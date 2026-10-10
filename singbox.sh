#!/bin/bash

# 基础路径定义
export SCRIPT_VERSION="33"
export DEFAULT_SNI="www.amd.com"
export WS_EARLY_DATA_SIZE="2560"
export WS_EARLY_DATA_HEADER="Sec-WebSocket-Protocol"
SELF_SCRIPT_PATH="$(readlink -f "$0")"
SCRIPT_DIR="$(dirname "$SELF_SCRIPT_PATH")"
SINGBOX_DIR="/usr/local/etc/sing-box"
GITHUB_RAW_BASE="https://raw.githubusercontent.com/tatgck/singbox-lite/main"
SCRIPT_UPDATE_URL="${GITHUB_RAW_BASE}/singbox.sh"

# 注入 sing-box 1.12+ 废弃配置兼容环境变量 (用于脚本内嵌的前台命令调用，如 check/generate)
export ENABLE_DEPRECATED_LEGACY_DNS_SERVERS="true"
export ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM="true"
export ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER="true"

# --- 核心工具函数 ---

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'
ORANGE='\033[0;33m'

# 打印消息函数
_info() { echo -e "${CYAN}[信息] $1${NC}" >&2; }
_success() { echo -e "${GREEN}[成功] $1${NC}" >&2; }
_warn() { echo -e "${YELLOW}[注意] $1${NC}" >&2; }
_warning() { _warn "$1"; } # 别名兼容
_error() { echo -e "${RED}[错误] $1${NC}" >&2; }

# 检查 root 权限
_check_root() {
    if [[ $EUID -ne 0 ]]; then
        _error "此脚本必须以 root 权限运行。"
        exit 1
    fi
}

# 编解码器 (纯 Bash 稳健实现)
_url_decode() {
    local data="${1//+/ }"
    printf '%b' "${data//%/\\x}"
}
_url_encode() {
    # [修复] 使用 jq 内建 @uri 过滤器，完美处理 UTF-8 多字节字符
    # jq 是必装依赖，@uri 以字节为单位执行标准 percent-encoding
    printf '%s' "$1" | jq -sRr @uri
}

_ws_path_with_early_data() {
    local ws_path="${1:-/}"
    if [[ "$ws_path" == *"ed="* ]]; then
        printf '%s' "$ws_path"
        return
    fi
    if [[ "$ws_path" == *"?"* ]]; then
        printf '%s&ed=%s' "$ws_path" "$WS_EARLY_DATA_SIZE"
    else
        printf '%s?ed=%s' "$ws_path" "$WS_EARLY_DATA_SIZE"
    fi
}

_cert_sha256_hex() {
    local cert_path="$1"
    [ -f "$cert_path" ] || return 1
    openssl x509 -in "$cert_path" -noout -fingerprint -sha256 2>/dev/null | \
        awk -F= 'NR==1 { gsub(":", "", $2); print tolower($2) }'
}

_tls_insecure_params() {
    local skip_verify="$1"
    local cert_path="$2"
    local insecure_param=""
    if [[ "$skip_verify" == "true" ]]; then
        insecure_param="&insecure=1"
        local cert_pcs=$(_cert_sha256_hex "$cert_path")
        [ -n "$cert_pcs" ] && insecure_param="${insecure_param}&pcs=${cert_pcs}"
    fi
    printf '%s' "$insecure_param"
}

_append_pcs_to_tls_link() {
    local url="$1"
    local cert_path="$2"
    [ -n "$url" ] || return 0
    [[ "$url" == *"pcs="* ]] && { printf '%s' "$url"; return 0; }

    local cert_pcs=$(_cert_sha256_hex "$cert_path")
    [ -n "$cert_pcs" ] || { printf '%s' "$url"; return 0; }

    local body="$url"
    local fragment=""
    if [[ "$url" == *"#"* ]]; then
        body="${url%%#*}"
        fragment="#${url#*#}"
    fi

    local sep="&"
    [[ "$body" != *"?"* ]] && sep="?"
    printf '%s%s%s%s' "$body" "$sep" "pcs=${cert_pcs}" "$fragment"
}

_ss_base64_encode() {
    # Shadowsocks SIP002 规范要求 Base64 编码不带填充 (No Padding)
    printf '%s' "$1" | base64 | tr -d '\n\r ' | sed 's/=//g'
}

# 公网 IP 获取 (带全局缓存)
_get_public_ip() {
    [ -n "$server_ip" ] && [ "$server_ip" != "null" ] && { echo "$server_ip"; return; }
    local ip=$(timeout 5 curl -s4 --max-time 2 icanhazip.com 2>/dev/null || timeout 5 curl -s4 --max-time 2 ipinfo.io/ip 2>/dev/null)
    [ -z "$ip" ] && ip=$(timeout 5 curl -s6 --max-time 2 icanhazip.com 2>/dev/null || timeout 5 curl -s6 --max-time 2 ipinfo.io/ip 2>/dev/null)
    server_ip="$ip"
    echo "$ip"
}
_get_ip() { _get_public_ip; } # 别名兼容

# 系统环境检测
_detect_init_system() {
    if [ -f /sbin/openrc-run ] || command -v rc-service &>/dev/null; then
        export INIT_SYSTEM="openrc"
        export SERVICE_FILE="/etc/init.d/sing-box"
    elif command -v systemctl &>/dev/null && [ -d /run/systemd/system ]; then
        export INIT_SYSTEM="systemd"
        export SERVICE_FILE="/etc/systemd/system/sing-box.service"
    else
        export INIT_SYSTEM="direct"
        export SERVICE_FILE=""
    fi
}

# 端口占用检查
_check_port_occupied() {
    local port=$1
    local proto=${2:-tcp}
    if [[ "$proto" == "tcp" ]]; then
        if command -v ss &>/dev/null; then
            ss -lnpt | grep -q ":${port} " && return 0
        else
            netstat -lnpt | grep -q ":${port} " && return 0
        fi
    else
        if command -v ss &>/dev/null; then
            ss -lnpu | grep -q ":${port} " && return 0
        else
            netstat -lnpu | grep -q ":${port} " && return 0
        fi
    fi
    return 1
}

_is_pid_running_cmd() {
    local pid="$1"
    local pattern="$2"
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    if [ -r "/proc/${pid}/cmdline" ]; then
        tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null | grep -Fq "$pattern"
    else
        ps -p "$pid" -o args= 2>/dev/null | grep -Fq "$pattern"
    fi
}

_is_pid_file_running_cmd() {
    local pid_file="$1"
    local pattern="$2"
    local pid
    [ -s "$pid_file" ] || return 1
    pid=$(cat "$pid_file" 2>/dev/null)
    _is_pid_running_cmd "$pid" "$pattern"
}

# 配置文件端口扫描 (预检是否已被本程序占用)
_check_port_in_config() {
    local port=$1
    [ ! -f "$CONFIG_FILE" ] && return 1
    jq -e ".inbounds[] | select(.listen_port == ($port|tonumber))" "$CONFIG_FILE" >/dev/null 2>&1
}

# 综合端口碰撞检测
_check_port_conflict() {
    local port=$1
    local proto=${2:-tcp}
    local silent=${3:-false}
    if _check_port_in_config "$port"; then
        [ "$silent" != "true" ] && _error "端口 ${port} 已在 sing-box 配置文件中被占用。"
        return 0
    fi
    if _check_port_occupied "$port" "$proto"; then
        [ "$silent" != "true" ] && _error "端口 ${port} 已被系统其他程序占用。"
        return 0
    fi
    if [[ "$proto" == "udp" ]]; then
        local hop_conflict
        hop_conflict=$(_find_udp_hop_conflict_in_range "$port" "$port")
        if [ -n "$hop_conflict" ]; then
            local c_tag c_name c_range c_mode
            IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$hop_conflict"
            [ "$silent" != "true" ] && _error "UDP 端口 ${port} 落在已有 HY2 端口跳跃范围 ${c_range} 内（${c_name}, ${c_tag}, ${c_mode}）。"
            return 0
        fi
    fi
    return 1
}

_find_pf_udp_conflict_in_range() {
    local start="$1" end="$2"
    local pf_meta="${SINGBOX_DIR}/relay_pf.json"
    [ -f "$pf_meta" ] || return 1
    jq -r --argjson start "$start" --argjson end "$end" '
        to_entries[]
        | (.key | tonumber?) as $port
        | select($port != null and $port >= $start and $port <= $end)
        | select(.value.network == "udp" or .value.network == "tcp+udp")
        | [
            .key,
            (.value.name // "端口转发"),
            (.value.network_display // .value.network // "UDP"),
            ((.value.target_addr // "") + ":" + ((.value.target_port // "") | tostring))
          ]
        | @tsv
    ' "$pf_meta" 2>/dev/null | head -n 1
}

_find_udp_hop_conflict_in_range() {
    local start="$1" end="$2" exclude_tag="${3:-}"
    local conflict=""
    if [ -f "$METADATA_FILE" ]; then
        conflict=$(jq -r --argjson start "$start" --argjson end "$end" --arg exclude "$exclude_tag" '
            to_entries[]
            | select(.key != $exclude)
            | select(.value.portHopping)
            | (.value.portHopping | capture("^(?<start>[0-9]+)-(?<end>[0-9]+)$")?) as $range
            | select($range != null)
            | ($range.start | tonumber) as $other_start
            | ($range.end | tonumber) as $other_end
            | select($start <= $other_end and $end >= $other_start)
            | [
                .key,
                (.value.name // .key),
                .value.portHopping,
                ("主HY2/" + (.value.portHoppingMode // "unknown"))
              ]
            | @tsv
        ' "$METADATA_FILE" 2>/dev/null | head -n 1)
        [ -n "$conflict" ] && { echo "$conflict"; return 0; }
    fi

    local relay_links="${SINGBOX_DIR}/relay_links.json"
    if [ -f "$relay_links" ]; then
        conflict=$(jq -r --argjson start "$start" --argjson end "$end" --arg exclude "$exclude_tag" '
            to_entries[]
            | select(.key != $exclude)
            | select(.value.port_hopping)
            | (.value.port_hopping | capture("^(?<start>[0-9]+)-(?<end>[0-9]+)$")?) as $range
            | select($range != null)
            | ($range.start | tonumber) as $other_start
            | ($range.end | tonumber) as $other_end
            | select($start <= $other_end and $end >= $other_start)
            | [
                .key,
                (.value.node_name // .key),
                .value.port_hopping,
                "中转HY2/nftables"
              ]
            | @tsv
        ' "$relay_links" 2>/dev/null | head -n 1)
        [ -n "$conflict" ] && { echo "$conflict"; return 0; }
    fi

    return 1
}

# nftables 规则管理 (独立表，避免污染系统其他防火墙规则)
export NFT_TABLE="singboxlite"
export NFT_PERSIST_FILE="/etc/nftables.d/singboxlite.nft"

_nft_ensure_base() {
    command -v nft &>/dev/null || return 1
    nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || nft add table inet "$NFT_TABLE" >/dev/null 2>&1 || return 1
    nft list chain inet "$NFT_TABLE" prerouting >/dev/null 2>&1 || nft add chain inet "$NFT_TABLE" prerouting '{ type nat hook prerouting priority -100; policy accept; }' >/dev/null 2>&1 || return 1
    nft list chain inet "$NFT_TABLE" output >/dev/null 2>&1 || nft add chain inet "$NFT_TABLE" output '{ type nat hook output priority -100; policy accept; }' >/dev/null 2>&1 || return 1
    nft list chain inet "$NFT_TABLE" postrouting >/dev/null 2>&1 || nft add chain inet "$NFT_TABLE" postrouting '{ type nat hook postrouting priority 100; policy accept; }' >/dev/null 2>&1 || return 1
    nft list chain inet "$NFT_TABLE" forward >/dev/null 2>&1 || nft add chain inet "$NFT_TABLE" forward '{ type filter hook forward priority 0; policy accept; }' >/dev/null 2>&1 || return 1
}

_nft_delete_rules_by_comment() {
    local comment="$1"
    local entries chain handle
    command -v nft &>/dev/null || return 0
    entries=$(nft -a list table inet "$NFT_TABLE" 2>/dev/null | awk -v c="comment \"$comment\"" '
        /^[[:space:]]*chain / { chain=$2 }
        index($0, c) && /# handle / { print chain, $NF }
    ')
    [ -z "$entries" ] && return 0
    while read -r chain handle; do
        [ -n "$chain" ] && [ -n "$handle" ] && nft delete rule inet "$NFT_TABLE" "$chain" handle "$handle" >/dev/null 2>&1
    done <<< "$entries"
}

_nft_port_expr() {
    local start="$1" end="$2"
    if [ "$start" = "$end" ]; then
        echo "$start"
    else
        echo "${start}-${end}"
    fi
}

_nft_apply_redirect_rule() {
    local action="$1" start_port="$2" end_port="$3" target_port="$4" comment="$5"
    if [ "$action" = "delete" ]; then
        _nft_delete_rules_by_comment "$comment"
        return 0
    fi
    _nft_ensure_base || return 1
    _nft_delete_rules_by_comment "$comment"
    nft add rule inet "$NFT_TABLE" prerouting udp dport "$(_nft_port_expr "$start_port" "$end_port")" redirect to ":${target_port}" comment "$comment" >/dev/null 2>&1
}

_nft_can_redirect() {
    local test_port="${1:-65530}" target_port="${2:-65531}" comment="singboxlite-test-redirect-$$"
    _nft_apply_redirect_rule add "$test_port" "$test_port" "$target_port" "$comment" || return 1
    _nft_apply_redirect_rule delete "$test_port" "$test_port" "$target_port" "$comment"
    return 0
}

_save_nftables_rules() {
    command -v nft &>/dev/null || return 0
    mkdir -p /etc/nftables.d
    if nft list table inet "$NFT_TABLE" > "$NFT_PERSIST_FILE" 2>/dev/null; then
        if [ ! -f /etc/nftables.conf ]; then
            {
                echo '#!/usr/sbin/nft -f'
                echo 'include "/etc/nftables.d/*.nft"'
            } > /etc/nftables.conf
        elif ! grep -q 'singboxlite\.nft\|/etc/nftables\.d/\*\.nft' /etc/nftables.conf 2>/dev/null; then
            echo 'include "/etc/nftables.d/singboxlite.nft"' >> /etc/nftables.conf
        fi
        if command -v systemctl &>/dev/null; then
            systemctl enable nftables >/dev/null 2>&1 || true
        fi
        if command -v rc-update &>/dev/null; then
            rc-update add nftables default >/dev/null 2>&1 || true
        fi
    fi
}

_remove_nftables_rules() {
    if command -v nft &>/dev/null; then
        nft delete table inet "$NFT_TABLE" >/dev/null 2>&1 || true
    fi
    rm -f "$NFT_PERSIST_FILE"
    if [ -f /etc/nftables.conf ]; then
        sed -i '\|/etc/nftables.d/singboxlite.nft|d' /etc/nftables.conf 2>/dev/null || true
    fi
}

# 公网 IP 初始化
_init_server_ip() {
    _info "正在获取服务器公网 IP..."
    server_ip=$(_get_public_ip)
    if [ -z "$server_ip" ] || [ "$server_ip" == "null" ]; then
        _warn "自动获取 IP 失败，将回退到 127.0.0.1"
        server_ip="127.0.0.1"
    else
        _success "当前服务器公网 IP: ${server_ip}"
    fi
}

# 在启动或重启前校验实际会被加载的合并配置。
# 只检查 config.json 会漏掉 relay.json 引入的冲突，导致服务启动后立即退出且原因不明显。
_validate_merged_config() {
    [ -x "$SINGBOX_BIN" ] || {
        _error "未找到 sing-box 核心: ${SINGBOX_BIN}"
        return 1
    }
    [ -s "$CONFIG_FILE" ] || {
        _error "主配置不存在或为空: ${CONFIG_FILE}"
        return 1
    }
    [ -s "${SINGBOX_DIR}/relay.json" ] || {
        _error "中转配置不存在或为空: ${SINGBOX_DIR}/relay.json"
        return 1
    }

    local validation_output
    if validation_output=$(${SINGBOX_BIN} check -c "$CONFIG_FILE" -c "${SINGBOX_DIR}/relay.json" 2>&1); then
        return 0
    fi

    _error "合并配置检查失败，已阻止启动/重启 sing-box。"
    [ -n "$validation_output" ] && printf '%s\n' "$validation_output" >&2
    if [ "$INIT_SYSTEM" = "openrc" ] || [ "$INIT_SYSTEM" = "direct" ]; then
        _warn "请先运行主菜单 [12] 检查配置文件，或查看 ${LOG_FILE}（Alpine/OpenRC 日志）。"
    else
        _warn "请先运行主菜单 [12] 检查配置文件，或查看 journalctl -u sing-box -b。"
    fi
    return 1
}

_verify_service_ready() {
    local port="$1" proto="${2:-tcp}"
    if [ -n "$port" ] && ! command -v ss >/dev/null 2>&1; then
        _error "缺少 ss，无法确认端口 ${port} 是否真实监听。请在 Alpine 3.21 安装 iproute2。"
        return 1
    fi

    local attempt=0
    while [ "$attempt" -lt 10 ]; do
        local service_active=false
        case "$INIT_SYSTEM" in
            systemd) systemctl is-active --quiet sing-box && service_active=true ;;
            openrc)
                local openrc_status
                openrc_status=$(rc-service sing-box status 2>&1 || true)
                # supervise-daemon 的 status 可能只反映 supervisor 本身；同时确认
                # sing-box 进程仍在，避免把“启动命令已返回”当成就绪。
                if printf '%s\n' "$openrc_status" | grep -Eiq 'started|running' \
                    && { _is_pid_file_running_cmd "$PID_FILE" "$SINGBOX_BIN" \
                         || (command -v pgrep >/dev/null 2>&1 && pgrep -f "${SINGBOX_BIN} run" >/dev/null 2>&1); }; then
                    service_active=true
                fi
                ;;
            direct) _is_pid_file_running_cmd "$PID_FILE" "$SINGBOX_BIN" && service_active=true ;;
            *) return 1 ;;
        esac

        if [ "$service_active" = true ] && [ -n "$port" ]; then
            local sockets
            if [ "$proto" = "udp" ]; then
                sockets=$(ss -lnu 2>/dev/null)
            elif [ "$proto" = "any" ]; then
                sockets="$(ss -ln 2>/dev/null)\n$(ss -lnu 2>/dev/null)"
            else
                sockets=$(ss -ln 2>/dev/null)
            fi
            if printf '%b\n' "$sockets" | grep -Eq "[:.]${port}[[:space:]]"; then
                return 0
            fi
        elif [ "$service_active" = true ]; then
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 0.5
    done
    return 1
}

_snapshot_node_state() {
    local dir="$1"
    mkdir -p "$dir" || return 1
    for file in "$CONFIG_FILE" "$CLASH_YAML_FILE" "$METADATA_FILE" "$ARGO_METADATA_FILE"; do
        if [ -f "$file" ]; then
            cp -p "$file" "$dir/$(basename "$file")" || return 1
        else
            : > "$dir/$(basename "$file").missing" || return 1
        fi
    done
}

_restore_node_state() {
    local dir="$1" file base rc=0
    for file in "$CONFIG_FILE" "$CLASH_YAML_FILE" "$METADATA_FILE" "$ARGO_METADATA_FILE"; do
        base=$(basename "$file")
        if [ -f "$dir/$base.missing" ]; then
            rm -f "$file" || rc=1
        elif [ -f "$dir/$base" ]; then
            cp -p "$dir/$base" "$file" || rc=1
        else
            rc=1
        fi
    done
    return "$rc"
}

# 统一服务管理
_manage_service() {
    local action="$1"

    # [关键核心修复] 动态注入内置 NTP 时间同步模块
    # 解决部分廉价 LXC/Docker 容器无法修改母机系统时间，导致 SS-2022 触发 30s 重放保护直接爆 bad timestamp 拒连的断流问题
    if [[ "$action" == "restart" || "$action" == "start" ]]; then
        if [ -s "$CONFIG_FILE" ] && ! jq -e '.ntp' "$CONFIG_FILE" >/dev/null 2>&1; then
            _info "检测到内核配置缺失内置时间同步(NTP)模块，正在自动注入防重放保护补丁..."
            _atomic_modify_json "$CONFIG_FILE" '.ntp = {"enabled": true, "server": "time.apple.com", "server_port": 123, "interval": "30m"}' 2>/dev/null
        fi
        [ -s "${SINGBOX_DIR}/relay.json" ] || echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "${SINGBOX_DIR}/relay.json"
        if ! _validate_merged_config; then
            return 1
        fi
    fi

    [ -z "$INIT_SYSTEM" ] && _detect_init_system
    [ "$action" == "status" ] || _info "正在使用 ${INIT_SYSTEM} 执行: $action..."
    case "$INIT_SYSTEM" in
        systemd)
            if [ "$action" == "status" ]; then systemctl status sing-box --no-pager -l; return; fi
            systemctl "$action" sing-box ;;
        openrc)
            if [ "$action" == "status" ]; then rc-service sing-box status; return; fi
            rc-service sing-box "$action" ;;
        direct)
            case "$action" in
                start)
                    if _is_pid_file_running_cmd "$PID_FILE" "$SINGBOX_BIN"; then
                        _success "sing-box 已在 direct 模式运行。"
                        return 0
                    fi
                    rm -f "$PID_FILE"
                    [ -s "${SINGBOX_DIR}/relay.json" ] || echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "${SINGBOX_DIR}/relay.json"
                    nohup env GOMEMLIMIT="$(_get_mem_limit)MiB" \
                        ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true \
                        ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM=true \
                        ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true \
                        "$SINGBOX_BIN" run -c "$CONFIG_FILE" -c "${SINGBOX_DIR}/relay.json" \
                        >> "$LOG_FILE" 2>&1 &
                    echo $! > "$PID_FILE"
                    # 进程若因配置/证书错误立即退出，直接模式原先仍会显示“启动成功”。
                    sleep 0.2
                    if ! _is_pid_file_running_cmd "$PID_FILE" "$SINGBOX_BIN"; then
                        _error "sing-box 启动后立即退出，日志位置: ${LOG_FILE}"
                        [ -s "$LOG_FILE" ] && tail -n 30 "$LOG_FILE" >&2
                        rm -f "$PID_FILE"
                        return 1
                    fi
                    _success "sing-box 已以 direct 后台模式启动。"
                    ;;
                stop)
                    if [ -s "$PID_FILE" ]; then
                        local pid
                        pid=$(cat "$PID_FILE" 2>/dev/null)
                        if _is_pid_running_cmd "$pid" "$SINGBOX_BIN"; then
                            kill "$pid" 2>/dev/null
                        fi
                    fi
                    rm -f "$PID_FILE"
                    _success "sing-box direct 后台进程已停止。"
                    ;;
                restart)
                    _manage_service stop
                    sleep 1
                    _manage_service start
                    ;;
                status)
                    if _is_pid_file_running_cmd "$PID_FILE" "$SINGBOX_BIN"; then
                        _success "sing-box direct 后台模式运行中 (PID: $(cat "$PID_FILE"))"
                    else
                        rm -f "$PID_FILE"
                        _warn "sing-box direct 后台模式未运行。"
                        return 1
                    fi
                    ;;
                *) _error "direct 模式不支持的服务操作: $action"; return 1 ;;
            esac
            ;;
        *) _error "不支持的服务管理系统"; return 1 ;;
    esac
}

# 智能包管理
_pkg_install() {
    local pkgs="$*"
    local rc
    [ -z "$pkgs" ] && return 0
    if command -v apk &>/dev/null; then
        apk add --no-cache $pkgs >/dev/null 2>&1
    elif command -v apt-get &>/dev/null; then
        # 全新 LXC/容器上 apt 缓存可能为空，必须先 update
        if [ ! -d "/var/lib/apt/lists" ] || [ "$(ls -A /var/lib/apt/lists/ 2>/dev/null | wc -l)" -le 1 ]; then
            apt-get -o DPkg::Lock::Timeout=120 update -qq >/dev/null 2>&1
            rc=$?
            if [ "$rc" -ne 0 ]; then
                if [ "$rc" -eq 137 ]; then
                    _warn "apt-get update 被系统终止（可能是内存不足）；停止重试。"
                else
                    _warn "apt-get update 失败（退出码 ${rc}）；请检查网络、软件源或 apt 锁占用。"
                fi
                return "$rc"
            fi
        fi
        # 不安装推荐包，减少低内存 VPS 的下载量、解包量和安装时间。
        # Debian/Ubuntu 首次启动时 apt-daily 可能持有 dpkg 锁；等待最多 120 秒再失败。
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends -o Dpkg::Use-Pty=0 -o DPkg::Lock::Timeout=120 $pkgs >/dev/null 2>&1
        rc=$?
        if [ "$rc" -eq 0 ]; then
            return 0
        elif [ "$rc" -eq 137 ]; then
            _warn "apt-get install 被系统强制终止（SIGKILL，常见原因是 VPS 内存不足）；不再刷新索引或重试。"
            return "$rc"
        fi

        # 非 OOM 类错误（例如索引过期）才刷新一次索引后重试。
        _warn "apt-get install 失败（退出码 ${rc}），刷新软件索引后重试一次..."
        apt-get -o DPkg::Lock::Timeout=120 update -qq >/dev/null 2>&1
        rc=$?
        if [ "$rc" -eq 137 ]; then
            _warn "apt-get update 被系统强制终止（SIGKILL，常见原因是 VPS 内存不足）；停止重试。"
            return "$rc"
        elif [ "$rc" -ne 0 ]; then
            _warn "apt-get update 失败（退出码 ${rc}）。"
            return "$rc"
        fi
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends -o Dpkg::Use-Pty=0 -o DPkg::Lock::Timeout=120 $pkgs >/dev/null 2>&1
        rc=$?
        if [ "$rc" -eq 137 ]; then
            _warn "apt-get install 重试时再次被系统强制终止（SIGKILL）；请先释放/增加 VPS 内存后再运行。"
        elif [ "$rc" -ne 0 ]; then
            _warn "apt-get install 重试失败（退出码 ${rc}）。"
        fi
        return "$rc"
    elif command -v yum &>/dev/null; then yum install -y $pkgs >/dev/null 2>&1
    elif command -v dnf &>/dev/null; then dnf install -y $pkgs >/dev/null 2>&1
    else
        return 1
    fi
}

# 原子修改 JSON/YAML 文件
_atomic_modify_json() {
    local file="$1" filter="$2"
    [ ! -f "$file" ] && return 1
    local tmp="${file}.tmp"
    if jq "$filter" "$file" > "$tmp"; then mv "$tmp" "$file"
    else _error "修改JSON失败: $file"; rm -f "$tmp"; return 1; fi
}
_atomic_modify_yaml() {
    local file="$1" filter="$2"
    [ ! -f "$file" ] && return 1
    local tmp="${file}.tmp.$$"
    cp "$file" "$tmp" || return 1
    if ${YQ_BINARY} eval "$filter" -i "$file" 2>/dev/null; then
        rm -f "$tmp"
    else
        _error "修改YAML失败: $file"
        mv "$tmp" "$file"
        return 1
    fi
}

# 事务与服务校验共用的配置路径/辅助函数。旧版本只在部分代码路径中
# 使用了这些名称，导致节点创建失败后的回滚无法正确恢复 relay.json。
export RELAY_CONFIG_FILE="${SINGBOX_DIR}/relay.json"

_ensure_relay_config() {
    if [ ! -s "$RELAY_CONFIG_FILE" ]; then
        mkdir -p "$(dirname "$RELAY_CONFIG_FILE")" || return 1
        printf '%s\n' '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$RELAY_CONFIG_FILE" || return 1
    fi
    jq empty "$RELAY_CONFIG_FILE" >/dev/null 2>&1
}

_check_combined_config_files() {
    local binary="${1:-$SINGBOX_BIN}" main_config="${2:-$CONFIG_FILE}" relay_config="${3:-$RELAY_CONFIG_FILE}"
    [ -x "$binary" ] || { printf '%s\n' "未找到 sing-box 核心: $binary"; return 1; }
    [ -s "$main_config" ] || { printf '%s\n' "主配置不存在或为空: $main_config"; return 1; }
    [ -s "$relay_config" ] || { printf '%s\n' "中转配置不存在或为空: $relay_config"; return 1; }
    "$binary" check -c "$main_config" -c "$relay_config"
}

_secure_state_permissions() {
    [ -d "$SINGBOX_DIR" ] && chmod 700 "$SINGBOX_DIR" 2>/dev/null || true
    local path
    for path in "$CONFIG_FILE" "$CLASH_YAML_FILE" "$METADATA_FILE" "$ARGO_METADATA_FILE" "$RELAY_CONFIG_FILE"; do
        [ -f "$path" ] && chmod 600 "$path" 2>/dev/null || true
    done
}

# --- 资源与环境管理 ---

# 系统时间同步 (解决 TLS 握手 EOF 问题)
_sync_system_time() {
    _info "正在检查并同步系统时间..."
    local current_year=$(date +%Y)
    [ "$current_year" -lt 2024 ] && _warning "系统时间滞后，正在强制同步..."
    # 采用三级同步策略提升鲁棒性 (NTP -> HTTP -> Package)
    if _pkg_install ntpdate >/dev/null 2>&1 && command -v ntpdate &>/dev/null; then
        ntpdate -u ntp.aliyun.com >/dev/null 2>&1 || ntpdate -u pool.ntp.org >/dev/null 2>&1
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        _pkg_install chrony >/dev/null 2>&1
        chronyd -q 'server ntp.aliyun.com iburst' >/dev/null 2>&1
    else
        # 最后的屏障：通过 HTTP 头部修正时间 (防御 UDP 123 拦截)
        local http_time=$(curl -sI --max-time 3 https://www.google.com | grep -i '^date:' | cut -f2- -d' ')
        if [ -n "$http_time" ]; then
            # [修复] 先尝试 GNU date 直接设置，失败后尝试 epoch 方式 (兼容 BusyBox)
            if ! date -s "$http_time" >/dev/null 2>&1; then
                local epoch=$(date -d "$http_time" +%s 2>/dev/null)
                [ -n "$epoch" ] && date -s "@$epoch" >/dev/null 2>&1
            fi
        fi
    fi
    _info "当前时间：$(date)"
}

# Clash YAML 节点管理
_get_proxy_field() {
    local proxy_name="$1" field="$2"
    export PROXY_NAME="$proxy_name"
    ${YQ_BINARY} eval '.proxies[] | select(.name == env(PROXY_NAME)) | '"$field" "${CLASH_YAML_FILE}" 2>/dev/null | head -n 1
}
_add_node_to_yaml() {
    local proxy_json="$1"
    local proxy_name=$(echo "$proxy_json" | jq -r .name)
    _atomic_modify_yaml "$CLASH_YAML_FILE" ".proxies |= . + [${proxy_json}] | .proxies |= unique_by(.name)" || return 1
    export PROXY_NAME="$proxy_name"
    _atomic_modify_yaml "$CLASH_YAML_FILE" '.proxy-groups[] |= (select(.name == "节点选择") | .proxies |= . + [env(PROXY_NAME)] | .proxies |= unique)' || return 1
}
_remove_node_from_yaml() {
    local proxy_name="$1"
    export PROXY_NAME="$proxy_name"
    _atomic_modify_yaml "$CLASH_YAML_FILE" 'del(.proxies[] | select(.name == env(PROXY_NAME)))' || return 1
    _atomic_modify_yaml "$CLASH_YAML_FILE" '.proxy-groups[] |= (select(.name == "节点选择") | .proxies |= del(.[] | select(. == env(PROXY_NAME))))'
}
_find_proxy_name() {
    local port="$1" type="$2" tag="$3" proxy_name=""
    if [ -n "$tag" ] && [ -f "$METADATA_FILE" ]; then
        local yaml_enabled
        yaml_enabled=$(jq -r --arg t "$tag" '.[$t].yaml // empty' "$METADATA_FILE" 2>/dev/null)
        [ "$yaml_enabled" = "false" ] && return 0
    fi
    local proxy_obj=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}')' ${CLASH_YAML_FILE} 2>/dev/null | head -n 1)
    [ -n "$proxy_obj" ] && proxy_name=$(echo "$proxy_obj" | ${YQ_BINARY} eval '.name' -)
    [ -z "$proxy_name" ] && proxy_name=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}' or .port == 443) | .name' ${CLASH_YAML_FILE} 2>/dev/null | grep -i "${type:-.}" | head -n 1)
    echo "$proxy_name"
}

# 内存限额计算
_get_mem_limit() {
    local total_mem_mb=$(free -m | awk '/^Mem:/{print $2}')
    local cgroup_limit=""
    local limit

    [ -z "$total_mem_mb" ] && total_mem_mb=128

    if [ -r /sys/fs/cgroup/memory.max ]; then
        cgroup_limit=$(cat /sys/fs/cgroup/memory.max 2>/dev/null)
        if [ "$cgroup_limit" != "max" ] && [ -n "$cgroup_limit" ]; then
            total_mem_mb=$((cgroup_limit / 1024 / 1024))
        fi
    elif [ -r /sys/fs/cgroup/memory/memory.limit_in_bytes ]; then
        cgroup_limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null)
        if [ -n "$cgroup_limit" ] && [ "$cgroup_limit" -lt 9223372036854771712 ] 2>/dev/null; then
            total_mem_mb=$((cgroup_limit / 1024 / 1024))
        fi
    fi

    if [ "$total_mem_mb" -le 128 ]; then
        limit=48
    elif [ "$total_mem_mb" -le 256 ]; then
        limit=$((total_mem_mb * 50 / 100))
    elif [ "$total_mem_mb" -le 512 ]; then
        limit=$((total_mem_mb * 65 / 100))
    else
        limit=$((total_mem_mb * 80 / 100))
    fi

    [ "$limit" -lt 32 ] && limit=32
    echo "$limit"
}

# 安装阶段会产生较多文件缓存，低内存容器中尽力释放；失败不影响主流程
_release_install_cache() {
    sync 2>/dev/null || true
    if [ -w /proc/sys/vm/drop_caches ]; then
        if { echo 1 > /proc/sys/vm/drop_caches; } 2>/dev/null; then
            _info "已尝试释放安装产生的文件缓存。"
        fi
    fi
    return 0
}

# 安装 yq
_install_yq() {
    if [ ! -x "$YQ_BINARY" ]; then
        _info "安装 yq..."
        local arch=$(uname -m)
        case $arch in x86_64|amd64) arch='amd64' ;; aarch64|arm64) arch='arm64' ;; *) arch='amd64' ;; esac
        wget -qO "$YQ_BINARY" "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_$arch"
        chmod +x "$YQ_BINARY"
    fi
}

# --- 核心变量定义 ---
export SINGBOX_DIR="/usr/local/etc/sing-box"
export SINGBOX_BIN="/usr/local/bin/sing-box"
export YQ_BINARY="/usr/local/bin/yq"
export CONFIG_FILE="${SINGBOX_DIR}/config.json"
export CLASH_YAML_FILE="${SINGBOX_DIR}/clash.yaml"
export METADATA_FILE="${SINGBOX_DIR}/metadata.json"
export ARGO_METADATA_FILE="${SINGBOX_DIR}/argo_metadata.json"
export LOG_FILE="/var/log/sing-box.log"
export ARGO_LOG_FILE="/var/log/singbox_argo.log"
export PID_FILE="/tmp/sing-box.pid"
export CLOUDFLARED_BIN="/usr/local/bin/cloudflared"
export DEP_STATE_FILE="${SINGBOX_DIR}/dependencies.ok"
export DEP_STATE_VERSION="20260529-nft-1"
_detect_init_system
case "$INIT_SYSTEM" in
    openrc) export SERVICE_FILE="/etc/init.d/sing-box" ;;
    systemd) export SERVICE_FILE="/etc/systemd/system/sing-box.service" ;;
    *) export SERVICE_FILE="" ;;
esac

export -f _info _success _warn _warning _error _url_encode _url_decode _ws_path_with_early_data _cert_sha256_hex _tls_insecure_params _get_public_ip _detect_init_system _sync_system_time _release_install_cache _atomic_modify_json _atomic_modify_yaml _manage_service _pkg_install _get_proxy_field _add_node_to_yaml _remove_node_from_yaml _find_proxy_name _nft_ensure_base _nft_delete_rules_by_comment _nft_port_expr _nft_apply_redirect_rule _nft_can_redirect _save_nftables_rules _remove_nftables_rules

server_ip=""
BATCH_MODE=false
trap 'rm -f ${SINGBOX_DIR}/*.tmp /tmp/singbox_links.tmp' EXIT
# 依赖安装
_install_dependencies() {
    local force="${1:-false}"
    if [ "$force" != "true" ] && [ -s "$DEP_STATE_FILE" ] && grep -qx "$DEP_STATE_VERSION" "$DEP_STATE_FILE" 2>/dev/null; then
        local missing_cached=""
        for cmd in bash jq curl wget openssl tar unzip; do
            if ! command -v "$cmd" &>/dev/null; then
                missing_cached="$missing_cached $cmd"
            fi
        done
        if ! command -v nft &>/dev/null; then
            missing_cached="$missing_cached nftables"
        fi
        if [ -z "$missing_cached" ] && [ -x "$YQ_BINARY" ]; then
            return 0
        fi
        [ ! -x "$YQ_BINARY" ] && missing_cached="$missing_cached yq"
        _warn "依赖缓存存在，但关键工具缺失:${missing_cached}，将执行一次修复安装。"
    fi

    # 核心依赖：脚本运行的绝对前提，必须全部装上
    local core_pkgs="bash curl jq openssl wget tar unzip ca-certificates"
    # 可选依赖：部分功能需要，即使装失败也不致命
    local optional_pkgs="procps nftables socat iproute2 cron lsof"
    
    # 针对不同发行版的 cron 包名适配
    if command -v apk &>/dev/null; then
        optional_pkgs="${optional_pkgs/cron/dcron}"
    elif ! command -v apt-get &>/dev/null && ! command -v yum &>/dev/null && ! command -v dnf &>/dev/null; then
        optional_pkgs="${optional_pkgs/cron/cronie}"
    fi

    _info "正在安装核心依赖..."
    if ! _pkg_install $core_pkgs; then
        _error "核心依赖安装失败，停止后续安装，避免在 VPS 资源不足时反复调用包管理器。"
        _error "如果日志包含 Killed/SIGKILL，请检查内存和 OOM 记录（free -h; dmesg -T | tail -n 50），释放空间或增加 swap 后重试。"
        exit 1
    fi
    
    _info "正在安装可选依赖..."
    if _pkg_install $optional_pkgs 2>/dev/null; then
        :
    else
        # SIGKILL 往往表示 OOM；不能逐包重复启动 apt，否则会进一步消耗资源。
        local optional_rc=$?
        if [ "$optional_rc" -eq 137 ]; then
            _warn "可选依赖安装被系统强制终止；跳过逐包重试，继续检查已有工具。"
        else
            # 可选依赖批量安装失败时逐个尝试
            _warn "部分可选依赖批量安装失败，正在逐个尝试..."
            for pkg in $optional_pkgs; do
                _pkg_install "$pkg" 2>/dev/null
                optional_rc=$?
                [ "$optional_rc" -eq 137 ] && {
                    _warn "安装 ${pkg} 时遇到 SIGKILL，停止其余可选依赖重试。"
                    break
                }
            done
        fi
    fi
    
    _install_yq

    # [修复] Alpine 上 dcron 安装后需手动启动 cron 守护进程
    if command -v apk &>/dev/null; then
        if command -v crond &>/dev/null; then
            rc-service dcron start 2>/dev/null
            rc-update add dcron default 2>/dev/null
        fi
    fi

    # 关键依赖验证：如果核心工具缺失则无法继续
    local missing=""
    for cmd in bash jq curl wget openssl tar unzip; do
        if ! command -v "$cmd" &>/dev/null; then
            missing="$missing $cmd"
        fi
    done
    if [ ! -x "$YQ_BINARY" ]; then
        missing="$missing yq"
    fi
    if [ -n "$missing" ]; then
        _error "以下关键依赖安装失败:${missing}"
        _error "请使用系统包管理器手动安装这些工具（如 apk add / apt-get install / yum install）"
        exit 1
    fi

    mkdir -p "$SINGBOX_DIR"
    printf '%s\n' "$DEP_STATE_VERSION" > "$DEP_STATE_FILE"
}

# 确保 nftables 可用，并检测实际 netfilter 写入能力
_ensure_nftables() {
    if ! command -v nft &>/dev/null; then
        _info "未检测到 nftables，尝试安装..."
        _pkg_install nftables
        if ! command -v nft &>/dev/null; then
            _error "nftables 安装失败。"
            return 1
        fi
        _success "nftables 安装成功。"
    fi

    if ! _nft_can_redirect 65530 65531; then
        _warn "nftables 命令存在，但当前环境无 netfilter 写权限（容器/LXC 无特权模式）。"
        _warn "端口转发将自动使用 sing-box 引擎代替。"
        return 2
    fi

    return 0
}

_install_sing_box() {
    _info "正在安装最新稳定版 sing-box..."
    local arch=$(uname -m)
    local arch_tag
    local temp_dir=""
    local archive_path=""
    local extracted_bin=""
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='armv7' ;;
        *) _error "不支持的架构：$arch"; return 1 ;;
    esac
    
    # 检测 C 库类型：Alpine 等系统使用 musl，需要下载对应版本
    local libc_suffix=""
    if ldd --version 2>&1 | grep -qi musl || [ -f /etc/alpine-release ]; then
        _info "检测到 musl libc (Alpine 等系统)，将下载 musl 版本..."
        libc_suffix="-musl"
    fi
    
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local search_pattern="linux-${arch_tag}${libc_suffix}.tar.gz"
    local release_info=$(curl -s "$api_url")
    local download_url=$(echo "$release_info" | jq -r ".assets[] | select(.name | contains(\"${search_pattern}\")) | .browser_download_url" | head -1)

    if [ -z "$download_url" ]; then _error "无法获取 sing-box 下载链接 (搜索: ${search_pattern})。"; return 1; fi

    temp_dir=$(mktemp -d /root/.singbox-install.XXXXXX) || { _error "创建临时目录失败。"; return 1; }
    archive_path="${temp_dir}/sing-box.tar.gz"

    _info "正在下载 sing-box 安装包..."
    if ! wget -qO "$archive_path" "$download_url"; then
        _error "下载失败: $download_url"
        rm -rf "$temp_dir"
        return 1
    fi

    _info "正在解压 sing-box 安装包..."
    if ! tar -xzf "$archive_path" -C "$temp_dir"; then
        _error "解压 sing-box 安装包失败，临时目录保留: $temp_dir"
        return 1
    fi

    extracted_bin=$(find "$temp_dir" -name sing-box -type f 2>/dev/null | head -n 1)
    if [ -z "$extracted_bin" ]; then
        _error "解压后未找到 sing-box 二进制文件，临时目录保留: $temp_dir"
        return 1
    fi

    rm -f "$archive_path"

    _info "正在安装 sing-box 二进制文件..."
    mkdir -p "$(dirname "$SINGBOX_BIN")" || {
        _error "创建安装目录失败: $(dirname "$SINGBOX_BIN")"
        return 1
    }
    if ! mv -f "$extracted_bin" "$SINGBOX_BIN"; then
        _error "安装 sing-box 二进制文件失败: $SINGBOX_BIN"
        _error "临时目录保留: $temp_dir"
        return 1
    fi
    if ! chmod +x "$SINGBOX_BIN"; then
        _error "设置 sing-box 可执行权限失败: $SINGBOX_BIN"
        _error "临时目录保留: $temp_dir"
        return 1
    fi

    rm -rf "$temp_dir"
    _release_install_cache
    _success "sing-box 安装成功: ${SINGBOX_BIN}"
}

_install_cloudflared() {
    if [ -f "${CLOUDFLARED_BIN}" ]; then
        _info "cloudflared 已安装: $(${CLOUDFLARED_BIN} --version 2>&1 | head -n1)"
        return 0
    fi
    
    _info "正在安装依据环境所需的组件 (ca-certificates)..."
    _pkg_install ca-certificates # 关键修复：Alpine 等精简系统必须有证书才能进行 TLS 握手
    
    _info "正在安装 cloudflared..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='arm' ;;
        *) _error "不支持的架构：$arch"; return 1 ;;
    esac
    
    local download_url="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${arch_tag}"
    
    wget -qO "${CLOUDFLARED_BIN}" "$download_url" || { _error "cloudflared 下载失败!"; return 1; }
    chmod +x "${CLOUDFLARED_BIN}"
    
    _success "cloudflared 安装成功: $(${CLOUDFLARED_BIN} --version 2>&1 | head -n1)"
}

# --- Argo Tunnel 功能 ---

_start_argo_tunnel() {
    local target_port="$1"
    local protocol="$2"
    local token="$3" # 可选，用于固定隧道
    
    # 基于端口生成独立的 PID 和日志文件路径
    local pid_file="/tmp/singbox_argo_${target_port}.pid"
    local log_file="/tmp/singbox_argo_${target_port}.log"
    
    _info "正在启动 Argo 隧道 (端口: $target_port)..." >&2
    
    # 检查该端口对应的隧道是否已在运行
    if [ -f "$pid_file" ]; then
        local old_pid=$(cat "$pid_file" 2>/dev/null)
        if _is_pid_running_cmd "$old_pid" "$CLOUDFLARED_BIN"; then
            _warning "检测到端口 $target_port 的 Argo 隧道已在运行 (PID: $old_pid)" >&2
            return 0
        fi
    fi
    
    # 清理旧日志和同步时间
    rm -f "${log_file}"
    _sync_system_time
    
    if [ -n "$token" ]; then
        # --- Token 固定隧道模式 ---
        _info "启动固定隧道 (Token 模式)..." >&2
        
        # 强制锁定 protocol http2 (h2)，防止 QUIC (UDP) 被阻断导致连接失败
        # 增加 --no-autoupdate 防止在精简系统上因自更新导致的意外进程挂起
        nohup ${CLOUDFLARED_BIN} tunnel --protocol http2 --no-autoupdate run --token "$token" > "${log_file}" 2>&1 &
            
        local cf_pid=$!
        echo "$cf_pid" > "${pid_file}"
        
        sleep 5
        if ! kill -0 "$cf_pid" 2>/dev/null; then
             _error "cloudflared 进程已退出！" >&2
             _error "Token 可能无效，或者网络连接被拒绝。" >&2
             echo "--- 错误日志 (最后 20 行) ---" >&2
             cat "${log_file}" | tail -20 >&2
             echo "-----------------------------"
             return 1
        fi
        _enable_argo_watchdog
        _success "Argo 固定隧道 (端口: $target_port) 启动成功!" >&2
        return 0
    else
        # --- URL 临时隧道模式 ---
        _info "启动临时隧道，指向 127.0.0.1:${target_port}..." >&2
        
        # 优化：强制指定 http2 协议并禁用自动更新
        nohup ${CLOUDFLARED_BIN} tunnel --protocol http2 --no-autoupdate --url "http://127.0.0.1:${target_port}" \
            --logfile "${log_file}" \
            > /dev/null 2>&1 &
        
        local cf_pid=$!
        echo "$cf_pid" > "${pid_file}"
        
        # 等待隧道启动并获取域名
        _info "等待隧道建立 (最多30秒)..." >&2
        
        local tunnel_domain=""
        local wait_count=0
        local max_wait=30
        
        while [ $wait_count -lt $max_wait ]; do
            sleep 2
            wait_count=$((wait_count + 2))
            
            # 检查进程是否还在运行
            if ! kill -0 "$cf_pid" 2>/dev/null; then
                _error "cloudflared 进程已退出，请检查日志: ${log_file}" >&2
                cat "${log_file}" 2>/dev/null | tail -20 >&2
                return 1
            fi
            
            # 优化域名提取正则表达式，确保无论日志格式如何变化都能准确抓取
            if [ -f "${log_file}" ]; then
                tunnel_domain=$(grep -oE 'https?://[a-zA-Z0-9-]+\.trycloudflare\.com' "${log_file}" 2>/dev/null | head -n 1 | sed -E 's|https?://||')
                if [ -n "$tunnel_domain" ]; then
                    break
                fi
            fi
            echo -n "." >&2
        done
        echo "" >&2
        
        if [ -n "$tunnel_domain" ]; then
            _info "域名已获取，正在进行稳定性测试 (5秒)..." >&2
            sleep 5
            if ! kill -0 "$cf_pid" 2>/dev/null; then
                 _error "稳定性测试失败：cloudflared 进程异常退出。" >&2
                 cat "${log_file}" 2>/dev/null | tail -n 10 >&2
                 return 1
            fi

            _enable_argo_watchdog
            _success "Argo 临时隧道建立成功: ${tunnel_domain}" >&2
            echo "$tunnel_domain"
            return 0
        else
            _error "获取临时域名超时。请检查网络。日志最后几行：" >&2
            cat "${log_file}" 2>/dev/null | tail -n 5 >&2
            kill "$cf_pid" 2>/dev/null
            rm -f "${pid_file}"
            return 1
        fi
    fi
}

_stop_argo_tunnel() {
    local target_port="$1"
    if [ -z "$target_port" ]; then
        return
    fi
    
    local pid_file="/tmp/singbox_argo_${target_port}.pid"
    local log_file="/tmp/singbox_argo_${target_port}.log"

    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if _is_pid_running_cmd "$pid" "$CLOUDFLARED_BIN"; then
            kill "$pid" 2>/dev/null
            _success "Argo 隧道 (端口: $target_port) 已停止"
        fi
        rm -f "$pid_file" "$log_file"
    fi
}

_stop_all_argo_tunnels() {
    _info "正在停止所有 Argo 隧道..."
    local stopped_any=false
    for pid_file in /tmp/singbox_argo_*.pid; do
        [ -e "$pid_file" ] || continue
        # 解析端口
        local filename=$(basename "$pid_file")
        local port=${filename#singbox_argo_}
        port=${port%.pid}
        _stop_argo_tunnel "$port"
        stopped_any=true
    done
    if [ "$stopped_any" = false ]; then
        _warn "未找到本脚本记录的 Argo PID 文件，未执行全局 cloudflared 清理。"
    fi
}

# ============================================================
# 统一 Argo 节点创建函数 (消除 VLESS/Trojan 重复代码)
# 参数: $1 = 协议类型 ("vless" 或 "trojan")
# ============================================================
_add_argo_node() {
    local protocol="$1"
    local protocol_label=""
    local proto_name=""
    case "$protocol" in
        vless) protocol_label="VLESS-WS"; proto_name="Vless" ;;
        trojan) protocol_label="Trojan-WS"; proto_name="Trojan" ;;
        *) _error "不支持的 Argo 协议: $protocol"; return 1 ;;
    esac

    _info "--- 创建 ${protocol_label} + Argo 隧道节点 ---"

    # 安装 cloudflared
    _install_cloudflared || return 1

    # === [公共] 内部端口分配 ===
    read -p "请输入 Argo 内部监听端口 (回车随机生成): " input_port
    local port="$input_port"

    while true; do
        if [[ -n "$port" && "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1024 ] && [ "$port" -le 65535 ]; then
            _check_port_conflict "$port" "tcp" && port="" && continue
            _info "已使用监听端口: ${port}"
            break
        else
            [ -n "$port" ] && _warning "端口格式无效，将重新生成..."
            # 使用内建算法生成随机端口 (10000-60000)，移除 shuf 依赖
            port=$(( $(od -An -tu2 -N2 /dev/urandom | tr -d ' ') % 50001 + 10000 ))
            _info "正在尝试分配随机内部端口: ${port}..."
        fi
    done

    # === [公共] WebSocket 路径 ===
    read -p "请输入 WebSocket 路径 (回车随机生成): " ws_path
    if [ -z "$ws_path" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
        _info "已生成随机路径: ${ws_path}"
    else
        [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
    fi

    # === [协议特定] Trojan 密码输入 ===
    local password=""
    if [ "$protocol" == "trojan" ]; then
        read -p "请输入 Trojan 密码 (回车随机生成): " password
        if [ -z "$password" ]; then
            password=$(${SINGBOX_BIN} generate rand --hex 16)
            _info "已生成随机密码: ${password}"
        fi
    fi

    # === [公共] 隧道模式选择 ===
    echo ""
    echo "请选择隧道模式:"
    echo "  1. 临时隧道 (无需配置, 随机域名, 不稳定，重启失效)"
    echo "  2. 固定隧道 (需 Token, 自定义域名, 稳定持久，重启不失效)"
    read -p "请选择 [1/2] (默认: 1): " tunnel_mode
    tunnel_mode=${tunnel_mode:-1}

    local token=""
    local tunnel_domain=""
    local argo_type="temp"

    if [ "$tunnel_mode" == "2" ]; then
        argo_type="fixed"
        _info "您选择了 [固定隧道] 模式。"
        echo ""
        _info "请粘贴 Cloudflare Tunnel Token (支持直接粘贴CF网页端所给出的任何安装命令):"
        read -p "Token: " input_token
        # 自动提取 Token
        token=$(echo "$input_token" | grep -oE 'ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | head -1)
        if [ -z "$token" ]; then
             token=$(echo "$input_token" | grep -oE 'ey[A-Za-z0-9_-]{20,}' | head -1)
        fi
        if [ -z "$token" ]; then
             token="$input_token"
        fi

        if [ -z "$token" ]; then _error "Token 不能为空"; return 1; fi
        _info "已识别 Token (前20位): ${token:0:20}..."

        echo ""
        _info "请输入该 Tunnel 绑定的域名 (用于生成客户端配置):"
        read -p "域名 (例如 tunnel.example.com): " input_domain
        if [ -z "$input_domain" ]; then _error "域名不能为空"; return 1; fi
        tunnel_domain="$input_domain"

        echo ""
        _info "【重要提示】请务必去 Cloudflare Dashboard 配置该 Tunnel 的 Public Hostname:"
        _info "  Public Hostname: ${tunnel_domain}"
        _info "  Service: http://localhost:${port}"
        echo ""
        read -n 1 -s -r -p "确认配置无误后，按任意键继续..."
        echo ""
    else
        _info "您选择了 [临时隧道] 模式。"
    fi

    # === [公共] 节点名称 ===
    local default_prefix="Argo-Temp"
    if [ "$argo_type" == "fixed" ]; then
        default_prefix="Argo-Fixed"
    fi
    local default_name="${default_prefix}-${proto_name}-${port}"

    echo ""
    read -p "请输入节点名称 (默认: ${default_name}): " custom_name
    local name=${custom_name:-$default_name}

    # === [协议特定] 生成凭据、tag 和 Inbound ===
    local tag="argo-${protocol}-ws-${port}"
    local uuid=""
    local inbound_json=""

    if [ "$protocol" == "vless" ]; then
        uuid=$(${SINGBOX_BIN} generate uuid)
        inbound_json=$(jq -n \
            --arg t "$tag" \
            --arg p "$port" \
            --arg u "$uuid" \
            --arg wsp "$ws_path" \
            --argjson ed "$WS_EARLY_DATA_SIZE" \
            --arg edh "$WS_EARLY_DATA_HEADER" \
            '{
                "type": "vless",
                "tag": $t,
                "listen": "127.0.0.1",
                "listen_port": ($p|tonumber),
                "users": [{"uuid": $u, "flow": ""}],
                "transport": {
                    "type": "ws",
                    "path": $wsp,
                    "max_early_data": $ed,
                    "early_data_header_name": $edh
                }
            }')
    elif [ "$protocol" == "trojan" ]; then
        inbound_json=$(jq -n \
            --arg t "$tag" \
            --arg p "$port" \
            --arg pw "$password" \
            --arg wsp "$ws_path" \
            --argjson ed "$WS_EARLY_DATA_SIZE" \
            --arg edh "$WS_EARLY_DATA_HEADER" \
            '{
                "type": "trojan",
                "tag": $t,
                "listen": "127.0.0.1",
                "listen_port": ($p|tonumber),
                "users": [{"password": $pw}],
                "transport": {
                    "type": "ws",
                    "path": $wsp,
                    "max_early_data": $ed,
                    "early_data_header_name": $edh
                }
            }')
    fi

    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1

    # === [公共] 重启 + 启动隧道 ===
    if ! _manage_service "restart"; then
        _error "sing-box 服务重启失败，无法创建 Argo 节点。"
        _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$tag\"))" >/dev/null 2>&1 || true
        return 1
    fi
    sleep 2

    if [ "$argo_type" == "fixed" ]; then
        if ! _start_argo_tunnel "$port" "${protocol}-ws" "$token"; then
             _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$tag\"))"
             _manage_service "restart"
             return 1
        fi
    else
        local real_domain=$(_start_argo_tunnel "$port" "${protocol}-ws")
        if [ -z "$real_domain" ] || [ "$real_domain" == "" ]; then
            _error "隧道启动失败，正在回滚配置..."
            _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$tag\"))"
            _manage_service "restart"
            return 1
        fi
        tunnel_domain="$real_domain"
    fi

    # === [协议特定] 保存元数据 ===
    local credential_key="" credential_val=""
    if [ "$protocol" == "vless" ]; then
        credential_key="uuid"; credential_val="$uuid"
    else
        credential_key="password"; credential_val="$password"
    fi

    local argo_meta=$(jq -n \
        --arg tag "$tag" \
        --arg name "$name" \
        --arg domain "$tunnel_domain" \
        --arg port "$port" \
        --arg cred_val "$credential_val" \
        --arg cred_key "$credential_key" \
        --arg path "$ws_path" \
        --arg protocol "${protocol}-ws" \
        --arg type "$argo_type" \
        --arg token "$token" \
        --arg created "$(date '+%Y-%m-%d %H:%M:%S')" \
        '{($tag): {name: $name, domain: $domain, local_port: ($port|tonumber), ($cred_key): $cred_val, path: $path, protocol: $protocol, type: $type, token: $token, created_at: $created}}')

    if [ ! -f "$ARGO_METADATA_FILE" ]; then
        echo '{}' > "$ARGO_METADATA_FILE"
    fi
    _atomic_modify_json "$ARGO_METADATA_FILE" ". + $argo_meta" || return 1

    # === [协议特定] Clash 配置 + 分享链接 ===
    local proxy_json=""
    if [ "$protocol" == "vless" ]; then
        proxy_json=$(jq -n \
            --arg n "$name" \
            --arg s "$tunnel_domain" \
            --arg u "$uuid" \
            --arg wsp "$ws_path" \
            --argjson ed "$WS_EARLY_DATA_SIZE" \
            --arg edh "$WS_EARLY_DATA_HEADER" \
            '{
                "name": $n,
                "type": "vless",
                "server": $s,
                "port": 443,
                "uuid": $u,
                "tls": true,
                "udp": true,
                "skip-cert-verify": false,
                "network": "ws",
                "servername": $s,
                "ws-opts": {
                    "path": $wsp,
                    "max-early-data": $ed,
                    "early-data-header-name": $edh,
                    "headers": {
                        "Host": $s
                    }
                }
            }')
    elif [ "$protocol" == "trojan" ]; then
        proxy_json=$(jq -n \
            --arg n "$name" \
            --arg s "$tunnel_domain" \
            --arg pw "$password" \
            --arg wsp "$ws_path" \
            --argjson ed "$WS_EARLY_DATA_SIZE" \
            --arg edh "$WS_EARLY_DATA_HEADER" \
            '{
                "name": $n,
                "type": "trojan",
                "server": $s,
                "port": 443,
                "password": $pw,
                "udp": true,
                "skip-cert-verify": false,
                "network": "ws",
                "sni": $s,
                "ws-opts": {
                    "path": $wsp,
                    "max-early-data": $ed,
                    "early-data-header-name": $edh,
                    "headers": {
                        "Host": $s
                    }
                }
            }')
    fi

    _add_node_to_yaml "$proxy_json" || return 1

    # === [公共] 启用守护 + 显示结果 ===
    _enable_argo_watchdog

    echo ""
    _info "${protocol_label} + Argo 节点配置已写入，等待服务校验..."
    echo "-------------------------------------------"
    echo -e "节点名称: ${GREEN}${name}${NC}"
    echo -e "隧道类型: ${CYAN}${argo_type}${NC}"
    echo -e "隧道域名: ${CYAN}${tunnel_domain}${NC}"
    echo -e "本地端口: ${port}"
    echo "-------------------------------------------"
    
    # 使用统一链接生成器进行展示与持久化
    if [ "$protocol" == "vless" ]; then
        _show_node_link "vless-ws" "$name" "$tunnel_domain" "443" "$tag" "$uuid" "$ws_path"
    else
        _show_node_link "trojan-ws" "$name" "$tunnel_domain" "443" "$tag" "$password" "$ws_path"
    fi
    
    echo "-------------------------------------------"
    if [ "$argo_type" == "temp" ]; then
        _warning "注意: 临时隧道每次重启域名会变化！"
    fi
}

# 保留原始函数名作为薄包装器，确保向后兼容
_add_argo_vless_ws() { _add_argo_node "vless"; }

_add_argo_trojan_ws() { _add_argo_node "trojan"; }

_view_argo_nodes() {
    _info "--- Argo 隧道节点信息 ---"
    
    if [ ! -f "$ARGO_METADATA_FILE" ] || [ "$(jq 'length' "$ARGO_METADATA_FILE")" -eq 0 ]; then
        _warning "没有 Argo 隧道节点。"
        return
    fi
    
    echo "==================================================="
    # 遍历并显示
    jq -r 'to_entries[] | "\(.key)|\(.value.name)|\(.value.type)|\(.value.protocol)|\(.value.local_port)|\(.value.domain)|\(.value.uuid // "")|\(.value.path // "")|\(.value.password // "")"' "$ARGO_METADATA_FILE" | \
    while IFS='|' read -r tag name argo_type protocol port domain uuid path password; do
        echo -e "节点: ${GREEN}${name}${NC}"
        echo -e "  协议: ${protocol}"
        echo -e "  端口: ${port}"
        
        # 检查状态
        local pid_file="/tmp/singbox_argo_${port}.pid"
        local state="${RED}已停止${NC}"
        local running_domain=""
        
        # [M4] 一次读取 PID 到变量，避免重复 cat
        local pid=""
        if [ -f "$pid_file" ]; then pid=$(cat "$pid_file" 2>/dev/null); fi
        if _is_pid_running_cmd "$pid" "$CLOUDFLARED_BIN"; then
             state="${GREEN}运行中${NC} (PID: $pid)"
             # 如果是临时的，尝试从 log 读最新域名
             if [ "$argo_type" == "temp" ] || [ -z "$domain" ] || [ "$domain" == "null" ]; then
                  local log_file="/tmp/singbox_argo_${port}.log"
                  local temp_domain=$(grep -o 'https://[a-zA-Z0-9-]*\.trycloudflare\.com' "$log_file" 2>/dev/null | tail -1 | sed 's|https://||')
                   [ -n "$temp_domain" ] && domain="$temp_domain"
             fi
             running_domain="$domain"
        fi
        
        if [ -n "$domain" ] && [ "$domain" != "null" ]; then
             local link=""
             
             # [新架构] 优先使用持久化链接
             link=$(jq -r --arg t "$tag" '.[$t].share_link // empty' "$ARGO_METADATA_FILE")
             
              if [ -z "$link" ] || [ "$link" == "null" ]; then
                  local safe_name=$(_url_encode "$name")
                  local ed_path=$(_ws_path_with_early_data "$path")
                  local safe_path=$(_url_encode "$ed_path")
                  
                  if [[ "$protocol" == "vless-ws" ]]; then
                      link="vless://${uuid}@${domain}:443?encryption=none&security=tls&type=ws&host=${domain}&path=${safe_path}&sni=${domain}#${safe_name}"
                 elif [[ "$protocol" == "trojan-ws" ]]; then
                     local safe_pw=$(_url_encode "$password")
                     link="trojan://${safe_pw}@${domain}:443?security=tls&type=ws&host=${domain}&path=${safe_path}&sni=${domain}#${safe_name}"
                 fi
             fi

             if [ -n "$link" ]; then
                  echo -e "  ${YELLOW}链接:${NC} $link"
             fi
        fi
        echo "-------------------------------------------"
    done
    
    echo -e "${YELLOW}提示: 请使用 [9] 重启隧道 来刷新所有节点状态或获取新临时域名。${NC}"
    echo "==================================================="
}

_delete_argo_node() {
    if [ ! -f "$ARGO_METADATA_FILE" ] || [ "$(jq 'length' "$ARGO_METADATA_FILE")" -eq 0 ]; then
        _warning "没有 Argo 隧道节点可删除。"
        return
    fi
    
    _info "--- 删除 Argo 隧道节点 ---"
    
    # 读取所有节点到数组
    local i=1
    local keys=()
    local names=()
    local ports=()
    
    # 必须使用 while read 处理 process substitution 避免子 shell 问题
    while IFS='|' read -r key name port; do
        keys+=("$key")
        names+=("$name")
        ports+=("$port")
        echo -e " ${CYAN}$i)${NC} ${name} (端口: $port)"
        ((i++))
    done < <(jq -r 'to_entries[] | "\(.key)|\(.value.name)|\(.value.local_port)"' "$ARGO_METADATA_FILE")
    
    if [ ${#keys[@]} -eq 0 ]; then
         _warning "读取元数据失败。"
         return
    fi

    echo " 0) 返回"
    read -p "请选择要删除的节点: " choice
    
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -gt "${#keys[@]}" ]; then
        _error "无效输入"
        return
    fi
    
    if [ "$choice" -eq 0 ]; then return; fi
    
    local idx=$((choice - 1))
    local selected_key="${keys[$idx]}"
    local selected_name="${names[$idx]}"
    local selected_port="${ports[$idx]}"
    
    _info "正在删除节点: ${selected_name} (端口: ${selected_port})..."
    
    # 1. 停止该节点的隧道进程
    _stop_argo_tunnel "$selected_port"
    
    # 2. 从 sing-box 配置文件中移除 inbound
    _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$selected_key\"))"
    
    # 3. 删除 Argo 元数据
    jq "del(.\"$selected_key\")" "$ARGO_METADATA_FILE" > "${ARGO_METADATA_FILE}.tmp" && mv "${ARGO_METADATA_FILE}.tmp" "$ARGO_METADATA_FILE"
    
    # 4. 删除 Clash 配置
    _remove_node_from_yaml "$selected_name"
    
    # 5. 检查是否还有节点，如果没有则禁用守护进程
    if [ "$(jq 'length' "$ARGO_METADATA_FILE" 2>/dev/null)" -eq 0 ]; then
        _disable_argo_watchdog
    fi

    # 6. 重启 sing-box
    _manage_service "restart"
    
    _success "节点 ${selected_name} 已删除！"
}

_stop_argo_menu() {
    _info "--- 停止 Argo 隧道进程 (保留配置) ---"
    # 复用选择逻辑
    local i=1
    local keys=()
    local names=()
    local ports=()
    
    while IFS='|' read -r key name port; do
        keys+=("$key")
        names+=("$name")
        ports+=("$port")
        echo -e " ${CYAN}$i)${NC} ${name} (端口: $port)"
        ((i++))
    done < <(jq -r 'to_entries[] | "\(.key)|\(.value.name)|\(.value.local_port)"' "$ARGO_METADATA_FILE")
    
    echo " a) 停止所有运行中的隧道"
    echo " 0) 返回"
    read -p "请选择: " choice
    
    if [ "$choice" == "a" ]; then
        _stop_all_argo_tunnels
        _success "所有隧道已停止指令发送。"
        return
    fi
    
    if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 0 ] || [ "$choice" -gt "${#keys[@]}" ]; then
        _error "无效输入"
        return
    fi
    if [ "$choice" -eq 0 ]; then return; fi
    
    local idx=$((choice - 1))
    local selected_port="${ports[$idx]}"
    
    _stop_argo_tunnel "$selected_port"
}

_restart_argo_tunnel_menu() {
    _info "--- 重启 Argo 隧道 ---"
    
     if [ ! -f "$ARGO_METADATA_FILE" ] || [ "$(jq 'length' "$ARGO_METADATA_FILE")" -eq 0 ]; then
        _warning "没有 Argo 隧道节点。"
        return
    fi

    # 选择逻辑
    local i=1
    local keys=()
    local names=()
    local ports=()
    local protocols=()
    local types=()
    local tokens=()
    
    while IFS='|' read -r key name port proto type token; do
        keys+=("$key")
        names+=("$name")
        ports+=("$port")
        protocols+=("$proto")
        types+=("$type")
        tokens+=("$token")
        echo -e " ${CYAN}$i)${NC} ${name} (端口: $port)"
        ((i++))
    done < <(jq -r 'to_entries[] | "\(.key)|\(.value.name)|\(.value.local_port)|\(.value.protocol)|\(.value.type)|\(.value.token)"' "$ARGO_METADATA_FILE")
    
    echo " a) 重启所有节点"
    echo " 0) 返回"
    read -p "请选择: " choice
    
    local selected_indices=()
    if [ "$choice" == "a" ]; then
        # 生成所有索引
        for ((j=0; j<${#keys[@]}; j++)); do selected_indices+=($j); done
    elif [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -gt 0 ] && [ "$choice" -le "${#keys[@]}" ]; then
        selected_indices+=($((choice - 1)))
    else
        if [ "$choice" -ne 0 ]; then _error "无效输入"; fi
        return
    fi

    # 增强参数提取，为同步链接做准备
    local names=() ports=() protocols=() types=() tokens=() tags=() uuids=() passwords=() paths=()
    while IFS='|' read -r key name port proto type token uuid pw path; do
        tags+=("$key")
        names+=("$name")
        ports+=("$port")
        protocols+=("$proto")
        types+=("$type")
        tokens+=("$token")
        uuids+=("$uuid")
        passwords+=("$pw")
        paths+=("$path")
    done < <(jq -r 'to_entries[] | "\(.key)|\(.value.name)|\(.value.local_port)|\(.value.protocol)|\(.value.type)|\(.value.token // "")|\(.value.uuid // "")|\(.value.password // "")|\(.value.path // "")"' "$ARGO_METADATA_FILE")

    for i in "${!selected_indices[@]}"; do
        local idx="${selected_indices[$i]}"
        local tag="${tags[$idx]}"
        local name="${names[$idx]}"
        local port="${ports[$idx]}"
        local proto_full="${protocols[$idx]}"
        local type="${types[$idx]}"
        local token="${tokens[$idx]}"
        local uuid="${uuids[$idx]}"
        local password="${passwords[$idx]}"
        local ws_path="${paths[$idx]}"
        
        # 提取 protocol 简写用于 _start_argo_tunnel (vless/trojan)
        local proto_short="vless"
        [[ "$proto_full" == "trojan-ws" ]] && proto_short="trojan"

        _info "正在重启: $name (端口: $port)..."
        
        # 停止
        _stop_argo_tunnel "$port"
        sleep 1
        
        # 启动
        local new_domain=""
        if [ "$type" == "fixed" ]; then
            if _start_argo_tunnel "$port" "$proto_short-ws" "$token"; then
                 new_domain=$(jq -r ".\"$tag\".domain" "$ARGO_METADATA_FILE")
            else
                 _error "固定隧道重启失败: $name"
            fi
        else
            new_domain=$(_start_argo_tunnel "$port" "$proto_short-ws")
            if [ -n "$new_domain" ]; then
                 _atomic_modify_json "$ARGO_METADATA_FILE" ".\"$tag\".domain = \"$new_domain\""
                 _success "更新临时域名: $new_domain"
                 
                 # [同步链接] 临时域名变动，立即重新持久化链接
                 if [[ "$proto_full" == "vless-ws" ]]; then
                     _show_node_link "vless-ws" "$name" "$new_domain" "443" "$tag" "$uuid" "$ws_path" >/dev/null
                 else
                     _show_node_link "trojan-ws" "$name" "$new_domain" "443" "$tag" "$password" "$ws_path" >/dev/null
                 fi
            else
                 _error "临时隧道重启失败: $name"
            fi
        fi
    done
    _success "操作完成。"
}

# --- Argo 守护进程逻辑 ---

_argo_keepalive() {
    # --- 性能优化: 互斥锁 ---
    local lock_dir="/tmp/singbox_keepalive.lock"
    if ! mkdir "$lock_dir" 2>/dev/null; then
        # 锁目录存在，等待所有权文件写入
        sleep 0.1 2>/dev/null || sleep 1
        local pid=""
        [ -f "$lock_dir/pid" ] && pid=$(cat "$lock_dir/pid" 2>/dev/null)
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            # 进程仍在运行，跳过本次执行
            return
        fi
        # 进程已死，强制清除残留锁目录并重试
        rm -rf "$lock_dir" 2>/dev/null
        mkdir -p "$lock_dir" 2>/dev/null || return
    fi
    echo "$$" > "$lock_dir/pid"
    # 确保退出时删除锁
    trap 'rm -rf "$lock_dir"' RETURN EXIT

    # --- 性能优化: 日志轮转 (10MB) ---
    local max_size=$((10 * 1024 * 1024))
    for log in "$LOG_FILE" "$ARGO_LOG_FILE"; do
        if [ -f "$log" ] && [ $(wc -c < "$log" 2>/dev/null || echo 0) -ge $max_size ]; then
            tail -n 1000 "$log" > "${log}.tmp" && mv "${log}.tmp" "$log"
        fi
    done

    # 如果元数据文件不存在或为空，不需要守护
    if [ ! -f "$ARGO_METADATA_FILE" ] || [ "$(jq 'length' "$ARGO_METADATA_FILE" 2>/dev/null)" -eq 0 ]; then
        return
    fi

    # 遍历所有节点
    local i=0
    # [资源优化] 合并提取所有必要元数据，支持域名链接同步
    while IFS=$'\t' read -r tag port type token protocol name uuid password path; do
        [ -z "$tag" ] && continue
        
        local pid_file="/tmp/singbox_argo_${port}.pid"
        local is_running=false
        
        if [ -f "$pid_file" ]; then
            local pid=$(cat "$pid_file" 2>/dev/null)
            if _is_pid_running_cmd "$pid" "$CLOUDFLARED_BIN"; then
                is_running=true
            fi
        fi
        
        if [ "$is_running" = false ]; then
            logger "sing-box-watchdog: Detected dead tunnel for $tag (Port: $port). Restarting..."
            
            # 提取 protocol 简写用于 _start_argo_tunnel (vless/trojan)
            local proto_short="vless"
            [[ "$protocol" == "trojan-ws" ]] && proto_short="trojan"

            if [ "$type" == "fixed" ] && [ -n "$token" ]; then
                 if _start_argo_tunnel "$port" "$proto_short-ws" "$token"; then
                     logger "sing-box-watchdog: Fixed tunnel $tag restarted successfully."
                 else
                     logger "sing-box-watchdog: Failed to restart fixed tunnel $tag."
                 fi
            else
                 # 临时隧道
                 local new_domain=$(_start_argo_tunnel "$port" "$proto_short-ws")
                 if [ -n "$new_domain" ]; then
                      # 更新元数据
                      _atomic_modify_json "$ARGO_METADATA_FILE" ".\"$tag\".domain = \"$new_domain\""
                      logger "sing-box-watchdog: Temp tunnel $tag restarted with new domain: $new_domain"
                      
                      # [同步链接] 临时域名变动，静默更新持久化链接
                      if [[ "$protocol" == "vless-ws" ]]; then
                          _show_node_link "vless-ws" "$name" "$new_domain" "443" "$tag" "$uuid" "$path" >/dev/null
                      else
                          _show_node_link "trojan-ws" "$name" "$new_domain" "443" "$tag" "$password" "$path" >/dev/null
                      fi
                 else
                      logger "sing-box-watchdog: Failed to restart temp tunnel $tag."
                 fi
            fi
        fi
    done < <(jq -r 'to_entries[] | [.key, (.value.local_port|tostring), (.value.type // ""), (.value.token // ""), (.value.protocol // "vless-ws"), .value.name, (.value.uuid // ""), (.value.password // ""), (.value.path // "")] | @tsv' "$ARGO_METADATA_FILE" 2>/dev/null)
}

_enable_argo_watchdog() {
    # 检查 crontab 是否已有任务
    local job="* * * * * bash ${SELF_SCRIPT_PATH} keepalive >/dev/null 2>&1"
    
    if ! crontab -l 2>/dev/null | grep -Fq "$job"; then
        _info "正在添加后台守护进程 (Watchdog)..."
        (crontab -l 2>/dev/null; echo "$job") | crontab -
        if [ $? -eq 0 ]; then
            _success "守护进程已启用！(每分钟检查并自动修复失效隧道)"
        else
            _warning "添加 Crontab 失败，守护进程未生效。"
        fi
    fi
}

_disable_argo_watchdog() {
    local job="bash ${SELF_SCRIPT_PATH} keepalive"
    
    if crontab -l 2>/dev/null | grep -Fq "$job"; then
        _info "正在移除后台守护进程..."
        crontab -l 2>/dev/null | grep -Fv "$job" | crontab -
        _success "守护进程已移除。"
    fi
}

_uninstall_argo() {
    _warning "！！！警告！！！"
    _warning "本操作将删除所有 Argo 隧道节点和 cloudflared 程序。"
    echo ""
    echo "即将删除的内容："
    echo -e "  ${RED}-${NC} cloudflared 程序: ${CLOUDFLARED_BIN}"
    echo -e "  ${RED}-${NC} 所有 Argo 日志文件和元数据文件"
    
    if [ -f "$ARGO_METADATA_FILE" ]; then
        local argo_count=$(jq 'length' "$ARGO_METADATA_FILE" 2>/dev/null || echo "0")
        echo -e "  ${RED}-${NC} Argo 节点数量: ${argo_count} 个"
    fi
    
    echo ""
    read -p "$(echo -e ${YELLOW}"确定要卸载 Argo 服务吗? (y/N): "${NC})" confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        _info "卸载已取消。"
        return
    fi
    
    _info "正在卸载 Argo 服务..."
    
    # 1. 停止所有隧道进程
    _stop_all_argo_tunnels
    
    # 2. 删除 sing-box 中的 Argo inbound 配置
    if [ -f "$ARGO_METADATA_FILE" ]; then
         # 同样需要遍历删除逻辑，这里简化为遍历 metadata 删除
         # 为防止 jq 读写竞争，先收集所有 tags
        local tags=$(jq -r 'keys[]' "$ARGO_METADATA_FILE" 2>/dev/null)
        for tag in $tags; do
             if [ -n "$tag" ]; then
                _info "正在删除 Argo 隧道: $tag ..."
                # [修复] 先读取节点名，再删除元数据
                local node_name=$(jq -r ".\"$tag\".name" "$ARGO_METADATA_FILE" 2>/dev/null)
    _atomic_modify_json "$ARGO_METADATA_FILE" "del(.\""$tag"\")" 2>/dev/null
    _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$tag\"))"
                
                if [ -n "$node_name" ] && [ "$node_name" != "null" ]; then
                    _remove_node_from_yaml "$node_name"
                fi
             fi
        done
    fi
    
    # 3. 移除守护进程
    _disable_argo_watchdog

    # 4. 删除 cloudflared 和相关文件及服务
    _info "正在清理 cloudflared 文件及服务..."
    
    if command -v systemctl &>/dev/null; then
        systemctl stop cloudflared >/dev/null 2>&1
        systemctl disable cloudflared >/dev/null 2>&1
    fi
    
    _stop_all_argo_tunnels 2>/dev/null
    
    # 删除所有 PID/LOG 文件
    rm -f /tmp/singbox_argo_*.pid /tmp/singbox_argo_*.log
    rm -f "${CLOUDFLARED_BIN}" "${ARGO_METADATA_FILE}"
    rm -rf "/etc/cloudflared"
    
    # 4. 重启 sing-box
    _manage_service "restart"
    
    _success "Argo 服务已完全卸载！"
    _success "已释放 cloudflared 占用的空间。"
}

_view_argo_logs() {
    if [ ! -f "$ARGO_METADATA_FILE" ] || [ "$(jq 'length' "$ARGO_METADATA_FILE" 2>/dev/null)" -eq 0 ]; then
        _warning "当前没有任何 Argo 隧道节点。"
        return
    fi

    _info "--- 选择要查看日志的 Argo 隧道 ---"
    local tags=$(jq -r 'keys[]' "$ARGO_METADATA_FILE")
    local i=1
    local tag_list=()
    for tag in $tags; do
        local name=$(jq -r ".\"$tag\".name" "$ARGO_METADATA_FILE")
        local port=$(jq -r ".\"$tag\".local_port" "$ARGO_METADATA_FILE")
        echo "  ${i}) ${name} (端口: ${port})"
        tag_list[$i]=$tag
        ((i++))
    done
    echo "  0) 返回上级菜单"
    read -p "请输入选项: " log_choice
    [[ "$log_choice" == "0" || -z "$log_choice" ]] && return

    local selected_tag=${tag_list[$log_choice]}
    if [ -n "$selected_tag" ]; then
        local port=$(jq -r ".\"$selected_tag\".local_port" "$ARGO_METADATA_FILE")
        local log_file="/tmp/singbox_argo_${port}.log"
        if [ -f "$log_file" ]; then
            _info "正在查看隧道日志 [${selected_tag}]，按 Ctrl+C 退出。"
            tail -f "$log_file"
        else
            _error "日志文件不存在: ${log_file}"
        fi
    else
        _error "无效选项"
    fi
}

_sync_argo_early_data() {
    local config_updated=false
    local links_updated=false
    local yaml_updated=false

    export WS_ED="$WS_EARLY_DATA_SIZE"
    export WS_EDH="$WS_EARLY_DATA_HEADER"

    if [ -s "$CONFIG_FILE" ] && jq -e 'any(.inbounds[]?; ((.tag // "" | startswith("argo-")) and ((.transport.type // "") == "ws") and (((.transport.max_early_data // 0) != (env.WS_ED | tonumber)) or ((.transport.early_data_header_name // "") != env.WS_EDH))))' "$CONFIG_FILE" >/dev/null 2>&1; then
        _atomic_modify_json "$CONFIG_FILE" '(.inbounds[] | select((.tag // "" | startswith("argo-")) and ((.transport.type // "") == "ws")) | .transport.max_early_data) = (env.WS_ED | tonumber) | (.inbounds[] | select((.tag // "" | startswith("argo-")) and ((.transport.type // "") == "ws")) | .transport.early_data_header_name) = env.WS_EDH' || return 1
        config_updated=true
    fi

    if [ -s "$ARGO_METADATA_FILE" ]; then
        while IFS=$'\t' read -r tag protocol name domain uuid password path share_link; do
            [ -z "$tag" ] && continue
            [[ "$protocol" != "vless-ws" && "$protocol" != "trojan-ws" ]] && continue
            [[ -z "$domain" || "$domain" == "null" ]] && continue

            if [ -s "$CLASH_YAML_FILE" ] && [ -x "$YQ_BINARY" ] && [ -n "$name" ] && [ "$name" != "null" ]; then
                export PROXY_NAME="$name"
                local yaml_needs_update
                yaml_needs_update=$(${YQ_BINARY} eval '.proxies[] | select(.name == env(PROXY_NAME) and .network == "ws" and (((.["ws-opts"]["max-early-data"] // "") | tostring) != strenv(WS_ED) or (.["ws-opts"]["early-data-header-name"] // "") != env(WS_EDH))) | .name' "$CLASH_YAML_FILE" 2>/dev/null | head -n 1)
                if [ -n "$yaml_needs_update" ] && [ "$yaml_needs_update" != "null" ]; then
                    _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(PROXY_NAME) and .network == "ws") | .["ws-opts"]["max-early-data"]) = (env(WS_ED) | tonumber) | (.proxies[] | select(.name == env(PROXY_NAME) and .network == "ws") | .["ws-opts"]["early-data-header-name"]) = env(WS_EDH)' >/dev/null 2>&1 && yaml_updated=true
                fi
            fi

            if [[ "$share_link" == *"ed%3D${WS_EARLY_DATA_SIZE}"* || "$share_link" == *"ed=${WS_EARLY_DATA_SIZE}"* ]]; then
                continue
            fi

            if [[ "$protocol" == "vless-ws" && -n "$uuid" && "$uuid" != "null" ]]; then
                _show_node_link "vless-ws" "$name" "$domain" "443" "$tag" "$uuid" "$path" >/dev/null
                links_updated=true
            elif [[ "$protocol" == "trojan-ws" && -n "$password" && "$password" != "null" ]]; then
                _show_node_link "trojan-ws" "$name" "$domain" "443" "$tag" "$password" "$path" >/dev/null
                links_updated=true
            fi
        done < <(jq -r 'to_entries[] | [.key, (.value.protocol // "vless-ws"), (.value.name // ""), (.value.domain // ""), (.value.uuid // ""), (.value.password // ""), (.value.path // "/"), (.value.share_link // "")] | @tsv' "$ARGO_METADATA_FILE" 2>/dev/null)
    fi

    if [ "$config_updated" = true ]; then
        _info "已为既有 Argo WS 节点补齐 Early Data 配置，正在重启 sing-box..."
        _manage_service restart
    elif [ "$links_updated" = true ] || [ "$yaml_updated" = true ]; then
        _info "已同步既有 Argo WS 节点的 Early Data 客户端配置。"
    fi
}

_argo_menu() {
    _sync_argo_early_data
    while true; do
        clear
        echo -e "${CYAN}"
        echo '  ╔═══════════════════════════════════════╗'
        echo '  ║           Argo 隧道节点管理           ║'
        echo '  ╚═══════════════════════════════════════╝'
        echo -e "${NC}"
        
        echo -e "  ${CYAN}【创建节点】${NC}"
        echo -e "    ${GREEN}[1]${NC} 创建 VLESS-WS + Argo 节点"
        echo -e "    ${GREEN}[2]${NC} 创建 Trojan-WS + Argo 节点"
        echo ""
        
        echo -e "  ${CYAN}【节点管理】${NC}"
        echo -e "    ${GREEN}[3]${NC} 查看 Argo 节点信息"
        echo -e "    ${GREEN}[4]${NC} 查看 Argo 隧道日志"
        echo -e "    ${GREEN}[5]${NC} 删除 Argo 节点"
        echo ""
        
        echo -e "  ${CYAN}【隧道控制】${NC}"
        echo -e "    ${RED}[6]${NC} 卸载 Argo 服务"
        echo -e "    ${GREEN}[7]${NC} 重启 Argo 隧道"
        echo ""
        
        echo -e "  ─────────────────────────────────────────"
        echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
        echo ""
        
        read -p "  请输入选项 [0-7]: " choice

        case $choice in
            1) _add_argo_vless_ws ;;
            2) _add_argo_trojan_ws ;;
            3) _view_argo_nodes ;;
            4) _view_argo_logs ;;
            5) _delete_argo_node ;;
            6) _uninstall_argo ;;
            7) _restart_argo_tunnel_menu ;;
            0) break ;;
            *) _error "无效选项" ;;
        esac
        echo ""
        read -n 1 -s -r -p "按任意键继续..."
    done
}

# --- 服务与配置管理 ---

_create_systemd_service() {
    local mem_limit_mb=$(_get_mem_limit)
    
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
Environment="GOMEMLIMIT=${mem_limit_mb}MiB"
Environment="ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true"
Environment="ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM=true"
Environment="ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true"
ExecStartPre=${SINGBOX_BIN} check -c ${CONFIG_FILE} -c ${SINGBOX_DIR}/relay.json
ExecStart=${SINGBOX_BIN} run -c ${CONFIG_FILE} -c ${SINGBOX_DIR}/relay.json
Restart=on-failure
RestartSec=3s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
}

_create_openrc_service() {
    # 确保日志文件存在
    touch "${LOG_FILE}"
    local mem_limit_mb=$(_get_mem_limit)
    
    cat > "$SERVICE_FILE" <<EOF
#!/sbin/openrc-run

description="sing-box service"
command="${SINGBOX_BIN}"
command_args="run -c ${CONFIG_FILE} -c ${SINGBOX_DIR}/relay.json"
# 使用 supervise-daemon 实现守护和重启
supervisor="supervise-daemon"
supervise_daemon_args="--env GOMEMLIMIT=${mem_limit_mb}MiB --env ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true --env ENABLE_DEPRECATED_OUTBOUND_DNS_RULE_ITEM=true --env ENABLE_DEPRECATED_MISSING_DOMAIN_RESOLVER=true"
respawn_delay=3
respawn_max=0

pidfile="${PID_FILE}"
# supervise-daemon 自动将 stdout/stderr 重定向功能需要 openrc 版本支持
# 如果不支持，日志可能不会输出到文件，但服务能正常运行
output_log="${LOG_FILE}"
error_log="${LOG_FILE}"

start_pre() {
    "${SINGBOX_BIN}" check -c "${CONFIG_FILE}" -c "${SINGBOX_DIR}/relay.json"
}

depend() {
    need net
    after firewall
}
EOF
    chmod +x "$SERVICE_FILE"
}

_create_service_files() {
    
    _info "正在创建 ${INIT_SYSTEM} 服务文件..."
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        _create_systemd_service
        systemctl daemon-reload
        systemctl enable sing-box
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        touch "$LOG_FILE"
        _create_openrc_service
        rc-update add sing-box default
    elif [ "$INIT_SYSTEM" == "direct" ]; then
        touch "$LOG_FILE"
        _info "当前容器没有 systemd/openrc，将使用 direct 后台模式管理 sing-box。"
        return 0
    fi
    _success "${INIT_SYSTEM} 服务创建并启用成功。"
}

# 每 48 小时清空一次本脚本产生的运行日志，避免小磁盘被持续写满。
_cleanup_runtime_logs() {
    local state_file="${SINGBOX_DIR}/.last_log_cleanup"
    local now last
    now=$(date +%s 2>/dev/null) || return 1
    last=$(cat "$state_file" 2>/dev/null)

    # 首次启用时立即清理一次，先释放可能已经被占满的磁盘空间。
    if ! [[ "$last" =~ ^[0-9]+$ ]]; then
        last=0
    fi
    [ $((now - last)) -lt 172800 ] && return 0

    local log
    for log in "$LOG_FILE" "$ARGO_LOG_FILE" /var/log/xray.log /tmp/singbox_argo_*.log; do
        [ -f "$log" ] && : > "$log"
    done
    printf '%s\n' "$now" > "$state_file"
}

_setup_log_cleanup() {
    command -v crontab >/dev/null 2>&1 || {
        _warning "未找到 crontab，无法启用每 2 天自动清理日志。"
        return 1
    }

    local tag="# sing-box-log-cleanup"
    local job="17 * * * * bash ${SELF_SCRIPT_PATH} cleanup-logs >/dev/null 2>&1 ${tag}"
    local current
    current=$(crontab -l 2>/dev/null || true)
    if ! printf '%s\n' "$current" | grep -Fq "$tag"; then
        { printf '%s\n' "$current"; printf '%s\n' "$job"; } | sed '/^$/d' | crontab - || return 1
    fi
    _cleanup_runtime_logs
}

_remove_log_cleanup() {
    local tag="# sing-box-log-cleanup"
    if command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -Fq "$tag"; then
        crontab -l 2>/dev/null | grep -Fv "$tag" | crontab -
    fi
    rm -f "${SINGBOX_DIR}/.last_log_cleanup"
}


# 注意: _manage_service 已在上方定义，此处不再重复定义

_view_log() {
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        _info "systemd 模式日志由 journal 管理；按 Ctrl+C 退出日志查看。"
        _info "诊断命令: journalctl -u sing-box -b --no-pager"
        journalctl -u sing-box -f --no-pager
    else # 适用于 openrc 和 direct 模式
        if [ ! -f "$LOG_FILE" ]; then
            _warning "日志文件 ${LOG_FILE} 不存在。"
            return
        fi
        _info "按 Ctrl+C 退出日志查看 (日志文件: ${LOG_FILE})。"
        tail -f "$LOG_FILE"
    fi
}

_uninstall() {
    _warning "！！！警告！！！"
    _warning "本操作将停止并禁用 [主脚本] 服务 (sing-box)，"
    _warning "删除所有相关文件 (包括二进制、组件脚本、别名及配置文件)。"
    
    echo ""
    echo "即将删除以下内容："
    echo -e "  ${RED}-${NC} 主配置与脚本目录: ${SINGBOX_DIR}"
    echo -e "  ${RED}-${NC} sing-box 二进制: ${SINGBOX_BIN}"
    echo -e "  ${RED}-${NC} yq 二进制: ${YQ_BINARY}"
    [ -f "${CLOUDFLARED_BIN}" ] && echo -e "  ${RED}-${NC} cloudflared 二进制: ${CLOUDFLARED_BIN}"
    [ -f "/usr/local/bin/xray" ] && echo -e "  ${RED}-${NC} Xray 核心及配置: /usr/local/etc/xray/"
    echo -e "  ${RED}-${NC} 系统别名: /usr/local/bin/sb"
    echo -e "  ${RED}-${NC} 管理脚本: ${SELF_SCRIPT_PATH}"
    echo ""
    
    read -p "$(echo -e ${YELLOW}"确定要执行卸载吗? (y/N): "${NC})" confirm_main
    [[ "$confirm_main" != "y" && "$confirm_main" != "Y" ]] && _info "卸载已取消。" && return

    # 1. 停止服务
    _manage_service "stop"
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        systemctl disable sing-box >/dev/null 2>&1
        systemctl daemon-reload
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        rc-update del sing-box default >/dev/null 2>&1
    fi

    # 2. 清理配置与日志
    _info "正在清理配置文件与日志..."
    _remove_log_cleanup
    # 清理脚本创建的 nftables 规则
    local pf_meta="${SINGBOX_DIR}/relay_pf.json"
    [ ! -f "$pf_meta" ] && pf_meta="${SINGBOX_DIR}/pf_metadata.json"
    if [ -f "$pf_meta" ] && command -v jq &>/dev/null; then
        # 清理 DNS 动态刷新的 cron 任务
        if crontab -l 2>/dev/null | grep -qF "# pf-dns-auto-refresh"; then
            crontab -l 2>/dev/null | grep -vF "# pf-dns-auto-refresh" | crontab -
        fi
    fi
    _remove_nftables_rules
    rm -rf "${SINGBOX_DIR}" "${LOG_FILE}"
    
    # 3. 清理 Argo 隧道
    if [ -f "${CLOUDFLARED_BIN}" ]; then
        _info "正在清理 Argo 隧道..."
        _disable_argo_watchdog 2>/dev/null
        _stop_all_argo_tunnels 2>/dev/null
        rm -f "${CLOUDFLARED_BIN}"
        rm -rf "/etc/cloudflared"
    fi

    # 4. 清理 Xray 核心 (如果已安装)
    if [ -f "/usr/local/bin/xray" ]; then
        _info "正在清理 Xray 核心..."
        if [ "$INIT_SYSTEM" == "systemd" ]; then
            systemctl stop xray 2>/dev/null
            systemctl disable xray 2>/dev/null
            rm -f /etc/systemd/system/xray.service
            systemctl daemon-reload
        elif [ "$INIT_SYSTEM" == "openrc" ]; then
            rc-service xray stop 2>/dev/null
            rc-update del xray default 2>/dev/null
            rm -f /etc/init.d/xray
        fi
        rm -f "/usr/local/bin/xray"
        rm -rf "/usr/local/etc/xray"
    fi

    # 5. 清理组件脚本与别名 (双重清理，防止目录合并后的物理残留)
    _info "正在清理周边环境..."
    rm -f "${SINGBOX_DIR}/parser.sh" "${SINGBOX_DIR}/advanced_relay.sh" "${SINGBOX_DIR}/xray_manager.sh"
    rm -f "${SCRIPT_DIR}/parser.sh" "${SCRIPT_DIR}/advanced_relay.sh" "${SCRIPT_DIR}/xray_manager.sh"
    rm -f "/usr/local/bin/sb"
    
    # 5. 复原 MOTD
    if [ -f "/etc/motd" ]; then
        sed -i '/sing-box 节点信息/d' /etc/motd 2>/dev/null
        sed -i '/====/d' /etc/motd 2>/dev/null
        sed -i '/Base64 订阅/d' /etc/motd 2>/dev/null
    fi

    # 6. 处理主程序 (考虑与线路机共用)
    local relay_script="/root/relay-install.sh"
    if [ -f "$relay_script" ]; then
        _warn "检测到 [线路机] 脚本存在，为保持其运行，将 [保留] sing-box 主程序。"
    else
        _info "正在删除 sing-box 主程序..."
        rm -f "${SINGBOX_BIN}" "${YQ_BINARY}"
    fi

    _success "清理完成。脚本已自毁。再见！"
    [ -f "${SELF_SCRIPT_PATH}" ] && rm -f "${SELF_SCRIPT_PATH}"
    exit 0
}

_initialize_config_files() {
    mkdir -p ${SINGBOX_DIR}
    if [ ! -s "$CONFIG_FILE" ]; then
        # 初始化包含完整 dns 配置和路由策略的基础文件，以支持中转第三方域名节点
        cat > "$CONFIG_FILE" << 'EOF'
{
  "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m"
  },
  "dns": {
    "servers": [
      {
        "type": "local",
        "tag": "dns-local",
        "prefer_go": true
      }
    ],
    "final": "dns-local",
    "strategy": "prefer_ipv4"
  },
  "inbounds": [],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [],
    "final": "direct",
    "default_domain_resolver": {
      "server": "dns-local",
      "strategy": "prefer_ipv4"
    }
  }
}
EOF
    fi
    [ -s "$METADATA_FILE" ] || echo "{}" > "$METADATA_FILE"
    
    # [关键修复] 初始化 relay.json - 服务启动命令会加载这个文件
    # 必须确保在服务运行前此文件物理存在，否则 sing-box 会 Fatal 退出
    local RELAY_JSON="${SINGBOX_DIR}/relay.json"
    if [ ! -s "$RELAY_JSON" ]; then
        echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "$RELAY_JSON"
        _info "已初始化中转配置文件: $RELAY_JSON"
    fi
    if [ ! -s "$CLASH_YAML_FILE" ]; then
        _info "正在创建全新的 clash.yaml 配置文件..."
        cat > "$CLASH_YAML_FILE" << 'EOF'
port: 7890
socks-port: 7891
mixed-port: 7892
allow-lan: false
bind-address: '*'
mode: rule
log-level: info
ipv6: true
find-process-mode: strict
external-controller: '127.0.0.1:9090'
profile:
  store-selected: true
  store-fake-ip: true
unified-delay: true
tcp-concurrent: true
ntp:
  enable: true
  write-to-system: false
  server: ntp.aliyun.com
  port: 123
  interval: 30
dns:
  enable: true
  respect-rules: true
  use-system-hosts: true
  prefer-h3: false
  listen: '0.0.0.0:1053'
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  use-hosts: true
  fake-ip-filter:
    - +.lan
    - +.local
    - localhost.ptlogin2.qq.com
    - +.msftconnecttest.com
    - +.msftncsi.com
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
    - 'https://1.1.1.1/dns-query'
    - 'https://dns.quad9.net/dns-query'
  default-nameserver:
    - 1.1.1.1
    - 8.8.8.8
  proxy-server-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - 'https://1.0.0.1/dns-query'
    - 'https://9.9.9.10/dns-query'
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true
  strict-route: false
  dns-hijack:
    - 'any:53'
  device: SakuraiTunnel
  endpoint-independent-nat: true
proxies: []
proxy-groups:
  - name: 节点选择
    type: select
    proxies: []
rules:
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,节点选择
EOF
    fi
}

_init_relay_config() {
    # 确保中转配置文件存在 (隔离配置)
    if [ ! -s "${SINGBOX_DIR}/relay.json" ]; then
        echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "${SINGBOX_DIR}/relay.json"
        _info "已初始化中转配置文件"
    fi
}

_cleanup_legacy_config() {
    # 检查并清理 config.json 中残留的旧版中转配置 (tag 以 relay-out- 开头的 outbound)
    # 这些残留会导致路由冲突，使主脚本节点误走中转线路
    local needs_restart=false
    
    if jq -e '.outbounds[] | select(.tag | startswith("relay-out-"))' "$CONFIG_FILE" >/dev/null 2>&1; then
        _warn "检测到旧版中转残留配置，正在清理..."
        cp "$CONFIG_FILE" "${CONFIG_FILE}.bak_legacy"
        
        # 删除所有 relay-out- 开头的 outbounds
        jq 'del(.outbounds[] | select(.tag | startswith("relay-out-")))' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        
        # 删除所有 relay-out- 开头的路由规则 (如果有)
        if jq -e '.route.rules' "$CONFIG_FILE" >/dev/null 2>&1; then
            jq 'del(.route.rules[] | select(.outbound | startswith("relay-out-")))' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        fi
        
        # 确保存在 direct 出站且位于第一位 (如果没有 direct，添加一个)
        if ! jq -e '.outbounds[] | select(.tag == "direct")' "$CONFIG_FILE" >/dev/null 2>&1; then
             jq '.outbounds = [{"type":"direct","tag":"direct"}] + .outbounds' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        fi
        
        _success "配置清理完成。相关中转已被迁移至独立配置文件 (relay.json)。"
        needs_restart=true
    fi
    
    # [关键修复] 确保 route.final 设置为 "direct"
    # 这是核心修复：当 config.json 和 relay.json 合并时，relay-out-* outbound 会被插入到 outbounds 列表前面
    # 如果没有 route.final，sing-box 会使用列表中的第一个 outbound 作为默认出口，导致主节点流量走中转
    if ! jq -e '.route.final == "direct"' "$CONFIG_FILE" >/dev/null 2>&1; then
        _warn "检测到 route.final 未设置或不正确，正在修复..."
        
        # 确保 route 对象存在
        if ! jq -e '.route' "$CONFIG_FILE" >/dev/null 2>&1; then
            jq '. + {"route":{"rules":[],"final":"direct"}}' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        else
            # 设置 route.final = "direct"
            jq '.route.final = "direct"' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        fi
        
        _success "route.final 已设置为 direct，主节点流量将走本机 IP。"
        needs_restart=true
    fi
    
    if [ "$needs_restart" = true ]; then
        return 0
    fi
    return 1
}

# 将旧版 DNS address 字符串转换为 sing-box 1.12+ 类型化 DNS 服务器 JSON
# 用法: _dns_address_to_server_json <address> [tag]，失败返回非 0
_dns_address_to_server_json() {
    local address="$1"
    local tag="${2:-dns-local}"
    local scheme="" rest="" hostport="" host="" port="" path=""

    case "$address" in
        ""|local)
            jq -n --arg tag "$tag" '{type:"local", tag:$tag, prefer_go:true}'
            return 0 ;;
        *"://"*)
            scheme="${address%%://*}"
            rest="${address#*://}" ;;
        *)
            scheme="udp"
            rest="$address" ;;
    esac

    hostport="${rest%%/*}"
    [[ "$rest" == */* ]] && path="/${rest#*/}"

    if [[ "$hostport" == \[*\]* ]]; then
        host="${hostport%%]*}"; host="${host#[}"
        port="${hostport##*]}"; port="${port#:}"
    elif [[ "$hostport" == *:* ]]; then
        host="${hostport%%:*}"
        port="${hostport##*:}"
    else
        host="$hostport"
    fi
    [ -z "$host" ] && return 1
    [[ "$port" =~ ^[0-9]+$ ]] || port=""

    local type=""
    case "$scheme" in
        udp|tcp|tls|quic) type="$scheme" ;;
        https|h3) type="https" ;;
        *) return 1 ;;
    esac

    local jq_args=(--arg type "$type" --arg tag "$tag" --arg server "$host")
    local jq_filter='{type:$type, tag:$tag, server:$server}'
    if [ -n "$port" ]; then
        jq_args+=(--argjson port "$port")
        jq_filter+=' + {server_port:$port}'
    fi
    if [ "$type" = "https" ] && [ -n "$path" ] && [ "$path" != "/dns-query" ]; then
        jq_args+=(--arg path "$path")
        jq_filter+=' + {path:$path}'
    fi
    jq -n "${jq_args[@]}" "$jq_filter"
}

_check_and_fix_dns() {
    # 热修复：1.补充缺失的 DNS 模块，2.将容易引起出站路由绑定死循环（连接被秒重置）的 auto_detect_interface 清除
    # 3. 为未设置策略的旧配置补充 prefer_ipv4；保留用户在 DNS 菜单中明确选择的策略
    # 4. [sing-box 1.14 适配] 旧版 address 型 DNS 服务器已在 1.14 移除：
    #    自动迁移为类型化服务器，删除已移除的 {"outbound":"any"} DNS 规则，
    #    并补充 route.default_domain_resolver
    if [ ! -f "$CONFIG_FILE" ]; then return 1; fi

    local has_dns=$(jq 'has("dns")' "$CONFIG_FILE" 2>/dev/null)
    local has_auto_detect=$(jq 'try .route.auto_detect_interface catch false' "$CONFIG_FILE" 2>/dev/null)
    local dns_strategy=$(jq -r '.dns.strategy // ""' "$CONFIG_FILE" 2>/dev/null)
    local legacy_dns=$(jq '[(.dns.servers // [])[] | has("address")] | any' "$CONFIG_FILE" 2>/dev/null)
    local legacy_rules=$(jq '[(.dns.rules // [])[] | has("outbound")] | any' "$CONFIG_FILE" 2>/dev/null)
    local has_resolver=$(jq '(.route // {}) | has("default_domain_resolver")' "$CONFIG_FILE" 2>/dev/null)
    local needs_restart=false

    if [ "$has_dns" == "false" ] || [ "$has_auto_detect" == "true" ] || [ -z "$dns_strategy" ] \
        || [ "$legacy_dns" == "true" ] || [ "$legacy_rules" == "true" ] || [ "$has_resolver" != "true" ]; then
        _warn "检测到 DNS/路由配置需要兼容性修复，正在自动处理..."

        # 迁移时保留旧配置中的 DNS 地址；无法识别时回退为系统 DNS
        local replace_servers="true"
        local server_json=""
        if [ "$legacy_dns" == "true" ]; then
            local old_address=$(jq -r '.dns.servers[0].address // ""' "$CONFIG_FILE" 2>/dev/null)
            server_json=$(_dns_address_to_server_json "$old_address" "dns-local" 2>/dev/null)
        elif [ "$has_dns" == "true" ] && jq -e '(.dns.servers // []) | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then
            # 已是类型化服务器，保留原样
            replace_servers="false"
        fi
        [ -z "$server_json" ] && server_json='{"type":"local","tag":"dns-local","prefer_go":true}'

        local resolver_tag="dns-local"
        if [ "$replace_servers" == "false" ]; then
            resolver_tag=$(jq -r '.dns.servers[0].tag // "dns-local"' "$CONFIG_FILE" 2>/dev/null)
        fi

        local tmp_file="${CONFIG_FILE}.tmp"
        jq --argjson server "$server_json" --arg rtag "$resolver_tag" \
           --argjson replace "$( [ "$replace_servers" == "true" ] && echo true || echo false )" '
            .dns = (.dns // {})
            | .dns.servers = (if $replace then [$server] else .dns.servers end)
            | .dns.rules = ([(.dns.rules // [])[] | select(has("outbound") | not)])
            | (if (.dns.rules | length) == 0 then del(.dns.rules) else . end)
            | .dns.final = (if ((.dns.final // "") == "") then "dns-local" else .dns.final end)
            | .dns.strategy = (if ((.dns.strategy // "") == "") then "prefer_ipv4" else .dns.strategy end)
            | .route = (.route // {})
            | .route.default_domain_resolver = {"server": $rtag, "strategy": (.dns.strategy // "prefer_ipv4")}
            | del(.route.auto_detect_interface)
        ' "$CONFIG_FILE" > "$tmp_file"

        if [ $? -eq 0 ] && [ -s "$tmp_file" ]; then
            mv "$tmp_file" "$CONFIG_FILE"
            _success "DNS 与路由参数热修复完成！"
            needs_restart=true
        else
            _error "高级修复应用失败！"
            rm -f "$tmp_file"
        fi
    fi

    if [ -f "$CLASH_YAML_FILE" ] && [ -x "$YQ_BINARY" ]; then
        local clash_ipv6=$(${YQ_BINARY} eval '.ipv6 // false' "$CLASH_YAML_FILE" 2>/dev/null)
        local clash_dns_ipv6=$(${YQ_BINARY} eval '.dns.ipv6 // false' "$CLASH_YAML_FILE" 2>/dev/null)
        if [ "$clash_ipv6" != "true" ] || [ "$clash_dns_ipv6" != "true" ]; then
            if _atomic_modify_yaml "$CLASH_YAML_FILE" '.ipv6 = true | .dns.ipv6 = true' >/dev/null 2>&1; then
                _success "已开启 clash.yaml 的 IPv6 与 DNS IPv6 支持。"
            else
                _warn "clash.yaml IPv6 自动修复失败，请手动检查 YAML 格式。"
            fi
        fi
    fi
    
    if [ "$needs_restart" == "true" ]; then
        return 0
    fi
    return 1
}

_generate_self_signed_cert() {
    local domain="$1"
    local cert_path="$2"
    local key_path="$3"

    _info "正在为 ${domain} 生成支持 SAN 的高级自签名证书..."
    
    # 创建临时配置文件用于生成 SAN
    local openssl_config=$(mktemp)
    cat > "$openssl_config" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = ${domain}
[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${domain}
DNS.2 = *.${domain}
EOF

    # 使用 RSA 2048 生成证书 (CF 回源兼容性更佳)
    openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
        -keyout "$key_path" -out "$cert_path" \
        -config "$openssl_config" >/dev/null 2>&1
    
    local status=$?
    rm -f "$openssl_config"

    if [ $status -ne 0 ]; then
        _error "为 ${domain} 生成证书失败！"
        rm -f "$cert_path" "$key_path"
        return 1
    fi
    _success "证书 ${cert_path} (含 SAN) 已成功生成。"
    return 0
}

# 注意: _atomic_modify_json, _atomic_modify_yaml, _get_proxy_field, _add_node_to_yaml, _remove_node_from_yaml
# 均在上方统一定义，此处不再重复定义以避免不一致

# 显示节点分享链接（在添加节点后调用）
# 参数: $1=协议类型, $2=节点名称, $3=服务器IP(用于链接), $4=端口, $5=节点TAG, 其他参数根据协议不同
_show_node_link() {
    local type="$1"
    local name="$2"
    local link_ip="$3"
    local port="$4"
    local tag="$5"
    # [关键修复] 处理 IPv6 括号包裹逻辑
    if [[ "$link_ip" == *":"* ]] && [[ "$link_ip" != "["* ]]; then
        link_ip="[${link_ip}]"
    fi

    shift 5
    
    local url=""
    
    case "$type" in
        "vless-reality")
            # 参数: uuid, sni, public_key, short_id, flow
            local uuid="$1" pk="$3" sid="$4" flow="${5:-xtls-rprx-vision}"
            # 对 SNI 执行终极保底与净化
            local sni=$(echo "$2" | xargs)
            [[ -z "$sni" ]] && sni="$DEFAULT_SNI"
            
            url="vless://${uuid}@${link_ip}:${port}?security=reality&encryption=none&pbk=$(_url_encode "${pk}")&fp=chrome&type=tcp&flow=${flow}&sni=${sni}&sid=${sid}#$(_url_encode "$name")"
            ;;
        "vless-ws-tls")
            # 参数: uuid, sni, ws_path, skip_verify
            local uuid="$1" sni="${2:-$DEFAULT_SNI}" ws_path="$3" skip_verify="$4" cert_path="$5"
            local insecure_param=$(_tls_insecure_params "$skip_verify" "$cert_path")
            url="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&type=ws&host=${sni}&path=$(_url_encode "$ws_path")&sni=${sni}${insecure_param}#$(_url_encode "$name")"
            ;;
        "vless-grpc-tls")
            # 参数: uuid, sni, service_name, skip_verify, cert_path
            local uuid="$1" sni="${2:-$DEFAULT_SNI}" service_name="$3" skip_verify="$4" cert_path="$5"
            local insecure_param=$(_tls_insecure_params "$skip_verify" "$cert_path")
            url="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&type=grpc&serviceName=$(_url_encode "$service_name")&authority=${sni}&sni=${sni}${insecure_param}#$(_url_encode "$name")"
            ;;
        "vless-tcp")
            # 参数: uuid
            local uuid="$1"
            url="vless://${uuid}@${link_ip}:${port}?encryption=none&type=tcp#$(_url_encode "$name")"
            ;;
        "trojan-ws-tls")
            # 参数: password, sni, ws_path, skip_verify
            local password="$1" sni="${2:-$DEFAULT_SNI}" ws_path="$3" skip_verify="$4" cert_path="$5"
            local insecure_param=$(_tls_insecure_params "$skip_verify" "$cert_path")
            url="trojan://${password}@${link_ip}:${port}?security=tls&type=ws&host=${sni}&path=$(_url_encode "$ws_path")&sni=${sni}${insecure_param}#$(_url_encode "$name")"
            ;;
        "hysteria2")
            # 参数: password, sni, obfs_password(可选), port_hopping(可选)
            local password="$1" sni="${2:-$DEFAULT_SNI}" obfs_password="$3" port_hopping="$4"
            local obfs_param=""; [[ -n "$obfs_password" ]] && obfs_param="&obfs=salamander&obfs-password=$(_url_encode "${obfs_password}")"
            local hop_param=""; [[ -n "$port_hopping" ]] && hop_param="&mport=${port_hopping}&ports=${port_hopping}"
            local cert_path="${SINGBOX_DIR}/${tag}.pem"
            local pin_param=""
            local cert_pcs=$(_cert_sha256_hex "$cert_path")
            [ -n "$cert_pcs" ] && pin_param="&pinSHA256=${cert_pcs}"
            url="hysteria2://${password}@${link_ip}:${port}?sni=${sni}&insecure=1${obfs_param}${hop_param}${pin_param}#$(_url_encode "$name")"
            ;;
        "tuic")
            # 参数: uuid, password, sni
            local uuid="$1" password="$2" sni="${3:-$DEFAULT_SNI}"
            url="tuic://${uuid}:${password}@${link_ip}:${port}?sni=${sni}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "$name")"
            ;;
        "anytls")
            # 参数: password, sni, skip_verify
            local password="$1" sni="${2:-$DEFAULT_SNI}" skip_verify="$3" cert_path="$4"
            local insecure_param=$(_tls_insecure_params "$skip_verify" "$cert_path")
            url="anytls://${password}@${link_ip}:${port}?security=tls&sni=${sni}${insecure_param}#$(_url_encode "$name")"
            ;;
        "any-reality")
            # 参数: password, sni, public_key, short_id
            local password="$1" sni="${2:-$DEFAULT_SNI}" public_key="$3" short_id="$4"
            url="anytls://${password}@${link_ip}:${port}?security=reality&sni=${sni}&fp=chrome&pbk=$(_url_encode "${public_key}")&sid=${short_id}&type=tcp&headerType=none#$(_url_encode "$name")"
            ;;
        "shadowsocks")
            # 参数: method, password
            local method="$1" password="$2"
            local userinfo=$(printf '%s' "${method}:${password}" | base64 | tr -d '\n\r ' | tr '+/' '-_' | tr -d '=')
            url="ss://${userinfo}@${link_ip}:${port}#$(_url_encode "$name")"
            ;;
        "shadowsocks-shadowtls")
            # 参数: method, pw, spw, sni
            local method="$1" pw="$2" spw="$3" sni="$4"
            url=""
            echo -e "${YELLOW}====== [客户端配置参考片段 (Clash Meta / Mihomo)] ======${NC}"
            echo -e "  - name: \"${name}\""
            echo -e "    type: ss"
            echo -e "    server: ${link_ip}"
            echo -e "    port: ${port}"
            echo -e "    cipher: ${method}"
            echo -e "    password: ${pw}"
            echo -e "    plugin: shadow-tls"
            echo -e "    plugin-opts:"
            echo -e "      host: ${sni}"
            echo -e "      password: ${spw}"
            echo -e "      version: 3"
            echo -e "${YELLOW}========================================================${NC}"
            echo -e "${CYAN}[提示] ShadowTLS 需要特定的客户端配置。${NC}"
            echo -e "${CYAN}您也可以直接打开本机位于 ${YELLOW}/usr/local/etc/sing-box/clash.yaml${CYAN} 的配置文件，${NC}"
            echo -e "${CYAN}找到对应节点的 YAML 代码块，并复制到您的客户端中使用！${NC}"
            ;;
        "vless-ws")
            # Argo 专用: uuid, path
            local uuid="$1" ws_path="$2"
            local ed_path=$(_ws_path_with_early_data "$ws_path")
            url="vless://${uuid}@${link_ip}:443?encryption=none&security=tls&type=ws&host=${link_ip}&path=$(_url_encode "$ed_path")&sni=${link_ip}#$(_url_encode "$name")"
            ;;
        "trojan-ws")
            # Argo 专用: password, path
            local password="$1" ws_path="$2"
            local ed_path=$(_ws_path_with_early_data "$ws_path")
            url="trojan://$(_url_encode "${password}")@${link_ip}:443?security=tls&type=ws&host=${link_ip}&path=$(_url_encode "$ed_path")&sni=${link_ip}#$(_url_encode "$name")"
            ;;
        "socks")
            # 参数: username, password
            local username="$1" password="$2"
            echo ""
            _info "节点信息: 服务器: ${link_ip}, 端口: ${port}, 用户名: ${username}, 密码: ${password}"
            return
            ;;
    esac
    
    if [ -n "$url" ]; then
        echo ""
        local clean_url=$(echo "$url" | sed 's/&insecure=1//g' | sed 's/&pcs=[a-fA-F0-9]*//g')
        if [ "$clean_url" != "$url" ] && [[ "$type" != "anytls" ]] && [[ "$type" != "hysteria2" ]] && [[ "$type" != "tuic" ]] && [[ "$type" != "vless-reality" ]] && [[ "$type" != "any-reality" ]]; then
            echo -e "${YELLOW}═══════════════ 🔗 直连分享链接 (含防劫持指纹) ═══════════════${NC}"
            echo -e "${CYAN}${url}${NC}"
            echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
            echo ""
            echo -e "${YELLOW}═════════════ 🔗 CF优选专用链接 (纯净版，无指纹冲突) ═════════════${NC}"
            echo -e "${CYAN}${clean_url}${NC}"
            echo -e "${YELLOW}══════════════════════════════════════════════════════════════${NC}"
            echo -e "${CYAN}[提示] 如果您套用了 Cloudflare，请导入 ${YELLOW}CF优选专用链接${CYAN} 以避免握手失败！${NC}"
        else
            echo -e "${YELLOW}═══════════════════ 分享链接 ═══════════════════${NC}"
            echo -e "${CYAN}${url}${NC}"
            echo -e "${YELLOW}═════════════════════════════════════════════════${NC}"
        fi
        
        # [持久化] 将生成的链接存入元数据，防止查看时由于动态提取导致的 SNI 丢失
        if [ -n "$tag" ] && [ "$tag" != "null" ]; then
            if [[ "$tag" == argo-* ]]; then
                _atomic_modify_json "$ARGO_METADATA_FILE" ". + { \"$tag\": ((.[\"$tag\"] // {}) + { \"share_link\": \"$url\" }) }" || return 1
            else
                _atomic_modify_json "$METADATA_FILE" ". + { \"$tag\": ((.[\"$tag\"] // {}) + { \"share_link\": \"$url\" }) }" || return 1
            fi
        fi
    fi
}

_show_cdn_guidance() {
    local domain="$1"
    local port="$2"
    echo ""
    echo -e "${YELLOW}══════════════════ 🔧 如何开启 Cloudflare CDN 优选 ══════════════════${NC}"
    _info "如果您希望开启 CDN 并在之后使用优选域名/IP，请按照以下步骤配置："
    _info "1. ${CYAN}【CF 后台】${NC}将该域名的解析记录开启小黄云 (${ORANGE}Proxied${NC})。"
    _info "2. ${CYAN}【CF 后台】${NC}在 [SSL/TLS] 菜单中，将加密模式设为: ${GREEN}Full (完全)${NC}。"
    if [ "$port" != "443" ]; then
        _warn "3. 您的服务器监听的是 ${port} 端口。请在 [Rules] -> [Origin Rules] 中配置："
        _warn "   - 主机名 包含 \"${domain}\" -> 重写到端口: ${port}"
    else
        _info "3. 您的服务器已监听 443 端口，无需设置 Origin Rules。"
    fi
    _info "4. ${CYAN}【客户端】${NC}修改配置：地址改为优选域名/IP，端口改为 ${GREEN}443${NC}。"
    _info "   (注：Host/SNI 必须保持为您的域名 ${domain})"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════════════${NC}"
}

_show_grpc_cdn_guidance() {
    local domain="$1"
    local port="$2"
    echo ""
    echo -e "${YELLOW}══════════════════ 🔧 VLESS gRPC + Cloudflare 配置提示 ══════════════════${NC}"
    _info "1. ${CYAN}【CF 后台】${NC}将该域名的解析记录开启小黄云 (${ORANGE}Proxied${NC})。"
    _info "2. ${CYAN}【CF 后台】${NC}在 [SSL/TLS] 菜单中，将加密模式设为: ${GREEN}Full (完全)${NC}。"
    _info "3. ${CYAN}【CF 后台】${NC}在 [Network] 菜单中确认 gRPC 已开启。"
    if [ "$port" != "443" ]; then
        _warn "4. 您的服务器监听的是 ${port} 端口。请在 [Rules] -> [Origin Rules] 中配置："
        _warn "   - 主机名 包含 \"${domain}\" -> 重写到端口: ${port}"
    else
        _info "4. 您的服务器已监听 443 端口，无需设置 Origin Rules。"
    fi
    _info "5. ${CYAN}【客户端】${NC}地址可改为优选域名/IP，端口改为 ${GREEN}443${NC}。"
    _info "   (注：SNI 必须保持为您的域名 ${domain}，gRPC serviceName 必须保持一致)"
    echo -e "${YELLOW}══════════════════════════════════════════════════════════════════════${NC}"
}


_add_vless_ws_tls() {
    local camouflage_domain=""
    local port=""
    local client_server_addr="${server_ip}"

    if [ "$BATCH_MODE" = "true" ]; then
        [[ -n "$BATCH_IP" ]] && client_server_addr="$BATCH_IP"
        port="$BATCH_PORT"
        camouflage_domain="${BATCH_WS_TLS_DOMAIN:-$BATCH_SNI}"
    else
        _info "--- VLESS (WebSocket+TLS) 设置向导 ---"
        _info "请输入客户端用于“连接”的地址:"
        _info "  - (推荐) 直接回车, 使用VPS的公网 IP: ${server_ip}"
        _info "  - (其他) 您也可以手动输入一个IP或域名"
        read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
        client_server_addr=${connection_address:-$server_ip}
        
        # IPv6 处理
        if [[ "$client_server_addr" == *":"* ]] && [[ "$client_server_addr" != "["* ]]; then
             client_server_addr="[${client_server_addr}]"
        fi

        _info "请输入您的“伪装域名”，这个域名必须是您证书对应的域名。"
        _info " (例如: xxx.741865.xyz)"
        read -p "请输入伪装域名: " camouflage_domain
        [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

        while true; do
            read -p "请输入监听端口 (直连模式下首推 443 端口): " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "tcp" && continue
            break
        done
    fi

    # 客户端连接端口默认与监听端口一致 (直连模式)
    local client_port="$port"

    # --- 步骤 4: 路径 ---
    local ws_path=""
    if [ "$BATCH_MODE" = "true" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
    else
        read -p "请输入 WebSocket 路径 (回车则随机生成): " input_ws_path
        if [ -z "$input_ws_path" ]; then
            ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
            _info "已为您生成随机 WebSocket 路径: ${ws_path}"
        else
            ws_path="$input_ws_path"
            [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
        fi
    fi

    # 提前定义 tag，用于证书文件命名
    local tag="vless-ws-in-${port}"
    local cert_path=""
    local key_path=""
    local skip_verify=false

    # --- 步骤 5: 证书选择 ---
    local cert_choice="1"
    if [ "$BATCH_MODE" = "true" ]; then
        cert_choice="1"
    else
        echo ""
        echo "请选择证书类型:"
        echo "  1) 自动生成自签名证书 (适合CF回源/直连跳过验证)"
        echo "  2) 手动上传证书文件 (acme.sh签发/Cloudflare源证书等)"
        read -p "请选择 [1-2] (默认: 1): " cert_choice
        cert_choice=${cert_choice:-1}
    fi

    if [ "$cert_choice" == "1" ]; then
        # 自签名证书
        cert_path="${SINGBOX_DIR}/${tag}.pem"
        key_path="${SINGBOX_DIR}/${tag}.key"
        _generate_self_signed_cert "$camouflage_domain" "$cert_path" "$key_path" || return 1
        skip_verify=true
        _info "已生成自签名证书，客户端将跳过证书验证。"
    else
        # 手动上传证书
        _info "请输入 ${camouflage_domain} 对应的证书文件路径。"
        _info "  - (推荐) 使用 acme.sh 签发的 fullchain.pem"
        _info "  - (或)   使用 Cloudflare 源服务器证书"
        read -p "请输入证书文件 .pem/.crt 的完整路径: " cert_path
        [[ ! -f "$cert_path" ]] && _error "证书文件不存在: ${cert_path}" && return 1

        read -p "请输入私钥文件 .key 的完整路径: " key_path
        [[ ! -f "$key_path" ]] && _error "私钥文件不存在: ${key_path}" && return 1
        
        # 询问是否跳过验证
        read -p "$(echo -e ${YELLOW}"您是否正在使用 Cloudflare 源服务器证书 (或自签名证书)? (y/N): "${NC})" use_origin_cert
        if [[ "$use_origin_cert" == "y" || "$use_origin_cert" == "Y" ]]; then
            skip_verify=true
            _warning "已启用 'skip-cert-verify: true'。这将跳过证书验证。"
        fi
    fi
    
    # [!] 自定义名称
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-VLESS-WS-${port}"
    else
        local default_name="VLESS-WS-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi

    local uuid=$(${SINGBOX_BIN} generate uuid)
    
    # Inbound (服务器端) 配置
    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg u "$uuid" \
        --arg cp "$cert_path" \
        --arg kp "$key_path" \
        --arg sn "$camouflage_domain" \
        --arg wsp "$ws_path" \
        '{
            "type": "vless",
            "tag": $t,
            "listen": "::",
            "listen_port": ($p|tonumber),
            "users": [{"uuid": $u, "flow": ""}],
            "tls": {
                "enabled": true,
                "server_name": $sn,
                "certificate_path": $cp,
                "key_path": $kp
            },
            "transport": {
                "type": "ws",
                "path": $wsp
            }
        }')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    # Proxy (客户端) 配置
    local proxy_json=$(jq -n \
            --arg n "$name" \
            --arg s "$client_server_addr" \
            --arg p "$client_port" \
            --arg u "$uuid" \
            --arg sn "$camouflage_domain" \
            --arg wsp "$ws_path" \
            --arg skip_verify_bool "$skip_verify" \
            --arg host_header "$camouflage_domain" \
            '{
                "name": $n,
                "type": "vless",
                "server": $s,
                "port": ($p|tonumber),
                "uuid": $u,
                "encryption": "none",
                "tls": true,
                "udp": true,
                "skip-cert-verify": ($skip_verify_bool == "true"),
                "network": "ws",
                "sni": $sn,
                "ws-opts": {
                    "path": $wsp,
                    "headers": {
                        "Host": $host_header
                    }
                }
            }')
            
    _add_node_to_yaml "$proxy_json" || return 1
    _info "VLESS (WebSocket+TLS) 节点 [${name}] 配置已写入，等待服务校验..."
    _info "客户端连接地址 (server): ${client_server_addr}"
    _info "客户端连接端口 (port): ${client_port}"
    _info "客户端伪装域名 (sni/Host): ${camouflage_domain}"
    
    # CDN 指引 (仅在非批量模式下详细显示)
    [ "$BATCH_MODE" != "true" ] && _show_cdn_guidance "${camouflage_domain}" "${port}"

    # IPv6 处理用于链接
    local link_ip="$client_server_addr"
    _show_node_link "vless-ws-tls" "$name" "$link_ip" "$client_port" "$tag" "$uuid" "$camouflage_domain" "$ws_path" "$skip_verify" "$cert_path"
}

_add_vless_grpc_tls() {
    local camouflage_domain=""
    local port=""
    local client_server_addr="${server_ip}"

    if [ "$BATCH_MODE" = "true" ]; then
        [[ -n "$BATCH_IP" ]] && client_server_addr="$BATCH_IP"
        port="$BATCH_PORT"
        camouflage_domain="${BATCH_GRPC_TLS_DOMAIN:-$BATCH_SNI}"
    else
        _info "--- VLESS (gRPC+TLS) 设置向导 ---"
        _info "请输入客户端用于“连接”的地址:"
        _info "  - (推荐) 直接回车, 使用VPS的公网 IP: ${server_ip}"
        _info "  - (其他) 您也可以手动输入一个IP或域名"
        read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
        client_server_addr=${connection_address:-$server_ip}

        # IPv6 处理
        if [[ "$client_server_addr" == *":"* ]] && [[ "$client_server_addr" != "["* ]]; then
             client_server_addr="[${client_server_addr}]"
        fi

        _info "请输入您的“伪装域名”，这个域名必须是您证书对应的域名。"
        _info " (例如: xxx.741865.xyz)"
        read -p "请输入伪装域名: " camouflage_domain
        [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

        while true; do
            read -p "请输入监听端口 (直连模式下首推 443 端口): " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "tcp" && continue
            break
        done
    fi

    local client_port="$port"

    local generated_service_name="grpc-$(${SINGBOX_BIN} generate rand --hex 4)"
    local service_name=""
    if [ "$BATCH_MODE" = "true" ]; then
        service_name="${BATCH_GRPC_SERVICE_NAME:-$generated_service_name}"
    else
        read -p "请输入 gRPC serviceName (回车则随机生成: ${generated_service_name}): " input_service_name
        service_name=${input_service_name:-$generated_service_name}
        service_name=$(echo "$service_name" | xargs)
        [[ -z "$service_name" ]] && _error "gRPC serviceName 不能为空" && return 1
        _info "gRPC serviceName: ${service_name}"
    fi

    local tag="vless-grpc-in-${port}"
    local cert_path=""
    local key_path=""
    local skip_verify=false

    local cert_choice="1"
    if [ "$BATCH_MODE" = "true" ]; then
        cert_choice="1"
    else
        echo ""
        echo "请选择证书类型:"
        echo "  1) 自动生成自签名证书 (适合CF回源/直连跳过验证)"
        echo "  2) 手动上传证书文件 (acme.sh签发/Cloudflare源证书等)"
        read -p "请选择 [1-2] (默认: 1): " cert_choice
        cert_choice=${cert_choice:-1}
    fi

    if [ "$cert_choice" == "1" ]; then
        cert_path="${SINGBOX_DIR}/${tag}.pem"
        key_path="${SINGBOX_DIR}/${tag}.key"
        _generate_self_signed_cert "$camouflage_domain" "$cert_path" "$key_path" || return 1
        skip_verify=true
        _info "已生成自签名证书，客户端将跳过证书验证。"
    else
        _info "请输入 ${camouflage_domain} 对应的证书文件路径。"
        _info "  - (推荐) 使用 acme.sh 签发的 fullchain.pem"
        _info "  - (或)   使用 Cloudflare 源服务器证书"
        read -p "请输入证书文件 .pem/.crt 的完整路径: " cert_path
        [[ ! -f "$cert_path" ]] && _error "证书文件不存在: ${cert_path}" && return 1

        read -p "请输入私钥文件 .key 的完整路径: " key_path
        [[ ! -f "$key_path" ]] && _error "私钥文件不存在: ${key_path}" && return 1

        read -p "$(echo -e ${YELLOW}"您是否正在使用 Cloudflare 源服务器证书 (或自签名证书)? (y/N): "${NC})" use_origin_cert
        if [[ "$use_origin_cert" == "y" || "$use_origin_cert" == "Y" ]]; then
            skip_verify=true
            _warning "已启用 'skip-cert-verify: true'。这将跳过证书验证。"
        fi
    fi

    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-VLESS-gRPC-${port}"
    else
        local default_name="VLESS-gRPC-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi

    local uuid=$(${SINGBOX_BIN} generate uuid)

    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg u "$uuid" \
        --arg cp "$cert_path" \
        --arg kp "$key_path" \
        --arg sn "$camouflage_domain" \
        --arg svc "$service_name" \
        '{
            "type": "vless",
            "tag": $t,
            "listen": "::",
            "listen_port": ($p|tonumber),
            "users": [{"uuid": $u, "flow": ""}],
            "tls": {
                "enabled": true,
                "server_name": $sn,
                "alpn": ["h2"],
                "certificate_path": $cp,
                "key_path": $kp
            },
            "transport": {
                "type": "grpc",
                "service_name": $svc
            }
        }')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    local proxy_json=$(jq -n \
            --arg n "$name" \
            --arg s "$client_server_addr" \
            --arg p "$client_port" \
            --arg u "$uuid" \
            --arg sn "$camouflage_domain" \
            --arg svc "$service_name" \
            --arg skip_verify_bool "$skip_verify" \
            '{
                "name": $n,
                "type": "vless",
                "server": $s,
                "port": ($p|tonumber),
                "uuid": $u,
                "encryption": "none",
                "tls": true,
                "udp": true,
                "skip-cert-verify": ($skip_verify_bool == "true"),
                "network": "grpc",
                "servername": $sn,
                "grpc-opts": {
                    "grpc-service-name": $svc
                }
            }')

    _add_node_to_yaml "$proxy_json" || return 1
    _info "VLESS (gRPC+TLS) 节点 [${name}] 配置已写入，等待服务校验..."
    _info "客户端连接地址 (server): ${client_server_addr}"
    _info "客户端连接端口 (port): ${client_port}"
    _info "客户端伪装域名 (sni): ${camouflage_domain}"
    _info "gRPC serviceName: ${service_name}"

    [ "$BATCH_MODE" != "true" ] && _show_grpc_cdn_guidance "${camouflage_domain}" "${port}"

    local link_ip="$client_server_addr"
    _show_node_link "vless-grpc-tls" "$name" "$link_ip" "$client_port" "$tag" "$uuid" "$camouflage_domain" "$service_name" "$skip_verify" "$cert_path"
}

_add_trojan_ws_tls() {
    local camouflage_domain=""
    local port=""
    local client_server_addr="${server_ip}"

    if [ "$BATCH_MODE" = "true" ]; then
        [[ -n "$BATCH_IP" ]] && client_server_addr="$BATCH_IP"
        port="$BATCH_PORT"
        camouflage_domain="${BATCH_WS_TLS_DOMAIN:-$BATCH_SNI}"
    else
        _info "--- Trojan (WebSocket+TLS) 设置向导 ---"
        _info "请输入客户端用于“连接”的地址:"
        _info "  - (推荐) 直接回车, 使用VPS的公网 IP: ${server_ip}"
        _info "  - (其他) 您也可以手动输入一个IP或域名"
        read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
        client_server_addr=${connection_address:-$server_ip}
        
        # IPv6 处理
        if [[ "$client_server_addr" == *":"* ]] && [[ "$client_server_addr" != "["* ]]; then
             client_server_addr="[${client_server_addr}]"
        fi

        _info "请输入您的“伪装域名”，这个域名必须是您证书对应的域名。"
        read -p "请输入伪装域名: " camouflage_domain
        [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

        while true; do
            read -p "请输入监听端口 (直连模式下首推 443 端口): " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "tcp" && continue
            break
        done
    fi

    # 客户端连接端口默认与监听端口一致 (直连模式)
    local client_port="$port"

    # --- 步骤 4: 路径 ---
    local ws_path=""
    if [ "$BATCH_MODE" = "true" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
    else
        read -p "请输入 WebSocket 路径 (回车则随机生成): " input_ws_path
        if [ -z "$input_ws_path" ]; then
            ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
            _info "已为您生成随机 WebSocket 路径: ${ws_path}"
        else
            ws_path="$input_ws_path"
            [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
        fi
    fi

    # 提前定义 tag，用于证书文件命名
    local tag="trojan-ws-in-${port}"
    local cert_path=""
    local key_path=""
    local skip_verify=false

    # --- 步骤 5: 证书选择 ---
    if [ "$BATCH_MODE" = "true" ]; then
        cert_path="${SINGBOX_DIR}/${tag}.pem"
        key_path="${SINGBOX_DIR}/${tag}.key"
        _generate_self_signed_cert "$camouflage_domain" "$cert_path" "$key_path" || return 1
        skip_verify=true
    else
        echo ""
        echo "请选择证书类型:"
        echo "  1) 自动生成自签名证书 (适合CF回源/直连跳过验证)"
        echo "  2) 手动上传证书文件 (acme.sh签发/Cloudflare源证书等)"
        read -p "请选择 [1-2] (默认: 1): " cert_choice
        cert_choice=${cert_choice:-1}
        if [ "$cert_choice" == "1" ]; then
            cert_path="${SINGBOX_DIR}/${tag}.pem"
            key_path="${SINGBOX_DIR}/${tag}.key"
            _generate_self_signed_cert "$camouflage_domain" "$cert_path" "$key_path" || return 1
            skip_verify=true
            _info "已生成自签名证书，客户端将跳过证书验证。"
        else
            # 手动上传证书
            _info "请输入 ${camouflage_domain} 对应的证书文件路径。"
            _info "  - (推荐) 使用 acme.sh 签发的 fullchain.pem"
            _info "  - (或)   使用 Cloudflare 源服务器证书"
            read -p "请输入证书文件 .pem/.crt 的完整路径: " cert_path
            [[ ! -f "$cert_path" ]] && _error "证书文件不存在: ${cert_path}" && return 1

            read -p "请输入私钥文件 .key 的完整路径: " key_path
            [[ ! -f "$key_path" ]] && _error "私钥文件不存在: ${key_path}" && return 1
            
            # 询问是否跳过验证
            read -p "$(echo -e ${YELLOW}"您是否正在使用 Cloudflare 源服务器证书 (或自签名证书)? (y/N): "${NC})" use_origin_cert
            if [[ "$use_origin_cert" == "y" || "$use_origin_cert" == "Y" ]]; then
                skip_verify=true
                _warning "已启用 'skip-cert-verify: true'。这将跳过证书验证。"
            fi
        fi
    fi

    # [!] Trojan: 使用密码
    local password=""
    if [ "$BATCH_MODE" = "true" ]; then
        password=$(${SINGBOX_BIN} generate rand --hex 16)
    else
        read -p "请输入 Trojan 密码 (回车则随机生成): " input_pw
        if [ -z "$input_pw" ]; then
            password=$(${SINGBOX_BIN} generate rand --hex 16)
            _info "已为您生成随机密码: ${password}"
        else
            password="$input_pw"
        fi
    fi

    # [!] 自定义名称
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-Trojan-WS-${port}"
    else
        local default_name="Trojan-WS-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi

    # Inbound (服务器端) 配置
    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg pw "$password" \
        --arg cp "$cert_path" \
        --arg kp "$key_path" \
        --arg sn "$camouflage_domain" \
        --arg wsp "$ws_path" \
        '{
            "type": "trojan",
            "tag": $t,
            "listen": "::",
            "listen_port": ($p|tonumber),
            "users": [{"password": $pw}],
            "tls": {
                "enabled": true,
                "server_name": $sn,
                "certificate_path": $cp,
                "key_path": $kp
            },
            "transport": {
                "type": "ws",
                "path": $wsp
            }
        }')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    # Proxy (客户端) 配置
    local proxy_json=$(jq -n \
            --arg n "$name" \
            --arg s "$client_server_addr" \
            --arg p "$client_port" \
            --arg pw "$password" \
            --arg sn "$camouflage_domain" \
            --arg wsp "$ws_path" \
            --arg skip_verify_bool "$skip_verify" \
            --arg host_header "$camouflage_domain" \
            '{
                "name": $n,
                "type": "trojan",
                "server": $s,
                "port": ($p|tonumber),
                "password": $pw,
                "udp": true,
                "skip-cert-verify": ($skip_verify_bool == "true"),
                "network": "ws",
                "sni": $sn,
                "ws-opts": {
                    "path": $wsp,
                    "headers": {
                        "Host": $host_header
                    }
                }
            }')
            
    _add_node_to_yaml "$proxy_json" || return 1
    _info "Trojan (WebSocket+TLS) 节点 [${name}] 配置已写入，等待服务校验..."
    _info "客户端连接地址 (server): ${client_server_addr}"
    _info "客户端连接端口 (port): ${client_port}"
    _info "客户端伪装域名 (sni/Host): ${camouflage_domain}"
    
    # CDN 指引 (仅在非批量模式下详细显示)
    [ "$BATCH_MODE" != "true" ] && _show_cdn_guidance "${camouflage_domain}" "${port}"

    # IPv6 处理用于链接
    local link_ip="$client_server_addr"
    _show_node_link "trojan-ws-tls" "$name" "$link_ip" "$client_port" "$tag" "$password" "$camouflage_domain" "$ws_path" "$skip_verify" "$cert_path"
}

_create_anytls_tls_node() {
    local node_ip="$1"
    local port="$2"
    local server_name="$3"
    local password="$4"
    local name="$5"

    # --- 步骤 4: 证书选择 ---
    local cert_choice="1"
    if [ "$BATCH_MODE" = "true" ]; then
        cert_choice="1"
    else
        echo ""
        echo "请选择证书类型:"
        echo "  1) 自动生成自签名证书 (推荐)"
        echo "  2) 手动上传证书文件 (Cloudflare源证书等)"
        read -p "请选择 [1-2] (默认: 1): " cert_choice
        cert_choice=${cert_choice:-1}
    fi
    
    local cert_path=""
    local key_path=""
    local skip_verify=true  # 默认跳过验证 (自签证书需要)
    local tag="anytls-in-${port}"
    
    if [ "$cert_choice" == "1" ]; then
        # 自签名证书
        cert_path="${SINGBOX_DIR}/${tag}.pem"
        key_path="${SINGBOX_DIR}/${tag}.key"
        _generate_self_signed_cert "$server_name" "$cert_path" "$key_path" || return 1
        _info "已生成自签名证书，客户端将跳过证书验证。"
    else
        # 手动上传证书
        _info "请输入 ${server_name} 对应的证书文件路径。"
        read -p "请输入证书文件 .pem/.crt 的完整路径: " cert_path
        [[ ! -f "$cert_path" ]] && _error "证书文件不存在: ${cert_path}" && return 1
        
        read -p "请输入私钥文件 .key 的完整路径: " key_path
        [[ ! -f "$key_path" ]] && _error "私钥文件不存在: ${key_path}" && return 1
        
        # 询问是否跳过验证
        read -p "$(echo -e ${YELLOW}"您是否正在使用自签名证书或Cloudflare源证书? (y/N): "${NC})" use_self_signed
        if [[ "$use_self_signed" == "y" || "$use_self_signed" == "Y" ]]; then
            skip_verify=true
            _warning "已启用 'skip-cert-verify: true'，客户端将跳过证书验证。"
        else
            skip_verify=false
        fi
    fi
    
    # IPv6 处理
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"
    [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    # --- 生成 Inbound 配置 (包含 padding_scheme) ---
    # padding_scheme 是 AnyTLS 的核心功能，用于流量填充对抗检测
    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg pw "$password" \
        --arg sn "$server_name" \
        --arg cp "$cert_path" \
        --arg kp "$key_path" \
        '{
            "type": "anytls",
            "tag": $t,
            "listen": "::",
            "listen_port": ($p|tonumber),
            "users": [{"name": "default", "password": $pw}],
            "padding_scheme": [
                "stop=2",
                "0=100-200",
                "1=100-200"
            ],
            "tls": {
                "enabled": true,
                "alpn": ["http/1.1"],
                "certificate_path": $cp,
                "key_path": $kp
            }
        }')
    
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1
    
    # --- 生成 Clash YAML 配置 ---
    # 根据用户提供的格式：包含 client-fingerprint, udp, alpn
    local proxy_json=$(jq -n \
        --arg n "$name" \
        --arg s "$yaml_ip" \
        --arg p "$port" \
        --arg pw "$password" \
        --arg sn "$server_name" \
        --arg skip_verify_bool "$skip_verify" \
        '{
            "name": $n,
            "type": "anytls",
            "server": $s,
            "port": ($p|tonumber),
            "password": $pw,
            "client-fingerprint": "chrome",
            "udp": true,
            "idle-session-check-interval": 30,
            "idle-session-timeout": 30,
            "min-idle-session": 0,
            "sni": $sn,
            "alpn": ["h2", "http/1.1"],
            "skip-cert-verify": ($skip_verify_bool == "true")
        }')
    
    _add_node_to_yaml "$proxy_json" || return 1
    
    # --- 保存元数据 ---
    local meta_json
    meta_json=$(jq -n --arg n "$name" --arg sn "$server_name" '{name:$n, server_name:$sn, yaml:true}')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": $meta_json}" || return 1
    
    # --- 生成分享链接 ---
    local insecure_param=""
    if [ "$skip_verify" == "true" ]; then
        insecure_param="&insecure=1"
    fi
    local share_link="anytls://${password}@${link_ip}:${port}?security=tls&sni=${server_name}${insecure_param}&type=tcp#$(_url_encode "$name")"
    
    _info "AnyTLS 节点 [${name}] 配置已写入，等待服务校验..."
    _show_node_link "anytls" "$name" "$link_ip" "$port" "$tag" "$password" "$server_name" "$skip_verify"
}

_create_anyreality_node() {
    local node_ip="$1"
    local port="$2"
    local server_name="$3"
    local password="$4"
    local name="$5"
    local tag="any-reality-in-${port}"

    local keypair private_key public_key short_id
    keypair=$(${SINGBOX_BIN} generate reality-keypair)
    private_key=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    public_key=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    short_id=$(${SINGBOX_BIN} generate rand --hex 8)

    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg pw "$password" \
        --arg sn "$server_name" \
        --arg pk "$private_key" \
        --arg sid "$short_id" \
        '{
            "type": "anytls",
            "tag": $t,
            "listen": "::",
            "listen_port": ($p|tonumber),
            "users": [{"name": "default", "password": $pw}],
            "padding_scheme": [],
            "tls": {
                "enabled": true,
                "server_name": $sn,
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": $sn,
                        "server_port": 443
                    },
                    "private_key": $pk,
                    "short_id": [$sid]
                }
            }
        }')

    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    local link_ip="$node_ip"
    [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"

    local share_link="anytls://${password}@${link_ip}:${port}?security=reality&sni=${server_name}&fp=chrome&pbk=$(_url_encode "$public_key")&sid=${short_id}&type=tcp&headerType=none#$(_url_encode "$name")"
    local meta_json
    meta_json=$(jq -n \
        --arg type "any-reality" \
        --arg sn "$server_name" \
        --arg pub "$public_key" \
        --arg sid "$short_id" \
        --arg link "$share_link" \
        --arg n "$name" \
        '{type:$type, name:$n, server_name:$sn, publicKey:$pub, shortId:$sid, share_link:$link, yaml:false}')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": $meta_json}" || return 1

    _info "Any-Reality 节点 [${name}] 配置已写入，等待服务校验..."
    _warning "Any-Reality 为 AnyTLS + Reality，Mihomo/Clash 不支持，已跳过写入 clash.yaml。"
    _show_node_link "any-reality" "$name" "$link_ip" "$port" "$tag" "$password" "$server_name" "$public_key" "$short_id"
}

_add_anytls() {
    local node_ip="${server_ip}"
    [[ "$BATCH_MODE" == "true" && -n "$BATCH_IP" ]] && node_ip="$BATCH_IP"
    local port=""
    local server_name="www.amd.com"
    local mode_choice="1"

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        server_name="${BATCH_SNI:-www.amd.com}"
        mode_choice="${BATCH_ANYTLS_MODE:-1}"
    else
        _info "--- 添加 AnyTLS / Any-Reality 节点 ---"
        echo "请选择节点协议:"
        echo "  1) AnyTLS"
        echo "  2) Any-Reality"
        echo "  1,2) 同时创建 AnyTLS 和 Any-Reality"
        read -p "请选择 [1/2/1,2] (默认: 1): " mode_choice
        mode_choice=${mode_choice:-1}
        mode_choice=$(echo "$mode_choice" | tr '，' ',' | xargs)
        case "$mode_choice" in
            1|2|1,2|2,1|"1 2"|"2 1") ;;
            *) _error "无效选择"; return 1 ;;
        esac

        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        while true; do
            read -p "请输入起始监听端口: " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "tcp" && continue
            if [[ "$mode_choice" == "1,2" || "$mode_choice" == "2,1" || "$mode_choice" == "1 2" || "$mode_choice" == "2 1" ]]; then
                local reality_port=$((port + 1))
                if [ "$reality_port" -gt 65535 ]; then
                    _error "同时创建两个节点时，起始端口不能为 65535。"
                    continue
                fi
                _check_port_conflict "$reality_port" "tcp" && continue
            fi
            break
        done
        read -p "请输入伪装域名/SNI (默认: www.amd.com): " camouflage_domain
        server_name=${camouflage_domain:-"www.amd.com"}
    fi

    local password=""
    if [ "$BATCH_MODE" = "true" ]; then
        password=$(${SINGBOX_BIN} generate uuid)
    else
        read -p "请输入密码/UUID (回车则随机生成，两种模式共用): " input_pw
        password=${input_pw:-$(${SINGBOX_BIN} generate uuid)}
    fi

    local created=false
    case "$mode_choice" in
        1)
            local name
            if [ "$BATCH_MODE" = "true" ]; then
                name="Batch-AnyTLS-${port}"
            else
                local default_name="AnyTLS-${port}"
                read -p "请输入 AnyTLS 节点名称 (默认: ${default_name}): " custom_name
                name=${custom_name:-$default_name}
            fi
            _create_anytls_tls_node "$node_ip" "$port" "$server_name" "$password" "$name" || return 1
            created=true
            ;;
        2)
            local name
            if [ "$BATCH_MODE" = "true" ]; then
                name="Batch-Any-Reality-${port}"
            else
                local default_name="Any-Reality-${port}"
                read -p "请输入 Any-Reality 节点名称 (默认: ${default_name}): " custom_name
                name=${custom_name:-$default_name}
            fi
            _create_anyreality_node "$node_ip" "$port" "$server_name" "$password" "$name" || return 1
            created=true
            ;;
        1,2|2,1|"1 2"|"2 1")
            local tls_port="$port"
            local reality_port=$((port + 1))
            local tls_name reality_name
            if [ "$BATCH_MODE" = "true" ]; then
                tls_name="Batch-AnyTLS-${tls_port}"
                reality_name="Batch-Any-Reality-${reality_port}"
            else
                local default_tls_name="AnyTLS-${tls_port}"
                local default_reality_name="Any-Reality-${reality_port}"
                _info "同时创建时，Any-Reality 将使用端口 ${reality_port}。"
                read -p "请输入 AnyTLS 节点名称 (默认: ${default_tls_name}): " custom_tls_name
                tls_name=${custom_tls_name:-$default_tls_name}
                read -p "请输入 Any-Reality 节点名称 (默认: ${default_reality_name}): " custom_reality_name
                reality_name=${custom_reality_name:-$default_reality_name}
            fi
            _create_anytls_tls_node "$node_ip" "$tls_port" "$server_name" "$password" "$tls_name" || return 1
            _create_anyreality_node "$node_ip" "$reality_port" "$server_name" "$password" "$reality_name" || return 1
            created=true
            ;;
    esac

    [ "$created" = true ]
}

_add_vless_reality() {
    [ -z "$server_ip" ] && server_ip=$(_get_ip)
    local node_ip="${server_ip}"
    [[ "$BATCH_MODE" == "true" && -n "$BATCH_IP" ]] && node_ip="$BATCH_IP"
    local server_name="www.amd.com"
    local port=""
    local name=""

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        # 批量模式变量预加载，增加多层保底，防止变量泄露
        server_name=$(echo "${BATCH_SNI}" | xargs)
        [[ -z "$server_name" ]] && server_name="$DEFAULT_SNI"
        name="Batch-Reality-${port}"
        # 批量模式下如果不显式指定，可能丢失 IP，此处进行双重保险
        [ -z "$node_ip" ] && node_ip="$server_ip"
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        read -p "请输入伪装域名 (默认: www.amd.com): " camouflage_domain
        server_name=${camouflage_domain:-"www.amd.com"}
        while true; do
            read -p "请输入监听端口: " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "tcp" && continue
            break
        done
        local default_name="VLESS-REALITY-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi

    local uuid=$(${SINGBOX_BIN} generate uuid)
    local keypair=$(${SINGBOX_BIN} generate reality-keypair)
    local private_key=$(echo "$keypair" | awk '/PrivateKey/ {print $2}')
    local public_key=$(echo "$keypair" | awk '/PublicKey/ {print $2}')
    local short_id=$(${SINGBOX_BIN} generate rand --hex 8)
    local tag="vless-in-${port}"
    # IPv6处理：YAML用原始IP，链接用带[]的IP
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pk "$private_key" --arg sid "$short_id" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":$sn,"reality":{"enabled":true,"handshake":{"server":$sn,"server_port":443},"private_key":$pk,"short_id":[$sid]}}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": {\"publicKey\": \"$public_key\", \"shortId\": \"$short_id\"}}" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg u "$uuid" --arg sn "$server_name" --arg pbk "$public_key" --arg sid "$short_id" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"tls":true,"network":"tcp","flow":"xtls-rprx-vision","servername":$sn,"client-fingerprint":"chrome","reality-opts":{"public-key":$pbk,"short-id":$sid}}')
    _add_node_to_yaml "$proxy_json" || return 1
    _info "VLESS (REALITY) 节点 [${name}] 配置已写入，等待服务校验..."
    _show_node_link "vless-reality" "$name" "$link_ip" "$port" "$tag" "$uuid" "$server_name" "$public_key" "$short_id"
}

_add_vless_tcp() {
    local node_ip="${server_ip}"
    [[ "$BATCH_MODE" == "true" && -n "$BATCH_IP" ]] && node_ip="$BATCH_IP"
    local port=""
    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        if [ -z "$port" ]; then
            _error "批量创建错误: BATCH_PORT 为空，跳过 VLESS (TCP) 安装。"
            return 1
        fi
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        while true; do
            read -p "请输入监听端口: " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "tcp" && continue
            break
        done
    fi
    # [!] 自定义名称 (批量模式下自动分配)
    local default_name="VLESS-TCP-${port}"
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-TCP-${port}"
    else
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi

    local uuid=$(${SINGBOX_BIN} generate uuid)
    local tag="vless-tcp-in-${port}"
    # IPv6处理：YAML用原始IP，链接用带[]的IP
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"
    
    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" \
        '{"type":"vless","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"flow":""}],"tls":{"enabled":false}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg u "$uuid" \
        '{"name":$n,"type":"vless","server":$s,"port":($p|tonumber),"uuid":$u,"tls":false,"network":"tcp"}')
    _add_node_to_yaml "$proxy_json" || return 1
    _info "VLESS (TCP) 节点 [${name}] 配置已写入，等待服务校验..."
    _show_node_link "vless-tcp" "$name" "$link_ip" "$port" "$tag" "$uuid"
}

_add_hysteria2() {
    [ -z "$server_ip" ] && server_ip=$(_get_ip)
    local node_ip="${server_ip}"
    [[ "$BATCH_MODE" == "true" && -n "$BATCH_IP" ]] && node_ip="$BATCH_IP"
    local port=""
    local server_name="www.amd.com"
    local obfs_password=""
    local port_hopping=""
    local use_multiport="false"

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        if [ -z "$port" ]; then
            _error "批量创建错误: BATCH_PORT 为空，跳过 Hysteria2 安装。"
            return 1
        fi
        server_name="$BATCH_SNI"
        # 批量模式 double check
        [ -z "$node_ip" ] && node_ip="$server_ip"
        [ "$BATCH_HY2_OBFS" != "none" ] && obfs_password=$(${SINGBOX_BIN} generate rand --hex 16)
        port_hopping="$BATCH_HY2_HOP"
        if [ -n "$port_hopping" ]; then
            local port_range_start=$(echo $port_hopping | cut -d'-' -f1)
            local port_range_end=$(echo $port_hopping | cut -d'-' -f2)
            if [ "$port_range_start" -lt 1 ] || [ "$port_range_end" -gt 65535 ] || [ "$port_range_start" -gt "$port_range_end" ]; then
                _error "批量创建错误: HY2 端口跳跃范围 ${port_hopping} 无效。"
                return 1
            fi
            local pf_conflict
            pf_conflict=$(_find_pf_udp_conflict_in_range "$port_range_start" "$port_range_end")
            if [ -n "$pf_conflict" ]; then
                local c_port c_name c_net c_target
                IFS=$'\t' read -r c_port c_name c_net c_target <<< "$pf_conflict"
                _error "批量创建错误: HY2 端口跳跃范围 ${port_hopping} 覆盖已有 ${c_net} 端口转发入口 ${c_port}（${c_name} -> ${c_target}）。"
                return 1
            fi
            local hop_conflict
            hop_conflict=$(_find_udp_hop_conflict_in_range "$port_range_start" "$port_range_end" "hy2-in-${port}")
            if [ -n "$hop_conflict" ]; then
                local c_tag c_name c_range c_mode
                IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$hop_conflict"
                _error "批量创建错误: HY2 端口跳跃范围 ${port_hopping} 与已有跳跃范围 ${c_range} 重叠。"
                _error "冲突节点: ${c_name} (${c_tag}, ${c_mode})。"
                return 1
            fi
            use_multiport="true"
        fi
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        while true; do
            read -p "请输入监听端口: " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "udp" && continue
            break
        done
        read -p "请输入伪装域名 (默认: www.amd.com): " camouflage_domain
        server_name=${camouflage_domain:-"www.amd.com"}
    fi

    local tag="hy2-in-${port}"
    local cert_path="${SINGBOX_DIR}/${tag}.pem"
    local key_path="${SINGBOX_DIR}/${tag}.key"
    _generate_self_signed_cert "$server_name" "$cert_path" "$key_path" || return 1

    local password=""
    if [ "$BATCH_MODE" = "true" ]; then
        password=$(${SINGBOX_BIN} generate rand --hex 16)
    else
        read -p "请输入密码 (默认随机): " password; password=${password:-$(${SINGBOX_BIN} generate rand --hex 16)}
        read -p "是否开启 QUIC 流量混淆 (salamander)? (y/N): " h_choice
        if [[ "$h_choice" == "y" ]]; then
            obfs_password=$(${SINGBOX_BIN} generate rand --hex 16)
        fi
        read -p "是否开启端口跳跃? (y/N): " hop_choice
        if [[ "$hop_choice" == "y" ]]; then
            read -p "请输入端口范围 (如 20000-30000): " port_range
            if [[ "$port_range" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                port_range_start="${BASH_REMATCH[1]}"
                port_range_end="${BASH_REMATCH[2]}"
                if [ "$port_range_start" -lt 1 ] || [ "$port_range_end" -gt 65535 ] || [ "$port_range_start" -gt "$port_range_end" ]; then
                    _error "端口跳跃范围无效。"
                    return 1
                fi
                local pf_conflict
                pf_conflict=$(_find_pf_udp_conflict_in_range "$port_range_start" "$port_range_end")
                if [ -n "$pf_conflict" ]; then
                    local c_port c_name c_net c_target
                    IFS=$'\t' read -r c_port c_name c_net c_target <<< "$pf_conflict"
                    _error "端口跳跃范围 ${port_range} 覆盖了已有 ${c_net} 端口转发入口 ${c_port}（${c_name} -> ${c_target}）。"
                    _error "请调整跳跃范围或先删除/修改该端口转发规则。"
                    return 1
                fi
                local hop_conflict
                hop_conflict=$(_find_udp_hop_conflict_in_range "$port_range_start" "$port_range_end" "$tag")
                if [ -n "$hop_conflict" ]; then
                    local c_tag c_name c_range c_mode
                    IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$hop_conflict"
                    _error "端口跳跃范围 ${port_range} 与已有跳跃范围 ${c_range} 重叠。"
                    _error "冲突节点: ${c_name} (${c_tag}, ${c_mode})。请调整跳跃范围。"
                    return 1
                fi
                port_hopping="$port_range"
                use_multiport="true"
            fi
        fi
    fi
    
    # [!] 自定义名称
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-Hysteria2-${port}"
    else
        local default_name="Hysteria2-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi
    
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"

    local up="${up_speed:-100}"
    local down="${down_speed:-100}"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg pw "$password" --arg op "$obfs_password" --arg cert "$cert_path" --arg key "$key_path" \
        '{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}} | if $op != "" then .obfs={"type":"salamander","password":$op} else . end')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    # [!] 多端口监听模式逻辑：优先使用 nftables，失败则降级到 JSON Inbound (带数量保护)
    local port_hopping_mode=""
    if [ "$use_multiport" == "true" ] && [ -n "$port_hopping" ]; then
        if _nft_apply_redirect_rule add "$port_range_start" "$port_range_end" "$port" "singboxlite-hy2-hop-${tag}"; then
            _save_nftables_rules 2>/dev/null
            port_hopping_mode="nftables"
            _success "已启动底层 nftables 高效 UDP 端口跳跃范围映射: ${port_hopping} -> ${port}"
        fi

        if [ "$port_hopping_mode" != "nftables" ]; then
            _warn "发现防火墙受限 (无 nftables redirect 写权限)，准备降级至 Sing-box 原生多实例监听方案..."
            local hop_count=$((port_range_end - port_range_start + 1))
            if [ "$hop_count" -le 1000 ]; then
                _info "正在生成原生大量监听配置块 (${port_range_start}-${port_range_end})..."
                local batch_array="[]"
                local skipped=0
                for ((p=port_range_start; p<=port_range_end; p++)); do
                    if [ "$p" -eq "$port" ]; then continue; fi
                    if _check_port_conflict "$p" "udp" "true"; then ((skipped++)); continue; fi
                    local hop_tag="${tag}-hop-${p}"
                    batch_array=$(echo "$batch_array" | jq --arg t "$hop_tag" --arg p "$p" --arg pw "$password" --arg cert "$cert_path" --arg key "$key_path" --arg op "$obfs_password" \
                        '. += [{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}} | if $op != "" then .obfs={"type":"salamander","password":$op} else . end]')
                done
                _atomic_modify_json "$CONFIG_FILE" ".inbounds += $batch_array | .inbounds |= unique_by(.tag)" || return 1
                local added_count=$(echo "$batch_array" | jq 'length')
                port_hopping_mode="native"
                _success "安全降级成功：已硬编码 ${added_count} 个原生辅助监听节点 (跳过 ${skipped} 个冲突端口)。"
            else
                _error "降级失败：目标跳跃端口数量 (${hop_count}) 超出低配原生环境的内存承载安全阈值 (1000)！"
                _warn "鉴于当前系统容器不支持内核级 nftables 重定向，且端口数量超配，已自动取消该节点的跳跃设定。"
                port_hopping=""
                port_hopping_mode=""
            fi
        fi
    fi
    
    # 保存元数据（包含端口跳跃信息）
    local meta_json=$(jq -n --arg up "$up" --arg down "$down" --arg op "$obfs_password" --arg hop "$port_hopping" --arg hop_mode "$port_hopping_mode" \
        '{ "up": $up, "down": $down } | if $op != "" then .obfsPassword = $op else . end | if $hop != "" then .portHopping = $hop else . end | if $hop_mode != "" then .portHoppingMode = $hop_mode else . end')
    _atomic_modify_json "$METADATA_FILE" ". + {\"$tag\": $meta_json}" || return 1

    # Clash 配置中的端口（如果有端口跳跃，使用范围格式）
    local clash_ports="$port"
    if [ -n "$port_hopping" ]; then
        clash_ports="$port_hopping"
    fi
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg ports "$clash_ports" --arg pw "$password" --arg sn "$server_name" --arg up "$up" --arg down "$down" --arg op "$obfs_password" --arg hop "$port_hopping" \
        '{
            "name": $n,
            "type": "hysteria2",
            "server": $s,
            "port": ($p|tonumber),
            "password": $pw,
            "sni": $sn,
            "skip-cert-verify": true,
            "alpn": ["h3"],
            "up": ($up|tonumber),
            "down": ($down|tonumber)
        } | if $op != "" then .obfs = "salamander" | .["obfs-password"] = $op else . end | if $hop != "" then .ports = $hop else . end')
    _add_node_to_yaml "$proxy_json" || return 1
    
    _info "Hysteria2 节点 [${name}] 配置已写入，等待服务校验..."
    
    # 显示端口跳跃信息
    if [ -n "$port_hopping" ]; then
        _info "端口跳跃范围: ${port_hopping}"
    fi
    
    _show_node_link "hysteria2" "$name" "$link_ip" "$port" "$tag" "$password" "$server_name" "$obfs_password" "$port_hopping"
}

_add_tuic() {
    local node_ip="${server_ip}"
    [[ "$BATCH_MODE" == "true" && -n "$BATCH_IP" ]] && node_ip="$BATCH_IP"
    local port=""
    local server_name="www.amd.com"

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        server_name="${BATCH_SNI:-www.amd.com}"
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        while true; do
            read -p "请输入监听端口: " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "udp" && continue
            break
        done
        read -p "请输入伪装域名 (默认: www.amd.com): " camouflage_domain
        server_name=${camouflage_domain:-"www.amd.com"}
    fi

    local tag="tuic-in-${port}"
    local cert_path="${SINGBOX_DIR}/${tag}.pem"
    local key_path="${SINGBOX_DIR}/${tag}.key"
    
    _generate_self_signed_cert "$server_name" "$cert_path" "$key_path" || return 1

    local uuid=$(${SINGBOX_BIN} generate uuid); local password=$(${SINGBOX_BIN} generate rand --hex 16)
    
    # [!] 自主生成与名称分配
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-TUICv5-${port}"
    else
        local default_name="TUICv5-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi

    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$uuid" --arg pw "$password" --arg cert "$cert_path" --arg key "$key_path" \
        '{"type":"tuic","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"uuid":$u,"password":$pw}],"congestion_control":"bbr","tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1
    
    local proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg u "$uuid" --arg pw "$password" --arg sn "$server_name" \
        '{"name":$n,"type":"tuic","server":$s,"port":($p|tonumber),"uuid":$u,"password":$pw,"sni":$sn,"skip-cert-verify":true,"alpn":["h3"],"udp-relay-mode":"native","congestion-controller":"bbr"}')
    _add_node_to_yaml "$proxy_json" || return 1
    _info "TUICv5 节点 [${name}] 配置已写入，等待服务校验..."
    _show_node_link "tuic" "$name" "$link_ip" "$port" "$tag" "$uuid" "$password" "$server_name"
}

_add_shadowsocks_menu() {
    local choice=""
    if [ "$BATCH_MODE" = "true" ]; then
        choice="$BATCH_SS_VARIANT"
    else
        clear
        echo "========================================"
        _info "          添加 Shadowsocks 节点"
        echo "========================================"
        echo " [经典 SS]"
        echo " 1) aes-256-gcm"
        echo " 2) chacha20-ietf-poly1305"
        echo " [SS-2022 (强抗重放保护)]"
        echo " 3) 2022-blake3-aes-256-gcm"
        echo " 4) 2022-blake3-aes-256-gcm (带 Padding)"
        echo " [SS-2022 + ShadowTLS (完美伪装组合)]"
        echo " 5) 2022-blake3-aes-256-gcm + ShadowTLS v3"
        echo " 0) 返回"
        echo "========================================"
        read -p "请选择加密方式 [0-5]: " choice
    fi

    local method="" password="" name_prefix="" use_multiplex=false use_shadowtls=false
    case $choice in
        1) 
            method="aes-256-gcm"
            password=$(${SINGBOX_BIN} generate rand --hex 16)
            name_prefix="SS-aes256"
            ;;
        2) 
            method="chacha20-ietf-poly1305"
            password=$(${SINGBOX_BIN} generate rand --hex 16)
            name_prefix="SS-chacha20"
            ;;
        3)
            method="2022-blake3-aes-256-gcm"
            # SS-2022 的 aes-256 需要严格的 32 字节 (256位) base64 密钥
            password=$(${SINGBOX_BIN} generate rand --base64 32)
            name_prefix="SS-2022"
            ;;
        4)
            method="2022-blake3-aes-256-gcm"
            password=$(${SINGBOX_BIN} generate rand --base64 32)
            name_prefix="SS-2022-Padding"
            use_multiplex=true
            _info "已启用 Multiplex + Padding 模式"
            _warning "注意：客户端也必须启用 Multiplex + Padding 才能连接！"
            ;;
        5)
            # SS-2022 256 位版本（抗重放增强）
            method="2022-blake3-aes-256-gcm"
            password=$(${SINGBOX_BIN} generate rand --base64 32)
            name_prefix="SS-ShadowTLS"
            use_shadowtls=true
            ;;
        0) return 1 ;;
        *) _error "无效输入"; return 1 ;;
    esac

    local node_ip="${server_ip}"
    [[ "$BATCH_MODE" == "true" && -n "$BATCH_IP" ]] && node_ip="$BATCH_IP"
    local port=""
    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        read -p "请输入监听端口: " port; [[ -z "$port" ]] && _error "端口不能为空" && return 1
    fi
    
    # [!] 新增：自定义名称
    local name=""
    if [ "$BATCH_MODE" = "true" ]; then
        name="Batch-${name_prefix}-${port}"
    else
        local default_name="${name_prefix}-${port}"
        read -p "请输入节点名称 (默认: ${default_name}): " custom_name
        name=${custom_name:-$default_name}
    fi
    
    local shadowtls_password=""
    local shadowtls_sni="www.amd.com"
    if [ "$use_shadowtls" == "true" ]; then
        shadowtls_password=$(${SINGBOX_BIN} generate rand --hex 16)
        read -p "请输入 ShadowTLS 伪装白名单域名 (默认: www.amd.com): " custom_sni
        shadowtls_sni=${custom_sni:-www.amd.com}
    fi

    local tag="${name_prefix}-in-${port}"
    local yaml_ip="$node_ip"
    local link_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && link_ip="[$node_ip]"

    # 根据是否启用 Multiplex 或 ShadowTLS 生成不同配置
    local inbound_json=""
    local jq_modify_expr=".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)"
    
    if [ "$use_shadowtls" == "true" ]; then
        local ss_tag="${tag}-ss"
        inbound_json=$(jq -n --arg t "$tag" --arg st "$ss_tag" --arg p "$port" --arg m "$method" --arg pw "$password" --arg spw "$shadowtls_password" --arg sni "$shadowtls_sni" \
            '[
                {
                    "type": "shadowtls",
                    "tag": $t,
                    "listen": "::",
                    "listen_port": ($p|tonumber),
                    "version": 3,
                    "users": [
                        {
                            "password": $spw
                        }
                    ],
                    "handshake": {
                        "server": $sni,
                        "server_port": 443
                    },
                    "detour": $st
                },
                {
                    "type": "shadowsocks",
                    "tag": $st,
                    "method": $m,
                    "password": $pw
                }
            ]')
        jq_modify_expr=".inbounds += $inbound_json | .inbounds |= unique_by(.tag)"
    elif [ "$use_multiplex" == "true" ]; then
        # 带 Multiplex + Padding 的配置
        inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg m "$method" --arg pw "$password" \
            '{
                "type": "shadowsocks",
                "tag": $t,
                "listen": "::",
                "listen_port": ($p|tonumber),
                "method": $m,
                "password": $pw,
                "multiplex": {
                    "enabled": true,
                    "padding": true
                }
            }')
        jq_modify_expr=".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)"
    else
        # 标准配置
        inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg m "$method" --arg pw "$password" \
            '{
                "type": "shadowsocks",
                "tag": $t,
                "listen": "::",
                "listen_port": ($p|tonumber),
                "method": $m,
                "password": $pw
            }')
        jq_modify_expr=".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)"
    fi
    _atomic_modify_json "$CONFIG_FILE" "$jq_modify_expr" || return 1

    # YAML 配置也需要根据特定状态生成
    local proxy_json=""
    if [ "$use_shadowtls" == "true" ]; then
        proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg m "$method" --arg pw "$password" --arg spw "$shadowtls_password" --arg sni "$shadowtls_sni" \
            '{
                "name": $n,
                "type": "ss",
                "server": $s,
                "port": ($p|tonumber),
                "cipher": $m,
                "password": $pw,
                "plugin": "shadow-tls",
                "plugin-opts": {
                    "host": $sni,
                    "password": $spw,
                    "version": 3
                }
            }')
    elif [ "$use_multiplex" == "true" ]; then
        proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg m "$method" --arg pw "$password" \
            '{
                "name": $n,
                "type": "ss",
                "server": $s,
                "port": ($p|tonumber),
                "cipher": $m,
                "password": $pw,
                "smux": {
                    "enabled": true,
                    "padding": true
                }
            }')
    else
        proxy_json=$(jq -n --arg n "$name" --arg s "$yaml_ip" --arg p "$port" --arg m "$method" --arg pw "$password" \
            '{
                "name": $n,
                "type": "ss",
                "server": $s,
                "port": ($p|tonumber),
                "cipher": $m,
                "password": $pw
            }')
    fi
    _add_node_to_yaml "$proxy_json" || return 1

    _info "Shadowsocks (${method}) 节点 [${name}] 配置已写入，等待服务校验..."
    if [ "$use_multiplex" == "true" ]; then
        _info "Multiplex + Padding 已启用，客户端需配置对应选项"
    fi
    if [ "$use_shadowtls" == "true" ]; then
        _show_node_link "shadowsocks-shadowtls" "$name" "$link_ip" "$port" "$tag" "$method" "$password" "$shadowtls_password" "$shadowtls_sni"
    else
        _show_node_link "shadowsocks" "$name" "$link_ip" "$port" "$tag" "$method" "$password"
    fi
    return 0
}

_add_socks() {
    local node_ip="${server_ip}"
    [[ "$BATCH_MODE" == "true" && -n "$BATCH_IP" ]] && node_ip="$BATCH_IP"
    local port=""
    local username=""
    local password=""

    if [ "$BATCH_MODE" = "true" ]; then
        port="$BATCH_PORT"
        if [ -z "$port" ]; then
            _error "批量创建错误: BATCH_PORT 为空，跳过 SOCKS5 安装。"
            return 1
        fi
        username=$(${SINGBOX_BIN} generate rand --hex 8)
        password=$(${SINGBOX_BIN} generate rand --hex 16)
    else
        read -p "请输入服务器IP地址 (默认: ${server_ip}): " custom_ip
        node_ip=${custom_ip:-$server_ip}
        while true; do
            read -p "请输入监听端口: " port
            [[ -z "$port" ]] && _error "端口不能为空" && continue
            _check_port_conflict "$port" "tcp" && continue
            break
        done
        read -p "请输入用户名 (默认随机): " username; username=${username:-$(${SINGBOX_BIN} generate rand --hex 8)}
        read -p "请输入密码 (默认随机): " password; password=${password:-$(${SINGBOX_BIN} generate rand --hex 16)}
    fi
    local tag="socks-in-${port}"
    local name="Batch-SOCKS5-${port}"
    [ "$BATCH_MODE" != "true" ] && name="SOCKS5-${port}"
    local display_ip="$node_ip"; [[ "$node_ip" == *":"* ]] && display_ip="[$node_ip]"

    local inbound_json=$(jq -n --arg t "$tag" --arg p "$port" --arg u "$username" --arg pw "$password" \
        '{"type":"socks","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"username":$u,"password":$pw}]}')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json] | .inbounds |= unique_by(.tag)" || return 1

    local proxy_json=$(jq -n --arg n "$name" --arg s "$display_ip" --arg p "$port" --arg u "$username" --arg pw "$password" \
        '{"name":$n,"type":"socks5","server":$s,"port":($p|tonumber),"username":$u,"password":$pw}')
    _add_node_to_yaml "$proxy_json" || return 1
    _info "SOCKS5 节点配置已写入，等待服务校验..."
    _show_node_link "socks" "$name" "$display_ip" "$port" "$tag" "$username" "$password"
}

_view_nodes() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then _warning "当前没有任何节点。"; return; fi
    
    # 统计有效节点数量（排除辅助节点）
    local node_count=$(jq '[.inbounds[] | select(.tag | contains("-hop-") | not)] | length' "$CONFIG_FILE")
    _info "--- 当前节点信息 (共 ${node_count} 个) ---"
    
    # [关键修复] 确保在查看前清空之前的临时链接缓存
    rm -f /tmp/singbox_links.tmp
    
    # [资源优化] 传递紧凑 JSON，循环内用单次 jq 提取 tag/type/port (3次→1次)
    jq -c '.inbounds[]' "$CONFIG_FILE" | while IFS= read -r node; do
        # 合并3次字段提取为1次
        local _base_fields
        _base_fields=$(echo "$node" | jq -r '[.tag, .type, (.listen_port|tostring)] | @tsv')
        local tag type port
        IFS=$'\t' read -r tag type port <<< "$_base_fields"
        
        # 过滤掉多端口监听生成的辅助节点（跳过 tag 中包含 -hop- 的节点）
        if [[ "$tag" == *"-hop-"* ]]; then continue; fi
        
        # 使用统一查找函数
        local proxy_name_to_find=$(_find_proxy_name "$port" "$type" "$tag")

        # 创建显示名称，优先使用 clash.yaml 中的名称，失败则回退到 tag
        local meta_name=$(jq -r --arg t "$tag" '.[$t].name // empty' "$METADATA_FILE" 2>/dev/null)
        local display_name=${proxy_name_to_find:-${meta_name:-$tag}}

        # 优先使用 metadata.json 中的 IP (用于 REALITY 和 TCP)
        local display_server=$(_get_proxy_field "$proxy_name_to_find" ".server")
        # 移除方括号
        local display_ip=$(echo "$display_server" | tr -d '[]')
        # IPv6链接格式：添加[]
        local link_ip="$display_ip"; [[ "$display_ip" == *":"* ]] && link_ip="[$display_ip]"
        
        echo "-------------------------------------"
        # [!] 已修改：使用 display_name
        _info " 节点: ${display_name}"
        local url=""
        
        # [新架构] 优先使用持久化生成的链接（从极源解决动态提取可能存在的 SNI 丢失死角）
        url=$(jq -r --arg t "$tag" '.[$t].share_link // empty' "$METADATA_FILE")
        if { [ -z "$url" ] || [ "$url" == "null" ]; } && [[ "$tag" == argo-* ]] && [ -f "$ARGO_METADATA_FILE" ]; then
            url=$(jq -r --arg t "$tag" '.[$t].share_link // empty' "$ARGO_METADATA_FILE" 2>/dev/null)
        fi
        
        if [ -n "$url" ] && [ "$url" != "null" ]; then
            : # 直接使用持久化链接
        else
            case "$type" in
            "vless")
                # [资源优化] 合并 VLESS 关键字段读取，避免循环内多次 jq
                local _vless_fields
                # [加固] 智能回溯 SNI: 优先 .tls.server_name, 备选 .tls.reality.handshake.server, 保底 www.amd.com
            _vless_fields=$(echo "$node" | jq -r '[.users[0].uuid, (.users[0].flow // ""), (.tls.reality.enabled // false | tostring), (.transport.type // ""), (.tls.enabled // false | tostring), (.tls.server_name // .tls.reality.handshake.server // "www.amd.com"), (.tls.certificate_path // ""), (.transport.path // ""), (.transport.service_name // "")] | @tsv')
            IFS=$'\t' read -r uuid flow is_reality transport_type tls_enabled tls_sn cert_path ws_path grpc_service_name <<< "$_vless_fields"
                
                # [加固] 确保 Reality 模式下的流量控制字段非空 (v2rayN 要求)
                [ "$is_reality" == "true" ] && [ -z "$flow" ] && flow="xtls-rprx-vision"
                
                if [ "$is_reality" == "true" ]; then
                    # [修复] 放弃对 Base64/Hex 密钥使用 @tsv，避免损坏
                    local pk=$(jq -r --arg t "$tag" '.[$t].publicKey // empty' "$METADATA_FILE")
                    local sid=$(jq -r --arg t "$tag" '.[$t].shortId // empty' "$METADATA_FILE")
                    local sn="$tls_sn"
                    local fp="chrome"
                    url="vless://${uuid}@${link_ip}:${port}?security=reality&encryption=none&pbk=$(_url_encode "${pk}")&fp=${fp}&type=tcp&flow=${flow}&sni=${sn}&sid=${sid}#$(_url_encode "$display_name")"
                elif [ "$transport_type" == "ws" ]; then
                    # ws_path 已在上方合并提取
                    local sn="$tls_sn"
                    [ -z "$sn" ] || [ "$sn" == "null" ] && sn=$(_get_proxy_field "$proxy_name_to_find" ".servername")
                    url="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&type=ws&host=${sn}&path=$(_url_encode "$ws_path")&sni=${sn}#$(_url_encode "$display_name")"
                    
                    # Argo 节点元数据已迁移到 argo_metadata.json
                    local argo_domain=""
                    if [[ "$tag" == argo-* ]] && [ -f "$ARGO_METADATA_FILE" ]; then
                        argo_domain=$(jq -r --arg t "$tag" '.[$t].domain // empty' "$ARGO_METADATA_FILE" 2>/dev/null)
                    fi
                    if [ -n "$argo_domain" ] && [ "$argo_domain" != "null" ]; then
                        local argo_ws_path=$(_ws_path_with_early_data "$ws_path")
                        url="vless://${uuid}@${argo_domain}:443?security=tls&encryption=none&type=ws&host=${argo_domain}&path=$(_url_encode "$argo_ws_path")&sni=${argo_domain}#$(_url_encode "$display_name")"
                    fi
                elif [ "$transport_type" == "grpc" ]; then
                    local sn="$tls_sn"
                    [ -z "$sn" ] || [ "$sn" == "null" ] && sn=$(_get_proxy_field "$proxy_name_to_find" ".servername")
                    [ -z "$sn" ] || [ "$sn" == "null" ] && sn="$DEFAULT_SNI"
                    local svc="$grpc_service_name"
                    if [ -z "$svc" ] || [ "$svc" == "null" ]; then
                        svc=$(_get_proxy_field "$proxy_name_to_find" '.["grpc-opts"]["grpc-service-name"]')
                    fi
                    [ -z "$svc" ] || [ "$svc" == "null" ] && svc="grpc"
                    local skip_verify=$(_get_proxy_field "$proxy_name_to_find" '.["skip-cert-verify"]')
                    local insecure_param=""
                    if [[ "$skip_verify" == "true" ]]; then
                        insecure_param="&insecure=1"
                        local cert_pcs=$(_cert_sha256_hex "$cert_path")
                        [ -n "$cert_pcs" ] && insecure_param="${insecure_param}&pcs=${cert_pcs}"
                    fi
                    url="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&type=grpc&serviceName=$(_url_encode "$svc")&sni=${sn}${insecure_param}#$(_url_encode "$display_name")"
                elif [ "$tls_enabled" == "true" ]; then
                    local sn="$tls_sn"
                    url="vless://${uuid}@${link_ip}:${port}?security=tls&encryption=none&type=tcp&sni=${sn}#$(_url_encode "$display_name")"
                else
                    url="vless://${uuid}@${link_ip}:${port}?encryption=none&type=tcp#$(_url_encode "$display_name")"
                fi
                ;;
            "trojan")
                # [资源优化] 合并3次jq为1次
                local _trojan_fields
                _trojan_fields=$(echo "$node" | jq -r '[.users[0].password, (.transport.type // ""), (.transport.path // "")] | @tsv')
                local password transport_type ws_path
                IFS=$'\t' read -r password transport_type ws_path <<< "$_trojan_fields"
                
                if [ "$transport_type" == "ws" ]; then
                    local sn=$(_get_proxy_field "$proxy_name_to_find" ".sni")
                    url="trojan://${password}@${link_ip}:${port}?security=tls&type=ws&host=${sn}&path=$(_url_encode "$ws_path")&sni=${sn}#$(_url_encode "$display_name")"
                    
                    # Argo 节点元数据已迁移到 argo_metadata.json
                    local argo_domain=""
                    if [[ "$tag" == argo-* ]] && [ -f "$ARGO_METADATA_FILE" ]; then
                        argo_domain=$(jq -r --arg t "$tag" '.[$t].domain // empty' "$ARGO_METADATA_FILE" 2>/dev/null)
                    fi
                    if [ -n "$argo_domain" ] && [ "$argo_domain" != "null" ]; then
                        local argo_ws_path=$(_ws_path_with_early_data "$ws_path")
                        url="trojan://${password}@${argo_domain}:443?security=tls&type=ws&host=${argo_domain}&path=$(_url_encode "$argo_ws_path")&sni=${argo_domain}#$(_url_encode "$display_name")"
                    fi
                else
                    local sn=$(_get_proxy_field "$proxy_name_to_find" ".sni")
                    url="trojan://${password}@${link_ip}:${port}?security=tls&type=tcp&sni=${sn}#$(_url_encode "$display_name")"
                fi
                ;;
            "hysteria2")
                local pw=$(echo "$node" | jq -r '.users[0].password')
                local sn="$tls_sn"
                [ -z "$sn" ] || [ "$sn" == "null" ] && sn=$(_get_proxy_field "$proxy_name_to_find" ".sni")
                # [修复] 放弃对混合类型元数据使用 @tsv，避免损坏
                local op=$(jq -r --arg t "$tag" '.[$t].obfsPassword // empty' "$METADATA_FILE")
                local hop=$(jq -r --arg t "$tag" '.[$t].portHopping // empty' "$METADATA_FILE")
                local obfs_param=""; [[ -n "$op" && "$op" != "null" ]] && obfs_param="&obfs=salamander&obfs-password=$(_url_encode "${op}")"
                # 端口跳跃参数
                local hop_param=""; [[ -n "$hop" && "$hop" != "null" ]] && hop_param="&mport=${hop}&ports=${hop}"
                url="hysteria2://${pw}@${link_ip}:${port}?sni=${sn}&insecure=1${obfs_param}${hop_param}#$(_url_encode "$display_name")"
                ;;
            "tuic")
                # [资源优化] 合并2次jq为1次
                local uuid pw
                IFS=$'\t' read -r uuid pw <<< "$(echo "$node" | jq -r '[.users[0].uuid, .users[0].password] | @tsv')"
                local sn=$(_get_proxy_field "$proxy_name_to_find" ".sni")
                url="tuic://${uuid}:${pw}@${link_ip}:${port}?sni=${sn}&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=1#$(_url_encode "$display_name")"
                ;;
            "anytls")
                # [资源优化] 合并2次jq为1次
                local pw sn
                # [加固] 允许 server_name 回溯
                IFS=$'\t' read -r pw sn <<< "$(echo "$node" | jq -r '[.users[0].password, (.tls.server_name // "www.amd.com")] | @tsv')"
                local skip_verify=$(_get_proxy_field "$proxy_name_to_find" ".skip-cert-verify")
                local insecure_param=""
                if [ "$skip_verify" == "true" ]; then
                    insecure_param="&insecure=1"
                fi
                url="anytls://${pw}@${link_ip}:${port}?security=tls&sni=${sn}${insecure_param}&type=tcp#$(_url_encode "$display_name")"
                ;;
            "shadowsocks")
                # [资源优化] 合并2次jq为1次
                local method password
                IFS=$'\t' read -r method password <<< "$(echo "$node" | jq -r '[.method, .password] | @tsv')"
                url="ss://$(_url_encode "${method}:${password}")@${link_ip}:${port}#$(_url_encode "$display_name")"
                ;;
            "socks")
                # [资源优化] 合并2次jq为1次
                local u p
                IFS=$'\t' read -r u p <<< "$(echo "$node" | jq -r '[.users[0].username, .users[0].password] | @tsv')"
                _info "  类型: SOCKS5, 地址: $display_server, 端口: $port, 用户: $u, 密码: $p"
                ;;
        esac
        fi
        [ -n "$url" ] && echo -e "  ${YELLOW}分享链接:${NC} ${url}"
        # 收集链接到临时文件
        [ -n "$url" ] && echo "$url" >> /tmp/singbox_links.tmp
    done
    echo "-------------------------------------"
    
    # 生成聚合 Base64 选项
    if [ -f /tmp/singbox_links.tmp ]; then
        echo ""
        read -p "是否生成聚合 Base64 订阅? (y/N): " gen_base64
        if [[ "$gen_base64" == "y" || "$gen_base64" == "Y" ]]; then
            echo ""
            _info "=== 聚合 Base64 订阅 ==="
            local base64_result=$(cat /tmp/singbox_links.tmp | base64 | tr -d '\n')
            echo -e "${CYAN}${base64_result}${NC}"
            echo ""
            _success "可直接复制上方内容导入 v2rayN 等客户端"
        fi
        rm -f /tmp/singbox_links.tmp
    fi
}

_delete_node() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then _warning "当前没有任何节点。"; return; fi
    _info "--- 节点删除 ---"
    
    # --- [!] 新的列表逻辑 ---
    # 我们需要先构建一个数组，来映射用户输入和节点信息
    local inbound_tags=()
    local inbound_ports=()
    local inbound_types=()
    local display_names=() # 存储显示名称
    local i=1
    # [资源优化] 一次性提取 tag/type/port，避免循环内多次 fork jq
    while IFS=$'\t' read -r tag type port; do
        
        # [!] 过滤辅助节点
        if [[ "$tag" == *"-hop-"* ]]; then continue; fi
        
        # 存储信息
        inbound_tags+=("$tag")
        inbound_ports+=("$port")
        inbound_types+=("$type")

        # 使用 utils.sh 中的统一查找函数
        local proxy_name_to_find=$(_find_proxy_name "$port" "$type" "$tag")
        
        local meta_name=$(jq -r --arg t "$tag" '.[$t].name // empty' "$METADATA_FILE" 2>/dev/null)
        local display_name=${proxy_name_to_find:-${meta_name:-$tag}} # 回退到 metadata/tag
        display_names+=("$display_name") # 存储显示名称
        
        # [!] 已修改：显示自定义名称、类型和端口
        echo -e "  ${CYAN}$i)${NC} ${display_name} (${YELLOW}${type}${NC}) @ ${port}"
        ((i++))
    done < <(jq -r '.inbounds[] | [.tag, .type, (.listen_port|tostring)] | @tsv' "$CONFIG_FILE")
    # --- 列表逻辑结束 ---
    
    # 添加删除所有选项
    local count=${#inbound_tags[@]}
    echo ""
    echo -e "  ${RED}99)${NC} 删除所有节点"

    read -p "请输入要删除的节点编号 (输入 0 返回): " num
    
    [[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -eq 0 ] && return
    
    # 处理删除所有节点
    if [ "$num" -eq 99 ]; then
        read -p "$(echo -e ${RED}"确定要删除所有节点吗? 此操作不可恢复! (输入 yes 确认): "${NC})" confirm_all
        if [ "$confirm_all" != "yes" ]; then
            _info "删除已取消。"
            return
        fi
        
        _info "正在删除所有节点..."
        
        # [安全性加固] 精准分离并销毁仅关联本脚本的 nftables 跳跃端口规则（必须在清空 metadata 之前执行！）
        if [ -f "$METADATA_FILE" ]; then
            jq -r 'to_entries | .[] | select(.value.portHopping) | "\(.key)|\(.value.portHopping)|\(.value.portHoppingMode // \"\")"' "$METADATA_FILE" 2>/dev/null | while IFS="|" read -r ptag hop hop_mode; do
                local psuffix=$(echo "$ptag" | grep -oE "[0-9]+$")
                local hstart="${hop%-*}"
                local hend="${hop#*-}"
                if [ -z "$hop_mode" ]; then
                    if jq -e --arg prefix "${ptag}-hop-" '.inbounds[] | select(.tag | startswith($prefix))' "$CONFIG_FILE" >/dev/null 2>&1; then
                        hop_mode="native"
                    else
                        hop_mode="nftables"
                    fi
                fi
                if [ "$hop_mode" = "nftables" ]; then
                    _nft_apply_redirect_rule delete "$hstart" "$hend" "$psuffix" "singboxlite-hy2-hop-${ptag}"
                fi
            done
            _save_nftables_rules 2>/dev/null
        fi
        
        # 清空配置
        _atomic_modify_json "$CONFIG_FILE" '.inbounds = []'
        _atomic_modify_json "$METADATA_FILE" '{}'
        
        # 清空 clash.yaml 中的代理
        _atomic_modify_yaml "$CLASH_YAML_FILE" '.proxies = []'
        _atomic_modify_yaml "$CLASH_YAML_FILE" '.proxy-groups[] |= (select(.name == "节点选择") | .proxies = ["DIRECT"])'
        
        # 删除所有证书文件
        rm -f ${SINGBOX_DIR}/*.pem ${SINGBOX_DIR}/*.key 2>/dev/null
        
        _success "所有节点已删除！"
        _manage_service "restart"
        return
    fi
    
    # [!] 已修改：现在 count 会在循环外被正确计算
    if [ "$num" -gt "$count" ]; then _error "编号超出范围。"; return; fi

    local index=$((num - 1))
    # [!] 已修改：从数组中获取正确的信息
    local tag_to_del=${inbound_tags[$index]}
    local type_to_del=${inbound_types[$index]}
    local port_to_del=${inbound_ports[$index]}
    local display_name_to_del=${display_names[$index]}

    # --- [!] 新的删除逻辑 ---
    # 使用统一查找函数确定 clash.yaml 中的确切名称
    local proxy_name_to_del=$(_find_proxy_name "$port_to_del" "$type_to_del" "$tag_to_del")

    # [!] 已修改：使用显示名称进行确认
    read -p "$(echo -e ${YELLOW}"确定要删除节点 ${display_name_to_del} 吗? (y/N): "${NC})" confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        _info "删除已取消。"
        return
    fi
    
    # === 关键修复：必须先读取 metadata 判断节点类型，再删除！===
    local node_metadata=$(jq -r --arg tag "$tag_to_del" '.[$tag] // empty' "$METADATA_FILE" 2>/dev/null)
    local node_type=""
    if [ -n "$node_metadata" ]; then
        node_type=$(echo "$node_metadata" | jq -r '.type // empty')
    fi
    
    # [!] 重要修正：不使用索引删除（因为列表已过滤），改为使用 Tag 精确匹配删除
    _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[] | select(.tag == \"$tag_to_del\"))" || return
    
    # [!] 新增：精准剥离该节点绑定的系统级防火墙端口跳跃策略
    local port_hopping=$(echo "$node_metadata" | jq -r '.portHopping // empty' 2>/dev/null)
    local port_hopping_mode=$(echo "$node_metadata" | jq -r '.portHoppingMode // empty' 2>/dev/null)
    if [ -n "$port_hopping" ]; then
        if [ -z "$port_hopping_mode" ]; then
            if jq -e --arg prefix "${tag_to_del}-hop-" '.inbounds[] | select(.tag | startswith($prefix))' "$CONFIG_FILE" >/dev/null 2>&1; then
                port_hopping_mode="native"
            else
                port_hopping_mode="nftables"
            fi
        fi
        local hop_start="${port_hopping%-*}"
        local hop_end="${port_hopping#*-}"
        if [ "$port_hopping_mode" = "nftables" ]; then
            _nft_apply_redirect_rule delete "$hop_start" "$hop_end" "$port_to_del" "singboxlite-hy2-hop-${tag_to_del}"
            _save_nftables_rules 2>/dev/null
            _info "已卸载关联的底层 nftables UDP 端口映射策略 (${port_hopping})"
        fi
    fi
    # [!] 级联清理：同时删除 JSON Fallback 模式可能生成的辅助跳跃子 inbounds (格式: tag-hop-xxx)
    _atomic_modify_json "$CONFIG_FILE" ".inbounds |= map(select(.tag | startswith(\"$tag_to_del-hop-\") | not))" 2>/dev/null
    
    _atomic_modify_json "$METADATA_FILE" "del(.\"$tag_to_del\")" || return
    
    # [!] 已修改：使用找到的 proxy_name_to_del 从 clash.yaml 中删除
    if [ -n "$proxy_name_to_del" ]; then
        _remove_node_from_yaml "$proxy_name_to_del"
    fi

    # 证书清理逻辑 - 包含 hysteria2, tuic, anytls (基于 tag)
    if [ "$type_to_del" == "hysteria2" ] || [ "$type_to_del" == "tuic" ] || [ "$type_to_del" == "anytls" ]; then
        local cert_to_del="${SINGBOX_DIR}/${tag_to_del}.pem"
        local key_to_del="${SINGBOX_DIR}/${tag_to_del}.key"
        if [ -f "$cert_to_del" ] || [ -f "$key_to_del" ]; then
            _info "正在删除节点关联的证书文件: ${cert_to_del}, ${key_to_del}"
            rm -f "$cert_to_del" "$key_to_del"
        fi
    fi
    
    # === 根据之前读取的节点类型清理相关配置 ===
    if [ "$node_type" == "third-party-adapter" ]; then
        # === 第三方适配层：删除 outbound 和 route ===
        _info "检测到第三方适配层，正在清理关联配置..."
        
        # 先查找对应的 outbound (必须在删除 route 之前)
        local outbound_tag=$(jq -r --arg inbound "$tag_to_del" '.route.rules[] | select(.inbound == $inbound) | .outbound' "$CONFIG_FILE" 2>/dev/null | head -n 1)
        
        # 删除 route 规则
        _atomic_modify_json "$CONFIG_FILE" "del(.route.rules[] | select(.inbound == \"$tag_to_del\"))" || true
        
        # 删除对应的 outbound
        if [ -n "$outbound_tag" ] && [ "$outbound_tag" != "null" ]; then
            _atomic_modify_json "$CONFIG_FILE" "del(.outbounds[] | select(.tag == \"$outbound_tag\"))" || true
            _info "已删除关联的 outbound: $outbound_tag"
        fi
    else
        # === 普通节点：只有 inbound，没有额外的 outbound 和 route ===
        # 主脚本创建的节点通常只包含 inbound，outbound 是全局的（如 direct）
        # 如果有特殊的 outbound（如某些协议的专用配置），也要删除
        
        # 检查是否有基于此 inbound 的 route 规则（通常不应该有，但为了清理干净）
        local has_route=$(jq -e ".route.rules[]? | select(.inbound == \"$tag_to_del\")" "$CONFIG_FILE" 2>/dev/null)
        if [ -n "$has_route" ]; then
            _info "检测到关联的路由规则，正在清理..."
            _atomic_modify_json "$CONFIG_FILE" "del(.route.rules[] | select(.inbound == \"$tag_to_del\"))" || true
        fi
        
        # 注意：不删除任何 outbound，因为普通节点的 outbound 通常是共享的全局 outbound
        # （如 "direct"），删除会影响其他节点
    fi
    # === 清理逻辑结束 ===
    
    _success "节点 ${display_name_to_del} 已删除！"
    _manage_service "restart"
}

_check_config() {
    _info "正在检查 sing-box 配置文件..."
    if _validate_merged_config; then
        _success "主配置与中转配置合并检查通过。"
    fi
}

_apply_dns_config() {
    local dns_address="$1"
    local dns_strategy="$2"
    local tmp_file="${CONFIG_FILE}.dns.tmp.$$"
    local backup_file="${CONFIG_FILE}.bak_dns_$(date +%Y%m%d_%H%M%S)"
    local check_result

    # [sing-box 1.14 适配] 使用类型化 DNS 服务器格式
    local server_json
    server_json=$(_dns_address_to_server_json "$dns_address" "dns-local")
    if [ $? -ne 0 ] || [ -z "$server_json" ]; then
        _error "无法识别的 DNS 地址格式：${dns_address}"
        return 1
    fi

    if ! jq --argjson server "$server_json" --arg strategy "$dns_strategy" '
        .dns = {
            "servers": [$server],
            "final": "dns-local",
            "strategy": $strategy
        }
        | .route = (.route // {})
        | .route.default_domain_resolver = {"server": "dns-local", "strategy": $strategy}
    ' "$CONFIG_FILE" > "$tmp_file"; then
        _error "生成 DNS 配置失败。"
        rm -f "$tmp_file"
        return 1
    fi

    _ensure_relay_config || {
        _error "中转配置不存在或无效，DNS 配置未修改。"
        rm -f "$tmp_file"
        return 1
    }
    check_result=$(_check_combined_config_files "$SINGBOX_BIN" "$tmp_file" "$RELAY_CONFIG_FILE" 2>&1)
    if [ $? -ne 0 ]; then
        _error "新的 DNS 配置未通过 config.json + relay.json 组合校验，原配置未修改："
        echo "$check_result"
        rm -f "$tmp_file"
        return 1
    fi

    if ! cp "$CONFIG_FILE" "$backup_file" || ! mv "$tmp_file" "$CONFIG_FILE"; then
        _error "保存 DNS 配置失败。"
        rm -f "$tmp_file"
        return 1
    fi

    if ! _manage_service "restart"; then
        _error "DNS 配置已写入但服务重启失败，正在恢复旧配置。"
        mv "$backup_file" "$CONFIG_FILE" 2>/dev/null || true
        _manage_service "restart" >/dev/null 2>&1 || true
        return 1
    fi
    _success "DNS 配置已保存并通过服务重启校验，备份文件：${backup_file}"
    return 0
}

_dns_config_menu() {
    local current_address current_strategy choice dns_address dns_strategy

    while true; do
        current_address=$(jq -r '
            (.dns.servers[0] // {}) |
            if has("address") then .address
            elif .type == "local" then "local"
            elif .type == "https" then "https://\(.server)\(.path // "/dns-query")"
            elif .type != null then "\(.type)://\(.server)\(if .server_port then ":\(.server_port)" else "" end)"
            else "未设置" end
        ' "$CONFIG_FILE" 2>/dev/null)
        current_strategy=$(jq -r '.dns.strategy // "prefer_ipv4"' "$CONFIG_FILE" 2>/dev/null)
        [ -z "$current_address" ] || [ "$current_address" = "null" ] && current_address="未设置"
        [ -z "$current_strategy" ] || [ "$current_strategy" = "null" ] && current_strategy="prefer_ipv4"

        clear
        echo -e "${CYAN}"
        echo "  ╔═══════════════════════════════════════╗"
        echo "  ║          sing-box DNS 设置            ║"
        echo "  ╚═══════════════════════════════════════╝"
        echo -e "${NC}"
        echo -e "  当前 DNS:  ${GREEN}${current_address}${NC}"
        echo -e "  当前策略:  ${GREEN}${current_strategy}${NC}"
        echo ""
        echo -e "    ${GREEN}[1]${NC} 系统 DNS（local）"
        echo -e "    ${GREEN}[2]${NC} 阿里 DNS（DoH）"
        echo -e "    ${GREEN}[3]${NC} 腾讯 DNSPod（DoH）"
        echo -e "    ${GREEN}[4]${NC} Cloudflare（DoH）"
        echo -e "    ${GREEN}[5]${NC} Google（DoH）"
        echo -e "    ${GREEN}[6]${NC} 自定义 DNS 地址"
        echo -e "    ${GREEN}[7]${NC} 修改域名解析策略"
        echo -e "    ${GREEN}[8]${NC} 查看完整 DNS 配置"
        echo ""
        echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
        echo ""
        read -p "  请输入选项 [0-8]: " choice

        dns_address=""
        dns_strategy="$current_strategy"
        case "$choice" in
            1) dns_address="local" ;;
            2) dns_address="https://dns.alidns.com/dns-query" ;;
            3) dns_address="https://doh.pub/dns-query" ;;
            4) dns_address="https://1.1.1.1/dns-query" ;;
            5) dns_address="https://dns.google/dns-query" ;;
            6)
                echo ""
                echo "  支持 local、IP、udp://、tcp://、tls://、https:// 等 sing-box DNS 地址。"
                read -r -p "  请输入 DNS 地址（留空取消）: " dns_address
                [ -z "$dns_address" ] && continue
                if [[ "$dns_address" =~ [[:space:]] ]]; then
                    _error "DNS 地址不能包含空白字符。"
                    read -n 1 -s -r -p "按任意键继续..."
                    continue
                fi
                ;;
            7)
                echo ""
                echo "    1) prefer_ipv4（推荐，IPv4 优先）"
                echo "    2) prefer_ipv6（IPv6 优先）"
                echo "    3) ipv4_only（仅 IPv4）"
                echo "    4) ipv6_only（仅 IPv6）"
                read -p "  请选择解析策略 [1-4]: " strategy_choice
                case "$strategy_choice" in
                    1) dns_strategy="prefer_ipv4" ;;
                    2) dns_strategy="prefer_ipv6" ;;
                    3) dns_strategy="ipv4_only" ;;
                    4) dns_strategy="ipv6_only" ;;
                    *) _error "无效输入。"; read -n 1 -s -r -p "按任意键继续..."; continue ;;
                esac
                dns_address="$current_address"
                if [ "$dns_address" = "未设置" ]; then
                    dns_address="local"
                fi
                ;;
            8)
                echo ""
                jq '.dns' "$CONFIG_FILE" 2>/dev/null || _error "无法读取 DNS 配置。"
                echo ""
                read -n 1 -s -r -p "按任意键继续..."
                continue
                ;;
            0) return ;;
            *) _error "无效输入，请重试。"; read -n 1 -s -r -p "按任意键继续..."; continue ;;
        esac

        echo ""
        _info "准备设置 DNS 为 ${dns_address}，解析策略为 ${dns_strategy}。"
        read -r -p "  确认保存并重启 sing-box？[Y/n]: " confirm
        if [[ "$confirm" =~ ^[Nn]$ ]]; then
            continue
        fi
        _apply_dns_config "$dns_address" "$dns_strategy"
        echo ""
        read -n 1 -s -r -p "按任意键继续..."
    done
}

_modify_port() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then
        _warning "当前没有任何节点。"
        return
    fi
    
    _info "--- 修改节点端口 ---"
    
    # 列出所有节点
    local inbound_tags=()
    local inbound_ports=()
    local inbound_types=()
    local display_names=()
    
    local i=1
    # [资源优化] 合并3次jq为1次 + 使用公共函数 _find_proxy_name 替代内联查找
    while IFS=$'\t' read -r tag type port; do
        # [!] 过滤辅助跳跃子节点（与 _view_nodes / _delete_node 保持一致）
        if [[ "$tag" == *"-hop-"* ]]; then continue; fi

        inbound_tags+=("$tag")
        inbound_ports+=("$port")
        inbound_types+=("$type")
        
        # [M1] 使用公共函数替代内联重复的代理名查找逻辑
        local proxy_name_to_find=$(_find_proxy_name "$port" "$type" "$tag")
        
        local meta_name=$(jq -r --arg t "$tag" '.[$t].name // empty' "$METADATA_FILE" 2>/dev/null)
        local display_name=${proxy_name_to_find:-${meta_name:-$tag}}
        display_names+=("$display_name")
        
        echo -e "  ${CYAN}$i)${NC} ${display_name} (${YELLOW}${type}${NC}) @ ${GREEN}${port}${NC}"
        ((i++))
    done < <(jq -r '.inbounds[] | [.tag, .type, (.listen_port|tostring)] | @tsv' "$CONFIG_FILE")
    
    read -p "请输入要修改端口的节点编号 (输入 0 返回): " num
    
    [[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -eq 0 ] && return
    
    local count=${#inbound_tags[@]}
    if [ "$num" -gt "$count" ]; then
        _error "编号超出范围。"
        return
    fi
    
    local index=$((num - 1))
    local tag_to_modify=${inbound_tags[$index]}
    local type_to_modify=${inbound_types[$index]}
    local old_port=${inbound_ports[$index]}
    local display_name_to_modify=${display_names[$index]}
    local hop_info=""
    local hop_mode=""
    local hop_range_input=""
    local final_hop_info=""
    local final_hop_start=""
    local final_hop_end=""
    
    _info "当前节点: ${display_name_to_modify} (${type_to_modify})"
    _info "当前端口: ${old_port}"
    
    if [ "$type_to_modify" = "hysteria2" ] && [ -f "$METADATA_FILE" ] && jq -e ".\"$tag_to_modify\"" "$METADATA_FILE" >/dev/null 2>&1; then
        hop_info=$(jq -r ".\"$tag_to_modify\".portHopping // \"\"" "$METADATA_FILE" 2>/dev/null)
        hop_mode=$(jq -r ".\"$tag_to_modify\".portHoppingMode // \"\"" "$METADATA_FILE" 2>/dev/null)
        if [ -n "$hop_info" ] && [ -z "$hop_mode" ]; then
            if jq -e --arg prefix "${tag_to_modify}-hop-" '.inbounds[] | select(.tag | startswith($prefix))' "$CONFIG_FILE" >/dev/null 2>&1; then
                hop_mode="native"
            else
                hop_mode="nftables"
            fi
        fi
    fi
    
    read -p "请输入新的端口号: " new_port
    
    # 验证端口
    if [[ ! "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then
        _error "无效的端口号！"
        return
    fi
    
    if [ "$new_port" -eq "$old_port" ]; then
        _warning "新端口与当前端口相同，无需修改。"
        return
    fi
    
    # 检查端口是否已被占用
    if jq -e --arg tag "$tag_to_modify" --argjson port "$new_port" '.inbounds[] | select(.listen_port == $port and .tag != $tag)' "$CONFIG_FILE" >/dev/null 2>&1; then
        _error "端口 $new_port 已被其他节点使用！"
        return
    fi

    if [[ "$type_to_modify" == "hysteria2" || "$type_to_modify" == "tuic" ]]; then
        local new_port_hop_conflict
        new_port_hop_conflict=$(_find_udp_hop_conflict_in_range "$new_port" "$new_port" "$tag_to_modify")
        if [ -n "$new_port_hop_conflict" ]; then
            local c_tag c_name c_range c_mode
            IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$new_port_hop_conflict"
            _error "新端口 ${new_port} 落在已有 HY2 端口跳跃范围 ${c_range} 内。"
            _error "冲突节点: ${c_name} (${c_tag}, ${c_mode})。请换端口。"
            return
        fi
    fi
    
    if [ -n "$hop_info" ]; then
        _info "检测到当前 HY2 节点启用了端口跳跃 (${hop_mode:-unknown}): ${hop_info}"
        read -p "请输入新的端口跳跃范围（直接回车保留原范围，输入 none 关闭）: " hop_range_input
        if [ -z "$hop_range_input" ]; then
            final_hop_info="$hop_info"
        elif [ "$hop_range_input" = "none" ]; then
            final_hop_info=""
        else
            if [[ ! "$hop_range_input" =~ ^[0-9]+-[0-9]+$ ]]; then
                _error "端口跳跃范围格式无效，应为 start-end。"
                return
            fi
            final_hop_start="${hop_range_input%-*}"
            final_hop_end="${hop_range_input#*-}"
            if [ "$final_hop_start" -lt 1 ] || [ "$final_hop_end" -gt 65535 ] || [ "$final_hop_start" -gt "$final_hop_end" ]; then
                _error "端口跳跃范围无效。"
                return
            fi
            local pf_conflict
            pf_conflict=$(_find_pf_udp_conflict_in_range "$final_hop_start" "$final_hop_end")
            if [ -n "$pf_conflict" ]; then
                local c_port c_name c_net c_target
                IFS=$'\t' read -r c_port c_name c_net c_target <<< "$pf_conflict"
                _error "端口跳跃范围 ${hop_range_input} 覆盖了已有 ${c_net} 端口转发入口 ${c_port}（${c_name} -> ${c_target}）。"
                _error "请调整跳跃范围或先删除/修改该端口转发规则。"
                return
            fi
            local hop_conflict
            hop_conflict=$(_find_udp_hop_conflict_in_range "$final_hop_start" "$final_hop_end" "$tag_to_modify")
            if [ -n "$hop_conflict" ]; then
                local c_tag c_name c_range c_mode
                IFS=$'\t' read -r c_tag c_name c_range c_mode <<< "$hop_conflict"
                _error "端口跳跃范围 ${hop_range_input} 与已有跳跃范围 ${c_range} 重叠。"
                _error "冲突节点: ${c_name} (${c_tag}, ${c_mode})。请调整跳跃范围。"
                return
            fi
            final_hop_info="$hop_range_input"
        fi
    fi
    
    if [ -n "$final_hop_info" ]; then
        final_hop_start="${final_hop_info%-*}"
        final_hop_end="${final_hop_info#*-}"
    fi
    
    _info "正在修改端口: ${old_port} -> ${new_port}"

    local modify_state_dir="/tmp/singbox-port-state.$$"
    if ! _snapshot_node_state "$modify_state_dir"; then
        _error "无法创建端口修改前的配置快照，已取消操作。"
        rm -rf "$modify_state_dir"
        return 1
    fi
    
    # 1. 修改 config.json 主节点端口（按 tag 精确匹配，避免过滤 hop 子节点后索引错位）
    _atomic_modify_json "$CONFIG_FILE" "(.inbounds[] | select(.tag == \"$tag_to_modify\") | .listen_port) = $new_port" || return
    
    # 2. 修改 clash.yaml (全链路同步模式)
    local old_proxy_name=$(_find_proxy_name "$old_port" "$type_to_modify" "$tag_to_modify")
    if [ -n "$old_proxy_name" ]; then
        # 生成新名字：将名字中的旧端口替换为新端口
        local new_proxy_name=$(echo "$old_proxy_name" | sed "s/${old_port}/${new_port}/g")
        
        export OLD_NAME="$old_proxy_name"
        export NEW_NAME="$new_proxy_name"
        export NEW_PORT_VAL="$new_port"
        
        # 原子改名与改端口
        _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(OLD_NAME)) | .name) = env(NEW_NAME)'
        _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME)) | .port) = (env(NEW_PORT_VAL)|tonumber)'
        
        # 全局同步更新所有分组中的引用
        _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxy-groups[].proxies[] | select(. == env(OLD_NAME))) = env(NEW_NAME)'
        
        if [ -n "$final_hop_info" ]; then
            export NEW_PORTS_VAL="$final_hop_info"
            _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(NEW_NAME)) | .ports) = env(NEW_PORTS_VAL)'
        elif [ -n "$hop_info" ]; then
            _atomic_modify_yaml "$CLASH_YAML_FILE" 'del(.proxies[] | select(.name == env(NEW_NAME)) | .ports)'
        fi
        
        _info "Clash 节点名同步: ${old_proxy_name} -> ${new_proxy_name}"
    fi
    
    # [修复] 3. 全局同步更新 metadata.json 中的链接端口与备注名
    if [ -f "$METADATA_FILE" ]; then
        if jq -e ".\"$tag_to_modify\"" "$METADATA_FILE" >/dev/null 2>&1; then
            # [关键修复] _view_nodes 优先读取的是 .share_link 字段 (非 .link)
            local current_link=$(jq -r ".\"$tag_to_modify\".share_link // \"\"" "$METADATA_FILE")
            if [ -n "$current_link" ]; then
                # 精准替换：仅替换 URL 中端口位置的数字（@IP:PORT? 和 #name-PORT 部分），避免误伤 UUID/密码
                local new_link=$(echo "$current_link" | sed -E "s/(:${old_port})([?&#\/]|$)/:${new_port}\2/g; s/(-${old_port})([?&#\/]|$)/-${new_port}\2/g")
                if [ -n "$hop_info" ]; then
                    if [ -n "$final_hop_info" ]; then
                        # 更新 mport 参数
                        if [[ "$new_link" == *"&mport="* ]] || [[ "$new_link" == *"?mport="* ]]; then
                            new_link=$(echo "$new_link" | sed -E "s/([?&]mport=)[0-9]+-[0-9]+/\1${final_hop_info}/g")
                        else
                            new_link="${new_link}&mport=${final_hop_info}"
                        fi
                        # 更新 ports 参数
                        if [[ "$new_link" == *"&ports="* ]] || [[ "$new_link" == *"?ports="* ]]; then
                            new_link=$(echo "$new_link" | sed -E "s/([?&]ports=)[0-9]+-[0-9]+/\1${final_hop_info}/g")
                        else
                            new_link="${new_link}&ports=${final_hop_info}"
                        fi
                    else
                        new_link=$(echo "$new_link" | sed -E 's/[?&]mport=[0-9]+-[0-9]+//g')
                        new_link=$(echo "$new_link" | sed -E 's/[?&]ports=[0-9]+-[0-9]+//g')
                        new_link=$(echo "$new_link" | sed -E 's/\?&/?/g; s/&$//g; s/\?$//g')
                    fi
                fi
                _atomic_modify_json "$METADATA_FILE" ".\"$tag_to_modify\".share_link = \"$new_link\""
                _info "分享链接已同步更新。"
            fi
            local current_meta_name
            current_meta_name=$(jq -r ".\"$tag_to_modify\".name // \"\"" "$METADATA_FILE")
            if [ -n "$current_meta_name" ]; then
                local new_meta_name
                new_meta_name=$(echo "$current_meta_name" | sed "s/${old_port}/${new_port}/g")
                if [ "$new_meta_name" != "$current_meta_name" ]; then
                    _atomic_modify_json "$METADATA_FILE" ".\"$tag_to_modify\".name = \"$new_meta_name\"" || return
                fi
            fi
            if [ -n "$hop_info" ]; then
                if [ -n "$final_hop_info" ]; then
                    _atomic_modify_json "$METADATA_FILE" ".\"$tag_to_modify\".portHopping = \"$final_hop_info\"" || return
                    if [ -n "$hop_mode" ]; then
                        _atomic_modify_json "$METADATA_FILE" ".\"$tag_to_modify\".portHoppingMode = \"$hop_mode\"" || return
                    fi
                else
                    _atomic_modify_json "$METADATA_FILE" "del(.\"$tag_to_modify\".portHopping, .\"$tag_to_modify\".portHoppingMode)" || return
                fi
            fi
        fi
    fi

    # 4. 通用 tag 重命名（所有含端口的 tag 都可能需要更新）
    local new_tag=$(echo "$tag_to_modify" | sed "s/${old_port}/${new_port}/g")
    if [ "$new_tag" != "$tag_to_modify" ]; then
        # 4a. 处理证书文件重命名（仅 Hysteria2, TUIC, AnyTLS 有独立证书）
        if [ "$type_to_modify" == "hysteria2" ] || [ "$type_to_modify" == "tuic" ] || [ "$type_to_modify" == "anytls" ]; then
            local old_cert="${SINGBOX_DIR}/${tag_to_modify}.pem"
            local old_key="${SINGBOX_DIR}/${tag_to_modify}.key"
            local new_cert="${SINGBOX_DIR}/${new_tag}.pem"
            local new_key="${SINGBOX_DIR}/${new_tag}.key"
            
            if [ -f "$old_cert" ] && [ -f "$old_key" ]; then
                mv "$old_cert" "$new_cert"
                mv "$old_key" "$new_key"
                _atomic_modify_json "$CONFIG_FILE" "(.inbounds[] | select(.tag == \"$tag_to_modify\") | .tls.certificate_path) = \"$new_cert\"" || return
                _atomic_modify_json "$CONFIG_FILE" "(.inbounds[] | select(.tag == \"$tag_to_modify\") | .tls.key_path) = \"$new_key\"" || return
            fi
        fi
        
        # 4b. 更新 config.json 中主节点的 tag
        _atomic_modify_json "$CONFIG_FILE" "(.inbounds[] | select(.tag == \"$tag_to_modify\") | .tag) = \"$new_tag\"" || return
        
        # 4c. 迁移 metadata.json 中的 key (旧tag -> 新tag)
        if [ -f "$METADATA_FILE" ] && jq -e ".\"$tag_to_modify\"" "$METADATA_FILE" >/dev/null 2>&1; then
            local meta_content=$(jq ".\"$tag_to_modify\"" "$METADATA_FILE")
            _atomic_modify_json "$METADATA_FILE" "del(.\"$tag_to_modify\") | . + {\"$new_tag\": $meta_content}" || return
        fi
        
        _info "Tag 同步: ${tag_to_modify} -> ${new_tag}"
    fi
    
    # 5. 联动更新端口跳跃规则
    local final_tag="${new_tag:-$tag_to_modify}"
    if [ -n "$hop_info" ]; then
        if [ "$hop_mode" = "nftables" ]; then
            # [修复] 事务性 nftables 更新：先尝试写入新规则，成功后再持久化，失败则回滚
            local nft_ok="false"
            local old_hop_start="${hop_info%-*}"
            local old_hop_end="${hop_info#*-}"

            if [ -n "$final_hop_info" ]; then
                if [ "$final_tag" != "$tag_to_modify" ]; then
                    _nft_apply_redirect_rule delete "$old_hop_start" "$old_hop_end" "$old_port" "singboxlite-hy2-hop-${tag_to_modify}"
                fi
                if _nft_apply_redirect_rule add "$final_hop_start" "$final_hop_end" "$new_port" "singboxlite-hy2-hop-${final_tag}"; then
                    nft_ok="true"
                    _save_nftables_rules 2>/dev/null
                    _info "已将端口跳跃映射从 ${old_port} 联动更新到 ${new_port}，范围: ${final_hop_info}"
                else
                    _nft_apply_redirect_rule delete "$final_hop_start" "$final_hop_end" "$new_port" "singboxlite-hy2-hop-${final_tag}"
                    _error "端口跳跃 nftables 规则更新失败，旧映射保持不变。端口修改仍会继续，但 HY2 跳跃可能失效，请手动检查 nftables 规则！"
                fi
            else
                # === 无新跳跃范围：仅删除旧规则 ===
                _nft_apply_redirect_rule delete "$old_hop_start" "$old_hop_end" "$old_port" "singboxlite-hy2-hop-${tag_to_modify}"
                _save_nftables_rules 2>/dev/null
                _info "已移除端口跳跃映射。"
            fi
        elif [ "$hop_mode" = "native" ]; then
            _atomic_modify_json "$CONFIG_FILE" ".inbounds |= map(select(.tag | startswith(\"${tag_to_modify}-hop-\") | not))" || return
            if [ -n "$new_tag" ] && [ "$new_tag" != "$tag_to_modify" ]; then
                _atomic_modify_json "$CONFIG_FILE" ".inbounds |= map(select(.tag | startswith(\"${new_tag}-hop-\") | not))" || return
            fi
            if [ -n "$final_hop_info" ]; then
                local cert_path="${SINGBOX_DIR}/${final_tag}.pem"
                local key_path="${SINGBOX_DIR}/${final_tag}.key"
                local hy2_password=$(jq -r --arg t "$final_tag" '.inbounds[] | select(.tag == $t) | .users[0].password // ""' "$CONFIG_FILE")
                local hy2_obfs_password=$(jq -r --arg t "$final_tag" '.inbounds[] | select(.tag == $t) | .obfs.password // ""' "$CONFIG_FILE")
                local batch_array="[]"
                local skipped=0
                local p
                for ((p=final_hop_start; p<=final_hop_end; p++)); do
                    if [ "$p" -eq "$new_port" ]; then continue; fi
                    # 仅检查 config.json 中是否有其他节点占用（排除自身旧 hop 端口在进程中仍占用的误判）
                    if _check_port_in_config "$p"; then ((skipped++)); continue; fi
                    local hop_tag="${final_tag}-hop-${p}"
                    batch_array=$(echo "$batch_array" | jq --arg t "$hop_tag" --arg p "$p" --arg pw "$hy2_password" --arg cert "$cert_path" --arg key "$key_path" --arg op "$hy2_obfs_password" '. += [{"type":"hysteria2","tag":$t,"listen":"::","listen_port":($p|tonumber),"users":[{"password":$pw}],"tls":{"enabled":true,"alpn":["h3"],"certificate_path":$cert,"key_path":$key}} | if $op != "" then .obfs={"type":"salamander","password":$op} else . end]')
                done
                if [ "$(echo "$batch_array" | jq 'length')" -gt 0 ]; then
                    _atomic_modify_json "$CONFIG_FILE" ".inbounds += $batch_array" || return
                fi
                _info "已重建原生端口跳跃子节点，范围: ${final_hop_info}"
                if [ "$skipped" -gt 0 ]; then
                    _warning "有 ${skipped} 个跳跃端口因冲突被跳过。"
                fi
            else
                _info "已移除原生端口跳跃子节点。"
            fi
        fi
    fi
    
    if _manage_service "restart" && _verify_service_ready "$new_port" "any"; then
        rm -rf "$modify_state_dir"
        _success "端口修改成功，服务已重新加载并确认端口监听: ${old_port} -> ${new_port}"
    else
        _error "端口修改失败：服务重启或新端口监听校验未通过，正在恢复旧配置。"
        _restore_node_state "$modify_state_dir"
        _manage_service "restart" >/dev/null 2>&1 || true
        rm -rf "$modify_state_dir"
        return 1
    fi
}

# --- 更新管理脚本 ---
# --- 修改节点（端口/SNI）二级菜单 ---
_modify_node_menu() {
    echo ""
    echo -e "    ${GREEN}[1]${NC} 修改节点端口"
    echo -e "    ${GREEN}[2]${NC} 修改节点 SNI"
    echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
    echo ""
    read -p "  请选择 [0-2]: " modify_choice
    case "$modify_choice" in
        1) _modify_port ;;
        2) _modify_sni ;;
        *) ;;
    esac
}

# 校验 SNI 域名格式（含至少一个点的合法主机名）
_validate_sni_domain() {
    [ "${#1}" -le 253 ] || return 1
    [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]] || return 1
    [[ "$1" =~ ^[0-9.]+$ ]] && return 1
    local label
    local labels="${1//./ }"
    for label in $labels; do [ "${#label}" -le 63 ] || return 1; done
    return 0
}

# Only regenerate verified self-signed files dedicated to this script-created node.
_sni_cert_regenerable() {
    local tag="$1" cert="$2" key="$3" subject issuer file
    case "$tag" in */*|*..*) return 1 ;; esac
    [ "$cert" = "${SINGBOX_DIR}/${tag}.pem" ] && [ "$key" = "${SINGBOX_DIR}/${tag}.key" ] || return 1
    [ -f "$cert" ] && [ -f "$key" ] && [ ! -L "$cert" ] && [ ! -L "$key" ] || return 1
    subject=$(openssl x509 -in "$cert" -noout -subject -nameopt RFC2253 2>/dev/null) || return 1
    issuer=$(openssl x509 -in "$cert" -noout -issuer -nameopt RFC2253 2>/dev/null) || return 1
    [ "${subject#subject=}" = "${issuer#issuer=}" ] || return 1
    openssl verify -no_check_time -check_ss_sig -CAfile "$cert" "$cert" >/dev/null 2>&1 || return 1
    for file in "$CONFIG_FILE" "${SINGBOX_DIR}/relay.json"; do
        [ -f "$file" ] || continue
        # A shared certificate/key cannot be replaced without updating its other users.
        jq empty "$file" >/dev/null 2>&1 || return 1
        jq -e --arg t "$tag" --arg c "$cert" --arg k "$key" --arg f "$file" --arg main "$CONFIG_FILE" '
            [.inbounds[]? | select(.tls.certificate_path == $c or .tls.key_path == $k) |
            select($f != $main or (.tag != $t and (.tag|startswith($t + "-hop-")|not)))] | length == 0
            ' "$file" >/dev/null 2>&1 || return 1
    done
    return 0
}

_modify_sni() {
    # Scope signal handlers and exported jq values to this transaction.
    (
    trap - EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then
        _warning "当前没有任何节点。"
        return
    fi

    _info "--- 修改节点 SNI ---"

    # 只列出带 TLS SNI 的节点（Reality / TLS 类）；SS、SOCKS5、纯 VLESS 无 SNI
    local inbound_tags=()
    local inbound_ports=()
    local inbound_types=()
    local inbound_snis=()
    local display_names=()

    local i=1
    while IFS=$'\t' read -r tag type port sni; do
        if [[ "$tag" == *"-hop-"* ]]; then continue; fi
        [ -z "$sni" ] && continue

        inbound_tags+=("$tag")
        inbound_ports+=("$port")
        inbound_types+=("$type")
        inbound_snis+=("$sni")

        local proxy_name_to_find=$(_find_proxy_name "$port" "$type" "$tag")
        local meta_name=$(jq -r --arg t "$tag" '.[$t].name // empty' "$METADATA_FILE" 2>/dev/null)
        local display_name=${proxy_name_to_find:-${meta_name:-$tag}}
        display_names+=("$display_name")

        echo -e "  ${CYAN}$i)${NC} ${display_name} (${YELLOW}${type}${NC}) @ ${GREEN}${port}${NC}  SNI: ${CYAN}${sni}${NC}"
        ((i++))
    done < <(jq -r '.inbounds[] | [.tag, .type, (.listen_port|tostring), (.tls.server_name // "")] | @tsv' "$CONFIG_FILE")

    if [ ${#inbound_tags[@]} -eq 0 ]; then
        _warning "没有可修改 SNI 的节点（仅 Reality / TLS 类节点有 SNI）。"
        return
    fi

    local num new_sni regen_choice
    read -r -p "请输入要修改 SNI 的节点编号 (输入 0 返回): " num || return
    [[ "$num" =~ ^[0-9]+$ ]] || return
    [ "${#num}" -le 6 ] || { _error "编号超出范围。"; return 1; }
    num=$((10#$num))
    [ "$num" -eq 0 ] && return

    local count=${#inbound_tags[@]}
    if [ "$num" -gt "$count" ]; then
        _error "编号超出范围。"
        return
    fi

    local index=$((num - 1))
    local tag_to_modify=${inbound_tags[$index]}
    local type_to_modify=${inbound_types[$index]}
    local port_to_modify=${inbound_ports[$index]}
    local sni_socket_proto=tcp
    case "$type_to_modify" in hysteria2|tuic) sni_socket_proto=udp ;; esac
    local old_sni=${inbound_snis[$index]}
    local display_name_to_modify=${display_names[$index]}

    local node_json=$(jq -c --arg t "$tag_to_modify" '.inbounds[] | select(.tag == $t)' "$CONFIG_FILE")
    local is_reality=$(echo "$node_json" | jq -r '.tls.reality.enabled // false')
    local cert_path=$(echo "$node_json" | jq -r '.tls.certificate_path // ""')
    local key_path=$(echo "$node_json" | jq -r '.tls.key_path // ""')

    _info "当前节点: ${display_name_to_modify} (${type_to_modify})"
    _info "当前 SNI: ${old_sni}"
    if [ "$is_reality" == "true" ]; then
        _info "Reality 节点：新 SNI 必须是支持 TLS 1.3 + HTTP/2 且直连可访问的真实域名（可用主菜单 [20] SNI 优选测试）。"
    fi

    read -r -p "请输入新的 SNI 域名: " new_sni || return
    new_sni=$(printf '%s' "$new_sni" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    if [ -z "$new_sni" ]; then _warning "输入为空，已取消。"; return; fi
    if ! _validate_sni_domain "$new_sni"; then _error "SNI 域名格式无效！"; return; fi
    if [ "$new_sni" == "$old_sni" ]; then _warning "新 SNI 与当前相同，无需修改。"; return; fi

    # 自签证书节点询问是否重新生成证书（在写配置前确认，便于失败时整体回滚）
    local regen_cert="false"
    if [ "$is_reality" != "true" ] && _sni_cert_regenerable "$tag_to_modify" "$cert_path" "$key_path"; then
        read -r -p "检测到自签名证书，是否同时为新 SNI 重新生成证书? (Y/n): " regen_choice || return
        if [[ "$regen_choice" != "n" && "$regen_choice" != "N" ]]; then
            regen_cert="true"
        fi
    fi
    if [ "$is_reality" != true ] && [ "$regen_cert" != true ]; then
        _warn "证书未重签：新 SNI 必须已被现有证书覆盖或符合客户端固定指纹策略；否则客户端可能拒绝连接。"
    fi

    _info "正在修改 SNI: ${old_sni} -> ${new_sni}"
    export SNI_TAG_VALUE="$tag_to_modify"
    export SNI_NEW_VALUE="$new_sni"

    # 备份配置与证书，任一步失败可整体回滚
    local sni_state_dir
    sni_state_dir=$(mktemp -d /tmp/singbox-sni-state.XXXXXX) || return 1
    if ! _snapshot_node_state "$sni_state_dir"; then
        _error "无法完整备份配置，取消 SNI 修改。"
        rm -rf "$sni_state_dir"
        return 1
    fi
    if [ "$regen_cert" == "true" ]; then
        if ! cp -p "$cert_path" "$sni_state_dir/certificate.pem" ||
           ! cp -p "$key_path" "$sni_state_dir/key.pem"; then
            _error "无法备份证书与私钥，取消 SNI 修改。"
            rm -rf "$sni_state_dir"
            return 1
        fi
    fi

    local sni_pending=false sni_restarted=false
    _rollback_sni_change() {
        sni_pending=false
        local rollback_rc=0
        _restore_node_state "$sni_state_dir" || rollback_rc=1
        if [ "$regen_cert" == "true" ]; then
            cp -p "$sni_state_dir/certificate.pem" "$cert_path" || rollback_rc=1
            cp -p "$sni_state_dir/key.pem" "$key_path" || rollback_rc=1
        fi
        if [ "$rollback_rc" -eq 0 ]; then
            _info "已恢复 SNI 修改前的文件。"
        else
            _error "部分文件恢复失败，请使用保留快照人工恢复，勿继续修改节点。"
        fi
        _info "SNI 修改前的恢复快照保留在: ${sni_state_dir}（包含敏感配置，请勿公开）。"
        return "$rollback_rc"
    }
    trap 'if [ "$sni_pending" = true ]; then
        if _rollback_sni_change && [ "$sni_restarted" = true ]; then
            if ! _manage_service restart >/dev/null 2>&1 || ! _verify_service_ready "$port_to_modify" "$sni_socket_proto"; then
                _error "中断恢复后旧服务仍未就绪，请检查日志及保留快照。"
            fi
        fi
    fi' EXIT
    sni_pending=true

    # 1. config.json: 主节点及 HY2 跳跃子节点统一更新 server_name；Reality 同步 handshake.server
    if ! _atomic_modify_json "$CONFIG_FILE" '.inbounds |= map(if ((.tag == env.SNI_TAG_VALUE) or (.tag | startswith(env.SNI_TAG_VALUE + "-hop-"))) and ((.tls.server_name // null) != null) then .tls.server_name = env.SNI_NEW_VALUE else . end)'; then
        _error "更新配置失败！"; _rollback_sni_change; return 1
    fi
    if [ "$is_reality" == "true" ]; then
        if ! _atomic_modify_json "$CONFIG_FILE" '.inbounds |= map(if (.tag == env.SNI_TAG_VALUE) and ((.tls.reality // null) != null) then .tls.reality.handshake.server = env.SNI_NEW_VALUE else . end)'; then
            _error "更新 Reality 握手域名失败！"; _rollback_sni_change; return 1
        fi
    fi

    # 2. 自签证书节点：为新 SNI 重新生成证书并记录新指纹
    local old_fp=""
    local new_fp=""
    if [ "$regen_cert" == "true" ]; then
        old_fp=$(_cert_sha256_hex "$sni_state_dir/certificate.pem")
        if _generate_self_signed_cert "$new_sni" "$cert_path" "$key_path"; then
            new_fp=$(_cert_sha256_hex "$cert_path")
        else
            _error "证书重新生成失败！"; _rollback_sni_change; return 1
        fi
    fi

    # 3. sing-box 校验，失败回滚
    if ! _validate_merged_config >/dev/null 2>&1; then
        _error "新配置未通过合并配置校验，正在恢复旧文件。"
        _rollback_sni_change
        return 1
    fi

    # 4. clash.yaml 同步（vless 用 servername，其余协议用 sni；只更新已存在的字段）
    local proxy_name=$(_find_proxy_name "$port_to_modify" "$type_to_modify" "$tag_to_modify")
    if [ -n "$proxy_name" ] && [ -f "$CLASH_YAML_FILE" ]; then
        export SNI_PROXY_NAME="$proxy_name"
        export NEW_SNI_VAL="$new_sni"
        if ! _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(SNI_PROXY_NAME)) | select(has("servername")) | .servername) = env(NEW_SNI_VAL)' ||
           ! _atomic_modify_yaml "$CLASH_YAML_FILE" '(.proxies[] | select(.name == env(SNI_PROXY_NAME)) | select(has("sni")) | .sni) = env(NEW_SNI_VAL)'; then
            _error "客户端 YAML 同步失败，正在恢复旧文件。"; _rollback_sni_change; return 1
        fi
        _info "Clash 配置 SNI 已同步: ${proxy_name}"
    fi

    # 5. metadata.json: server_name 字段与分享链接 sni/pcs/pinSHA256 参数
    if [ -f "$METADATA_FILE" ] && jq -e --arg t "$tag_to_modify" '.[$t]' "$METADATA_FILE" >/dev/null 2>&1; then
        if ! _atomic_modify_json "$METADATA_FILE" 'if (.[env.SNI_TAG_VALUE] | has("server_name")) then .[env.SNI_TAG_VALUE].server_name = env.SNI_NEW_VALUE else . end'; then
            _error "SNI 元数据同步失败，正在恢复旧文件。"; _rollback_sni_change; return 1
        fi
        local current_link=$(jq -r --arg t "$tag_to_modify" '.[$t].share_link // ""' "$METADATA_FILE")
        if [ -n "$current_link" ]; then
            local new_link=$(echo "$current_link" | sed -E "s/([?&]sni=)[^&#]*/\1${new_sni}/g; s/([?&]peer=)[^&#]*/\1${new_sni}/g")
            if [ -n "$new_fp" ]; then
                new_link=$(echo "$new_link" | sed -E "s/([?&](pcs|pinSHA256)=)[0-9a-fA-F]+/\1${new_fp}/g")
            fi
            export SNI_LINK_VALUE="$new_link"
            if ! _atomic_modify_json "$METADATA_FILE" '.[env.SNI_TAG_VALUE].share_link = env.SNI_LINK_VALUE'; then
                _error "分享链接同步失败，正在恢复旧文件。"; _rollback_sni_change; return 1
            fi
        fi
    fi

    sni_restarted=true
    if ! _manage_service "restart" || ! _verify_service_ready "$port_to_modify" "$sni_socket_proto"; then
        _error "SNI 已修改但服务重启或端口就绪检查失败，正在恢复旧配置。"
        if _rollback_sni_change; then
            if ! _manage_service "restart" >/dev/null 2>&1 || ! _verify_service_ready "$port_to_modify" "$sni_socket_proto"; then
                _error "旧配置恢复后服务仍未就绪，请检查服务日志。"
            fi
        fi
        return 1
    fi
    sni_pending=false
    rm -rf "$sni_state_dir"
    _success "SNI 修改成功，服务已重新加载: ${old_sni} -> ${new_sni}"
    _info "请在客户端更新订阅或重新导入下方链接；已导入节点的 SNI 不会随服务端自动更新。"

    local updated_link=$(jq -r --arg t "$tag_to_modify" '.[$t].share_link // ""' "$METADATA_FILE" 2>/dev/null)
    if [ -n "$updated_link" ]; then
        echo ""
        echo -e "更新后的分享链接:"
        echo -e "${CYAN}${updated_link}${NC}"
    fi
    if [ -n "$new_fp" ]; then
        _info "自签证书已按新 SNI 重新生成，客户端如固定了证书指纹（pcs/pinSHA256）请使用新链接。"
    fi
    )
}

# ============================================================
# --- SNI 候选筛选（Reality/TLS 伪装域名）---
# 优选标准参考 Reality 社区规范（XTLS/RealiTLScanner 项目思路）：
#   目标域名需支持 TLS 1.3 + HTTP/2、直连可通、无跳转、非过于大众的域名
# ============================================================

# 国内线路参考目录：格式为 运营商|地区|DNS IP|经度|纬度|Globalping ASN。
# DNS IP 用于当前 VPS 的连通性参考；真实的国内出发测试由 Globalping 运营商探针完成。
_sni_source_catalog() {
    cat <<'EOF'
电信|成都|61.139.2.69|104.0663|30.6667|4134
电信|北京|220.181.12.199|116.3971|39.9075|4134
电信|上海|202.96.209.133|121.4689|31.2243|4134
电信|广州|202.96.128.166|113.2646|23.1274|4134
电信|合肥|61.132.163.68|117.2808|31.8639|4134
电信|厦门|218.85.152.99|118.0819|24.4798|4134
电信|贵阳|202.98.192.67|106.7167|26.5833|4134
电信|洛阳|222.88.88.88|112.4536|34.6836|4134
电信|哈尔滨|219.147.198.230|126.6500|45.7500|4134
电信|南京|218.2.2.2|118.7778|32.0617|4134
电信|南昌|202.101.224.69|115.9333|28.5500|4134
电信|天津|219.150.32.132|117.1767|39.1422|4134
电信|昆明|222.172.200.68|102.7183|25.0389|4134
联通|重庆|221.5.203.98|106.5528|29.5628|4837
联通|成都|119.6.6.6|104.0663|30.6667|4837
联通|北京|111.201.101.156|116.3971|39.9075|4837
联通|深圳|210.21.196.6|114.1333|22.5333|4837
联通|河北|202.99.160.68|115.2750|39.8897|4837
联通|哈尔滨|202.97.224.69|126.6500|45.7500|4837
联通|上海|140.207.198.6|121.4689|31.2243|4837
联通|长春|202.98.0.68|125.3228|43.8800|4837
联通|青岛|202.102.128.68|120.3719|36.0986|4837
联通|广州|120.80.88.88|113.2646|23.1274|4837
联通|杭州|221.12.1.227|120.1614|30.2936|4837
移动|北京|221.130.33.60|116.3971|39.9075|9808
移动|上海|211.136.112.50|121.4689|31.2243|9808
移动|广州|211.136.192.6|113.2646|23.1274|9808
移动|成都|183.221.253.100|104.0663|30.6667|9808
移动|南京|221.131.143.69|118.7778|32.0617|9808
移动|合肥|211.138.180.2|117.2808|31.8639|9808
移动|青岛|218.201.96.130|120.3719|36.0986|9808
移动|太原|211.138.106.2|112.5615|37.8694|9808
移动|济南|211.137.191.26|116.9972|36.6683|9808
移动|杭州|211.140.13.188|120.1614|30.2936|9808
移动|南昌|211.141.90.68|115.9333|28.5500|9808
移动|西安|211.137.130.19|108.9286|34.2583|9808
移动|海口|221.179.38.7|110.3417|20.0458|9808
移动|郑州|211.138.30.66|113.6486|34.7578|9808
移动|重庆|218.201.4.3|106.5531|29.5628|9808
移动|贵州|211.139.5.29|110.6898|30.9969|9808
EOF
}

# 通过 Globalping 从中国运营商探针发起测量；返回完整 JSON。
_sni_globalping_city() {
    case "$1" in
        成都) echo Chengdu ;; 北京) echo Beijing ;; 上海) echo Shanghai ;;
        广州) echo Guangzhou ;; 合肥) echo Hefei ;; 厦门) echo Xiamen ;;
        贵阳) echo Guiyang ;; 洛阳) echo Luoyang ;; 哈尔滨) echo Harbin ;;
        南京) echo Nanjing ;; 南昌) echo Nanchang ;; 天津) echo Tianjin ;;
        昆明) echo Kunming ;; 重庆) echo Chongqing ;; 深圳) echo Shenzhen ;;
        长春) echo Changchun ;; 青岛) echo Qingdao ;; 杭州) echo Hangzhou ;;
        太原) echo Taiyuan ;; 济南) echo Jinan ;; 西安) echo "Xi'an" ;;
        海口) echo Haikou ;; 郑州) echo Zhengzhou ;;
        *) echo "" ;;
    esac
}

_sni_globalping_measure() {
    local measurement_type="$1" target="$2" locations_json="$3" fallback_json="${4:-}"
    local payload response measurement_id data state http_code response_file
    local requested_count fallback_expected_count actual_count usable_count fallback_data fallback_count
    printf '%s' "$locations_json" | jq -e 'type == "array" and length > 0 and length <= 5 and
        all(.[]; .country == "CN" and .limit == 1)' >/dev/null 2>&1 || return 1
    if [ -n "$fallback_json" ]; then
        printf '%s' "$fallback_json" | jq -e 'type == "array" and length > 0 and length <= 5 and
            all(.[]; .country == "CN" and .limit == 1)' >/dev/null 2>&1 || return 1
        fallback_expected_count=$(printf '%s' "$fallback_json" | jq -r 'length') || return 1
    fi
    if [ "$measurement_type" = http ]; then
        payload=$(jq -nc --arg type "$measurement_type" --arg target "$target" --argjson locations "$locations_json" \
            '{type:$type,target:$target,locations:$locations,measurementOptions:{protocol:"HTTP2",ipVersion:4,request:{method:"HEAD"}}}') || return 1
    else
        payload=$(jq -nc --arg type "$measurement_type" --arg target "$target" --argjson locations "$locations_json" \
            '{type:$type,target:$target,locations:$locations}') || return 1
    fi
    response_file=$(mktemp /tmp/sni-globalping.XXXXXX) || return 1
    http_code=$(curl -q -sS --connect-timeout 8 --max-time 15 -X POST \
        -H 'content-type: application/json' -H "user-agent: singbox-lite-sni/${SCRIPT_VERSION}" \
        --data "$payload" -o "$response_file" -w '%{http_code}' \
        'https://api.globalping.io/v1/measurements' 2>/dev/null)
    if [ "$http_code" = 422 ] && [ -n "$fallback_json" ] && \
       jq -e '.error.type == "no_probes_found"' "$response_file" >/dev/null 2>&1; then
        rm -f "$response_file"
        _warn "所选城市缺少可用探针，回退到同运营商中国探针；实际城市以结果为准。"
        fallback_data=$(_sni_globalping_measure "$measurement_type" "$target" "$fallback_json" '') || return 1
        printf '%s' "$fallback_data" | jq -c --argjson expected "$fallback_expected_count" --argjson original "$(printf '%s' "$locations_json" | jq -r 'length')" \
            '. + {_singboxFallback:true,_singboxExpectedCount:$expected,_singboxOriginalExpectedCount:$original}'
        return
    fi
    if [ "$http_code" != 202 ]; then
        _warn "Globalping 创建测量失败（HTTP ${http_code:-网络错误}）。"
        rm -f "$response_file"
        return 1
    fi
    response=$(<"$response_file")
    rm -f "$response_file"
    response=$(printf '%s' "$response" | tr -d '\000-\010\013\014\016-\037')
    measurement_id=$(printf '%s' "$response" | jq -r '.id // empty')
    [[ "$measurement_id" =~ ^[A-Za-z0-9_-]+$ ]] && [ "${#measurement_id}" -le 128 ] || return 1

    data=""
    state=""
    # Globalping 的 HTTP 探针可能要等待目标首字节；总轮询窗口约 30 秒。
    local deadline=$((SECONDS + 30))
    while [ "$SECONDS" -lt "$deadline" ]; do
        sleep 1
        data=$(curl -q -fsS --connect-timeout 5 --max-time 6 \
            "https://api.globalping.io/v1/measurements/${measurement_id}" 2>/dev/null) || continue
        data=$(printf '%s' "$data" | tr -d '\000-\010\013\014\016-\037')
        state=$(printf '%s' "$data" | jq -r '.status // empty' 2>/dev/null) || continue
        [[ "$state" == "finished" || "$state" == "failed" ]] && break
    done
    [ "$state" = "finished" ] || return 1

    requested_count=$(printf '%s' "$locations_json" | jq -r 'length')
    actual_count=$(printf '%s' "$data" | jq -r '(.results // []) | length')
    usable_count=$(printf '%s' "$data" | jq -r --arg type "$measurement_type" --argjson locations "$locations_json" '
        [.results[]? | . as $r | select($r.probe.country == "CN") |
            select(any($locations[]; .asn == $r.probe.asn and
                (.city == null or ((.city|ascii_downcase) == (($r.probe.city // "")|ascii_downcase))))) |
            select(if $type == "http" then
                $r.result.status == "finished" and $r.result.tls.protocol == "TLSv1.3" and
                $r.result.tls.authorized == true and $r.result.statusCode >= 200 and $r.result.statusCode < 300
            else $r.result.stats.avg != null end)] | length') || return 1
    if [ -n "$fallback_json" ] && [ "$usable_count" -lt "$requested_count" ] 2>/dev/null; then
        _warn "精确城市有效探针不足（${usable_count}/${requested_count}，返回 ${actual_count} 条），尝试同运营商中国探针回退；实际城市以结果为准。"
        fallback_data=$(_sni_globalping_measure "$measurement_type" "$target" "$fallback_json" '') || fallback_data=''
        if [ -n "$fallback_data" ]; then
            fallback_count=$(printf '%s' "$fallback_data" | jq -r --arg type "$measurement_type" --argjson locations "$fallback_json" '
                [.results[]? | . as $r | select(any($locations[]; .asn == $r.probe.asn)) |
                    select($r.probe.country == "CN" and
                        (if $type == "http" then
                            $r.result.status == "finished" and $r.result.tls.protocol == "TLSv1.3" and
                            $r.result.tls.authorized == true and $r.result.statusCode >= 200 and $r.result.statusCode < 300
                        else $r.result.stats.avg != null end))] | length') || fallback_count=0
            if { [ "$fallback_count" -gt "$usable_count" ] ||
                 { [ "$fallback_count" -eq "$fallback_expected_count" ] && [ "$usable_count" -lt "$requested_count" ]; }; } 2>/dev/null; then
                data=$(printf '%s' "$fallback_data" | jq -c --argjson expected "$fallback_expected_count" --argjson original "$requested_count" \
                    '. + {_singboxFallback:true,_singboxExpectedCount:$expected,_singboxOriginalExpectedCount:$original}')
                _warn "已采用运营商回退结果（有效运营商 ${fallback_count}/${fallback_expected_count}；原选城市不再精确匹配）。"
            fi
        fi
    fi
    printf '%s\n' "$data"
}

# 输出: 平均 TLS 毫秒<TAB>成功探针数<TAB>探针详情
_sni_globalping_http() {
    local data avg good details protocols requested expected http_good coverage
    data=$(_sni_globalping_measure http "$1" "$2" "$3") || return 1
    # Reject malformed/incomplete API data before shell arithmetic or TSV parsing.
    printf '%s' "$data" | jq -e '
        type == "object" and .status == "finished" and (.results|type == "array") and
        (.probesCount|type == "number" and . >= 1 and . <= 5 and . == floor) and
        .probesCount == (.results|length) and all(.results[];
            (.probe|type == "object") and (.result|type == "object") and
            (.probe.city == null or (.probe.city|type == "string")) and
            (.probe.network == null or (.probe.network|type == "string")) and
            (.result.timings.tls == null or
                (.result.timings.tls|type == "number" and . >= 0 and . <= 60000)) and
            (.result.statusCode == null or
                (.result.statusCode|type == "number" and . >= 100 and . <= 599 and . == floor)))
        ' >/dev/null 2>&1 || { _warn "Globalping HTTP 响应字段异常或探针结果不完整，跳过评分。"; return 1; }
    avg=$(printf '%s' "$data" | jq -r '
        [.results[]? | select(.probe.country == "CN" and .result.tls.protocol == "TLSv1.3" and .result.tls.authorized == true) | .result.timings.tls // empty] |
        if length > 0 then (add / length | floor | tostring) else empty end')
    good=$(printf '%s' "$data" | jq -r '[.results[]? | select(.probe.country == "CN" and .result.tls.protocol == "TLSv1.3" and .result.tls.authorized == true) | .result.timings.tls // empty] | length')
    [ -n "$avg" ] && [ "$good" -gt 0 ] 2>/dev/null || {
        _warn "${1}: 无中国探针完成证书有效的 TLS1.3 测试；HTTP 成功也不代表符合 Reality 标准。"; return 1;
    }
    protocols=$(printf '%s' "$data" | jq -r '[.results[]? | select(.result.timings.tls != null) |
        (.result.tls.protocol // "unknown")] | unique | join(",")')
    requested=$(printf '%s' "$data" | jq -r '.probesCount // 0')
    expected=$(printf '%s' "$data" | jq -r --argjson locations "$2" '._singboxExpectedCount // ($locations | length)')
    details=$(printf '%s' "$data" | jq -r '[.results[]? |
        ((.probe.city // "?") + "/" + (.probe.network // "?") + " AS" + ((.probe.asn // 0)|tostring) + " @ " +
         ((.probe.longitude // 0)|tostring) + "," + ((.probe.latitude // 0)|tostring) +
         " [TLS=" + (.result.tls.protocol // "unknown") + ", HTTP=" + ((.result.statusCode // "none")|tostring) +
         ", status=" + (.result.status // "unknown") + "]")] |
        join("; ") | gsub("[\u0000-\u001f\u007f]"; " ")')
    http_good=$(printf '%s' "$data" | jq -r '[.results[]? |
        select(.probe.country == "CN" and .result.tls.protocol == "TLSv1.3" and
        .result.tls.authorized == true and .result.status == "finished" and
        .result.statusCode >= 200 and .result.statusCode < 300)] | length')
    coverage=$(printf '%s' "$data" | jq -r --argjson locations "$2" '
        def valid($r):
            $r.probe.country == "CN" and $r.result.tls.protocol == "TLSv1.3" and
            $r.result.tls.authorized == true and $r.result.status == "finished" and
            $r.result.statusCode >= 200 and $r.result.statusCode < 300;
        . as $data | .results as $r |
        if $data._singboxFallback == true then
            ([$locations[].asn] | unique) as $asns |
            [$asns[] | . as $asn | any($r[]?; .probe.asn == $asn and valid(.))] |
            if length > 0 and all(. == true) then "complete-fallback" else "partial-fallback" end
        else
            [$locations[] | . as $loc | any($r[]?;
                .probe.asn == $loc.asn and
                ($loc.city == null or (((.probe.city // "")|ascii_downcase) == ($loc.city|ascii_downcase))) and valid(.))] |
            if length > 0 and all(. == true) then "complete" else "partial" end
        end') || return 1
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$avg" "$good" "$details" "$protocols" "$requested" "$http_good" "$coverage" "$expected"
}

_sni_globalping_ping_vps() {
    local data="$1"
    printf '%s' "$data" | jq -r '.results[]? |
        (.probe.city // "?") + "/" + (.probe.network // "?") +
        " ASN" + ((.probe.asn // 0)|tostring) +
        " (" + ((.probe.longitude // 0)|tostring) + "," +
        ((.probe.latitude // 0)|tostring) + "): " +
        (if .result.stats.avg != null then
            ((.result.stats.avg | floor | tostring) + "ms, loss " +
             ((.result.stats.loss // 0)|tostring) + "%")
         elif .result.status == "failed" then
            ("ICMP 无结果（" + (.result.failureSource // "探针或目标") + "）")
         else "无结果" end)'
}

_sni_choose_sources() {
    local rows=() choices=() choice idx selected=() source_locations='[]' fallback_locations='[]'
    local carrier city ip lon lat asn ping_state row selected_idx
    SNI_SOURCE_LOCATIONS=''
    SNI_SOURCE_COUNT=0
    SNI_SOURCE_SELECTED_COUNT=0
    SNI_SOURCE_LABEL=''
    SNI_SOURCE_FALLBACK_LOCATIONS=''
    SNI_SOURCE_CARRIER_COUNT=0

    while IFS= read -r row; do
        rows+=("$row")
    done < <(_sni_source_catalog)
    echo ""
    echo -e "${CYAN}国内出发点选择（最多 5 个）${NC}"
    echo "DNS IP 仅作线路参考和本机 ping 检查；实际 HTTPS 测试使用 Globalping 的中国运营商探针。"
    _warn "目录来自用户参考数据，IP 归属与坐标未逐一核实；目录 ASN 是运营商探针筛选条件，不是 IP 归属证明。"
    local n=1
    for row in "${rows[@]}"; do
        IFS='|' read -r carrier city ip lon lat asn <<< "$row"
        printf '  %2d) %-4s %-5s %-15s (%s,%s)\n' "$n" "$carrier" "$city" "$ip" "$lon" "$lat"
        n=$((n + 1))
    done
    echo ""
    read -r -p "输入编号（逗号分隔，最多 5 个；直接回车使用三网各 1 个参考点）: " choice || return 1
    if [ -z "$choice" ]; then
        choice="2,15,26"
    fi
    choice=${choice//,/ }
    read -r -a choices <<< "$choice"
    local requested_count=${#choices[@]}
    [ "$requested_count" -gt 5 ] && _warn "单次最多选择 5 个出发点，仅处理前 5 个有效编号。"

    for idx in "${choices[@]}"; do
        [[ "$idx" =~ ^[0-9]+$ ]] || continue
        [ "${#idx}" -le 3 ] || continue
        idx=$((10#$idx))
        [ "$idx" -ge 1 ] && [ "$idx" -le "${#rows[@]}" ] || continue
        local duplicate=false
        for selected_idx in "${selected[@]}"; do
            [ "$selected_idx" -eq "$idx" ] && duplicate=true
        done
        [ "$duplicate" = true ] && continue
        selected+=("$idx")
        [ "${#selected[@]}" -ge 5 ] && break
    done
    if [ "${#selected[@]}" -eq 0 ]; then
        _warn "没有有效的出发点编号，已取消远程测试。"
        SNI_SOURCE_LOCATIONS=''
        SNI_SOURCE_COUNT=0
        SNI_SOURCE_LABEL=''
        SNI_SOURCE_SELECTED_COUNT=0
        SNI_SOURCE_FALLBACK_LOCATIONS=''
        return 1
    fi

    local seen_asn="" labels=""
    for idx in "${selected[@]}"; do
        IFS='|' read -r carrier city ip lon lat asn <<< "${rows[$((idx - 1))]}"
        ping_state="未测试"
        if command -v ping >/dev/null 2>&1 && ping -c 1 -W 1 -w 2 "$ip" >/dev/null 2>&1; then
            ping_state="可达"
        elif command -v ping >/dev/null 2>&1; then
            ping_state="不可达/禁 ICMP"
        fi
        echo "  已选 #${idx}: ${carrier} ${city} ${ip} (${lon},${lat})，本机 ping: ${ping_state}"
        echo "       地图: https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=8/${lat}/${lon}"
        labels="${labels}${labels:+；}${carrier}/${city} ${ip} (${lon},${lat})"
        local globalping_city
        globalping_city=$(_sni_globalping_city "$city")
        if [ -n "$globalping_city" ]; then
            source_locations=$(echo "$source_locations" | jq -c --argjson asn "$asn" --arg city "$globalping_city" \
                '. + [{country:"CN",asn:$asn,city:$city,limit:1}]')
        else
            source_locations=$(echo "$source_locations" | jq -c --argjson asn "$asn" \
                '. + [{country:"CN",asn:$asn,limit:1}]')
        fi
        case " $seen_asn " in
            *" $asn "*) ;;
            *)
                fallback_locations=$(echo "$fallback_locations" | jq -c --argjson asn "$asn" \
                    '. + [{country:"CN",asn:$asn,limit:1}]')
                seen_asn="${seen_asn}${seen_asn:+ }${asn}"
                ;;
        esac
    done
    SNI_SOURCE_LOCATIONS="$source_locations"
    SNI_SOURCE_FALLBACK_LOCATIONS="$fallback_locations"
    SNI_SOURCE_COUNT=$(echo "$source_locations" | jq 'length')
    SNI_SOURCE_CARRIER_COUNT=$(echo "$fallback_locations" | jq 'length')
    SNI_SOURCE_SELECTED_COUNT="${#selected[@]}"
    SNI_SOURCE_LABEL="$labels"
}

# Do not degrade to unverified TLS/HTTP1 results on minimal curl builds.
_sni_curl_capable() {
    curl -V 2>/dev/null | grep -Eq '(^|[[:space:]])HTTP2([[:space:]]|$)' || return 1
    curl --help all 2>/dev/null | grep -q -- '--tlsv1.3' || return 1
    curl --help all 2>/dev/null | grep -q -- '--tls-max'
}

_sni_public_ipv4() {
    printf '%s\n' "$1" | awk -F. '
        NF != 4 {exit 1}
        {for(i=1;i<=4;i++) if($i !~ /^[0-9]+$/ || length($i)>3 || $i+0>255) exit 1}
        $1==0 || $1==10 || $1==127 || $1>=224 || ($1==169 && $2==254) ||
        ($1==172 && $2>=16 && $2<=31) || ($1==192 && $2==168) ||
        ($1==100 && $2>=64 && $2<=127) || ($1==198 && ($2==18 || $2==19)) ||
        ($1==192 && $2==0 && ($3==0 || $3==2)) ||
        ($1==198 && $2==51 && $3==100) || ($1==203 && $2==0 && $3==113) {exit 1}'
}

# Three HEAD requests avoid downloads, proxy environment variables and redirects.
# Pin rounds 2/3 to the first validated IPv4; do not persist this IP into production config.
# Output: avg_ms, jitter_ms, h2, rounds, IP (tab separated).
_sni_test_domain() {
    local domain="$1"
    local times="" ok=0 ip="" r out rc app connect hv code verify observed t_ms
    _validate_sni_domain "$domain" || return 1
    local resolve_args=()
    for r in 1 2 3; do
        local round_timeout=6
        if [ -n "${SNI_LOCAL_DEADLINE:-}" ]; then
            round_timeout=$((SNI_LOCAL_DEADLINE - SECONDS))
            [ "$round_timeout" -gt 0 ] || { _warn "${domain}: 本轮本地测试时间预算已耗尽。"; return 1; }
            [ "$round_timeout" -gt 6 ] && round_timeout=6
        fi
        out=$(curl -q --noproxy '*' -4 -I -o /dev/null -sS --tlsv1.3 --tls-max 1.3 --http2 \
            "${resolve_args[@]}" --connect-timeout 3 --max-time "$round_timeout" \
            -w '%{time_appconnect} %{time_connect} %{http_version} %{http_code} %{ssl_verify_result} %{remote_ip}' \
            "https://${domain}/" 2>/dev/null)
        rc=$?
        if [ "$rc" -ne 0 ]; then
            case "$rc" in
                4) _warn "${domain}: 当前 curl TLS 后端不支持请求的功能（exit 4）。" ;;
                6) _warn "${domain}: DNS 解析失败。" ;;
                28) _warn "${domain}: 连接/TLS/HTTP 超时。" ;;
                35) _warn "${domain}: TLS 握手失败（exit 35），可能为目标拒绝、协议不兼容或线路异常。" ;;
                60) _warn "${domain}: 证书验证失败。" ;;
                *) _warn "${domain}: curl 失败（exit ${rc}）。" ;;
            esac
            return 1
        fi
        read -r app connect hv code verify observed <<< "$out"
        [ "$verify" = 0 ] || { _warn "${domain}: 证书校验结果 ${verify:-未知}，跳过。"; return 1; }
        [ "$hv" = 2 ] || { _warn "${domain}: 实际 HTTP/${hv:-未知}，未协商 HTTP/2。"; return 1; }
        # Exclude redirects and WAF/error pages; HEAD-unsupported sites need manual validation.
        [[ "$code" =~ ^2[0-9][0-9]$ ]] || { _warn "${domain}: HEAD 返回 HTTP ${code:-未知}（跳转、WAF 或不支持 HEAD 等），按保守策略排除。"; return 1; }
        _sni_public_ipv4 "$observed" || return 1
        [ -z "$ip" ] && { ip="$observed"; resolve_args=(--resolve "${domain}:443:${ip}"); }
        [ "$observed" = "$ip" ] || return 1
        t_ms=$(printf '%s %s\n' "$app" "$connect" | awk '$1>0 && $1>=$2 {printf "%.0f", ($1-$2)*1000}')
        [[ "$t_ms" =~ ^[0-9]+$ ]] || return 1
        times="${times}${t_ms} "
        ok=$((ok+1))
    done
    [ "$ok" -eq 3 ] || return 1
    printf '%s\n' "$times" | awk -v ip="$ip" '{
        min=99999; max=0; sum=0; n=0
        for (i=1; i<=NF; i++) { sum+=$i; n++; if ($i<min) min=$i; if ($i>max) max=$i }
        if (n>0) printf "%.0f\t%.0f\t✓\t3\t%s\n", sum/n, max-min, ip
    }'
}

_sni_ip_metadata() {
    _sni_public_ipv4 "$1" || return 1
    curl -q --noproxy '*' -fsS --connect-timeout 2 --max-time 4 "https://ipwho.is/$1" 2>/dev/null |
        jq -ce --arg ip "$1" 'select(.success == true and .ip == $ip) |
            {country:.country_code,city:.city,asn:.connection.asn,org:.connection.org}'
}

# CDN detection is evidence, not proof of an origin server or its physical location.
_sni_cdn_hint() {
    case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
        *cloudflare*|*incapdns*|*incapsula*|*imperva*|*fastly*|*akamai*|*cloudfront*|*edgesuite*|*edgekey*|*azureedge*|*cdn*) printf 'detected' ;;
        *) printf 'unknown' ;;
    esac
}

# Accept domain names only, never URLs/CIDRs/shell fragments, at most 32 unique entries.
_sni_parse_candidates() {
    local input="${1//,/ }" domain result="" count=0
    input=${input//$'\r'/ }
    local domains=()
    read -r -a domains <<< "${input//$'\n'/ }"
    for domain in "${domains[@]}"; do
        domain=$(printf '%s' "$domain" | tr '[:upper:]' '[:lower:]')
        _validate_sni_domain "$domain" || { _warn "无效候选: ${domain}"; return 1; }
        case " $result " in *" $domain "*) continue ;; esac
        count=$((count+1))
        [ "$count" -le 32 ] || { _warn "最多 32 个候选域名。"; return 1; }
        result="${result}${result:+ }${domain}"
    done
    [ "$count" -gt 0 ] || return 1
    printf '%s\n' "$result"
}

# Province codes verified against https://www.zstaticcdn.com/api/v1/DescribeAllNodes.
# Keep the directory offline; resolve the selected domains on each run.
_province_catalog() {
    printf '%s\n' '河北|he' '山西|sx' '辽宁|ln' '吉林|jl' '黑龙江|hl' \
        '江苏|js' '浙江|zj' '安徽|ah' '福建|fj' '江西|jx' '山东|sd' \
        '河南|ha' '湖北|hb' '湖南|hn' '广东|gd' '海南|hi' '四川|sc' \
        '贵州|gz' '云南|yn' '陕西|sn' '甘肃|gs' '青海|qh' '内蒙古|nm' \
        '广西|gx' '西藏|xz' '宁夏|nx' '新疆|xj' '北京|bj' '天津|tj' \
        '上海|sh' '重庆|cq'
}

# One small HEAD per round, no redirects, no proxy environment, no body download.
# TCP success is independent of HTTP status and is not a throughput/loss estimate.
_province_test_endpoint() {
    local host="$1" out rc ip connect code r ms
    local tcp_ok=0 http_ok=0 sum=0 min=999999 max=0 ips='' rounds=''
    [[ "$host" =~ ^[a-z]{2}-(ct|cu|cm)-v4\.ip\.zstaticcdn\.com$ ]] || return 1
    for r in 1 2 3; do
        rc=0
        out=$(LC_ALL=C curl -q --noproxy '*' -4 -I -sS -o /dev/null \
            --connect-timeout 3 --max-time 5 \
            -w '%{remote_ip} %{time_connect} %{http_code}' "http://${host}:80/" 2>/dev/null) || rc=$?
        # Use a delimiter-preserving placeholder when curl reports no remote IP.
        read -r ip connect code <<< "${out/# /- }"
        if _sni_public_ipv4 "$ip" && [[ "$connect" =~ ^[0-9]+([.][0-9]+)?$ ]] && \
           awk -v t="$connect" 'BEGIN {exit !(t > 0 && t <= 5)}'; then
            ms=$(LC_ALL=C awk -v t="$connect" 'BEGIN {printf "%.0f", t*1000}')
            tcp_ok=$((tcp_ok + 1)); sum=$((sum + ms))
            [ "$ms" -lt "$min" ] && min=$ms
            [ "$ms" -gt "$max" ] && max=$ms
            case " $ips " in *" $ip "*) ;; *) ips="${ips}${ips:+ }${ip}" ;; esac
        fi
        if [ "$rc" -eq 0 ] && [[ "$code" =~ ^[1-5][0-9][0-9]$ ]] && _sni_public_ipv4 "$ip"; then
            http_ok=$((http_ok + 1))
        fi
        rounds="${rounds}${rounds:+$'\n'}第${r}轮 HTTP=${code:-000}/curl=${rc}"
    done
    if [ "$tcp_ok" -gt 0 ]; then
        printf 'TCP 成功 %s/3，建连均值 %sms，范围 %s–%sms\nHTTP 响应 %s/3\n实际 IPv4: %s\n%s\n' \
            "$tcp_ok" "$((sum / tcp_ok))" "$min" "$max" "$http_ok" "$ips" "$rounds"
    else
        printf 'TCP 成功 0/3，建连耗时不可用\nHTTP 响应 %s/3\n实际 IPv4: 未建立公网 IPv4 连接\n%s\n' "$http_ok" "$rounds"
    fi
}

_province_print_report() {
    [ -n "$SNI_PROVINCE_REPORT" ] || return 0
    printf '\n════ VPS → %s 三网 IPv4 参考结果 ════\n%s\n' "$SNI_PROVINCE_NAME" "$SNI_PROVINCE_REPORT"
    echo 'TCP 建连耗时包含往返路径；这里不测国内主动访问 VPS，也不验证 SNI、代理吞吐或丢包率。'
    echo 'HTTP 3xx/4xx/5xx 表示收到响应；curl 6=解析失败，7=连接失败，28=超时。省份/运营商为目录标签。'
}

_province_test_menu() {
    SNI_PROVINCE_REPORT='' SNI_PROVINCE_NAME=''
    command -v curl >/dev/null 2>&1 || { _error '缺少 curl，无法测试。'; return 1; }
    local rows=() row name code choice idx=1 selected='' carrier host result
    echo '选择一个省级地区，自动测试电信、联通、移动 IPv4（固定 3 个目标，每个 3 轮，总等待约不超过 45 秒）。'
    echo '来源: https://www.zstaticcdn.com/；方向: 当前 VPS → 省级三网 HTTP :80 参考节点。'
    while IFS= read -r row; do
        rows+=("$row")
        IFS='|' read -r name code <<< "$row"
        printf '  %2d) %s (%s)\n' "$idx" "$name" "$code"
        idx=$((idx + 1))
    done < <(_province_catalog)
    read -r -p '输入省份编号/名称/代码（如 河北 或 he；0/回车取消）: ' choice || return 1
    case "$choice" in ''|0) return 1 ;; esac
    if [[ "$choice" =~ ^[0-9]{1,2}$ ]]; then
        idx=$((10#$choice))
        [ "$idx" -ge 1 ] && [ "$idx" -le "${#rows[@]}" ] && selected="${rows[$((idx - 1))]}"
    else
        for row in "${rows[@]}"; do
            IFS='|' read -r name code <<< "$row"
            if [ "$choice" = "$name" ] || [ "$choice" = "$code" ]; then selected="$row"; break; fi
        done
    fi
    [ -n "$selected" ] || { _warn '省份无效，本轮取消；一次只选一个省。'; return 1; }
    IFS='|' read -r name code <<< "$selected"
    SNI_PROVINCE_NAME="$name"
    idx=1
    for carrier in ct cu cm; do
        case "$carrier" in ct) name=电信 ;; cu) name=联通 ;; cm) name=移动 ;; esac
        host="${code}-${carrier}-v4.ip.zstaticcdn.com"
        printf '  测试 %s %s:80（最多 15 秒）...\n' "$name" "$host"
        result=$(_province_test_endpoint "$host") || result='未取得测试结果'
        # Keep progress short; render one numbered list after all three tests.
        SNI_PROVINCE_REPORT="${SNI_PROVINCE_REPORT}${SNI_PROVINCE_REPORT:+$'\n\n'}${idx}. ${name}"$'\n'"   ${host}:80"$'\n'"$(printf '%s\n' "$result" | sed 's/^/   /')"
        idx=$((idx + 1))
    done
    _province_print_report
}

_sni_optimizer_menu() {
    local SNI_PROVINCE_REPORT='' SNI_PROVINCE_NAME=''
    if ! command -v curl >/dev/null 2>&1; then
        _error "缺少 curl 依赖，无法测试。"
        return
    fi
    command -v jq >/dev/null 2>&1 || { _error "缺少 jq 依赖。"; return 1; }

    # Legacy seed domains are unverified discovery inputs, not preapproved Reality targets.
    local pool_us="www.amd.com www.cisco.com aws.amazon.com www.dell.com addons.mozilla.org academy.nvidia.com swdist.apple.com updates.cdn-apple.com"
    local pool_jp="www.lovelive-anime.jp www.nintendo.co.jp www.sony.jp www.canon.jp www.toyota.jp www.jal.co.jp www.sega.jp www.square-enix.co.jp"
    local pool_sg="www.ntu.edu.sg www.sutd.edu.sg www.a-star.edu.sg www.np.edu.sg www.nea.gov.sg www.nus.edu.sg www.smu.edu.sg www.singaporeair.com www.dbs.com.sg www.sgx.com www.singtel.com www.starhub.com www.uob.com.sg www.capitaland.com www.grab.com"
    local pool_hk="www.cathaypacific.com www.hkex.com.hk www.hangseng.com www.pccw.com www.towngas.com www.mtr.com.hk"
    local pool_kr="www.hyundai.com www.kia.com www.lge.co.kr www.coupang.com www.krx.co.kr"
    local pool_tw="www.asus.com www.gigabyte.com www.msi.com www.acer.com www.tsmc.com"
    local pool_de="www.sap.com www.siemens.com www.bosch.com www.zalando.de www.mediamarkt.de"
    local pool_gb="www.arm.com www.dyson.co.uk www.tesco.com www.bt.com www.burberry.com"
    # Unverified global seeds may resolve to CDN edges; apply the same checks.
    local pool_global="swdist.apple.com updates.cdn-apple.com gateway.icloud.com itunes.apple.com aws.amazon.com www.amd.com www.cisco.com addons.mozilla.org"

    clear
    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║      SNI 优选（脚本 v${SCRIPT_VERSION}）          ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo -e "${NC}"
    echo "  本地筛选：证书验证 + TLS 1.3 + HTTP/2 + 非跳转 2xx，IPv4 同 IP 三轮测试。"
    echo "  远程筛选：中国运营商探针发起 HTTP/2 + HEAD；TLS 1.3、证书及 HTTP 状态分别校验。"
    echo "  注意：远程结果不等于真实客户端到 VPS 的代理吞吐或断流测试。"
    echo "  TLS 耗时不含 DNS/TCP 建连；排名仅比较本轮候选，不代表全网最优。"
    _warn "中国远程模式使用公开探针，结果用于线路筛选；正式使用前仍建议从实际客户端复测。"
    _warn "适用于 VLESS-Reality/Any-Reality。普通 AnyTLS 请使用证书覆盖的自有域名；第三方 SNI 不等于可信伪装。"
    echo ""
    echo -e "    ${GREEN}[4]${NC} 自动检测当前服务器所在地区（默认，直接回车）"
    echo -e "    ${GREEN}[1]${NC} 美国 (US)"
    echo -e "    ${GREEN}[2]${NC} 日本 (JP)"
    echo -e "    ${GREEN}[3]${NC} 新加坡 (SG)"
    echo -e "    ${GREEN}[5]${NC} 自定义候选域名（最多 32 个）"
    echo ""
    echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
    echo ""
    local region_choice
    read -r -p "  请选择候选来源 [0-5，默认 4]: " region_choice || return
    region_choice=${region_choice:-4}

    local pool=""
    local region_name=""
    local test_mode=""
    local source_locations=""
    local source_count=0
    local source_fallback_locations=""
    local source_selected_count=0
    local source_carrier_count=0
    local source_label=""
    local candidate_input
    case "$region_choice" in
        1) pool="$pool_us"; region_name="美国" ;;
        2) pool="$pool_jp"; region_name="日本" ;;
        3) pool="$pool_sg"; region_name="新加坡" ;;
        4)
            _info "正在检测服务器所在地区..."
            local country=$(curl -q --noproxy '*' -4 -fsS --connect-timeout 3 --max-time 5 https://ipinfo.io/country 2>/dev/null | tr -d ' \n\r')
            case "$country" in
                US) pool="$pool_us"; region_name="美国 (US)" ;;
                JP) pool="$pool_jp"; region_name="日本 (JP)" ;;
                SG) pool="$pool_sg"; region_name="新加坡 (SG)" ;;
                HK) pool="$pool_hk"; region_name="香港 (HK)" ;;
                KR) pool="$pool_kr"; region_name="韩国 (KR)" ;;
                TW) pool="$pool_tw"; region_name="台湾 (TW)" ;;
                DE) pool="$pool_de"; region_name="德国 (DE)" ;;
                GB) pool="$pool_gb"; region_name="英国 (GB)" ;;
                "") pool="$pool_global"; region_name="未知地区（使用全球 CDN 池）" ;;
                *)  pool="$pool_global"; region_name="${country}（未收录，使用全球 CDN 池）" ;;
            esac
            _info "检测结果: ${region_name}"
            ;;
        5)
            read -r -p "候选域名（空格/逗号分隔；空输入取消）: " candidate_input || return
            pool=$(_sni_parse_candidates "$candidate_input") || return 1
            region_name="自定义候选"
            ;;
        *) return ;;
    esac

    local exclude_cdn=Y
    echo ""
    echo -e "    ${GREEN}[4]${NC} VPS 本地 SNI + 一个省三网 IPv4 参考（默认，直接回车）"
    echo -e "    ${GREEN}[1]${NC} 仅测试当前 VPS"
    echo -e "    ${GREEN}[3]${NC} VPS + 中国远程出发点（进阶，依赖探针覆盖）"
    echo -e "    ${GREEN}[2]${NC} 仅测试中国远程出发点（诊断，不作本地推荐）"
    read -r -p "  请选择测试方式 [1-4，默认 4]: " test_mode || return
    test_mode=${test_mode:-4}
    case "$test_mode" in
        1|3)
            read -r -p "排除检测到的 CDN/WAF 候选？[Y/n，默认 Y]: " exclude_cdn || return
            exclude_cdn=${exclude_cdn:-Y}
            ;;
        2) ;;
        4) _info '常用模式：默认排除检测到的 CDN/WAF 候选。' ;;
        *) _warn "测试方式无效，已取消。"; return 1 ;;
    esac
    _info "未检测出 CDN 不代表一定是源站；同地域/同 ASN 是参考，不保证隐蔽或不会被封。"
    [ -z "$server_ip" ] && _init_server_ip >/dev/null 2>&1
    local vps_meta=""
    if _sni_public_ipv4 "$server_ip"; then vps_meta=$(_sni_ip_metadata "$server_ip"); fi
    [ -n "$vps_meta" ] && _info "VPS IP 数据库信息（可能不准）: ${vps_meta}"

    if [ "$test_mode" = 4 ]; then
        _province_test_menu || return 1
        test_mode=1
        _info '省级三网结果仅作线路参考；接下来独立验证 VPS 本地 SNI，不计入 SNI 排名。'
    fi
    local requested_test_mode="$test_mode"
    if [ "$test_mode" = 2 ]; then
        _warn "仅远程模式不执行本地证书/H2/CDN 校验；CDN 排除策略未验证，只展示线路诊断结果。"
    fi
    if [ "$test_mode" = "2" ] || [ "$test_mode" = "3" ]; then
        _sni_choose_sources || return 1
        source_locations="$SNI_SOURCE_LOCATIONS"
        source_fallback_locations="$SNI_SOURCE_FALLBACK_LOCATIONS"
        source_count="$SNI_SOURCE_COUNT"
        source_selected_count="$SNI_SOURCE_SELECTED_COUNT"
        source_carrier_count="$SNI_SOURCE_CARRIER_COUNT"
        source_label="$SNI_SOURCE_LABEL"
        _info "已选 ${source_selected_count} 个城市参考点，覆盖 ${source_carrier_count} 家运营商；先精确请求 ${source_count} 个城市探针，缺失时按运营商回退。"
    fi
    if [ "$test_mode" != "1" ]; then
        [ -z "$server_ip" ] && _init_server_ip >/dev/null 2>&1
        if _sni_public_ipv4 "$server_ip"; then
            _info "正在验证中国出发点到当前 VPS（${server_ip}）的 ICMP 延迟..."
            local vps_ping_data
            vps_ping_data=$(_sni_globalping_measure ping "$server_ip" "$source_locations" "$source_fallback_locations")
            if [ -n "$vps_ping_data" ]; then
                echo "  中国出发点 -> VPS ${server_ip}："
                _sni_globalping_ping_vps "$vps_ping_data" | sed 's/^/    /'
            else
                _warn "远程 VPS ping 测试未返回结果，继续进行 SNI HTTPS 测试。"
            fi
        else
            _warn "未能识别当前 VPS 公网 IPv4，跳过远程 VPS ping（不向探针提交本机/私网地址）。"
        fi
    fi

    echo ""
    [ "$test_mode" = "1" ] && _info "开始测试 ${region_name} 候选域名（当前 VPS，每个 3 轮）..."
    [ "$test_mode" = "2" ] && _info "开始测试 ${region_name} 候选域名（仅中国远程探针）..."
    [ "$test_mode" = "3" ] && _info "开始测试 ${region_name} 候选域名（VPS 本地 + 中国远程探针）..."

    if [ "$test_mode" != "2" ]; then
        _sni_curl_capable || { _error "当前 curl 缺少 HTTP/2 或 TLS1.3 参数支持，不能可靠验证 Reality；请升级 curl 或选择仅远程测试。"; return 1; }
    fi
    echo ""

    local results=""
    local candidate_count=0 local_pass_count=0 local_excluded_count=0
    local local_failed_count=0 local_failures="" local_exclusions="" local_skipped_count=0
    local SNI_LOCAL_DEADLINE=$((SECONDS + 120))
    local domain result avg jitter h2 ok score target_ip cname target_meta cdn_status
    candidate_count=$(printf '%s\n' $pool | awk 'NF {count++} END {print count+0}')
    echo "  本轮 ${candidate_count} 个候选；本地测试预算约 120 秒，失败即跳过，不自动扩展或循环重试。"
    if [ "$test_mode" != "2" ]; then
        for domain in $pool; do
            if [ "$SECONDS" -ge "$SNI_LOCAL_DEADLINE" ]; then
                local_skipped_count=$((local_skipped_count + 1))
                local_failures="${local_failures}${domain}\t未测试：本轮时间预算耗尽（不代表域名失败）\n"
                continue
            fi
            printf '  测试 %-28s ... ' "$domain"
            result=$(_sni_test_domain "$domain")
            if [ -z "$result" ]; then
                if [ "$SECONDS" -ge "$SNI_LOCAL_DEADLINE" ]; then
                    local_skipped_count=$((local_skipped_count + 1))
                    local_failures="${local_failures}${domain}\t未完成：本轮时间预算耗尽，不能判定失败\n"
                    echo '时间预算耗尽，未完成校验'
                    continue
                fi
                local_failed_count=$((local_failed_count + 1))
                local_failures="${local_failures}${domain}\t未通过严格校验（具体原因见上方 [注意]）\n"
                echo -e "${RED}未通过证书/TLS1.3/H2/HTTP/稳定性校验${NC}"
                continue
            fi
            IFS=$'\t' read -r avg jitter h2 ok target_ip <<< "$result"
            echo -e "TLS 平均 ${GREEN}${avg}ms${NC} 波动 ${YELLOW}${jitter}ms${NC} HTTP/2: ${h2} (${ok}/3)"
            cname=""
            if command -v dig >/dev/null 2>&1; then
                cname=$(dig +time=2 +tries=1 +short CNAME "$domain" 2>/dev/null | head -1)
            fi
            target_meta=$(_sni_ip_metadata "$target_ip")
            cdn_status=$(_sni_cdn_hint "$cname $target_meta")
            printf '    IP: %s  CNAME: %s  CDN/WAF: %s\n' "$target_ip" "${cname:-未知/无}" "$cdn_status"
            printf '    IP 数据库信息（不是实测位置）: %s\n' "${target_meta:-不可用}"
            if [ -n "$vps_meta" ] && [ -n "$target_meta" ]; then
                printf '    与 VPS 对比: %s\n' "$(jq -nr --argjson v "$vps_meta" --argjson t "$target_meta" '
                    "同国家=" + (($v.country == $t.country)|tostring) +
                    " 同ASN=" + (($v.asn != null and $v.asn == $t.asn)|tostring)')"
            fi
            if [ "$cdn_status" = detected ] && [[ "$exclude_cdn" != n && "$exclude_cdn" != N ]]; then
                local_excluded_count=$((local_excluded_count + 1))
                local_exclusions="${local_exclusions}${domain}\t检测到 CDN/WAF，按本次策略排除\n"
                _warn "${domain} 检测到 CDN/WAF，按本次策略排除。"; continue
            fi
            # Locality is displayed as evidence, not guessed from a domain TLD.
            local_pass_count=$((local_pass_count + 1))
            score=$((avg + jitter))
            results="${results}${score}\t${domain}\t${avg}\t${jitter}\t${h2}\n"
        done
    fi

    # 远程请求每个域名最多使用用户选择的五个地点，候选最多五个。
    local remote_domains=() remote_scores=()
    local remote_diagnostic_count=0
    local remote_diagnostics=""
    local remote_attempted_count=0 remote_complete_count=0 remote_failed_count=0
    local remote_failures=""
    local remote_skipped_count=0 remote_skipped=""
    local remote_candidates="" remote_result remote_avg remote_good remote_details remote_protocols remote_requested remote_http_good remote_coverage remote_expected coverage_unit
    if [ "$test_mode" = "2" ] || [ "$test_mode" = "3" ]; then
        if [ -z "$source_locations" ] || [ "$source_count" -eq 0 ]; then
            _warn "没有可用的远程出发点，跳过 Globalping 测试。"
        else
            if [ -n "$results" ]; then
                remote_candidates=$(echo -e "$results" | grep -v '^$' | sort -n | head -5 | cut -f2)
            elif [ "$test_mode" = 2 ]; then
                # 远程模式也只取前 5 个候选，避免一次菜单操作产生过多外部请求。
                remote_candidates=$(printf '%s\n' $pool | head -5)
            else
                echo '  联合模式：本地无通过项，跳过候选远程请求；需要单独诊断请选仅远程模式。'
            fi
            local pool_domain remote_domain selected_for_remote
            for pool_domain in $pool; do
                selected_for_remote=false
                for remote_domain in $remote_candidates; do
                    [ "$pool_domain" = "$remote_domain" ] && { selected_for_remote=true; break; }
                done
                if [ "$selected_for_remote" = false ]; then
                    remote_skipped_count=$((remote_skipped_count + 1))
                    remote_skipped="${remote_skipped}${pool_domain}\n"
                fi
            done
            echo ""
            [ -n "$remote_candidates" ] && _info "开始中国远程探测（最多 5 个候选；精确城市 ${source_count} 个，运营商回退 ${source_carrier_count} 个）..."
            local remote_results=""
            for domain in $remote_candidates; do
                remote_attempted_count=$((remote_attempted_count + 1))
                printf '  远程测试 %-25s ... ' "$domain"
                remote_result=$(_sni_globalping_http "$domain" "$source_locations" "$source_fallback_locations")
                if [ -z "$remote_result" ]; then
                    remote_failed_count=$((remote_failed_count + 1))
                    remote_failures="${remote_failures}${domain}\t未取得有效结果（API/超时/证书/TLS1.3）\n"
                    echo -e "${RED}远程探针失败/超时${NC}"
                    continue
                fi
                IFS=$'\t' read -r remote_avg remote_good remote_details remote_protocols remote_requested remote_http_good remote_coverage remote_expected <<< "$remote_result"
                remote_expected=${remote_expected:-$source_count}
                echo -e "TLS 平均 ${GREEN}${remote_avg}ms${NC}，TLS 成功 ${remote_good}/${remote_expected}，HTTP 2xx ${remote_http_good}/${remote_expected}，实际返回 ${remote_requested} 个探针，协议 ${remote_protocols}"
                echo "    出发点: ${remote_details}"
                [ "$remote_coverage" = complete-fallback ] && _warn "${domain} 使用同运营商回退探针；并非原选城市，实际地点见出发点明细。"
                case "$remote_coverage" in *-fallback) coverage_unit="运营商" ;; *) coverage_unit="城市" ;; esac
                if { [ "$remote_coverage" != complete ] && [ "$remote_coverage" != complete-fallback ]; } || [ "$remote_good" -lt "$remote_expected" ] || [ "$remote_http_good" -lt "$remote_expected" ]; then
                    remote_diagnostic_count=$((remote_diagnostic_count + 1))
                    remote_diagnostics="${remote_diagnostics}${remote_http_good}\t${remote_good}\t${remote_avg}\t${domain}\t${remote_expected}\t${remote_requested}\t${remote_coverage}\n"
                    _warn "${domain} 期望覆盖 ${remote_expected} 个${coverage_unit}出发点，实际返回 ${remote_requested} 个探针、HTTP 成功 ${remote_http_good}；覆盖不足，仅作诊断，不进入正式排名。"
                    continue
                fi
                remote_complete_count=$((remote_complete_count + 1))
                remote_domains+=("$domain")
                remote_scores+=("$((remote_avg + (remote_expected - remote_http_good) * 500))")
                remote_results="${remote_results}${remote_scores[${#remote_scores[@]}-1]}\t${domain}\t${remote_avg}\t0\t-\t${remote_avg}\n"
            done

            if [ "$test_mode" = "2" ]; then
                results="$remote_results"
            elif [ -z "$results" ] && [ -n "$remote_results" ]; then
                _warn "VPS 本地所有候选均失败；仅展示中国探针结果，不作为 Reality SNI 推荐。"
                results="$remote_results"
                test_mode="2"
            elif [ -z "$remote_results" ]; then
                if [ -n "$results" ]; then
                    _warn "中国远程探针无完整覆盖结果，仅展示 VPS 本地结果，不代表联合测试通过。"
                    test_mode="1"
                else
                    _warn "中国远程探针无完整覆盖结果；将在结尾保留部分覆盖和失败明细。"
                fi
            fi

            # 远程模式下，将远程 TLS 延迟和丢失探针惩罚加到本地评分。
            if [ "$test_mode" = "3" ] && [ -n "$results" ]; then
                local merged_results=""
                local matched_score j
                while IFS=$'\t' read -r score domain avg jitter h2 ok; do
                    [ -z "$domain" ] && continue
                    matched_score=""
                    for ((j=0; j<${#remote_domains[@]}; j++)); do
                        if [ "${remote_domains[$j]}" = "$domain" ]; then
                            matched_score="${remote_scores[$j]}"
                            break
                        fi
                    done
                    [ -n "$matched_score" ] || continue
                    score=$((score + matched_score))
                    merged_results="${merged_results}${score}\t${domain}\t${avg}\t${jitter}\t${h2}\t${matched_score}\n"
                done <<< "$(echo -e "$results")"
                results="$merged_results"
            fi
        fi
    fi

    if [ -z "$results" ]; then
        _province_print_report
        echo ""
        echo -e "${YELLOW}════════════ 本轮 SNI 筛选结论 ════════════${NC}"
        echo -e "  ${RED}结论：本轮没有可直接应用的 SNI 候选。${NC}"
        if [ "$requested_test_mode" != "2" ]; then
            printf '  VPS 本地严格校验: %s/%s 通过，%s 个未通过' "$local_pass_count" "$candidate_count" "$local_failed_count"
            [ "$local_excluded_count" -gt 0 ] && printf '，%s 个因 CDN/WAF 策略排除' "$local_excluded_count"
            echo ""
        fi
        if [ "$requested_test_mode" != 1 ]; then
            printf '  中国远程探测: %s/%s 个候选已尝试，%s 个完整覆盖，%s 个部分覆盖，%s 个无有效结果\n' \
                "$remote_attempted_count" "$candidate_count" "$remote_complete_count" "$remote_diagnostic_count" "$remote_failed_count"
            if [ "$remote_skipped_count" -gt 0 ]; then
                printf '  未进入远程阶段: %s 个（联合模式仅验证本地通过项；每轮最多 5 个）\n' \
                    "$remote_skipped_count"
                printf '    %s\n' "$(printf '%b' "$remote_skipped" | paste -sd ' ' -)"
            fi
        fi
        if [ "$remote_diagnostic_count" -gt 0 ]; then
            _warn "部分候选已完成远程诊断，但未满足完整出发点/HTTP 覆盖或 VPS 本地校验，因此不生成联合排名。"
            if [ -n "$remote_diagnostics" ]; then
                echo ""
                echo -e "${YELLOW}════ 远程诊断候选（仅供复测，不是正式推荐）════${NC}"
                local diagnostic_http diagnostic_tls diagnostic_avg diagnostic_domain diagnostic_expected diagnostic_returned diagnostic_coverage
                while IFS=$'\t' read -r diagnostic_http diagnostic_tls diagnostic_avg diagnostic_domain diagnostic_expected diagnostic_returned diagnostic_coverage; do
                    [ -n "$diagnostic_domain" ] || continue
                    printf '  %-28s HTTP 2xx %s/%s，TLS1.3 %s/%s，平均 %sms，返回 %s 个探针，覆盖=%s\n' \
                        "$diagnostic_domain" "$diagnostic_http" "$diagnostic_expected" "$diagnostic_tls" "$diagnostic_expected" \
                        "$diagnostic_avg" "$diagnostic_returned" "$diagnostic_coverage"
                done <<< "$(echo -e "$remote_diagnostics" | grep -v '^$' | sort -t $'\t' -k1,1nr -k2,2nr -k3,3n)"
            fi
            _warn "请优先复测 HTTP 2xx/TLS 成功数最多的候选；若 VPS 本地仍超时，不要直接应用。"
        fi
        if [ -n "$remote_failures" ]; then
            echo ""
            echo -e "${YELLOW}════ 远程未完成候选 ════${NC}"
            while IFS=$'\t' read -r domain result; do
                [ -n "$domain" ] || continue
                printf '  %-28s %s\n' "$domain" "$result"
            done <<< "$(echo -e "$remote_failures")"
        fi
        if [ -n "$local_failures" ]; then
            echo ""
            echo -e "${YELLOW}════ VPS 本地未通过／未完成候选 ════${NC}"
            while IFS=$'\t' read -r domain result; do
                [ -n "$domain" ] || continue
                printf '  %-28s %s\n' "$domain" "$result"
            done <<< "$(echo -e "$local_failures")"
        fi
        if [ -n "$local_exclusions" ]; then
            echo ""
            echo -e "${YELLOW}════ VPS 本地 CDN/WAF 排除候选 ════${NC}"
            while IFS=$'\t' read -r domain result; do
                [ -n "$domain" ] || continue
                printf '  %-28s %s\n' "$domain" "$result"
            done <<< "$(echo -e "$local_exclusions")"
        fi
        printf '  因本地时间预算未测试或未完成: %s 个。\n' "$local_skipped_count"
        if [ "$requested_test_mode" = 3 ] && [ "$local_pass_count" -eq 0 ]; then
            echo '  请补充候选后重测；本地淘汰项未重复发起远程请求。'
        elif [ "$requested_test_mode" != "1" ] && [ "$remote_diagnostic_count" -eq 0 ] && \
           [ "$remote_complete_count" -eq 0 ] && [ "$remote_failed_count" -eq 0 ]; then
            _warn "没有取得可评分的远程结果；请检查出发点、Globalping 状态或稍后重试。"
        elif [ "$requested_test_mode" = "1" ]; then
            _warn "本轮仅执行 VPS 本地测试；请更换候选域名后重试。"
        fi
        echo -e "${YELLOW}═══════════════════════════════════════════${NC}"
        return
    fi

    _province_print_report
    echo ""
    [ "$test_mode" = "1" ] && echo -e "${YELLOW}═════════════ VPS 侧候选结果 TOP 5（本轮评分较低者在最后）═════════════${NC}"
    [ "$test_mode" = "2" ] && echo -e "${YELLOW}════ 中国远程复测候选 TOP 5（不代表 VPS 本地通过）════${NC}"
    [ "$test_mode" = "3" ] && echo -e "${YELLOW}══════ VPS + 中国远程探针综合结果 TOP 5（本轮评分较低者在最后）══════${NC}"
    # 取综合评分前 5，倒序展示。
    local top5=$(echo -e "$results" | grep -v '^$' | sort -n | head -5 | sort -rn)
    local rank=$(echo "$top5" | grep -c .)
    if [ "$rank" -eq 1 ]; then
        echo '  仅 1 个候选进入本轮排名，缺少可比样本，不能认定为最优；建议补充候选。'
    fi
    while IFS=$'\t' read -r score domain avg jitter h2 remote_score_value; do
        [ -z "$domain" ] && continue
        if [ "$test_mode" = "2" ]; then
            echo -e "  第 ${rank} 名  ${CYAN}${domain}${NC}  中国探针 TLS1.3: ${avg}ms"
        elif [ "$avg" -ge 300 ]; then
            echo "  第 ${rank} 名  ${domain}  VPS TLS ${avg}ms 波动 ${jitter}ms HTTP/2:${h2}  高延迟，暂不建议优先使用"
        elif [ "$rank" -eq 1 ]; then
            echo -e "  ${GREEN}第 1 名  ${domain}${NC}  VPS TLS ${avg}ms 波动 ${jitter}ms HTTP/2:${h2}  本轮复测候选"
        else
            echo -e "  第 ${rank} 名  ${CYAN}${domain}${NC}  VPS 平均 ${avg}ms 波动 ${jitter}ms HTTP/2:${h2}"
        fi
        rank=$((rank - 1))
    done <<< "$top5"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo '  本地 TLS ≥300ms 标注为高延迟（经验提示，非协议硬性标准）；波动为三轮最大值减最小值。'
    printf '  因本地时间预算未测试或未完成: %s 个。\n' "$local_skipped_count"
    if [ -n "$remote_diagnostics" ]; then
        echo ""
        echo -e "${YELLOW}════ 其余远程诊断候选（仅供复测）════${NC}"
        local diagnostic_http diagnostic_tls diagnostic_avg diagnostic_domain diagnostic_expected diagnostic_returned diagnostic_coverage
        while IFS=$'\t' read -r diagnostic_http diagnostic_tls diagnostic_avg diagnostic_domain diagnostic_expected diagnostic_returned diagnostic_coverage; do
            [ -n "$diagnostic_domain" ] || continue
            printf '  %-28s HTTP 2xx %s/%s，TLS1.3 %s/%s，平均 %sms，返回 %s 个探针，覆盖=%s\n' \
                "$diagnostic_domain" "$diagnostic_http" "$diagnostic_expected" "$diagnostic_tls" "$diagnostic_expected" \
                "$diagnostic_avg" "$diagnostic_returned" "$diagnostic_coverage"
        done <<< "$(echo -e "$remote_diagnostics" | grep -v '^$' | sort -t $'\t' -k1,1nr -k2,2nr -k3,3n)"
    fi
    if [ -n "$remote_failures" ]; then
        echo ""
        echo -e "${YELLOW}════ 远程未完成候选 ════${NC}"
        while IFS=$'\t' read -r domain result; do
            [ -n "$domain" ] || continue
            printf '  %-28s %s\n' "$domain" "$result"
        done <<< "$(echo -e "$remote_failures")"
    fi
    if [ "$remote_skipped_count" -gt 0 ]; then
        echo ""
        printf '[信息] 未进入远程阶段（联合模式仅验证本地通过项；每轮最多 5 个）: %s\n' \
            "$(printf '%b' "$remote_skipped" | paste -sd ' ' -)"
    fi
    echo ""
    if [ "$requested_test_mode" = "2" ]; then
        printf '[信息] 本轮汇总：远程完整覆盖候选 %s 个，部分覆盖诊断 %s 个，无有效结果 %s 个；VPS 本地未参与测试。\n' \
            "$remote_complete_count" "$remote_diagnostic_count" "$remote_failed_count"
    elif [ "$requested_test_mode" = "3" ]; then
        printf '[信息] 本轮汇总：VPS 本地通过 %s/%s（未通过 %s，CDN/WAF 排除 %s）；远程尝试 %s 个（完整覆盖 %s，部分覆盖 %s，无有效结果 %s）。\n' \
            "$local_pass_count" "$candidate_count" "$local_failed_count" "$local_excluded_count" \
            "$remote_attempted_count" "$remote_complete_count" "$remote_diagnostic_count" "$remote_failed_count"
    else
        printf '[信息] 本轮汇总：VPS 本地严格校验通过 %s/%s，未通过 %s，CDN/WAF 策略排除 %s。\n' \
            "$local_pass_count" "$candidate_count" "$local_failed_count" "$local_excluded_count"
    fi
    if [ -n "$local_failures" ]; then
        echo -e "${YELLOW}════ VPS 本地未通过／未完成候选 ════${NC}"
        while IFS=$'\t' read -r domain result; do
            [ -n "$domain" ] || continue
            printf '  %-28s %s\n' "$domain" "$result"
        done <<< "$(echo -e "$local_failures")"
    fi
    if [ -n "$local_exclusions" ]; then
        echo -e "${YELLOW}════ VPS 本地 CDN/WAF 排除候选 ════${NC}"
        while IFS=$'\t' read -r domain result; do
            [ -n "$domain" ] || continue
            printf '  %-28s %s\n' "$domain" "$result"
        done <<< "$(echo -e "$local_exclusions")"
    fi
    echo ""
    [ "$test_mode" = "1" ] && _info "本次结果仅代表 VPS 侧测试；用于节点前，请从中国客户端实际复测。"
    [ "$test_mode" != "1" ] && _info "远程结果来自 Globalping 中国运营商探针；探针城市、网络和经纬度已在测试时显示。"
    [ "$test_mode" != "1" ] && _info "已选出发点：${source_label}"
    _warn "这不是端到端代理吞吐/断流测试，也不是不会被封或不会被回落滥用的保证。"
    _info "从实际客户端复测通过后，再到主菜单 [5] 修改节点 SNI，或 [18] 中转菜单 [7] 修改中转入口 SNI。"
}

_download_update_file() {
    local url="$1" destination="$2"
    # Alpine 的 BusyBox wget 在部分镜像上会静默吞掉 TLS/HTTP 错误；优先使用
    # curl 的 fail-fast 模式，wget 仅作为没有 curl 的回退。
    if command -v curl >/dev/null 2>&1 && curl -fsSL --retry 2 --connect-timeout 8 --max-time 60 "$url" -o "$destination"; then
        return 0
    fi
    command -v wget >/dev/null 2>&1 && wget -qO "$destination" "$url"
}

_update_script() {
    _info "--- 更新脚本 ---"
    
    if [ "$SCRIPT_UPDATE_URL" == "YOUR_GITHUB_RAW_URL_HERE/singbox.sh" ]; then
        _error "错误：您尚未在脚本中配置 SCRIPT_UPDATE_URL 变量。"
        _warning "请编辑此脚本，找到 SCRIPT_UPDATE_URL 并填入您正确的 GitHub raw 链接。"
        return 1
    fi

    # 更新主脚本。时间戳查询参数用于绕过代理/CDN 的旧文件缓存。
    _info "正在从 GitHub 下载最新版本..."
    local temp_script_path
    temp_script_path=$(mktemp "${SELF_SCRIPT_PATH}.tmp.XXXXXX") || {
        _error "无法创建更新临时文件，请检查脚本目录权限。"
        return 1
    }
    local cache_bust
    local main_script_url
    local downloaded_version
    local main_updated=false
    cache_bust=$(date +%s)
    main_script_url="${SCRIPT_UPDATE_URL}?v=${cache_bust}"
    
    if _download_update_file "$main_script_url" "$temp_script_path"; then
        if [ ! -s "$temp_script_path" ]; then
            _error "主脚本下载失败或文件为空！"
            rm -f "$temp_script_path"
            return 1
        fi

        downloaded_version=$(sed -n 's/^export SCRIPT_VERSION="\([^"]*\)".*/\1/p' "$temp_script_path" | head -n 1)
        if [ -z "$downloaded_version" ] || ! head -n 1 "$temp_script_path" | grep -q '^#!/bin/bash'; then
            _error "下载内容不是有效的 singbox.sh，已拒绝覆盖本地脚本。"
            rm -f "$temp_script_path"
            return 1
        fi
        if ! bash -n "$temp_script_path" 2>/dev/null; then
            _error "下载的新脚本未通过 Bash 语法检查，已拒绝覆盖本地脚本。"
            rm -f "$temp_script_path"
            return 1
        fi

        if [[ "$downloaded_version" =~ ^[0-9]+$ && "$SCRIPT_VERSION" =~ ^[0-9]+$ ]] \
            && [ "$downloaded_version" -lt "$SCRIPT_VERSION" ]; then
            _warning "远端脚本版本 v${downloaded_version} 低于当前 v${SCRIPT_VERSION}，已拒绝降级覆盖。"
            rm -f "$temp_script_path"
            return 1
        fi
        
        if cmp -s "$temp_script_path" "$SELF_SCRIPT_PATH"; then
            rm -f "$temp_script_path"
            _info "主脚本已是最新版 (v${SCRIPT_VERSION})，内容没有变化。"
        else
            chmod +x "$temp_script_path"
            mv "$temp_script_path" "$SELF_SCRIPT_PATH"
            main_updated=true
            if [ "$downloaded_version" = "$SCRIPT_VERSION" ]; then
                _success "主脚本内容已更新（版本号保持 v${downloaded_version}）。"
            else
                _success "主脚本更新成功：v${SCRIPT_VERSION} -> v${downloaded_version}"
            fi
        fi
    else
        _error "主脚本下载失败！请检查网络或 GitHub 链接。"
        rm -f "$temp_script_path"
        return 1
    fi
    
    # 需要更新的子脚本列表
    local sub_scripts=("advanced_relay.sh" "parser.sh" "xray_manager.sh")
    
    for script_name in "${sub_scripts[@]}"; do
        local script_url="${GITHUB_RAW_BASE}/${script_name}?v=${cache_bust}"
        local temp_sub_path="${SINGBOX_DIR}/.${script_name}.tmp.$$"
        local updated=false
        local download_ok=false
        local target_path
        local target_paths=("${SINGBOX_DIR}/${script_name}")

        # 子脚本不依赖“当前是否已存在”：首次更新也必须下载到规范目录。
        # 如果当前入口目录还有旧副本，则一并覆盖，避免运行时优先命中旧文件。
        if [ "${SCRIPT_DIR}/${script_name}" != "${SINGBOX_DIR}/${script_name}" ] \
            && [ -f "${SCRIPT_DIR}/${script_name}" ]; then
            target_paths+=("${SCRIPT_DIR}/${script_name}")
        fi

        _info "正在下载子脚本: ${script_name}..."
        if _download_update_file "$script_url" "$temp_sub_path" \
            && [ -s "$temp_sub_path" ] \
            && head -n 1 "$temp_sub_path" | grep -q '^#!/bin/bash' \
            && bash -n "$temp_sub_path" 2>/dev/null; then
            download_ok=true
            chmod +x "$temp_sub_path"
            for target_path in "${target_paths[@]}"; do
                mkdir -p "$(dirname "$target_path")" 2>/dev/null || continue
                if [ -f "$target_path" ] && cmp -s "$temp_sub_path" "$target_path"; then
                    continue
                fi
                if cp "$temp_sub_path" "${target_path}.tmp.$$" \
                    && chmod +x "${target_path}.tmp.$$" \
                    && mv "${target_path}.tmp.$$" "$target_path"; then
                    updated=true
                else
                    rm -f "${target_path}.tmp.$$"
                fi
            done
        fi
        rm -f "$temp_sub_path"

        if [ "$updated" = true ]; then
            _success "子脚本 (${script_name}) 更新成功。"
        elif [ "$download_ok" = true ]; then
            _info "子脚本 (${script_name}) 已是最新，内容没有变化。"
        else
            _warning "子脚本 ${script_name} 下载失败或校验失败，保留现有文件。"
        fi
    done
    
    # 更新 yq 工具（如果缺失或版本过旧）
    _install_yq
    
    if [ "$main_updated" = true ]; then
        _success "脚本更新检查完成，主脚本内容已刷新至 v${downloaded_version}。"
    else
        _info "脚本更新检查完成，主脚本当前已是 v${downloaded_version}。"
    fi
    _info "请重新运行脚本以应用所有变更："
    echo -e "${YELLOW}bash ${SELF_SCRIPT_PATH}${NC}"
    exit 0
}

# 守卫函数：检查 sing-box 核心是否已安装
_require_singbox() {
    if [ ! -f "${SINGBOX_BIN}" ]; then
        _error "此功能需要先安装 Sing-box 核心。请前往主菜单【核心管理】-> [15] 进行安装。"
        return 1
    fi
    return 0
}

# [安装/更新 Sing-box 核心] — 双模态：未装就装、已装就更新
_install_or_update_singbox() {
    if [ -f "${SINGBOX_BIN}" ]; then
        local current_ver=$(${SINGBOX_BIN} version 2>/dev/null | head -n1 | awk '{print $3}')
        _info "当前 Sing-box 版本: v${current_ver}，正在检查更新..."
    else
        _info "Sing-box 核心未安装，正在执行首次安装..."
    fi
    _do_update_singbox
}

# 执行 sing-box 核心的安装/更新
_do_update_singbox() {
    _info "--- 安装/更新 Sing-box 核心 ---"
    _install_dependencies true
    _install_sing_box
    
    if [ $? -eq 0 ]; then
        _success "sing-box 安装/更新成功！"
        # 确保配置文件存在
        if [ ! -f "${CONFIG_FILE}" ] || [ ! -f "${CLASH_YAML_FILE}" ]; then
            _info "检测到主配置文件缺失，正在初始化..."
            _initialize_config_files
        fi
        _init_relay_config
        if [ ! -s "${SINGBOX_DIR}/relay.json" ]; then
            echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "${SINGBOX_DIR}/relay.json"
        fi
        _create_service_files
        _setup_log_cleanup
        _info "正在启动/重启 [主] 服务 (sing-box)..."
        _manage_service "restart"
        _success "[主] 服务已就绪。"
    else
        _error "Sing-box 核心安装/更新失败。"
    fi
}

# [安装/更新 Xray 核心] — 双模态：未装就装、已装就更新
_install_or_update_xray() {
    local xray_bin="/usr/local/bin/xray"
    if [ -f "$xray_bin" ]; then
        local current_ver=$($xray_bin version 2>/dev/null | head -1 | awk '{print $2}')
        _info "当前 Xray 版本: v${current_ver}，正在检查更新..."
    else
        _info "Xray 核心未安装，正在执行首次安装..."
    fi
    _do_update_xray
}

# 执行 Xray 核心的安装/更新 (内联实现，避免依赖 xray_manager.sh 的 source)
_do_update_xray() {
    _info "--- 安装/更新 Xray 核心 ---"
    
    local xray_bin="/usr/local/bin/xray"
    local xray_dir="/usr/local/etc/xray"
    local is_first_install=false
    [ ! -f "$xray_bin" ] && is_first_install=true
    
    # 确保 unzip 可用
    command -v unzip &>/dev/null || _pkg_install unzip
    
    local arch=$(uname -m)
    local xray_arch=""
    case "$arch" in
        x86_64|amd64)  xray_arch="64" ;;
        aarch64|arm64) xray_arch="arm64-v8a" ;;
        armv7l)        xray_arch="arm32-v7a" ;;
        *)             xray_arch="64" ;;
    esac
    
    local download_url="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${xray_arch}.zip"
    local tmp_dir=$(mktemp -d)
    local tmp_zip="${tmp_dir}/xray.zip"
    
    _info "下载地址: ${download_url}"
    if ! wget -qO "$tmp_zip" "$download_url"; then
        _error "Xray 下载失败！"
        rm -rf "$tmp_dir"
        return 1
    fi
    
    if ! unzip -qo "$tmp_zip" -d "$tmp_dir"; then
        _error "Xray 解压失败！"
        rm -rf "$tmp_dir"
        return 1
    fi
    
    mv "${tmp_dir}/xray" "$xray_bin"
    chmod +x "$xray_bin"
    
    mkdir -p "$xray_dir"
    [ -f "${tmp_dir}/geoip.dat" ] && mv "${tmp_dir}/geoip.dat" "$xray_dir/"
    [ -f "${tmp_dir}/geosite.dat" ] && mv "${tmp_dir}/geosite.dat" "$xray_dir/"

    rm -rf "$tmp_dir"
    _release_install_cache
    
    local version=$($xray_bin version 2>/dev/null | head -1 | awk '{print $2}')
    _success "Xray-core v${version} 安装/更新成功！"
    
    # 首次安装时：初始化配置与服务
    if [ "$is_first_install" = true ]; then
        _info "首次安装 Xray，正在初始化配置与服务..."
        # 初始化配置文件
        if [ ! -s "${xray_dir}/config.json" ]; then
            echo '{"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[]}}' > "${xray_dir}/config.json"
        fi
        [ -s "${xray_dir}/metadata.json" ] || echo '{}' > "${xray_dir}/metadata.json"
        # 创建 Xray 系统服务文件
        _create_xray_service_from_main
        _info "正在启动 Xray 服务..."
        if [ "$INIT_SYSTEM" == "systemd" ]; then
            systemctl start xray
        elif [ "$INIT_SYSTEM" == "openrc" ]; then
            rc-service xray start
        elif [ "$INIT_SYSTEM" == "direct" ]; then
            nohup "$xray_bin" run -c "${xray_dir}/config.json" >> /var/log/xray.log 2>&1 &
            echo $! > /tmp/xray.pid
        fi
        _success "Xray 首次安装完成并已启动！"
    else
        # 已安装：重启服务
        if command -v systemctl &>/dev/null && systemctl is-active xray &>/dev/null; then
            _info "正在重启 Xray 服务..."
            systemctl restart xray
            _success "Xray 服务已重启。"
        elif command -v rc-service &>/dev/null && rc-service xray status &>/dev/null 2>&1; then
            _info "正在重启 Xray 服务..."
            rc-service xray restart
            _success "Xray 服务已重启。"
        elif [ "$INIT_SYSTEM" == "direct" ]; then
            if [ -s /tmp/xray.pid ]; then
                local xray_pid
                xray_pid=$(cat /tmp/xray.pid 2>/dev/null)
                if _is_pid_running_cmd "$xray_pid" "$xray_bin"; then
                    kill "$xray_pid" 2>/dev/null
                fi
            fi
            nohup "$xray_bin" run -c "${xray_dir}/config.json" >> /var/log/xray.log 2>&1 &
            echo $! > /tmp/xray.pid
            _success "Xray direct 后台模式已重启。"
        fi
    fi
}

# 从主脚本创建 Xray 服务文件 (内联实现)
_create_xray_service_from_main() {
    local xray_bin="/usr/local/bin/xray"
    local xray_dir="/usr/local/etc/xray"
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        if [ ! -f "/etc/systemd/system/xray.service" ]; then
            cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
ExecStart=${xray_bin} run -c ${xray_dir}/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable xray
        fi
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        if [ ! -f "/etc/init.d/xray" ]; then
            cat > /etc/init.d/xray << 'EOF'
#!/sbin/openrc-run
name="xray"
description="Xray Service"
command="/usr/local/bin/xray"
command_args="run -c /usr/local/etc/xray/config.json"
command_background=true
pidfile="/run/xray.pid"
EOF
            chmod +x /etc/init.d/xray
            rc-update add xray default 2>/dev/null
        fi
    fi
}

# --- 进阶功能 (子脚本) ---
_advanced_features() {
    local script_name="advanced_relay.sh"
    local script_path="${SINGBOX_DIR}/${script_name}"
    
    # 优先检测当前目录 (开发者/测试点优先)
    if [ -f "$SCRIPT_DIR/$script_name" ]; then
        script_path="$SCRIPT_DIR/$script_name"
    fi

    # 如果都不存在，则下载
    if [ ! -f "$script_path" ]; then
        _info "本地未检测到进阶脚本，正在尝试下载..."
        local download_url="${GITHUB_RAW_BASE}/${script_name}"
        
        if wget -qO "$script_path" "$download_url"; then
            chmod +x "$script_path"
            _success "下载成功！"
        else
            _error "下载失败！请检查网络或确认 GitHub 仓库地址。"
            # 清理可能的空文件
            rm -f "$script_path"
            return 1
        fi
    fi

    # 执行脚本
    if [ -f "$script_path" ]; then
        # 赋予权限并执行
        chmod +x "$script_path"
        bash "$script_path"
    else
        _error "找不到进阶脚本文件: ${script_path}"
    fi
}

# --- Xray 节点管理 (子脚本) ---
_xray_features() {
    # 前置检查：Xray 核心必须已安装
    if [ ! -f "/usr/local/bin/xray" ]; then
        _error "Xray 核心未安装！请先通过主菜单【核心管理】-> [16] 进行安装。"
        return 1
    fi

    local script_name="xray_manager.sh"
    local script_path="${SINGBOX_DIR}/${script_name}"
    
    if [ -f "$SCRIPT_DIR/$script_name" ]; then
        script_path="$SCRIPT_DIR/$script_name"
    fi
    
    if [ ! -f "$script_path" ]; then
        _info "本地未检测到 Xray 管理脚本，正在尝试下载..."
        local download_url="${GITHUB_RAW_BASE}/${script_name}"
        if wget -qO "$script_path" "$download_url"; then
            chmod +x "$script_path"
            _success "下载成功！"
        else
            _error "下载失败！请检查网络或确认 GitHub 仓库地址。"
            rm -f "$script_path"
            return 1
        fi
    fi
    
    if [ -f "$script_path" ]; then
        chmod +x "$script_path"
        bash "$script_path"
    else
        _error "找不到 Xray 管理脚本: ${script_path}"
    fi
}

_main_menu() {
    while true; do
        clear
        # ASCII Logo
        echo -e "${CYAN}"
        echo '  ____  _             ____            '
        echo ' / ___|(_)_ __   __ _| __ )  _____  __'
        echo ' \___ \| | '\''_ \ / _` |  _ \ / _ \ \/ /'
        echo '  ___) | | | | | (_| | |_) | (_) >  < '
        echo ' |____/|_|_| |_|\__, |____/ \___/_/\_\'
        echo '                |___/    Lite Manager '
        echo -e "${NC}"
        
        # 版本标题
        echo -e "${CYAN}"
        echo "  ╔═══════════════════════════════════════╗"
        echo "  ║         sing-box 管理脚本 v${SCRIPT_VERSION}         ║"
        echo "  ╚═══════════════════════════════════════╝"
        echo -e "${NC}"
        echo ""
        
        # 获取系统信息
        local os_info="未知"
        if [ -f /etc/os-release ]; then
            os_info=$(grep -E "^PRETTY_NAME=" /etc/os-release 2>/dev/null | cut -d'"' -f2 | head -1)
            [ -z "$os_info" ] && os_info=$(grep -E "^NAME=" /etc/os-release 2>/dev/null | cut -d'"' -f2 | head -1)
        fi
        [ -z "$os_info" ] && os_info=$(uname -s)
        
        # 获取 Sing-box 版本和状态
        local sb_version=""
        local service_status="○ 未知"
        if [ -f "$SINGBOX_BIN" ]; then
            sb_version=" v$($SINGBOX_BIN version 2>/dev/null | head -n1 | awk '{print $3}')"
            if [ "$INIT_SYSTEM" == "systemd" ]; then
                if systemctl is-active --quiet sing-box 2>/dev/null; then
                    service_status="${GREEN}● 运行中${NC}"
                else
                    service_status="${RED}○ 已停止${NC}"
                fi
            elif [ "$INIT_SYSTEM" == "openrc" ]; then
                if rc-service sing-box status 2>/dev/null | grep -q "started"; then
                    service_status="${GREEN}● 运行中${NC}"
                else
                    service_status="${RED}○ 已停止${NC}"
                fi
            elif [ "$INIT_SYSTEM" == "direct" ]; then
                if _is_pid_file_running_cmd "$PID_FILE" "$SINGBOX_BIN"; then
                    service_status="${GREEN}● 运行中${NC}"
                else
                    service_status="${RED}○ 已停止${NC}"
                fi
            fi
        else
            service_status="${RED}○ 未安装${NC}"
        fi
        
        # 获取 Argo 状态 (修复 Alpine/BusyBox 的 ps 截断问题：优先使用 PID 文件检测)
        local argo_status="${RED}○ 未安装${NC}"
        if [ -f "$CLOUDFLARED_BIN" ]; then
            local argo_running=false
            # 方式1 (精准): 遍历 PID 文件，与守护进程 _argo_keepalive 使用相同的检测方式
            for pid_file in /tmp/singbox_argo_*.pid; do
                [ -f "$pid_file" ] || continue
                local pid=$(cat "$pid_file" 2>/dev/null)
                if _is_pid_running_cmd "$pid" "$CLOUDFLARED_BIN"; then
                    argo_running=true
                    break
                fi
            done
            # 方式2 (兜底): PID 文件不存在时，尝试 pgrep 或 ps 匹配进程名
            if [ "$argo_running" = false ]; then
                if command -v pgrep &>/dev/null; then
                    pgrep -x cloudflared &>/dev/null && argo_running=true
                elif ps w 2>/dev/null | grep -v "grep" | grep -q "cloudflared"; then
                    argo_running=true
                fi
            fi
            if [ "$argo_running" = true ]; then
                argo_status="${GREEN}● 运行中${NC}"
            else
                argo_status="${YELLOW}○ 已安装 (未运行)${NC}"
            fi
        fi
        
        # 获取 Xray 版本和状态
        local xray_version=""
        local xray_status="${RED}○ 未安装${NC}"
        if [ -f "/usr/local/bin/xray" ]; then
            xray_version=" v$(/usr/local/bin/xray version 2>/dev/null | head -1 | awk '{print $2}')"
            if [ "$INIT_SYSTEM" == "systemd" ]; then
                if systemctl is-active --quiet xray 2>/dev/null; then
                    xray_status="${GREEN}● 运行中${NC}"
                else
                    xray_status="${YELLOW}○ 已停止${NC}"
                fi
            elif [ "$INIT_SYSTEM" == "openrc" ]; then
                if rc-service xray status 2>/dev/null | grep -q "started"; then
                    xray_status="${GREEN}● 运行中${NC}"
                else
                    xray_status="${YELLOW}○ 已停止${NC}"
                fi
            elif [ "$INIT_SYSTEM" == "direct" ]; then
                if _is_pid_file_running_cmd /tmp/xray.pid /usr/local/bin/xray; then
                    xray_status="${GREEN}● 运行中${NC}"
                else
                    xray_status="${YELLOW}○ 已停止${NC}"
                fi
            fi
            local xray_nodes=$(jq '.inbounds | length' /usr/local/etc/xray/config.json 2>/dev/null || echo "0")
            xray_status="${xray_status} (${xray_nodes}节点)"
        fi
        
        echo -e "  系统: ${CYAN}${os_info}${NC}  |  模式: ${CYAN}${INIT_SYSTEM}${NC}"
        echo -e "  Sing-box${CYAN}${sb_version}${NC}: ${service_status}  |  Argo: ${argo_status}"
        echo -e "  Xray${CYAN}${xray_version}${NC}: ${xray_status}"
        echo ""
        
        # 节点管理
        echo -e "  ${CYAN}【节点管理】${NC}"
        echo -e "    ${GREEN}[1]${NC} 添加节点          ${GREEN}[2]${NC} Argo 隧道节点"
        echo -e "    ${GREEN}[3]${NC} 查看节点链接      ${GREEN}[4]${NC} 删除节点"
        echo -e "    ${GREEN}[5]${NC} 修改节点端口/SNI"
        echo ""
        
        # 服务控制
        echo -e "  ${CYAN}【服务控制】${NC}"
        echo -e "    ${GREEN}[6]${NC} 重启服务          ${GREEN}[7]${NC} 停止服务"
        echo -e "    ${GREEN}[8]${NC} 查看运行状态      ${GREEN}[9]${NC} 查看实时日志"
        echo -e "    ${GREEN}[10]${NC} 定时重启设置"
        echo -e "    ${GREEN}[11]${NC} 同步系统时间"
        echo ""
        
        # 配置与更新
        echo -e "  ${CYAN}【配置与更新】${NC}"
        echo -e "    ${GREEN}[12]${NC} 检查配置文件    ${GREEN}[13]${NC} 更新脚本"
        echo -e "    ${GREEN}[14]${NC} DNS 设置"
        echo ""
        
        # 核心管理
        echo -e "  ${CYAN}【核心管理】${NC}"
        echo -e "    ${GREEN}[15]${NC} 安装/更新 Sing-box 核心"
        echo -e "    ${GREEN}[16]${NC} 安装/更新 Xray 核心"
        echo -e "    ${RED}[17]${NC} 卸载脚本"
        echo ""
        
        # 进阶功能
        echo -e "  ${CYAN}【进阶功能】${NC}"
        echo -e "    ${GREEN}[18]${NC} 落地/中转/第三方节点导入"
        echo -e "    ${GREEN}[19]${NC} Xray 节点管理"
        echo -e "    ${GREEN}[20]${NC} SNI 优选（伪装域名测速）"
        echo -e "    ${GREEN}[21]${NC} 省级三网 IPv4 线路参考"
        echo ""

        echo -e "  ─────────────────────────────────────────────────"
        echo -e "    ${YELLOW}[0]${NC} 退出脚本"
        echo ""

        read -p "  请输入选项 [0-21]: " choice

        case $choice in
            1) _require_singbox && _show_add_node_menu ;;
            2) _require_singbox && _argo_menu ;;
            3) _require_singbox && _view_nodes ;;
            4) _require_singbox && _delete_node ;;
            5) _require_singbox && _modify_node_menu ;;
            6) _require_singbox && _manage_service "restart" ;;
            7) _require_singbox && _manage_service "stop" ;;
            8) _require_singbox && _manage_service "status" ;;
            9) _require_singbox && _view_log ;;
            10) _require_singbox && _scheduled_restart_menu ;;
            11) _sync_system_time ;;
            12) _require_singbox && _check_config ;;
            13) _update_script ;;
            14) _require_singbox && _dns_config_menu ;;
            15) _install_or_update_singbox ;;
            16) _install_or_update_xray ;;
            17) _uninstall ;; 
            18) _require_singbox && _advanced_features ;;
            19) _xray_features ;;
            20) _sni_optimizer_menu ;;
            21) _province_test_menu ;;
            0) exit 0 ;;
            *) _error "无效输入，请重试。" ;;
        esac
        echo
        read -n 1 -s -r -p "按任意键返回主菜单..."
    done
}

    # 定时重启功能 - 零依赖版本 (Systemd Timer & OpenRC Logic)
    _scheduled_restart_menu() {
        clear
        echo -e "${CYAN}"
        echo '  ╔═══════════════════════════════════════╗'
        echo '  ║         定时重启 sing-box             ║'
        echo '  ╚═══════════════════════════════════════╝'
        echo -e "${NC}"
        echo ""
        
        # [!] 零依赖策略：不再安装 cron
        # 仅简单的环境预判
        if [ "$INIT_SYSTEM" == "direct" ]; then
            _error "未能识别系统初始化环境 (systemd/openrc)，定时重启功能暂不可用。"
            read -n 1 -s -r -p "按任意键返回..."
            return
        fi

    
    # 获取服务器时间信息
    local server_time=$(date '+%Y-%m-%d %H:%M:%S')
    local server_tz_offset=$(date +%z)  # 如: +0800, +0000, -0500
    local server_tz_name=$(date +%Z 2>/dev/null || echo "Unknown")  # 如: CST, UTC
    
    # 解析时区偏移 (格式: +0800 或 -0500)
    local offset_sign="${server_tz_offset:0:1}"
    local offset_hours="${server_tz_offset:1:2}"
    local offset_mins="${server_tz_offset:3:2}"
    
    # 去除前导零
    offset_hours=$((10#$offset_hours))
    offset_mins=$((10#$offset_mins))
    
    # 计算总偏移分钟数
    local server_offset_mins=$((offset_hours * 60 + offset_mins))
    if [ "$offset_sign" == "-" ]; then
        server_offset_mins=$((-server_offset_mins))
    fi
    
    # 北京时间 = UTC+8 = +480 分钟
    local beijing_offset_mins=480
    local diff_mins=$((beijing_offset_mins - server_offset_mins))
    local diff_hours=$((diff_mins / 60))
    local diff_remaining_mins=$((diff_mins % 60))
    
    # 格式化显示
    local diff_display=""
    if [ $diff_mins -gt 0 ]; then
        diff_display="北京时间比服务器快 ${diff_hours} 小时"
        if [ $diff_remaining_mins -ne 0 ]; then
            diff_display="${diff_display} ${diff_remaining_mins} 分钟"
        fi
    elif [ $diff_mins -lt 0 ]; then
        diff_display="北京时间比服务器慢 $((-diff_hours)) 小时"
        if [ $diff_remaining_mins -ne 0 ]; then
            diff_display="${diff_display} $((-diff_remaining_mins)) 分钟"
        fi
    else
        diff_display="服务器与北京时间同步"
    fi
    
    # 检查当前定时任务状态
    local cron_status="未设置"
    local cron_time=""
    
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        if [ -f "/etc/systemd/system/sing-box-restart.timer" ]; then
            cron_time=$(grep "OnCalendar" /etc/systemd/system/sing-box-restart.timer | cut -d' ' -f2 | cut -d: -f1,2)
            cron_status="已启用 (每天 ${cron_time} 重启 - Systemd)"
        fi
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        if [ -f "/etc/init.d/sing-box-timer" ] && rc-service sing-box-timer status &>/dev/null; then
            cron_time=$(grep "RESTART_TIME=" /etc/init.d/sing-box-timer | cut -d'"' -f2)
            cron_status="已启用 (每天 ${cron_time} 重启 - OpenRC)"
        fi
    fi
    
    echo -e "  ${CYAN}【服务器时间信息】${NC}"
    echo -e "    当前时间: ${GREEN}${server_time}${NC}"
    echo -e "    时区: ${GREEN}${server_tz_name} (UTC${server_tz_offset})${NC}"
    echo -e "    与北京时间: ${YELLOW}${diff_display}${NC}"
    echo ""
    echo -e "  ${CYAN}【定时重启状态】${NC}"
    if [ "$cron_status" != "未设置" ]; then
        echo -e "    状态: ${GREEN}${cron_status}${NC}"
    else
        echo -e "    状态: ${YELLOW}${cron_status}${NC}"
    fi
    echo ""
    echo -e "  ─────────────────────────────────────────"
    echo -e "    ${GREEN}[1]${NC} 设置定时重启"
    echo -e "    ${GREEN}[2]${NC} 查看当前设置"
    echo -e "    ${RED}[3]${NC} 取消定时重启"
    echo ""
    echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
    echo ""
    
    read -p "  请输入选项 [0-3]: " choice
    
    case $choice in
        1)
            echo ""
            echo -e "  ${CYAN}设置定时重启时间${NC}"
            echo -e "  提示: 输入服务器时区的时间 (24小时制)"
            echo ""
            read -p "  请输入重启时间 (格式 HH:MM, 如 04:30): " restart_time
            
            # 验证时间格式
            if [[ ! "$restart_time" =~ ^([0-1]?[0-9]|2[0-3]):([0-5][0-9])$ ]]; then
                _error "时间格式错误！请使用 HH:MM 格式 (如 04:30)"
                return
            fi
            
            local hour=$(echo "$restart_time" | cut -d: -f1)
            local min=$(echo "$restart_time" | cut -d: -f2)
            local time_str=$(printf "%02d:%02d" "$((10#$hour))" "$((10#$min))")

            if [ "$INIT_SYSTEM" == "systemd" ]; then
                # Systemd Timer 方案
                cat > /etc/systemd/system/sing-box-restart.service <<EOF
[Unit]
Description=Sing-box Scheduled Restart
[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl restart sing-box
EOF
                cat > /etc/systemd/system/sing-box-restart.timer <<EOF
[Unit]
Description=Sing-box Scheduled Restart Timer
[Timer]
OnCalendar=*-*-* ${time_str}:00
Persistent=true
[Install]
WantedBy=timers.target
EOF
                systemctl daemon-reload
                systemctl enable --now sing-box-restart.timer
            elif [ "$INIT_SYSTEM" == "openrc" ]; then
                # OpenRC 调度服务方案
                cat > /usr/local/bin/sb-timer.sh <<EOF
#!/bin/bash
TARGET_TIME="\$1"
while true; do
    [ "\$(date +%H:%M)" == "\$TARGET_TIME" ] && rc-service sing-box restart && sleep 61
    sleep 30
done
EOF
                chmod +x /usr/local/bin/sb-timer.sh
                cat > /etc/init.d/sing-box-timer <<EOF
#!/sbin/openrc-run
description="Sing-box Scheduled Restart Timer"
command="/usr/local/bin/sb-timer.sh"
command_args="${time_str}"
pidfile="/run/sing-box-timer.pid"
command_background=true
RESTART_TIME="${time_str}"
EOF
                chmod +x /etc/init.d/sing-box-timer
                rc-service sing-box-timer restart 2>/dev/null
                rc-update add sing-box-timer default 2>/dev/null
            fi
            
            _success "定时重启已通过 ${INIT_SYSTEM} 原生组件设置完成！"
            echo ""
            echo -e "  重启时间: ${GREEN}每天 ${time_str}${NC} (服务器时区)"
                
                # 计算对应的北京时间
                local beijing_hour=$((hour + diff_hours))
                local beijing_min=$((min + diff_remaining_mins))
                
                # 处理分钟溢出
                if [ $beijing_min -ge 60 ]; then
                    beijing_min=$((beijing_min - 60))
                    beijing_hour=$((beijing_hour + 1))
                elif [ $beijing_min -lt 0 ]; then
                    beijing_min=$((beijing_min + 60))
                    beijing_hour=$((beijing_hour - 1))
                fi
                
                # 处理小时溢出
                if [ $beijing_hour -ge 24 ]; then
                    beijing_hour=$((beijing_hour - 24))
                elif [ $beijing_hour -lt 0 ]; then
                    beijing_hour=$((beijing_hour + 24))
                fi
                
                echo -e "  对应北京时间: ${YELLOW}$(printf "%02d:%02d" "$beijing_hour" "$beijing_min")${NC}"
            ;;
        2)
            echo ""
            echo -e "  ${CYAN}当前定时任务详情:${NC}"
            if [ "$INIT_SYSTEM" == "systemd" ]; then
                systemctl list-timers sing-box-restart.timer --no-pager
            elif [ "$INIT_SYSTEM" == "openrc" ]; then
                rc-service sing-box-timer status
            fi
            ;;
        3)
            echo ""
            if [ "$cron_status" == "未设置" ]; then
                _warning "当前没有设置定时重启"
            else
                read -p "$(echo -e ${YELLOW}"  确定取消定时重启? (y/N): "${NC})" confirm
                if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                    if [ "$INIT_SYSTEM" == "systemd" ]; then
                        systemctl disable --now sing-box-restart.timer 2>/dev/null
                        rm -f /etc/systemd/system/sing-box-restart.timer /etc/systemd/system/sing-box-restart.service
                        systemctl daemon-reload
                    elif [ "$INIT_SYSTEM" == "openrc" ]; then
                        rc-service sing-box-timer stop 2>/dev/null
                        rc-update del sing-box-timer default 2>/dev/null
                        rm -f /etc/init.d/sing-box-timer /usr/local/bin/sb-timer.sh
                    fi
                    _success "定时重启已取消，相关系统组件已清理。"
                else
                    _info "已取消操作"
                fi
            fi
            ;;
        0)
            return
            ;;
        *)
            _error "无效输入"
            ;;
    esac
    
    echo ""
    read -n 1 -s -r -p "按任意键继续..."
}

# 批量创建节点 (v11.3 深度向导版)
_batch_create_nodes() {
    local input_str="$1"
    if [ -z "$input_str" ]; then
        _info "请输入协议编号 (空格或逗号分隔，如: 1,6,9)"
        _warn "注：批量部署不支持含有 CDN 的协议 (2, 3, 4)"
        read -p "协议列表: " input_str
    fi
    [ -z "$input_str" ] && return 1

    # 1. 解析协议列表
    local proto_ids=$(echo "$input_str" | tr ',' ' ' | xargs)
    local proto_count=0
    local has_complex=false 
    local has_sni_req=false 
    local has_hy2=false     
    local has_ss=false      
    local ss_occurences=0

    for pid in $proto_ids; do
        if [[ ! "$pid" =~ ^(1|2|3|4|5|6|7|8|9|10)$ ]]; then
            _error "协议 ID $pid 无效，请输入 1-10 范围内的协议编号。"
            return 1
        fi
        if [[ "$pid" =~ ^(2|3|4)$ ]]; then
            _error "协议 ID $pid (WebSocket/gRPC+TLS) 不支持批量创建，请使用单节点模式单独创建以开启高级 CDN 优化。"
            return 1
        fi
        ((proto_count++))
        if [[ "$pid" == "8" ]]; then
            has_ss=true
            ((ss_occurences++))
        fi
        [[ "$pid" =~ ^(6|8)$ ]] && has_complex=true
        [[ "$pid" =~ ^(1|4|5|6|7)$ ]] && has_sni_req=true
        [[ "$pid" == "6" ]] && has_hy2=true
    done

    [ $proto_count -eq 0 ] && { _error "未选择任何协议"; return 1; }

    # 2. 引导向导
    _info "--- 批量部署引导向导 ---"
    
    # [修复] 强制初始化服务器 IP，防止各协议函数因变量未定义生成空配置
    [ -z "$server_ip" ] && server_ip=$(_get_ip)
    local batch_ip="${server_ip}"
    read -p "请输入批量节点绑定的IP地址 (回车默认: ${server_ip}): " custom_batch_ip
    batch_ip=${custom_batch_ip:-$server_ip}
    export BATCH_IP="$batch_ip"
    
    # 2.1 SNI 收集 (强制净化处理)
    export BATCH_SNI="$DEFAULT_SNI"
    if [ "$has_sni_req" = true ]; then
        read -p "请输入统一伪装域名 (SNI) [默认: $BATCH_SNI]: " input_sni
        input_sni=$(echo "$input_sni" | xargs)
        [ -n "$input_sni" ] && BATCH_SNI="$input_sni"
    fi

    # 2.2 Hy2 专项
    local hy2_obfs="none"
    local hy2_hop="false"
    local hy2_hop_range=""
    if [ "$has_hy2" = true ]; then
        read -p "是否开启 Hysteria2 QUIC 混淆? (y/N): " hy2_q_choice
        [[ "$hy2_q_choice" == "y" ]] && hy2_obfs="salamander"
        read -p "是否开启 Hysteria2 端口跳跃? (y/N): " hy2_h_choice
        if [[ "$hy2_h_choice" == "y" ]]; then
            hy2_hop="true"
            read -p "请输入端口跳跃范围 (如 20000-30000): " hy2_hop_range
        fi
    fi

    # 2.4 SS 专项 (支持多选)
    local ss_variant="1"
    if [ "$has_ss" = true ]; then
        echo "选择 Shadowsocks 批量加密方式 (支持多选，如 1,2,3,4):"
        echo " 1) aes-256-gcm"
        echo " 2) chacha20-ietf-poly1305"
        echo " 3) 2022-blake3-aes-256-gcm"
        echo " 4) 2022-blake3-aes-256-gcm (带 Padding)"
        read -p "选择 [1-4] (默认1): " ss_choice
        ss_variant=${ss_choice:-1}
        # 计算 SS 实际需要的端口数
        local ss_needed=$(echo "$ss_variant" | tr ',' ' ' | wc -w)
        # 每个 Shadowsocks ID (7) 额外需要 (ss_needed - 1) 个端口
        proto_count=$((proto_count + (ss_needed - 1) * ss_occurences))
    fi

    # 3. 端口规划
    local ports_list=()
    _info "共需规划 $proto_count 个批量监听端口。"
    while true; do
        read -p "请输入端口号 (范围如 10001-10010 或空格分隔): " p_input
        local current_p_list=()
        local invalid_port=false
        local duplicate_port=false
        local occupied_port=false
        local seen_ports=" "
        p_input=$(echo "$p_input" | tr ',' ' ' | xargs)
        [ -z "$p_input" ] && { _error "端口不能为空，请重新输入。"; continue; }
        if [[ "$p_input" == *"-"* ]]; then
            local start_p=$(echo $p_input | cut -d'-' -f1)
            local end_p=$(echo $p_input | cut -d'-' -f2)
            if [[ ! "$start_p" =~ ^[0-9]+$ ]] || [[ ! "$end_p" =~ ^[0-9]+$ ]] || [ "$start_p" -lt 1 ] || [ "$end_p" -gt 65535 ] || [ "$start_p" -gt "$end_p" ]; then
                _error "端口范围无效，应为 1-65535 内的 start-end。"
                continue
            fi
            for ((p=start_p; p<=end_p; p++)); do current_p_list+=($p); done
        else
            current_p_list=($p_input)
        fi

        local p
        for p in "${current_p_list[@]}"; do
            if [[ ! "$p" =~ ^[0-9]+$ ]] || [ "$p" -lt 1 ] || [ "$p" -gt 65535 ]; then
                _error "端口 ${p} 无效，应为 1-65535。"
                invalid_port=true
                break
            fi
            if [[ "$seen_ports" == *" $p "* ]]; then
                _error "端口 ${p} 重复，请重新输入。"
                duplicate_port=true
                break
            fi
            seen_ports="${seen_ports}${p} "
            if _check_port_conflict "$p" "tcp" "true"; then
                _error "端口 ${p} 已被占用，请重新输入。"
                occupied_port=true
                break
            fi
        done
        if [ "$invalid_port" = true ] || [ "$duplicate_port" = true ] || [ "$occupied_port" = true ]; then
            continue
        fi
        
        if [ ${#current_p_list[@]} -lt $proto_count ]; then
            _error "输入端口数量不足（仅 ${#current_p_list[@]} 个），请重新输入。"
        else
            ports_list=("${current_p_list[@]}")
            break
        fi
    done

    # 4. 执行安装循环
    local state_dir="/tmp/singbox-batch-state.$$"
    if ! _snapshot_node_state "$state_dir"; then
        _error "无法创建批量创建前的配置快照，已取消操作。"
        rm -rf "$state_dir"
        return 1
    fi
    local batch_failed=false
    local created_ports=()
    local bulk_idx=0
    local proto_array=($proto_ids)
    for i in "${!proto_array[@]}"; do
        local pid=${proto_array[$i]}
        
        if [ "$pid" == "8" ]; then
            local ss_variants=$(echo "$ss_variant" | tr ',' ' ')
            for v in $ss_variants; do
                local current_port=${ports_list[$bulk_idx]}
                _info "正在安装 Shadowsocks (变体 $v) 到端口 $current_port..."
                export BATCH_MODE="true"
                export BATCH_PORT="$current_port"
                export BATCH_SS_VARIANT="$v"
                if ! _add_shadowsocks_menu; then
                    batch_failed=true
                else
                    created_ports+=("$current_port")
                fi
                ((bulk_idx++))
            done
        else
            local current_port=${ports_list[$bulk_idx]}
            _info "正在安装协议 [$pid] 到端口 $current_port..."
            
            export BATCH_MODE="true"
            export BATCH_PORT="$current_port"
            export BATCH_HY2_OBFS="$hy2_obfs"
            export BATCH_HY2_HOP="$hy2_hop_range"

            local action_result=0
            case $pid in
                1) _add_vless_reality; action_result=$? ;;
                2) _add_vless_ws_tls; action_result=$? ;;
                3) _add_trojan_ws_tls; action_result=$? ;;
                4) _add_vless_grpc_tls; action_result=$? ;;
                5) _add_anytls; action_result=$? ;;
                6) _add_hysteria2; action_result=$? ;;
                7) _add_tuic; action_result=$? ;;
                9) _add_vless_tcp; action_result=$? ;;
                10) _add_socks; action_result=$? ;;
            esac
            if [ "$action_result" -ne 0 ]; then
                batch_failed=true
            else
                created_ports+=("$current_port")
            fi
            ((bulk_idx++))
        fi
    done

    unset BATCH_MODE BATCH_PORT BATCH_SNI BATCH_HY2_OBFS BATCH_HY2_HOP BATCH_SS_VARIANT BATCH_ANYTLS_MODE BATCH_IP BATCH_GRPC_TLS_DOMAIN BATCH_GRPC_SERVICE_NAME

    if [ "$batch_failed" = true ] || [ "${#created_ports[@]}" -eq 0 ]; then
        _error "批量创建失败：至少一个节点配置写入未完成，正在恢复创建前配置。"
        _restore_node_state "$state_dir"
        _manage_service restart >/dev/null 2>&1 || true
        rm -rf "$state_dir"
        return 1
    fi

    _info "批量配置已写入，正在检查合并配置、重启服务和端口监听..."
    local service_ready=true
    if ! _manage_service restart; then
        service_ready=false
    else
        local check_port
        for check_port in "${created_ports[@]}"; do
            if ! _verify_service_ready "$check_port" "any"; then
                _error "端口 ${check_port} 未通过服务监听校验。"
                service_ready=false
                break
            fi
        done
    fi

    if [ "$service_ready" != true ]; then
        _error "批量创建失败：服务重启或端口监听校验未通过，正在恢复创建前配置。"
        _restore_node_state "$state_dir"
        _manage_service restart >/dev/null 2>&1 || true
        rm -rf "$state_dir"
        return 1
    fi

    rm -rf "$state_dir"
    echo ""
    echo -e "${YELLOW}══════════════════ 批量创建完成提示 ══════════════════${NC}"
    _success "所有批量节点均已通过服务校验并确认端口监听。"
    _info "您可以运行 sb 查看具体配置。"
    echo -e "${YELLOW}══════════════════════════════════════════════════════${NC}"
    return 0
}

_show_add_node_menu() {
    local needs_restart=false
    local action_result
    local state_dir="/tmp/singbox-node-state.$$"
    [ -z "$server_ip" ] && _init_server_ip
    clear
    echo -e "${CYAN}"
    echo '  ╔═══════════════════════════════════════╗'
    echo '  ║          sing-box 添加节点            ║'
    echo '  ╚═══════════════════════════════════════╝'
    echo -e "${NC}"
    echo ""
    
    echo -e "  ${CYAN}【协议选择】${NC}"
    echo -e "    ${GREEN}[1]${NC} VLESS (Vision+REALITY)"
    echo -e "    ${GREEN}[2]${NC} VLESS (WebSocket+TLS)"
    echo -e "    ${GREEN}[3]${NC} Trojan (WebSocket+TLS)"
    echo -e "    ${GREEN}[4]${NC} VLESS (gRPC+TLS)"
    echo -e "    ${GREEN}[5]${NC} AnyTLS"
    echo -e "    ${GREEN}[6]${NC} Hysteria2"
    echo -e "    ${GREEN}[7]${NC} TUICv5"
    echo -e "    ${GREEN}[8]${NC} Shadowsocks"
    echo -e "    ${GREEN}[9]${NC} VLESS (TCP)"
    echo -e "    ${GREEN}[10]${NC} SOCKS5"
    echo ""
    
    echo -e "  ${CYAN}【快捷功能】${NC}"
    echo -e "   ${GREEN}[11]${NC} 批量创建节点"
    echo ""
    
    echo -e "  ─────────────────────────────────────────"
    echo -e "    ${YELLOW}[0]${NC} 返回主菜单"
    echo ""
    
    read -p "  请输入选项 [0-11]: " choice

    # 如果输入包含逗号或空格，自动进入批量处理模式
    if [[ "$choice" == *","* ]] || [[ "$choice" == *" "* ]]; then
        _batch_create_nodes "$choice"
        return
    fi

    if [ "$choice" = "0" ]; then
        return
    fi
    if [ "$choice" = "11" ]; then
        _batch_create_nodes
        return
    fi

    rm -rf "$state_dir"
    if ! _snapshot_node_state "$state_dir"; then
        _error "无法创建节点变更快照，已取消操作。"
        rm -rf "$state_dir"
        return 1
    fi

    case $choice in
        1) _add_vless_reality; action_result=$? ;;
        2) _add_vless_ws_tls; action_result=$? ;;
        3) _add_trojan_ws_tls; action_result=$? ;;
        4) _add_vless_grpc_tls; action_result=$? ;;
        5) _add_anytls; action_result=$? ;;
        6) _add_hysteria2; action_result=$? ;;
        7) _add_tuic; action_result=$? ;;
        8) _add_shadowsocks_menu; action_result=$? ;;
        9) _add_vless_tcp; action_result=$? ;;
        10) _add_socks; action_result=$? ;;
        11) _batch_create_nodes; return ;;
        0) return ;;
        *) _error "无效输入，请重试。" ;;
    esac

    if [ "$action_result" -eq 0 ] 2>/dev/null; then
        needs_restart=true
    fi

    if [ "$needs_restart" = true ]; then
        local new_node_info new_tag new_port
        new_node_info=$(jq -r --slurpfile old "$state_dir/config.json" '
            .inbounds[] as $new
            | select((($old[0].inbounds // []) | map(.tag) | index($new.tag)) | not)
            | [$new.tag, ($new.listen_port|tostring)] | @tsv
        ' "$CONFIG_FILE" 2>/dev/null)
        if [ -z "$new_node_info" ]; then
            _error "节点函数未生成可验证的入站端口，正在恢复创建前配置。"
            _restore_node_state "$state_dir"
            rm -rf "$state_dir"
            return 1
        fi
        _info "配置已写入，正在检查合并配置、重启服务和监听端口..."
        local service_ready=true
        if ! _manage_service "restart"; then
            service_ready=false
        else
            while IFS=$'\t' read -r new_tag new_port; do
                [ -z "$new_port" ] && continue
                if ! _verify_service_ready "$new_port" "any"; then
                    _error "端口 ${new_port} 未通过服务监听校验。"
                    service_ready=false
                    break
                fi
            done <<< "$new_node_info"
        fi
        if [ "$service_ready" != true ]; then
            _error "节点创建失败：服务重启或端口监听校验未通过，正在恢复创建前配置。"
            _restore_node_state "$state_dir"
            _manage_service "restart" >/dev/null 2>&1 || true
            rm -rf "$state_dir"
            return 1
        fi
        _success "节点配置已加载，服务运行正常，新增端口均已监听。"
    else
        _error "节点配置写入失败，未执行服务重启。"
        rm -rf "$state_dir"
        return 1
    fi
    rm -rf "$state_dir"
}

# --- 脚本入口 ---

main() {
    _check_root
    _detect_init_system
    
    # 强制预创建目录，防止后续 cp/mv 因路径不存在报错 (保底机制)
    mkdir -p "${SINGBOX_DIR}" 2>/dev/null
    
    # 1. 首次安装或依赖状态失效时才完整检查，避免每次 sb 进入菜单都触发包管理器
    _install_dependencies
    
    # 2. 根据核心安装状态决定初始化路径
    if [ -f "${SINGBOX_BIN}" ]; then
        # --- sing-box 已安装：执行完整的初始化与自愈检测 ---
        
        # 3. 检查配置文件
        if [ ! -f "${CONFIG_FILE}" ] || [ ! -f "${CLASH_YAML_FILE}" ]; then
             _info "检测到主配置文件缺失，正在初始化..."
             _initialize_config_files
        fi

        # 3.1 初始化中转配置 (配置隔离)
        _init_relay_config
        
        # 3.2 [关键修复] 清理主配置文件中的旧版残留
        local config_updated=false
        if _cleanup_legacy_config; then
            config_updated=true
        fi
        
        # 3.3 [热修复] 检测并补充 DNS 模块
        if _check_and_fix_dns; then
            config_updated=true
        fi
        
        if [ "$config_updated" = true ]; then
            _manage_service restart
        fi
        
        # [BUG FIX] 检查并修复旧版服务文件
        if [ -f "$SERVICE_FILE" ]; then
            local need_update=false
            if grep -q "\-C " "$SERVICE_FILE"; then
                _warn "检测到旧版服务配置(目录加载模式导致冲突)，正在修复..."
                need_update=true
            fi
            if [ "$INIT_SYSTEM" == "systemd" ] && ! grep -q '^ExecStartPre=.*sing-box.*check' "$SERVICE_FILE"; then
                _warn "检测到服务缺少启动前合并配置校验，正在修复..."
                need_update=true
            fi
            if [ "$INIT_SYSTEM" == "systemd" ] && ! grep -q 'relay\.json' "$SERVICE_FILE"; then
                _warn "检测到服务未加载 relay.json，正在修复..."
                need_update=true
            fi
            if [ "$INIT_SYSTEM" == "openrc" ] && ! grep -q "supervisor=" "$SERVICE_FILE"; then
                _warn "检测到旧版 OpenRC 服务配置，正在修复以兼容 Alpine..."
                need_update=true
            fi
            if [ "$INIT_SYSTEM" == "openrc" ] && ! grep -q '^start_pre()' "$SERVICE_FILE"; then
                _warn "检测到 OpenRC 服务缺少启动前配置校验，正在修复..."
                need_update=true
            fi
            if [ "$need_update" = true ]; then
                if [ "$INIT_SYSTEM" == "systemd" ]; then
                     _create_systemd_service
                     systemctl daemon-reload
                elif [ "$INIT_SYSTEM" == "openrc" ]; then
                     _create_openrc_service
                fi
                if { [ "$INIT_SYSTEM" == "systemd" ] && systemctl is-active sing-box >/dev/null 2>&1; } || { [ "$INIT_SYSTEM" == "openrc" ] && rc-service sing-box status >/dev/null 2>&1; }; then
                    _manage_service restart
                fi
                _success "服务配置修复完成。"
            fi
        fi

        # [PATH FIX] 确保 relay.json 存在
        if [ ! -s "${SINGBOX_DIR}/relay.json" ]; then
            echo '{"inbounds":[],"outbounds":[],"route":{"rules":[]}}' > "${SINGBOX_DIR}/relay.json"
        fi

        # 4. 首次安装或服务文件缺失时才创建，避免每次进入菜单都重写服务文件
        if [ -n "$SERVICE_FILE" ] && [ ! -f "$SERVICE_FILE" ]; then
            _create_service_files
        elif [ "$INIT_SYSTEM" == "direct" ] && [ ! -f "$LOG_FILE" ]; then
            touch "$LOG_FILE"
        fi
        _setup_log_cleanup
    else
        # --- sing-box 未安装：仅显示提示，不自动安装 ---
        _warn "sing-box 核心未安装。请通过主菜单【核心管理】进行安装。"
    fi
    
    _main_menu
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        keepalive)
            _argo_keepalive
            exit 0
            ;;
        cleanup-logs)
            _cleanup_runtime_logs
            exit $?
            ;;
        *)
            shift
            ;;
    esac
done

main
