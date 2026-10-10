#!/bin/bash
# Extract definitions only: never source the production main entry point.
set -e
repo_dir=$(cd "$(dirname "$0")/.." && pwd)
load_function() {
    eval "$(awk -v name="$1" '$0 == name "() {" {p=1} p {print} p && /^}$/ {exit}' "$repo_dir/singbox.sh")"
    declare -F "$1" >/dev/null
}
for name in _validate_sni_domain _sni_cert_regenerable _sni_public_ipv4 _sni_test_domain _sni_parse_candidates \
    _sni_cdn_hint _sni_globalping_http _sni_source_catalog _sni_globalping_city _sni_choose_sources \
    _snapshot_node_state _restore_node_state _modify_sni _sni_optimizer_menu; do load_function "$name"; done
_warn() { :; }; _warning() { :; }; _info() { :; }; _error() { :; }; _success() { :; }
CYAN='' NC='' YELLOW='' GREEN=''
tests=0
check() { "$@" || { printf 'FAIL: %s\n' "$*" >&2; exit 1; }; tests=$((tests+1)); }
reject() { if "$@" >/dev/null 2>&1; then printf 'UNEXPECTED SUCCESS: %s\n' "$*" >&2; exit 1; fi; tests=$((tests+1)); }
check _validate_sni_domain www.example.com
reject _validate_sni_domain 'https://example.com/'
reject _validate_sni_domain 'example.com;id'
reject _validate_sni_domain '1.1.1.1'
reject _validate_sni_domain "$(printf '%064d' 1).com"
check _sni_public_ipv4 45.60.35.24
for ip in 127.0.0.1 10.0.0.1 192.168.1.2 100.64.1.1 169.254.1.1 198.18.0.1 203.0.113.1 1.2.3.999 ::1; do
    reject _sni_public_ipv4 "$ip"
done
check test "$(_sni_parse_candidates 'WWW.Example.com, www.example.com second.example.com')" = 'www.example.com second.example.com'
check test "$(_sni_parse_candidates $'www.example.com\r\nsecond.example.com\r\n')" = 'www.example.com second.example.com'
reject _sni_parse_candidates '*.example.com'
reject _sni_parse_candidates "$(printf 'n%s.example.com ' {1..13})"
check test "$(_sni_cdn_hint '6w6nks5.x.incapdns.net')" = detected
check test "$(_sni_cdn_hint 'Cloudflare Inc.')" = detected
check test "$(_sni_cdn_hint 'hosting.example.net')" = unknown

# Reject transport failures even if write-out reports a plausible appconnect time.
curl() { printf '%s\n' "$mock_output"; return "$mock_rc"; }
mock_rc=0 mock_output='0.030 0.010 2 200 0 45.60.35.24'
check test "$(_sni_test_domain www.example.com)" = $'20\t0\t✓\t3\t45.60.35.24'
mock_rc=28
reject _sni_test_domain www.example.com
mock_rc=0
for mock_output in '0 0.010 2 200 0 45.60.35.24' '0.030 0.010 1.1 200 0 45.60.35.24' \
    '0.030 0.010 2 301 0 45.60.35.24' '0.030 0.010 2 403 0 45.60.35.24' \
    '0.030 0.010 2 200 60 45.60.35.24' '0.030 0.010 2 200 0 127.0.0.1'; do
    reject _sni_test_domain www.example.com
done

_sni_globalping_measure() { printf '%s\n' "$fixture"; }
fixture='{"status":"finished","probesCount":1,"results":[{"probe":{"country":"CN","city":"Beijing","asn":4134,"network":"Test\\nCarrier"},"result":{"status":"finished","statusCode":200,"timings":{"tls":20},"tls":{"authorized":true,"protocol":"TLSv1.3"}}}]}'
locations='[{"country":"CN","asn":4134,"city":"Beijing","limit":1}]'
result=$(_sni_globalping_http www.example.com "$locations" '')
check test "$(printf '%s' "$result" | cut -f7)" = complete
check test "$(printf '%s' "$result" | cut -f6)" = 1
result=$(_sni_globalping_http www.example.com '[{"country":"CN","asn":4837,"city":"Beijing","limit":1}]' '')
check test "$(printf '%s' "$result" | cut -f7)" = partial
fixture=$(printf '%s' "$fixture" | jq '.results[0].result.status="failed" | .results[0].result.statusCode=null')
result=$(_sni_globalping_http www.example.com "$locations" '')
check test "$(printf '%s' "$result" | cut -f6)" = 0
check test "$(printf '%s' "$result" | cut -f7)" = partial
fixture=$(printf '%s' "$fixture" | jq '.results[0].result.tls.authorized=false')
reject _sni_globalping_http www.example.com "$locations" ''
fixture=$(printf '%s' "$fixture" | jq '.results[0].result.tls.authorized=true | .results[0].probe.country="US"')
reject _sni_globalping_http www.example.com "$locations" ''
fixture=$(printf '%s' "$fixture" | jq '.results[0].probe.country="CN" | .probesCount=2')
reject _sni_globalping_http www.example.com "$locations" ''
fixture=$(printf '%s' "$fixture" | jq '.probesCount=1 | .results[0].result.timings.tls=-1')
reject _sni_globalping_http www.example.com "$locations" ''

ping() { return 1; }
reject _sni_choose_sources <<< '*'
_sni_choose_sources <<< '08,09,10,11,12,13,08' >/dev/null
check test "$SNI_SOURCE_COUNT" = 5
check test "$SNI_SOURCE_SELECTED_COUNT" = 5
check test "$(printf '%s' "$SNI_SOURCE_LOCATIONS" | jq -r '.[0].city')" = Luoyang

# SNI edit must restore server config AND client metadata/YAML on a write/restart error.
task_tmp=$(mktemp -d /tmp/sni-tests.XXXXXX)
trap 'rm -rf "$task_tmp"' EXIT
mktemp() { command mktemp -d "$task_tmp/state.XXXXXX"; }
SINGBOX_DIR="$task_tmp"
CONFIG_FILE="$task_tmp/config.json" CLASH_YAML_FILE="$task_tmp/clash.yaml"
METADATA_FILE="$task_tmp/metadata.json" ARGO_METADATA_FILE="$task_tmp/argo.json"
_find_proxy_name() { printf 'test-node'; }
_atomic_modify_json() {
    local data
    data=$(jq "$2" "$1") || return 1
    printf '%s\n' "$data" > "$1" || return 1
    # Abort after a real temporary config write to exercise the transaction EXIT handler.
    [ "$failure_mode" = aborted ] && exit 42
    if [ "$failure_mode" = terminated ]; then command sh -c 'kill -TERM "$PPID"'; fi
    return 0
}
_atomic_modify_yaml() { printf 'changed\n' > "$1"; [ "$failure_mode" != yaml ]; }
_validate_merged_config() { return 0; }
_manage_service() { [ "$failure_mode" != restart ]; }
_verify_service_ready() {
    [ "$2" = tcp ] && [ "$failure_mode" != unready ]
}
reset_state() {
    printf '%s\n' '{"inbounds":[{"tag":"vless-in-443","type":"vless","listen_port":443,"tls":{"server_name":"old.example.com","reality":{"enabled":true,"handshake":{"server":"old.example.com"}}}}]}' > "$CONFIG_FILE"
    printf '%s\n' '{"vless-in-443":{"name":"test-node","server_name":"old.example.com","share_link":"vless://test?sni=old.example.com"}}' > "$METADATA_FILE"
    printf 'original\n' > "$CLASH_YAML_FILE"
    cp "$CONFIG_FILE" "$task_tmp/original-config"
    cp "$METADATA_FILE" "$task_tmp/original-meta"
}
for failure_mode in yaml restart unready aborted terminated; do
    reset_state
    reject _modify_sni <<< $'1\nnew.example.com'
    check cmp -s "$CONFIG_FILE" "$task_tmp/original-config"
    check cmp -s "$METADATA_FILE" "$task_tmp/original-meta"
    check test "$(<"$CLASH_YAML_FILE")" = original
done
failure_mode=none
reset_state
check _modify_sni <<< $'1\nnew.example.com'
check test "$(jq -r '.inbounds[0].tls.reality.handshake.server' "$CONFIG_FILE")" = new.example.com
reset_state
special_tag='quoted"tag'
jq --arg t "$special_tag" '.inbounds[0].tag=$t' "$CONFIG_FILE" > "$task_tmp/config-special.json"
mv "$task_tmp/config-special.json" "$CONFIG_FILE"
jq --arg t "$special_tag" '{($t): .["vless-in-443"]}' "$METADATA_FILE" > "$task_tmp/metadata-special.json"
mv "$task_tmp/metadata-special.json" "$METADATA_FILE"
check _modify_sni <<< $'1\nnew.example.com'
check test "$(jq -r --arg t "$special_tag" '.inbounds[0].tls.reality.handshake.server' "$CONFIG_FILE")" = new.example.com
check test "$(jq -r --arg t "$special_tag" '.[$t].server_name' "$METADATA_FILE")" = new.example.com
reset_state
cert="$task_tmp/vless-in-443.pem"
key="$task_tmp/vless-in-443.key"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=old.example.com' \
    -keyout "$key" -out "$cert" >/dev/null 2>&1
check _sni_cert_regenerable vless-in-443 "$cert" "$key"
jq --arg c "$cert" --arg k "$key" '.inbounds += [{tag:"other-node",tls:{certificate_path:$c,key_path:$k}}]' \
    "$CONFIG_FILE" > "$task_tmp/config-shared.json"
mv "$task_tmp/config-shared.json" "$CONFIG_FILE"
reject _sni_cert_regenerable vless-in-443 "$cert" "$key"
reject _sni_cert_regenerable vless-in-443 "$cert" "$task_tmp/other.key"
reset_state
reject _modify_sni < /dev/null
check cmp -s "$CONFIG_FILE" "$task_tmp/original-config"

# Exercise all menu modes without touching production services or networks.
clear() { :; }
dig() { :; }
_sni_curl_capable() { return 0; }
_sni_ip_metadata() { printf '%s\n' "{\"country\":\"SG\",\"asn\":123,\"org\":\"$mock_org\"}"; }
_sni_test_domain() { printf '20\t0\t✓\t3\t45.60.35.24\n'; }
_sni_choose_sources() {
    SNI_SOURCE_LOCATIONS='[{"country":"CN","asn":4134,"city":"Beijing","limit":1}]'
    SNI_SOURCE_FALLBACK_LOCATIONS='[{"country":"CN","asn":4134,"limit":1}]'
    SNI_SOURCE_COUNT=1 SNI_SOURCE_SELECTED_COUNT=1 SNI_SOURCE_LABEL=Beijing
}
_sni_globalping_http() { printf '%s\n' "$remote_fixture"; }
_init_server_ip() { server_ip=127.0.0.1; }
server_ip=127.0.0.1 mock_org=hosting
remote_fixture=$'20\t1\tBeijing/Test\tTLSv1.3\t1\t1\tcomplete'
menu=$(_sni_optimizer_menu <<< $'5\nwww.example.com\nY\n3')
check test "$(printf '%s' "$menu" | grep -c '综合结果 TOP')" = 1
check test "$(printf '%s' "$menu" | grep -c '优先复测候选')" = 1
remote_fixture=$'20\t1\tGuangzhou/Test\tTLSv1.3\t1\t1\tpartial'
menu=$(_sni_optimizer_menu <<< $'5\nwww.example.com\nY\n3')
reject grep -q '综合结果 TOP' <<< "$menu"
check grep -q 'VPS 侧候选结果' <<< "$menu"
menu=$(_sni_optimizer_menu <<< $'5\nwww.example.com\nY\n2')
check grep -q '中国远程探针结果 TOP' <<< "$menu"
reject grep -q '优先复测候选' <<< "$menu"
mock_org='Cloudflare Inc'
menu=$(_sni_optimizer_menu <<< $'5\nwww.example.com\nY\n1')
reject grep -q '候选结果 TOP' <<< "$menu"
mock_org=hosting
_sni_test_domain() { return 1; }
remote_fixture=$'20\t1\tBeijing/Test\tTLSv1.3\t1\t1\tcomplete'
menu=$(_sni_optimizer_menu <<< $'5\nwww.example.com\nY\n3')
check grep -q '中国远程探针结果 TOP' <<< "$menu"
reject grep -q '优先复测候选' <<< "$menu"
printf 'PASS: %s checks (mocked network and config writes)\n' "$tests"
