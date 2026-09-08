# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is **singbox-lite**, a comprehensive sing-box + Xray dual-core management script suite for Linux servers. It provides automated node creation, relay/transit configurations, third-party node import, port forwarding, Argo tunnels, and Clash/Mihomo configuration export.

**Current script versions**: `singbox.sh v20`, `advanced_relay.sh`, `parser.sh`, `xray_manager.sh`

Note: The README.md describes v28 features (latest upstream), but the current codebase contains v20 scripts with recent fixes applied.

## Repository Structure

| File | Purpose |
|------|---------|
| `singbox.sh` | Main entry point; handles dependencies, sing-box core, nodes, Argo, DNS, services, and subscript orchestration |
| `advanced_relay.sh` | Transit/relay configuration, third-party node import, port forwarding, and routing rules |
| `parser.sh` | Strict parser for third-party share links (VLESS, Shadowsocks, Hysteria2, TUIC, etc.) |
| `xray_manager.sh` | Xray-core installation, service, and node management; shares `clash.yaml` with sing-box |
| `README.md` | User-facing documentation in Chinese |

## Architecture

### Script Coordination

- **Main script** (`singbox.sh`): Entry point, handles core management and node CRUD operations
- **Relay script** (`advanced_relay.sh`): Manages transit configurations, downloads `parser.sh` on demand
- **Parser** (`parser.sh`): Standalone link parser, invoked by relay script via `bash parser.sh <link>`
- **Xray manager** (`xray_manager.sh`): Independent Xray management, shares output configuration

Scripts communicate through:
- Shared JSON config files: `/usr/local/etc/sing-box/config.json`, `relay.json`
- Metadata file: `/usr/local/etc/sing-box/metadata.json`
- Shared Clash config: `/usr/local/etc/sing-box/clash.yaml`
- State lock mechanism to prevent concurrent modifications

### Configuration Files

```
/usr/local/etc/sing-box/
├── config.json          # sing-box primary nodes
├── relay.json          # transit and user-space port forwarding
├── clash.yaml          # sing-box + Xray shared client config
├── metadata.json       # node metadata and share links
├── core-version.lock   # fixed version 1.13.21 persistent lock (if set)
└── relay.d/            # transit, port forwarding, and auxiliary state
```

### Key Components

1. **Node Protocol Support**:
   - VLESS (TCP/Reality/Vision, WebSocket/TLS, gRPC/TLS)
   - Trojan (WebSocket/TLS)
   - Hysteria2 (with Salamander obfuscation and port hopping)
   - TUIC v5
   - AnyTLS / Any-Reality
   - Shadowsocks (classic + SS2022 variants)
   - SOCKS5

2. **Transit Modes**:
   - **Mode 1**: Local node token export/import (ENC2 encrypted)
   - **Mode 2**: Third-party landing node via share link

3. **Port Forwarding**:
   - Auto-detects capability: nftables (kernel forwarding) or sing-box user-space
   - Supports TCP, UDP, TCP+UDP
   - IPv4, IPv6, domain targets
   - Domain targets refresh every minute via scheduled task

4. **Argo Tunnel Support**:
   - Temporary tunnels (auto-generated subdomain)
   - Fixed tunnels (user-provided token)
   - Auto-daemon with cron for process protection

## Recent Fixes (Applied to v20 Base)

### 1. Repository URL Update
All script download URLs changed from:
```bash
https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main
```
to:
```bash
https://raw.githubusercontent.com/tatgck/singbox-lite/main
```

**Files affected**: `singbox.sh`, `advanced_relay.sh`

### 2. Enhanced Shadowsocks Parser
The `parser.sh` SS link parser was rewritten with:
- Proper handling of both SIP002 (`ss://base64@server:port`) and legacy formats
- URL decoding before Base64 decoding
- Comprehensive error messages for each failure point:
  - Base64 decode failures
  - Missing `@` separator
  - Missing `method:password` colon
  - Invalid server:port format
  - Incomplete link information
- Query parameter stripping (`?` removal)
- Fragment handling (`#` removal)
- Validation of all required fields before JSON generation

**Location**: `parser.sh:201-287`

### 3. sing-box 1.14 DNS Format Migration
sing-box 1.14 removed legacy DNS server formats (`address` field) and the `{"outbound":"any"}` DNS rule, causing `FATAL decode config ... dns.servers[0]` on startup. Fixed in `singbox.sh`:
- New configs use typed DNS servers (`{"type":"local","tag":"dns-local","prefer_go":true}`) plus `route.default_domain_resolver` instead of the removed outbound-any DNS rule
- `_dns_address_to_server_json()` converts legacy address strings (`local`, bare IP, `udp://`, `tcp://`, `tls://`, `quic://`, `https://host/path`) to typed server JSON
- `_check_and_fix_dns()` auto-migrates existing legacy configs on script start (idempotent; preserves the user's chosen DNS address and strategy)
- `_apply_dns_config()` (DNS menu) writes typed format; menu display reconstructs a readable address from typed servers
- The `ENABLE_DEPRECATED_*` env vars still exported by scripts/service files are inert on 1.14 (harmless)

### 4. SNI Modification + SNI Optimizer (v22)
Three new features:
- **Main menu [5]** is now a submenu: 1) modify port (existing `_modify_port`), 2) modify SNI (new `_modify_sni` in `singbox.sh`). SNI edit lists TLS/Reality nodes by number, updates `tls.server_name` (+ `tls.reality.handshake.server` for Reality, + hop children), optionally regenerates self-signed certs for the new domain, syncs clash.yaml (`servername`/`sni` fields, only if present), metadata `server_name` and share-link `sni=`/`peer=`/`pcs=`/`pinSHA256=` params. Validates with `sing-box check`, full rollback on failure.
- **Relay menu [7] 修改中转入口 SNI** (`_modify_relay_sni` in `advanced_relay.sh`): same pattern for relay entrances (vless-reality/hysteria2/tuic/anytls); regenerates entrance certs (`RELAY_AUX_DIR/<tag>.pem`) with the simple `openssl req -subj /CN=` style used at creation; validates merged config (`check -c config.json -c relay.json`). Relay menu renumbered: clear-all 7→8, port-forwarding 8→9.
- **Main menu [20] SNI 优选** (`_sni_optimizer_menu`): region pools (US/JP/SG + auto-detect via ipinfo.io→ip-api.com, plus HK/KR/TW/DE/GB pools and a global anycast-CDN fallback), 3 rounds of TLS handshake latency per domain via curl (`time_appconnect - time_namelookup`, exit code deliberately ignored since some CDNs reject Range/HEAD after a successful handshake), score = avg + jitter + 300ms penalty if no HTTP/2, top-5 shown reversed (best last). Probes curl for `--tlsv1.3` support once (exit 4 = unsupported build) and degrades gracefully.

## Common Development Tasks

### Testing SS Link Parsing
```bash
bash parser.sh "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@192.168.1.1:8388#test"
```

Expected output: JSON with `type:"shadowsocks"`, `server`, `server_port`, `method`, `password`

### Script Update Workflow
The main script downloads subscripts from the same repository:
```bash
# In singbox.sh or advanced_relay.sh
GITHUB_RAW_BASE="https://raw.githubusercontent.com/tatgck/singbox-lite/main"
wget -qO "$target_path" "${GITHUB_RAW_BASE}/parser.sh"
```

### Configuration Validation
```bash
/usr/local/bin/sing-box check -c /usr/local/etc/sing-box/config.json
jq empty /usr/local/etc/sing-box/relay.json  # JSON syntax check
```

### Common Issues

1. **SS link parsing fails**: Check Base64 encoding, ensure proper URL encoding, verify `method:password@server:port` format
2. **Parser not found**: Main script auto-downloads from `GITHUB_RAW_BASE` on first relay operation
3. **Port conflicts**: Scripts check across main config, relay config, Xray config, and Hysteria2 jump ranges
4. **Time sync for SS2022**: Requires accurate system time (±30s window); main script includes NTP compensation for sing-box

## Git Workflow

Current state:
- Working on `main` branch
- Remote: `git@github.com:tatgck/singbox-lite.git`
- Uncommitted: 4 new shell scripts, modified README.md

Typical workflow:
```bash
git add singbox.sh advanced_relay.sh parser.sh xray_manager.sh README.md
git commit -m "Fix SS parsing and update repo URLs to tatgck/singbox-lite"
git push origin main
```

## Notes for Future Sessions

- README.md describes v28 features; current scripts are v20 with fixes
- Parser supports strict protocol-specific parsing (no auto-detection fallback)
- All scripts share a state lock mechanism at `/var/lock/singbox_relay.lock`
- Atomic writes use temp files + `mv` for JSON/YAML updates
- Service management supports systemd, OpenRC, and direct background mode
- Chinese-language user documentation and prompts throughout
