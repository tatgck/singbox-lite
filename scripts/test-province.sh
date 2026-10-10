#!/bin/bash
# Extract definitions only; no production entry point or external requests.
set -e
repo_dir=$(cd "$(dirname "$0")/.." && pwd)
for name in _sni_public_ipv4 _province_catalog _province_test_endpoint _province_print_report _province_test_menu; do
    eval "$(awk -v name="$name" '$0 == name "() {" {p=1} p {print} p && /^}$/ {exit}' "$repo_dir/singbox.sh")"
    declare -F "$name" >/dev/null
done
_warn() { printf '%s\n' "$*" >&2; }
_error() { _warn "$@"; }
tests=0
check() { "$@" || { printf 'FAIL: %s\n' "$*" >&2; exit 1; }; tests=$((tests+1)); }
reject() { if "$@" >/dev/null 2>&1; then printf 'UNEXPECTED SUCCESS: %s\n' "$*" >&2; exit 1; fi; tests=$((tests+1)); }
task_tmp=$(mktemp -d /tmp/province-tests.XXXXXX)
trap 'rm -rf "$task_tmp"' EXIT
curl() {
    printf '%s\n' "$*" >> "$task_tmp/calls"
    printf '%s' "$mock_output"
    return "$mock_rc"
}
mock_output='219.148.62.1 0.090000 412' mock_rc=0
result=$(_province_test_endpoint he-ct-v4.ip.zstaticcdn.com)
check grep -q 'TCP 成功 3/3，建连均值 90ms' <<< "$result"
check grep -q 'HTTP 响应 3/3' <<< "$result"
check grep -q 'HTTP=412/curl=0' <<< "$result"
check test "$(wc -l < "$task_tmp/calls" | tr -d ' ')" = 3
check test "$(grep -c -- '--noproxy \* -4 -I.*--connect-timeout 3 --max-time 5.*http://he-ct-v4.ip.zstaticcdn.com:80/' "$task_tmp/calls")" = 3
reject grep -qE -- ' -L|--retry' "$task_tmp/calls"

# HEAD rejection still demonstrates TCP and HTTP reachability.
mock_output='110.249.198.60 0.100000 404'
result=$(_province_test_endpoint he-cu-v4.ip.zstaticcdn.com)
check grep -q 'TCP 成功 3/3' <<< "$result"
check grep -q 'HTTP 响应 3/3' <<< "$result"
mock_output='111.63.63.207 0.110000 000' mock_rc=28
result=$(_province_test_endpoint he-cm-v4.ip.zstaticcdn.com)
check grep -q 'TCP 成功 3/3' <<< "$result"
check grep -q 'HTTP 响应 0/3' <<< "$result"
check grep -q 'HTTP=000/curl=28' <<< "$result"
mock_output=' 0.000000 000' mock_rc=6
result=$(_province_test_endpoint he-ct-v4.ip.zstaticcdn.com)
check grep -q 'TCP 成功 0/3' <<< "$result"
check grep -q 'HTTP=000/curl=6' <<< "$result"
mock_output='127.0.0.1 0.010000 200' mock_rc=0
result=$(_province_test_endpoint he-ct-v4.ip.zstaticcdn.com)
check grep -q 'TCP 成功 0/3' <<< "$result"
check grep -q 'HTTP 响应 0/3' <<< "$result"
mock_output='2001:db8::1 0.010000 200'
result=$(_province_test_endpoint he-ct-v4.ip.zstaticcdn.com)
check grep -q 'TCP 成功 0/3' <<< "$result"
reject _province_test_endpoint 'he-ct-v4.ip.zstaticcdn.com;id'
reject _province_test_endpoint 'he-ct-v6.ip.zstaticcdn.com'

# Single province expands to exactly three carriers (nine requests).
mock_output='219.148.62.1 0.090000 200'
before=$(wc -l < "$task_tmp/calls")
menu=$(_province_test_menu <<< '河北')
after=$(wc -l < "$task_tmp/calls")
check test "$((after-before))" = 9
check grep -q 'VPS → 河北 三网 IPv4 参考结果' <<< "$menu"
check grep -q '^1\. 电信$' <<< "$menu"
check grep -q '^2\. 联通$' <<< "$menu"
check grep -q '^3\. 移动$' <<< "$menu"
check test "$(grep -c 'TCP 成功' <<< "$menu")" = 3
check grep -q '^   第3轮 HTTP=200/curl=0$' <<< "$menu"
for code in ct cu cm; do check grep -q "he-${code}-v4.ip.zstaticcdn.com:80" <<< "$menu"; done
check test "$(_province_catalog | wc -l | tr -d ' ')" = 31
check test "$(_province_catalog | cut -d '|' -f2 | sort -u | wc -l | tr -d ' ')" = 31
for selection in '0' '' '32' '1 2' '河北,山西' '*'; do
    reject _province_test_menu <<< "$selection"
done
before=$(wc -l < "$task_tmp/calls")
menu=$(_province_test_menu <<< 'sn')
check grep -q 'VPS → 陕西 三网' <<< "$menu"
check grep -q 'sn-ct-v4.ip.zstaticcdn.com:80' <<< "$menu"
menu=$(_province_test_menu <<< '02')
check grep -q 'VPS → 山西 三网' <<< "$menu"
check grep -q 'sx-ct-v4.ip.zstaticcdn.com:80' <<< "$menu"
after=$(wc -l < "$task_tmp/calls")
check test "$((after-before))" = 18
printf 'PASS: %s province checks (mocked HTTP, no external requests)\n' "$tests"
