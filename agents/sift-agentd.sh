#!/bin/bash
# sift-agentd — the Sift exec daemon.
SIFT_AGENT_VERSION="2026.11.09.2"
#
# Long-polls the Sift server for READ-ONLY, allowlisted diagnostic commands, runs each one
# with NO shell (argv array only — so ; | $() `` redirects can't be injected), and POSTs the
# output back. Companion to sift-agent.sh (the collector); same agent.env / env vars.
#
# Security model (why this is safe to run, even as root):
#   * The server can only ever queue a KEY from a fixed menu (+ typed, validated args).
#   * This daemon re-validates every arg and maps the key to a hard-coded argv array.
#     An unknown key or a malformed arg is refused — it is NEVER passed to a shell.
#   * Nothing here writes, installs, restarts or deletes. Read-only diagnostics only.
#     (The one exception is the admin-only uninstall control, which removes the agent itself.)
#   * The token lives in a 0600 header file, never in a process's argv.
#
# Run as a persistent systemd service (Restart=always). Zero deps: bash + curl.
#   SIFT_SERVER   e.g. http://sift.lan:8130 (LAN) or https://sift.example.com (via your proxy)
#   SIFT_TOKEN    this host's agent token (or the server's ingest token on older servers)
#   SIFT_HOST     label for this host (default: hostname) — must match the collector's label
#   SIFT_EXEC_TIMEOUT  per-command wall-clock cap (default 20s).  SIFT_EXEC_OUTMAX bytes (default 8000).
set -u
HERE="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
[ -f "$HERE/agent.env" ] && . "$HERE/agent.env"
SERVER="${SIFT_SERVER:-http://localhost:8130}"; SERVER="${SERVER%/}"
TOKEN="${SIFT_TOKEN:-}"
HOST="${SIFT_HOST:-$(hostname)}"
TIMEOUT="${SIFT_EXEC_TIMEOUT:-20}"
OUT_MAX="${SIFT_EXEC_OUTMAX:-8000}"
HB_EVERY=60          # heartbeat at most once a minute (the long-poll loop is ~25s)

is_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; }
is_disk() { [[ "$1" =~ ^[a-z0-9]{1,16}$ ]]; }
is_int()  { [[ "$1" =~ ^[0-9]{1,4}$ ]]; }

[[ "$HOST" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { echo "[sift-agentd] invalid SIFT_HOST '$HOST'" >&2; exit 2; }

# Private scratch dir (systemd's PrivateTmp makes /tmp per-service; mktemp makes it 0700).
WORK="$(mktemp -d "${TMPDIR:-/tmp}/sift-agentd.XXXXXX")" || exit 1
trap 'rm -rf "$WORK"' EXIT
( umask 077; printf 'Authorization: Bearer %s\n' "$TOKEN" > "$WORK/auth.hdr" )
_v="$(curl --version 2>/dev/null | awk 'NR==1{print $2}')"; _maj="${_v%%.*}"; _r="${_v#*.}"; _min="${_r%%.*}"
if [ "${_maj:-0}" -gt 7 ] 2>/dev/null || { [ "${_maj:-0}" -eq 7 ] && [ "${_min:-0}" -ge 55 ]; } 2>/dev/null; then
    AUTH=(-H "@$WORK/auth.hdr")
else
    AUTH=(-H "Authorization: Bearer $TOKEN")
fi

# Map a command KEY (+ validated args in the globals below) to an argv array in ARGV.
# Returns non-zero and sets REASON on an unknown key or a bad arg — the only commands that
# can ever run are the literal argv arrays written here.
build_argv() {
    local cmd="$1"
    is_int "$lines" || lines=50
    case "$cmd" in
        uptime)      ARGV=(uptime) ;;
        disk)        ARGV=(df -h) ;;
        mem)         ARGV=(free -h) ;;
        zpool)       ARGV=(zpool status) ;;
        docker_ps)   ARGV=(docker ps) ;;
        docker_logs) is_name "$container" || { REASON="bad container"; return 1; }
                     ARGV=(docker logs --tail "$lines" "$container") ;;
        smart)       is_disk "$disk" || { REASON="bad disk"; return 1; }
                     ARGV=(smartctl -H -A "/dev/$disk") ;;
        journal)     is_name "$unit" || { REASON="bad unit"; return 1; }
                     ARGV=(journalctl -u "$unit" -n "$lines" --no-pager) ;;
        failed)      ARGV=(systemctl --failed --no-pager) ;;
        procs)       ARGV=(ps -eo pid,pcpu,pmem,comm --sort=-pcpu) ;;
        net)         ARGV=(ss -tulpn) ;;
        uname)       ARGV=(uname -a) ;;
        *)           REASON="unknown command '$cmd'"; return 1 ;;
    esac
}

# Keep the TAIL of long output: for logs/journal the newest lines are at the end.
tail_bytes() {   # text max
    local t="$1" m="$2"
    if [ "${#t}" -gt "$m" ]; then printf '…(truncated)\n%s' "${t: -$m}"; else printf '%s' "$t"; fi
}

post_result() {   # id  output  rc   — id/rc in headers, raw output as the body (no JSON encoding needed)
    tail_bytes "$2" "$OUT_MAX" | curl -s -m 15 "${AUTH[@]}" -H "X-Cmd-Id: $1" -H "X-Cmd-Rc: $3" \
         --data-binary @- "$SERVER/agent/command-result" >/dev/null 2>&1
}

last_hb=0
heartbeat() {
    [ $((SECONDS - last_hb)) -lt "$HB_EVERY" ] && [ "$last_hb" -ne 0 ] && return 0
    printf '{"host":"%s","component":"daemon","version":"%s"}' "$HOST" "$SIFT_AGENT_VERSION" \
        | curl -s -m 10 "${AUTH[@]}" -H 'Content-Type: application/json' --data-binary @- \
               "$SERVER/agent/heartbeat" >/dev/null 2>&1 && last_hb=$SECONDS
}

# Self-uninstall (admin-only control from the server). Runs as a SEPARATE transient unit, so
# stopping sift-agentd can't kill it — and as an inline script: no file in /tmp to race on.
uninstall() {
    local rmdir=""
    case "$HERE" in /opt/sift-agent*) rmdir="$HERE" ;; esac   # only remove a dedicated install dir
    local script
    script="sleep 1
systemctl disable --now sift-agent.timer >/dev/null 2>&1 || true
systemctl stop sift-agent.service >/dev/null 2>&1 || true
systemctl disable --now sift-agentd >/dev/null 2>&1 || true
rm -f /etc/systemd/system/sift-agentd.service /etc/systemd/system/sift-agent.service /etc/systemd/system/sift-agent.timer
systemctl daemon-reload >/dev/null 2>&1 || true
for u in root \$(ls /var/spool/cron/crontabs 2>/dev/null); do
  if crontab -u \"\$u\" -l 2>/dev/null | grep -q 'sift-agent\\.sh'; then
    crontab -u \"\$u\" -l 2>/dev/null | grep -v 'sift-agent\\.sh' | crontab -u \"\$u\" - 2>/dev/null || true
  fi
done
rm -rf /var/tmp/sift-agent
${rmdir:+rm -rf '$rmdir'}"
    if ! systemd-run --no-block --collect --unit="sift-uninstall-$$" /bin/bash -c "$script" >/dev/null 2>&1; then
        setsid /bin/bash -c "$script" </dev/null >/dev/null 2>&1 &
    fi
}

# Failure backoff: a refused, broken or unauthorised server must not be hammered, because a
# reverse proxy's WAF will read rapid-fire errors as an attack and ban this host.
BACKOFF_MAX="${SIFT_BACKOFF_MAX:-300}"
MIN_CYCLE=2          # a long-poll that returns faster than this is not really long-polling
delay=0
backoff() {          # $1 = reason. Doubles 5s -> BACKOFF_MAX, logging once per failure.
    if [ "$delay" -eq 0 ]; then delay=5; else delay=$((delay * 2)); fi
    [ "$delay" -gt "$BACKOFF_MAX" ] && delay="$BACKOFF_MAX"
    echo "[sift-agentd] $1; retrying in ${delay}s" >&2
    sleep "$delay"
}

[ "${SIFT_AGENT_LIB:-}" = 1 ] && return 0 2>/dev/null   # sourced by tests: functions only

echo "[sift-agentd] v$SIFT_AGENT_VERSION $HOST polling $SERVER (read-only exec daemon)" >&2
while true; do
    started=$SECONDS
    heartbeat
    # long-poll (server holds up to 25s); -m 35 leaves headroom. text fmt = tab-separated lines.
    # -w appends the status on its own line: curl exits 0 on a 401/403/404/5xx, so test it explicitly.
    resp="$(curl -s -m 35 -D "$WORK/poll.headers" -w '\n%{http_code}' "${AUTH[@]}" \
            "$SERVER/agent/commands?host=$HOST&fmt=text" 2>/dev/null)" || { backoff "server unreachable"; continue; }
    code="${resp##*$'\n'}"
    resp="${resp%$'\n'*}"
    case "$code" in
        2??) ;;
        *)   backoff "server returned HTTP $code"; continue ;;   # never parse an error body as commands
    esac
    # A 200 without the X-Sift marker is a login/captive page or a proxy, not Sift.
    if ! grep -qi '^x-sift: *1' "$WORK/poll.headers" 2>/dev/null; then
        backoff "response is not from Sift (no X-Sift header)"; continue
    fi
    if [ "$delay" -ne 0 ]; then echo "[sift-agentd] server reachable again" >&2; delay=0; fi
    ran=0
    while IFS=$'\t' read -r id cmd argstr; do
        [[ "$id" =~ ^[0-9]+$ ]] || continue   # real commands have a numeric id; skips blanks and stray HTML
        ran=1
        container=""; unit=""; disk=""; lines=""; action=""
        for kv in $argstr; do
            case "${kv%%=*}" in
                container) container="${kv#*=}" ;;
                unit)      unit="${kv#*=}" ;;
                disk)      disk="${kv#*=}" ;;
                lines)     lines="${kv#*=}" ;;
                action)    action="${kv#*=}" ;;
            esac
        done
        # reserved CONTROL channel (admin-only on the server) — NOT part of the read-only allowlist
        if [ "$cmd" = "__control__" ]; then
            if [ "$action" = "uninstall" ]; then
                post_result "$id" "uninstalling the Sift agent on $HOST…" 0
                uninstall
                exit 0
            fi
            post_result "$id" "unknown control action: $action" 2
            continue
        fi
        REASON=""; ARGV=()
        if ! build_argv "$cmd"; then
            post_result "$id" "refused: ${REASON:-not allowed}" 2
            continue
        fi
        out="$(timeout "$TIMEOUT" "${ARGV[@]}" 2>&1)"; rc=$?
        [ "$rc" = 124 ] && out="${out}
(timed out after ${TIMEOUT}s)"
        post_result "$id" "$out" "$rc"
    done <<< "$resp"
    # nothing to do and the server answered instantly: pause so a 200 can't become a tight loop either
    [ "$ran" -eq 0 ] && [ $((SECONDS - started)) -lt "$MIN_CYCLE" ] && sleep "$MIN_CYCLE"
done
