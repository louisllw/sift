#!/bin/bash
# sift-agentd — the Sift exec daemon.
#
# Long-polls the Sift server for READ-ONLY, allowlisted diagnostic commands, runs each one
# with NO shell (argv array only — so ; | $() `` redirects can't be injected), and POSTs the
# output back. Companion to sift-agent.sh (the cron collector); same agent.env / env vars.
#
# Security model (why this is safe to run, even as root):
#   * The server can only ever queue a KEY from a fixed menu (+ typed, validated args).
#   * This daemon re-validates every arg and maps the key to a hard-coded argv array.
#     An unknown key or a malformed arg is refused — it is NEVER passed to a shell.
#   * Nothing here writes, installs, restarts or deletes. Read-only diagnostics only.
#
# Run as a persistent systemd service (Restart=always). Zero deps: bash + curl.
#   SIFT_SERVER   e.g. http://sift.lan:8130 (LAN) or https://sift.example.com (via your proxy)
#   SIFT_TOKEN    the server's ingest_token
#   SIFT_HOST     label for this host (default: hostname) — must match the collector's label
#   SIFT_EXEC_TIMEOUT  per-command wall-clock cap (default 20s).  SIFT_EXEC_OUTMAX bytes (default 8000).
set -u
HERE="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
[ -f "$HERE/agent.env" ] && . "$HERE/agent.env"
SERVER="${SIFT_SERVER:-http://localhost:8130}"
TOKEN="${SIFT_TOKEN:-}"
HOST="${SIFT_HOST:-$(hostname)}"
TIMEOUT="${SIFT_EXEC_TIMEOUT:-20}"
OUT_MAX="${SIFT_EXEC_OUTMAX:-8000}"
AUTH=(-H "Authorization: Bearer $TOKEN")

is_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]; }
is_disk() { [[ "$1" =~ ^[a-z0-9]{1,16}$ ]]; }
is_int()  { [[ "$1" =~ ^[0-9]{1,4}$ ]]; }

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
                     ARGV=(smartctl -H "/dev/$disk") ;;
        journal)     is_name "$unit" || { REASON="bad unit"; return 1; }
                     ARGV=(journalctl -u "$unit" -n "$lines" --no-pager) ;;
        failed)      ARGV=(systemctl --failed --no-pager) ;;
        procs)       ARGV=(ps -eo pid,pcpu,pmem,comm --sort=-pcpu) ;;
        net)         ARGV=(ss -tulpn) ;;
        uname)       ARGV=(uname -a) ;;
        *)           REASON="unknown command '$cmd'"; return 1 ;;
    esac
}

post_result() {   # id  output  rc   — id/rc in headers, raw output as the body (no JSON encoding needed)
    curl -s -m 10 "${AUTH[@]}" -H "X-Cmd-Id: $1" -H "X-Cmd-Rc: $3" \
         --data-binary "${2:0:$OUT_MAX}" "$SERVER/agent/command-result" >/dev/null 2>&1
}

echo "[sift-agentd] $HOST polling $SERVER (read-only exec daemon)" >&2
while true; do
    # heartbeat so the server/UI knows this host + its exec daemon are alive
    curl -s -m 10 "${AUTH[@]}" -X POST --data "{\"host\":\"$HOST\"}" "$SERVER/agent/heartbeat" >/dev/null 2>&1
    # long-poll (server holds up to 25s); -m 35 leaves headroom. text fmt = tab-separated lines.
    resp="$(curl -s -m 35 "${AUTH[@]}" "$SERVER/agent/commands?host=$HOST&fmt=text" 2>/dev/null)" || { sleep 5; continue; }
    [ -z "$resp" ] && continue
    while IFS=$'\t' read -r id cmd argstr; do
        [ -z "$id" ] && continue
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
                RMDIR=""; case "$HERE" in /opt/sift-agent*) RMDIR="$HERE" ;; esac   # only remove a dedicated install dir
                cat > /tmp/sift-uninstall.sh <<TEARDOWN
#!/bin/bash
sleep 1
systemctl disable --now sift-agentd >/dev/null 2>&1 || true
rm -f /etc/systemd/system/sift-agentd.service
systemctl daemon-reload >/dev/null 2>&1 || true
( crontab -l 2>/dev/null | grep -vF "$HERE/sift-agent.sh" ) | crontab - 2>/dev/null || true
[ -n "$RMDIR" ] && rm -rf "$RMDIR"
rm -f /tmp/sift-uninstall.sh
TEARDOWN
                chmod +x /tmp/sift-uninstall.sh
                # run teardown as a SEPARATE transient unit so stopping sift-agentd can't kill it
                if ! systemd-run --no-block --collect --unit=sift-uninstall /tmp/sift-uninstall.sh >/dev/null 2>&1; then
                    setsid /tmp/sift-uninstall.sh </dev/null >/dev/null 2>&1 &
                fi
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
done
