#!/bin/bash
# sift-agent — the Sift helper for any host. Dumb by design: it collects and POSTs,
# all triage/AI/alerting lives in the Sift server. Zero dependencies (bash + curl).
#
#   What it does each run:
#     1. heartbeat  -> server knows this host is alive (dead-man's switch)
#     2. metrics    -> disk / ZFS / SMART / unhealthy containers  (state-change only)
#     3. logs       -> forwards NEW error-level journald lines for the server's AI to triage
#                      (capped, and skipped if identical to the previous batch = no firehose)
#
# Run via cron (e.g. */5 * * * *) or a systemd timer. Config via env:
#   SIFT_SERVER   e.g. http://sift.lan:8130 (LAN) or https://sift.example.com (remote, via your existing proxy)
#   SIFT_TOKEN    the server's ingest_token
#   SIFT_HOST     label for this host (default: hostname)
#   SIFT_LOG_PRIORITY  journald priority floor (default: err).  SIFT_LOG_MAX lines per run (default 15).
#   SIFT_NO_LOGS=1 to disable log forwarding;  SIFT_NO_SMART=1 to skip SMART.
set -u
HERE="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
[ -f "$HERE/agent.env" ] && . "$HERE/agent.env"   # optional: SIFT_SERVER/SIFT_TOKEN/SIFT_HOST live here (chmod 600)
SERVER="${SIFT_SERVER:-http://localhost:8130}"
TOKEN="${SIFT_TOKEN:-}"
HOST="${SIFT_HOST:-$(hostname)}"
STATE="${SIFT_STATE:-/var/tmp/sift-agent}"
LOG_PRIORITY="${SIFT_LOG_PRIORITY:-err}"
LOG_MAX="${SIFT_LOG_MAX:-15}"
LOG_IGNORE="${SIFT_LOG_IGNORE:-}"     # per-host extra noise to drop (regex, case-insensitive)
# lines that commonly carry a scary word but aren't incidents; the server's AI does the real judging
LOG_BENIGN='level=(info|debug)|[0-9]Z? +(INFO|DEBUG|TRACE) |(^| )0 errors?( |$)|no errors?\b|error[_-]log|errorlevel=0|warn(ing)?s?=0|kex_exchange_identification'
NOISE="$LOG_BENIGN"; [ -n "$LOG_IGNORE" ] && NOISE="$LOG_BENIGN|$LOG_IGNORE"
mkdir -p "$STATE"

AUTH=(-H "Authorization: Bearer $TOKEN")
post() { curl -s -m 10 "${AUTH[@]}" -H "Title: $1" --data "$2" "$SERVER/$3" >/dev/null; }

# 1) heartbeat
curl -s -m 10 "${AUTH[@]}" -X POST --data "{\"host\":\"$HOST\"}" "$SERVER/agent/heartbeat" >/dev/null

# 2) metrics (report only on healthy<->problem transition). SIFT_NO_METRICS=1 skips this
# (e.g. on a host where another agent already owns disk/ZFS/SMART/backup checks).
problems=""
if [ -n "${SIFT_NO_METRICS:-}" ]; then problems=""; else
if command -v zpool >/dev/null 2>&1; then
  zx="$(zpool status -x 2>/dev/null)"
  [ -n "$zx" ] && [ "$zx" != "all pools are healthy" ] && problems+="ZFS:\n$(zpool status 2>/dev/null | head -30)\n\n"
fi
while read -r pcent target; do
  n="${pcent%\%}"
  [ -n "$n" ] && [ "$n" -ge 90 ] 2>/dev/null && problems+="Disk ${target} at ${pcent}\n"
done < <(df -h --output=pcent,target -x tmpfs -x devtmpfs -x overlay -x squashfs -x iso9660 2>/dev/null | tail -n +2 | grep -vE '/snap(/|$)')
if [ -z "${SIFT_NO_SMART:-}" ] && command -v smartctl >/dev/null 2>&1; then
  for d in $(lsblk -dno NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}'); do
    h="$(sudo -n smartctl -H "/dev/$d" 2>/dev/null | grep -iE 'overall-health|SMART Health')"
    [ -n "$h" ] && ! echo "$h" | grep -qiE 'PASSED|OK' && problems+="SMART /dev/$d: $h\n"
  done
fi
if command -v docker >/dev/null 2>&1; then
  bad="$(docker ps --filter health=unhealthy --filter status=restarting --format '{{.Names}} ({{.Status}})' 2>/dev/null)"
  [ -n "$bad" ] && problems+="Containers unhealthy:\n$bad\n"
fi
prev="$(cat "$STATE/metrics" 2>/dev/null)"
if [ -n "$problems" ]; then
  [ "$prev" != "PROBLEM" ] && post "$HOST health" "$(echo -e "$problems")" "host-$HOST"
  echo PROBLEM > "$STATE/metrics"
else
  [ "$prev" = "PROBLEM" ] && post "$HOST health" "Recovered — $HOST healthy." "host-$HOST"
  echo OK > "$STATE/metrics"
fi
fi  # end SIFT_NO_METRICS gate

# 3) forward NEW error-level logs for AI triage (skip if identical to last batch)
# Log source: journald on a host, else docker container logs (socket) in a container.
if [ -z "${SIFT_NO_LOGS:-}" ]; then
  lines=""
  # Host/systemd errors from journald...
  if command -v journalctl >/dev/null 2>&1; then
    since="$(cat "$STATE/log-ts" 2>/dev/null || echo '5 minutes ago')"
    date '+%Y-%m-%d %H:%M:%S' > "$STATE/log-ts"
    lines="$(journalctl --since "$since" -p "$LOG_PRIORITY" -q --no-pager -o short-iso 2>/dev/null | grep -v 'sift-agent' | grep -ivE "$NOISE")"
  fi
  # ...AND container app errors from docker (default json-file driver isn't in journald).
  if [ -z "${SIFT_NO_DOCKER_LOGS:-}" ] && command -v docker >/dev/null 2>&1; then
    win="${SIFT_DOCKER_SINCE:-5m}"
    for cnt in $(docker ps --format '{{.Names}}' 2>/dev/null); do
      cl="$(docker logs --since "$win" "$cnt" 2>&1 | grep -iE 'error|fatal|panic|exception|traceback|segfault|critical|\bfail(ed|ure)?\b' | grep -v 'sift-agent' | grep -ivE "$NOISE")"
      [ -n "$cl" ] && lines="${lines}$(printf '%s\n' "$cl" | sed "s/^/[$cnt] /")"$'\n'
    done
  fi
  if [ -n "$lines" ]; then
    count="$(printf '%s\n' "$lines" | wc -l | tr -d ' ')"
    body="$(printf '%s\n' "$lines" | head -n "$LOG_MAX")"
    [ "$count" -gt "$LOG_MAX" ] && body="$body"$'\n'"…and $((count-LOG_MAX)) more"
    newhash="$(printf '%s' "$body" | cksum)"
    if [ "$newhash" != "$(cat "$STATE/log-hash" 2>/dev/null)" ]; then   # don't resend an identical batch
      post "$HOST: $count error log line(s)" "$body" "logs-$HOST"
      echo "$newhash" > "$STATE/log-hash"
    fi
  fi
fi
