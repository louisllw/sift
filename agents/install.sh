#!/bin/bash
# Sift agent installer — served by the Sift server at /agent/install.sh.
# Sets up, on the host you run it on, either/both of:
#   * the exec DAEMON (sift-agentd, systemd) — runs read-only allowlisted diagnostics on demand
#   * the metrics COLLECTOR (sift-agent, cron */5) — pushes disk/ZFS/SMART/container health + error logs
#
# Run ON the target host, as root (needs systemd + cron):
#   curl -fsSL <SIFT_SERVER>/agent/install.sh \
#     | sudo SIFT_SERVER=<url> SIFT_TOKEN=<token> SIFT_HOST=<name> bash
#
# Env:
#   SIFT_SERVER   (required) e.g. http://sift.lan:8130 (LAN) or https://sift.example.com (remote)
#   SIFT_TOKEN    (required) the server's ingest_token
#   SIFT_HOST     label for this host (default: hostname)
#   SIFT_COMPONENTS  both | daemon | collector   (default: both)
#   SIFT_NO_METRICS=1  collector heartbeat+logs only, skip disk/ZFS/SMART (for a host whose
#                      own scripts already own those checks). Daemon is unaffected.
#   SIFT_DIR      install dir (default: /opt/sift-agent)
set -eu
: "${SIFT_SERVER:?set SIFT_SERVER=http://your-sift:8130}"
: "${SIFT_TOKEN:?set SIFT_TOKEN=<ingest_token>}"
HOST="${SIFT_HOST:-$(hostname)}"
DIR="${SIFT_DIR:-/opt/sift-agent}"
COMP="${SIFT_COMPONENTS:-both}"
SERVER="${SIFT_SERVER%/}"
[ "$(id -u)" = 0 ] || { echo "run me as root (sudo) — I install a systemd service + cron" >&2; exit 1; }

mkdir -p "$DIR"
umask 077
{
  echo "SIFT_SERVER=$SERVER"
  echo "SIFT_TOKEN=$SIFT_TOKEN"
  echo "SIFT_HOST=$HOST"
  [ -n "${SIFT_NO_METRICS:-}" ] && echo "SIFT_NO_METRICS=1"
} > "$DIR/agent.env"
chmod 600 "$DIR/agent.env"

fetch() { curl -fsSL "$SERVER/agent/$1" -o "$DIR/$1" && chmod +x "$DIR/$1"; }

if [ "$COMP" = both ] || [ "$COMP" = daemon ]; then
  fetch sift-agentd.sh
  cat > /etc/systemd/system/sift-agentd.service <<UNIT
[Unit]
Description=Sift exec daemon (read-only diagnostics)
After=network-online.target docker.service
Wants=network-online.target
[Service]
Type=simple
User=root
EnvironmentFile=$DIR/agent.env
ExecStart=$DIR/sift-agentd.sh
Restart=always
RestartSec=5
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now sift-agentd >/dev/null 2>&1 || systemctl enable --now sift-agentd
  echo "[sift] exec daemon installed + started  ($(systemctl is-active sift-agentd))"
fi

if [ "$COMP" = both ] || [ "$COMP" = collector ]; then
  fetch sift-agent.sh
  ( crontab -l 2>/dev/null | grep -v 'sift-agent.sh'; echo "*/5 * * * * $DIR/sift-agent.sh" ) | crontab -
  "$DIR/sift-agent.sh" >/dev/null 2>&1 || true   # first heartbeat now so the host appears immediately
  echo "[sift] metrics collector installed (cron */5)"
fi

echo "[sift] done — host '$HOST' now reports to $SERVER"
