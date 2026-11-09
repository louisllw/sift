#!/bin/bash
# Sift agent installer — served by the Sift server at /agent/install.sh.
SIFT_AGENT_VERSION="2026.11.09.2"
# Sets up, on the host you run it on, either/both of:
#   * the exec DAEMON (sift-agentd, systemd) — runs read-only allowlisted diagnostics on demand
#   * the COLLECTOR (sift-agent, systemd timer every 5 min; cron if there's no systemd) —
#     pushes disk/ZFS/SMART/container health + error logs
#
# Run ON the target host, as root. The same command INSTALLS or UPGRADES (idempotent):
#   curl -fsSL <SIFT_SERVER>/agent/install.sh \
#     | sudo SIFT_SERVER=<url> SIFT_TOKEN=<token> SIFT_HOST=<name> bash
# On an existing host, a bare `curl -fsSL <SIFT_SERVER>/agent/install.sh | sudo bash`
# upgrades in place and keeps the current server/token/host and any extra settings.
#
# Env:
#   SIFT_SERVER   e.g. http://sift.lan:8130 (LAN) or https://sift.example.com (remote).
#                 Plain http:// is refused for public addresses unless SIFT_ALLOW_HTTP=1.
#   SIFT_TOKEN    this host's agent token. Or SIFT_TOKEN_FILE=<path>, or you're prompted
#                 on the terminal; on upgrade the existing token is kept.
#   SIFT_HOST     label for this host (default: hostname; letters, digits, . _ - only)
#   SIFT_COMPONENTS  both | daemon | collector   (default: both)
#   SIFT_NO_METRICS=1  collector does heartbeat+logs only, skips disk/ZFS/SMART
#   SIFT_DIR      install dir (default: /opt/sift-agent)
# Other keys already in agent.env (SIFT_LOG_IGNORE, SIFT_NO_SMART, …) are preserved.

# Everything runs inside main(), called on the LAST line: a truncated download can't run half.
main() {
    set -eu
    umask 077
    [ "$(id -u)" = 0 ] || { echo "run me as root (sudo) — I install systemd units" >&2; exit 1; }

    local DIR="${SIFT_DIR:-/opt/sift-agent}"
    local COMP="${SIFT_COMPONENTS:-both}"
    case "$COMP" in both|daemon|collector) ;; *) echo "SIFT_COMPONENTS must be both|daemon|collector" >&2; exit 1 ;; esac
    local ENVF="$DIR/agent.env"

    # existing settings (upgrade path)
    local OLD_SERVER="" OLD_TOKEN="" OLD_HOST=""
    if [ -f "$ENVF" ]; then
        OLD_SERVER="$(env_get "$ENVF" SIFT_SERVER)"
        OLD_TOKEN="$(env_get "$ENVF" SIFT_TOKEN)"
        OLD_HOST="$(env_get "$ENVF" SIFT_HOST)"
    fi

    local SERVER="${SIFT_SERVER:-$OLD_SERVER}"
    SERVER="${SERVER%/}"
    [ -n "$SERVER" ] || { echo "set SIFT_SERVER=https://your-sift (no existing install to upgrade)" >&2; exit 1; }
    local url_re='^https?://[][A-Za-z0-9.:_/@-]+$'
    [[ "$SERVER" =~ $url_re ]] || { echo "SIFT_SERVER looks wrong: $SERVER" >&2; exit 1; }
    if [[ "$SERVER" == http://* ]] && ! is_lan_url "$SERVER" && [ -z "${SIFT_ALLOW_HTTP:-}" ]; then
        echo "refusing plain http:// to a public address ($SERVER) — the token and agent code would" >&2
        echo "travel unencrypted. Use https://, or set SIFT_ALLOW_HTTP=1 if you really mean it." >&2
        exit 1
    fi

    local TOKEN="${SIFT_TOKEN:-}"
    if [ -z "$TOKEN" ] && [ -n "${SIFT_TOKEN_FILE:-}" ]; then
        TOKEN="$(tr -d ' \r\n' < "$SIFT_TOKEN_FILE")"
    fi
    if [ -z "$TOKEN" ] && [ -n "$OLD_TOKEN" ]; then TOKEN="$OLD_TOKEN"; fi
    if [ -z "$TOKEN" ] && [ -r /dev/tty ]; then
        read -rsp "Sift agent token: " TOKEN < /dev/tty || true; echo >&2
    fi
    [ -n "$TOKEN" ] || { echo "no token: set SIFT_TOKEN or SIFT_TOKEN_FILE" >&2; exit 1; }
    [[ "$TOKEN" =~ ^[A-Za-z0-9._~+/=-]+$ ]] || { echo "token has unexpected characters" >&2; exit 1; }

    local HOST="${SIFT_HOST:-${OLD_HOST:-$(hostname)}}"
    [[ "$HOST" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || { echo "SIFT_HOST '$HOST' invalid (letters, digits, . _ - only)" >&2; exit 1; }

    mkdir -p "$DIR"; chmod 755 "$DIR"

    # ---- merge agent.env: keep every other key, replace only these three (+ NO_METRICS if given)
    local tmpenv; tmpenv="$(mktemp "$DIR/.agent.env.XXXXXX")"
    if [ -f "$ENVF" ]; then
        grep -vE '^(SIFT_SERVER|SIFT_TOKEN|SIFT_HOST)=' "$ENVF" > "$tmpenv" || true
        if [ -n "${SIFT_NO_METRICS:-}" ]; then
            grep -v '^SIFT_NO_METRICS=' "$tmpenv" > "$tmpenv.2" || true
            mv -f "$tmpenv.2" "$tmpenv"
        fi
    fi
    {
        echo "SIFT_SERVER=$SERVER"
        echo "SIFT_TOKEN=$TOKEN"
        echo "SIFT_HOST=$HOST"
        if [ -n "${SIFT_NO_METRICS:-}" ]; then echo "SIFT_NO_METRICS=1"; fi
    } >> "$tmpenv"
    chmod 600 "$tmpenv"; mv -f "$tmpenv" "$ENVF"

    # ---- download everything first (to a temp dir), verify, THEN swap into place
    STAGE="$(mktemp -d)"                      # global: the EXIT trap runs after main returns
    trap 'rm -rf "${STAGE:-}"' EXIT
    local stage="$STAGE"
    local hdr="$stage/auth.hdr"
    printf 'Authorization: Bearer %s\n' "$TOKEN" > "$hdr"
    local files=()
    case "$COMP" in
        both)      files=(sift-agentd.sh sift-agentd.service sift-agent.sh sift-agent.service sift-agent.timer) ;;
        daemon)    files=(sift-agentd.sh sift-agentd.service) ;;
        collector) files=(sift-agent.sh sift-agent.service sift-agent.timer) ;;
    esac
    local f
    for f in "${files[@]}"; do
        curl -fsS -m 30 -H "@$hdr" "$SERVER/agent/$f" -o "$stage/$f" \
            || { echo "download failed: $SERVER/agent/$f" >&2; exit 1; }
        case "$f" in
            *.sh)
                bash -n "$stage/$f" || { echo "$f failed a syntax check — not installing" >&2; exit 1; }
                grep -q '^SIFT_AGENT_VERSION=' "$stage/$f" || { echo "$f doesn't look like a Sift agent script" >&2; exit 1; } ;;
            *.service|*.timer)
                grep -qE '^\[(Service|Timer)\]' "$stage/$f" || { echo "$f doesn't look like a systemd unit" >&2; exit 1; }
                sed -i "s#/opt/sift-agent#$DIR#g" "$stage/$f" ;;
        esac
    done

    local have_systemd=""
    [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 && have_systemd=1

    # ---- daemon
    if [ "$COMP" = both ] || [ "$COMP" = daemon ]; then
        if [ -z "$have_systemd" ]; then
            echo "the exec daemon needs systemd — skipping it" >&2
        else
            install -m 755 "$stage/sift-agentd.sh" "$DIR/sift-agentd.sh.new" && mv -f "$DIR/sift-agentd.sh.new" "$DIR/sift-agentd.sh"
            install -m 644 "$stage/sift-agentd.service" /etc/systemd/system/sift-agentd.service
            systemctl daemon-reload
            systemctl enable sift-agentd >/dev/null 2>&1
            systemctl restart sift-agentd          # restart (not just start) so upgrades take effect
            echo "[sift] exec daemon v$SIFT_AGENT_VERSION running  ($(systemctl is-active sift-agentd))"
        fi
    fi

    # ---- collector
    if [ "$COMP" = both ] || [ "$COMP" = collector ]; then
        install -m 755 "$stage/sift-agent.sh" "$DIR/sift-agent.sh.new" && mv -f "$DIR/sift-agent.sh.new" "$DIR/sift-agent.sh"
        if [ -n "$have_systemd" ]; then
            install -m 644 "$stage/sift-agent.service" /etc/systemd/system/sift-agent.service
            install -m 644 "$stage/sift-agent.timer" /etc/systemd/system/sift-agent.timer
            systemctl daemon-reload
            remove_cron_lines                      # an older install ran it from cron: don't run twice
            systemctl enable --now sift-agent.timer >/dev/null 2>&1
            systemctl start --no-block sift-agent.service   # first run now, so the host shows up
            echo "[sift] collector v$SIFT_AGENT_VERSION scheduled (systemd timer, every 5 min)"
        else
            remove_cron_lines
            ( crontab -l 2>/dev/null; echo "*/5 * * * * $DIR/sift-agent.sh" ) | crontab -
            "$DIR/sift-agent.sh" >/dev/null 2>&1 || true
            echo "[sift] collector v$SIFT_AGENT_VERSION scheduled (cron */5 — no systemd here)"
        fi
    fi

    echo "[sift] done — host '$HOST' reports to $SERVER"
}

# KEY=VALUE from an env file, without sourcing it
env_get() { grep -E "^$2=" "$1" 2>/dev/null | tail -n1 | cut -d= -f2- | sed -E 's/^"(.*)"$/\1/'; }

# true for loopback, RFC1918, .local/.lan/.internal/.home.arpa and single-label names
is_lan_url() {
    local h="${1#*://}"; h="${h%%/*}"; h="${h##*@}"
    case "$h" in \[*) h="${h%%]*}"; h="${h#[}" ;; *) h="${h%%:*}" ;; esac
    if [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then   # numeric ranges only for real IPv4 literals
        case "$h" in                                           # ("10.evil.com" must not count as LAN)
            127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
            *) return 1 ;;
        esac
    fi
    case "$h" in
        localhost|::1|*.local|*.lan|*.internal|*.home.arpa) return 0 ;;
        *.*) return 1 ;;
        *) return 0 ;;   # single-label name (e.g. a docker service name like "sift")
    esac
}

# drop any crontab line running sift-agent.sh — root's, and the sudo-invoking user's
remove_cron_lines() {
    local u
    for u in root ${SUDO_USER:-}; do
        if crontab -u "$u" -l 2>/dev/null | grep -q 'sift-agent\.sh'; then
            crontab -u "$u" -l 2>/dev/null | grep -v 'sift-agent\.sh' | crontab -u "$u" - \
                && echo "[sift] removed old cron line(s) for $u"
        fi
    done
}

[ "${SIFT_INSTALL_LIB:-}" = 1 ] || main "$@"
