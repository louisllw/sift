#!/bin/bash
# sift-agent — the Sift collector for any host. Dumb by design: it collects and POSTs,
# all triage/AI/alerting lives in the Sift server. Zero dependencies (bash + curl).
SIFT_AGENT_VERSION="2026.11.09.2"
#
#   Each run:
#     1. heartbeat  -> server knows this host is alive (dead-man's switch)
#     2. metrics    -> disk/inodes, ZFS, SMART, broken containers. Posted whenever the SET of
#                      problems changes (new problem, problem cleared, all clear).
#     3. logs       -> NEW error lines from journald + docker since the last run, for the
#                      server's AI to triage (collapsed, capped, de-duplicated with a 1h TTL).
#   Nothing is lost when the server is down: undelivered posts are spooled to disk and
#   replayed on the next run, and the log cursors only advance once a batch is delivered
#   or safely spooled.
#
# Run via the systemd timer install.sh sets up (or cron / a container loop). Config via env
# or a sibling agent.env (chmod 600):
#   SIFT_SERVER   e.g. http://sift.lan:8130 (LAN) or https://sift.example.com (remote)
#   SIFT_TOKEN    this host's agent token (or the server's ingest token on older servers)
#   SIFT_HOST     label for this host (default: hostname; letters, digits, . _ - only)
#   SIFT_LOG_PRIORITY  journald priority floor (default: err).  SIFT_LOG_MAX lines/source (default 15).
#   SIFT_LOG_IGNORE    extra per-host noise to drop (regex, case-insensitive)
#   SIFT_IGNORE_CONTAINERS  regex of container names to leave out of health + log checks
#   SIFT_NO_LOGS=1 / SIFT_NO_DOCKER_LOGS=1 / SIFT_NO_METRICS=1 / SIFT_NO_SMART=1 to disable parts.
set -u

# ---------------------------------------------------------------- filters (pure, testable)
# Lines that are ALWAYS forwarded, even if they look benign (Stalwart logs some real auth /
# delivery failures at INFO level). Case-insensitive.
KEEP_RE='auth\.failed|auth\.error|queue\.failed|delivery\.failed|security\.'
# Lines that carry a scary word but are not incidents. Case-SENSITIVE and anchored, so a
# real error that merely mentions "info" somewhere is never swallowed.
BENIGN_RE='(^|[[:space:]])level=(info|debug|trace)([[:space:]]|$)'
BENIGN_RE+='|^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9:.]+(Z|[+-][0-9:]+)?[[:space:]]+(INFO|DEBUG|TRACE)[[:space:]]'
BENIGN_RE+='|kex_exchange_identification'
BENIGN_RE+='|"level":"(info|debug)"'
BENIGN_RE+='|(^|[^0-9])0 [Ee]rrors?([^A-Za-z]|$)|errorlevel=0|warn(ing)?s?=0'
# What counts as an error line in a container's log (grep -iE; no \b so busybox grep works too).
DOCKER_ERR_RE='error|fatal|panic|exception|traceback|segfault|critical|(^|[^a-z])fail(ed|ure|s)?([^a-z]|$)'
DOCKER_ERR_RE+='|connection refused|permission denied|cannot allocate|out of memory|(^|[^a-z])oom([^a-z]|$)|oom.?kill'
DOCKER_ERR_RE+='|(^|[^a-z])killed([^a-z]|$)|timed out|deadline exceeded|\[(emerg|alert|crit)\]|^E[0-9]{4} '

# stdin -> stdout: keep lines worth forwarding, preserving order.
filter_lines() {
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "${line//[[:space:]]/}" ] && continue
        case "$line" in *sift-agent*) continue ;; esac            # never forward our own noise
        shopt -s nocasematch
        if [ -n "${LOG_IGNORE:-}" ] && [[ $line =~ $LOG_IGNORE ]]; then shopt -u nocasematch; continue; fi
        if [[ $line =~ $KEEP_RE ]]; then shopt -u nocasematch; printf '%s\n' "$line"; continue; fi
        shopt -u nocasematch
        [[ $line =~ $BENIGN_RE ]] && continue
        printf '%s\n' "$line"
    done
}

# stdin -> stdout: collapse lines that differ only in numbers (timestamps, pids, ports) into
# the first occurrence + "(xN)", in first-seen order.
collapse_lines() {
    awk '{ k=$0; gsub(/[0-9]+/, "#", k)
           if (!(k in c)) { order[++n]=k; first[k]=$0 }
           c[k]++ }
         END { for (i=1; i<=n; i++) { k=order[i]
                 if (c[k] > 1) printf "%s  (x%d)\n", first[k], c[k]; else print first[k] } }'
}

# stdout: a stable hash of stdin with numbers normalised away (for "same batch as last time?")
norm_hash() { sed -E 's/[0-9]+/#/g' | cksum | awk '{print $1"-"$2}'; }

# Problem keys -> stable fingerprint (order-independent).
keys_hash() { printf '%s\n' "$@" | LC_ALL=C sort -u | cksum | awk '{print $1"-"$2}'; }

valid_host() { [[ "$1" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; }

heartbeat_json() {   # host component version (all validated -> no escaping needed)
    printf '{"host":"%s","component":"%s","version":"%s"}' "$1" "$2" "$3"
}

# ---------------------------------------------------------------- transport
# The token goes in a 0600 header file, never in curl's argv (visible in `ps`).
setup_auth() {
    HDR="$STATE/auth.hdr"
    local want; want="Authorization: Bearer $TOKEN"
    if [ "$(cat "$HDR" 2>/dev/null)" != "$want" ]; then
        ( umask 077; printf '%s\n' "$want" > "$HDR.tmp" && mv -f "$HDR.tmp" "$HDR" )
    fi
    local v; v="$(curl --version 2>/dev/null | awk 'NR==1{print $2}')"
    local maj="${v%%.*}" rest="${v#*.}"; local min="${rest%%.*}"
    if [ "${maj:-0}" -gt 7 ] 2>/dev/null || { [ "${maj:-0}" -eq 7 ] && [ "${min:-0}" -ge 55 ]; } 2>/dev/null; then
        AUTH=(-H "@$HDR")
    else
        AUTH=(-H "$want")       # very old curl: no @file support
    fi
}

SERVER_OK=1   # cleared if the heartbeat shows the server isn't really Sift (captive page / proxy error)

# send TOPIC TITLE BODY -> 0 only on a 2xx from the server
send() {
    [ "$SERVER_OK" = 1 ] || return 1
    local title code
    title="$(printf '%s' "$2" | tr -d '\r\n' | cut -c1-200)"
    code="$(printf '%s' "$3" | curl -sS -m 15 -o /dev/null -w '%{http_code}' "${AUTH[@]}" \
            -H "Title: $title" --data-binary @- "$SERVER/$1" 2>/dev/null)" || return 1
    case "$code" in 2??) return 0 ;; esac
    return 1
}

SPOOL_MAX=50
spool() {   # TOPIC TITLE BODY -> file; returns 0 if safely written
    local f
    f="$STATE/spool/$(date +%s)-$$-$RANDOM"
    { printf '%s\n%s\n' "$1" "$(printf '%s' "$2" | tr -d '\r\n')"; printf '%s' "$3"; } > "$f.tmp" 2>/dev/null \
        && mv -f "$f.tmp" "$f" || { rm -f "$f.tmp"; return 1; }
    # cap: drop the oldest beyond SPOOL_MAX
    local n; n="$(ls -1 "$STATE/spool" 2>/dev/null | grep -vc '\.tmp$')"
    if [ "$n" -gt "$SPOOL_MAX" ]; then
        ls -1 "$STATE/spool" | grep -v '\.tmp$' | LC_ALL=C sort | head -n "$((n - SPOOL_MAX))" \
            | while read -r old; do rm -f "$STATE/spool/$old"; done
    fi
    return 0
}

# deliver now, or keep it for the next run. 0 = delivered or safely spooled.
post() { send "$1" "$2" "$3" && return 0; spool "$1" "$2" "$3"; }

replay_spool() {
    [ "$SERVER_OK" = 1 ] || return 0
    local f topic title body
    for f in $(ls -1 "$STATE/spool" 2>/dev/null | grep -v '\.tmp$' | LC_ALL=C sort); do
        f="$STATE/spool/$f"
        { IFS= read -r topic; IFS= read -r title; body="$(cat)"; } < "$f"
        if send "$topic" "$title (delayed)" "$body"; then rm -f "$f"; else break; fi
    done
}

heartbeat() {
    local hdrs code
    hdrs="$STATE/hb.headers"
    code="$(heartbeat_json "$HOST" collector "$SIFT_AGENT_VERSION" | curl -sS -m 10 -o /dev/null -D "$hdrs" \
            -w '%{http_code}' "${AUTH[@]}" -H 'Content-Type: application/json' --data-binary @- \
            "$SERVER/agent/heartbeat" 2>/dev/null)" || code=000
    # A 2xx without the X-Sift marker is a login/captive page or a proxy, not Sift: don't
    # "deliver" anything into it this run — spool instead.
    case "$code" in
        2??) grep -qi '^x-sift: *1' "$hdrs" 2>/dev/null || SERVER_OK=0 ;;
        *)   SERVER_OK=0 ;;
    esac
    rm -f "$hdrs"
}

# ---------------------------------------------------------------- metrics
PKEYS=()   # stable keys, one per problem (used for change detection)
PTEXT=""   # human detail
problem() { PKEYS+=("$1"); PTEXT+="$2"$'\n'; }

check_zfs() {
    command -v zpool >/dev/null 2>&1 || return 0
    local zx
    zx="$(timeout 20 zpool status -x 2>&1)"
    case "$zx" in
        ""|"all pools are healthy"|"no pools available") return 0 ;;
    esac
    # key = pool + state lines only (scrub/resilver progress % would change every run)
    local key
    key="$(printf '%s\n' "$zx" | grep -E '^[[:space:]]*(pool|state):' | tr -s ' \t' ' ' | tr '\n' ';')"
    problem "zfs:${key:-unknown}" "ZFS:"$'\n'"$(timeout 20 zpool status 2>&1 | head -30)"
}

check_disks() {
    local pcent target n bucket
    while read -r pcent target; do
        n="${pcent%\%}"; [[ "$n" =~ ^[0-9]+$ ]] || continue
        [ "$n" -ge 90 ] || continue
        bucket=90; [ "$n" -ge 95 ] && bucket=95; [ "$n" -ge 98 ] && bucket=98
        problem "disk:$target:$bucket" "Disk $target at $pcent"
    done < <(timeout 10 df -l --output=pcent,target -x tmpfs -x devtmpfs -x overlay -x squashfs -x iso9660 2>/dev/null \
             | tail -n +2 | grep -vE '/snap(/|$)')
    while read -r pcent target; do
        n="${pcent%\%}"; [[ "$n" =~ ^[0-9]+$ ]] || continue
        [ "$n" -ge 90 ] && problem "inodes:$target" "Inodes on $target at $pcent used"
    done < <(timeout 10 df -l --output=ipcent,target -x tmpfs -x devtmpfs -x overlay -x squashfs -x iso9660 2>/dev/null \
             | tail -n +2 | grep -vE '/snap(/|$)')
}

check_smart() {
    [ -z "${SIFT_NO_SMART:-}" ] || return 0
    command -v smartctl >/dev/null 2>&1 || return 0
    local SUDO=()
    if [ "$(id -u)" != 0 ]; then
        command -v sudo >/dev/null 2>&1 || return 0
        SUDO=(sudo -n)
    fi
    local d out health attrs cache
    for d in $(lsblk -dno NAME,TYPE 2>/dev/null | awk '$2=="disk" && $1 !~ /^(zram|loop)/ {print $1}'); do
        cache="$STATE/smart-$d"
        # -n standby,0: don't spin up a sleeping disk just to ask; reuse its last result instead
        out="$(timeout 30 "${SUDO[@]}" smartctl -n standby,0 -H -A "/dev/$d" 2>/dev/null)"
        if printf '%s' "$out" | grep -qiE 'Unknown USB bridge|specify device type'; then
            out="$(timeout 30 "${SUDO[@]}" smartctl -d sat -n standby,0 -H -A "/dev/$d" 2>/dev/null)"
        fi
        if printf '%s' "$out" | grep -qi 'STANDBY'; then
            [ -s "$cache" ] && while IFS=$'\t' read -r k t; do problem "$k" "$t"; done < "$cache"
            continue
        fi
        : > "$cache.new"
        health="$(printf '%s\n' "$out" | grep -iE 'overall-health|SMART Health Status')"
        if [ -n "$health" ] && ! printf '%s' "$health" | grep -qiE 'PASSED|OK'; then
            problem "smart:$d:health" "SMART /dev/$d: $health"
            printf 'smart:%s:health\tSMART /dev/%s: %s\n' "$d" "$d" "$health" >> "$cache.new"
        fi
        # ATA attributes 5 (reallocated) + 197 (pending): RAW_VALUE is column 10
        attrs="$(printf '%s\n' "$out" | awk '($1=="5"||$1=="197") && $10+0>0 {print $1"="$10}' | tr '\n' ' ')"
        if [ -n "$attrs" ]; then
            problem "smart:$d:sectors:$attrs" "SMART /dev/$d bad sectors (5=reallocated, 197=pending): $attrs"
            printf 'smart:%s:sectors:%s\tSMART /dev/%s bad sectors (5=reallocated, 197=pending): %s\n' \
                "$d" "$attrs" "$d" "$attrs" >> "$cache.new"
        fi
        mv -f "$cache.new" "$cache"
    done
}

# parse "name<TAB>status" lines from `docker ps -a` into problems (pure, testable)
docker_problems() {
    local name status code
    while IFS=$'\t' read -r name status; do
        [ -n "$name" ] || continue
        if [ -n "${SIFT_IGNORE_CONTAINERS:-}" ] && [[ $name =~ $SIFT_IGNORE_CONTAINERS ]]; then continue; fi
        case "$status" in
            *"(unhealthy)"*) problem "ctr:$name:unhealthy" "Container $name unhealthy ($status)" ;;
            Restarting*)     problem "ctr:$name:restarting" "Container $name crash-looping ($status)" ;;
            Exited\ \(*)
                code="${status#Exited (}"; code="${code%%)*}"
                [ "$code" != 0 ] && problem "ctr:$name:exited:$code" "Container $name exited with code $code ($status)" ;;
        esac
    done
}

check_docker() {
    command -v docker >/dev/null 2>&1 || return 0
    local out
    if ! out="$(timeout 15 docker ps -a --format '{{.Names}}	{{.Status}}' 2>&1)"; then
        case "$out" in
            *"ermission denied"*) problem "docker:noperm" "Cannot read docker: permission denied (run the agent as root or in the docker group)" ;;
            *)                    problem "docker:down" "Docker daemon unreachable: $(printf '%s' "$out" | head -1)" ;;
        esac
        return 0
    fi
    docker_problems <<< "$out"
}

run_metrics() {
    [ -z "${SIFT_NO_METRICS:-}" ] || return 0
    PKEYS=(); PTEXT=""
    check_zfs; check_disks; check_smart; check_docker
    local now_hash prev_hash prev_keys cur_keys new cleared body title
    if [ "${#PKEYS[@]}" -gt 0 ]; then
        now_hash="$(keys_hash "${PKEYS[@]}")"
        cur_keys="$(printf '%s\n' "${PKEYS[@]}" | LC_ALL=C sort -u)"
    else
        now_hash="clear"; cur_keys=""
    fi
    prev_hash="$(cat "$STATE/metrics-hash" 2>/dev/null)"
    if [ -z "$prev_hash" ]; then                        # migrate from the old PROBLEM/OK state file
        case "$(cat "$STATE/metrics" 2>/dev/null)" in
            PROBLEM) prev_hash="legacy" ;;
            *)       prev_hash="clear" ;;
        esac
    fi
    [ "$now_hash" = "$prev_hash" ] && return 0
    prev_keys="$(cat "$STATE/metrics-keys" 2>/dev/null)"
    new="$(LC_ALL=C comm -13 <(printf '%s\n' "$prev_keys" | sed '/^$/d') <(printf '%s\n' "$cur_keys" | sed '/^$/d'))"
    cleared="$(LC_ALL=C comm -23 <(printf '%s\n' "$prev_keys" | sed '/^$/d') <(printf '%s\n' "$cur_keys" | sed '/^$/d'))"
    if [ "$now_hash" = "clear" ]; then
        title="$HOST health: all clear"
        body="All clear — $HOST is healthy again."
        [ -n "$cleared" ] && body+=$'\n'"Cleared: $(printf '%s' "$cleared" | tr '\n' ' ')"
    else
        title="$HOST health: ${#PKEYS[@]} problem(s)"
        body="Problems on $HOST now:"$'\n'"$PTEXT"
        [ -n "$new" ] && body+=$'\n'"New since last report: $(printf '%s' "$new" | tr '\n' ' ')"
        [ -n "$cleared" ] && body+=$'\n'"Cleared since last report: $(printf '%s' "$cleared" | tr '\n' ' ')"
    fi
    if post "host-$HOST" "$title" "$body"; then
        printf '%s\n' "$now_hash" > "$STATE/metrics-hash"
        printf '%s\n' "$cur_keys" > "$STATE/metrics-keys"
        rm -f "$STATE/metrics"
    fi
}

# ---------------------------------------------------------------- logs
LOG_TTL="${SIFT_LOG_TTL:-3600}"   # resend an identical batch after this long

collect_journal() {   # -> $JLINES, and $JCURSOR_TMP to commit on success
    JLINES=""; JCURSOR_TMP=""
    command -v journalctl >/dev/null 2>&1 || return 0
    local args=(-p "$LOG_PRIORITY" -q --no-pager -o short-iso)
    if journalctl --help 2>/dev/null | grep -q -- '--cursor-file'; then
        JCURSOR_TMP="$STATE/journal.cursor.tmp"
        rm -f "$JCURSOR_TMP"
        if [ -s "$STATE/journal.cursor" ]; then
            cp -f "$STATE/journal.cursor" "$JCURSOR_TMP"
            args+=(--cursor-file "$JCURSOR_TMP")
        else
            # First run: journalctl refuses --since together with --cursor-file (systemd 259+), and a
            # cursor file alone would replay the whole journal. So: note where the journal ends NOW,
            # read this window by time, and start the cursor from that point next run.
            local seed
            seed="$(journalctl -n 1 --show-cursor -q -o cat 2>/dev/null | sed -n 's/^-- cursor: //p' | tail -1)"
            [ -n "$seed" ] && printf '%s' "$seed" > "$JCURSOR_TMP"
            args+=(--since "@$LAST_EPOCH" --until "@$NOW_EPOCH")
        fi
    else
        args+=(--since "@$LAST_EPOCH" --until "@$NOW_EPOCH")   # older systemd: exact epoch window
    fi
    local jerr="$STATE/journal.err"
    JLINES="$(timeout 30 journalctl "${args[@]}" 2>"$jerr" | filter_lines | collapse_lines | tail -n "$LOG_MAX")"
    if [ -s "$jerr" ]; then     # never fail silently again: surface journalctl's own complaint once
        JLINES+=$'\n'"sift-agent: journalctl problem: $(head -c 300 "$jerr" | tr '\n' ' ')"
    fi
    rm -f "$jerr"
}

collect_docker_logs() {   # -> $DLINES
    DLINES=""
    [ -z "${SIFT_NO_DOCKER_LOGS:-}" ] || return 0
    command -v docker >/dev/null 2>&1 || return 0
    local cnt cl
    for cnt in $(timeout 15 docker ps --filter status=running --filter status=restarting --format '{{.Names}}' 2>/dev/null); do
        if [ -n "${SIFT_IGNORE_CONTAINERS:-}" ] && [[ $cnt =~ $SIFT_IGNORE_CONTAINERS ]]; then continue; fi
        # one shared window for every container: no gaps, no overlaps, no cron-jitter drift
        cl="$(timeout 20 docker logs --since "$LAST_EPOCH" --until "$NOW_EPOCH" "$cnt" 2>&1 \
              | grep -iE "$DOCKER_ERR_RE" | filter_lines | collapse_lines | tail -n "$LOG_MAX")"
        [ -n "$cl" ] && DLINES+="$(printf '%s\n' "$cl" | sed "s/^/[$cnt] /")"$'\n'
    done
    DLINES="$(printf '%s' "$DLINES" | sed '/^$/d' | tail -n "$((LOG_MAX * 2))")"
}

commit_logs() {
    [ -n "${JCURSOR_TMP:-}" ] && [ -s "$JCURSOR_TMP" ] && mv -f "$JCURSOR_TMP" "$STATE/journal.cursor"
    rm -f "${JCURSOR_TMP:-/nonexistent}"
    printf '%s\n' "$NOW_EPOCH" > "$STATE/log-epoch"
}

run_logs() {
    [ -z "${SIFT_NO_LOGS:-}" ] || return 0
    collect_journal
    collect_docker_logs
    local lines count h prev prev_h prev_t body
    lines="$(printf '%s\n%s\n' "$JLINES" "$DLINES" | sed '/^$/d')"
    if [ -z "$lines" ]; then
        rm -f "$STATE/log-hash"
        commit_logs
        return 0
    fi
    count="$(printf '%s\n' "$lines" | wc -l | tr -d ' ')"
    h="$(printf '%s\n' "$lines" | norm_hash)"
    prev="$(cat "$STATE/log-hash" 2>/dev/null)"
    prev_h="${prev%% *}"; prev_t="${prev##* }"
    [[ "$prev_t" =~ ^[0-9]+$ ]] || prev_t=0
    if [ "$h" = "$prev_h" ] && [ $((NOW_EPOCH - prev_t)) -lt "$LOG_TTL" ]; then
        commit_logs            # same batch as last time, recently sent: deliberately skip
        return 0
    fi
    body="$(printf '%s\n' "$lines" | head -c 12000)"
    if post "logs-$HOST" "$HOST: $count error log line(s)" "$body"; then
        printf '%s %s\n' "$h" "$NOW_EPOCH" > "$STATE/log-hash"
        commit_logs
    fi
}

# ---------------------------------------------------------------- main
main() {
    HERE="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
    [ -f "$HERE/agent.env" ] && . "$HERE/agent.env"
    SERVER="${SIFT_SERVER:-http://localhost:8130}"; SERVER="${SERVER%/}"
    TOKEN="${SIFT_TOKEN:-}"
    HOST="${SIFT_HOST:-$(hostname)}"
    STATE="${SIFT_STATE:-/var/tmp/sift-agent}"
    LOG_PRIORITY="${SIFT_LOG_PRIORITY:-err}"
    LOG_MAX="${SIFT_LOG_MAX:-15}"; [[ "$LOG_MAX" =~ ^[0-9]+$ ]] || LOG_MAX=15
    LOG_IGNORE="${SIFT_LOG_IGNORE:-}"
    if ! valid_host "$HOST"; then
        echo "[sift-agent] SIFT_HOST '$HOST' is invalid (letters, digits, . _ - only, max 64)" >&2; exit 2
    fi
    umask 077
    if [ -L "$STATE" ]; then echo "[sift-agent] state dir $STATE is a symlink — refusing" >&2; exit 2; fi
    mkdir -p "$STATE/spool" && chmod 700 "$STATE" 2>/dev/null
    # running as root but the state dir was left by an older non-root install: take it over
    if [ "$(id -u)" = 0 ] && [ "$(stat -c %u "$STATE" 2>/dev/null || echo 0)" != 0 ]; then
        chown -hR 0:0 "$STATE" 2>/dev/null
    fi

    # one run at a time (a hung mount or slow smartctl must not let runs pile up)
    if command -v flock >/dev/null 2>&1; then
        exec 9>"$STATE/lock"
        flock -n 9 || { echo "[sift-agent] previous run still going — skipping" >&2; exit 0; }
    else
        if ! mkdir "$STATE/lock.d" 2>/dev/null; then
            if [ -n "$(find "$STATE/lock.d" -maxdepth 0 -mmin +15 2>/dev/null)" ]; then
                rmdir "$STATE/lock.d" 2>/dev/null; mkdir "$STATE/lock.d" 2>/dev/null || exit 0
            else
                exit 0
            fi
        fi
        trap 'rmdir "$STATE/lock.d" 2>/dev/null' EXIT
    fi

    NOW_EPOCH="$(date +%s)"
    LAST_EPOCH="$(cat "$STATE/log-epoch" 2>/dev/null)"
    if ! [[ "$LAST_EPOCH" =~ ^[0-9]+$ ]] || [ "$LAST_EPOCH" -ge "$NOW_EPOCH" ] \
       || [ $((NOW_EPOCH - LAST_EPOCH)) -gt 86400 ]; then
        LAST_EPOCH=$((NOW_EPOCH - 300))       # first run, clock went backwards, or a day+ gap
    fi
    rm -f "$STATE/log-ts"                      # old local-time cursor (DST-unsafe), superseded

    setup_auth
    heartbeat
    replay_spool
    run_metrics
    run_logs
}

[ "${SIFT_AGENT_LIB:-}" = 1 ] || main "$@"
