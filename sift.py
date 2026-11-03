#!/usr/bin/env python3
"""
Sift — an AI notification brain for a homelab.

Ingests events (native webhook + ntfy-compatible), lets a local (or any OpenAI-compatible)
LLM triage and correlate them, and only pushes the urgent + actionable ones to Telegram.
Everything routine goes into a once-a-day plain-English digest the LLM writes.

Design rules:
  * A deterministic "critical bypass" (config regexes) pushes straight to Telegram
    WITHOUT the LLM — the things that must never be missed don't depend on the AI.
  * Fail OPEN: if the LLM is unreachable/slow, un-triaged events are pushed raw
    rather than silently dropped.

Stdlib only. Run:  python3 sift.py [config.json]
"""
import base64, hashlib, hmac, json, os, re, secrets, socket, sqlite3, sys, threading, time, urllib.request, urllib.error, urllib.parse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_PATH = sys.argv[1] if len(sys.argv) > 1 else "config.json"


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


CFG = load_config()
BYPASS = [re.compile(p) for p in CFG.get("critical_bypass", [])]
# mute_patterns: deterministic noise suppression — matching events are filed to the digest,
# never pushed (the operator's own "never ping me about this" list, tuned from the UI).
MUTE = [re.compile(p, re.I) for p in CFG.get("mute_patterns", [])]
# ai_context: plain-English description of THIS homelab, injected into triage + chat + digest so
# the AI judges what matters here vs what's normal background noise. The single biggest smartness lever.
AI_CONTEXT = (CFG.get("ai_context") or "").strip()
_db_lock = threading.Lock()

# The LLM is OPTIONAL. With no llm.url configured, Sift runs in rules-only mode:
# critical bypass + keyword triage + plain (non-AI) digests and chat replies.
LLM = CFG.get("llm") or {}
LLM_ENABLED = bool(LLM.get("url"))
LLM_TIMEOUT = LLM.get("timeout", 45)
LLM_HEADERS = {"Content-Type": "application/json"}
if LLM.get("api_key"):   # for OpenAI/Groq/etc; local endpoints (Ollama/vLLM/etc.) usually need none
    LLM_HEADERS["Authorization"] = f"Bearer {LLM['api_key']}"

# keyword heuristics used when no LLM is available
RULE_URGENT = re.compile(r"(?i)\b(down|offline|unreachable|timed? ?out|fail(ed|ure)?|errors?|"
                         r"critical|crash(ed)?|panic|degraded|faulted|expired?|exceeded|refused)\b")
RULE_NOISE = re.compile(r"(?i)\b(recovered|resolved|back up|flap\w*|info|debug|notice|started|"
                        r"available|completed|success)\b")


def rules_verdict(title, body):
    blob = f"{title} {body}"
    if RULE_URGENT.search(blob):
        return ("urgent", True)
    if RULE_NOISE.search(blob):
        return ("noise", False)
    return ("routine", False)


# ---------------------------------------------------------------- storage
def db():
    c = sqlite3.connect(CFG["db_path"], check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY,
            ts TEXT, source TEXT, title TEXT, body TEXT, tags TEXT, priority TEXT,
            status TEXT DEFAULT 'pending',   -- pending|sent|digested
            severity TEXT,                   -- critical|urgent|routine|noise
            actionable INTEGER,
            summary TEXT, grp TEXT, sent_at TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS agents(
            host TEXT PRIMARY KEY, last_seen TEXT, alerted_silent INTEGER DEFAULT 0)""")
        c.execute("""CREATE TABLE IF NOT EXISTS commands(
            id INTEGER PRIMARY KEY,
            host TEXT, cmd TEXT, args TEXT,
            status TEXT DEFAULT 'queued',    -- queued|sent|done|error
            output TEXT, exit_code INTEGER, requested_by TEXT,
            created_at TEXT, completed_at TEXT)""")


def add_event(ev):
    with _db_lock, db() as c:
        cur = c.execute(
            "INSERT INTO events(ts,source,title,body,tags,priority) VALUES(?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"),
             ev.get("source", "unknown"), ev.get("title", ""), ev.get("body", ""),
             ",".join(ev.get("tags", []) if isinstance(ev.get("tags"), list) else []),
             str(ev.get("priority", ""))))
        return cur.lastrowid


def mark(ids, **fields):
    if not ids:
        return
    sets = ",".join(f"{k}=?" for k in fields)
    vals = list(fields.values())
    with _db_lock, db() as c:
        c.execute(f"UPDATE events SET {sets} WHERE id IN ({','.join('?'*len(ids))})",
                  vals + list(ids))


# ---------------------------------------------------------------- delivery
def telegram(text):
    tok = CFG["telegram"]["bot_token"]
    chat = CFG["telegram"]["chat_id"]
    if "PUT_" in tok or "PUT_" in str(chat):
        print(f"[telegram NOT CONFIGURED] would send:\n{text}\n", flush=True)
        return False
    data = json.dumps({"chat_id": chat, "text": text,
                       "parse_mode": "HTML", "disable_web_page_preview": True}).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{tok}/sendMessage", data,
        {"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=15).read()
        return True
    except Exception as e:
        print(f"[telegram ERROR] {e}", flush=True)
        return False


def deliver(text):
    """Outbound notification via the configured channel (default: telegram)."""
    d = CFG.get("delivery") or {"channel": "telegram"}
    ch = d.get("channel", "telegram")
    plain = re.sub(r"<[^>]+>", "", text)   # strip HTML for non-telegram channels
    try:
        if ch == "telegram":
            return telegram(text)
        if ch == "ntfy":
            req = urllib.request.Request(d["url"], plain.encode(),
                                         {"Title": d.get("title", "Sift")})
            if d.get("token"):
                req.add_header("Authorization", f"Bearer {d['token']}")
            urllib.request.urlopen(req, timeout=15).read(); return True
        if ch in ("discord", "slack"):
            key = "content" if ch == "discord" else "text"
            req = urllib.request.Request(d["url"], json.dumps({key: plain}).encode(),
                                         {"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=15).read(); return True
        if ch == "webhook":
            req = urllib.request.Request(d["url"], json.dumps({"text": plain}).encode(),
                                         {"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=15).read(); return True
    except Exception as e:
        print(f"[deliver:{ch}] error: {e}", flush=True)
        return False
    print(f"[deliver] unknown channel '{ch}'", flush=True)
    return False


ICON = {"critical": "🔴", "urgent": "⚠️", "routine": "·", "noise": "·"}


def push_event(row, severity, summary):
    line = summary or row["title"] or row["body"][:200]
    src = row["source"]
    deliver(f"{ICON.get(severity,'⚠️')} <b>{severity.upper()}</b> · {src}\n{line}")
    mark([row["id"]], status="sent", severity=severity, summary=summary,
         sent_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))


# ---------------------------------------------------------------- LLM
def llm_chat(system, user, expect_json=True):
    body = json.dumps({
        "model": LLM.get("model", "default"),
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "temperature": 0, "max_tokens": 1200,
        "chat_template_kwargs": {"enable_thinking": False},
    }).encode()
    req = urllib.request.Request(LLM["url"], body, dict(LLM_HEADERS))
    with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as r:
        content = json.loads(r.read())["choices"][0]["message"]["content"]
    if not expect_json:
        return content
    m = re.search(r"\{.*\}|\[.*\]", content, re.S)   # tolerate stray prose
    return json.loads(m.group(0) if m else content)


TRIAGE_SYSTEM = (
    "You are the triage brain for a solo operator's homelab. They HATE false alarms: only a "
    "genuinely URGENT and ACTIONABLE problem should interrupt them — everything else waits for the "
    "daily digest. When unsure, go QUIETER (routine/noise), never louder.\n"
    "Classify each event, and correlate events sharing one root cause (several services down behind "
    "one tunnel = ONE incident with one summary).\n"
    "Return ONLY a JSON array, one object per input id: "
    '{"id":<int>,"severity":"critical|urgent|routine|noise","actionable":true|false,'
    '"summary":"<=140 chars, plain English, lead with WHAT + which HOST","group":"<short root-cause label or empty>"}.\n'
    "severity:\n"
    "- critical: data or safety at risk — drive/pool/filesystem fault, a failed or missing backup, a "
    "server disk nearly full. Always interrupts.\n"
    "- urgent: a real service/site is actually DOWN or unreachable, or a real security event needing "
    "action now. Interrupts only when actionable.\n"
    "- routine: see it later, not now — updates available, a container that already recovered, a "
    "one-off blip, informational state changes.\n"
    "- noise: ignore — internet scanners/bots being blocked, single failed login probes from the wild, "
    "health-check flaps, debug/info chatter, or a repeat of something already classified.\n"
    "Set actionable=false when there's nothing the operator could usefully do — then it won't interrupt "
    "even if it sounds urgent."
)


def _recent_context():
    """Last hour of already-classified items, so the LLM can spot repeats and not double-alert."""
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    rows = _rows("SELECT source,severity,summary FROM events WHERE status IN('sent','digested') "
                 "AND ts>=? ORDER BY id DESC LIMIT 12", (since,))
    return "\n".join(f"- [{r['severity']}] {r['source']}: {r['summary']}" for r in rows if r.get("summary"))


def _triage_system():
    s = TRIAGE_SYSTEM
    if AI_CONTEXT:
        s += "\n\nABOUT THIS HOMELAB (use it to judge what matters vs what's normal here):\n" + AI_CONTEXT
    rc = _recent_context()
    if rc:
        s += ("\n\nRECENTLY CLASSIFIED (last hour). If an incoming event is essentially a repeat or "
              "continuation of one of these, classify it 'noise' so we don't double-alert:\n" + rc)
    return s


def triage_worker():
    while True:
        time.sleep(CFG["triage_interval_seconds"])
        with db() as c:
            rows = c.execute(
                "SELECT * FROM events WHERE status='pending' ORDER BY id LIMIT ?",
                (CFG["triage_batch_max"],)).fetchall()
        if not rows:
            continue
        rows = list(rows)
        if MUTE:                                   # deterministic noise suppression (user's mute list)
            keep = []
            for r in rows:
                if any(p.search(f"{r['title']} {r['body']}") for p in MUTE):
                    mark([r["id"]], status="digested", severity="noise",
                         summary=r["title"] or r["body"][:120])
                else:
                    keep.append(r)
            rows = keep
            if not rows:
                continue
        if not LLM_ENABLED:                        # rules-only mode (no LLM configured)
            for r in rows:
                sev, act = rules_verdict(r["title"], r["body"])
                if sev == "urgent":
                    push_event(r, "urgent", r["title"] or r["body"][:140])
                else:
                    mark([r["id"]], status="digested", severity=sev,
                         summary=r["title"] or r["body"][:140])
            continue
        payload = [{"id": r["id"], "source": r["source"], "title": r["title"],
                    "body": r["body"][:600], "tags": r["tags"]} for r in rows]
        try:
            verdicts = llm_chat(_triage_system(), json.dumps(payload))
            vmap = {v["id"]: v for v in verdicts}
        except Exception as e:
            print(f"[triage FAIL-OPEN] {e} -> pushing {len(rows)} raw", flush=True)
            for r in rows:                       # fail open: never drop
                push_event(r, "urgent", f"(untriaged) {r['title'] or r['body'][:120]}")
            continue
        for r in rows:
            v = vmap.get(r["id"], {})
            sev = v.get("severity", "urgent")
            summary = v.get("summary", r["title"])
            grp = v.get("group", "")
            if sev in ("critical", "urgent") and v.get("actionable", True):
                push_event(r, sev, summary)
            else:
                mark([r["id"]], status="digested", severity=sev, summary=summary, grp=grp)


# ---------------------------------------------------------------- digest
DIGEST_SYSTEM = (
    "Write a short, calm daily homelab digest for a solo operator. Group related "
    "items, lead with anything that still wants a look, and end reassuringly if all "
    "is quiet. Plain text, a few lines, no preamble."
)


def digest_worker():
    sent_for = None
    while True:
        now = datetime.now().astimezone()
        if now.hour == CFG["digest_hour_local"] and sent_for != now.date():
            since = (datetime.now(timezone.utc)
                     - timedelta(hours=CFG["digest_lookback_hours"])).isoformat()
            with db() as c:
                rows = c.execute(
                    "SELECT severity,source,summary,grp FROM events "
                    "WHERE status='digested' AND ts>=? ORDER BY id", (since,)).fetchall()
            items = [dict(r) for r in rows]
            if items:
                plain = "\n".join(f"· {i['source']}: {i['summary']}" for i in items[:25])
                if LLM_ENABLED:
                    try:
                        dsys = DIGEST_SYSTEM + ("\n\nContext about this homelab:\n" + AI_CONTEXT if AI_CONTEXT else "")
                        plain = llm_chat(dsys, json.dumps(items), expect_json=False).strip()
                    except Exception:
                        pass
                deliver("📋 <b>Daily digest</b>\n" + plain)
            else:
                deliver("📋 <b>Daily digest</b>\nQuiet day — nothing needed you.")
            sent_for = now.date()
        time.sleep(60)


# ---------------------------------------------------------------- fleet watcher (outbound uptime)
# Sift actively checks each server/service from where it sits — no agent needed on
# the remote hosts. Alerts on a state CHANGE (up<->down), so no "still down" spam.
MON_STATE = {}   # name -> {"up": bool, "since": ts, "detail": str}


def check_monitor(m):
    t = m.get("type", "http")
    try:
        if t == "http":
            req = urllib.request.Request(m["url"], method="GET",
                                         headers={"User-Agent": "sift-monitor"})
            try:
                with urllib.request.urlopen(req, timeout=12) as r:
                    code = r.status
            except urllib.error.HTTPError as e:
                code = e.code                         # 401/302/etc still means "reachable"
            return (code < 500, f"HTTP {code}")
        if t == "tcp":
            socket.create_connection((m["host"], int(m["port"])), timeout=8).close()
            return (True, "port open")
    except Exception as e:
        return (False, str(e)[:120])
    return (False, "unknown monitor type")


def _emit_monitor(name, ok, detail):
    title = f"{name} recovered" if ok else f"{name} is DOWN"
    eid = add_event({"source": "monitor", "title": title,
                     "body": f"{name}: {detail}", "tags": ["uptime"]})
    with db() as c:
        row = c.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if ok:
        deliver(f"✅ <b>RECOVERED</b> · {name}\nBack up ({detail}).")
        mark([eid], status="sent", severity="routine", summary=f"{name} recovered ({detail})",
             sent_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    else:
        push_event(row, "urgent", f"{name} is DOWN — {detail}")   # down is urgent, deterministic


def monitor_worker():
    mons = CFG.get("monitors", [])
    if not mons:
        return
    iv = CFG.get("monitor_interval_seconds", 90)
    print(f"[monitor] watching {len(mons)} targets every {iv}s", flush=True)
    while True:
        for m in mons:
            name = m["name"]
            ok, detail = check_monitor(m)
            prev = MON_STATE.get(name)
            changed = (prev is not None and prev["up"] != ok)
            MON_STATE[name] = {"up": ok, "detail": detail,
                               "since": time.time() if (prev is None or prev["up"] != ok) else prev["since"]}
            if changed or (prev is None and not ok):   # alert on change, or if already down at startup
                try:
                    _emit_monitor(name, ok, detail)
                except Exception as e:
                    print(f"[monitor] emit error: {e}", flush=True)
        time.sleep(iv)


# ---------------------------------------------------------------- helper agents
AGENT_SILENT_AFTER = 1200   # no heartbeat for 20 min -> consider the host down. Persisted to DB so
                            # the agent list survives restarts (config saves restart the process).


def _agent_age(last_seen):
    try:
        return time.time() - datetime.fromisoformat(last_seen).timestamp()
    except Exception:
        return 1e9


def agent_heartbeat(host):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _db_lock, db() as c:
        prev = c.execute("SELECT alerted_silent FROM agents WHERE host=?", (host,)).fetchone()
        c.execute("INSERT INTO agents(host,last_seen,alerted_silent) VALUES(?,?,0) "
                  "ON CONFLICT(host) DO UPDATE SET last_seen=excluded.last_seen, alerted_silent=0", (host, now))
    if prev and prev["alerted_silent"]:
        deliver(f"✅ <b>RECOVERED</b> · agent {host}\nHeartbeat is back.")


def agent_watch():
    while True:
        time.sleep(60)
        for r in _rows("SELECT host,last_seen,alerted_silent FROM agents"):
            if not r["alerted_silent"] and _agent_age(r["last_seen"]) > AGENT_SILENT_AFTER:
                with _db_lock, db() as c:
                    c.execute("UPDATE agents SET alerted_silent=1 WHERE host=?", (r["host"],))
                eid = add_event({"source": "agent", "title": f"agent {r['host']} is silent",
                                 "body": f"No heartbeat from {r['host']} for over {AGENT_SILENT_AFTER//60} min — the host may be down.",
                                 "tags": ["agent", "down"]})
                with db() as c:
                    row = c.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
                push_event(row, "urgent", f"Agent {r['host']} went silent — host may be down.")


def tool_agents(_):
    rows = _rows("SELECT host,last_seen FROM agents ORDER BY host")
    if not rows:
        return [{"note": "no helper agents have reported in yet"}]
    return [{"host": r["host"], "last_seen": r["last_seen"],
             "silent": _agent_age(r["last_seen"]) > AGENT_SILENT_AFTER} for r in rows]


# ---------------------------------------------------------------- interactive (READ-ONLY)
# You message the bot; a local LLM maps it to ONE of these fixed read-only tools.
# The LLM never generates or runs commands, and only your chat id is answered.
def _rows(sql, args=()):
    with db() as c:
        return [dict(r) for r in c.execute(sql, args).fetchall()]


def tool_status(_):
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    return {"last24h_by_severity": _rows(
                "SELECT severity, COUNT(*) n FROM events WHERE ts>=? GROUP BY severity", (since,)),
            "recent_urgent": _rows(
                "SELECT ts,source,summary FROM events WHERE severity IN('critical','urgent') "
                "AND ts>=? ORDER BY id DESC LIMIT 15", (since,))}


def tool_recent(a):
    q = "SELECT ts,source,severity,status,summary,title FROM events WHERE 1=1"
    p = []
    if a.get("severity"):
        q += " AND severity=?"; p.append(a["severity"])
    if a.get("source"):
        q += " AND source LIKE ?"; p.append(f"%{a['source']}%")
    q += " ORDER BY id DESC LIMIT ?"; p.append(min(int(a.get("limit", 10)), 30))
    return _rows(q, p)


def tool_updates(_):
    return _rows("SELECT ts,source,summary,title,body FROM events WHERE "
                 "lower(title) LIKE '%updat%' OR lower(tags) LIKE '%updat%' OR "
                 "source LIKE '%updat%' OR lower(body) LIKE '%upgrad%' ORDER BY id DESC LIMIT 25")


def tool_search(a):
    kw = f"%{a.get('query','')}%"
    return _rows("SELECT ts,source,severity,summary,title,body FROM events WHERE "
                 "title LIKE ? OR body LIKE ? OR summary LIKE ? ORDER BY id DESC LIMIT 15",
                 (kw, kw, kw))


def tool_fleet(_):
    if not MON_STATE:
        return [{"note": "fleet monitors still warming up — ask again in a moment"}]
    return [{"server": n, "status": "up" if v["up"] else "DOWN", "detail": v.get("detail"),
             "since": datetime.fromtimestamp(v["since"], timezone.utc).isoformat(timespec="minutes")}
            for n, v in MON_STATE.items()]


# ---------------------------------------------------------------- remote exec (READ-ONLY, allowlisted)
# Agents never accept inbound connections: the exec DAEMON on each host long-polls
# /agent/commands, runs ONE allowlisted diagnostic (argv only — never a shell, so no
# ; | $() `` redirect injection is possible), and POSTs the output back. The server only
# ever queues a KEY (+ validated args) from the menu below; the daemon re-validates. Nothing
# here can write, install, delete or change anything — strictly read-only diagnostics.
EXEC_ALLOW = {
    "uptime":      {"desc": "Load average + uptime", "args": {}},
    "disk":        {"desc": "Disk usage (df -h)", "args": {}},
    "mem":         {"desc": "Memory usage (free -h)", "args": {}},
    "zpool":       {"desc": "ZFS pool status", "args": {}},
    "docker_ps":   {"desc": "Running containers", "args": {}},
    "docker_logs": {"desc": "Last N lines of a container's logs", "args": {"container": "name", "lines": "int?"}},
    "smart":       {"desc": "SMART health of a disk (e.g. sda)", "args": {"disk": "disk"}},
    "journal":     {"desc": "Last N journal lines for a systemd unit", "args": {"unit": "name", "lines": "int?"}},
    "failed":      {"desc": "Failed systemd units", "args": {}},
    "procs":       {"desc": "Top processes by CPU", "args": {}},
    "net":         {"desc": "Listening sockets (ss -tulpn)", "args": {}},
    "uname":       {"desc": "Kernel / OS version", "args": {}},
}
_EXEC_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_EXEC_DISK = re.compile(r"^[a-z0-9]{1,16}$")


def validate_command(cmd, args):
    """Server-side gate: only an allowlisted key with safe, typed args can be queued."""
    spec = EXEC_ALLOW.get(cmd)
    if not spec:
        return None, f"unknown command '{cmd}'"
    args = args or {}
    clean = {}
    for k, kind in spec["args"].items():
        optional = kind.endswith("?")
        kind = kind.rstrip("?")
        v = args.get(k)
        if v in (None, ""):
            if kind == "int":
                clean[k] = 50          # default line count
            elif not optional:
                return None, f"missing '{k}'"
            continue
        if kind == "int":
            try:
                clean[k] = max(1, min(int(v), 500))
            except Exception:
                return None, f"'{k}' must be a number"
        elif kind == "disk":
            if not _EXEC_DISK.match(str(v)):
                return None, f"bad disk '{v}'"
            clean[k] = str(v)
        else:
            if not _EXEC_NAME.match(str(v)):
                return None, f"bad {k} '{v}'"
            clean[k] = str(v)
    return clean, None


def queue_command(host, cmd, args, requested_by):
    clean, err = validate_command(cmd, args)
    if err:
        return None, err
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _db_lock, db() as c:
        cur = c.execute("INSERT INTO commands(host,cmd,args,status,requested_by,created_at) "
                        "VALUES(?,?,?,'queued',?,?)",
                        (host, cmd, json.dumps(clean), requested_by, now))
        return cur.lastrowid, None


def queue_control(host, action, requested_by):
    """Queue a reserved CONTROL command (e.g. self-uninstall). Bypasses the read-only
    EXEC_ALLOW gate on purpose — only admin endpoints call this, never the exec/chat path."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _db_lock, db() as c:
        cur = c.execute("INSERT INTO commands(host,cmd,args,status,requested_by,created_at) "
                        "VALUES(?,?,?,'queued',?,?)",
                        (host, "__control__", json.dumps({"action": action}), requested_by, now))
        return cur.lastrowid


def claim_commands(host):
    with _db_lock, db() as c:
        rows = c.execute("SELECT id,cmd,args FROM commands WHERE host=? AND status='queued' "
                         "ORDER BY id", (host,)).fetchall()
        ids = [r["id"] for r in rows]
        if ids:
            c.execute(f"UPDATE commands SET status='sent' WHERE id IN ({','.join('?'*len(ids))})", ids)
    return [{"id": r["id"], "cmd": r["cmd"], "args": json.loads(r["args"] or "{}")} for r in rows]


def store_result(cid, output, exit_code):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    status = "done" if exit_code == 0 else "error"
    with _db_lock, db() as c:
        c.execute("UPDATE commands SET status=?,output=?,exit_code=?,completed_at=? "
                  "WHERE id=? AND status='sent'", (status, (output or "")[:8000], exit_code, now, cid))


def get_command(cid):
    rows = _rows("SELECT id,host,cmd,args,status,output,exit_code,requested_by,created_at,completed_at "
                 "FROM commands WHERE id=?", (cid,))
    return rows[0] if rows else None


def known_hosts():
    return [r["host"] for r in _rows("SELECT host FROM agents ORDER BY host")]


def run_on_agent(host, cmd, args, requested_by, wait=30):
    """Queue a command and block until the agent returns a result (or we time out)."""
    cid, err = queue_command(host, cmd, args, requested_by)
    if err:
        return {"error": err}
    deadline = time.time() + wait
    while time.time() < deadline:
        row = get_command(cid)
        if row and row["status"] in ("done", "error"):
            return {"host": host, "cmd": cmd, "status": row["status"],
                    "exit_code": row["exit_code"], "output": (row["output"] or "")[:4000]}
        time.sleep(0.5)
    return {"host": host, "cmd": cmd, "status": "timeout",
            "note": "no result — is the sift-agentd exec daemon running on that host?"}


def tool_exec(a):
    host = str(a.get("host", "")).strip()
    cmd = str(a.get("cmd", "")).strip()
    kh = known_hosts()
    if host not in kh:
        return {"error": f"unknown host '{host}'", "known_hosts": kh}
    if cmd not in EXEC_ALLOW:
        return {"error": f"unknown command '{cmd}'", "available": list(EXEC_ALLOW)}
    extra = {k: v for k, v in a.items() if k not in ("host", "cmd")}
    return run_on_agent(host, cmd, extra, requested_by="telegram", wait=30)


TOOLS = {"status": tool_status, "recent": tool_recent, "updates": tool_updates,
         "search": tool_search, "fleet": tool_fleet, "agents": tool_agents, "exec": tool_exec}

PERSONA = (
    "You are Sift, a homelab assistant, over Telegram. Voice: a sharp, dry, friendly sysadmin "
    "mate — human and natural, never a status page. Concise (Telegram-length), plain, contractions, a "
    "little wit; no markdown headings or bullet dumps unless they genuinely help.\n"
    "GROUND EVERY FACTUAL CLAIM IN A TOOL. For anything about the operator's real systems — health, events, "
    "updates, outages, what a host is doing — call a tool; never guess, invent or half-remember a "
    "status, number, name or event. If a lookup is empty, say so like a person and note it fills in as "
    "events flow.\n"
    "BE PROACTIVE AND JOIN THE DOTS: 'is everything ok?' → check fleet AND agents AND recent urgent, "
    "then give a one-line verdict. When something's wrong and the cause isn't obvious from stored "
    "events, USE THE exec TOOL to actually look (disk, logs, zpool, procs, smart…) on the relevant "
    "host and answer from what you find — don't guess and don't make them go check it themselves. Pick the "
    "right host from the fleet/agents list; chain a couple of tools when it helps.\n"
    "Everything you can do is READ-ONLY: you cannot change, write, install, restart, delete or "
    "uninstall anything — if asked, say so plainly. Chit-chat or explaining yourself needs no tools. "
    "Keep it to a few sentences and lead with the answer."
)

TOOLS_SPEC = [
    {"type": "function", "function": {
        "name": "status", "description": "Overall homelab health in the last 24h: event counts by severity plus any recent critical/urgent items.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "recent", "description": "Recent events, newest first. Optionally filter.",
        "parameters": {"type": "object", "properties": {
            "severity": {"type": "string", "enum": ["critical", "urgent", "routine", "noise"]},
            "source": {"type": "string", "description": "source/app name substring"},
            "limit": {"type": "integer"}}}}},
    {"type": "function", "function": {
        "name": "updates", "description": "Pending software/container updates that have been reported.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "search", "description": "Find events mentioning a keyword — a service/host/app name like 'sure', 'frigate', 'backup'.",
        "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "fleet", "description": "Live up/down status of all monitored servers and services (the AI rig, the VPSes, key sites). Use for 'are my servers up?'.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "agents", "description": "Which helper agents (per-host sift-agent) have reported in, when they were last seen, and whether any has gone silent.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "exec", "description": "Run ONE read-only diagnostic command on a specific host's agent and read the output back. Use for live host state the stored events don't cover (what's eating disk/CPU on a box, a container's recent logs, a drive's SMART health, listening ports). Read-only — it cannot change, restart, write or delete anything. Check the host label with the agents tool first.",
        "parameters": {"type": "object", "properties": {
            "host": {"type": "string", "description": "host label exactly as the agents tool shows it"},
            "cmd": {"type": "string", "enum": list(EXEC_ALLOW),
                    "description": "disk=df -h, mem=free, zpool, docker_ps, docker_logs, smart, journal, failed=failed units, procs=top CPU, net=listening ports, uptime, uname"},
            "container": {"type": "string", "description": "container name (for docker_logs)"},
            "unit": {"type": "string", "description": "systemd unit (for journal)"},
            "disk": {"type": "string", "description": "disk e.g. sda (for smart)"},
            "lines": {"type": "integer", "description": "line count for docker_logs/journal (default 50)"}},
            "required": ["host", "cmd"]}}},
]


def _llm_turn(messages):
    body = json.dumps({
        "model": LLM.get("model", "default"), "messages": messages,
        "tools": TOOLS_SPEC, "tool_choice": "auto",
        "temperature": 0.4, "max_tokens": 800,
        "chat_template_kwargs": {"enable_thinking": True, "reasoning_effort": "low"},
    }).encode()
    req = urllib.request.Request(LLM["url"], body, dict(LLM_HEADERS))
    with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as r:
        return json.loads(r.read())["choices"][0]["message"]


# short-term per-chat memory so follow-ups ("is it ok now?", "what about frigate?") have context
CONVO = {}            # chat_id -> {"ts": float, "msgs": [{role,content}, ...]}  (user/assistant only)
CONVO_TTL = 1800      # start fresh after 30 min idle
CONVO_MAX = 12        # keep the last N user/assistant turns


def _history(chat_id):
    e = CONVO.get(chat_id)
    if not e or (time.time() - e["ts"] > CONVO_TTL):
        CONVO.pop(chat_id, None)
        return []
    return e["msgs"]


def _remember(chat_id, user_text, reply):
    e = CONVO.setdefault(chat_id, {"ts": 0, "msgs": []})
    e["msgs"] = (e["msgs"] + [{"role": "user", "content": user_text},
                              {"role": "assistant", "content": reply}])[-CONVO_MAX:]
    e["ts"] = time.time()


def _rules_chat(text):
    """No-LLM chat: keyword-route to a read-only tool and format the result plainly."""
    t = text.lower()
    if "updat" in t or "upgrad" in t:
        d = tool_updates({}); return "\n".join(f"· {x.get('summary') or x.get('title')}" for x in d) or "No updates recorded."
    if any(w in t for w in ("server", "down", "online", "fleet", "reachable")):
        data = tool_fleet({})
        if data and "status" in data[0]:
            return "\n".join(f"{'✅' if d['status']=='up' else '🔴'} {d['server']}: {d['status']}" for d in data)
        return "Fleet monitors still warming up."
    if any(w in t for w in ("ok", "health", "status", "everything", "alert")):
        s = tool_status({})
        return "Last 24h by severity: " + (", ".join(f"{r['severity']}×{r['n']}" for r in s["last24h_by_severity"]) or "nothing") \
               + ("\nRecent: " + "; ".join(x["summary"] for x in s["recent_urgent"][:5]) if s["recent_urgent"] else "")
    d = tool_search({"query": text.split()[-1] if text.split() else ""})
    return "\n".join(f"· {x.get('summary') or x.get('title')}" for x in d[:8]) or \
           "(No-LLM mode) Try: 'are my servers up?', 'any updates?', 'how's everything?'."


def answer_query(text, chat_id="cli"):
    """Conversational agent with short-term memory; calls read-only tools itself."""
    if not LLM_ENABLED:
        reply = _rules_chat(text)
        _remember(chat_id, text, reply)
        return reply
    sysmsg = PERSONA + ("\n\nABOUT THIS HOMELAB:\n" + AI_CONTEXT if AI_CONTEXT else "")
    msgs = [{"role": "system", "content": sysmsg}] + _history(chat_id) + \
           [{"role": "user", "content": text}]
    reply = "That spiralled a bit — ask me something more specific?"
    for _ in range(4):
        try:
            m = _llm_turn(msgs)
        except Exception as e:
            print(f"[chat] LLM unreachable: {e}", flush=True)
            return ("Can't reach my brain (the LLM) right now, so I can't look that "
                    "up — your alerts still work in the meantime.")
        calls = m.get("tool_calls")
        if not calls:
            reply = (m.get("content") or "").strip() or \
                    "Not sure what you're after — try 'how's everything?' or 'any updates?'"
            break
        msgs.append(m)
        for tc in calls:
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except Exception:
                args = {}
            result = TOOLS[fn["name"]](args) if fn.get("name") in TOOLS else {"error": "unknown tool"}
            msgs.append({"role": "tool", "tool_call_id": tc.get("id", ""),
                         "name": fn.get("name"), "content": json.dumps(result)[:4000]})
    _remember(chat_id, text, reply)
    return reply


def tg_api(method, params=None, timeout=60):
    tok = CFG["telegram"]["bot_token"]
    url = f"https://api.telegram.org/bot{tok}/{method}"
    if params is not None:
        req = urllib.request.Request(url, json.dumps(params).encode(),
                                     {"Content-Type": "application/json"})
    else:
        req = urllib.request.Request(url)
    return json.load(urllib.request.urlopen(req, timeout=timeout))


def telegram_listener():
    allowed = {str(x) for x in CFG["telegram"].get("authorized_chat_ids", []) if "PUT_" not in str(x)}
    if not allowed or "PUT_" in CFG["telegram"]["bot_token"]:
        print("[chat] interactive disabled (no token / no authorized_chat_ids)", flush=True)
        return
    offset = 0
    try:                                   # skip any backlog so we don't answer stale messages on start
        res = tg_api("getUpdates", {"offset": -1, "timeout": 0}).get("result", [])
        if res:
            offset = res[-1]["update_id"] + 1
    except Exception as e:
        print(f"[chat] init: {e}", flush=True)
    print(f"[chat] interactive listener ready — answering {sorted(allowed)} only", flush=True)
    while True:
        try:
            up = tg_api("getUpdates", {"offset": offset, "timeout": 25})
        except Exception as e:
            print(f"[chat] poll error: {e}", flush=True); time.sleep(5); continue
        for u in up.get("result", []):
            offset = u["update_id"] + 1
            msg = u.get("message") or u.get("edited_message") or {}
            sender = str((msg.get("from") or {}).get("id") or (msg.get("chat") or {}).get("id") or "")
            text = (msg.get("text") or "").strip()
            if sender not in allowed:        # silent — never reveal the bot to anyone else
                continue
            if not text:
                continue
            try:
                reply = answer_query(text, chat_id=sender)
                tg_api("sendMessage", {"chat_id": msg["chat"]["id"], "text": reply,
                                       "parse_mode": "HTML", "disable_web_page_preview": True})
            except Exception as e:
                print(f"[chat] handle error: {e}", flush=True)


# ---------------------------------------------------------------- ingest/HTTP
def is_critical(title, body):
    blob = f"{title}\n{body}"
    return any(p.search(blob) for p in BYPASS)


def handle_event(ev):
    eid = add_event(ev)
    with db() as c:
        row = c.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if is_critical(ev.get("title", ""), ev.get("body", "")):
        detail = " — ".join(x for x in (ev.get("title", ""), ev.get("body", "")[:300]) if x)
        push_event(row, "critical", detail.strip(" —") or "critical event")  # deterministic, no LLM
    return eid


# ---------------------------------------------------------------- admin / web UI
# Admin sessions are STATELESS signed tokens (exp.hmac) so they survive restarts/rebuilds —
# no in-memory store to wipe on every config save. Keyed on the admin password, so changing
# the password invalidates all existing sessions. Default 30-day lifetime (config-tunable).
SESSION_TTL = int(CFG.get("admin_session_days", 30)) * 86400
WEB_INDEX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "index.html")
AGENTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agents")


def _admin_password():
    return CFG.get("admin_password") or ""


def _session_sig(exp):
    key = (_admin_password() or "sift-no-pw").encode()
    return hmac.new(key, str(exp).encode(), hashlib.sha256).hexdigest()


def _new_session():
    exp = int(time.time()) + SESSION_TTL
    return f"{exp}.{_session_sig(exp)}"


def _session_valid(tok):
    try:
        exp_s, sig = (tok or "").split(".", 1)
        exp = int(exp_s)
    except Exception:
        return False
    if exp < time.time():
        return False
    return hmac.compare_digest(sig, _session_sig(exp))


def save_config_and_restart(new_cfg):
    with open(CONFIG_PATH, "w") as f:
        json.dump(new_cfg, f, indent=2)
    threading.Timer(0.6, lambda: os.execv(
        sys.executable, [sys.executable, os.path.abspath(__file__), CONFIG_PATH])).start()


def _telegram_chat_ids():
    tok = (CFG.get("telegram") or {}).get("bot_token", "")
    if not tok or "PUT_" in tok:
        return {"error": "no bot token set"}
    try:
        up = json.load(urllib.request.urlopen(
            f"https://api.telegram.org/bot{tok}/getUpdates", timeout=15))
    except Exception as e:
        return {"error": str(e)[:160]}
    ids = []
    for u in up.get("result", []):
        ch = (u.get("message") or u.get("edited_message") or {}).get("chat", {})
        if ch.get("id") and ch["id"] not in [i["id"] for i in ids]:
            ids.append({"id": ch["id"], "name": ch.get("first_name") or ch.get("username") or ch.get("title")})
    return {"chats": ids, "hint": "message your bot first if this is empty"}


def _llm_test():
    if not LLM_ENABLED:
        return {"ok": False, "detail": "no LLM configured (rules-only mode)"}
    try:
        llm_chat("Reply with the single word ok.", "ping", expect_json=False)
        return {"ok": True, "detail": f"reached {LLM.get('model','model')}"}
    except Exception as e:
        return {"ok": False, "detail": str(e)[:160]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _reply(self, code=200, msg="ok"):
        self._json({"status": msg}, code)

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self, html, code=200):
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _ingest_authed(self):
        tok = CFG.get("ingest_token", "")
        if not tok:
            return True
        auth = self.headers.get("Authorization", "")
        if auth == f"Bearer {tok}" or self.headers.get("X-Sift-Token") == tok:
            return True
        if auth.startswith("Basic "):   # ntfy-compatible: `curl -u ":<token>"` or user:<token>
            try:
                up = base64.b64decode(auth[6:]).decode("utf-8", "ignore")
                return hmac.compare_digest(up.split(":", 1)[-1], tok)
            except Exception:
                return False
        return False

    def _admin_authed(self):
        return _session_valid(self.headers.get("X-Admin-Token"))

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) if n else b""
        return raw

    # ---- GET ----
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            try:
                with open(WEB_INDEX, encoding="utf-8") as f:
                    return self._html(f.read())
            except Exception:
                return self._reply(msg="sift alive (web UI not found)")
        if p == "/health":
            return self._reply(msg="sift alive")
        if p in ("/agent/sift-agent.sh", "/agent/sift-agentd.sh", "/agent/install.sh"):   # serve the helpers (no secrets in them)
            try:
                with open(os.path.join(AGENTS_DIR, os.path.basename(p)), encoding="utf-8") as f:
                    body = f.read().encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            except Exception:
                return self._reply(404, "agent script not found")
        if p == "/agent/commands":               # exec daemon long-polls here for queued commands
            if not self._ingest_authed():
                return self._reply(401, "unauthorized")
            qs = urllib.parse.parse_qs(self.path.split("?", 1)[1]) if "?" in self.path else {}
            host = (qs.get("host") or ["unknown"])[0]
            fmt = (qs.get("fmt") or ["json"])[0]
            deadline = time.time() + 25
            cmds = []
            while time.time() < deadline:
                cmds = claim_commands(host)
                if cmds:
                    break
                time.sleep(1)
            if fmt == "text":                    # tab-separated: id<TAB>cmd<TAB>k=v k=v  (args are pre-validated safe)
                lines = "\n".join(f"{c['id']}\t{c['cmd']}\t" +
                                  " ".join(f"{k}={v}" for k, v in c["args"].items()) for c in cmds)
                body = lines.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            return self._json({"commands": cmds})
        if p == "/admin/meta":                 # no auth: tells the UI whether to show setup or login
            return self._json({"needs_setup": not _admin_password(),
                               "llm": LLM_ENABLED, "channel": (CFG.get("delivery") or {}).get("channel", "telegram")})
        if p.startswith("/admin/"):
            if not self._admin_authed():
                return self._reply(401, "unauthorized")
            if p == "/admin/config":
                return self._json(CFG)
            if p == "/admin/events":
                return self._json(_rows("SELECT id,ts,source,status,severity,summary,title "
                                        "FROM events ORDER BY id DESC LIMIT 50"))
            if p == "/admin/fleet":
                return self._json(tool_fleet({}))
            if p == "/admin/agents":
                return self._json(tool_agents({}))
            if p == "/admin/exec/spec":
                return self._json({"commands": [{"key": k, "desc": v["desc"], "args": v["args"]}
                                                for k, v in EXEC_ALLOW.items()],
                                   "hosts": known_hosts()})
            if p == "/admin/commands":
                return self._json(_rows("SELECT id,host,cmd,args,status,exit_code,requested_by,"
                                        "created_at,completed_at FROM commands ORDER BY id DESC LIMIT 40"))
            if p.startswith("/admin/exec/") and p.rsplit("/", 1)[-1].isdigit():
                return self._json(get_command(int(p.rsplit("/", 1)[-1])) or {"error": "not found"})
            if p == "/admin/telegram/chatid":
                return self._json(_telegram_chat_ids())
            if p == "/admin/llm/test":
                return self._json(_llm_test())
        return self._reply(404, "not found")

    # ---- POST ----
    def do_POST(self):
        p = self.path.split("?")[0]
        if p.startswith("/admin/"):
            return self._admin_post(p)
        if p == "/agent/heartbeat":
            if not self._ingest_authed():
                return self._reply(401, "unauthorized")
            try:
                host = str(json.loads(self._body() or b"{}").get("host", "unknown"))
            except Exception:
                host = "unknown"
            agent_heartbeat(host)
            return self._reply(msg="beat")
        if p == "/agent/command-result":         # exec daemon posts output back here (id/rc in headers, body = output)
            if not self._ingest_authed():
                return self._reply(401, "unauthorized")
            try:
                cid = int(self.headers.get("X-Cmd-Id", "0") or 0)
                rc = int(self.headers.get("X-Cmd-Rc", "0") or 0)
            except Exception:
                return self._reply(400, "bad headers")
            store_result(cid, self._body().decode("utf-8", "ignore"), rc)
            return self._reply(msg="stored")
        # ingest
        if not self._ingest_authed():
            return self._reply(401, "unauthorized")
        raw = self._body()
        if p == "/notify":
            try:
                ev = json.loads(raw or b"{}")
            except Exception:
                return self._reply(400, "bad json")
        else:                                  # ntfy-compatible: POST /<topic>
            ev = {"source": p.strip("/") or "default",
                  "title": self.headers.get("X-Title") or self.headers.get("Title") or p.strip("/") or "event",
                  "body": raw.decode("utf-8", "ignore"),
                  "tags": (self.headers.get("X-Tags") or self.headers.get("Tags") or "").split(",")}
        handle_event(ev)
        self._reply(msg="accepted")

    def _admin_post(self, p):
        try:
            data = json.loads(self._body() or b"{}")
        except Exception:
            return self._reply(400, "bad json")
        if p == "/admin/setup":                # first-run: set the admin password (only if none yet)
            if _admin_password():
                return self._reply(409, "already set up")
            pw = str(data.get("password", ""))
            if len(pw) < 6:
                return self._reply(400, "password too short (min 6)")
            CFG["admin_password"] = pw
            with open(CONFIG_PATH, "w") as f:
                json.dump(CFG, f, indent=2)
            return self._json({"token": _new_session()})
        if p == "/admin/login":
            pw = _admin_password()
            if pw and hmac.compare_digest(str(data.get("password", "")), pw):
                return self._json({"token": _new_session()})
            return self._reply(401, "wrong password")
        # everything below needs a valid session
        if not self._admin_authed():
            return self._reply(401, "unauthorized")
        if p == "/admin/telegram/test":
            ok = telegram("✅ Sift test — if you can read this, delivery works.")
            return self._json({"ok": bool(ok)})
        if p == "/admin/config":
            new = data.get("config")
            if not isinstance(new, dict):
                return self._reply(400, "config must be an object")
            new.setdefault("admin_password", CFG.get("admin_password"))   # never drop the password
            save_config_and_restart(new)
            return self._json({"status": "saved — restarting"})
        if p == "/admin/exec":                 # queue a read-only command for a host's exec daemon
            host = str(data.get("host", "")).strip()
            cmd = str(data.get("cmd", "")).strip()
            if host not in known_hosts():
                return self._reply(400, "unknown host")
            cid, err = queue_command(host, cmd, data.get("args") or {}, requested_by="admin-ui")
            if err:
                return self._reply(400, err)
            return self._json({"id": cid})
        if p == "/admin/agent/uninstall":      # tell a host's exec daemon to remove itself (needs the daemon running)
            host = str(data.get("host", "")).strip()
            if not host:
                return self._reply(400, "host required")
            cid = queue_control(host, "uninstall", "admin-ui")
            with _db_lock, db() as c:          # drop it from the fleet view now; a live daemon will tear down on its next poll
                c.execute("DELETE FROM agents WHERE host=?", (host,))
            return self._json({"status": "uninstall queued", "id": cid,
                               "note": "the agent removes itself on its next poll (needs the exec daemon running there)"})
        return self._reply(404, "not found")


def main():
    init_db()
    threading.Thread(target=triage_worker, daemon=True).start()
    threading.Thread(target=digest_worker, daemon=True).start()
    threading.Thread(target=telegram_listener, daemon=True).start()
    threading.Thread(target=monitor_worker, daemon=True).start()
    threading.Thread(target=agent_watch, daemon=True).start()
    port = CFG["listen_port"]
    mode = "AI" if LLM_ENABLED else "rules-only"
    print(f"Sift listening on :{port}  [{mode}]  — web UI at /, ingest at POST /<topic>", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
