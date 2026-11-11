#!/usr/bin/env python3
"""Read-only log watcher with explicit allowlisted approvals, agent memory, and NVIDIA Auto-Ontology integration."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shlex
import sqlite3
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple

from auto_ontology_bridge import AutoOntologyBridge

ROOT = pathlib.Path(os.environ.get("OPS_WATCH_HOME", pathlib.Path(__file__).parent / "state"))
DB = ROOT / "ops-watch.db"
ONTOLOGY_FILE = pathlib.Path(__file__).with_name("ontology.json")
WORKLOG_FILE = pathlib.Path(__file__).with_name("WORKLOG.md")
DEFAULT_SOURCE = "journalctl -p warning..alert --since '-5 min' -o cat --no-pager"

RULES = (
    ("credential", ("/etc/shadow", "sudoers", "Sensitive file read", "/etc/security"), "collect-evidence"),
    ("privilege", ("Suspicious ROOT execution", "Unexpected setuid", "setuid binary execution"), "collect-evidence"),
    ("network", ("crypto-mining", "Raw/packet socket", "internal network"), "collect-evidence"),
)
REISSUE_SCRIPT = pathlib.Path(__file__).parent.parent / "headscale" / "reissue-student-key.sh"
ACTION_ALLOWLIST = {
    "collect-evidence": ["journalctl", "-u", "falco-modern-bpf", "-u", "auditd", "--since", "-1h", "--no-pager"],
    "reissue-headscale-student1": ["bash", str(REISSUE_SCRIPT), "student1", "--execute"]
}
AGY = os.environ.get("OPS_WATCH_ANTIGRAVITY", os.path.expanduser("~/.local/bin/agy"))


def db() -> sqlite3.Connection:
    ROOT.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB)
    c.execute(
        """CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY,
            created INTEGER,
            category TEXT,
            evidence TEXT,
            action TEXT,
            fingerprint TEXT UNIQUE,
            status TEXT DEFAULT 'pending',
            resolved_at INTEGER,
            resolution_note TEXT
        )"""
    )
    c.execute(
        """CREATE TABLE IF NOT EXISTS worklog (
            id INTEGER PRIMARY KEY,
            created INTEGER,
            ticket_id INTEGER,
            kind TEXT,
            body TEXT,
            tags TEXT
        )"""
    )
    return c


def load_ontology() -> Dict[str, Any]:
    bridge = AutoOntologyBridge()
    local = bridge.load_local_ontology()
    return local


def search_memory(category: str, evidence: str, current_ticket_id: Optional[int] = None, limit: int = 3) -> List[Dict[str, Any]]:
    """Retrieve historical precedents from past tickets and worklog memory."""
    c = db()
    query = """
        SELECT t.id, t.created, t.category, t.evidence, t.action, t.status, t.resolution_note,
               (SELECT body FROM worklog WHERE ticket_id = t.id AND kind = 'llm-analysis' ORDER BY id DESC LIMIT 1) as analysis
        FROM tickets t
        WHERE (t.category = ? OR ? LIKE '%' || t.category || '%')
    """
    params: List[Any] = [category, evidence]
    if current_ticket_id is not None:
        query += " AND t.id != ?"
        params.append(current_ticket_id)
    query += " ORDER BY t.id DESC LIMIT ?"
    params.append(limit)

    rows = c.execute(query, params).fetchall()
    results = []
    for r in rows:
        results.append({
            "ticket_id": r[0],
            "created": r[1],
            "category": r[2],
            "evidence": r[3],
            "action": r[4],
            "status": r[5],
            "resolution_note": r[6],
            "past_analysis": r[7]
        })
    return results


def scan() -> int:
    import shutil
    source = os.environ.get("OPS_WATCH_SOURCE")
    if not source:
        if shutil.which("journalctl"):
            source = DEFAULT_SOURCE
        else:
            # Local machine has no journalctl (macOS); default to remote GPU server journalctl
            source = "ssh -o ConnectTimeout=5 linux-builder journalctl -p warning..alert --since '-5 min' -o cat --no-pager"

    try:
        p = subprocess.run(shlex.split(source), text=True, capture_output=True, timeout=45)
        log_output = p.stdout or ""
    except Exception as e:
        print(f"Log source execution warning: {e}")
        log_output = ""

    c, made = db(), 0
    now = int(time.time())
    for line in log_output.splitlines():
        for category, needles, action in RULES:
            if any(n.lower() in line.lower() for n in needles):
                fp = hashlib.sha256((category + line).encode()).hexdigest()
                before = c.total_changes
                c.execute(
                    "INSERT OR IGNORE INTO tickets(created, category, evidence, action, fingerprint) VALUES(?,?,?,?,?)",
                    (now, category, line[:1800], action, fp),
                )
                if c.total_changes > before:
                    made += 1
                    tid = c.execute("SELECT id FROM tickets WHERE fingerprint=?", (fp,)).fetchone()[0]
                    c.execute(
                        "INSERT INTO worklog(created, ticket_id, kind, body, tags) VALUES(?,?,?,?,?)",
                        (now, tid, "ticket-created", f"Finding detected under category '{category}'", category)
                    )
                break
    # Check for endpoint (PC / OS) changes
    try:
        import endpoint_tracker
        ep_alerts = endpoint_tracker.check_and_update_endpoints()
        made += len(ep_alerts)
    except Exception as e:
        print(f"Endpoint tracking warning: {e}")

    # Check for running process anomalies (top/ps inspection)
    try:
        import process_inspector
        proc_anomalies = process_inspector.inspect_anomalies()
        for pa in proc_anomalies:
            category = "process-anomaly"
            action = "collect-evidence"
            evidence = f"Process Anomaly: PID {pa['pid']} (user: {pa['user']}) - {pa['description']}"
            fp = hashlib.sha256((category + evidence).encode()).hexdigest()
            before = c.total_changes
            c.execute(
                "INSERT OR IGNORE INTO tickets(created, category, evidence, action, fingerprint) VALUES(?,?,?,?,?)",
                (now, category, evidence[:1800], action, fp),
            )
            if c.total_changes > before:
                made += 1
                tid = c.execute("SELECT id FROM tickets WHERE fingerprint=?", (fp,)).fetchone()[0]
                c.execute(
                    "INSERT INTO worklog(created, ticket_id, kind, body, tags) VALUES(?,?,?,?,?)",
                    (now, tid, "process-anomaly", f"Process anomaly detected: {evidence}", "process-anomaly")
                )
    except Exception as e:
        print(f"Process inspection warning: {e}")

    c.commit()
    print(f"scan complete: {made} new ticket(s)")
    return made


def pending() -> None:
    for row in db().execute(
        "SELECT id, datetime(created,'unixepoch','localtime'), category, action, evidence, status FROM tickets WHERE status='pending' ORDER BY id"
    ):
        print(f"#{row[0]} {row[1]} [{row[2]}] proposed={row[3]} status={row[5]}\n  {row[4]}")


def _ssh_host_from_source(source: str) -> Optional[str]:
    """Extract the target host from an `ssh [-o ...] host [cmd...]` source string."""
    try:
        tokens = shlex.split(source)
    except Exception:
        return None
    if not tokens or tokens[0] != "ssh":
        return None
    with_value = {"-o", "-p", "-i", "-F", "-l", "-L", "-R", "-D", "-W",
                  "-b", "-c", "-E", "-e", "-I", "-m", "-O", "-Q", "-S", "-w"}
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok.startswith("-"):
            if tok in with_value:
                i += 2
            else:
                i += 1
            continue
        return tok
    return None


def approve(ticket: int) -> None:
    c = db()
    row = c.execute("SELECT action, status, category, evidence FROM tickets WHERE id=?", (ticket,)).fetchone()
    if not row:
        raise SystemExit("unknown ticket")
    if row[1] != "pending":
        raise SystemExit(f"ticket is already {row[1]}")
    argv = ACTION_ALLOWLIST.get(row[0])
    if not argv:
        raise SystemExit("action is not allowlisted")

    import shutil
    source = os.environ.get("OPS_WATCH_SOURCE", "")
    if not shutil.which(argv[0]):
        if source.startswith("ssh "):
            ssh_host = _ssh_host_from_source(source)
            if not ssh_host:
                raise SystemExit(f"cannot parse ssh host from OPS_WATCH_SOURCE: {source!r}")
            argv = ["ssh", "-o", "ConnectTimeout=5", ssh_host] + argv
        else:
            # Never pretend an action ran. Previously this was replaced by `echo` and the
            # ticket was marked approved anyway, which made the audit trail unreliable.
            raise SystemExit(
                f"action '{row[0]}' cannot run on this host: '{argv[0]}' not found. "
                "Set OPS_WATCH_SOURCE='ssh <host>' or run ops-watch on the server."
            )

    p = subprocess.run(argv, text=True, capture_output=True, timeout=45)
    out = (p.stdout + p.stderr)[-4000:]
    now = int(time.time())

    if p.returncode != 0:
        c.execute("UPDATE tickets SET status='failed', resolved_at=? WHERE id=?", (now, ticket))
        c.execute(
            "INSERT INTO worklog(created, ticket_id, kind, body, tags) VALUES(?,?,?,?,?)",
            (now, ticket, "operator-approval-failed",
             f"Action '{row[0]}' failed (rc={p.returncode}). Output: {out[:800]}", "approval,failed")
        )
        c.commit()
        raise SystemExit(f"action '{row[0]}' failed (rc={p.returncode}): {out[:500]}")

    c.execute("UPDATE tickets SET status='approved', resolved_at=? WHERE id=?", (now, ticket))
    c.execute(
        "INSERT INTO worklog(created, ticket_id, kind, body, tags) VALUES(?,?,?,?,?)",
        (now, ticket, "operator-approval", f"Approved action '{row[0]}'. Result: {out[:500]}", "approval")
    )
    c.commit()
    print(out)
    print(f"approved #{ticket}: {row[0]}")


def note(ticket: int, text: str) -> None:
    c = db()
    row = c.execute("SELECT id FROM tickets WHERE id=?", (ticket,)).fetchone()
    if not row:
        raise SystemExit(f"ticket #{ticket} does not exist")
    now = int(time.time())
    c.execute("UPDATE tickets SET resolution_note=? WHERE id=?", (text, ticket))
    c.execute(
        "INSERT INTO worklog(created, ticket_id, kind, body, tags) VALUES(?,?,?,?,?)",
        (now, ticket, "operator-note", text, "operator-memory")
    )
    c.commit()
    print(f"Recorded note into worklog for ticket #{ticket}: {text}")


def analyze(ticket: int) -> None:
    c = db()
    row = c.execute("SELECT category, evidence, action, status FROM tickets WHERE id=?", (ticket,)).fetchone()
    if not row:
        raise SystemExit("unknown ticket")

    ontology_data = load_ontology()
    bridge = AutoOntologyBridge()
    remote_status = bridge.check_connection()

    # Retrieve agent memory / past precedents
    memory_precedents = search_memory(row[0], row[1], current_ticket_id=ticket, limit=3)

    schema = json.dumps({
        "type": "object",
        "properties": {
            "summary": {"type": "string", "description": "자연스러운 한국어(Korean)로 작성된 종합 분석 내용"},
            "decision_grounds": {"type": "string", "description": "결정 및 위험도 판정에 대한 구체적 근거를 풀어서 한글로 상세 설명"},
            "severity": {"enum": ["info", "warning", "critical"]},
            "needs_approval": {"type": "boolean"},
            "precedent_match": {"type": "string", "description": "과거 선례 매칭 결과 한글 설명"},
            "recommended_action": {"type": "string"}
        },
        "required": ["summary", "decision_grounds", "severity", "needs_approval", "recommended_action"]
    })

    background_str = json.dumps(ontology_data.get("background", {}), ensure_ascii=False)
    terms_str = json.dumps(ontology_data.get("terms", []), ensure_ascii=False)
    patterns_str = json.dumps(ontology_data.get("normal_patterns", []), ensure_ascii=False)
    signals_str = json.dumps(ontology_data.get("incident_signals", []), ensure_ascii=False)
    precedents_str = json.dumps(memory_precedents, ensure_ascii=False)

    prompt = (
        "You are an AI Security Operations Triage Assistant operating with NVIDIA Auto-Ontology integration.\n"
        "=== SYSTEM BACKGROUND ===\n"
        f"{background_str}\n\n"
        "=== SEMANTIC ONTOLOGY & TERMS ===\n"
        f"Terms: {terms_str}\n"
        f"Normal Baselines: {patterns_str}\n"
        f"Threat Signals: {signals_str}\n\n"
        "=== HISTORICAL MEMORY & PRECEDENTS ===\n"
        f"{precedents_str}\n\n"
        "=== TASK ===\n"
        "Analyze this single finding against the background, semantic ontology, and historical memory.\n"
        "Rules:\n"
        "1. Do NOT call any tools, do not invoke commands. Directly generate the final JSON analysis.\n"
        "2. Cross-reference evidence with normal baselines (e.g. PAM/MOTD/Livepatch or VS Code short connects).\n"
        "3. Check whether past precedents resolved this as a benign false positive or confirmed threat.\n"
        "4. 중요: 모든 설명 필드(summary, decision_grounds, precedent_match)는 자연스러운 한국어(Korean)로 작성하고, 결정 근거를 풀어서 명확히 설명하십시오.\n"
        f"Finding: category={row[0]} allowlisted_action={row[2]} evidence={row[1]}\n"
    )

    # Provider fallback chain: agy -> opencode -> openrouter (OPS_WATCH_LLM_CHAIN).
    import analysis_llm
    result = analysis_llm.analyze(prompt, json.loads(schema))
    provider = result["provider"]
    model_used = result.get("model") or "-"
    stored_text = json.dumps(result["data"], ensure_ascii=False, indent=2)

    tags = f"analysis,llm:{provider}"
    if result.get("errors"):
        tags += ",fallback"

    now = int(time.time())
    c.execute(
        "INSERT INTO worklog(created, ticket_id, kind, body, tags) VALUES(?,?,?,?,?)",
        (now, ticket, "llm-analysis", stored_text[-8000:], tags)
    )
    c.commit()
    print(f"[llm:{provider} {model_used}] {stored_text}")


def memory(query: Optional[str] = None) -> None:
    """Query agent memory from past worklog entries and decisions."""
    c = db()
    sql = """
        SELECT w.id, datetime(w.created,'unixepoch','localtime'), w.ticket_id, w.kind, w.body, w.tags
        FROM worklog w
    """
    params: List[Any] = []
    if query:
        sql += " WHERE w.body LIKE ? OR w.tags LIKE ? OR w.kind LIKE ?"
        q = f"%{query}%"
        params.extend([q, q, q])
    sql += " ORDER BY w.id DESC LIMIT 15"

    rows = c.execute(sql, params).fetchall()
    if not rows:
        print("No memory records found.")
        return

    print(f"=== OPERATIONAL MEMORY ({len(rows)} record(s)) ===")
    for r in rows:
        ticket_str = f"Ticket #{r[2]}" if r[2] else "General"
        print(f"[{r[1]}] [{ticket_str}] [{r[3]}] (tags: {r[5] or 'none'})")
        body_summary = r[4].strip()
        if len(body_summary) > 200:
            body_summary = body_summary[:200] + "..."
        print(f"  {body_summary}\n")


def worklog(limit: int = 15, export_md: bool = False) -> None:
    """View durable worklog or export to WORKLOG.md."""
    c = db()
    rows = c.execute(
        """SELECT w.id, datetime(w.created,'unixepoch','localtime'), w.ticket_id, w.kind, w.body
           FROM worklog w ORDER BY w.id DESC LIMIT ?""",
        (limit,)
    ).fetchall()

    if export_md:
        lines = [
            "# 운영 업무기록 (Durable Worklog)\n",
            "이 문서는 `state/ops-watch.db`의 운영 판단·승인·분석 이력을 요약합니다.\n",
            "## 최근 운영 로그\n"
        ]
        for r in rows:
            lines.append(f"### {r[1]} — {r[3]} (Ticket #{r[2]})")
            lines.append(f"```text\n{r[4]}\n```\n")
        WORKLOG_FILE.write_text("\n".join(lines), encoding="utf-8")
        print(f"Updated {WORKLOG_FILE}")
        return

    print(f"=== DURABLE WORKLOG (Last {len(rows)}) ===")
    for r in rows:
        print(f"[{r[1]}] #{r[0]} (Ticket #{r[2]}) [{r[3]}]:\n  {r[4][:250]}")


def ontology_cmd(sync_remote: bool = False, export_ossie: bool = False) -> None:
    bridge = AutoOntologyBridge()
    conn = bridge.check_connection()
    print("=== NVIDIA AUTO-ONTOLOGY INTEGRATION ===")
    print(f"Status: {json.dumps(conn, indent=2, ensure_ascii=False)}")

    if export_ossie:
        ossie = bridge.export_ossie_model()
        print("\n=== EXPORTED APACHE OSSIE / AUTO-ONTOLOGY MODEL ===")
        print(json.dumps(ossie, indent=2, ensure_ascii=False))
        return

    terms = bridge.get_terms()
    print(f"\nLoaded {len(terms)} Semantic Term(s):")
    for t in terms:
        print(f"- {t.get('name')}: {t.get('description')[:80]}...")


def main() -> None:
    ap = argparse.ArgumentParser(description="ops-watch with Auto-Ontology & Memory")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan")
    sub.add_parser("pending")

    a = sub.add_parser("approve")
    a.add_argument("ticket", type=int)

    n = sub.add_parser("analyze")
    n.add_argument("ticket", type=int)

    m = sub.add_parser("memory")
    m.add_argument("query", nargs="?", default=None, help="Search query for memory")

    w = sub.add_parser("worklog")
    w.add_argument("--limit", type=int, default=15)
    w.add_argument("--export", action="store_true", help="Sync into WORKLOG.md")

    nt = sub.add_parser("note")
    nt.add_argument("ticket", type=int)
    nt.add_argument("text", type=str)

    o = sub.add_parser("ontology")
    o.add_argument("--sync-remote", action="store_true")
    o.add_argument("--export-ossie", action="store_true")

    wb = sub.add_parser("web")
    wb.add_argument("--port", type=int, default=8080)

    args = ap.parse_args()
    actions = {
        "scan": scan,
        "pending": pending,
        "approve": lambda: approve(args.ticket),
        "analyze": lambda: analyze(args.ticket),
        "memory": lambda: memory(args.query),
        "worklog": lambda: worklog(args.limit, args.export),
        "note": lambda: note(args.ticket, args.text),
        "ontology": lambda: ontology_cmd(args.sync_remote, args.export_ossie),
        "web": lambda: __import__("dashboard").run_server(args.port),
    }
    actions[args.cmd]()


if __name__ == "__main__":
    main()
