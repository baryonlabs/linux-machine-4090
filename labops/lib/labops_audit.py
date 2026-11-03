"""Minimal ausearch wrapper: run `ausearch --raw` and group records into events."""
import os
import re
import subprocess
import time

REC_RE = re.compile(r"^type=(\S+) msg=audit\((\d+)\.\d+:(\d+)\): ?(.*)$")
KV_RE = re.compile(r'(\w+)=("([^"]*)"|\S+)')


def _kv(body):
    body = body.split("\x1d", 1)[0]  # drop ENRICHED trailer
    return {m.group(1): (m.group(3) if m.group(3) is not None else m.group(2)) for m in KV_RE.finditer(body)}


def ausearch_start(seconds_ago):
    """ausearch --start expects the locale's %x %X; we always run with LC_ALL=C."""
    t = time.localtime(time.time() - seconds_ago)
    return [time.strftime("%x", t), time.strftime("%X", t)]


def search(key=None, start=None, checkpoint=None, extra=None, timeout=300):
    """Return list of events: dict(ts, serial, types:set, syscall:{...}, records:[(type, kv)])."""
    cmd = ["ausearch", "--raw", "--input-logs"]
    if key:
        cmd += ["-k", key]
    if start:
        cmd += ["--start"] + (start if isinstance(start, list) else [start])
    if checkpoint:
        cmd += ["--checkpoint", checkpoint]
    if extra:
        cmd += extra
    env = {**os.environ, "LC_ALL": "C"}
    p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
    if checkpoint and p.returncode in (10, 11, 12):  # bad/stale checkpoint → reset
        try:
            os.unlink(checkpoint)
        except OSError:
            pass
        retry = cmd if start else cmd + ["--start", "recent"]
        p = subprocess.run(retry, capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
    events = {}
    for ln in p.stdout.splitlines():
        m = REC_RE.match(ln)
        if not m:
            continue
        typ, ts, serial, body = m.group(1), int(m.group(2)), m.group(3), m.group(4)
        ev = events.setdefault((ts, serial), {"ts": ts, "serial": serial, "types": set(), "syscall": {}, "records": []})
        kv = _kv(body)
        ev["types"].add(typ)
        ev["records"].append((typ, kv))
        if typ == "SYSCALL":
            ev["syscall"] = kv
    return sorted(events.values(), key=lambda e: (e["ts"], e["serial"])), p.returncode
