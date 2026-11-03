"""Privileged-request queue: storage format shared by labops-reqd, labops-executor and labctl.

Trust model
  requests/<id>.json   written ONLY by labops-reqd (user `labops`, uid from SO_PEERCRED) and
                       labops-executor (root). Dir labops:<admin-group> 2750 → admin can read, not write.
  decisions/<id>.json  written ONLY by the admin user (martin, no sudo needed). Dir <admin>:<admin> 0700.
                       A decision only references a request id + sha256 of the request core;
                       the executor never takes the action/args from the decision file.
  The executor re-validates every apt-install against a fixed catalog, so admin approval
  can only ever result in installing Ubuntu-archive packages that pass validation.
"""
import fcntl
import hashlib
import json
import os
import re
import time

CORE_FIELDS = ("id", "uid", "user", "ts", "action", "args", "reason")
ACTIONS = ("apt-install", "other")
FINAL_STATES = ("done", "failed", "rejected", "cancelled", "expired", "acknowledged")
ID_FILE_RE = re.compile(r"^(\d{1,9})\.json$")


def core_hash(req):
    core = {k: req.get(k) for k in CORE_FIELDS}
    return hashlib.sha256(json.dumps(core, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def req_path(conf, rid):
    return os.path.join(conf["REQ_DIR"], f"{int(rid)}.json")


def load_request(conf, rid):
    p = req_path(conf, rid)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as f:
        st = os.fstat(f.fileno())
        if st.st_size > 256 * 1024:
            raise ValueError("request file too large")
        return json.load(f)


def list_requests(conf):
    out = []
    try:
        names = os.listdir(conf["REQ_DIR"])
    except OSError:
        return out
    for n in names:
        m = ID_FILE_RE.match(n)
        if not m:
            continue
        try:
            out.append(load_request(conf, int(m.group(1))))
        except (OSError, ValueError):
            continue
    out.sort(key=lambda r: int(r.get("id", 0)))
    return out


class Lock:
    """flock on REQ_DIR/.lock (shared by reqd and executor)."""

    def __init__(self, conf):
        self.path = os.path.join(conf["REQ_DIR"], ".lock")
        self.fd = None

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


def next_id(conf):
    p = os.path.join(conf["REQ_DIR"], ".seq")
    try:
        with open(p) as f:
            n = int(f.read().strip() or 0)
    except (OSError, ValueError):
        n = 0
    n += 1
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(n))
    os.rename(tmp, p)
    return n


def write_request(conf, req, uid=-1, gid=-1):
    from labops_common import atomic_write
    atomic_write(req_path(conf, req["id"]), json.dumps(req, indent=1, sort_keys=True) + "\n",
                 mode=0o640, uid=uid, gid=gid)


def append_log(conf, line):
    try:
        with open(conf["REQ_LOG"], "a") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%S%z ") + line.replace("\n", " ") + "\n")
    except OSError:
        pass


def fmt_request(r, width=60):
    args = " ".join(r.get("args") or []) if r.get("action") == "apt-install" else ""
    what = f"apt-install {args}" if args else (r.get("reason") or "")
    if len(what) > width:
        what = what[: width - 3] + "..."
    return f"#{r['id']:<4} {r.get('user', '?'):<14} {r.get('status', '?'):<12} " \
           f"{time.strftime('%m-%d %H:%M', time.localtime(r.get('ts', 0)))}  {what}"
