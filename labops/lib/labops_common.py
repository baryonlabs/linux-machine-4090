"""Shared helpers for labops (stdlib only — no pip deps on the server).

- config:   /etc/labops/labops.conf  (KEY=VALUE, shell-compatible)
- registry: /etc/labops/users.yaml   (restricted YAML subset, see parse_registry)
- discord:  webhook URL read from /etc/labops/discord-webhook.url (never logged)
"""
import grp
import json
import os
import pwd
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

os.environ["LC_ALL"] = "C"

CONF_PATH = os.environ.get("LABOPS_CONF", "/etc/labops/labops.conf")

DEFAULTS = {
    "ADMIN_USER": "martin",
    "REGISTRY": "/etc/labops/users.yaml",
    "WEBHOOK_FILE": "/etc/labops/discord-webhook.url",
    "SSHD_ALLOWUSERS_FILE": "/etc/ssh/sshd_config.d/99-user-manager-hardening.conf",
    "SSH_PORT": "2322",
    "SSH_HOST": "100.64.0.2",
    "DATA_ROOT": "/mnt/data/users",
    "STUDENT_GROUPS": "video,render,users,students",
    "STUDENTS_GROUP": "students",
    "HS_CONTAINER": "headscale",
    "HS_ACL": "/home/martin/headscale/config/acl.hujson",
    "HS_ACL_IN_CONTAINER": "/etc/headscale/acl.hujson",
    "HS_LOGIN_SERVER": os.environ.get("LABOPS_HS_LOGIN_SERVER", "https://<headscale-tunnel-host>"),
    "HS_HEALTH_URL": "http://127.0.0.1:9080/health",
    "HS_KEY_EXPIRY": "1440h",
    "STATE_DIR": "/var/lib/labops",
    "LOG_DIR": "/var/log/labops",
    "BACKUP_DIR": "/var/backups/labops",
    "GPU_DB": "/var/lib/labops/gpu.db",
    "GPU_INTERVAL_S": "60",
    "GPU_ALERT_HIGH_PCT": "50",      # notify when utilization >= this ...
    "GPU_ALERT_HIGH_SAMPLES": "2",   # ... for N consecutive 1-min samples
    "GPU_ALERT_IDLE_SAMPLES": "3",   # notify "back to 0%" after N consecutive 0% samples
    "GPU_ALERT_STATE": "/var/lib/labops/gpu-alert.json",
    "SESSION_NOTIFY": "1",           # Discord on SSH login/logout (pam_exec hook)
    "SESSION_NOTIFY_ADMIN": "0",     # 1 = also notify the admin's own sessions (noisy with automation)
    "SESSION_STATE_DIR": "/run/labops/sessions",
    "SESSION_DEDUP_S": "30",
    "FALCO_LIST_FILE": "/etc/falco/rules.d/labops_00_students.yaml",
    "AUDIT_STUDENT_RULES": "/etc/audit/rules.d/51-labops-students.rules",
    "AUDIT_SETUID_RULES": "/etc/audit/rules.d/52-labops-setuid.rules",
    "REQ_DIR": "/var/lib/labops/requests",
    "REQ_DECISIONS": "/var/lib/labops/decisions",
    "REQ_DECISIONS_TMP": "/var/lib/labops/decisions.tmp",
    "REQ_PROCESSED": "/var/lib/labops/decisions-processed",
    "REQ_SOCKET": "/run/labops/req.sock",
    "REQ_LOG": "/var/log/labops/requests.log",
    "REQ_MAX_PENDING": "5",
    "REQ_EXPIRY_DAYS": "7",
    "REQ_MAX_PACKAGES": "20",
    "REQ_MAX_NEW_PACKAGES": "80",
    "REQ_EXTRA_UIDS": "",  # extra uids (besides students) allowed to submit, e.g. admin for testing
    "APT_ALLOWED_HOSTS": "archive.ubuntu.com,security.ubuntu.com,kr.archive.ubuntu.com,mirror.kakao.com",
}


def load_conf(path=None):
    conf = dict(DEFAULTS)
    path = path or CONF_PATH
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                    v = v[1:-1]
                conf[k.strip()] = v
    except FileNotFoundError:
        pass
    return conf


# ----------------------------------------------------------------------------- registry
# Supported subset:
#   users:
#     - name: foo            # comment
#       full_name: "Foo Bar"
#       expires: 2027-01-04
#       headscale: true
#       ssh_pubkey: null
# Scalars only (str / bool / null / int). Quoted strings may contain '#'.

_KEY_RE = re.compile(r"^(\s*)(-\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$")


def _strip_comment(v):
    out, q = [], None
    for ch in v:
        if q:
            out.append(ch)
            if ch == q:
                q = None
        elif ch in "\"'":
            q = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out).strip()


def _scalar(v):
    v = _strip_comment(v)
    if v == "" or v in ("null", "~", "Null", "NULL"):
        return None
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        s = v[1:-1]
        if v[0] == '"':
            s = s.replace('\\"', '"').replace("\\\\", "\\")
        return s
    if v in ("true", "True", "yes"):
        return True
    if v in ("false", "False", "no"):
        return False
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    return v


def parse_registry(text):
    users, cur, in_users = [], None, False
    for n, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if re.match(r"^users\s*:\s*(#.*)?$", raw):
            in_users = True
            continue
        if not in_users:
            continue
        m = _KEY_RE.match(raw)
        if not m:
            raise ValueError(f"users.yaml:{n}: cannot parse: {raw!r}")
        _, dash, key, val = m.groups()
        if dash:
            cur = {}
            users.append(cur)
        if cur is None:
            raise ValueError(f"users.yaml:{n}: key outside of a '- name:' item")
        cur[key] = _scalar(val)
    names = set()
    for u in users:
        if not u.get("name") or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", str(u["name"])):
            raise ValueError(f"invalid user name: {u.get('name')!r}")
        if u["name"] in names:
            raise ValueError(f"duplicate user: {u['name']}")
        names.add(u["name"])
        u.setdefault("role", "student")
        u.setdefault("state", "active")
        u.setdefault("headscale", False)
        u.setdefault("gpu", True)
        if u["role"] not in ("student", "admin"):
            raise ValueError(f"{u['name']}: role must be student|admin")
        if u["state"] not in ("active", "locked", "removed"):
            raise ValueError(f"{u['name']}: state must be active|locked|removed")
        if u.get("expires") is not None and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(u["expires"])):
            raise ValueError(f"{u['name']}: expires must be YYYY-MM-DD or null")
        k = u.get("ssh_pubkey")
        if k is not None and not re.fullmatch(r"(ssh-(ed25519|rsa)|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh.com) [A-Za-z0-9+/=]+( [^\n]*)?", k):
            raise ValueError(f"{u['name']}: ssh_pubkey does not look like an OpenSSH public key")
    return users


def load_registry(path):
    with open(path) as f:
        return parse_registry(f.read())


def registry_set_field(text, user, field, value):
    """Return text with `field: value` set inside the block of `user` (line-based, keeps comments)."""
    lines = text.splitlines(keepends=True)
    start = end = None
    for i, raw in enumerate(lines):
        m = _KEY_RE.match(raw)
        if m and m.group(2):  # new item
            if start is not None and end is None:
                end = i
            if m.group(3) == "name" and _scalar(m.group(4)) == user:
                start = i
    if start is None:
        raise KeyError(user)
    end = end or len(lines)
    indent = re.match(r"^(\s*)-\s+", lines[start]).group(1) + "  "
    rendered = "null" if value is None else (("true" if value else "false") if isinstance(value, bool) else str(value))
    for i in range(start, end):
        m = _KEY_RE.match(lines[i])
        if m and m.group(3) == field:
            comment = ""
            cm = re.search(r"\s+#.*$", lines[i].rstrip("\n"))
            if cm and _strip_comment(m.group(4)) != m.group(4).strip():
                comment = cm.group(0)
            prefix = lines[i][: m.start(3)]
            lines[i] = f"{prefix}{field}: {rendered}{comment}\n"
            return "".join(lines)
    # insert after last non-blank line of the block
    j = end
    while j > start + 1 and not lines[j - 1].strip():
        j -= 1
    lines.insert(j, f"{indent}{field}: {rendered}\n")
    return "".join(lines)


# ----------------------------------------------------------------------------- users / groups
def user_exists(name):
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def group_members(group):
    try:
        g = grp.getgrnam(group)
    except KeyError:
        return []
    members = set(g.gr_mem)
    for p in pwd.getpwall():
        if p.pw_gid == g.gr_gid:
            members.add(p.pw_name)
    return sorted(members)


def user_in_group(name, group):
    try:
        p = pwd.getpwnam(name)
        g = grp.getgrnam(group)
    except KeyError:
        return False
    return g.gr_gid in os.getgrouplist(name, p.pw_gid)


def uid_name(uid):
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError):
        return str(uid)


# ----------------------------------------------------------------------------- discord
def _webhook(conf):
    path = conf["WEBHOOK_FILE"]
    try:
        with open(path) as f:
            url = f.read().strip()
    except OSError:
        return None
    if not re.match(r"^https://(discord\.com|discordapp\.com|ptb\.discord\.com|canary\.discord\.com)/api/webhooks/", url):
        return None
    return url


def split_message(text, limit=1900):
    chunks, cur = [], ""
    for line in text.splitlines():
        while len(line) > limit:
            if cur:
                chunks.append(cur)
                cur = ""
            chunks.append(line[:limit])
            line = line[limit:]
        if len(cur) + len(line) + 1 > limit:
            chunks.append(cur)
            cur = ""
        cur = f"{cur}\n{line}" if cur else line
    if cur:
        chunks.append(cur)
    return chunks or [""]


def discord_post(text, conf=None, username="labops"):
    """Post text (split into <=1900-char chunks). Returns True on success. Never prints the URL."""
    conf = conf or load_conf()
    url = _webhook(conf)
    if not url:
        log("discord: webhook file missing/invalid — message not sent", err=True)
        return False
    ok = True
    for chunk in split_message(text):
        body = json.dumps({
            "content": chunk,
            "username": username,
            "allowed_mentions": {"parse": []},  # never ping @everyone/@here from user-controlled text
        }).encode()
        for attempt in range(4):
            req = urllib.request.Request(url, data=body, method="POST", headers={
                "Content-Type": "application/json", "User-Agent": "labops/1.0 (+gpu-server)"})
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    r.read()
                break
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    try:
                        wait = float(json.loads(e.read() or b"{}").get("retry_after", 2))
                    except ValueError:
                        wait = 2
                    time.sleep(min(wait, 30))
                    continue
                log(f"discord: HTTP {e.code}", err=True)
                ok = False
                break
            except (urllib.error.URLError, OSError) as e:
                log(f"discord: {type(e).__name__}", err=True)
                time.sleep(2)
        else:
            ok = False
        time.sleep(0.4)
    return ok


# ----------------------------------------------------------------------------- misc
def log(msg, err=False):
    print(msg, file=sys.stderr if err else sys.stdout, flush=True)


def run(cmd, check=False, timeout=None, input=None):
    """Run a command (list). Returns CompletedProcess with text output; never raises on missing binary."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout,
                              input=input, env={**os.environ, "LC_ALL": "C"})
    except FileNotFoundError:
        return subprocess.CompletedProcess(cmd, 127, "", f"{cmd[0]}: not found")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", f"{cmd[0]}: timeout")


def sanitize_text(s, maxlen):
    s = "".join(ch if (ch.isprintable() or ch == " ") else " " for ch in str(s))
    s = re.sub(r"\s+", " ", s).strip()
    return s[:maxlen]


def atomic_write(path, data, mode=0o640, uid=-1, gid=-1, tmpdir=None):
    d = tmpdir or os.path.dirname(path)
    tmp = os.path.join(d, f".{os.path.basename(path)}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if uid != -1 or gid != -1:
            os.chown(tmp, uid, gid)
        os.chmod(tmp, mode)
        os.rename(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
