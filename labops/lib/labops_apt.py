"""Validation of `apt-install` requests (privileged-request queue).

Pure parsing functions are unit-tested offline against captured server output
(tests/fixtures). `validate()` runs `apt-cache policy` and `apt-get -s install`,
both of which work without root.
"""
import fnmatch
import re
import subprocess
from urllib.parse import urlparse

PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]{1,62}$")

# Never installable through the queue — neither requested nor pulled in as a dependency.
DENY_PATTERNS = [
    "linux-*", "nvidia-*", "libnvidia-*", "cuda-*", "libcuda*", "*-dkms", "dkms",
    "xserver-xorg-video-nvidia*", "openssh-*", "ssh", "sudo", "sudo-*", "doas", "opendoas",
    "docker*", "containerd*", "runc", "podman*", "lxd*", "tailscale*", "headscale*",
    "systemd*", "libpam-*", "libnss-*", "ufw", "iptables*", "nftables", "firewalld",
    "auditd", "audispd*", "acct", "falco*", "lynis", "apparmor*", "selinux*",
    "grub*", "shim*", "initramfs-tools*", "dracut*", "ubuntu-pro*", "snapd",
    "unattended-upgrades", "apt", "apt-*", "dpkg*", "cron", "anacron", "at",
    "polkitd*", "pkexec", "policykit-*", "login", "passwd", "shadow", "util-linux",
    "mount", "kmod", "bpf*", "bpftrace", "ngrok*", "*-ppa",
]

ALLOWED_SUITES = {"noble", "noble-updates", "noble-security", "noble-backports"}
ALLOWED_COMPONENTS = {"main", "restricted", "universe", "multiverse"}


def denied(name):
    base = name.split(":", 1)[0]
    return [p for p in DENY_PATTERNS if fnmatch.fnmatchcase(base, p)]


def parse_policy(text):
    """Parse `apt-cache policy <pkg>` output for ONE package.
    Returns dict(found, installed, candidate, sources=[(prio, url, suite/component)] for candidate)."""
    res = {"found": False, "installed": None, "candidate": None, "candidate_sources": []}
    lines = text.splitlines()
    if not any(re.match(r"^\S+:\s*$", ln) for ln in lines):
        return res
    res["found"] = True
    in_table, cur_ver = False, None
    for ln in lines:
        m = re.match(r"^\s+Installed:\s*(.+)$", ln)
        if m:
            res["installed"] = None if m.group(1).strip() == "(none)" else m.group(1).strip()
            continue
        m = re.match(r"^\s+Candidate:\s*(.+)$", ln)
        if m:
            res["candidate"] = None if m.group(1).strip() == "(none)" else m.group(1).strip()
            continue
        if re.match(r"^\s+Version table:", ln):
            in_table = True
            continue
        if not in_table:
            continue
        m = re.match(r"^\s(?:\*\*\*|   )\s(\S+)\s+(-?\d+)\s*$", ln)
        if m:
            cur_ver = m.group(1)
            continue
        m = re.match(r"^\s+(-?\d+)\s+(\S+)(?:\s+(\S+))?(?:\s+\S+\s+Packages)?\s*$", ln)
        if m and cur_ver is not None and cur_ver == res["candidate"]:
            res["candidate_sources"].append((int(m.group(1)), m.group(2), m.group(3) or ""))
    return res


def source_allowed(url, dist, allowed_hosts):
    if url == "/var/lib/dpkg/status":
        return None  # installed copy, neutral
    u = urlparse(url)
    if u.scheme not in ("http", "https") or u.hostname not in allowed_hosts:
        return False
    if not u.path.rstrip("/").endswith("/ubuntu"):
        return False
    suite, _, comp = dist.partition("/")
    return suite in ALLOWED_SUITES and comp in ALLOWED_COMPONENTS


def check_policy(pkg, policy, allowed_hosts):
    errs = []
    if not policy["found"]:
        return ["package not found in apt index"]
    if policy["candidate"] is None:
        return ["no installation candidate (virtual or unavailable package)"]
    if policy["installed"] is not None:
        errs.append(f"already installed ({policy['installed']})")
    srcs = [s for s in policy["candidate_sources"] if s[1] != "/var/lib/dpkg/status"]
    if not srcs:
        errs.append("candidate has no archive source")
    for _, url, dist in srcs:
        if not source_allowed(url, dist, allowed_hosts):
            errs.append(f"candidate comes from non-Ubuntu source {url} {dist}")
    return errs


SIM_INST = re.compile(r"^Inst (\S+)(?: \[([^\]]+)\])? \((\S+) (.+?) \[[^\]]+\]\)")
SIM_REMV = re.compile(r"^Remv (\S+)")


def parse_sim(text):
    """Parse `apt-get -s install` output → dict(inst=[(pkg, oldver|None, newver, origins)], remv=[pkg], errors=[...])."""
    out = {"inst": [], "remv": [], "errors": []}
    for ln in text.splitlines():
        m = SIM_INST.match(ln)
        if m:
            origins = [o.strip() for o in m.group(4).split(",")]
            out["inst"].append((m.group(1), m.group(2), m.group(3), origins))
            continue
        m = SIM_REMV.match(ln)
        if m:
            out["remv"].append(m.group(1))
            continue
        if ln.startswith("E: "):
            out["errors"].append(ln[3:])
    return out


def check_sim(sim, max_new=80):
    errs = []
    errs += [f"apt error: {e}" for e in sim["errors"]]
    if sim["remv"]:
        errs.append("simulation REMOVES packages: " + ", ".join(sim["remv"][:10]))
    ups = [p for p, old, _, _ in sim["inst"] if old]
    if ups:
        errs.append("simulation UPGRADES installed packages: " + ", ".join(ups[:10]))
    bad = sorted({p for p, _, _, _ in sim["inst"] if denied(p)})
    if bad:
        errs.append("pulls deny-listed packages: " + ", ".join(bad[:10]))
    foreign = sorted({p for p, _, _, origins in sim["inst"] if not all(o.startswith("Ubuntu:24.04/") for o in origins)})
    if foreign:
        errs.append("pulls packages from non-Ubuntu origins: " + ", ".join(foreign[:10]))
    if len(sim["inst"]) > max_new:
        errs.append(f"too many new packages ({len(sim['inst'])} > {max_new})")
    if not sim["inst"] and not errs:
        errs.append("nothing to install")
    return errs


def _run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                       timeout=180)
    return p.returncode, p.stdout + p.stderr


def validate(pkgs, allowed_hosts, max_packages=20, max_new=80):
    """Full validation. Returns (ok, errors, sim_dict). Safe to run unprivileged."""
    errs = []
    if not pkgs:
        return False, ["no packages given"], None
    if len(pkgs) > max_packages:
        return False, [f"too many packages ({len(pkgs)} > {max_packages})"], None
    if len(set(pkgs)) != len(pkgs):
        errs.append("duplicate package names")
    for p in pkgs:
        if not PKG_RE.match(p):
            errs.append(f"{p!r}: invalid package name")
            continue
        d = denied(p)
        if d:
            errs.append(f"{p}: deny-listed ({d[0]})")
            continue
        _, out = _run(["apt-cache", "policy", p])
        errs += [f"{p}: {e}" for e in check_policy(p, parse_policy(out), allowed_hosts)]
    if errs:
        return False, errs, None
    _, out = _run(["apt-get", "install", "-s", "--no-install-recommends"] + list(pkgs))
    sim = parse_sim(out)
    errs += check_sim(sim, max_new)
    return not errs, errs, sim
