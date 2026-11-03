#!/usr/bin/env python3
"""Request-queue flow test in temp dirs (no root, no systemd, no Discord). Linux only (SO_PEERCRED).
Covers: peer-uid identity, submit validation, rate limit, cancel, labctl approve/reject decision files,
executor hash check / ownership check / reject / other / invalid files / expiry."""
import importlib.machinery
import importlib.util
import json
import os
import pwd
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "lib"))


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux only")
class QueueFlow(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="labops-q-")
        me = pwd.getpwuid(os.getuid())
        d = {k: os.path.join(self.t, k) for k in ("requests", "decisions", "decisions.tmp", "processed")}
        for p in d.values():
            os.makedirs(p)
        self.confpath = os.path.join(self.t, "labops.conf")
        with open(self.confpath, "w") as f:
            f.write(f"ADMIN_USER={me.pw_name}\nREQ_DIR={d['requests']}\nREQ_DECISIONS={d['decisions']}\n"
                    f"REQ_DECISIONS_TMP={d['decisions.tmp']}\nREQ_PROCESSED={d['processed']}\n"
                    f"REQ_LOG={self.t}/requests.log\nREQ_EXTRA_UIDS={os.getuid()}\nREQ_MAX_PENDING=2\n"
                    f"WEBHOOK_FILE={self.t}/nohook\nSTUDENTS_GROUP=students\n")
        os.environ["LABOPS_CONF"] = self.confpath
        import labops_common as C
        C.CONF_PATH = self.confpath
        self.C = C
        self.conf = C.load_conf(self.confpath)
        self.reqd = load(os.path.join(ROOT, "bin", "labops-reqd"), "reqd")
        self.exe = load(os.path.join(ROOT, "bin", "labops-executor"), "exe")
        self.me = me

    def labctl(self, *args):
        return subprocess.run([sys.executable, os.path.join(ROOT, "labctl"), *args], capture_output=True, text=True,
                              env={**os.environ, "LABOPS_CONF": self.confpath})

    def test_peercred(self):
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        uid, pid = self.reqd.peer_uid(a)
        self.assertEqual(uid, os.getuid())
        self.assertEqual(self.reqd.allowed(self.conf, uid), self.me.pw_name)  # via REQ_EXTRA_UIDS
        a.close(), b.close()

    def test_flow(self):
        h = lambda m: self.reqd.handle(self.conf, os.getuid(), self.me.pw_name, m)  # noqa: E731
        self.assertFalse(h({"op": "submit", "action": "apt-install", "args": ["-oAPT::x"], "reason": "test"})["ok"])
        self.assertFalse(h({"op": "submit", "action": "apt-install", "args": ["nvidia-utils-595"], "reason": "test"})["ok"])
        self.assertFalse(h({"op": "submit", "action": "apt-install", "args": ["cowsay"], "reason": ""})["ok"])
        self.assertFalse(h({"op": "submit", "action": "rm -rf", "reason": "xxxx"})["ok"])
        r1 = h({"op": "submit", "action": "apt-install", "args": ["cowsay", "sl"], "reason": "fun @everyone"})
        r2 = h({"op": "submit", "action": "other", "reason": "please mount the NAS share"})
        self.assertTrue(r1["ok"] and r2["ok"], (r1, r2))
        self.assertIn("pending requests", h({"op": "submit", "action": "other", "reason": "third"})["error"])  # rate limit
        st = h({"op": "status"})
        self.assertEqual([r["id"] for r in st["requests"]], [r1["id"], r2["id"]])
        # someone else's id is invisible / not cancellable
        self.assertFalse(self.reqd.handle(self.conf, 99999, "x", {"op": "cancel", "id": r1["id"]})["ok"])
        self.assertFalse(self.reqd.handle(self.conf, 99999, "x", {"op": "status", "id": r1["id"]})["ok"])

        # labctl lists and decides (as the admin user = current user here)
        out = self.labctl("requests")
        self.assertIn(f"#{r1['id']}", out.stdout, out.stderr)
        self.assertEqual(self.labctl("reject", str(r2["id"]), "--reason", "do it yourself").returncode, 0)
        dfile = os.path.join(self.conf["REQ_DECISIONS"], f"{r2['id']}.json")
        self.assertTrue(os.path.exists(dfile))
        self.assertEqual(os.listdir(self.conf["REQ_DECISIONS_TMP"]), [])
        # tampered request: change args after the decision → hash mismatch → invalid, stays pending
        dec = {"id": r1["id"], "decision": "approve", "sha256": "0" * 64, "ts": int(time.time())}
        with open(os.path.join(self.conf["REQ_DECISIONS"], f"{r1['id']}.json"), "w") as f:
            json.dump(dec, f)
        with open(os.path.join(self.conf["REQ_DECISIONS"], "evil.json"), "w") as f:
            f.write("{}")
        self.exe.process_decisions(self.conf)
        self.assertEqual(os.listdir(self.conf["REQ_DECISIONS"]), [])  # always drained
        R = self.exe.R
        self.assertEqual(R.load_request(self.conf, r2["id"])["status"], "rejected")
        self.assertEqual(R.load_request(self.conf, r1["id"])["status"], "pending")
        proc = os.listdir(self.conf["REQ_PROCESSED"])
        self.assertEqual(sum(p.endswith(".invalid") for p in proc), 2, proc)
        # cancel own pending
        self.assertTrue(h({"op": "cancel", "id": r1["id"]})["ok"])
        self.assertEqual(R.load_request(self.conf, r1["id"])["status"], "cancelled")
        # 'other' approval = acknowledged, never executed
        r3 = h({"op": "submit", "action": "other", "reason": "need port 8888 opened"})
        self.assertEqual(self.labctl("approve", str(r3["id"])).returncode, 0)
        self.exe.process_decisions(self.conf)
        self.assertEqual(R.load_request(self.conf, r3["id"])["status"], "acknowledged")
        # expiry
        r4 = h({"op": "submit", "action": "other", "reason": "old one"})
        req = R.load_request(self.conf, r4["id"])
        req["ts"] -= 8 * 86400
        req["sha256"] = R.core_hash(req)
        R.write_request(self.conf, req)
        self.exe.expire(self.conf)
        self.assertEqual(R.load_request(self.conf, r4["id"])["status"], "expired")
        # history
        self.assertIn("rejected", self.labctl("requests", "--history").stdout)

    def test_approve_refuses_invalid_apt(self):
        if not os.path.exists("/usr/bin/apt-cache"):
            self.skipTest("no apt")
        h = lambda m: self.reqd.handle(self.conf, os.getuid(), self.me.pw_name, m)  # noqa: E731
        r = h({"op": "submit", "action": "apt-install", "args": ["htop"], "reason": "already installed test"})
        out = self.labctl("approve", str(r["id"]))
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("already installed", out.stdout + out.stderr)
        r = h({"op": "submit", "action": "apt-install", "args": ["cowsay"], "reason": "valid"})
        out = self.labctl("approve", str(r["id"]))
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("OK: would install 1 package(s): cowsay", out.stdout)


if __name__ == "__main__":
    unittest.main()
