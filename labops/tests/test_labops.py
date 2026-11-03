#!/usr/bin/env python3
"""Offline unit tests. Run: python3 -m unittest discover -s labops/tests -v
Fixtures were captured on the server (as martin) with apt-cache policy / apt-get -s."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
import labops_apt as A  # noqa: E402
import labops_common as C  # noqa: E402

HOSTS = {"archive.ubuntu.com", "security.ubuntu.com", "mirror.kakao.com"}


def fx(name):
    with open(os.path.join(HERE, "fixtures", name)) as f:
        return f.read()


class PolicyTests(unittest.TestCase):
    def test_cowsay_ok(self):
        p = A.parse_policy(fx("policy_cowsay.txt"))
        self.assertTrue(p["found"])
        self.assertIsNone(p["installed"])
        self.assertEqual(p["candidate"], "3.03+dfsg2-8")
        self.assertEqual(A.check_policy("cowsay", p, HOSTS), [])

    def test_installed_rejected(self):
        p = A.parse_policy(fx("policy_htop.txt"))
        errs = A.check_policy("htop", p, HOSTS)
        self.assertTrue(any("already installed" in e for e in errs), errs)

    def test_third_party_rejected(self):
        p = A.parse_policy(fx("policy_doppler.txt"))
        errs = A.check_policy("doppler", p, HOSTS)
        self.assertTrue(any("non-Ubuntu source" in e for e in errs), errs)
        p = A.parse_policy(fx("policy_docker-ce.txt"))
        self.assertTrue(any("non-Ubuntu source" in e for e in A.check_policy("docker-ce", p, HOSTS)))

    def test_missing_and_virtual(self):
        self.assertEqual(A.check_policy("x", A.parse_policy(fx("policy_nosuchpkg-xyz.txt")), HOSTS),
                         ["package not found in apt index"])
        errs = A.check_policy("mta", A.parse_policy(fx("policy_mail-transport-agent.txt")), HOSTS)
        self.assertTrue(errs and "no installation candidate" in errs[0])

    def test_mirror_not_allowed_if_host_unknown(self):
        p = A.parse_policy(fx("policy_cowsay.txt"))
        self.assertTrue(A.check_policy("cowsay", p, {"archive.ubuntu.com"}))

    def test_source_allowed(self):
        self.assertTrue(A.source_allowed("http://mirror.kakao.com/ubuntu", "noble/universe", HOSTS))
        self.assertTrue(A.source_allowed("http://security.ubuntu.com/ubuntu", "noble-security/main", HOSTS))
        self.assertFalse(A.source_allowed("http://mirror.kakao.com/ubuntu", "noble-proposed/main", HOSTS))
        self.assertFalse(A.source_allowed("https://ppa.launchpadcontent.net/x/ubuntu", "noble/main", HOSTS))
        self.assertFalse(A.source_allowed("http://mirror.kakao.com/evil", "noble/main", HOSTS))


class SimTests(unittest.TestCase):
    def test_cowsay_clean(self):
        s = A.parse_sim(fx("sim_cowsay.txt"))
        self.assertEqual([i[0] for i in s["inst"]], ["cowsay"])
        self.assertEqual(A.check_sim(s), [])

    def test_two_packages(self):
        s = A.parse_sim(fx("sim_cowsay+sl.txt"))
        self.assertEqual(sorted(i[0] for i in s["inst"]), ["cowsay", "sl"])
        self.assertEqual(A.check_sim(s), [])

    def test_removal_refused(self):
        s = A.parse_sim(fx("sim_ntp.txt"))
        self.assertIn("systemd-timesyncd", s["remv"])
        self.assertTrue(any("REMOVES" in e for e in A.check_sim(s)))

    def test_nvidia_upgrade_refused(self):
        s = A.parse_sim(fx("sim_libnvidia-compute-590.txt"))
        errs = A.check_sim(s)
        self.assertTrue(any("UPGRADES" in e for e in errs), errs)
        self.assertTrue(any("deny-listed" in e for e in errs), errs)

    def test_third_party_dependency_refused(self):
        s = A.parse_sim(fx("sim_docker-ce.txt"))
        errs = A.check_sim(s)
        self.assertTrue(any("non-Ubuntu origins" in e for e in errs), errs)
        self.assertTrue(any("UPGRADES" in e for e in errs), errs)

    def test_unknown_package_error(self):
        errs = A.check_sim(A.parse_sim(fx("sim_nosuchpkg-xyz.txt")))
        self.assertTrue(any("Unable to locate" in e for e in errs), errs)

    def test_already_installed_nothing_to_do(self):
        self.assertTrue(A.check_sim(A.parse_sim(fx("sim_htop.txt"))))


class NameTests(unittest.TestCase):
    def test_regex(self):
        for ok in ["cowsay", "g++", "libssl3t64", "python3.12-venv", "ffmpeg"]:
            self.assertTrue(A.PKG_RE.match(ok), ok)
        for bad in ["-oAPT::x", "Cowsay", "a", "pkg;rm", "pkg name", "pkg:i386", "../x", "x" * 70, "pkg/noble"]:
            self.assertFalse(A.PKG_RE.match(bad), bad)

    def test_denylist(self):
        for d in ["linux-image-generic", "nvidia-driver-595-open", "libnvidia-gl-590", "cuda-toolkit-12-4",
                  "zfs-dkms", "openssh-server", "sudo", "docker.io", "systemd-container", "ufw",
                  "iptables-persistent", "nftables", "auditd", "falco", "libpam-script"]:
            self.assertTrue(A.denied(d), d)
        for ok in ["cowsay", "ffmpeg", "build-essential", "htop", "python3-venv"]:
            self.assertFalse(A.denied(ok), ok)


class RegistryTests(unittest.TestCase):
    def test_repo_registry_parses(self):
        users = C.load_registry(os.path.join(HERE, "..", "users.yaml"))
        names = {u["name"]: u for u in users}
        self.assertIn("kimsunghyun", names)
        self.assertEqual(names["kimsunghyun"]["expires"], "2027-01-04")
        self.assertTrue(names["kimsunghyun"]["ssh_pubkey"].startswith("ssh-ed25519 "))
        self.assertEqual(names["martin"]["role"], "admin")
        self.assertEqual(names["jiayiqu12"]["state"], "locked")

    def test_set_field(self):
        text = "users:\n  - name: a  # x\n    expires: 2026-01-01  # keep\n  - name: b\n    state: active\n"
        t2 = C.registry_set_field(text, "a", "expires", "2027-02-02")
        self.assertIn("expires: 2027-02-02  # keep", t2)
        t3 = C.registry_set_field(t2, "b", "state", "removed")
        self.assertEqual({u["name"]: u["state"] for u in C.parse_registry(t3)}["b"], "removed")
        t4 = C.registry_set_field(t3, "a", "state", "locked")
        self.assertEqual({u["name"]: u["state"] for u in C.parse_registry(t4)}["a"], "locked")

    def test_bad_inputs(self):
        with self.assertRaises(ValueError):
            C.parse_registry("users:\n  - name: Bad;Name\n")
        with self.assertRaises(ValueError):
            C.parse_registry("users:\n  - name: a\n    ssh_pubkey: \"rm -rf /\"\n")
        with self.assertRaises(ValueError):
            C.parse_registry("users:\n  - name: a\n  - name: a\n")

    def test_split(self):
        text = "\n".join("line %d %s" % (i, "x" * 50) for i in range(200))
        chunks = C.split_message(text)
        self.assertTrue(all(len(c) <= 1900 for c in chunks))
        self.assertEqual("\n".join(chunks), text)


class HujsonTests(unittest.TestCase):
    def test_acl_group_edit(self):
        sys.path.insert(0, os.path.join(HERE, ".."))
        import importlib.machinery
        import importlib.util
        path = os.path.join(HERE, "..", "labctl")
        loader = importlib.machinery.SourceFileLoader("labctl_mod", path)
        spec = importlib.util.spec_from_loader("labctl_mod", loader)
        labctl = importlib.util.module_from_spec(spec)
        loader.exec_module(labctl)
        acl = fx("acl.hujson")
        self.assertEqual(labctl.acl_get_students(acl), ["kimsunghyun@"])
        new = labctl.acl_set_students(acl, ["kimsunghyun@", "imshen19@"])
        self.assertEqual(labctl.acl_get_students(new), ["imshen19@", "kimsunghyun@"])
        self.assertIn("// martin: full access", new)
        self.assertEqual(labctl.acl_get_students(labctl.acl_set_students(new, [])), [])


if __name__ == "__main__":
    unittest.main()
