"""Tests for keepalivedwho. Hermetic fixture-tree tests (BG1-BG9);
stdlib-only runner, plain `python3 test_keepalivedwho.py` (no pytest
-- the aptpinswho lesson). No keepalived binary exists on this box,
so there is no live-agreement test to skip-guard against; fixture
trees are the only oracle, exactly as the manual text is the only
authority."""
import importlib.machinery
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "keepalivedwho")
_mod = importlib.machinery.SourceFileLoader("keepalivedwho_mod", TOOL)
keepalivedwho = _mod.load_module()


def run_cli(args, cwd=None):
    proc = subprocess.run([sys.executable, TOOL] + args,
                          capture_output=True, text=True, cwd=cwd)
    return proc.returncode, proc.stdout, proc.stderr


class TmpTree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="keepalivedwho-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, rel, text):
        path = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(text)
        return path

    def conf(self, text, name="keepalived.conf"):
        return self.write(name, text)

    def query(self, conf_path, query, extra=None):
        args = [query, "--conf", conf_path] + (extra or [])
        return run_cli(args)

    def query_json(self, conf_path, query, extra=None):
        rc, out, err = self.query(conf_path, query,
                                  (extra or []) + ["--json"])
        try:
            data = json.loads(out)
        except ValueError:
            self.fail("not JSON (rc=%d, err=%r): %r" % (rc, err, out))
        return rc, data, err

    def findings_with(self, data, fid):
        return [f for f in data["findings"] if f["id"] == fid]


# ------------------------------------------------------------------- BG1

class BG1CoreProvenance(TmpTree):
    def test_vip_in_main_file(self):
        # KV01/KV09/KV10: FOUND with instance + file:line.
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24 dev eth0\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertEqual(data["decider"]["where"], cfg + ":7")
        m = data["matches"][0]
        self.assertEqual(m["kind"], "vrrp_vip")
        self.assertEqual(m["instance"], "VI_1")
        self.assertEqual(m["instance_where"], cfg + ":1")
        self.assertEqual(m["mask"], 24)
        self.assertEqual(m["options"], {"dev": "eth0"})

    def test_vip_in_included_file(self):
        sub = self.write("sub/vips.conf",
                         "vrrp_instance VI_9 {\n"
                         "    state BACKUP\n"
                         "    interface eth1\n"
                         "    virtual_router_id 52\n"
                         "    priority 90\n"
                         "    virtual_ipaddress {\n"
                         "        10.0.0.9/24\n"
                         "    }\n"
                         "}\n")
        cfg = self.conf("include sub/vips.conf\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.9")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertEqual(data["decider"]["where"], sub + ":7")
        self.assertEqual(data["matches"][0]["instance"], "VI_9")

    def test_instance_query_lists_vips_with_file_lines(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    advert_int 1\n"
            "    nopreempt\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "        10.0.0.6/24 dev eth0\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        m = data["matches"][0]
        self.assertEqual(m["kind"], "instance")
        self.assertEqual(m["where"], cfg + ":1")
        self.assertEqual([v["address"] for v in m["vips"]],
                         ["10.0.0.5", "10.0.0.6"])
        self.assertEqual([v["where"] for v in m["vips"]],
                         [cfg + ":9", cfg + ":10"])
        ctx = m["context"]
        self.assertEqual(ctx["state"], "MASTER")
        self.assertEqual(ctx["interface"], "eth0")
        self.assertEqual(ctx["virtual_router_id"], 51)
        self.assertEqual(ctx["priority"], 100)
        self.assertTrue(ctx["nopreempt"])
        self.assertIn("[mastership-not-adjudicated]",
                      " ".join(data["banners"]))

    def test_virtual_server_ip_port_query(self):
        cfg = self.conf(
            "virtual_server 10.0.0.5 443 {\n"
            "    protocol TCP\n"
            "    lvs_sched rr\n"
            "    real_server 192.168.1.10 80 {\n"
            "        weight 1\n"
            "        TCP_CHECK {\n"
            "            connect_timeout 3\n"
            "        }\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5:443")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertEqual(data["decider"]["where"], cfg + ":1")
        m = data["matches"][0]
        self.assertEqual(m["kind"], "virtual_server")
        self.assertEqual(m["port"], 443)
        self.assertEqual(m["protocol"], "TCP")
        self.assertEqual(m["real_servers"], 1)

    def test_bare_ip_matches_vrrp_vip_and_virtual_server(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n"
            "virtual_server 10.0.0.5 443 {\n"
            "    protocol TCP\n"
            "    real_server 192.168.1.10 80 {\n"
            "        weight 1\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        kinds = [m["kind"] for m in data["matches"]]
        self.assertIn("vrrp_vip", kinds)
        self.assertIn("virtual_server", kinds)

    def test_group_member_vip_via_virtual_server_group(self):
        cfg = self.conf(
            "virtual_server_group WEB {\n"
            "    192.168.200.1-10 80\n"
            "    192.168.201.5 443\n"
            "}\n"
            "virtual_server group WEB {\n"
            "    protocol TCP\n"
            "    real_server 10.1.1.1 80 {\n"
            "        weight 1\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "192.168.200.7")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        m = data["matches"][0]
        self.assertEqual(m["kind"], "group_member")
        self.assertEqual(m["group"], "WEB")
        self.assertEqual(m["member_where"], cfg + ":2")
        self.assertEqual(len(m["using_servers"]), 1)
        self.assertEqual(m["using_servers"][0]["where"], cfg + ":5")

    def test_fwmark_query(self):
        cfg = self.conf(
            "virtual_server fwmark 100 {\n"
            "    protocol TCP\n"
            "    lvs_sched rr\n"
            "    real_server 192.168.1.10 80 {\n"
            "        weight 1\n"
            "    }\n"
            "}\n")
        # "fwmark N" is two positionals.
        rc, out, err = run_cli(["fwmark", "100", "--conf", cfg,
                                "--json"])
        data = json.loads(out)
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertEqual(data["matches"][0]["kind"],
                         "virtual_server")
        self.assertEqual(data["matches"][0]["fwmark"], 100)

    def test_not_found(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.99")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "NOT-FOUND")

    def test_name_matching_instance_and_group_both_answered(self):
        cfg = self.conf(
            "vrrp_instance WEB {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n"
            "virtual_server_group WEB {\n"
            "    192.168.200.1 80\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "WEB")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        kinds = sorted(m["kind"] for m in data["matches"])
        self.assertEqual(kinds, ["instance", "virtual_server_group"])

    def test_ipv6_vip_and_mask_query(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        2001:db8::5/64\n"
            "        10.0.0.5/32\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "2001:db8::5")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        rc, data, _ = self.query_json(cfg, "10.0.0.5/24")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertEqual(data["query"]["mask"], 24)
        self.assertEqual(data["matches"][0]["mask"], 32)


# ------------------------------------------------------------------- BG2

class BG2IncludeChain(TmpTree):
    def test_nested_includes_three_deep(self):
        self.write("c.conf",
                   "vrrp_instance VI_C {\n"
                   "    state BACKUP\n"
                   "    interface eth0\n"
                   "    virtual_router_id 53\n"
                   "    priority 80\n"
                   "    virtual_ipaddress {\n"
                   "        10.0.0.3/24\n"
                   "    }\n"
                   "}\n")
        self.write("b.conf", "include c.conf\n")
        self.write("a.conf", "include b.conf\n")
        cfg = self.conf("include a.conf\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.3")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertEqual(data["decider"]["where"],
                         os.path.join(self.tmp, "c.conf") + ":7")
        self.assertEqual(len(data["coverage"]["files"]), 4)

    def test_relative_include_resolved_against_including_file(self):
        self.write("sub/deep/vips.conf",
                   "vrrp_instance VI_D {\n"
                   "    state BACKUP\n"
                   "    interface eth0\n"
                   "    virtual_router_id 54\n"
                   "    priority 80\n"
                   "    virtual_ipaddress {\n"
                   "        10.0.0.4/24\n"
                   "    }\n"
                   "}\n")
        self.write("sub/mid.conf", "include deep/vips.conf\n")
        cfg = self.conf("include sub/mid.conf\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.4")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        kv02 = [f for f in data["findings"]
                if f["id"] == "KV02" and
                "relative include" in f["message"]]
        self.assertTrue(kv02, "expected a KV02 relative-include "
                        "finding")

    def test_glob_sorted_order(self):
        self.write("conf.d/b.conf",
                   "vrrp_instance VI_B {\n"
                   "    state BACKUP\n"
                   "    interface eth0\n"
                   "    virtual_router_id 52\n"
                   "    priority 90\n"
                   "    virtual_ipaddress {\n"
                   "        10.0.0.2/24\n"
                   "    }\n"
                   "}\n")
        self.write("conf.d/a.conf",
                   "vrrp_instance VI_A {\n"
                   "    state BACKUP\n"
                   "    interface eth0\n"
                   "    virtual_router_id 51\n"
                   "    priority 100\n"
                   "    virtual_ipaddress {\n"
                   "        10.0.0.1/24\n"
                   "    }\n"
                   "}\n")
        cfg = self.conf("include conf.d/*.conf\n")
        rc, out, _ = run_cli(["--list-vips", "--conf", cfg])
        self.assertEqual(rc, 0)
        addrs = [l.split()[2] for l in out.splitlines()
                 if l.startswith("  vrrp VIP")]
        self.assertEqual(addrs, ["10.0.0.1/24", "10.0.0.2/24"])
        rc, data, _ = self.query_json(cfg, "10.0.0.1")
        matches = data["coverage"]["expansions"][0]["matches"]
        self.assertEqual(
            [os.path.basename(m) for m in matches],
            ["a.conf", "b.conf"])

    def test_brace_expansion(self):
        self.write("inc/one.conf",
                   "vrrp_instance VI_ONE {\n"
                   "    state BACKUP\n"
                   "    interface eth0\n"
                   "    virtual_router_id 51\n"
                   "    priority 100\n"
                   "    virtual_ipaddress {\n"
                   "        10.0.0.11/24\n"
                   "    }\n"
                   "}\n")
        self.write("inc/two.conf",
                   "vrrp_instance VI_TWO {\n"
                   "    state BACKUP\n"
                   "    interface eth0\n"
                   "    virtual_router_id 52\n"
                   "    priority 90\n"
                   "    virtual_ipaddress {\n"
                   "        10.0.0.12/24\n"
                   "    }\n"
                   "}\n")
        cfg = self.conf('include "inc/{one,two}.conf"\n')
        rc, data, _ = self.query_json(cfg, "10.0.0.12")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        rc, data, _ = self.query_json(cfg, "10.0.0.11")
        self.assertEqual(data["verdict"], "FOUND")

    def test_brace_expansion_nested_and_empty_alternative(self):
        self.write("inc/b.conf",
                   "vrrp_instance VI_B {\n"
                   "    state BACKUP\n"
                   "    interface eth0\n"
                   "    virtual_router_id 51\n"
                   "    priority 100\n"
                   "    virtual_ipaddress {\n"
                   "        10.0.0.21/24\n"
                   "    }\n"
                   "}\n")
        self.write("inc/c.conf",
                   "vrrp_instance VI_C {\n"
                   "    state BACKUP\n"
                   "    interface eth0\n"
                   "    virtual_router_id 52\n"
                   "    priority 90\n"
                   "    virtual_ipaddress {\n"
                   "        10.0.0.22/24\n"
                   "    }\n"
                   "}\n")
        self.write("inc/file.conf",
                   "vrrp_instance VI_F {\n"
                   "    state BACKUP\n"
                   "    interface eth0\n"
                   "    virtual_router_id 53\n"
                   "    priority 80\n"
                   "    virtual_ipaddress {\n"
                   "        10.0.0.23/24\n"
                   "    }\n"
                   "}\n")
        self.write("inc/xfile.conf",
                   "vrrp_instance VI_X {\n"
                   "    state BACKUP\n"
                   "    interface eth0\n"
                   "    virtual_router_id 54\n"
                   "    priority 70\n"
                   "    virtual_ipaddress {\n"
                   "        10.0.0.24/24\n"
                   "    }\n"
                   "}\n")
        cfg = self.conf(
            'include "inc/{a,{b,c}}.conf"\n'
            'include "inc/{,x}file.conf"\n')
        # "a" does not exist: plain include tolerates it.
        for ip in ("10.0.0.21", "10.0.0.22", "10.0.0.23",
                   "10.0.0.24"):
            rc, data, _ = self.query_json(cfg, ip)
            self.assertEqual(data["verdict"], "FOUND", ip)

    def test_plain_include_missing_file_is_warning_verdict_stands(self):
        cfg = self.conf(
            "include does-not-exist.conf\n"
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        kv03 = [f for f in data["findings"]
                if f["id"] == "KV03" and
                f["severity"] == "warning"]
        self.assertTrue(kv03)

    def test_includea_no_match_is_fatal(self):
        cfg = self.conf("includea missing-*.conf\n")
        rc, out, err = self.query(cfg, "10.0.0.5")
        self.assertEqual(rc, 2)
        self.assertIn("wildcard_match", err)

    def test_includem_literal_missing_is_fatal(self):
        cfg = self.conf("includem missing.conf\n")
        rc, out, err = self.query(cfg, "10.0.0.5")
        self.assertEqual(rc, 2)
        self.assertIn("match", err)

    def test_includew_wildcard_no_match_is_fatal(self):
        cfg = self.conf("includew missing-*.conf\n")
        rc, out, err = self.query(cfg, "10.0.0.5")
        self.assertEqual(rc, 2)
        self.assertIn("wildcard_match", err)

    def test_includeb_brace_no_match_is_fatal(self):
        cfg = self.conf('includeb "inc/{a,b}.conf"\n')
        rc, out, err = self.query(cfg, "10.0.0.5")
        self.assertEqual(rc, 2)
        self.assertIn("brace_match", err)

    def test_includer_unreadable_is_fatal(self):
        # A directory is not a readable file (KV03 readable
        # check); a chmod-000 file would not be unreadable to
        # root, so a directory is the hermetic stand-in.
        os.makedirs(os.path.join(self.tmp, "somedir"))
        cfg = self.conf("includer somedir\n")
        rc, out, err = self.query(cfg, "10.0.0.5")
        self.assertEqual(rc, 2)
        self.assertIn("readable", err)

    def test_plain_include_of_directory_is_warning_only(self):
        os.makedirs(os.path.join(self.tmp, "somedir"))
        cfg = self.conf(
            "include somedir\n"
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")

    def test_include_check_toggling(self):
        # +match makes a missing literal fatal; -wildcard_match
        # removes the wildcard check again.
        cfg = self.conf(
            "include_check +match -wildcard_match\n"
            "include missing.conf\n")
        rc, out, err = self.query(cfg, "10.0.0.5")
        self.assertEqual(rc, 2)
        self.assertIn("match", err)
        cfg2 = self.conf(
            "include_check +match -wildcard_match\n"
            "include missing-*.conf\n")
        rc, data, _ = self.query_json(cfg2, "10.0.0.5")
        # wildcard pattern + match check only: match does not
        # apply to wildcards, so this is a tolerated miss and
        # the query is NOT-FOUND (rc 1), not fatal (rc 2).
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "NOT-FOUND")

    def test_include_check_save_restore_across_file_boundary(self):
        # The level set inside an included file must not leak
        # out (KV03 stack-scoped save/restore).
        self.write("inner.conf",
                   "include_check -match\n"
                   "include also-missing.conf\n")
        cfg = self.conf(
            "include_check +match\n"
            "include inner.conf\n"
            "include missing-after.conf\n")
        rc, out, err = self.query(cfg, "10.0.0.5")
        self.assertEqual(rc, 2)
        self.assertIn("missing-after.conf", err)

    def test_include_cycle_is_fatal(self):
        self.write("a.conf", "include b.conf\n")
        self.write("b.conf", "include a.conf\n")
        cfg = self.conf("include a.conf\n")
        rc, out, err = self.query(cfg, "10.0.0.5")
        self.assertEqual(rc, 2)
        self.assertIn("cycle", err)

    def test_multi_conf_concatenation_order(self):
        c1 = self.conf("vrrp_instance VI_1 {\n"
                       "    state MASTER\n"
                       "    interface eth0\n"
                       "    virtual_router_id 51\n"
                       "    priority 100\n"
                       "    virtual_ipaddress {\n"
                       "        10.0.0.5/24\n"
                       "    }\n"
                       "}\n", name="one.conf")
        c2 = self.conf("vrrp_instance VI_2 {\n"
                       "    state BACKUP\n"
                       "    interface eth0\n"
                       "    virtual_router_id 52\n"
                       "    priority 90\n"
                       "    virtual_ipaddress {\n"
                       "        10.0.0.6/24\n"
                       "    }\n"
                       "}\n", name="two.conf")
        rc, out, err = run_cli(["--list-instances", "--conf", c1,
                                "--conf", c2])
        self.assertEqual(rc, 0)
        names = [l.split()[1] for l in out.splitlines()
                 if l.startswith("  instance")]
        self.assertEqual(names, ["VI_1", "VI_2"])
        self.assertIn("concatenated", out)

# ------------------------------------------------------------------- BG3

class BG3Conditionals(TmpTree):
    GATED_CFG = (
        "@main vrrp_instance VI_1 {\n"
        "    state MASTER\n"
        "    interface eth0\n"
        "    virtual_router_id 51\n"
        "    priority 240\n"
        "    virtual_ipaddress {\n"
        "        10.0.0.5/24\n"
        "    }\n"
        "}\n")

    def test_at_main_with_matching_config_id(self):
        cfg = self.conf(self.GATED_CFG)
        rc, data, _ = self.query_json(cfg, "10.0.0.5",
                                      extra=["--config-id", "main"])
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertEqual(data["matches"][0]["gate"],
                         "gated-included")

    def test_at_main_with_mismatching_config_id(self):
        cfg = self.conf(self.GATED_CFG)
        rc, data, _ = self.query_json(cfg, "10.0.0.5",
                                      extra=["--config-id",
                                             "backup"])
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "NOT-FOUND")
        self.assertEqual(data["coverage"]["gated_lines"]["count"], 1)

    def test_no_config_id_is_gated_unknown(self):
        cfg = self.conf(self.GATED_CFG)
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "GATED-UNKNOWN")
        self.assertIn("gated-unknown", data["blocker"])
        self.assertIn("[config-id-not-given]",
                      " ".join(data["banners"]))

    def test_negative_conditional_both_ways(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        @^main 10.0.0.7/24\n"
            "    }\n"
            "}\n")
        # @^main with --config-id main: dropped.
        rc, data, _ = self.query_json(cfg, "10.0.0.7",
                                      extra=["--config-id", "main"])
        self.assertEqual(data["verdict"], "NOT-FOUND")
        # @^main with --config-id backup: included.
        rc, data, _ = self.query_json(cfg, "10.0.0.7",
                                      extra=["--config-id",
                                             "backup"])
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        # No --config-id: gated-unknown.
        rc, data, _ = self.query_json(cfg, "10.0.0.7")
        self.assertEqual(data["verdict"], "GATED-UNKNOWN")

    def test_gated_instance_header_gates_all_its_vips(self):
        cfg = self.conf(
            "@main vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 240\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "        10.0.0.6/24\n"
            "    }\n"
            "}\n")
        for ip in ("10.0.0.5", "10.0.0.6"):
            rc, data, _ = self.query_json(cfg, ip)
            self.assertEqual(data["verdict"], "GATED-UNKNOWN", ip)
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(data["verdict"], "GATED-UNKNOWN")

    def test_gated_vip_line_only_sibling_still_found(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "        @main 10.0.0.6/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        rc, data, _ = self.query_json(cfg, "10.0.0.6")
        self.assertEqual(data["verdict"], "GATED-UNKNOWN")

    def test_gated_param_definition_makes_using_line_gated(self):
        cfg = self.conf(
            "@main $PRIORITY=240\n"
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority $PRIORITY\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        # No --config-id: the definition is gated-unknown, so
        # the priority field is unknown -- but the instance is
        # still FOUND (its header is ungated).
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertIsNone(data["matches"][0]["context"]["priority"])
        # With --config-id main: the definition applies.
        rc, data, _ = self.query_json(cfg, "VI_1",
                                      extra=["--config-id", "main"])
        self.assertEqual(data["matches"][0]["context"]["priority"],
                         240)

    def test_ungated_copy_plus_gated_copy_is_found(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n"
            "@main vrrp_instance VI_2 {\n"
            "    state BACKUP\n"
            "    interface eth0\n"
            "    virtual_router_id 52\n"
            "    priority 90\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertEqual(data["matches"][0]["instance"], "VI_1")
        gated = [f for f in data["findings"]
                 if "gated copy" in f["message"]]
        self.assertTrue(gated, "expected a gated-duplicate "
                        "finding")


# ------------------------------------------------------------------- BG4

class BG4Substitution(TmpTree):
    def test_param_basic_and_braced(self):
        cfg = self.conf(
            "$VIP=10.0.0.5\n"
            "$PORT=443\n"
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        ${VIP}/24\n"
            "    }\n"
            "}\n"
            "virtual_server $VIP $PORT {\n"
            "    protocol TCP\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        rc, data, _ = self.query_json(cfg, "10.0.0.5:443")
        self.assertEqual(data["verdict"], "FOUND")

    def test_recursive_substitution(self):
        # $A's value is itself a ${...} reference: substitution
        # is recursive and happens at replacement time (KV06).
        # The value ${B} is a braced reference, so it is replaced
        # on the next pass.
        cfg = self.conf(
            "$B=10.0.0.5\n"
            "$A=${B}\n"
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        ${A}/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")

    def test_bare_param_followed_by_slash_not_replaced(self):
        # KV06, strict reading: a bare $PARAMETER is replaced
        # only when followed by whitespace (or end of line); a
        # ${PARAMETER} need not be. So `$A/24` is left literal
        # and the VIP line is unparseable.
        cfg = self.conf(
            "$A=10.0.0.5\n"
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        $A/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "UNKNOWN")

    def test_definition_after_use_not_replaced(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority $PRIORITY\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n"
            "$PRIORITY=200\n")
        # The priority line is unparseable (KV21) because the
        # parameter was undefined at that point; the instance
        # query is UNKNOWN, the VIP query is unaffected.
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "UNKNOWN")
        self.assertIn("priority", data["blocker"])
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(data["verdict"], "FOUND")

    def test_conditional_definition_with_config_id(self):
        cfg = self.conf(
            "@main $PRIORITY=240\n"
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority $PRIORITY\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_1",
                                      extra=["--config-id", "main"])
        self.assertEqual(data["matches"][0]["context"]["priority"],
                         240)
        # With a mismatching config-id the definition is
        # dropped, so the priority line is unparseable.
        rc, data, _ = self.query_json(cfg, "VI_1",
                                      extra=["--config-id",
                                             "backup"])
        self.assertEqual(data["verdict"], "UNKNOWN")

    def test_pwd_in_script_path(self):
        sub = self.write("conf/check.sh", "#!/bin/sh\n")
        cfg = self.write("conf/keepalived.conf",
                         "vrrp_script chk {\n"
                         '    script "${_PWD}/check.sh"\n'
                         "    interval 2\n"
                         "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        inv = data["unmodeled"]
        paths = [u["reason"] for u in inv
                 if "vrrp_script" in u["reason"]]
        self.assertTrue(paths)
        self.assertIn(os.path.join(self.tmp, "conf", "check.sh"),
                      paths[0])

    def test_hash_and_bang_do_not_start_comments(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100 # trailing comment\n"
            '    notify_master "/bin/echo ${_HASH}ok"\n'
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(rc, 0)
        self.assertEqual(data["matches"][0]["context"]["priority"],
                         100)
        inv = [u for u in data["unmodeled"]
               if u["reason"].startswith("script ")]
        self.assertTrue(inv)
        self.assertIn("#ok", inv[0]["reason"])

    def test_random_line_is_random_unknown(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.${_RANDOM}/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "UNKNOWN")
        self.assertIn("random", data["blocker"])
        self.assertEqual(len(data["coverage"]["random_lines"]), 1)

    def test_seq_line_generating_vip_lines(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "        ~SEQ(i, 1, 1, 5) 10.0.1.$i/24\n"
            "    }\n"
            "}\n")
        # The ungated VIP is still FOUND; a generated one is
        # UNKNOWN, naming the ~SEQ line as the blocker.
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(data["verdict"], "FOUND")
        rc, data, _ = self.query_json(cfg, "10.0.1.3")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "UNKNOWN")
        self.assertIn("seq", data["blocker"])
        self.assertEqual(len(data["coverage"]["seq_lines"]), 1)

    def test_seq_line_generating_instance_headers(self):
        cfg = self.conf(
            "~SEQ(i, 1, 1, 5) vrrp_instance VI_$i {\n"
            "vrrp_instance VI_9 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.9/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_3")
        self.assertEqual(data["verdict"], "UNKNOWN")
        rc, data, _ = self.query_json(cfg, "VI_9")
        self.assertEqual(data["verdict"], "FOUND")

    def test_lst_line(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "        ~LST(v, 10.0.2.1, 10.0.2.2) $v/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.2.1")
        self.assertEqual(data["verdict"], "UNKNOWN")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(data["verdict"], "FOUND")

    def test_undefined_param_left_literal(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.$UNDEF/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "UNKNOWN")
        kv21 = self.findings_with(data, "KV21")
        self.assertTrue(kv21)

    def test_at_prefixed_include_not_followed(self):
        sub = self.write("sub/vips.conf",
                         "vrrp_instance VI_9 {\n"
                         "    state BACKUP\n"
                         "    interface eth0\n"
                         "    virtual_router_id 52\n"
                         "    priority 90\n"
                         "    virtual_ipaddress {\n"
                         "        10.0.0.9/24\n"
                         "    }\n"
                         "}\n")
        cfg = self.conf("@main include sub/vips.conf\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.9")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "UNKNOWN")
        self.assertIn("include", data["blocker"])
        kv04 = self.findings_with(data, "KV04")
        self.assertTrue(kv04)

    def test_dollar_pattern_include_not_followed(self):
        self.write("sub/vips.conf",
                   "vrrp_instance VI_9 {\n"
                   "    state BACKUP\n"
                   "    interface eth0\n"
                   "    virtual_router_id 52\n"
                   "    priority 90\n"
                   "    virtual_ipaddress {\n"
                   "        10.0.0.9/24\n"
                   "    }\n"
                   "}\n")
        cfg = self.conf("$DIR=sub\n"
                        "include $DIR/vips.conf\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.9")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "UNKNOWN")
        kv04 = self.findings_with(data, "KV04")
        self.assertTrue(kv04)


# ------------------------------------------------------------------- BG5

class BG5VipMatching(TmpTree):
    def test_mask_ignored_for_match_shown_as_context(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/32\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(data["verdict"], "FOUND")
        self.assertEqual(data["matches"][0]["mask"], 32)

    def test_excluded_vip_found_with_flag(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress_excluded {\n"
            "        10.0.0.9/24 dev eth0\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.9")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertTrue(data["matches"][0]["excluded"])
        self.assertTrue(any("excluded-from-adverts" in f["message"]
                            for f in data["findings"]))

    def test_same_vip_in_both_blocks_of_one_instance(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "    virtual_ipaddress_excluded {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        dup = [f for f in data["findings"]
               if "declared 2 times" in f["message"]]
        self.assertTrue(dup)

    def test_vip_options_shown_as_context(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24 dev eth0 scope site "
            "label eth0:1 peer 10.0.0.6\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        opts = data["matches"][0]["options"]
        self.assertEqual(opts["dev"], "eth0")
        self.assertEqual(opts["scope"], "site")
        self.assertEqual(opts["label"], "eth0:1")
        self.assertEqual(opts["peer"], "10.0.0.6")

    def test_group_range_membership(self):
        cfg = self.conf(
            "virtual_server_group RANGES {\n"
            "    192.168.200.1-10 80\n"
            "    192.168.201.1-192.168.201.5 80\n"
            "    192.168.202.8/29 80\n"
            "}\n"
            "virtual_server group RANGES {\n"
            "    protocol TCP\n"
            "}\n")
        for ip in ("192.168.200.1", "192.168.200.10",
                   "192.168.201.3", "192.168.202.9",
                   "192.168.202.15"):
            rc, data, _ = self.query_json(cfg, ip)
            self.assertEqual(data["verdict"], "FOUND", ip)
        for ip in ("192.168.200.11", "192.168.201.6",
                   "192.168.202.16"):
            rc, data, _ = self.query_json(cfg, ip)
            self.assertEqual(data["verdict"], "NOT-FOUND", ip)

    def test_portless_persistent_vs_matches_port_query(self):
        cfg = self.conf(
            "virtual_server 10.0.0.5 {\n"
            "    protocol TCP\n"
            "    persistence_timeout 300\n"
            "    real_server 192.168.1.10 80 {\n"
            "        weight 1\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5:443")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertIsNone(data["matches"][0]["port"])
        self.assertTrue(any("no port" in f["message"]
                            for f in data["findings"]))

    def test_fwmark_vs_never_matches_vip_query(self):
        cfg = self.conf(
            "virtual_server fwmark 100 {\n"
            "    protocol TCP\n"
            "    real_server 192.168.1.10 80 {\n"
            "        weight 1\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(data["verdict"], "NOT-FOUND")

    def test_excluded_block_rejects_use_vmac_option(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress_excluded {\n"
            "        10.0.0.9/24 use_vmac\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.9")
        self.assertEqual(data["verdict"], "UNKNOWN")
        kv21 = self.findings_with(data, "KV21")
        self.assertTrue(kv21)

# ------------------------------------------------------------------- BG6

class BG6Duplicates(TmpTree):
    def test_duplicate_instance_names_ambiguous(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n"
            "vrrp_instance VI_1 {\n"
            "    state BACKUP\n"
            "    interface eth1\n"
            "    virtual_router_id 52\n"
            "    priority 90\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.6/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "AMBIGUOUS")
        self.assertEqual([m["where"] for m in data["matches"]],
                         [cfg + ":1", cfg + ":10"])

    def test_same_vip_on_two_instances_ambiguous(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n"
            "vrrp_instance VI_2 {\n"
            "    state BACKUP\n"
            "    interface eth0\n"
            "    virtual_router_id 52\n"
            "    priority 90\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "AMBIGUOUS")
        self.assertEqual(len(data["matches"]), 2)

    def test_duplicate_virtual_server_ip_port_ambiguous(self):
        cfg = self.conf(
            "virtual_server 10.0.0.5 443 {\n"
            "    protocol TCP\n"
            "}\n"
            "virtual_server 10.0.0.5 443 {\n"
            "    protocol TCP\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5:443")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "AMBIGUOUS")

    def test_duplicate_group_name_ambiguous(self):
        cfg = self.conf(
            "virtual_server_group WEB {\n"
            "    192.168.200.1 80\n"
            "}\n"
            "virtual_server_group WEB {\n"
            "    192.168.200.2 80\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "WEB")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "AMBIGUOUS")

    def test_same_vrid_and_interface_is_warning_not_ambiguous(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n"
            "vrrp_instance VI_2 {\n"
            "    state BACKUP\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 90\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.6/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertTrue(any("share VRID" in f["message"]
                            for f in data["findings"]))


# ------------------------------------------------------------------- BG7

class BG7ScriptsContextNegatives(TmpTree):
    def test_scripts_inventoried_never_executed(self):
        marker = os.path.join(self.tmp, "marker")
        marker2 = os.path.join(self.tmp, "marker2")
        marker3 = os.path.join(self.tmp, "marker3")
        cfg = self.conf(
            "vrrp_script chk {\n"
            '    script "/bin/touch %s"\n' % marker +
            "    interval 2\n"
            "}\n"
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            '    notify_master "/bin/touch %s"\n' % marker2 +
            "    track_script {\n"
            "        chk\n"
            "    }\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n"
            "virtual_server 10.0.0.5 443 {\n"
            "    protocol TCP\n"
            "    quorum_up \"/bin/touch %s\"\n" % marker3 +
            "    real_server 192.168.1.10 80 {\n"
            "        weight 1\n"
            "        MISC_CHECK {\n"
            "            misc_path \"/bin/touch %s\"\n" % marker +
            "        }\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertFalse(os.path.exists(marker))
        self.assertFalse(os.path.exists(marker2))
        self.assertFalse(os.path.exists(marker3))
        by_class = data["coverage"]["scripts"]["by_class"]
        self.assertEqual(by_class.get("vrrp_script"), 1)
        self.assertEqual(by_class.get("notify"), 1)
        self.assertEqual(by_class.get("quorum"), 1)
        self.assertEqual(by_class.get("misc"), 1)

    def test_sync_group_membership_shown(self):
        cfg = self.conf(
            "vrrp_sync_group SG1 {\n"
            "    group {\n"
            "        VI_1\n"
            "        VI_2\n"
            "    }\n"
            "}\n"
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n"
            "vrrp_instance VI_2 {\n"
            "    state BACKUP\n"
            "    interface eth0\n"
            "    virtual_router_id 52\n"
            "    priority 90\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.6/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(data["verdict"], "FOUND")
        sg = data["matches"][0]["sync_groups"]
        self.assertEqual(len(sg), 1)
        self.assertEqual(sg[0]["name"], "SG1")
        self.assertEqual(sg[0]["where"], cfg + ":1")

    def test_dangling_sync_group_member_finding(self):
        cfg = self.conf(
            "vrrp_sync_group SG1 {\n"
            "    group {\n"
            "        VI_1\n"
            "        VI_MISSING\n"
            "    }\n"
            "}\n"
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(data["verdict"], "FOUND")
        self.assertTrue(any("VI_MISSING" in f["message"] and
                            "dangling" in f["message"]
                            for f in data["findings"]))

    def test_dangling_track_script_finding(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    track_script {\n"
            "        chk_missing weight 10\n"
            "    }\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(data["verdict"], "FOUND")
        self.assertTrue(any("chk_missing" in f["message"]
                            for f in data["findings"]))

    def test_priority_state_nopreempt_context_and_banner(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state BACKUP\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 90\n"
            "    nopreempt\n"
            "    preempt_delay 300\n"
            "    advert_int 1\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_1")
        ctx = data["matches"][0]["context"]
        self.assertEqual(ctx["state"], "BACKUP")
        self.assertEqual(ctx["priority"], 90)
        self.assertTrue(ctx["nopreempt"])
        self.assertEqual(ctx["preempt_delay"], 300)
        self.assertIn("[mastership-not-adjudicated]",
                      " ".join(data["banners"]))

    def test_static_ipaddress_is_not_a_vip(self):
        cfg = self.conf(
            "static_ipaddress {\n"
            "    10.0.0.9/24 dev eth0\n"
            "}\n"
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.9")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "NOT-A-VIP")
        self.assertEqual(data["coverage"]["static_addresses"], 1)

    def test_no_virtual_ipaddress_instance_found_zero_vips(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    no_virtual_ipaddress\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertEqual(data["matches"][0]["vips"], [])
        self.assertTrue(any("no_virtual_ipaddress" in f["message"]
                            for f in data["findings"]))

    def test_empty_instance_without_flag_warns(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(data["verdict"], "FOUND")
        warn = [f for f in data["findings"]
                if f["severity"] == "warning" and
                "no VIPs" in f["message"]]
        self.assertTrue(warn)


# ------------------------------------------------------------------- BG8

class BG8Honesty(TmpTree):
    def test_unparseable_in_queried_instance_is_unknown(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priorty 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "UNKNOWN")
        self.assertIn("priorty", data["blocker"])

    def test_unparseable_in_unrelated_block_is_warning_only(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priorty 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n"
            "vrrp_instance VI_2 {\n"
            "    state BACKUP\n"
            "    interface eth0\n"
            "    virtual_router_id 52\n"
            "    priority 90\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.6/24\n"
            "    }\n"
            "}\n")
        # VI_2 is unaffected by VI_1's broken line.
        rc, data, _ = self.query_json(cfg, "VI_2")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        rc, data, _ = self.query_json(cfg, "10.0.0.6")
        self.assertEqual(data["verdict"], "FOUND")
        # But a VIP query is poisoned by an unparseable line in
        # a virtual_ipaddress block -- not by a bad priority
        # line, which cannot be a VIP.
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(data["verdict"], "FOUND")

    def test_unparseable_vip_line_poisons_vip_query(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "        not-an-ip-address\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 1)
        self.assertEqual(data["verdict"], "UNKNOWN")

    def test_coverage_completeness(self):
        sub = self.write("sub/vips.conf",
                         "vrrp_instance VI_9 {\n"
                         "    state BACKUP\n"
                         "    interface eth0\n"
                         "    virtual_router_id 52\n"
                         "    priority 90\n"
                         "    virtual_ipaddress {\n"
                         "        10.0.0.9/24\n"
                         "    }\n"
                         "}\n")
        cfg = self.conf(
            "include sub/vips.conf\n"
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        cov = data["coverage"]
        self.assertEqual(len(cov["files"]), 2)
        self.assertEqual(
            {os.path.basename(f["path"]) for f in cov["files"]},
            {"keepalived.conf", "vips.conf"})
        self.assertEqual(
            {i["name"] for i in cov["instances"]},
            {"VI_1", "VI_9"})
        self.assertEqual(cov["vips"]["total"], 2)
        self.assertEqual(cov["vips"]["by_instance"]["VI_1"], 1)
        self.assertEqual(cov["vips"]["by_instance"]["VI_9"], 1)
        self.assertEqual(len(cov["expansions"]), 1)
        self.assertEqual(cov["expansions"][0]["variant"], "include")

    def test_list_modes(self):
        cfg = self.conf(
            "@main vrrp_instance VI_G {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n"
            "vrrp_instance VI_1 {\n"
            "    state BACKUP\n"
            "    interface eth0\n"
            "    virtual_router_id 52\n"
            "    priority 90\n"
            "    virtual_ipaddress_excluded {\n"
            "        10.0.0.9/24\n"
            "    }\n"
            "}\n"
            "virtual_server 10.0.0.5 443 {\n"
            "    protocol TCP\n"
            "}\n"
            "virtual_server_group WEB {\n"
            "    192.168.200.1 80\n"
            "}\n")
        rc, out, _ = run_cli(["--list-instances", "--conf", cfg])
        self.assertEqual(rc, 0)
        self.assertIn("VI_G", out)
        self.assertIn("VI_1", out)
        self.assertIn("[gated-unknown]", out)
        rc, out, _ = run_cli(["--list-vips", "--conf", cfg])
        self.assertEqual(rc, 0)
        self.assertIn("10.0.0.5", out)
        self.assertIn("[excluded-from-adverts]", out)
        rc, out, _ = run_cli(["--list-servers", "--conf", cfg])
        self.assertEqual(rc, 0)
        self.assertIn("10.0.0.5:443", out)
        self.assertIn("WEB", out)
        # Empty inventory exits 1.
        cfg2 = self.conf("global_defs {\n"
                         "    router_id x\n"
                         "}\n")
        rc, out, _ = run_cli(["--list-vips", "--conf", cfg2])
        self.assertEqual(rc, 1)

    def test_json_fidelity_vs_text(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        rc2, out, _ = self.query(cfg, "10.0.0.5")
        self.assertEqual(rc, rc2)
        self.assertEqual(out.splitlines()[0], data["verdict"])

    def test_exit_codes(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, _, _ = self.query(cfg, "10.0.0.5")
        self.assertEqual(rc, 0)
        rc, _, _ = self.query(cfg, "10.0.0.99")
        self.assertEqual(rc, 1)
        rc, _, err = self.query(cfg, "not-an-ip:99999")
        self.assertEqual(rc, 2)
        rc, _, err = run_cli(["--conf", cfg])
        self.assertEqual(rc, 2)
        rc, _, err = run_cli(["10.0.0.5", "--conf",
                              "/nonexistent/keepalived.conf"])
        self.assertEqual(rc, 2)
        rc, _, err = run_cli(["fwmark", "abc", "--conf", cfg])
        self.assertEqual(rc, 2)
        rc, out, _ = run_cli(["--version"])
        self.assertEqual(rc, 0)
        self.assertIn("1.0.0", out)

    def test_quiet_prints_verdict_only(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, out, _ = self.query(cfg, "10.0.0.5",
                                extra=["--quiet"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "FOUND\n")

    def test_vrid_out_of_range_is_unparseable(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 300\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(data["verdict"], "UNKNOWN")
        self.assertTrue(self.findings_with(data, "KV21"))

    def test_case_sensitive_keyword_is_unparseable(self):
        # KV08: keyword case is hypothesized case-sensitive; a
        # differently-cased block keyword is an unparseable-line
        # finding, not a silent miss.
        cfg = self.conf(
            "VRRP_Instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertEqual(data["verdict"], "NOT-FOUND")
        self.assertTrue(self.findings_with(data, "KV21"))


# ------------------------------------------------------------------- BG9

class BG9Safety(TmpTree):
    def test_never_executes_payloads(self):
        marker = os.path.join(self.tmp, "marker")
        marker2 = os.path.join(self.tmp, "marker2")
        marker3 = os.path.join(self.tmp, "marker3")
        cfg = self.conf(
            "# $(touch %s)\n" % marker +
            "vrrp_script chk {\n"
            '    script "/bin/touch %s"\n' % marker +
            "    interval 2\n"
            "}\n"
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            '    notify_master "/bin/touch %s"\n' % marker2 +
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n"
            "virtual_server 10.0.0.5 443 {\n"
            "    protocol TCP\n"
            "    real_server 192.168.1.10 80 {\n"
            "        weight 1\n"
            "        MISC_CHECK {\n"
            "            misc_path \"/bin/touch %s\"\n" % marker3 +
            "        }\n"
            "    }\n"
            "}\n")
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 0)
        self.assertEqual(data["verdict"], "FOUND")
        self.assertFalse(os.path.exists(marker))
        self.assertFalse(os.path.exists(marker2))
        self.assertFalse(os.path.exists(marker3))

    def test_no_subprocess_socket_dns_or_environ_in_source(self):
        with open(TOOL) as fh:
            src = fh.read()
        for banned in ("import subprocess", "import socket",
                       "os.system", "os.popen", "eval(",
                       "exec(", "__import__", "pty.",
                       "getaddrinfo", "gethostbyname", "os.environ",
                       "os.getenv", "socket."):
            self.assertNotIn(banned, src, "source contains %r" % banned)

    def test_no_writes_and_no_network(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        before = sorted(os.listdir(self.tmp))
        mtime = os.path.getmtime(cfg)
        rc, data, _ = self.query_json(cfg, "10.0.0.5")
        self.assertEqual(rc, 0)
        self.assertEqual(sorted(os.listdir(self.tmp)), before)
        self.assertEqual(os.path.getmtime(cfg), mtime)

    def test_config_is_not_modified_by_query(self):
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        with open(cfg) as fh:
            before = fh.read()
        self.query(cfg, "10.0.0.5")
        with open(cfg) as fh:
            after = fh.read()
        self.assertEqual(before, after)

    def test_auth_hmac_key_values_never_printed(self):
        secret = "s3cr3t-hmac-value-xyz"
        cfg = self.conf(
            "vrrp_instance VI_1 {\n"
            "    state MASTER\n"
            "    interface eth0\n"
            "    virtual_router_id 51\n"
            "    priority 100\n"
            "    auth_hmac {\n"
            "        key 1 sha256 %s\n" % secret +
            "    }\n"
            "    virtual_ipaddress {\n"
            "        10.0.0.5/24\n"
            "    }\n"
            "}\n")
        rc, out, _ = self.query(cfg, "VI_1")
        self.assertEqual(rc, 0)
        self.assertNotIn(secret, out)
        rc, data, _ = self.query_json(cfg, "VI_1")
        self.assertNotIn(secret, json.dumps(data))
        keys = data["matches"][0]["context"]["auth_hmac_keys"]
        self.assertEqual(keys, ["1"])

    def test_tokenizer_quotes_comments_and_braces(self):
        # KV08: braces may share a line with a keyword; comments
        # start with # or ! anywhere; quoted strings keep spaces.
        # Comments are stripped before tokenizing (the parser
        # strips them on the raw line, so a ${_HASH} that
        # substitutes to # afterwards is not a comment, KV06).
        tok = lambda line: [t.text for t in keepalivedwho.tokenize(
            keepalivedwho.strip_comment(line))]
        self.assertEqual(
            tok('vrrp_instance VI_1 { # comment'),
            ["vrrp_instance", "VI_1", "{"])
        self.assertEqual(
            tok('notify_master "/path/notify.sh \'a b\'"'),
            ["notify_master", "/path/notify.sh 'a b'"])
        self.assertEqual(
            tok("priority 100 ! trailing comment"),
            ["priority", "100"])
        self.assertEqual(
            keepalivedwho.tokenize('"a\\nb"')[0].text, "a\nb")
        self.assertEqual(
            keepalivedwho.tokenize('"a\\x41b"')[0].text, "aAb")

    def test_brace_expansion_unit(self):
        self.assertEqual(
            keepalivedwho.expand_braces("{foo/{,cat,dog},bar}"),
            ["foo/", "foo/cat", "foo/dog", "bar"])
        self.assertEqual(
            keepalivedwho.expand_braces("a{b{c,d},e}f"),
            ["abcf", "abdf", "aef"])
        self.assertEqual(
            keepalivedwho.expand_braces("plain.conf"),
            ["plain.conf"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
