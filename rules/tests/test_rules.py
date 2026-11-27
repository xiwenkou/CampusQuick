#!/usr/bin/env python3
"""Regression tests for CampusQuick ad-block rules & preset schemas."""

from __future__ import annotations

import json
import pathlib
import sys
import unittest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "rules" / "scripts"))
import build_rules  # noqa: E402


def matches_domain(host: str, exact: set[str], suffixes: list[str], keywords: list[str]) -> bool:
    h = host.lower().rstrip(".")
    if h in exact:
        return True
    for s in suffixes:
        s = s.lower()
        if h == s or h.endswith("." + s):
            return True
    for kw in keywords:
        if kw.lower() in h:
            return True
    return False


class TestRulesSafetyAndFormats(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.src = build_rules.load_source(build_rules.SRC_PATH)
        cls.outputs = build_rules.build_outputs(cls.src)

    def test_no_business_domain_blocked(self) -> None:
        all_suffixes = self.src["pure_ad_domains"] + self.src["process_scoped_domains"]
        exact = set(self.src["pure_ad_exact"])
        keywords = self.src["pure_ad_keywords"]
        for biz in self.src["business_allowlist"]:
            self.assertFalse(
                matches_domain(biz, exact, all_suffixes, keywords),
                f"Business domain '{biz}' accidentally matched an ad-block rule!",
            )

    def test_no_consumer_app_blocked_globally(self) -> None:
        exact = set(self.src["pure_ad_exact"])
        global_suffixes = self.src["pure_ad_domains"]
        keywords = self.src["pure_ad_keywords"]
        for dom in self.src["consumer_apps_guard"]:
            self.assertFalse(
                matches_domain(dom, exact, global_suffixes, keywords),
                f"Consumer app domain '{dom}' matched a GLOBAL ad-block rule (should be process-scoped only)!",
            )

    def test_verified_ad_domains_are_blocked(self) -> None:
        exact = set(self.src["pure_ad_exact"])
        all_suffixes = self.src["pure_ad_domains"] + self.src["process_scoped_domains"]
        keywords = self.src["pure_ad_keywords"]
        must_block = [
            "datk.anythinktech.com",
            "mores.anythinktech.com",
            "sdk.beizi.biz",
            "sdktmp.hubcloud.com.cn",
            "api-access.pangolin-sdk-toutiao.com",
            "api-access.pangolin-sdk-toutiao1.com",
            "sf6-fe-tos.pglstatp-toutiao.com",
            "sdk.e.qq.com",
            "union.eff.qq.com",
            "open.e.kuaishou.com",
            "open.e.kuaishou.cn",
            "api.e.kuaishou.cn",
            "w1.kskwai.com",
            "w2.gskwai.com",
            "ulog-sdk.gifshow.com",
            "ulog-sdk.ksapisrv.com",
            "open.kuaishouzt.com",
            "open.kwaizt.com",
            "g-api.kwai.com",
            "httpdns.bcelive.com",
            "sdkoptedge.chinanetcenter.com",
            "doh.pub",
            "dot.pub",
            "gdt.dot.pub",
            "dns.alidns.com",
            "httpdns.volcengineapi.com",
            "dig.bdurl.net",
            "p.qpic.cn",
            "pub.idqqimg.com",
            "46a79741.fyeds3.com",
            "songzhaopian.com",
            "mobads-pre-config.cdn.bcebos.com",
            "render-server.cdn.bcebos.com",
            "oc-adpict.oss-cn-shanghai.aliyuncs.com",
            "ad.zhuanzhuan.com",
            "sdk-report.1rtb.com",
            "v.adintl.cn",
            "www.pangle.cn",
            "cdn-tos-cn.bytedance.net",
            "sdklog.zhangyuyidong.cn",
            "api-cfg.8ziben.com",
            "ad-api.adn-plus.com.cn",
            "api.fu.xcultur.com",
            "tencent-ssp.66mobi.com",
            "adx.ys7.com",
            "t.adbiding.cn",
            "impdsp.meituan.com",
            "webcast-open.douyin.com",
            "ali.pull.yximgs.com",
        ]
        for ad in must_block:
            self.assertTrue(
                matches_domain(ad, exact, all_suffixes, keywords),
                f"Known ad domain '{ad}' is NOT blocked!",
            )

    def test_generated_yaml_and_json_parse_cleanly(self) -> None:
        clash_doc = yaml.safe_load(
            self.outputs[build_rules.DIST_DIR / "tmall_campus_clash_rules.yaml"]
        )
        self.assertIsInstance(clash_doc["rules"], list)
        self.assertGreaterEqual(len(clash_doc["rules"]), 45)

        provider_doc = yaml.safe_load(
            self.outputs[build_rules.DIST_DIR / "tmall_campus_clash_provider.yaml"]
        )
        self.assertIsInstance(provider_doc["payload"], list)
        self.assertEqual(len(provider_doc["payload"]), len(clash_doc["rules"]))

        singbox_doc = json.loads(
            self.outputs[build_rules.DIST_DIR / "tmall_campus_singbox.json"]
        )
        self.assertEqual(singbox_doc["version"], 2)
        self.assertEqual(len(singbox_doc["rules"]), 2)

        android_doc = json.loads(self.outputs[build_rules.ANDROID_ASSET_PATH])
        self.assertEqual(android_doc["targetPackage"], "com.tmall.campus.and")
        self.assertIn("biz.confong.cn", android_doc["allowlist"])

    def test_dist_artifacts_are_in_sync(self) -> None:
        for path, expected in self.outputs.items():
            self.assertTrue(path.exists(), f"Missing generated artifact: {path}")
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                expected,
                f"Generated artifact {path} is stale; re-run build_rules.py",
            )


class TestPresetsSchema(unittest.TestCase):
    def test_presets_valid_and_sanitized(self) -> None:
        presets_path = REPO_ROOT / "presets" / "presets.json"
        data = json.loads(presets_path.read_text(encoding="utf-8"))
        self.assertIn("schemaVersion", data)
        self.assertIsInstance(data["presets"], list)
        self.assertGreaterEqual(len(data["presets"]), 1)

        seen_ids = set()
        for item in data["presets"]:
            for req in ("id", "name", "description", "targetPackage", "uri", "category"):
                self.assertIn(req, item)
                self.assertTrue(isinstance(item[req], str) and item[req].strip())
            self.assertNotIn(item["id"], seen_ids)
            seen_ids.add(item["id"])
            # Ensure no personal tokens/cookies leaked into public presets
            lower_uri = item["uri"].lower()
            for forbidden in ("token=", "cookie=", "sid=", "uid="):
                self.assertNotIn(forbidden, lower_uri)


if __name__ == "__main__":
    unittest.main()
