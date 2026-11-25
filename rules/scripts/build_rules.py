#!/usr/bin/env python3
"""
Compile single-source ad-block YAML into multi-platform rule artifacts:
  1. ClashMeta / mihomo inline rules YAML (with PROCESS-NAME isolation)
  2. ClashMeta / mihomo rule-providers classical payload YAML (subscription-safe)
  3. ClashMeta / Verge Rev JS override script (auto-injects on subscription update)
  4. sing-box rule_set JSON (v2)
  5. AdGuard / AdGuardHome DNS filter list (pure ad domains only)
  6. Hosts format (0.0.0.0, pure ad domains only)
  7. Android bundled JSON asset for CampusQuick's Per-App Local VPN
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC_PATH = REPO_ROOT / "rules" / "src" / "tmall_campus.yaml"
DIST_DIR = REPO_ROOT / "rules" / "dist"
ANDROID_ASSET_PATH = (
    REPO_ROOT / "android" / "app" / "src" / "main" / "assets" / "adblock_rules.json"
)


def load_source(path: pathlib.Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Invalid YAML root in {path}")
    for key in (
        "version",
        "target_package",
        "pure_ad_domains",
        "pure_ad_keywords",
        "pure_ad_exact",
        "process_scoped_domains",
    ):
        if key not in data:
            raise ValueError(f"Missing required key '{key}' in {path}")
    return data


def build_clash_lines(data: dict) -> list[str]:
    pkg = data["target_package"]
    lines: list[str] = []
    for d in data["pure_ad_domains"]:
        lines.append(f"DOMAIN-SUFFIX,{d},REJECT")
    for kw in data["pure_ad_keywords"]:
        lines.append(f"DOMAIN-KEYWORD,{kw},REJECT")
    for h in data["pure_ad_exact"]:
        lines.append(f"DOMAIN,{h},REJECT")
    for d in data["process_scoped_domains"]:
        lines.append(f"AND,((PROCESS-NAME,{pkg}),(DOMAIN-SUFFIX,{d})),REJECT")
    return lines


def build_clash_provider_payload(data: dict) -> list[str]:
    """Classical rule-provider payload omits the trailing target policy."""
    pkg = data["target_package"]
    payload: list[str] = []
    for d in data["pure_ad_domains"]:
        payload.append(f"DOMAIN-SUFFIX,{d}")
    for kw in data["pure_ad_keywords"]:
        payload.append(f"DOMAIN-KEYWORD,{kw}")
    for h in data["pure_ad_exact"]:
        payload.append(f"DOMAIN,{h}")
    for d in data["process_scoped_domains"]:
        payload.append(f"AND,((PROCESS-NAME,{pkg}),(DOMAIN-SUFFIX,{d}))")
    return payload


def build_outputs(data: dict) -> dict[pathlib.Path, str]:
    version = data["version"]
    pkg = data["target_package"]
    clash_rules = build_clash_lines(data)
    provider_payload = build_clash_provider_payload(data)

    # 1. ClashMeta inline rules
    clash_yaml = (
        f"# CampusQuick Ad-Block Rules v{version} (ClashMeta / mihomo)\n"
        f"# Target: {pkg} | Total rules: {len(clash_rules)}\n"
        "# Paste at the VERY TOP of `rules:` (before cn_domain / DIRECT).\n\n"
        "rules:\n"
        + "".join(f"  - {r}\n" for r in clash_rules)
    )

    # 2. ClashMeta classical rule-provider payload
    provider_yaml = (
        f"# CampusQuick Rule-Provider Payload v{version} (behavior: classical)\n"
        f"# Target: {pkg} | Total entries: {len(provider_payload)}\n"
        "# Use with: rule-providers -> behavior: classical, format: yaml\n"
        "# Then add at top of rules: - RULE-SET,campus-adblock,REJECT\n\n"
        "payload:\n"
        + "".join(f"  - '{r}'\n" for r in provider_payload)
    )

    # 3. Clash Verge / Mihomo JS override (survives subscription updates)
    js_rules_array = ",\n".join(f"  {json.dumps(r)}" for r in clash_rules)
    override_js = (
        f"// CampusQuick Mihomo / Clash Verge Rev Override Script v{version}\n"
        f"// Prepends {len(clash_rules)} ad-block rules for {pkg} on every subscription update.\n\n"
        "const CAMPUS_ADBLOCK_RULES = [\n"
        f"{js_rules_array}\n"
        "];\n\n"
        "function main(config) {\n"
        "  const existing = Array.isArray(config.rules) ? config.rules : [];\n"
        "  const seen = new Set(existing);\n"
        "  const prefix = CAMPUS_ADBLOCK_RULES.filter((r) => !seen.has(r));\n"
        "  config.rules = [...prefix, ...existing];\n"
        "  return config;\n"
        "}\n"
    )

    # 4. sing-box rule_set JSON (v2)
    singbox_obj = {
        "version": 2,
        "rules": [
            {
                "domain": list(data["pure_ad_exact"]),
                "domain_suffix": list(data["pure_ad_domains"]),
                "domain_keyword": list(data["pure_ad_keywords"]),
            },
            {
                "type": "logical",
                "mode": "and",
                "rules": [
                    {"package_name": [pkg]},
                    {"domain_suffix": list(data["process_scoped_domains"])},
                ],
            },
        ],
    }
    singbox_json = json.dumps(singbox_obj, indent=2, ensure_ascii=False) + "\n"

    # 5. AdGuard / AdGuardHome filter (pure ad rules only — safe globally)
    adguard_lines = [
        f"! Title: CampusQuick Ad-Block Filter (Tmall Campus)",
        f"! Version: {version}",
        f"! Scope: Pure ad-SDK domains only (safe for global DNS filtering)",
        "",
    ]
    for d in data["pure_ad_domains"]:
        adguard_lines.append(f"||{d}^")
    for h in data["pure_ad_exact"]:
        adguard_lines.append(f"||{h}^")
    for kw in data["pure_ad_keywords"]:
        adguard_lines.append(f"/*{kw}*/")
    adguard_txt = "\n".join(adguard_lines) + "\n"

    # 6. Hosts format (exact + primary known subdomains)
    hosts_lines = [
        f"# CampusQuick Ad-Block Hosts v{version}",
        "# Note: standard hosts files do not support wildcards; exact/root entries below.",
    ]
    for h in data["pure_ad_exact"]:
        hosts_lines.append(f"0.0.0.0 {h}")
    for d in data["pure_ad_domains"]:
        hosts_lines.append(f"0.0.0.0 {d}")
    hosts_txt = "\n".join(hosts_lines) + "\n"

    # 7. Android Per-App VPN bundled JSON
    # Inside CampusQuick's Per-App VPN (addAllowedApplication = target_package),
    # BOTH pure ad rules AND process_scoped_domains apply safely with zero collateral impact.
    android_obj = {
        "version": version,
        "targetPackage": pkg,
        "exactDomains": list(data["pure_ad_exact"]),
        "domainSuffixes": list(data["pure_ad_domains"])
        + list(data["process_scoped_domains"]),
        "processScopedSuffixes": list(data["process_scoped_domains"]),
        "domainKeywords": list(data["pure_ad_keywords"]),
        "allowlist": list(data.get("business_allowlist", [])),
    }
    android_json = json.dumps(android_obj, indent=2, ensure_ascii=False) + "\n"

    return {
        DIST_DIR / "tmall_campus_clash_rules.yaml": clash_yaml,
        DIST_DIR / "tmall_campus_clash_provider.yaml": provider_yaml,
        DIST_DIR / "tmall_campus_override.js": override_js,
        DIST_DIR / "tmall_campus_singbox.json": singbox_json,
        DIST_DIR / "tmall_campus_adguard.txt": adguard_txt,
        DIST_DIR / "tmall_campus_hosts.txt": hosts_txt,
        ANDROID_ASSET_PATH: android_json,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build CampusQuick rule artifacts")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify generated files are up to date without overwriting",
    )
    args = parser.parse_args()

    data = load_source(SRC_PATH)
    outputs = build_outputs(data)

    if args.check:
        stale = []
        for path, expected in outputs.items():
            if not path.exists() or path.read_text(encoding="utf-8") != expected:
                stale.append(str(path.relative_to(REPO_ROOT)))
        if stale:
            print("ERROR: Out-of-date generated rule artifacts:", file=sys.stderr)
            for s in stale:
                print(f"  - {s}", file=sys.stderr)
            return 1
        print(f"OK: All {len(outputs)} rule artifacts match rules/src/tmall_campus.yaml (v{data['version']}).")
        return 0

    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
        print(f"Generated {path.relative_to(REPO_ROOT)} ({len(content.encode('utf-8'))} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
