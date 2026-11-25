# 代理工具去广告配置指南

如果你已经在使用 ClashMeta (mihomo) / Clash Verge Rev / Sing-box / AdGuardHome，推荐直接复用 `rules/dist/` 中的自动编译产物，无需开启 CampusQuick 的内置本地 VPN（避免 Android 单 VPN 冲突）。

---

## 方案 1：Clash Verge Rev / Mihomo（推荐 · 更新订阅永不丢失）

使用 `rules/dist/tmall_campus_override.js` 作为全局覆写脚本（Global Extend Script），每次订阅更新会自动将 47 条进程隔离规则置顶。

## 方案 2：ClashMeta / Mihomo `rule-providers` 远程订阅（推荐）

将本仓库的 `rules/dist/tmall_campus_clash_provider.yaml` 托管到你的 GitHub Raw / CDN 地址，在配置文件中添加：

```yaml
rule-providers:
  campus-adblock:
    type: http
    behavior: classical
    format: yaml
    url: "https://raw.githubusercontent.com/xiwenkou/CampusQuick/main/rules/dist/tmall_campus_clash_provider.yaml"
    path: ./ruleset/campus-adblock.yaml
    interval: 86400

rules:
  - RULE-SET,campus-adblock,REJECT
  # ... 你原有的其他规则保持不变 ...
```

## 方案 3：ClashMetaForAndroid 直接内联粘贴

打开 `CampusQuick` App 点击 **「一键复制进程隔离规则」**（或直接打开 `rules/dist/tmall_campus_clash_rules.yaml`），将 `rules:` 下的规则粘贴到你配置中 `rules:` 的**最顶部**（必须在 `cn_domain` / `DIRECT` 之前）。

## 方案 4：Sing-box (v1.8+)

直接引用 `rules/dist/tmall_campus_singbox.json` 作为 `rule_set`（`format: "source"`），并在 `route.rules` 最顶部设置：

```json
{
  "rule_set": ["campus-adblock"],
  "action": "reject"
}
```

## 方案 5：AdGuardHome / 系统私人 DNS

导入 `rules/dist/tmall_campus_adguard.txt`（该文件仅包含纯广告 SDK 域名，已自动剔除共享消费类域名，全网生效无副作用）。
