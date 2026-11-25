# 贡献指南 (Contributing)

欢迎为 **CampusQuick** 补充新出现的广告联盟域名，或扩展更多高校/校园 App 的高频直达入口！

## 1. 补充去广告域名规则

所有平台的规则文件均由单一源文件 `rules/src/tmall_campus.yaml` 自动生成，**请勿直接手改 `rules/dist/` 或 `android/.../adblock_rules.json`**：

1. 编辑 `rules/src/tmall_campus.yaml`：
   - 纯广告 SDK 域名（不影响正常应用）→ 添加至 `pure_ad_domains` / `pure_ad_keywords` / `pure_ad_exact`；
   - 与正常消费类 App（抖音/快手/美团/微信等）共享的域名 → **必须**添加至 `process_scoped_domains`，保证仅按进程隔离，不误伤其他 App。
2. 重新编译所有 7 份产物并运行自动化防误杀测试：
   ```bash
   python rules/scripts/build_rules.py
   python -m unittest discover -s rules/tests -v
   python rules/scripts/build_rules.py --check
   ```

## 2. 扩展其他高校或校园 App 路由预设

1. 在 `presets/presets.json` 中按 `presets/schema.json` 格式新增条目（**严禁包含个人学号、房间号、Cookie、Token 或门锁 MAC 地址**）。
2. 同步拷贝至 `android/app/src/main/assets/presets.json`。
3. 运行 `python -m unittest discover -s rules/tests -v` 确认隐私与 Schema 校验全部通过。

## 3. 提交前自检

```bash
python rules/scripts/build_rules.py --check
python -m unittest discover -s rules/tests -v
cd android && ./gradlew testDebugUnitTest assembleDebug
```
