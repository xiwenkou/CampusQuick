# 技术分析报告（脱敏）

本文档记录 `CampusQuick` 架构设计所依据的静态分析与实机抓包结论（所有个人身份信息、Cookie、学号、房间号与设备 MAC 均已剥离）。

---

## 1. 为什么绝不反编译修改原 App

目标应用（`com.tmall.campus.and`）集成了阿里无线保镖组件（`libsgmainso-6.5.97.so`）与淘宝 MTOP 账户签名栈：
- APK 签名变更会直接破坏安全保镖校验，导致登录态与业务接口异常；
- 重打包修改商业账号系 App 存在触发账号风控的隐患。

因此本项目严格遵守**非侵入边界**：仅调用其 `AndroidManifest.xml` 中公开导出的 `DispatchActivity` DeepLink 路由，并在网络层精准拦截广告 SDK 域名。

---

## 2. 广告瀑布流与二级备用域名机制

目标应用聚合了 TopOn / Taku 与十余家国内广告联盟（倍孜、穿山甲/GroMore、优量汇、快手联盟、百度、章鱼、ZJSDK、ADN+、美数 1RTB、趣盟、UBiX 等），触发点包括：
1. **冷启动开屏**（`SplashActivity`）：串行加载与倒计时等待；
2. **切回热启开屏**（`HotSplashActivity`）：退后台超过 60 秒返回时触发；
3. **门锁页横幅与开锁后全屏插屏**（如倍孜 `BeiZiNewInterstitialActivity`）。

实机拦截验证发现，当主广告域名被拒绝后，多家 SDK 会立即切换**二级备用域与直播流媒体域**：
- 穿山甲：`api-access.pangolin-sdk-toutiao.com` → `api-access.pangolin-sdk-toutiao1.com` → `webcast-open.douyin.com`
- 倍孜 / AdScope：`sdk.beizi.biz` → `sdktmp.hubcloud.com.cn`
- 快手联盟：`open.e.kuaishou.com` → `open.kuaishouzt.com` → `open.kwaizt.com` / `g-api.kwai.com` → `*.pull.yximgs.com`

**解决策略**：
- 对纯广告域与编号后缀使用 `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` 拦截；
- 对消费类共享域（`douyin.com`、`yximgs.com`、`zijieapi.com`、`snssdk.com` 等），在代理模式中用 `AND,((PROCESS-NAME,com.tmall.campus.and),...)` 做**进程级隔离**，在无代理模式中利用 Android `VpnService.Builder.addAllowedApplication("com.tmall.campus.and")` 实现 **Per-App DNS 隔离**。
- 实测效果：单次冷启动期间 **402 次**广告请求全部命中 `REJECT`，而 `biz.confong.cn`、`content.confong.cn`、`alicdn.com`、`dingtalk.com` 等业务域名 100% 放行。

---

## 3. 31 秒开锁卡顿的真实根因

通过对门锁 JSBridge（`ZMUnlockJsBridge`）及蓝牙管理类（`MvLockManager`）的分析与真机日志比对：
- 门锁 H5 页通过服务端 MTOP 接口获取加密开锁载荷 `syncData`，再通过 WindVane JSBridge 传给 `MvLockManager.openLock(mac, syncData, callback)`；
- `MvLockManager.registMvLock()` 硬编码了 `FastBle` 参数：
  - `reconnectCount = 2`
  - `reconnectInterval = 5000 ms`
  - `connectOverTime = 20000 ms`
  - `operateTimeout = 5000 ms`
- 当用户在走廊距离门锁过远时提前点击开锁，底层 BLE 连接失败（`status=62`）会连续重试 3 次，总计阻塞 **~31.4 秒**；而在门前 1 米内点击开锁，从发起连接到完成开门仅需 **~2.7 秒**。

**解决策略**：
1. 通过 `LaunchProxyActivity` + Doze 电池白名单将热启动直达门锁页时间压至 **~0.44 秒**；
2. 内置 `BleProximityMonitor` 监测门锁广播信号强度（RSSI ≥ -68 dBm 为门前安全区），配合门框 NFC 贴纸从交互层面杜绝远处误点。

---

## 4. Per-App 本地 DNS VPN 原理

无代理用户的内置 `AdBlockVpnService` 采用了零 TCP 代理开销的纯 DNS 虚拟网卡架构：
1. 调用 `addAllowedApplication("com.tmall.campus.and")` 限定仅接管单个 App；
2. 分配虚拟网卡 `10.120.0.1/32`，设置虚拟 DNS `10.120.0.2`，**仅添加 `10.120.0.2/32` 单条路由**；
3. 业务 HTTPS/TCP 流量完全不经过 TUN 接口，保持原生内核速度；
4. 所有发往 `10.120.0.2:53` 的 UDP DNS 查询由 `DnsPacketCodec` 解析 QNAME：
   - 命中 `AdBlockMatcher`：本地合成带完整 RFC 791/768 校验和的 `NXDOMAIN` (`RCODE=3`) 报文，**< 1 ms 写回 TUN**；
   - 未命中或位于 `allowlist`：经 `protect()` 保护的 UDP Socket 转发至上游 DNS（`223.5.5.5` / `119.29.29.29`）并原样封装返回。
