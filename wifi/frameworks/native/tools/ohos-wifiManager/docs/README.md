# ohos-wifiManager

## 概述

WiFi STA（Station）模式控制工具，提供启用/禁用 STA 模式和 WiFi 扫描功能。

## 功能列表

- **sta-enable**: 启用 WiFi STA 模式
- **sta-disable**: 禁用 WiFi STA 模式
- **scan-start**: 启动 WiFi 扫描
- **scan-list**: 列出扫描结果
- **sta-connect**: 连接WiFi
- **sta-getLinkedInfo**: 查看网络连接状态

## 依赖

- 系统能力：`SystemCapability.Communication.WiFi.STA`
- 权限：
  - `ohos.permission.cli.MANAGE_WIFI_TOGGLE`
  - `ohos.permission.cli.MANAGE_WIFI_SCAN`
  - `ohos.permission.cli.MANAGE_WIFI_CONNECT`

## 安装路径

```
/system/bin/cli_tool/executable/ohos-wifiManager
```