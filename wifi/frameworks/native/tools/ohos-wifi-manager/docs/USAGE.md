# 使用说明

## 基本用法

```bash
ohos-wifiManager <command>
```

## 命令列表

| 命令 | 说明 | 权限 | 前置依赖 |
|------|------|------|----------|
| sta-enable | 启用 WiFi STA 模式 | SET_WIFI_INFO, MANAGE_WIFI_CONNECTION | 无 |
| sta-disable | 禁用 WiFi STA 模式 | SET_WIFI_INFO, MANAGE_WIFI_CONNECTION | 无 |
| scan-start | 启动 WiFi 扫描 | SET_WIFI_INFO | 无 |
| scan-list | 列出扫描结果 | GET_WIFI_INFO, GET_WIFI_PEERS_MAC | 无 |

## 示例

### 启用 WiFi STA 模式

```bash
ohos-wifiManager sta-enable
```

### 禁用 WiFi STA 模式

```bash
ohos-wifiManager sta-disable
```

### 启动 WiFi 扫描

```bash
ohos-wifiManager scan-start
```

### 列出扫描结果

```bash
ohos-wifiManager scan-list
```

## 输出格式

命令成功时返回 JSON 格式结果：

```json
{
  "success": true,
  "data": {
    "message": "WiFi STA mode enabled successfully"
  }
}
```

或扫描结果列表：

```json
{
  "success": true,
  "data": {
    "networks": [
      {
        "ssid": "MyWiFi",
        "bssid": "12:34:56:78:90:AB",
        "securityType": 5,
        "rssi": -45,
        "frequency": 2437
      }
    ],
    "count": 1
  }
}
```

命令失败时返回错误信息：

```json
{
  "success": false,
  "error": {
    "code": "WIFI_ERROR",
    "message": "WiFi cannot be enabled in airplane mode",
    "suggestion": "Check WiFi permissions and airplane mode"
  }
}
```