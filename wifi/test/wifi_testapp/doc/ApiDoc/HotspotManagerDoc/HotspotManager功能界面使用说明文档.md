## HotspotManager使用说明文档

​		本文档主要介绍了Wifi专项测试程序的HotspotManager部分（@ohos.wifiManager.d.ts）的功能使用说明。

#### 从主界面跳转到HotspotManager部分

---

#### setting界面

点击"switch"按钮，设置本设备的热点参数配置。



热点配置信息包括：

>### HotspotConfig  热点配置信息
>
>|   **名称**   |       **类型**       | 默认值设置 | **说明**                                |
>| :----------: | :------------------: | :--------: | :-------------------------------------- |
>|     ssid     |        string        |  testApp   | 热点的SSID，编码格式为UTF-8。           |
>| securityType | **WifiSecurityType** |     3      | 加密类型。                              |
>|     band     |        number        |     1      | 热点的带宽。1: 2.4G, 2: 5G, 3: 双模频段 |
>| preSharedKey |        string        |  12345678  | 热点的密钥。                            |
>|   maxConn    |        number        |     32     | 最大设备连接数。                        |
>|   channel    |        number        |     6      | 频道                                    |
>
>
>
>#### WifiSecurityType  表示加密类型的枚举
>
>| **名称**                    | **值** | **说明**                                              |
>| :-------------------------- | :----- | :---------------------------------------------------- |
>| WIFI_SEC_TYPE_INVALID       | 0      | 无效加密类型。                                        |
>| WIFI_SEC_TYPE_OPEN          | 1      | 开放加密类型。                                        |
>| WIFI_SEC_TYPE_WEP           | 2      | Wired Equivalent Privacy (WEP)加密类型。              |
>| WIFI_SEC_TYPE_PSK           | 3      | Pre-shared key (PSK)加密类型。                        |
>| WIFI_SEC_TYPE_SAE           | 4      | Simultaneous Authentication of Equals (SAE)加密类型。 |
>| WIFI_SEC_TYPE_EAP9+         | 5      | EAP加密类型。                                         |
>| WIFI_SEC_TYPE_EAP_SUITE_B9+ | 6      | Suite-B 192位加密类型。                               |
>| WIFI_SEC_TYPE_OWE9+         | 7      | 机会性无线加密类型。                                  |
>| WIFI_SEC_TYPE_WAPI_CERT9+   | 8      | WAPI-Cert加密类型。                                   |
>| WIFI_SEC_TYPE_WAPI_PSK9+    | 9      | WAPI-PSK加密类型。                                    |



#### HotsptManager（@ohos.wifiManager.d.ts）的主要接口

|        method名称        |          API名称           |        所需参数         |             返回值              | 备注 |
| :----------------------: | :------------------------: | :---------------------: | :-----------------------------: | :--: |
|         使能热点         |       enableHotspot        |           ()            |              void               |      |
|        去使能热点        |       disableHotspot       |           ()            |              void               |      |
|     热点是否支持双频     | isHotspotDualBandSupported |           ()            |             boolean             |      |
|      热点是否已使能      |        isHostActive        |           ()            |             boolean             |      |
|     设置热点配置信息     |      setHotspotConfig      | (config: HotspotConfig) |              void               |      |
|       热点配置信息       |      getHotspotConfig      |           ()            |          HotspotConfig          |      |
|      获取连接的设备      |     getHotspotStations     |           ()            |       Array<StationInfo>        |      |
|   注册热点状态改变事件   |   on.hotspotStateChange    |                         |   callback: Callback<number>    |      |
| 注册热点加入状态改变事件 |     on.hotspotStaJoin      |                         | callback: Callback<StationInfo> |      |
| 注册热点离开状态改变事件 |     on.hotspotStaLeave     |                         | callback: Callback<StationInfo> |      |
|                          |                            |                         |                                 |      |



#### 返回值介绍

>#### HotspotConfig   热点配置信息   (内容类型同上)
>
>
>
>#### Array<StationInfo>      StationInfo  接入的设备信息
>
>| **名称**   | **类型** | **可读** | **可写** | **说明**   |
>| :--------- | :------- | :------- | :------- | :--------- |
>| name       | string   | 是       | 否       | 设备名称。 |
>| macAddress | string   | 是       | 否       | MAC地址。  |
>| ipAddress  | string   | 是       | 否       | IP地址。   |



**热点和WiFi是无法同时打开的，只要有一个打开着，另一个就无法打开**



#### 功能

**"热点打开"是其他功能测试的前提**

1.  开/关热点 （ enableHotspot/disableHotspot ）

    **此方法是异步的**

    enableHotspot :  在启用Wi-Fi热点之后，Wi-Fi可能被禁用

    disableHotspot  :  如果在禁用Wi-Fi热点之后启用Wi-Fi，可能会重新启用Wi-Fi。

    - 使用指导：点击后，在设备上启动/关闭热点；根据设备的热点使能情况，显示返回信息。

    - 限制条件：

      - @throws {BusinessError} 201 - Permission denied.
      * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
      * @throws {BusinessError} 801 - Capability not supported.
      * @throws {BusinessError} 2601000 - Operation failed.
      * 返回值为void                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           

    - 验证方法：可用其他设备查看是否能搜到该设备的热点

      

2.  热点是否支持双频 ( isHotspotDualBandSupported )

    - 使用指导：检查用作 Wi-Fi 热点的设备是否同时支持 2.4 GHz 和 5 GHz Wi-Fi。

    - 限制条件：

      - @throws {BusinessError} 201 - Permission denied.
      * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
      * @throws {BusinessError} 801 - Capability not supported.
      * @throws {BusinessError} 2601000 - Operation failed.

    - 验证方法：如果方法调用成功，则返回 code: true，否则返回 code: false

      

3.  热点是否已使能 isHotspotActive

    - 使用指导：检查设备上的热点是否处于使能状态

    - 限制条件：

      - @throws {BusinessError} 201 - Permission denied.

      - @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
      - @throws {BusinessError} 801 - Capability not supported.
      - @throws {BusinessError} 2601000 - Operation failed.

    - 验证方法：如果启用了热点，则返回code： true，否则返回code ：false 

      

4.  设置热点配置信息 setHotspotConfig

    - 使用指导：设置设备的热点

    - 限制条件：只能配置 OPEN 和 WPA2 PSK 热点。

      - (config: HotspotConfig)配置表示 Wi-Fi 热点配置。
      - SSID 和 securityType 必须可用且正确。
      - 如果 securityType 不是 {open}，则 preSharedKey 必须可用且正确。
      - 返回值为void
      - @throws {BusinessError} 201 - Permission denied.
      * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
      * @throws {BusinessError} 401 - Invalid parameters.
      * @throws {BusinessError} 801 - Capability not supported.
      * @throws {BusinessError} 2601000 - Operation failed.

    - 验证方法：查看使能后热点的配置信息。

      

5.  热点配置信息 getHotspotConfig

    - 使用指导：获取 Wi-Fi 热点配置

    - 限制条件：

      - @throws {BusinessError} 201 - Permission denied.

      - @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
      - @throws {BusinessError} 801 - Capability not supported.
      - @throws {BusinessError} 2601000 - Operation failed.

    - 验证方法：返回现有或已启用的 Wi-Fi 热点的配置。

      

6.  获取连接的设备  getStations

    - 使用指导：获取连接到 Wi-Fi 热点的客户端列表。

    - 限制条件：

      - 此方法只能在用作 Wi-Fi 热点的设备上使用
      - @throws {BusinessError} 201 - Permission denied.
      * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
      * @throws {BusinessError} 801 - Capability not supported.
      * @throws {BusinessError} 2601000 - Operation failed.

    - 验证方法：返回连接到 Wi-Fi 热点的客户端列表。

      

7.  订阅/取消订阅注册热点状态改变事件 on/off.hotspotStateChange  

    - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。

    - 限制条件：需要在相关类型事件发生改变前，开启监听。

      > 注册状态变化：
      >
      > - 订阅热点状态更改时报告的事件。
      >
      > - type为要侦听的热点状态更改事件的类型。
      >
      >
      > - callback回调用于侦听热点状态事件。

      - 若本地热点已关闭，返回值为0，显示信息为"inactive"；
      - 若本地热点已打开，返回值为1，显示信息为"active"；
      - 若本地热点正在打开，返回值为2，显示信息为"activating"；
      - 若本地热点正在关闭，返回值为3，显示信息为"de-activating"；
      - @throws {BusinessError} 201 - Permission denied.
      * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
      * @throws {BusinessError} 401 - Invalid parameters.
      * @throws {BusinessError} 801 - Capability not supported.
      - @throws {BusinessError} 2601000 - Operation failed.

    - 验证方法：在事件变化后，查看是否有弹窗信息显示。

      

8.  订阅/取消订阅注册热点加入改变事件 on/off.hotspotStaJoin

    - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。

    - 限制条件：需要在相关类型事件发生改变前，开启监听。

      > 注册状态变化：
      >
      > - 订阅热点加入状态更改时报告的事件。
      >
      > - type为要侦听的热点加入状态更改事件的类型。
      >
      >
      > - callback回调用于侦听热点加入状态事件。

      - 返回热点加入的状态信息
      - @throws {BusinessError} 201 - Permission denied.
      * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
      * @throws {BusinessError} 401 - Invalid parameters.
      * @throws {BusinessError} 801 - Capability not supported.
      * @throws {BusinessError} 2601000 - Operation failed.

    - 验证方法：在事件变化后，查看是否有弹窗信息显示。

      

9.  订阅/取消订阅注册热点离开改变事件on/off.hotspotStaLeave

    - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。

    - 限制条件：需要在相关类型事件发生改变前，开启监听。

      > 注册状态变化：
      >
      > - 订阅热点离开状态更改时报告的事件。
      >
      > - type为要侦听的热点离开状态更改事件的类型。
      >
      >
      > - callback回调用于侦听热点离开状态事件。

      - 返回热点离开的状态信息
      - @throws {BusinessError} 201 - Permission denied.
      * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
      * @throws {BusinessError} 401 - Invalid parameters.
      * @throws {BusinessError} 801 - Capability not supported.
      - @throws {BusinessError} 2601000 - Operation failed.

    - 验证方法：在事件变化后，查看是否有弹窗信息显示。
