## Wifi使用说明文档

​		本文档主要介绍Wifi专项测试程序的Wifi部分（@ohos.wifi.d.ts）的功能使用说明。

#### 从主界面跳转到WIFI部分

---

#### setting界面

点击"switch"按钮 ，设置本设备的wifi参数配置。



Wifi配置信息包括: 

>### WifiDeviceConfig    WLAN配置信息
>
>| **参数名称**  |       **类型**       |               默认值设置                | **说明**                                           |
>| :-----------: | :------------------: | :-------------------------------------: | :------------------------------------------------- |
>|     ssid      |        string        |              TP-LINK_6365               | 热点的SSID，编码格式为UTF-8。                      |
>|     bssid     |        string        |            6c:b1:58:75:63:67            | 热点的BSSID。                                      |
>| preSharedKey  |        string        |               kaihong123                | 热点的密钥。                                       |
>| isHiddenSsid  |       boolean        |                  false                  | 是否是隐藏网络。                                   |
>| securityType  | **WifiSecurityType** |                    3                    | 加密类型。                                         |
>|  creatorUid   |        number        |                    1                    | 创建用户的ID。 **系统接口：** 此接口为系统接口。   |
>| disableReason |        number        |                    0                    | 禁用原因。 **系统接口：** 此接口为系统接口。       |
>|     netId     |        number        |                    0                    | 分配的网络ID。 **系统接口：** 此接口为系统接口。   |
>| randomMacType |        number        |                    0                    | 随机MAC类型。 **系统接口：** 此接口为系统接口。    |
>| randomMacAddr |        string        |            xx:xx:xx:xx:xx:xx            | 随机MAC地址。 **系统接口：** 此接口为系统接口。    |
>|    ipType     |      **IpType**      |                    1                    | IP地址类型。 **系统接口：** 此接口为系统接口。     |
>|   staticIp    |     **IpConfig**     | ipAddress；gateway；dnsServers；domains | 静态IP配置信息。 **系统接口：** 此接口为系统接口。 |
>
>  
>
>#### WifiSecurityType  表示加密类型的枚举
>
>| **值** |       **描述**        |                       **说明**                        |
>| :----: | :-------------------: | :---------------------------------------------------: |
>|   0    | WIFI_SEC_TYPE_INVALID |                    无效加密类型。                     |
>|   1    |  WIFI_SEC_TYPE_OPEN   |                    开放加密类型。                     |
>|   2    |   WIFI_SEC_TYPE_WEP   |       Wired Equivalent Privacy (WEP)加密类型。        |
>|   3    |   WIFI_SEC_TYPE_PSK   |            Pre-shared key (PSK)加密类型。             |
>|   4    |   WIFI_SEC_TYPE_SAE   | Simultaneous Authentication of Equals (SAE)加密类型。 |
>
>
>
>#### IpType   表示IP类型的枚举
>
>|  值  |  描述   |      说明      |
>| :--: | :-----: | :------------: |
>|  0   | STATIC  |    静态IP。    |
>|  1   |  DHCP   | 通过DHCP获取。 |
>|  2   | UNKNOWN |    未指定。    |
>
>
>
>#### IpConfig   IP配置信息
>
>| **参数名称** |   **类型**    | 默认值设为 |  **说明**   |
>| :----------: | :-----------: | :--------: | :---------: |
>|  ipAddress   |    number     | 3232235880 |  IP地址。   |
>|   gateway    |    number     | 3232235777 |   网关。    |
>|  dnsServers  |   number[]    | 3716386629 | DNS服务器。 |
>|   domains    | Array<string> |            |  域信息。   |
>
>

#### WIFi（@ohos.wifi.d.ts）的主要接口

|          method名称          |             API名称             |           所需参数           |                     返回值                     | 备注 |
| :--------------------------: | :-----------------------------: | :--------------------------: | :--------------------------------------------: | :--: |
|           使能WIFI           |           enableWifi            |              ()              |                    boolean                     |      |
|          去使能WIFI          |           disableWifi           |              ()              |                    boolean                     |      |
|          是否已使能          |          isWifiActive           |              ()              |                    boolean                     |      |
|         启动WLAN扫描         |              scan               |              ()              |                    boolean                     |      |
|     获取扫描信息,promise     |      getScanInfos(promise)      |              ()              |          Promise<Array<WifiScanInfo>>          |      |
|    获取扫描信息,callback     |     getScanInfos(callback)      |              ()              | (callback: AsyncCallback<Array<WifiScanInfo>>) |      |
|     添加网络配置,promise     |    addDeviceConfig(promise)     |  (config: WifiDeviceConfig)  |                Promise<number>                 |      |
|    添加网络配置,callback     |    addDeviceConfig(callback)    |  (config: WifiDeviceConfig)  |       (callback: AsyncCallback<number>)        |      |
| 添加不可信网络配置，promise  |   addUntrustedConfig(promise)   |  (config: WifiDeviceConfig)  |                Promise<boolean>                |      |
| 添加不可信网络配置，callback |  addUntrustedConfig(callback)   |  (config: WifiDeviceConfig)  |       (callback: AsyncCallback<boolean>)       |      |
| 移除不可信网络配置，promise  | removeUntrustedConfig(promise)  |  (config: WifiDeviceConfig)  |                Promise<boolean>                |      |
| 移除不可信网络配置，callback | removeUntrustedConfig(callback) |  (config: WifiDeviceConfig)  |       (callback: AsyncCallback<boolean>)       |      |
|        连接到指定网络        |        connectToNetwork         |     (networkId: number)      |                    boolean                     |      |
|        连接到指定网络        |         connectToDevice         |  (config: WifiDeviceConfig)  |                    boolean                     |      |
|        断开连接的网络        |           disconnect            |              ()              |                    boolean                     |      |
|       查询WLAN信号强度       |         getSignalLevel          | (rssi: number, band: number) |                     number                     |      |
|   获取WLAN连接信息,promise   |     getLinkedInfo(promise)      |              ()              |            Promise<WifiLinkedInfo>             |      |
|  获取WLAN连接信息,callback   |     getLinkedInfo(callback)     |              ()              |   (callback: AsyncCallback<WifiLinkedInfo>)    |      |
|        WLAN是否已连接        |           isConnected           |              ()              |                    boolean                     |      |
|      查询设备支持的特性      |      getSupportedFeatures       |              ()              |                     number                     |      |
|     是否支持相关WLAN特性     |       isFeatureSupported        |     (featureId: number)      |                    boolean                     |      |
|      获取设备的MAC地址       |       getDeviceMacAddress       |              ()              |                    string[]                    |      |
|          获取IP信息          |            getIpInfo            |              ()              |                     IpInfo                     |      |
|        获取国家码信息        |         getCountryCode          |              ()              |                     string                     |      |
|         重新关联网络         |           reassociate           |              ()              |                    boolean                     |      |
|         重新连接网络         |            reConnect            |              ()              |                    boolean                     |      |
|         获取网络配置         |        getDeviceConfigs         |              ()              |            Array<WifiDeviceConfig>             |      |
|         更新网络配置         |          updateNetwork          |  (config: WifiDeviceConfig)  |                     number                     |      |
|        去使能网络配置        |         disableNetwork          |       (netId: number)        |                    boolean                     |      |
|       移除所有网络配置       |        removeAllNetwork         |              ()              |                    boolean                     |      |
|      移除指定的网络配置      |          removeDevice           |         (id: number)         |                    boolean                     |      |
|     注册WLAN状态改变事件     |       on.wifiStateChange        |                              |          (callback: Callback<number>)          |      |
|   注册WLAN连接状态改变事件   |     on.wifiConnectionChange     |                              |          (callback: Callback<number>)          |      |
|     注册扫描状态改变事件     |     on.wifiScanStateChange      |                              |          (callback: Callback<number>)          |      |
|     注册RSSI状态改变事件     |        on.wifiRssiChange        |                              |          (callback: Callback<number>)          |      |
|        注册流改变事件        |         on.streamChange         |                              |          (callback: Callback<number>)          |      |
|                              |                                 |                              |                                                |      |



#### 返回值介绍

>#### WifiScanInfo      WLAN热点信息
>
>| **名称**     | **类型**             | **可读** | **可写** | **说明**                      |
>| :----------- | :------------------- | :------- | :------- | :---------------------------- |
>| ssid         | string               | 是       | 否       | 热点的SSID，编码格式为UTF-8。 |
>| bssid        | string               | 是       | 否       | 热点的BSSID。                 |
>| capabilities | string               | 是       | 否       | 热点能力。                    |
>| securityType | **WifiSecurityType** | 是       | 否       | WLAN加密类型。                |
>| rssi         | number               | 是       | 否       | 热点的信号强度(dBm)。         |
>| band         | number               | 是       | 否       | WLAN接入点的频段。            |
>| frequency    | number               | 是       | 否       | WLAN接入点的频率。            |
>| channelWidth | number               | 是       | 否       | WLAN接入点的带宽。            |
>| timestamp    | number               | 是       | 否       | 时间戳。                      |
>
>
>
>#### WifiSecurityType   表示加密类型的枚举
>
>| **名称**              | **值** | **说明**                                              |
>| :-------------------- | :----- | :---------------------------------------------------- |
>| WIFI_SEC_TYPE_INVALID | 0      | 无效加密类型。                                        |
>| WIFI_SEC_TYPE_OPEN    | 1      | 开放加密类型。                                        |
>| WIFI_SEC_TYPE_WEP     | 2      | Wired Equivalent Privacy (WEP)加密类型。              |
>| WIFI_SEC_TYPE_PSK     | 3      | Pre-shared key (PSK)加密类型。                        |
>| WIFI_SEC_TYPE_SAE     | 4      | Simultaneous Authentication of Equals (SAE)加密类型。 |
>
>
>
>#### WifiLinkedInfo   提供WLAN连接的相关信息
>
>| 名称         | 类型          | 可读 | 可写 | 说明                                                         |
>| :----------- | :------------ | :--- | :--- | :----------------------------------------------------------- |
>| ssid         | string        | 是   | 否   | 热点的SSID，编码格式为UTF-8。                                |
>| bssid        | string        | 是   | 否   | 热点的BSSID。                                                |
>| networkId    | number        | 是   | 否   | 网络配置ID。 **系统接口：** 此接口为系统接口。               |
>| rssi         | number        | 是   | 否   | 热点的信号强度(dBm)。                                        |
>| band         | number        | 是   | 否   | WLAN接入点的频段。                                           |
>| linkSpeed    | number        | 是   | 否   | WLAN接入点的速度。                                           |
>| frequency    | number        | 是   | 否   | WLAN接入点的频率。                                           |
>| isHidden     | boolean       | 是   | 否   | WLAN接入点是否是隐藏网络。                                   |
>| isRestricted | boolean       | 是   | 否   | WLAN接入点是否限制数据量。                                   |
>| chload       | number        | 是   | 否   | 连接负载，值越大表示负载约高。 **系统接口：** 此接口为系统接口。 |
>| snr          | number        | 是   | 否   | 信噪比。 **系统接口：** 此接口为系统接口。                   |
>| macAddress   | string        | 是   | 否   | 设备的MAC地址。                                              |
>| ipAddress    | number        | 是   | 否   | WLAN连接的IP地址。                                           |
>| suppState    | **SuppState** | 是   | 否   | 请求状态。 **系统接口：** 此接口为系统接口。                 |
>| connState    | **ConnState** | 是   | 否   | WLAN连接状态。                                               |
>
>
>
>#### ConnState   表示WLAN连接状态的枚举
>
>| 名称             | 值   | 说明                       |
>| :--------------- | :--- | :------------------------- |
>| SCANNING         | 0    | 设备正在搜索可用的AP。     |
>| CONNECTING       | 1    | 正在建立WLAN连接。         |
>| AUTHENTICATING   | 2    | WLAN连接正在认证中。       |
>| OBTAINING_IPADDR | 3    | 正在获取WLAN连接的IP地址。 |
>| CONNECTED        | 4    | WLAN连接已建立。           |
>| DISCONNECTING    | 5    | WLAN连接正在断开。         |
>| DISCONNECTED     | 6    | WLAN连接已断开。           |
>| UNKNOWN          | 7    | WLAN连接建立失败。         |
>
>
>
>#### SuppState   表示请求状态的枚举
>
>| 名称               | 值   | 说明             |
>| :----------------- | :--- | :--------------- |
>| DISCONNECTED       | 0    | 已断开。         |
>| INTERFACE_DISABLED | 1    | 接口禁用。       |
>| INACTIVE           | 2    | 未激活。         |
>| SCANNING           | 3    | 扫描中。         |
>| AUTHENTICATING     | 4    | 认证中。         |
>| ASSOCIATING        | 5    | 关联中。         |
>| ASSOCIATED         | 6    | 已关联。         |
>| FOUR_WAY_HANDSHAKE | 7    | 四次握手。       |
>| GROUP_HANDSHAKE    | 8    | 组握手。         |
>| COMPLETED          | 9    | 所有认证已完成。 |
>| UNINITIALIZED      | 10   | 连接建立失败。   |
>| INVALID            | 11   | 无效值。         |
>
>
>
>#### IpInfo   IP信息
>
>| **名称**      | **类型** | **可读** | **可写** | **说明**            |
>| :------------ | :------- | :------- | :------- | :------------------ |
>| ipAddress     | number   | 是       | 否       | IP地址。            |
>| gateway       | number   | 是       | 否       | 网关。              |
>| netmask       | number   | 是       | 否       | 掩码。              |
>| primaryDns    | number   | 是       | 否       | 主DNS服务器IP地址。 |
>| secondDns     | number   | 是       | 否       | 备DNS服务器IP地址。 |
>| serverIp      | number   | 是       | 否       | DHCP服务端IP地址。  |
>| leaseDuration | number   | 是       | 否       | IP地址租用时长。    |
>
>
>
>#### WifiDeviceConfig  WLAN配置信息  (内容类型同上)



**热点和WiFi是无法同时打开的，只要有一个打开着，另一个就无法打开**

#### 功能

**"Wifi打开"是其他功能测试的前提**

1.  开/关Wifi（enableWifi/disableWifi）

   - 使用指导：点击后，在设备上启动/关闭Wifi；根据设备的Wifi情况，显示返回信息。

   - 限制条件：
     - 若Wifi未开，点击"开Wifi"，显示信息为"true"；
     - 若Wifi未开，点击"开Wifi"，发生错误，显示信息为"false"；
     - 若Wifi已打开，点击"开Wifi"，显示信息为"Wifi已经使能"。
     - 若Wifi已打开，点击"关Wifi"，显示结果为"true"；
     - 若Wifi已打开，点击"关Wifi"，发生错误，显示信息为"false"；
     - 若Wifi未打开，点击"关Wifi"，显示结果为"Wifi未使能"。
     
   - 验证方法：可在设备的设置中查看Wifi的开关情况

     

2.  获取状态（isWifiActive）

   - 使用指导：点击后，基于Wifi的开关状态，判断Wifi当时的状态。

   - 限制条件：
     - 若本地Wifi打开，返回值为true
     - 若本地Wifi关闭，返回值为false
     
   - 验证方法：可在设备设置中查看Wifi的当前状态

     

3.  订阅/取消订阅Wifi状态改变事件（on/off.wifiStateChange）

   - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。

   - 限制条件：需要在相关类型事件发生改变前，开启监听。
     
     > 注册状态变化：
     >
     > - 订阅Wifi状态更改时报告的事件。
     >
     > - type为要侦听的Wifi状态更改事件的类型。
     >
     >
     > - callback回调用于侦听Wifi状态事件。
     
     - 若本地Wifi已关闭，返回值为0，显示信息为"inactive"；
     - 若本地Wifi已打开，返回值为1，显示信息为"active"；
     - 若本地Wifi正在打开，返回值为2，显示信息为"activating"；
     - 若本地Wifi正在关闭，返回值为3，显示信息为"de-activating"；

   - 验证方法：在事件变化后，查看是否有弹窗信息显示。

     

4.  扫描（scan）

   - 使用指导：点击后，扫描Wi-Fi热点。

   - 限制条件：
     - 若扫描成功，返回值为true
     - 若扫描失败，返回值为false
     
   - 验证方法：查看扫描的结果判断是否扫描成功，利用on.wifiScanStateChange()和getScanInfos()查看返回的结果。

     

5.  获取扫描结果（getScanInfos (Callback/Promise) )
   - 使用指导：点击后，返回有关扫描的Wi-Fi热点的信息（如果有的话）

   - 限制条件：扫描成功

   - 验证方法：查看返回的信息

     

6.  订阅/取消订阅Wifi扫描状态改变事件（on/off.wifiScanStateChange）

   - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。

   - 限制条件：需要在相关类型事件发生改变前，开启监听。

     > 注册状态变化：
     >
     > - 订阅Wifi scan状态更改时报告的事件。
     >
     > - type为要侦听的Wifi scan状态更改事件的类型。
     >
     >
     > - callback回调用于侦听Wifi scan状态事件。

     - 若scan失败，返回值为0，显示信息为"scan fail"；
     - 若scan成功，返回值为1，显示信息为"scan success"；

   - 验证方法：在事件变化后，查看是否有弹窗信息显示。

     

7.  添加网络配置（addDeviceConfig (callback/promise)）

   - 使用指导：向设备添加Wi-Fi连接配置。

   - 限制条件：WiFi已使能，且配置的参数 (config: WifiDeviceConfig) 都正确。

   - 验证方法：查看返回的信息。如果添加了配置，则返回code：networkId；否则返回code： -1。

     

8.  添加不可信网络配置 （addUntrustedConfig  (promise/callback)）

    - 使用指导：添加不可信任的网络配置。

    - 限制条件：WiFi已使能，Wifi配置的参数 (config: WifiDeviceConfig)都正确。

    - 验证方法：查看返回的信息。如果添加了不受信任的热点配置，则返回code：true，否则返回code：false。

      

9.  移除不可信网络配置 （removeUntrustedConfig (promise/callback)）
    - 使用指导：移除指定的不受信任的网络配置。

    - 限制条件：WiFi已使能，Wifi配置的参数 (config: WifiDeviceConfig) 都正确。

    - 验证方法：查看返回的信息。如果删除不受信任的热点配置，则返回code：true，否则返回code ：false。

      

10.  订阅/取消订阅注册WLAN连接状态改变事件  ( on/off.wifiConnectionChange )

     - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。

     - 限制条件：需要在相关类型事件发生改变前，开启监听。

       > 注册状态变化：
       >
       > - 订阅Wifi连接状态更改时报告的事件。
       >
       > - type为要侦听的Wifi连接状态更改事件的类型。
       >
       >
       > - callback回调用于侦听Wifi连接状态事件。

       - 若未连接，返回值为0，显示信息为"disconnected"；
       - 若已连接，返回值为1，显示信息为"connected"；

     - 验证方法：在事件变化后，查看是否有弹窗信息显示。

       

11.  连接到指定网络 （connecToNetwork）

     - 使用指导：连接到Wi-Fi网络

     - 限制条件：WiFi已使能，networkId参数配置成功

     - 验证方法：查看返回的信息。如果网络连接成功，则返回code：true，否则返回code：false。

       

12.  连接到指定网络 （connecToDevice）

     - 使用指导：连接到Wi-Fi网络

     - 限制条件：WiFi已使能，Wifi参数配置 (config: WifiDeviceConfig) 成功

     - 验证方法：查看返回的信息。如果网络连接成功，则返回code：true，否则返回code：false。

       

13.  查询WLAN是否已连接 (isConnected)
     - 使用指导：连接到Wi-Fi网络

     - 限制条件：WiFi已使能

     - 验证方法：查看返回的信息。如果Wi-Fi已经连接，则返回code：true，否则返回code：false。

       

14.  获取WLAN连接信息 （getLinkedInfo (promise/callback)）
     - 使用指导：获取有关Wi-Fi连接的信息

     - 限制条件：设备已经连接上了WiFi验证方法：查看返回的信息。返回Wi-Fi连接信息  ( WifiLinkedInfo )。

     - 验证方法：查看返回的信息。与设备的wifi连接是否一样

       

15.  WLAN信号强度 （getSignalLevel）
     - 使用指导：基于Wi-Fi的RSSI和频段( band )来计算Wi-Fi信号强度

     - 限制条件：设备已经连接上了WiFi，且获得了rssi（热点的信号强度）和band（WLAN接入点的频段）

     - 验证方法：查看返回的信息。返回范围从0到4的Wi-Fi信号强度。

       

16.  查询设备支持的特性 (getSupportedFeatures)

     - 使用指导：获取此设备支持的功能特性

     - 限制条件：无

     - 验证方法：查看返回的信息。返回此设备支持的特性Id

       

17.  判断设备是否支持相关WLAN特性( isFeatureSupported )

     - 使用指导：检查此设备是否支持指定功能

     - 限制条件：参数为特性功能Id (featureId: number)

     - 验证方法：查看返回的信息。如果此设备支持指定的功能，则返回code：true，否则返回ode：false。

       

18.  获取设备的MAC地址 ( getDeviceMacAddress )

     - 使用指导：获取 Wi-Fi 设备的 MAC 地址

     - 限制条件：必须启用 Wi-Fi。MAC 地址是唯一的，无法更改。

     - 验证方法：查看返回的信息。

       

19.  获取IP信息  ( getIpInfo )

     - 使用指导：获取 Wi-Fi 连接的 IP 信息。

     - 限制条件：设备已经连接上了WiFi。IP 信息包括主机 IP 地址、网关地址和 DNS 信息。

     - 验证方法：查看返回的信息。返回 Wi-Fi 连接的 IP 信息。

       

20.  获取国家码信息 ( getCountryCode )

     - 使用指导：获取此设备的国家/地区代码。

     - 限制条件：设备已经连接上了WiFi

     - 验证方法：查看返回的信息。返回此设备的国家/地区代码。

       

21.  断开连接的网络 ( disconnect）

     - 使用指导：断开Wi-Fi网络连接

     - 限制条件：设备已经连接上了WiFi

     - 验证方法：查看返回的信息。如果断开网络成功，返回code：true；否则返回code：false。

       

22.  重新关联网络 ( reassociate )

     - 使用指导： 重新关联到当前网络

     - 限制条件： 与当前网络取消关联

     - 验证方法： 查看返回的信息。如果 Wi-Fi 网络重新关联成功，返回code ：true；否则返回code：false。

       

23.  重新连接网络 ( reconnect )

     - 使用指导： 当前网络重新连接

     - 限制条件： 与当前网络断开连接

     - 验证方法： 查看返回的信息。如果断开网络成功，则返回code：true，否则返回 code：false

       

24.  获取网络配置 ( getDeviceConfigs )

     - 使用指导： 获取所有现有 Wi-Fi 配置的列表

     - 限制条件： 只能获取在自己的应用程序上创建的 Wi-Fi 配置。

     - 验证方法： 查看返回的信息。返回在应用程序上创建的所有现有 Wi-Fi 配置的列表。

       

25.  更新网络配置 ( updateNetwork)

     - 使用指导： 更新指定的 Wi-Fi 配置

     - 限制条件： 参数： (config: WifiDeviceConfig) ，指示要更新的 Wi-Fi 配置

     - 验证方法： 查看返回的信息。如果更新成功，则返回更新后的 Wi-Fi 配置中的网络 ID ;  如果列表中未包含指定的 Wi-Fi 配置，则返回code：-1。

       

26.  去使能网络配置 ( disableNetwork ) 

     - 使用指导： 禁用指定的网络

     - 限制条件： 参数：netId ，标识要禁用的网络。禁用的网络将不会再次关联。

     - 验证方法： 查看返回的信息。如果禁用指定的网络，则返回code： true，否则返回code：false。

       

27.  移除所有网络配置 ( removeAllNetwork )

     - 使用指导： 删除所有已保存的 Wi-Fi 配置。

     - 限制条件： 无

     - 验证方法： 查看返回的信息。如果删除所有保存的 Wi-Fi 配置，则返回 code：true；否则返回 code：false

       

28.  移除指定的网络配置 ( removeDevice )

     - 使用指导： 删除具有指定 ID 的 Wi-Fi 网络。

       - 删除 Wi-Fi 网络后，其配置将从 Wi-Fi 配置列表中删除。
       - 如果正在连接Wi-Fi网络，则连接将中断
       - 应用程序只能删除它创建的 Wi-Fi 网络。

     - 限制条件： 参数：id ，表示 Wi-Fi 网络的 ID （可以使用 {addDeviceConfig} 或 {getLinkedInfo} 方法获得。）

     - 验证方法： 查看返回的信息。如果成功删除 Wi-Fi 网络，则返回 code：true，否则返回 code：false。


​     

29.  订阅/取消订阅注册RSSI状态改变事件  ( on/off.wifiRssiChange )

     - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。

     - 限制条件：需要在相关类型事件发生改变前，开启监听。

       > 注册状态变化：
       >
       > - 订阅WifiRssi状态更改时报告的事件。
       >
       > - type为要侦听的WifiRssi状态更改事件的类型。
       >
       >
       > - callback回调用于侦听WifiRssi状态事件。

       - 返回以 dBm 为单位的 RSSI 值

     - 验证方法：在事件变化后，查看是否有弹窗信息显示。

       

30.  订阅/取消订阅注册流改变事件（ on/off.streamChange ）

     - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。
     - 限制条件：需要在相关类型事件发生改变前，开启监听。

       > 注册状态变化：
       >
       > - 订阅流状态更改时报告的事件。
       >
       > - type为要侦听的流状态更改事件的类型。
       >
       >
       > - callback回调用于侦听流状态事件。

       - 若流无，返回值为0，显示信息为"stream none"；
       - 若流向下，返回值为1，显示信息为"stream down"；
       - 若流向上，返回值为2，显示信息为"stream up"；
       - 若双向流，返回值为3，显示信息为"stream bidirectional"；

     - 验证方法：在事件变化后，查看是否有弹窗信息显示。
