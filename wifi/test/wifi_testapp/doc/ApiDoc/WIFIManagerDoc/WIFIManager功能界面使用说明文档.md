## wifiManager使用说明文档

​		本文档主要介绍Wifi专项测试程序的WifiManager部分（@ohos.wifiManager.d.ts）的功能使用说明。

#### 从主界面跳转到WIFIManager部分

---

#### setting界面

点击"switch"按钮，设置本设备的wifi参数配置。



WifiManager配置信息包括：

>#### WifiDeviceConfig  WLAN配置信息
>
>|   **名称**    |       **类型**       |               默认值设置                | **说明**                                                   |
>| :-----------: | :------------------: | :-------------------------------------: | :--------------------------------------------------------- |
>|     ssid      |        string        |              TP-LINK_6365               | 热点的SSID，编码格式为UTF-8。                              |
>|     bssid     |        string        |            6c:b1:58:75:63:67            | 热点的BSSID。                                              |
>| preSharedKey  |        string        |               kaihong123                | 热点的密钥。                                               |
>| isHiddenSsid  |       boolean        |                  false                  | 是否是隐藏网络。                                           |
>| securityType  | **WifiSecurityType** |                    3                    | 加密类型。                                                 |
>|  creatorUid   |        number        |                    1                    | 创建用户的ID。 **系统接口：** 此接口为系统接口。           |
>| disableReason |        number        |                    0                    | 禁用原因。 **系统接口：** 此接口为系统接口。               |
>|     netId     |        number        |                    0                    | 分配的网络ID。 **系统接口：** 此接口为系统接口。           |
>| randomMacType |        number        |                    0                    | 随机MAC类型。 **系统接口：** 此接口为系统接口。            |
>| randomMacAddr |        string        |            xx:xx:xx:xx:xx:xx            | 随机MAC地址。 **系统接口：** 此接口为系统接口。            |
>|    ipType     |      **IpType**      |                    1                    | IP地址类型。 **系统接口：** 此接口为系统接口。             |
>|   staticIp    |     **IpConfig**     | ipAddress；gateway；dnsServers；domains | 静态IP配置信息。 **系统接口：** 此接口为系统接口。         |
>|  eapConfig9+  |  **WifiEapConfig**   |                                         | 可扩展身份验证协议配置。 **系统接口：** 此接口为系统接口。 |
>
>
>
>#### IpType   表示IP类型的枚举
>
>| 名称    | 值   | 说明           |
>| :------ | :--- | :------------- |
>| STATIC  | 0    | 静态IP。       |
>| DHCP    | 1    | 通过DHCP获取。 |
>| UNKNOWN | 2    | 未指定。       |
>
>
>
>#### IpConfig   IP配置信息
>
>| **名称**     | **类型**      | **可读** | **可写** | **说明**    |
>| :----------- | :------------ | :------- | :------- | :---------- |
>| ipAddress    | number        | 是       | 否       | IP地址。    |
>| gateway      | number        | 是       | 否       | 网关。      |
>| prefixLength | number        | 是       | 否       | 掩码。      |
>| dnsServers   | number[]      | 是       | 否       | DNS服务器。 |
>| domains      | Array<string> | 是       | 否       | 域信息。    |
>
>
>
>#### WifiEapConfig  可扩展身份验证协议配置信息
>
>| **名称**          | **类型**         | **可读** | **可写** | **说明**                         |
>| :---------------- | :--------------- | :------- | :------- | :------------------------------- |
>| eapMethod         | **EapMethod**    | 是       | 否       | EAP认证方式。                    |
>| phase2Method      | **Phase2Method** | 是       | 否       | 第二阶段认证方式。               |
>| identity          | string           | 是       | 否       | 身份信息。                       |
>| anonymousIdentity | string           | 是       | 否       | 匿名身份。                       |
>| password          | string           | 是       | 否       | 密码。                           |
>| caCertAliases     | string           | 是       | 否       | CA 证书别名。                    |
>| caPath            | string           | 是       | 否       | CA 证书路径。                    |
>| clientCertAliases | string           | 是       | 否       | 客户端证书别名。                 |
>| altSubjectMatch   | string           | 是       | 否       | 替代主题匹配。                   |
>| domainSuffixMatch | string           | 是       | 否       | 域后缀匹配。                     |
>| realm             | string           | 是       | 否       | 通行证凭证的领域。               |
>| plmn              | string           | 是       | 否       | 公共陆地移动网的直通凭证提供商。 |
>| eapSubId          | number           | 是       | 否       | SIM卡的子ID。                    |
>
>
>
>#### EapMethod   表示EAP认证方式的枚举
>
>| 名称           | 值   | 说明             |
>| :------------- | :--- | :--------------- |
>| EAP_NONE       | 0    | 不指定。         |
>| EAP_PEAP       | 1    | PEAP类型。       |
>| EAP_TLS        | 2    | TLS类型。        |
>| EAP_TTLS       | 3    | TTLS类型。       |
>| EAP_PWD        | 4    | PWD类型。        |
>| EAP_SIM        | 5    | SIM类型。        |
>| EAP_AKA        | 6    | AKA类型。        |
>| EAP_AKA_PRIME  | 7    | AKA Prime类型。  |
>| EAP_UNAUTH_TLS | 8    | UNAUTH TLS类型。 |
>
>
>
>#### Phase2Method   表示第二阶段认证方式的枚举
>
>| 名称             | 值   | 说明            |
>| :--------------- | :--- | :-------------- |
>| PHASE2_NONE      | 0    | 不指定。        |
>| PHASE2_PAP       | 1    | PAP类型。       |
>| PHASE2_MSCHAP    | 2    | MSCHAP类型。    |
>| PHASE2_MSCHAPV2  | 3    | MSCHAPV2类型。  |
>| PHASE2_GTC       | 4    | GTC类型。       |
>| PHASE2_SIM       | 5    | SIM类型。       |
>| PHASE2_AKA       | 6    | AKA类型。       |
>| PHASE2_AKA_PRIME | 7    | AKA Prime类型。 |



#### wifiManager（@ohos.wifiManager.d.ts）的主要接口

|        method名称         |             API名称             |           所需参数           |                  返回值                   | 备注 |
| :-----------------------: | :-----------------------------: | :--------------------------: | :---------------------------------------: | :--: |
|         使能WIFI          |           enableWifi            |              ()              |                   void                    |      |
|        去使能WIFI         |           disableWifi           |              ()              |                   void                    |      |
|        是否已使能         |          isWifiActive           |              ()              |                  boolean                  |      |
|       启动WLAN扫描        |              scan               |              ()              |                   void                    |      |
|       获取扫描信息        |         getScanInfoList         |              ()              |            Array<WifiScanInfo>            |      |
|   添加网络配置,promise    |    addDeviceConfig(promise)     |  (config: WifiDeviceConfig)  |              Promise<number>              |      |
|   添加网络配置,callback   |    addDeviceConfig(callback)    |  (config: WifiDeviceConfig)  |     (callback: AsyncCallback<number>)     |      |
|   添加候选配置,promise    |   addCandidateConfig(promise)   | （config: WifiDeviceConfig） |              Promise<number>              |      |
|   添加候选配置,callback   |  addCandidateConfig(callback)   | (config: WifiDeviceConfig）  |      callback: AsyncCallback<number>      |      |
|   移除候选配置，promise   | removeCandidateConfig(promise)  |     (networkId: number)      |               Promise<void>               |      |
|  移除候选配置，callback   | removeCandidateConfig(callback) |     (networkId: number）     |       callback: AsyncCallback<void>       |      |
|       获取候选配置        |       getCandidateConfigs       |             （）             |          Array<WifiDeviceConfig>          |      |
|      连接到候选配置       |    connectToCandidateConfig     |     (networkId: number)      |                   void                    |      |
|      连接到指定网络       |        connectToNetwork         |     (networkId: number)      |                   void                    |      |
|      连接到指定网络       |         connectToDevice         |  (config: WifiDeviceConfig)  |                   void                    |      |
|      断开连接的网络       |           disconnect            |              ()              |                   void                    |      |
|     查询WLAN信号强度      |         getSignalLevel          | (rssi: number, band: number) |                  number                   |      |
| 获取WLAN连接信息,promise  |     getLinkedInfo(promise)      |              ()              |          Promise<WifiLinkedInfo>          |      |
| 获取WLAN连接信息,callback |     getLinkedInfo(callback)     |              ()              | (callback: AsyncCallback<WifiLinkedInfo>) |      |
|      WLAN是否已连接       |           isConnected           |              ()              |                  boolean                  |      |
|    查询设备支持的特性     |      getSupportedFeatures       |              ()              |                  number                   |      |
|   是否支持相关WLAN特性    |       isFeatureSupported        |     (featureId: number)      |                  boolean                  |      |
|     获取设备的MAC地址     |       getDeviceMacAddress       |              ()              |                 string[]                  |      |
|        获取IP信息         |            getIpInfo            |              ()              |                  IpInfo                   |      |
|      获取国家码信息       |         getCountryCode          |              ()              |                  string                   |      |
|       重新关联网络        |           reassociate           |              ()              |                   void                    |      |
|       重新连接网络        |            reConnect            |              ()              |                   void                    |      |
|       获取网络配置        |        getDeviceConfigs         |              ()              |          Array<WifiDeviceConfig>          |      |
|     更新指定Wifi配置      |       updateDeviceConfig        |  (config: WifiDeviceConfig)  |                  number                   |      |
|     禁用指定设备配置      |       disableDeviceConfig       |     (networkId: number)      |                   void                    |      |
|     移除所有网络配置      |     removeAllDeviceConfigs      |              ()              |                   void                    |      |
|    移除指定的网络配置     |       removeDeviceConfig        |     (networkId: number)      |                   void                    |      |
|   注册WLAN状态改变事件    |       on.wifiStateChange        |                              |       (callback: Callback<number>)        |      |
| 注册WLAN连接状态改变事件  |     on.wifiConnectionChange     |                              |       (callback: Callback<number>)        |      |
|   注册扫描状态改变事件    |     on.wifiScanStateChange      |                              |       (callback: Callback<number>)        |      |
|   注册RSSI状态改变事件    |        on.wifiRssiChange        |                              |       (callback: Callback<number>)        |      |
|      注册流改变事件       |         on.streamChange         |                              |       (callback: Callback<number>)        |      |
|   注册设备配置改变事件    |      on.deviceConfigChange      |                              |       (callback: Callback<number>)        |      |
|                           |                                 |                              |                                           |      |



#### 返回值介绍

>#### WifiScanInfo    WLAN热点信息
>
>| **名称**         | **类型**                | **可读** | **可写** | **说明**                                                     |
>| :--------------- | :---------------------- | :------- | :------- | :----------------------------------------------------------- |
>| ssid             | string                  | 是       | 否       | 热点的SSID，编码格式为UTF-8。                                |
>| bssid            | string                  | 是       | 否       | 热点的BSSID。                                                |
>| capabilities     | string                  | 是       | 否       | 热点能力。                                                   |
>| securityType     | **WifiSecurityType**    | 是       | 否       | WLAN加密类型。                                               |
>| rssi             | number                  | 是       | 否       | 热点的信号强度(dBm)。                                        |
>| band             | number                  | 是       | 否       | WLAN接入点的频段。                                           |
>| frequency        | number                  | 是       | 否       | WLAN接入点的频率。                                           |
>| channelWidth     | number                  | 是       | 否       | WLAN接入点的带宽。                                           |
>| centerFrequency0 | number                  | 是       | 否       | 热点的中心频率。                                             |
>| centerFrequency1 | number                  | 是       | 否       | 热点的中心频率。如果热点使用两个不重叠的WLAN信道，则返回两个中心频率，分别用centerFrequency0和centerFrequency1表示。 |
>| infoElems        | Array**<WifiInfoElem>** | 是       | 否       | 信息元素。                                                   |
>| timestamp        | number                  | 是       | 否       | 时间戳。                                                     |
>
>
>
>#### WifiSecurityType   表示加密类型的枚举
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
>
>
>
>#### WifiInfoElem    WLAN热点信息
>
>| **名称** | **类型**   | **可读** | **可写** | **说明**   |
>| :------- | :--------- | :------- | :------- | :--------- |
>| eid      | number     | 是       | 否       | 元素ID。   |
>| content  | Uint8Array | 是       | 否       | 元素内容。 |
>
>
>
>#### WifiLinkedInfo  提供WLAN连接的相关信息
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
>| macType9+    | number        | 是   | 否   | MAC地址类型。                                                |
>| macAddress   | string        | 是   | 否   | 设备的MAC地址。                                              |
>| ipAddress    | number        | 是   | 否   | WLAN连接的IP地址。                                           |
>| suppState    | **SuppState** | 是   | 否   | 请求状态。 **系统接口：** 此接口为系统接口。                 |
>| connState    | **ConnState** | 是   | 否   | WLAN连接状态。                                               |
>
>
>
>#### ConnState  表示WLAN连接状态的枚举
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
>#### SuppState  表示请求状态的枚举
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
>#### IpInfo  IP信息
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

1. 开/关Wifi

   - 使用指导：点击后，在设备上启动/关闭Wifi；根据设备的Wifi情况，显示返回信息。

   - 限制条件：

     - 返回值为void
     - @throws {BusinessError} 201 - Permission denied.
     * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
     * @throws {BusinessError} 801 - Capability not supported.
     * @throws {BusinessError} 2501000 - Operation failed.
     - @throws {BusinessError} 2501004 - Failed for wifi is opening.

   - 验证方法：可在设备的设置中查看Wifi的开关情况

     

2.  获取状态

    - 使用指导：点击后，基于Wifi的开关状态，判断Wifi当时的状态。

    - 限制条件：

      - 若本地Wifi打开，返回值为true
      - 若本地Wifi关闭，返回值为false
      - @throws {BusinessError} 201 - Permission denied.
      - @throws {BusinessError} 801 - Capability not supported.
      - @throws {BusinessError} 2501000 - Operation failed.

    - 验证方法：可在设备设置中查看Wifi的当前状态

      

3.  启动WLAN扫描

    - 使用指导：点击后，扫描Wi-Fi热点。

    - 限制条件：

      - 返回值为void
      - @throws {BusinessError} 201 - Permission denied.
      - @throws {BusinessError} 801 - Capability not supported.
      - @throws {BusinessError} 2501000 - Operation failed.

    - 验证方法：查看扫描的结果判断是否扫描成功，利用on.wifiScanStateChange()和getScanInfos()查看返回的结果。

      

4.  获取扫描信息  getScanInfoList

    - 使用指导：点击后，返回有关扫描的Wi-Fi热点的信息（如果有的话）

    - 限制条件：

      - 返回值为：Array<WifiScanInfo>
      - @throws {BusinessError} 201 - Permission denied.
      * @throws {BusinessError} 801 - Capability not supported.
      * @throws {BusinessError} 2501000 - Operation failed.

    - 验证方法：查看返回的信息

      

5.  添加网络配置  addDeviceConfig  ( promise/callback ）

    - 使用指导：将 Wi-Fi 连接配置添加到设备。

    - 限制条件：

      - WiFi已使能，且配置的参数 (config: WifiDeviceConfig) 都正确。
      - 添加配置时，配置将更新。配置 表示连接到 Wi-Fi 网络的设备配置。
      - @throws {BusinessError} 201 - Permission denied.
      * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
      * @throws {BusinessError} 401 - Invalid parameters.
      * @throws {BusinessError} 801 - Capability not supported.
      * @throws {BusinessError} 2501000 - Operation failed.

    - 验证方法：查看返回的信息。如果添加了配置，则返回code：networkId；否则返回code： -1。

      

6.  添加候选配置   addCandidateConfig ( promise/callback ）

    - 使用指导：添加指定的候选热点配置并返回 networkId

    - 限制条件：

      - 此方法一次添加一个配置。添加此配置后，设备将决定是否连接到热点。
      - 配置 - 候选配置。
      - @throws {BusinessError} 201 - Permission denied.
      - @throws {BusinessError} 401 - Invalid parameters.
      - @throws {BusinessError} 801 - Capability not supported.
      - @throws {BusinessError} 2501000 - Operation failed.

    - 验证方法：查看返回信息，如果添加了配置，则返回 {code ：networkId}；否则返回 {code： -1}。

      

7.  移除候选配置   removeCandidateConfig ( promise/callback )

    - 使用指导：删除指定的候选热点配置，只允许自己添加的配置

    - 限制条件：

      - networkId - 将被删除的网络 ID
      - 只能获取在自己的应用程序上创建的 Wi-Fi 配置。
      - @throws {BusinessError} 201 - Permission denied.
      - @throws {BusinessError} 401 - Invalid parameters.
      - @throws {BusinessError} 801 - Capability not supported.
      - @throws {BusinessError} 2501000 - Operation failed.

    - 验证方法：查看返回信息，如果删除候选热点配置，返回 {code： true} ，否则返回 {code： false}

      

7.  获取候选配置  ( getCandidateConfigs )

    - 使用指导：获取我们自己添加的所有现有候选 Wi-Fi 配置的列表

    - 限制条件：

      - WiFi已使能，networkId参数配置成功
      - 只能获取在自己的应用程序上创建的 Wi-Fi 配置。
      - @throws {BusinessError} 201 - Permission denied.
      - @throws {BusinessError} 801 - Capability not supported.
      - @throws {BusinessError} 2501000 - Operation failed.

    - 验证方法：查看返回信息，返回在应用程序上创建的所有现有 Wi-Fi 配置的列表。

      

8.  连接到候选配置  ( connectToCandidateConfig )

    - 使用指导：通过networkId连接到指定的候选热点，只有我们自己添加的配置

    - 限制条件：

      - WiFi已使能，networkId参数配置成功
      - 此方法一次连接到一个配置
      - @throws {BusinessError} 201 - Permission denied.
      - @throws {BusinessError} 401 - Invalid parameters.
      - @throws {BusinessError} 801 - Capability not supported.
      - @throws {BusinessError} 2501000 - Operation failed.
      - @throws {BusinessError} 2501001 - Wifi is closed.
      - 返回值为void

    - 验证方法：查看连接信息。

      

9.  连接到指定网络  ( connectToNetwork )

    - 使用指导：连接到networkId的指定Wi-Fi网络

    - 限制条件：

      - WiFi已使能，networkId参数配置成功
      - @throws {BusinessError} 201 - Permission denied.
      - @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
      - @throws {BusinessError} 401 - Invalid parameters.
      - @throws {BusinessError} 801 - Capability not supported.
      - @throws {BusinessError} 2501000 - Operation failed.
      - @throws {BusinessError} 2501001 - Wifi is closed.
      - 返回值为void

    - 验证方法：查看连接信息。

      

10.  连接到指定网络  ( connectToDevice )

     - 使用指导：连接到WiFi设备配置的指定Wi-Fi网络

     - 限制条件：

       - WiFi已使能，Wifi参数配置 (config: WifiDeviceConfig) 成功
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
       * @throws {BusinessError} 401 - Invalid parameters.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2501000 - Operation failed.
       * @throws {BusinessError} 2501001 - Wifi is closed.
       * 返回值为void

     - 验证方法：查看连接信息。

       

11.  断开连接的网络  ( disconnect )

     - 使用指导：断开Wi-Fi网络连接

     - 限制条件：

       - 设备已经连接上了WiFi
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2501000 - Operation failed.
       * 返回值为void

     - 验证方法：查看连接情况。

       

12.  查询WLAN信号强度 ( getSignalLevel )

     - 使用指导：基于Wi-Fi的RSSI和频段( band )来计算Wi-Fi信号强度

     - 限制条件：

       - 设备已经连接上了WiFi
       - 且获得了rssi（热点的信号强度）和band（WLAN接入点的频段）
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 401 - Invalid parameters.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2501000 - Operation failed.

     - 验证方法：查看返回的信息。返回范围从0到4的Wi-Fi信号强度。

       

13.  获取WLAN连接信息  getLinkedInfo ( promise/callback )

     - 使用指导：获取有关Wi-Fi连接的信息

     - 限制条件：

       - 设备已经连接上了WiFi验证方法：查看返回的信息。返回Wi-Fi连接信息  ( WifiLinkedInfo )。
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2501000 - Operation failed.
       * @throws {BusinessError} 2501001 - Wifi is closed.

     - 验证方法：查看返回的信息。与设备的wifi连接是否一样

       

14.  WLAN是否已连接  ( isConnected )

     - 使用指导：连接到Wi-Fi网络

     - 限制条件：

       - WiFi已使能
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2501000 - Operation failed.

     - 验证方法：查看返回的信息。如果Wi-Fi已经连接，则返回code：true，否则返回code：false。 

       ​                                

15.  查询设备支持的特性 ( getSupportedFeatures )

     - 使用指导：获取此设备支持的功能特性

     - 限制条件：

       - 无
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2401000 - Operation failed.

     - 验证方法：查看返回的信息。返回此设备支持的特性Id

       

16.  是否支持相关WLAN特性 ( isFeatureSupported)

     - 使用指导：检查此设备是否支持指定功能

     - 限制条件：

       - 参数为特性功能Id (featureId: number)
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 401 - Invalid parameters.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2401000 - Operation failed.

     - 验证方法：查看返回的信息。如果此设备支持指定的功能，则返回code：true，否则返回ode：false。

       

17.  获取设备的MAC地址  ( getDeviceMacAddress )

     - 使用指导：获取 Wi-Fi 设备的 MAC 地址

     - 限制条件：

       - 必须启用 Wi-Fi。
       - MAC 地址是唯一的，无法更改。
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2501000 - Operation failed.
       - @throws {BusinessError} 2501001 - Wifi is closed.

     - 验证方法：查看返回的信息。

       

18.  获取IP信息  ( getIpInfo )

     - 使用指导：获取 Wi-Fi 连接的 IP 信息。

     - 限制条件：

       - 设备已经连接上了WiFi。
       - 获取的IP 信息包括主机 IP 地址、网关地址和 DNS 信息。
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2501000 - Operation failed.

     - 验证方法：查看返回的信息。返回 Wi-Fi 连接的 IP 信息。

       

19.  获取国家码信息  ( getCountryCode )

     - 使用指导：获取此设备的国家/地区代码。

     - 限制条件：

       - 设备已经连接上了WiFi
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2401000 - Operation failed.

     - 验证方法：查看返回的信息。返回此设备的国家/地区代码。

       

20.  重新关联网络 ( reassociate )

     - 使用指导： 重新关联到当前网络

     - 限制条件： 

       - 与当前网络取消关联

       - @throws {BusinessError} 201 - Permission denied.

       * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2501000 - Operation failed.
       - @throws {BusinessError} 2501001 - Wifi is closed.
       - 返回值为void

     - 验证方法： 查看关联信息。

       

21.  重新连接网络  ( reConnect )

     - 使用指导： 当前网络重新连接

     - 限制条件： 

       - 与当前网络断开连接
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2501000 - Operation failed.
       * @throws {BusinessError} 2501001 - Wifi is closed.
       * 返回值为void

     - 验证方法： 查看连接情况。

       

22.  获取网络配置  ( getDeviceConfigs )

     - 使用指导： 获取所有现有 Wi-Fi 配置的列表

     - 限制条件： 

       - 只能获取在自己的应用程序上创建的 Wi-Fi 配置。
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2501000 - Operation failed.

     - 验证方法： 查看返回的信息。返回在应用程序上创建的所有现有 Wi-Fi 配置的列表。

       

24.  更新指定Wifi配置  ( updateDeviceConfig )

     - 使用指导： 更新指定的 Wi-Fi 配置

     - 限制条件： 

       - 参数： (config: WifiDeviceConfig) ，表示要更新的 Wi-Fi 配置
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
       * @throws {BusinessError} 401 - Invalid parameters.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2501000 - Operation failed.

     - 验证方法： 查看返回的信息。如果更新成功，则返回更新后的 Wi-Fi 配置中的网络 ID ;  如果列表中未包含指定的 Wi-Fi 配置，则返回code：-1。

       

25.  禁用指定设备配置  ( disableDeviceConfig )

     - 使用指导： 禁用指定的网络

     - 限制条件： 

       - 参数：networkId，标识要禁用的网络。禁用的网络将不会再次关联。
       - @throws {BusinessError} 201 - Permission denied.
        * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
        * @throws {BusinessError} 401 - Invalid parameters.
        - @throws {BusinessError} 801 - Capability not supported
        - 返回值为void

     - 验证方法： 查看设备配置信息。

       

26.  移除所有网络配置  ( removeAllDeviceConfigs )

     - 使用指导： 删除所有已保存的 Wi-Fi 配置。

     - 限制条件： 

       - 无，返回值为void
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
       * @throws {BusinessError} 801 - Capability not supported.
       * @throws {BusinessError} 2501000 - Operation failed.
       * 返回值为void

     - 验证方法： 查看网络配置信息。

       

27.  移除指定的网络配置  ( removeDeviceConfig )

     - 使用指导： 删除具有指定 ID 的 Wi-Fi 网络。

       - 删除 Wi-Fi 网络后，其配置将从 Wi-Fi 配置列表中删除。
       - 如果正在连接Wi-Fi网络，则连接将中断
       - 应用程序只能删除它创建的 Wi-Fi 网络。

     - 限制条件： 

       - 参数：id ，表示 Wi-Fi 网络的 ID （可以使用 {addDeviceConfig} 或 {getLinkedInfo} 方法获得。）

       - @throws {BusinessError} 201 - Permission denied.

       * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
       * @throws {BusinessError} 401 - Invalid parameters.
       * @throws {BusinessError} 801 - Capability not supported.
       - @throws {BusinessError} 2501000 - Operation failed.
       - 返回值为void

     - 验证方法： 查看网络配置

       

28.  订阅/取消订阅注册WLAN状态改变事件 ( on/off.wifiStateChange )

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
       - @throws {BusinessError} 201 - Permission denied.
       - @throws {BusinessError} 401 - Invalid parameters.
       - @throws {BusinessError} 801 - Capability not supported.
       - @throws {BusinessError} 2501000 - Operation failed.

     - 验证方法：在事件变化后，查看是否有弹窗信息显示。

       

29.  订阅/取消订阅注册WLAN连接状态改变事件 ( on/off.wifiConnectionChange )

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
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 401 - Invalid parameters.
       * @throws {BusinessError} 801 - Capability not supported.
       - @throws {BusinessError} 2501000 - Operation failed.

     - 验证方法：在事件变化后，查看是否有弹窗信息显示。

       

30.  订阅/取消订阅注册扫描状态改变事件  ( on/off.wifiScanStateChange )

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
       - @throws {BusinessError} 201 - Permission denied.
       - @throws {BusinessError} 401 - Invalid parameters.
       - @throws {BusinessError} 801 - Capability not supported.
       - @throws {BusinessError} 2501000 - Operation failed.

     - 验证方法：在事件变化后，查看是否有弹窗信息显示。

       

31.  订阅/取消订阅注册RSSI状态改变事件   ( on/off.wifiRssiChange)

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
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 401 - Invalid parameters.
       * @throws {BusinessError} 801 - Capability not supported.
       - @throws {BusinessError} 2501000 - Operation failed.

     - 验证方法：在事件变化后，查看是否有弹窗信息显示。

       

32.  订阅/取消订阅注册流改变事件   ( on/off.streamChange)

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
       - @throws {BusinessError} 201 - Permission denied.
       * @throws {BusinessError} 202 - System API is not allowed called by Non-system application.
       * @throws {BusinessError} 401 - Invalid parameters.
       * @throws {BusinessError} 801 - Capability not supported.
       - @throws {BusinessError} 2501000 - Operation failed.

     - 验证方法：在事件变化后，查看是否有弹窗信息显示。

       

33.  订阅/取消订阅注册设备配置改变事件  ( on/off.deviceConfigChange )

     - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。

     - 限制条件：需要在相关类型事件发生改变前，开启监听。

       > 注册状态变化：
       >
       > - 订阅设备配置更改时报告的事件。
       >
       > - type为要侦听的设备配置更改事件的类型。
       >
       >
       > - callback回调用于侦听设备配置更改事件。

       - 若添加配置，返回值为0，显示信息为"config is added"；
       - 若配置更改，返回值为1，显示信息为"config is changed"；
       - 若配置被删除，返回值为2，显示信息为"config is removed"；

     - 验证方法：在事件变化后，查看是否有弹窗信息显示。
