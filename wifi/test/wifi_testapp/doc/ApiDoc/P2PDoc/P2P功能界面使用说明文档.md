## P2P测试使用说明文档

​		本文档主要介绍Wifi专项测试程序的P2p部分（@ohos.wifi.d.ts）的功能使用说明。

### 从主界面跳转到P2P部分



#### setting界面

点击"switch"按钮 ，设置本设备的wifi参数配置。



p2p配置信息：

>#### WifiP2PConfig   表示P2P配置信息
>
>|     名称      |        类型        |    默认值设置     | 说明                                                   |
>| :-----------: | :----------------: | :---------------: | :----------------------------------------------------- |
>| deviceAddress |       string       | 6c:96:d7:3d:87:6f | 设备地址。                                             |
>|     netId     |       number       |        -2         | 网络ID。创建群组时-1表示创建临时组，-2表示创建永久组。 |
>|  passphrase   |       string       |     12345678      | 群组密钥。                                             |
>|   groupName   |       string       |     testGroup     | 群组名称。                                             |
>|    goBand     | **GroupOwnerBand** |         0         | 群组带宽。                                             |
>
>
>
>#### GroupOwnerBand  表示群组带宽的枚举
>
>| 名称         | 值   | 说明       |
>| :----------- | :--- | :--------- |
>| GO_BAND_AUTO | 0    | 自动模式。 |
>| GO_BAND_2GHZ | 1    | 2GHZ。     |
>| GO_BAND_5GHZ | 2    | 5GHZ。     |
>
>
>
>| **参数名** | **类型** |  默认值设置  | **必填** |  **说明**  |
>| :--------: | :------: | :----------: | :------: | :--------: |
>|  devName   |  string  | MyTestDevice |    是    | 设备名称。 |



#### P2P（@ohos.wifi.d.ts）的主要接口

|            method名称            |           API名称           |        所需参数         |                   返回值                   | 备注 |
| :------------------------------: | :-------------------------: | :---------------------: | :----------------------------------------: | :--: |
|     获取P2P连接信息,promise      |  getP2pLinkedInfo(promise)  |           ()            |         Promise<WifiP2pLinkedInfo>         |      |
|     获取P2P连接信息,callback     | getP2pLinkedInfo(callback)  |           ()            | callback: AsyncCallback<WifiP2pLinkedInfo> |      |
|    获取P2P当前组信息,promise     |  getCurrentGroup(promise)   |           ()            |         Promise<WifiP2pGroupInfo>          |      |
|    获取P2P当前组信息,callback    |  getCurrentGroup(callback)  |           ()            | callback: AsyncCallback<WifiP2pGroupInfo>  |      |
| 获取P2P对端设备列表信息,promise  | getP2pPeerDevices(promise)  |           ()            |          Promise<WifiP2pDevice[]>          |      |
| 获取P2P对端设备列表信息,callback | getP2pPeerDevices(callback) |           ()            |  callback: AsyncCallback<WifiP2pDevice[]>  |      |
|             创建群组             |         createGroup         | (config: WifiP2PConfig) |                  boolean                   |      |
|             移除群组             |         removeGroup         |           ()            |                  boolean                   |      |
|           执行P2P连接            |         p2pConnect          | (config: WifiP2PConfig) |                  boolean                   |      |
|           取消P2P连接            |      p2pCancelConnect       |           ()            |                  boolean                   |      |
|           开始发现设备           |    startDiscoverDevices     |           ()            |                  boolean                   |      |
|           停止发现设备           |     stopDiscoverDevices     |           ()            |                  boolean                   |      |
|            删除永久组            |    deletePersistentGroup    |     (netId: number)     |                  boolean                   |      |
|           设置设备名称           |        setDeviceName        |    (devName: string)    |                  boolean                   |      |
|     注册P2P开关状态改变事件      |      on.p2pStateChange      |                         |         callback: Callback<number>         |      |
|     注册P2P连接状态改变事件      |   on.p2pConnectionChange    |                         |   callback: Callback<WifiP2pLinkedInfo>    |      |
|     注册P2P设备状态改变事件      |     on.p2pDeviceChange      |                         |     callback: Callback<WifiP2pDevice>      |      |
|   注册P2P对端设备状态改变事件    |   on.p2pPeerDeviceChange    |                         |    callback: Callback<WifiP2pDevice[]>     |      |
|    注册P2P永久组状态改变事件     | on.p2pPersistentGroupChange |                         |          callback: Callback<void>          |      |
|     注册发现设备状态改变事件     |    on.p2pDiscoveryChange    |                         |         callback: Callback<number>         |      |
|                                  |                             |                         |                                            |      |



#### 返回值介绍

> ## WifiP2pLinkedInfo   提供WLAN连接的相关信息。
>
> |      名称      |        类型         | 可读 | 可写 |     说明      |
> | :------------: | :-----------------: | :--: | :--: | :-----------: |
> |  connectState  | **P2pConnectState** |  是  |  否  | P2P连接状态。 |
> |  isGroupOwner  |       boolean       |  是  |  否  | 是否是群主。  |
> | groupOwnerAddr |       string        |  是  |  否  | 群组MAC地址。 |
>
> 
>
> #### P2pConnectState  表示P2P连接状态的枚举
>
> | 名称         | 值   | 说明       |
> | :----------- | :--- | :--------- |
> | DISCONNECTED | 0    | 断开状态。 |
> | CONNECTED    | 1    | 连接状态。 |
>
> 
>
> #### WifiP2pGroupInfo  表示P2P群组相关信息
>
> | 名称          | 类型                | 可读 | 可写 | 说明                 |
> | :------------ | :------------------ | :--- | :--- | :------------------- |
> | isP2pGo       | boolean             | 是   | 否   | 是否是群主。         |
> | ownerInfo     | **WifiP2pDevice**   | 是   | 否   | 群组的设备信息。     |
> | passphrase    | string              | 是   | 否   | 群组密钥。           |
> | interface     | string              | 是   | 否   | 接口名称。           |
> | groupName     | string              | 是   | 否   | 群组名称。           |
> | networkId     | number              | 是   | 否   | 网络ID。             |
> | frequency     | number              | 是   | 否   | 群组的频率。         |
> | clientDevices | **WifiP2pDevice[]** | 是   | 否   | 接入的设备列表信息。 |
> | goIpAddress   | string              | 是   | 否   | 群组IP地址           |
>
> 
>
> #### WifiP2pDevice   表示P2P设备信息
>
> | 名称              | 类型                | 可读 | 可写 | 说明          |
> | :---------------- | :------------------ | :--- | :--- | :------------ |
> | deviceName        | string              | 是   | 否   | 设备名称。    |
> | deviceAddress     | string              | 是   | 否   | 设备MAC地址。 |
> | primaryDeviceType | string              | 是   | 否   | 主设备类型。  |
> | deviceStatus      | **P2pDeviceStatus** | 是   | 否   | 设备状态。    |
> | groupCapabilities | number              | 是   | 否   | 群组能力。    |
>
> 
>
> #### P2pDeviceStatus   表示设备状态的枚举
>
> | 名称        | 值   | 说明         |
> | :---------- | :--- | :----------- |
> | CONNECTED   | 0    | 连接状态。   |
> | INVITED     | 1    | 邀请状态。   |
> | FAILED      | 2    | 失败状态。   |
> | AVAILABLE   | 3    | 可用状态。   |
> | UNAVAILABLE | 4    | 不可用状态。 |



#### 测试功能

**"创建群组"是其他功能测试的前提**

1. 获取P2P连接信息  getP2pLinkedInfo(promise/callback)

   - 使用指导：获取有关 P2P 连接的信息。

   - 限制条件：p2p已经连接，返回p2p连接信息

   - 验证方法：可调用其他接口查看p2p连接信息

     

2. 获取P2P当前组信息  getCurrentGroup(promise/callback)

   - 使用指导：获取有关当前组的信息。

   - 限制条件：p2p创建组，返回当前组信息

   - 验证方法：可调用其他接口查看创建组的信息

     

3. 获取P2P对端设备列表信息 getP2pPeerDevices(promise/callback)

   - 使用指导：获取有关找到的设备的信息。

   - 限制条件：p2p有对端设备，返回找到的设备列表

   - 验证方法：可调用其他接口查看对端设备的列表信息

     

4. 创建群组  createGroup

   - 使用指导：创建一个 P2P 组。

   - 限制条件：创建组的配置参数 (config: WifiP2PConfig) 都正确

   - 验证方法：查看返回信息，如果操作成功，则返回 {true}，否则返回 {false}；可调用其他接口查看群组的情况

     

5. 移除群组  removeGroup

   - 使用指导：删除一个 P2P 组。

   - 限制条件：已经成功创建过组

   - 验证方法：查看返回信息，如果操作成功，则返回 {true}，否则返回 {false}；可调用其他接口查看群组的情况

     

6. 执行P2P连接 p2pConnect

   - 使用指导：启动与具有指定配置的设备的 P2P 连接

   - 限制条件：用于连接到特定组的配置参数（config: WifiP2PConfig）都正确

   - 验证方法：查看返回信息，如果操作成功，则返回 {true}，否则返回 {false}

     

7. 取消P2P连接 p2pCancelConnect

   - 使用指导：取消 P2P 连接

   - 限制条件：已经P2P连接成功过

   - 验证方法：查看返回信息，如果操作成功，则返回 {true}，否则返回 {false}

     

8. 开始发现设备 startDiscoverDevices

   - 使用指导：发现 Wi-Fi P2P 设备

   - 限制条件：无

   - 验证方法：查看返回信息，如果操作成功，则返回 {true}，否则返回 {false}

     

9. 停止发现设备 stopDiscoverDevices

   - 使用指导：停止发现 Wi-Fi P2P 设备

   - 限制条件：已经开始发现过设备

   - 验证方法：查看返回信息，如果操作成功，则返回 {true}，否则返回 {false}

     

10. 删除永久组 deletePersistentGroup

    - 使用指导：删除具有指定网络 ID 的持久 P2P 组

    - 限制条件：用于删除永久组的配置参数（netId: number）表示要删除的组的网络 ID

    - 验证方法：查看返回信息，如果操作成功，则返回 {true}，否则返回 {false}

      

11. 设置设备名称  setDeviceName

    - 使用指导：设置Wi-Fi P2P设备的名称

    - 限制条件：用于设置设备名称的配置参数（devName：string） 表示要设置的名称

    - 验证方法：查看返回信息，如果操作成功，则返回 {true}，否则返回 {false}

      

12. 订阅/取消订阅注册P2P开关状态改变事件  ( on/off.p2pStateChange )

    - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。

    - 限制条件：需要在相关类型事件发生改变前，开启监听。

      > 注册状态变化：
      >
      > - 订阅P2P 状态更改时报告的事件。
      >
      > - type为要侦听的P2P 状态更改事件的类型。
      >
      >
      > - callback回调用于侦听P2P 状态更改事件。

      - 若本地p2p空闲，返回值为1，显示信息为"idle"；
      - 若本地p2p正在打开，返回值为2，显示信息为"starting"；
      - 若本地p2p已打开，返回值为3，显示信息为"started"；
      - 若本地p2p正在关闭，返回值为4，显示信息为"closing"；
      - 若本地p2p已关闭，返回值为5，显示信息为"closed"；

    - 验证方法：在事件变化后，查看是否有弹窗信息显示。

      

13. 订阅/取消订阅注册P2P连接状态改变事件  ( on/off.p2pConnectionChange )

    - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。

    - 限制条件：需要在相关类型事件发生改变前，开启监听。

      > 注册状态变化：
      >
      > - 订阅P2P 连接更改时报告的事件。
      >
      > - type为要侦听的P2P 连接更改事件的类型。
      >
      >
      > - callback回调用于侦听P2P 连接更改事件。

      - 返回WifiP2pLinkedInfo

    - 验证方法：在事件变化后，查看是否有弹窗信息显示。

      

14. 订阅/取消订阅注册P2P设备状态改变事件 ( on/off.p2pDeviceChange )

    - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。

    - 限制条件：需要在相关类型事件发生改变前，开启监听。

      > 注册状态变化：
      >
      > - 订阅P2P 本地设备更改时报告的事件。
      >
      > - type为要侦听的P2P 本地设备更改事件的类型。
      >
      >
      > - callback回调用于侦听P2P 本地设备更改事件。

      - 返回WifiP2pDevice

    - 验证方法：在事件变化后，查看是否有弹窗信息显示。

      

15. 订阅/取消订阅注册P2P对端设备状态改变事件 ( on/off.p2pPeerDeviceChange )

    - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。

    - 限制条件：需要在相关类型事件发生改变前，开启监听。

      > 注册状态变化：
      >
      > - 订阅P2P 对等设备更改时报告的事件。
      >
      > - type为要侦听的P2P 对等设备更改事件的类型。
      >
      >
      > - callback回调用于侦听P2P 对等设备更改事件。

      - 返回WifiP2pDevice[]

    - 验证方法：在事件变化后，查看是否有弹窗信息显示。

      

16. 订阅/取消订阅注册P2P永久组状态改变事件 ( on/off.p2pPersistentGroupChange )

    - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。

    - 限制条件：需要在相关类型事件发生改变前，开启监听。

      > 注册状态变化：
      >
      > - 订阅P2P 持久组更改时报告的事件。
      >
      > - type为要侦听的P2P 持久组更改事件的类型。
      >
      >
      > - callback回调用于侦听P2P 持久组更改事件。

      - 返回 void

    - 验证方法：在事件变化后，查看是否有弹窗信息显示。

      

17. 订阅/取消订阅注册发现设备状态改变事件 ( on/off.p2pDiscoveryChange )

    - 使用指导：为回调函数，用来监听相关类型事件的变化，并弹窗显示信息。

    - 限制条件：需要在相关类型事件发生改变前，开启监听。

      > 注册状态变化：
      >
      > - 订阅P2P 发现时报告的事件。
      >
      > - type为要侦听的P2P 发现事件的类型。
      >
      >
      > - callback回调用于侦听P2P 发现事件。

      - 若本地p2p发现失败，返回值为0，显示信息为"initial state"；
      - 若本地p2p发现成功，返回值为1，显示信息为"discovery succeeded"；

    - 验证方法：在事件变化后，查看是否有弹窗信息显示。
