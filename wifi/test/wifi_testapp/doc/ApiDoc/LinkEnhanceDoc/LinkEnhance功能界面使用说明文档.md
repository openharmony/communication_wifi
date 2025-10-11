## LinkEnhance测试使用说明文档

​		本文档主要介绍WiFi专项测试程序的LinkEnhance软总线部分（@ohos.distributedsched.linkEnhance）的功能使用说明。

### 从主界面跳转到LinkEnhance部分

在主界面选择"API"标签页，滚动到"LinkEnhance"选项，点击进入。

#### 配置界面

进入LinkEnhance接口测试页面后，首先看到配置区域，用于设置测试参数。

LinkEnhance配置信息：

>#### LinkEnhance测试配置
>
>|     名称      |  类型  |     默认值设置     | 说明                               |
>| :-----------: | :----: | :----------------: | :--------------------------------- |
>|   服务器名称   | string | TestLinkEnhanceServer | 创建服务器时使用的名称             |
>|    设备ID     | string | test_device_12345  | 连接到对端设备的设备标识符         |
>|   测试消息    | string | Hello LinkEnhance! | 用于数据传输测试的消息内容         |
>| 连接超时(ms)  | number |       10000        | 连接超时时间，单位毫秒             |
>| 数据大小(字节) | number |        1024        | 测试数据的大小，单位字节           |

#### LinkEnhance（@ohos.distributedsched.linkEnhance）的主要接口

|            method名称            |                API名称                 |           所需参数           |           返回值           | 备注                   |
| :------------------------------: | :------------------------------------: | :--------------------------: | :------------------------: | :--------------------- |
|            创建服务器            |             createServer               |       (name: string)         |           Server           | 创建LinkEnhance服务器  |
|            启动服务器            |             server.start               |             ()               |            void            | 启动服务器监听连接     |
|            停止服务器            |              server.stop               |             ()               |            void            | 停止服务器             |
|            关闭服务器            |             server.close               |             ()               |            void            | 关闭服务器释放资源     |
|         监听连接接受事件         |    server.on('connectionAccepted')     |             ()               |   callback: Connection     | 监听新连接             |
|        监听服务器停止事件        |      server.on('serverStopped')        |             ()               |    callback: number        | 监听服务器停止         |
|         取消连接接受监听         |   server.off('connectionAccepted')     |             ()               |            void            | 取消连接监听           |
|        取消服务器停止监听        |     server.off('serverStopped')        |             ()               |            void            | 取消停止监听           |
|             创建连接             |           createConnection             | (deviceId, name: string)     |        Connection          | 创建连接实例           |
|             建立连接             |          connection.connect            |             ()               |            void            | 发起连接               |
|             断开连接             |         connection.disconnect          |             ()               |            void            | 断开连接               |
|             关闭连接             |           connection.close             |             ()               |            void            | 关闭连接释放资源       |
|         获取对端设备ID           |      connection.getPeerDeviceId        |             ()               |           string           | 获取对端设备标识       |
|             发送数据             |           connection.sendData          |  (data: ArrayBuffer)         |            void            | 发送数据到对端         |
|        监听连接结果事件          |   connection.on('connectResult')       |             ()               |  callback: ConnectResult   | 监听连接是否成功       |
|        监听断开连接事件          |    connection.on('disconnected')       |             ()               |    callback: number        | 监听连接断开           |
|        监听数据接收事件          |    connection.on('dataReceived')       |             ()               | callback: ArrayBuffer      | 监听接收到的数据       |
|       取消连接结果事件监听       |  connection.off('connectResult')       |             ()               |            void            | 取消连接结果监听       |
|       取消断开连接事件监听       |   connection.off('disconnected')       |             ()               |            void            | 取消断开监听           |
|       取消数据接收事件监听       |   connection.off('dataReceived')       |             ()               |            void            | 取消数据接收监听       |

#### 返回值介绍

> ## Server   LinkEnhance服务器对象
>
> |      名称      |           方法签名            | 说明                           |
> | :------------: | :---------------------------: | :----------------------------- |
> |     start      |          start(): void         | 启动服务器                     |
> |      stop      |          stop(): void          | 停止服务器                     |
> |     close      |         close(): void          | 关闭服务器                     |
> |       on       | on(type, callback): void       | 注册事件监听                   |
> |      off       | off(type, callback?): void     | 取消事件监听                   |
>
> 
>
> ## Connection   LinkEnhance连接对象
>
> |      名称      |              方法签名             | 说明                           |
> | :------------: | :-------------------------------: | :----------------------------- |
> |    connect     |          connect(): void           | 建立连接                       |
> |   disconnect   |         disconnect(): void         | 断开连接                       |
> |     close      |           close(): void            | 关闭连接                       |
> | getPeerDeviceId| getPeerDeviceId(): string          | 获取对端设备ID                 |
> |    sendData    | sendData(data: ArrayBuffer): void  | 发送数据                       |
> |       on       |   on(type, callback): void         | 注册事件监听                   |
> |      off       |   off(type, callback?): void       | 取消事件监听                   |
>
> 
>
> ## ConnectResult   连接结果对象
>
> |   名称    |  类型   | 说明                                     |
> | :-------: | :-----: | :--------------------------------------- |
> | deviceId  | string  | 连接的设备ID                             |
> | success   | boolean | 连接是否成功                             |
> |  reason   | number  | 失败原因代码（成功时为0）                |

#### 测试功能

**"创建服务器"和"创建连接"是其他功能测试的前提**

1. 创建服务器  createServer(name: string)

   - 使用指导：创建一个LinkEnhance服务器实例，用于接受其他设备的连接。

   - 限制条件：服务器名称必须唯一，不能与已存在的服务器重名

   - 验证方法：创建成功后显示服务器状态，可以继续进行其他服务器操作

     

2. 启动服务器  server.start()

   - 使用指导：启动服务器，使其处于可连接状态，可以接受来自其他设备的连接请求。

   - 限制条件：服务器必须已创建，并且未启动

   - 验证方法：查看返回信息，启动成功后服务器状态变为"运行中"

     

3. 停止服务器  server.stop()

   - 使用指导：停止服务器，不再接受新的连接请求。

   - 限制条件：服务器必须已启动

   - 验证方法：停止成功后服务器状态变为"已停止"，不再接受新连接

     

4. 关闭服务器  server.close()

   - 使用指导：关闭服务器并释放所有资源，取消所有事件监听。

   - 限制条件：服务器必须已创建

   - 验证方法：关闭成功后服务器对象失效，无法再进行操作

     

5. 监听连接接受事件  server.on('connectionAccepted', callback)

   - 使用指导：注册回调函数，当有新的连接接入时会触发。

   - 限制条件：服务器必须已创建，建议在启动服务器前注册监听

   - 验证方法：当有设备连接时，回调函数被调用，显示连接信息

     

6. 监听服务器停止事件  server.on('serverStopped', callback)

   - 使用指导：注册回调函数，当服务器停止时会触发。

   - 限制条件：服务器必须已创建

     > 服务器停止原因：
     >
     > - reason参数表示停止原因代码
     > - 可能是主动停止或异常停止

   - 验证方法：当服务器停止时，回调函数被调用，显示停止原因

     

7. 创建连接  createConnection(deviceId: string, name: string)

   - 使用指导：创建一个连接实例，用于连接到指定设备上的服务器。

   - 限制条件：必须提供有效的设备ID和要连接的服务器名称

   - 验证方法：创建成功后显示连接对象，可以继续进行连接操作

     

8. 建立连接  connection.connect()

   - 使用指导：发起连接请求，连接到对端设备的服务器。

   - 限制条件：连接对象必须已创建，且未连接

   - 验证方法：通过connectResult事件回调查看连接是否成功

     

9. 断开连接  connection.disconnect()

   - 使用指导：断开当前连接。

   - 限制条件：连接必须已建立

   - 验证方法：断开成功后连接状态变为"已断开"，触发disconnected事件

     

10. 关闭连接  connection.close()

    - 使用指导：关闭连接并释放资源。

    - 限制条件：连接对象必须已创建

    - 验证方法：关闭成功后连接对象失效，无法再进行操作

      

11. 获取对端设备ID  connection.getPeerDeviceId()

    - 使用指导：获取连接对端的设备ID。

    - 限制条件：连接对象必须已创建

    - 验证方法：返回字符串形式的设备ID，连接成功后返回有效ID，否则返回空字符串

      

12. 发送数据  connection.sendData(data: ArrayBuffer)

    - 使用指导：向对端设备发送数据。

    - 限制条件：连接必须已建立，数据必须是ArrayBuffer格式

    - 验证方法：发送成功后对端设备会触发dataReceived事件

      

13. 监听连接结果事件  connection.on('connectResult', callback)

    - 使用指导：注册回调函数，监听连接操作的结果。

    - 限制条件：连接对象必须已创建，建议在connect前注册监听

      > 连接结果信息：
      >
      > - ConnectResult包含deviceId（设备ID）、success（是否成功）、reason（失败原因）
      > - success为true表示连接成功，false表示失败
      > - reason为0表示成功，其他值表示失败原因代码

    - 验证方法：调用connect后，回调函数被触发，显示连接结果

      

14. 监听断开连接事件  connection.on('disconnected', callback)

    - 使用指导：注册回调函数，监听连接断开事件。

    - 限制条件：连接对象必须已创建

      > 断开原因：
      >
      > - reason参数表示断开原因代码
      > - 可能是主动断开或异常断开

    - 验证方法：当连接断开时，回调函数被触发，显示断开原因

      

15. 监听数据接收事件  connection.on('dataReceived', callback)

    - 使用指导：注册回调函数，监听接收到的数据。

    - 限制条件：连接对象必须已创建

      > 数据格式：
      >
      > - 接收到的数据为ArrayBuffer格式
      > - 需要转换为字符串或其他格式使用

    - 验证方法：当对端发送数据时，回调函数被触发，显示接收到的数据

#### 测试顺序建议

为了确保测试顺利进行，建议按以下顺序测试：

##### 服务器测试流程

```
1. 创建服务器
   ↓
2. 监听连接接受事件
   ↓
3. 监听服务器停止事件
   ↓
4. 启动服务器
   ↓
5. (等待客户端连接)
   ↓
6. 停止服务器
   ↓
7. 关闭服务器
```

##### 连接测试流程

```
1. 创建连接
   ↓
2. 监听连接结果事件
   ↓
3. 监听断开连接事件
   ↓
4. 监听数据接收事件
   ↓
5. 建立连接
   ↓
6. 获取对端设备ID
   ↓
7. 发送数据
   ↓
8. 断开连接
   ↓
9. 关闭连接
```

#### 注意事项

1. **权限要求**
   - 应用必须申请分布式数据同步权限：`ohos.permission.DISTRIBUTED_DATASYNC`
   - 在`module.json5`中配置相应权限

2. **设备要求**
   - 设备必须支持蓝牙功能
   - 蓝牙必须已开启
   - 对于跨设备连接测试，需要两台设备

3. **测试环境**
   - 建议在真实设备上测试（模拟器可能不支持完整功能）
   - 设备间需要能够正常通信
   - 确保没有其他应用占用蓝牙资源

4. **常见错误**
   - 错误代码201：权限拒绝
   - 错误代码32390206：参数无效
   - 错误代码32390203：服务器名称重复
   - 错误代码32390204：连接数超限
   - 错误代码32390300：内部错误

#### 数据编解码说明

在进行数据传输时，需要注意字符串与ArrayBuffer的转换：

**编码（字符串 → ArrayBuffer）**：
```typescript
import util from '@ohos.util';

const textEncoder = new util.TextEncoder();
const uint8Array = textEncoder.encodeInto(message);
const arrayBuffer = uint8Array.buffer;
```

**解码（ArrayBuffer → 字符串）**：
```typescript
import util from '@ohos.util';

const textDecoder = new util.TextDecoder('utf-8');
const uint8Array = new Uint8Array(arrayBuffer);
const text = textDecoder.decodeWithStream(uint8Array, { stream: false });
```

---

*最后更新：2025年10月*

