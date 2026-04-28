# WifiManager p2p相关接口文档

以下接口大多都有返回promise和回调两种形式，此文档仅列举返回promise的接口

## wifiManager.startDiscoverDevices

1. 功能：开始发现p2p设备

2. 需要权限：API 10起ohos.permission.GET_WIFI_INFO
3. 系统能力： SystemCapability.Communication.WiFi.P2P
4. 错误码
| 错误码  | 错误信息                 |
| ------- | ------------------------ |
| 201     | Permission denied        |
| 801     | Capability not supported |
| 2801000 | Operation failed         |
| 2801001 | Wi-Fi STA disabled       |

5. 示例：
```typescript
import { wifiManager } from '@kit.ConnectivityKit';
    // 开启设备发现后，需要监听p2pPeerDeviceChange事件来获取所有的对端设备
    wifiManager.on('p2pPeerDeviceChange', async (_: wifiManager.WifiP2pDevice[]) => {
      console.log(TAG, 'p2pPeerDeviceChange:', JSON.stringify(_))
      try {
        let devices = await wifiManager.getP2pPeerDevices()
        this.allDevice = devices.map(P2PDevice.from)
      } catch (e) {
        console.log(JSON.stringify(e))
      }
    })
    // 因为startDiscoveryDevices一段事件后会自动关闭，如果要求一直开启扫描，需要监听p2pDiscoverChange事件，在状态为0时重新开启设备发现
   wifiManager.on('p2pDiscoveryChange', (status) => {
      console.log(TAG, `p2pDiscoveryChange: ${status}`)
      if (status === 0) {
        wifiManager.startDiscoverDevices()
      }
    })
	try {
		wifiManager.startDiscoverDevices();	
	}catch(error){
		console.error("failed:" + JSON.stringify(error));
	}
```
6. 说明：
   调用startDiscoverDevices后，需要监听“onP2pPeerDeviceChange”事件以感知可用p2p设备的变化并进行相关逻辑。startDiscoverDevices一段时间后会自动停止发现

##  wifiManager.stopDiscoverDevices
1. 功能：停止发现设备
2. 需要权限：ohos.permission.GET_WIFI_INFO
3. 系统能力： SystemCapability.Communication.WiFi.P2P
4. 错误码：
| **错误码ID** | **错误信息**              |
| ------------ | ------------------------- |
| 201          | Permission denied.        |
| 801          | Capability not supported. |
| 2801000      | Operation failed.         |
| 2801001      | Wi-Fi STA disabled.       |
5. 示例：
```typescript
import { wifiManager } from '@kit.ConnectivityKit';

	try {
		wifiManager.stopDiscoverDevices();	
	}catch(error){
		console.error("failed:" + JSON.stringify(error));
	}
```
6. 说明： 
   即使不显式调用，startDiscoverDevice一段时间后也会stopDiscoverDevices,stop后调用getP2pPeerDevices返回值为空数组

## wifiManager.on('p2pDiscoveryChange')
1. 功能： 注册发现P2p设备状态改变事件
2. 需要权限： ohos.permission.GET_WIFI_INFO
3. 系统能力： SystemCapability.Communication.WiFi.P2P
4. 参数：

   | **参数名** | **类型**         | **必填** | **说明**                           |
   | ---------- | ---------------- | -------- | ---------------------------------- |
   | type       | string           | 是       | 固定填"p2pDiscoveryChange"字符串。 |
   | callback   | Callback<number> | 是       | 状态改变回调函数。                 |

   发现p2p设备状态改变事件callback中的number枚举：

   | **枚举值** | **说明**   |
   | ---------- | ---------- |
   | 0          | 初始状态。 |
   | 1          | 发现成功。 |

5. 错误码：

   | **错误码ID** | **错误信息**                                                 |
   | ------------ | ------------------------------------------------------------ |
   | 201          | Permission denied.                                           |
   | 401          | Invalid parameters. Possible causes: 1. Mandatory parameters are left unspecified. 2. Incorrect parameter types. |
   | 801          | Capability not supported.                                    |
   | 2801000      | Operation failed.                                            |
6. 说明：
   成功调用startDiscoverDevices和stopDiscoverDevices会触发此回调，对应的参数分别是1和0

## wifiManager.on('p2pPeerDeviceChange')
1. 功能：注册p2p对端设备变化回调
2. 需要权限：API 10起：ohos.permission.GET_WIFI_INFO
3. 系统能力：SystemCapability.Communication.WiFi.P2P
4. 参数：
| **参数名** | **类型**                  | **必填** | **说明**                                                     |
| ---------- | ------------------------- | -------- | ------------------------------------------------------------ |
| type       | string                    | 是       | 固定填"p2pPeerDeviceChange"字符串。                          |
| callback   | Callback<[WifiP2pDevice]> | 是       | 状态改变回调函数。如果应用申请了ohos.permission.GET_WIFI_PEERS_MAC权限（仅系统应用可申请），则返回结果中的deviceAddress为真实设备地址，否则为随机设备地址。 |

| **错误码ID** | **错误信息**                                                 |
| ------------ | ------------------------------------------------------------ |
| 201          | Permission denied.                                           |
| 401          | Invalid parameters. Possible causes: 1. Mandatory parameters are left unspecified. 2. Incorrect parameter types. |
| 801          | Capability not supported.                                    |
| 2801000      | Operation failed.                                            |
5. 说明： 此回调中调用wifiMannager可以获取到所有对端设备列表，<u>因为回调参数不是全量的对端设备，可能时增量，目前不确定</u>

## wifiManager.getP2pPeerDevices

1. 功能：所有所有的p2p对端设备信息列表
2. 权限：API 10起：ohos.permission.GET_WIFI_INFO
3. 系统能力：SystemCapability.Communication.WiFi.P2P

4. 返回值：



| 类型                     | 说明                                                         |
| ------------------------ | ------------------------------------------------------------ |
| Promise<[WifiP2pDevice]> | Promise对象。表示对端设备列表信息。如果应用申请了ohos.permission.GET_WIFI_PEERS_MAC权限（仅系统应用可申请），则返回结果中的deviceAddress为真实设备地址，否则为随机设备地址。 |

5. 错误码：

| **错误码ID** | **错误信息**              |
| ------------ | ------------------------- |
| 201          | Permission denied.        |
| 801          | Capability not supported. |
| 2801000      | Operation failed.         |

6. 说明：一般在设备信息发生变化时调用已获取最新的对端设备列表信息，例如：连接状态发生变化（有设备的连接状态需要更新）p2pConnectionChange, 扫描到新的设备 p2pPeerDeviceChange

## wifiManager.getP2pLocalDevice
1.  获取P2P本端设备信息
2. 权限： API 11起：ohos.permission.GET_WIFI_INFO
3. 系统能力：SystemCapability.Communication.WiFi.P2P
4. 返回值： 
   | 类型                     | 说明                            |
   | ------------------------ | ------------------------------- |
   | Promise<[WifiP2pDevice]> | Promise对象。表示本端设备信息。 |
5. 错误码：
   | **错误码ID** | **错误信息**              |
   | ------------ | ------------------------- |
   | 201          | Permission denied.        |
   | 801          | Capability not supported. |
   | 2801000      | Operation failed.         |

##   wifiManager.getP2pLinkedInfo
1. 功能：获取WLAN连接信息，使用Promise异步回调
2. 需求权限： ohos.permission.GET_WIFI_INFO，当macType是1 - 设备MAC地址时，获取 macAddress 还需申请ohos.permission.GET_WIFI_LOCAL_MAC权限（该权限仅系统应用可申请），无该权限时，macAddress 返回空字符串。
3. 系统能力： SystemCapability.Communication.WiFi.STA
4. 返回值： 
| 类型                      | 说明                            |
| ------------------------- | ------------------------------- |
| Promise<[WifiLinkedInfo]> | Promise对象。表示WLAN连接信息。 |
5. 错误码：

| 201     | Permission denied.        |
| ------- | ------------------------- |
| 801     | Capability not supported. |
| 2501000 | Operation failed.         |
| 2501001 | Wi-Fi STA disabled.       |

6： 应该在连接状态发生变化，也就是p2pConnectionChange回调中更新本地连接状态

##  wifiManager.getP2pGroups
1. 功能：获取创建的所有P2P群组信息，使用Promise异步回调，此接口为系统接口
2. 需要权限：API 9：ohos.permission.GET_WIFI_INFO、ohos.permission.LOCATION 和 ohos.permission.APPROXIMATELY_LOCATION
   API 10起：ohos.permission.GET_WIFI_INFO
3. 系统能力：  SystemCapability.Communication.WiFi.P2P
4. 返回值：
| 类型                                | 说明                                                         |
| ----------------------------------- | ------------------------------------------------------------ |
| Promise< Array<[WifiP2pGroupInfo] > | Promise对象。表示所有群组信息。如果应用申请了ohos.permission.GET_WIFI_PEERS_MAC权限，则返回结果中的deviceAddress为真实设备地址，否则为随机设备地址。 |
5. 错误码：
| **错误码ID** | **错误信息**                                                |
| ------------ | ----------------------------------------------------------- |
| 201          | Permission denied.                                          |
| 202          | System API is not allowed called by Non-system application. |
| 801          | Capability not supported.                                   |
| 2801000      | Operation failed.                                           |

6. 示例：
```typescript
import { wifiManager } from '@kit.ConnectivityKit';

	wifiManager.getP2pGroups((err, data:wifiManager.WifiP2pGroupInfo) => {
    if (err) {
        console.error("get P2P groups error");
        return;
    }
		console.info("get P2P groups: " + JSON.stringify(data));
	});

	wifiManager.getP2pGroups().then(data => {
		console.info("get P2P groups: " + JSON.stringify(data));
	});
```

##  wifiManager.setDeviceName

1. 功能：设置设备名称，此接口时系统
2. 需要权限：ohos.permission.SET_WIFI_INFO 和 ohos.permission.MANAGE_WIFI_CONNECTION，仅系统应用可用
3. 系统能力：SystemCapability.Communication.WiFi.P2P
4. 参数：

   | **参数名** | **类型** | **必填** | **说明**   |
   | ---------- | -------- | -------- | ---------- |
   | devName    | string   | 是       | 设备名称。 |

5. 错误码：

| **错误码ID** | **错误信息**                                                 |
| ------------ | ------------------------------------------------------------ |
| 201          | Permission denied.                                           |
| 202          | System API is not allowed called by Non-system application.  |
| 401          | Invalid parameters. Possible causes: 1. Mandatory parameters are left unspecified. 2. Incorrect parameter types. 3. Parameter verification failed. |
| 801          | Capability not supported.                                    |
| 2801000      | Operation failed.                                            |
| 2801001      | Wi-Fi STA disabled.                                          |

6. 示例：

```typescript
import { wifiManager } from '@kit.ConnectivityKit';

	try {
		let name = "****";
		wifiManager.setDeviceName(name);	
	}catch(error){
		console.error("failed:" + JSON.stringify(error));
	}
```

## wifiManager.createGroup

1. 功能：创建p2p群组
2. 需求权限： ohos.permission.GET_WIFI_INFO
3. 系统能力： SystemCapability.Communication.WiFi.P2P

4. 参数：

| **参数名** | **类型**      | 必填 | **说明**                                                     |
| ---------- | ------------- | ---- | ------------------------------------------------------------ |
| config     | WifiP2PConfig | 是   | 群组配置信息。如果DeviceAddressType未指定值，则DeviceAddressType默认为随机设备地址类型。 |

5.错误码：

| **错误码ID** | **错误信息**                                                 |
| ------------ | ------------------------------------------------------------ |
| 201          | Permission denied.                                           |
| 401          | Invalid parameters. Possible causes: 1. Incorrect parameter types. 2. Parameter verification failed. |
| 801          | Capability not supported.                                    |
| 2801000      | Operation failed.                                            |
| 2801001      | Wi-Fi STA disabled.                                          |

6. 示例：
   ```javascript
   import { wifiManager } from '@kit.ConnectivityKit';
   
   	try {
   		let config:wifiManager.WifiP2PConfig = {
   			deviceAddress: "****",
   			netId: 0,
   			passphrase: "*****",
   			groupName: "****",
   			goBand: 0
   		}
   		wifiManager.createGroup(config);	
   		
   	}catch(error){
   		console.error("failed:" + JSON.stringify(error));
   	}
   ```

## wifiManager.getCurrentGroup

1. 功能：获取P2P当前组信息，使用Promise异步回调。

2. 需要权限：API 10起：ohos.permission.GET_WIFI_INFO

3. 系统能力： SystemCapability.Communication.WiFi.P2P
4. 返回值：

| 类型                      | 说明                                                         |
| ------------------------- | ------------------------------------------------------------ |
| Promise<WifiP2pGroupInfo> | Promise对象。表示当前组信息。如果应用申请了ohos.permission.GET_WIFI_PEERS_MAC权限（仅系统应用可申请），则返回结果中的deviceAddress为真实设备地址，否则为随机设备地址。 |

5. 错误码：

| **错误码ID** | **错误信息**              |
| ------------ | ------------------------- |
| 201          | Permission denied.        |
| 801          | Capability not supported. |
| 2801000      | Operation failed.         |

6. 示例：

```typescript
import { wifiManager } from '@kit.ConnectivityKit';
	// p2p已经建组或者连接成功，才能正常获取到当前组信息
	wifiManager.getCurrentGroup((err, data:wifiManager.WifiP2pGroupInfo) => {
    if (err) {
        console.error("get current P2P group error");
        return;
    }
		console.info("get current P2P group: " + JSON.stringify(data));
	});

	wifiManager.getCurrentGroup().then(data => {
		console.info("get current P2P group: " + JSON.stringify(data));
	});
```

7 说明： 只有建立p2p连接的设备才能正常获取当前组信息，否则会抛异常，错误码2801000

## wifiManager.removeGroup
1. 功能： 移除p2p群组
2. 权限：ohos.permission.GET_WIFI_INFO
3. 能力：SystemCapability.Communication.WiFi.P2P
4. 错误码：
   | **错误码ID** | **错误信息**              |
   | ------------ | ------------------------- |
   | 201          | Permission denied.        |
   | 801          | Capability not supported. |
   | 2801000      | Operation failed.         |
   | 2801001      | Wi-Fi STA disabled.       |
5. 示例：
```typescript
import { wifiManager } from '@kit.ConnectivityKit';

	try {
		wifiManager.removeGroup();	
	}catch(error){
		console.error("failed:" + JSON.stringify(error));
	}
```

## wifiManager.p2pConnect

1. 功能：建立p2p连接
2. 需要权限：ohos.permission.GET_WIFI_INFO
3. 系统能力： SystemCapability.Communication.WiFi.P2P
4. 参数：

| **参数名** | **类型**      | 必填 | **说明**                                                     |
| ---------- | ------------- | ---- | ------------------------------------------------------------ |
| config     | WifiP2PConfig | 是   | 连接配置信息。如果DeviceAddressType未指定值，则DeviceAddressType默认为随机设备地址类型。 |

5 错误码：

| **错误码ID** | **错误信息**                                                 |
| ------------ | ------------------------------------------------------------ |
| 201          | Permission denied.                                           |
| 401          | Invalid parameters. Possible causes: 1. Incorrect parameter types. 2. Parameter verification failed. |
| 801          | Capability not supported.                                    |
| 2801000      | Operation failed.                                            |
| 2801001      | Wi-Fi STA disabled.                                          |

6 示例：

```typescript
import { wifiManager } from '@kit.ConnectivityKit';
  
  let recvP2pConnectionChangeFunc = (result:wifiManager.WifiP2pLinkedInfo) => {
      console.info("p2p connection change receive event: " + JSON.stringify(result));
      wifiManager.getP2pLinkedInfo((err, data:wifiManager.WifiP2pLinkedInfo) => {
          if (err) {
              console.error('failed to get getP2pLinkedInfo: ' + JSON.stringify(err));
              return;
          }
          console.info("get getP2pLinkedInfo: " + JSON.stringify(data));
      });
  }
  wifiManager.on("p2pConnectionChange", recvP2pConnectionChangeFunc);
  
  let recvP2pDeviceChangeFunc = (result:wifiManager.WifiP2pDevice) => {
      console.info("p2p device change receive event: " + JSON.stringify(result));
  }
  wifiManager.on("p2pDeviceChange", recvP2pDeviceChangeFunc);
  
  let recvP2pPeerDeviceChangeFunc = (result:wifiManager.WifiP2pDevice[]) => {
      console.info("p2p peer device change receive event: " + JSON.stringify(result));
      wifiManager.getP2pPeerDevices((err, data:wifiManager.WifiP2pDevice) => {
          if (err) {
              console.error('failed to get peer devices: ' + JSON.stringify(err));
              return;
          }
          console.info("get peer devices: " + JSON.stringify(data));
          let len = data.length;
          for (let i = 0; i < len; ++i) {
              if (data[i].deviceName === "my_test_device") {
                  console.info("p2p connect to test device: " + data[i].deviceAddress);
                  let config:wifiManager.WifiP2PConfig = {
                      deviceAddress:data[i].deviceAddress,
                      netId:-2,
                      passphrase:"",
                      groupName:"",
                      goBand:0,
                  }
                  wifiManager.p2pConnect(config);
              }
          }
      });
  }
  wifiManager.on("p2pPeerDeviceChange", recvP2pPeerDeviceChangeFunc);
  
  let recvP2pPersistentGroupChangeFunc = () => {
      console.info("p2p persistent group change receive event");
  
      wifiManager.getCurrentGroup((err, data:wifiManager.WifiP2pGroupInfo) => {
          if (err) {
              console.error('failed to get current group: ' + JSON.stringify(err));
              return;
          }
          console.info("get current group: " + JSON.stringify(data));
      });
  }
  wifiManager.on("p2pPersistentGroupChange", recvP2pPersistentGroupChangeFunc);
  
  setTimeout(() => {wifiManager.off("p2pConnectionChange", recvP2pConnectionChangeFunc);}, 125 * 1000);
  setTimeout(() =>  {wifiManager.off("p2pDeviceChange", recvP2pDeviceChangeFunc);}, 125 * 1000);
  setTimeout(() =>  {wifiManager.off("p2pPeerDeviceChange", recvP2pPeerDeviceChangeFunc);}, 125 * 1000);
  setTimeout(() =>  {wifiManager.off("p2pPersistentGroupChange", recvP2pPersistentGroupChangeFunc);}, 125 * 1000);
  console.info("start discover devices -> " + wifiManager.startDiscoverDevices());
```

## wifiManager.p2pCancelConnect

1. 功能： 在p2p连接的过程中，取消连接
2. 需要权限：ohos.permission.GET_WIFI_INFO

3. 系统能力：SystemCapability.Communication.WiFi.P2P

4. 错误码：

| **错误码ID** | **错误信息**              |
| ------------ | ------------------------- |
| 201          | Permission denied.        |
| 801          | Capability not supported. |
| 2801000      | Operation failed.         |
| 2801001      | Wi-Fi STA disabled.       |

5. 示例：

```typescript
import { wifiManager } from '@kit.ConnectivityKit';

	try {
		wifiManager.p2pCancelConnect();	
	}catch(error){
		console.error("failed:" + JSON.stringify(error));
	}
```

##  wifiManager.on('p2pDeviceChange')

1. 功能：注册P2P设备状态改变事件

2. 需要权限：API 10起：ohos.permission.GET_WIFI_INFO

3. 系统能力： SystemCapability.Communication.WiFi.P2P

4. 参数：

| **参数名** | **类型**                | **必填** | **说明**                        |
| ---------- | ----------------------- | -------- | ------------------------------- |
| type       | string                  | 是       | 固定填"p2pDeviceChange"字符串。 |
| callback   | Callback<WifiP2pDevice> | 是       | 状态改变回调函数。              |

5. 错误码：

| **错误码ID** | **错误信息**                                                 |
| ------------ | ------------------------------------------------------------ |
| 20110+       | Permission denied.                                           |
| 401          | Invalid parameters. Possible causes: 1. Mandatory parameters are left unspecified. 2. Incorrect parameter types. |
| 801          | Capability not supported.                                    |
| 2801000      | Operation failed.                                            |

6. 示例：

```typescript
 import { wifiManager } from '@kit.ConnectivityKit';
  
  let recvP2pDeviceChangeFunc = (result:wifiManager.WifiP2pDevice) => {
      console.info("Receive p2p device change event: " + result);
  }
  
  // Register event
  wifiManager.on("p2pDeviceChange", recvP2pDeviceChangeFunc);
  
  // Unregister event
  wifiManager.off("p2pDeviceChange", recvP2pDeviceChangeFunc);
```

## wifiManager.off()

1. 功能：取消以上列举的各种on事件监听
2. 说明：在没有监听某事件的情况下调用off会抛异常，需要保证注册监听和取消注册监听某事件的方法成对出现