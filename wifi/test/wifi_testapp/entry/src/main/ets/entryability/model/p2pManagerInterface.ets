/**
 * Copyright (c) 2022 Shenzhen Kaihong Digital Industry Development Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import prompt from '@system.prompt';
import router from '@ohos.router';
import wifiManager from '@ohos.wifiManager';
import { BusinessError } from '@ohos.base';

type Callback = (error: BusinessError | null , message?: string) => void;
type Callback1 = (error: BusinessError | null , linkedInfo?: wifiManager.WifiP2pLinkedInfo) => void;
type Callback2 = (error: BusinessError | null , linkedInfo?: wifiManager.WifiP2pGroupInfo) => void;
const TAG = "[p2pManagerInterface]"
/**
 * p2pManager Test Page Of Wifi test
 */
const PAGE_URI_P2P_FOUND_MODE = 'pages/subManualApiTest/subP2pTest/p2pFound';

export function testGetP2pLinkedInfoManagerPromise(): string {
  try {
    let message = "getP2pLinkedInfoPromise test"
    wifiManager.getP2pLinkedInfo().then(wifiP2pLinkedInfo => {
      console.log(TAG , "getP2pLinkedInfoPromise: " + JSON.stringify(wifiP2pLinkedInfo))
      message = "getP2pLinkedInfoPromise: " + JSON.stringify(wifiP2pLinkedInfo)
      prompt.showToast({ message : message })
    }).catch((error: BusinessError) => {
      console.log(TAG , "testGetP2pLinkedInfoManagerPromise error :" + error)
    })
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testGetP2pLinkedInfoManagerPromise. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testGetP2pLinkedInfoManagerPromise. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testGetP2pLinkedInfoManagerCallback(callback: Callback1): void {
  try {
    let message = "getP2pLinkedInfoCallback test"
    wifiManager.getP2pLinkedInfo((err: BusinessError , WifiP2pLinkedInfo) => {
      if ( err ) {
        console.error("getP2pLinkedInfoCallback error" , err);
        message = "Error getting P2P linked info: " + JSON.stringify(err);
        prompt.showToast({ message : message });
        callback(err); // 使用回调返回错误信息
      } else {
        console.log(TAG , "getP2pLinkedInfoCallback: " + JSON.stringify(WifiP2pLinkedInfo));
        message = "getP2pLinkedInfoCallback: " + JSON.stringify(WifiP2pLinkedInfo);
        prompt.showToast({ message : message });
        callback(null , WifiP2pLinkedInfo); // 使用回调返回成功的消息
      }
    })
    // 不要在这里显示提示信息，因为它可能与实际的异步结果不同步
    // 如果你想在调用开始时给用户反馈，可以在这里保留
    prompt.showToast({ message : message })
  } catch( error ) {
    console.log(TAG , `Failed to testGetP2pLinkedInfoManagerCallback. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testGetP2pLinkedInfoManagerCallback. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
  }
}

export function testGetCurrentP2pGroupManagerPromise(): string {
  try {
    let message = "getCurrentGroupPromise test"
    wifiManager.getCurrentGroup().then(WifiP2pGroupInfo => {
      console.log(TAG , "getCurrentGroupPromise: " + JSON.stringify(WifiP2pGroupInfo))
      message = "getCurrentGroupPromise: " + JSON.stringify(WifiP2pGroupInfo)
      prompt.showToast({ message : message })
    }).catch((error: BusinessError) => {
      console.log(TAG , "testGetCurrentP2pGroupManagerPromise error :" + error)
    })
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testGetCurrentP2pGroupManagerPromise. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testGetCurrentP2pGroupManagerPromise. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testGetCurrentP2pGroupManagerCallback(callback: Callback2): void {
  try {
    let message = "getCurrentGroupCallback test"

    wifiManager.getCurrentGroup((err: BusinessError , WifiP2pGroupInfo) => {
      if ( err ) {
        console.error("getCurrentGroupCallback error" , err);
        message = "Error getting current P2P group: " + JSON.stringify(err);
        prompt.showToast({ message : message });
        callback(err); // 使用回调返回错误信息
      } else {
        console.log(TAG , "getCurrentGroupCallback: " + JSON.stringify(WifiP2pGroupInfo));
        message = "getCurrentGroupCallback: " + JSON.stringify(WifiP2pGroupInfo);
        prompt.showToast({ message : message });
        callback(null , WifiP2pGroupInfo); // 使用回调返回成功的消息
      }
    })
    // 不要在这里显示提示信息，因为它可能与实际的异步结果不同步
    // 如果你想在调用开始时给用户反馈，可以在这里保留
    prompt.showToast({ message : message })
  } catch( error ) {
    console.log(TAG , `Failed to testGetCurrentP2pGroupManagerCallback. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testGetCurrentP2pGroupManagerCallback. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
  }
}

export function testGetP2pPeerDevicesManagerPromise() {
  try {
    let message = "getP2pPeerDevicesPromise test"
    wifiManager.getP2pPeerDevices().then(WifiP2pDevice => {
      console.log(TAG , "getP2pPeerDevicesPromise: " + JSON.stringify(WifiP2pDevice))
      message = "getP2pPeerDevicesPromise: " + JSON.stringify(WifiP2pDevice)
      prompt.showToast({ message : message })
    }).catch((error: BusinessError) => {
      console.log(TAG , "testGetP2pPeerDevicesManagerPromise error :" + error)
    })
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testGetP2pPeerDevicesManagerPromise. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testGetP2pPeerDevicesManagerPromise. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testGetP2pPeerDevicesManagerCallback(callback: Callback): void {
  try {
    let message = "GetP2pPeerDevicesCallback test"

    wifiManager.getP2pPeerDevices((err: BusinessError , WifiP2pDevice) => {
      if ( err ) {
        console.error("GetP2pPeerDevicesCallback error" , err);
        message = "Error getting P2P peer devices: " + JSON.stringify(err);
        prompt.showToast({ message : message });
        callback(err); // 使用回调返回错误信息
      } else {
        console.log(TAG , "GetP2pPeerDevicesCallback: " + JSON.stringify(WifiP2pDevice));
        message = "GetP2pPeerDevicesCallback: " + JSON.stringify(WifiP2pDevice);
        prompt.showToast({ message : message });
        callback(null , message); // 使用回调返回成功的消息
      }
    })
    // 不要在这里显示提示信息，因为它可能与实际的异步结果不同步
    // 如果你想在调用开始时给用户反馈，可以在这里保留
    prompt.showToast({ message : message })
  } catch( error ) {
    console.log(TAG , `Failed to testGetP2pPeerDevicesManagerCallback. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testGetP2pPeerDevicesManagerCallback. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
  }
}

export function testGetP2pLocalDeviceManagerPromise() {
  try {
    let message = "getP2pLocalDevicePromise test"
    wifiManager.getP2pLocalDevice().then(WifiP2pDevice => {
      console.log(TAG , "getP2pLocalDevicePromise: " + JSON.stringify(WifiP2pDevice))
      message = "getP2pLocalDevicePromise: " + JSON.stringify(WifiP2pDevice)
      prompt.showToast({ message : message })
    }).catch((error: BusinessError) => {
      console.log(TAG , "testGetP2pLocalDeviceManagerPromise error :" + error)
    })
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testGetP2pLocalDeviceManagerPromise. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testGetP2pLocalDeviceManagerPromise. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testGetP2pLocalDeviceManagerCallback(callback: Callback): void {
  try {
    let message = "getP2pLocalDeviceCallback test"
    wifiManager.getP2pLocalDevice((err: BusinessError , WifiP2pDevice) => {
      if ( err ) {
        console.error("getP2pLocalDeviceCallback error");
        message = "Error getting P2P local device: " + JSON.stringify(err);
        console.error(message);
        callback(err); // 使用回调返回错误
      } else {
        console.log(TAG , "getP2pLocalDeviceCallback: " + JSON.stringify(WifiP2pDevice));
        message = "getP2pLocalDeviceCallback: " + JSON.stringify(WifiP2pDevice);
        callback(null , message); // 使用回调返回成功的消息
      }
    })
    // 由于getP2pLocalDevice是异步的，这里的提示会立即显示，而不是在操作完成后
    // 所以你可能要考虑是否需要在这里显示提示
    prompt.showToast({ message : message });
  } catch( error ) {
    console.log(TAG , `Failed to testGetP2pLocalDeviceManagerCallback. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testGetP2pLocalDeviceManagerCallback. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
  }
}

export function testCreateP2pGroupManager(): string {
  try {
    let message = "createGroup test"
    let deviceAddress: string = AppStorage.get("deviceAddressManager") ! //非空断言操作符
    let netId: number = AppStorage.get("netIdManager") ! //非空断言操作符
    let passphrase: string = AppStorage.get("passphraseManager") ! //非空断言操作符
    let groupName: string = AppStorage.get("groupNameManager") ! //非空断言操作符
    let goBand: wifiManager.GroupOwnerBand = AppStorage.get("goBandManager") ! //非空断言操作符
    let wifiP2pConfigManager: wifiManager.WifiP2PConfig = {
      deviceAddress : deviceAddress ,
      netId : netId ,
      passphrase : passphrase ,
      groupName : groupName ,
      goBand : goBand
    }
    AppStorage.setOrCreate("wifiP2pConfigManager" , wifiP2pConfigManager)
    let ret = wifiManager.createGroup(wifiP2pConfigManager as wifiManager.WifiP2PConfig) // createP2pGroup的返回值为void
    message = "createP2pGroup 调用成功"
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testCreateP2pGroupManager. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testCreateP2pGroupManager. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testRemoveP2pGroupManager(): string {
  try {
    let message = "removeGroup test"
    let ret = wifiManager.removeGroup()
    message = "removeGroup: " + ret
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testRemoveP2pGroupManager. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testRemoveP2pGroupManager. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testP2pConnectManager(): string {
  try {
    let message = "P2pConnect test"
    let wifiP2pConfigManager = AppStorage.get("wifiP2pConfigManager") ! //非空断言操作符
    let ret = wifiManager.p2pConnect(wifiP2pConfigManager as wifiManager.WifiP2PConfig) // p2pConnect的返回值为void
    message = "p2pConnect 调用成功"
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testP2pConnectManager. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testP2pConnectManager. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testP2pCancelConnectManager(): string {
  try {
    let message = "p2pCancelConnect test"
    let ret = wifiManager.p2pCancelConnect() // p2pCancelConnect的返回值为void
    message = "p2pCancelConnect 调用成功"
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testP2pCancelConnectManager. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testP2pCancelConnectManager. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testStartDiscoverP2pDevicesManager(): string {
  try {
    let message = "startDiscoverDevices test"
    let ret = wifiManager.startDiscoverDevices() // startDiscoverP2pDevices的返回值为void
    message = "startDiscoverP2pDevices 调用成功"
    router.pushUrl({ url : PAGE_URI_P2P_FOUND_MODE });
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testStartDiscoverP2pDevicesManager. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testStartDiscoverP2pDevicesManager. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testStopDiscoverP2pDevicesManager(): string {
  try {
    let message = "stopDiscoverDevices test"
    let ret = wifiManager.stopDiscoverDevices() // stopDiscoverP2pDevices的返回值为void
    message = "stopDiscoverP2pDevices 调用成功"
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testStopDiscoverP2pDevicesManager. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testStopDiscoverP2pDevicesManager. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testDeletePersistentP2pGroupManager(): string {
  try {
    let message = "deletePersistentGroup test"
    let netId: number = AppStorage.get("netIdManager") ! //非空断言操作符
    let ret = wifiManager.deletePersistentGroup(netId)
    //      deletePersistentP2pGroup的返回值为void
    message = "deletePersistentP2pGroup 调用成功"
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testDeletePersistentP2pGroupManager. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testDeletePersistentP2pGroupManager. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testGetP2pGroupsManagerPromise() {
  try {
    let message = "getP2pGroupsPromise test"
    wifiManager.getP2pGroups().then(WifiP2pGroupInfo => {
      console.log(TAG , "getP2pGroupsPromise: " + JSON.stringify(WifiP2pGroupInfo))
      message = "getP2pGroupsPromise: " + JSON.stringify(WifiP2pGroupInfo)
      prompt.showToast({ message : message })
    }).catch((error: BusinessError) => {
      console.log(TAG , "testGetP2pGroupsManagerPromise error:" + error)
    })
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testGetP2pGroupsManagerPromise. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testGetP2pGroupsManagerPromise. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testGetP2pGroupsManagerCallback(callback: Callback): void {
  try {
    let message = "getP2pGroupsCallback test"

    wifiManager.getP2pGroups((err: BusinessError , WifiP2pGroupInfo) => {
      if ( err ) {
        console.error("getP2pGroupsCallback error")
        // 如果出错，返回错误信息
        callback(err);
      } else {
        console.log(TAG , "getP2pGroupsCallback: " + JSON.stringify(WifiP2pGroupInfo));
        message = "getP2pGroupsCallback: " + JSON.stringify(WifiP2pGroupInfo);
        prompt.showToast({ message : message });
        // 如果成功，返回null作为错误信息和对应的消息
        callback(null , message);
      }
    })
  } catch( error ) {
    console.log(TAG , `Failed to testGetP2pGroupsManagerCallback. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testGetP2pGroupsManagerCallback. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
  }
}

export function testSetP2pDeviceNameManager(): string {
  try {
    let message = "setDeviceName test"
    let devName: string = AppStorage.get("devNameManager") ! //非空断言操作符
    let ret = wifiManager.setDeviceName(devName)
    //      setP2pDeviceName的返回值为void
    let p2pManagerDeviceName = devName
    AppStorage.setOrCreate("p2pManagerDeviceName" , p2pManagerDeviceName)
    message = "setP2pDeviceName 调用成功"
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testSetP2pDeviceNameManager. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testSetP2pDeviceNameManager. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

let p2pStateChange = false

export function testOnP2pStateChangeManager(): string {
  try {
    let message = "OnP2pStateChange test"
    console.log(TAG , "testOnP2pStateChange test");
    if ( p2pStateChange ) {
      wifiManager.off("p2pStateChange" , () => {
        prompt.showToast({ message : "on.p2pStateChange监听已关闭" })
      })
      message = "关闭注册P2P开关状态改变事件"
    } else {
      wifiManager.on("p2pStateChange" , (number) => {
        //  @returns Returns 1: idle, 2: starting, 3:started, 4: closing, 5: closed
        let p2pStateMessage = ""
        switch ( number ) {
          case 1:
            p2pStateMessage = "idle";
            break;
          case 2:
            p2pStateMessage = "starting";
            break;
          case 3:
            p2pStateMessage = "started";
            break;
          case 4:
            p2pStateMessage = "closing";
            break;
          case 5:
            p2pStateMessage = "closed";
            break;
          default:
            p2pStateMessage = '未知状态';
            break;
        }
        prompt.showToast({ message : "状态: " + p2pStateMessage })
      })
      message = "打开注册P2P开关状态变化"
      prompt.showToast({ message : message })
    }
    p2pStateChange = !p2pStateChange
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testOnP2pStateChangeManager. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testOnP2pStateChangeManager. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

let p2pConnectionChange = false

export function testOnP2pConnectionChangeManager(): string {
  try {
    let message = "OnP2pConnectionChange test"
    console.log(TAG , "testOnP2pConnectionChange test");
    if ( p2pConnectionChange ) {
      wifiManager.off("p2pConnectionChange" , () => {
        prompt.showToast({ message : "on.P2pConnectionChange监听已关闭" })
      })
      message = "关闭P2P连接状态改变事件"
    } else {
      wifiManager.on("p2pConnectionChange" , (WifiP2pLinkedInfo) => {
        let connectState = WifiP2pLinkedInfo.connectState
        let p2pConnectionMessage = ""
        switch ( connectState ) {
          case 0:
            p2pConnectionMessage = "DISCONNECTED!";
            break;
          case 1:
            p2pConnectionMessage = "CONNECTED！";
            break;
          default:
            p2pConnectionMessage = '未知状态';
            break;
        }
        let isGroupOwner = WifiP2pLinkedInfo.isGroupOwner
        let groupOwnerAddr = WifiP2pLinkedInfo.groupOwnerAddr
        message = "Info : " + p2pConnectionMessage + ",isGroupOwner: " + isGroupOwner + ",groupOwnerAddr: " + groupOwnerAddr
        prompt.showToast({ message : message })
      })
      message = "打开注册WLAN连接状态变化"
      prompt.showToast({ message : message })
    }
    p2pConnectionChange = !p2pConnectionChange
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testOnP2pConnectionChangeManager. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testOnP2pConnectionChangeManager. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

let p2pDeviceChange = false

export function testOnP2pDeviceChangeManager(): string {
  try {

    let message = "OnP2pDeviceChange test"
    console.log(TAG , "testOnP2pDeviceChange test")
    if ( p2pDeviceChange ) {
      wifiManager.off("p2pDeviceChange" , () => {
        prompt.showToast({ message : "on.P2pDeviceChange监听已关闭" })
      })
      message = "关闭P2P设备状态改变事件"
    } else {
      wifiManager.on("p2pDeviceChange" , (data) => {
        let p2pDeviceStatusMessage = ""
        let deviceName = data.deviceName
        let deviceAddress = data.deviceAddress
        let primaryDeviceType = data.primaryDeviceType
        let deviceStatus = data.deviceStatus
        let groupCapabilitys = data.groupCapabilities
        switch ( deviceStatus ) {
          case 0:
            p2pDeviceStatusMessage = "CONNECTED"
            break;
          case 1:
            p2pDeviceStatusMessage = "INVITED"
            break;
          case 2:
            p2pDeviceStatusMessage = "FAILED"
            break;
          case 3:
            p2pDeviceStatusMessage = "AVAILABLE"
            break;
          case 4:
            p2pDeviceStatusMessage = "UNAVAILABLE"
            break;
          default:
            p2pDeviceStatusMessage = '未知状态';
            break;
        }
        console.log(TAG , "info:" + JSON.stringify(data))
        message = "deviceName: " + deviceName + "\n" +
        "deviceAddress: " + deviceAddress + "\n" +
        "primaryDeviceType: " + primaryDeviceType + "\n" +
        "deviceStatus: " + p2pDeviceStatusMessage + "\n" +
        "groupCapabilitys: " + groupCapabilitys + "\n"
        prompt.showToast({ message : message })
      })
      message = "打开注册WLAN连接状态变化"
      prompt.showToast({ message : message })
    }
    p2pDeviceChange = !p2pDeviceChange
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testOnP2pDeviceChangeManager. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testOnP2pDeviceChangeManager. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

let p2pPeerDeviceChange = false

export function testOnP2pPeerDeviceChangeManager(): string {
  try {
    let message = "OnP2pPeerDeviceChange test"
    console.log(TAG , "testOnP2pPeerDeviceChange test")
    if ( p2pPeerDeviceChange ) {
      wifiManager.off("p2pPeerDeviceChange" , () => {
        prompt.showToast({ message : "on.p2pPeerDeviceChange监听已关闭" })
      })
      message = "关闭P2P对端设备状态改变事件"
    } else {
      wifiManager.on("p2pPeerDeviceChange" , (data) => {
        let p2pPeerDeviceChangeMessage = ""
        console.log(TAG , "WifiP2pDevice: " + JSON.stringify(data))
        p2pPeerDeviceChangeMessage = "WifiP2pDevice: " + JSON.stringify(data)
        prompt.showToast({ message : "状态 " + p2pPeerDeviceChangeMessage })
      })
      message = "打开P2P对端设备状态变化"
      prompt.showToast({ message : message })
    }
    p2pPeerDeviceChange = !p2pPeerDeviceChange
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testOnP2pPeerDeviceChangeManager. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testOnP2pPeerDeviceChangeManager. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

let p2pPersistentGroupChange = false

export function testOnP2pPersistentGroupChangeManager(): string {
  try {
    let message = "OnP2pPersistentGroupChange test"
    console.log(TAG , "testOnP2pPersistentGroupChange test")
    if ( p2pPersistentGroupChange ) {
      wifiManager.off("p2pPersistentGroupChange" , () => {
        prompt.showToast({ message : "on.p2pPersistentGroupChange监听已关闭" })
      })
      message = "关闭P2P永久组状态改变事件"
    } else {
      wifiManager.on("p2pPersistentGroupChange" , (data) => {
        let p2pPersistentGroupChangeMessage = ""
        console.log(TAG , "p2pPersistentGroupChange: " + data)
        p2pPersistentGroupChangeMessage = "p2pPersistentGroupChange: " + data
        prompt.showToast({ message : "状态: " + p2pPersistentGroupChangeMessage })
      })
      message = "打开P2P永久组状态变化"
      prompt.showToast({ message : message })
    }
    p2pPersistentGroupChange = !p2pPersistentGroupChange
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testOnP2pPersistentGroupChangeManager. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testOnP2pPersistentGroupChangeManager. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

let p2pDiscoveryChange = false

export function testOnP2pDiscoveryChangeManager(): string {
  try {
    let message = "OnP2pDiscoveryChange test"
    console.log(TAG , "testOnP2pDiscoveryChange test")
    if ( p2pDiscoveryChange ) {
      wifiManager.off("p2pDiscoveryChange" , () => {
        prompt.showToast({ message : "on.P2pDiscoveryChange监听已关闭" })
      })
      message = "关闭发现设备状态改变事件"
    } else {
      wifiManager.on("p2pDiscoveryChange" , (number) => {
        //      @returns Returns 0: initial state, 1: discovery succeeded
        let p2pDiscoveryChangeMessage = ""
        switch ( number ) {
          case 0:
            p2pDiscoveryChangeMessage = "initial state";
            break;
          case 1:
            p2pDiscoveryChangeMessage = "discovery succeeded";
            break;
          default:
            p2pDiscoveryChangeMessage = '未知状态';
            break;
        }
        prompt.showToast({ message : "发现状态：" + p2pDiscoveryChangeMessage })
      })
      message = "打开发现设备状态变化"
      prompt.showToast({ message : message })
    }
    p2pDiscoveryChange = !p2pDiscoveryChange
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testOnP2pDiscoveryChangeManager. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testOnP2pDiscoveryChangeManager. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}