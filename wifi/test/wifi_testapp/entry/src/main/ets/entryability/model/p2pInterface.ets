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
import wifi from '@ohos.wifi';
import ConfigData from '../../utils/ConfigData'
import LogData from '../../utils/LogData'
import MessageData from '../../utils/MessageData'
import { BusinessError } from '@ohos.base';
import wifiManager from '@ohos.wifiManager';

const PAGE_URI_P2P_FOUND_MODE = 'pages/subManualApiTest/subP2pTest/p2pFound';
const TAG = "[p2pInterface]"

interface p2pDevice {
  "deviceName": string,
  "deviceAddress": string,
  "deviceAddressType": number,
  "primaryDeviceType": string,
  "devStatus": number,
  "groupCapability": number
}

type Callback = (error: BusinessError | null , message?: string) => void;
/**
 * p2p Test Page Of Wifi test
 */

export function testGetP2pLinkedInfoPromise(): string {
  try {
    let message = (MessageData.testGetP2pLinkedInfoPromise)
    console.log(TAG , LogData.testGetP2pLinkedInfoPromise_StartLog);
    wifi.getP2pLinkedInfo().then(wifiP2pLinkedInfo => {
      console.log(TAG , LogData.getP2pLinkedInfoPromise_successfulLog)
      console.log(TAG , "getP2pLinkedInfoPromise: " + JSON.stringify(wifiP2pLinkedInfo))
      message = "getP2pLinkedInfoPromise: " + JSON.stringify(wifiP2pLinkedInfo)
      console.log(TAG , LogData.testGetP2pLinkedInfoPromise_EndLog);
      AppStorage.setOrCreate("p2pLinkMessage" , message)
      prompt.showToast({ message : message })
    }).catch((error: BusinessError) => {
      console.log(TAG , "testGetP2pLinkedInfoPromise error :" + error)
    })
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testGetP2pLinkedInfoPromise. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testGetP2pLinkedInfoPromise. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testGetP2pLinkedInfoCallback(): string {
  try {
    let message = (MessageData.testGetP2pLinkedInfoCallback)
    console.log(TAG , LogData.testGetP2pLinkedInfoCallback_StartLog);
    wifi.getP2pLinkedInfo((err , WifiP2pLinkedInfo) => {
      if ( err ) {
        console.error("getP2pLinkedInfoCallback error");
        console.error('failed to get getP2pLinkedInfo: ' + JSON.stringify(err));
      } else {
        console.log(TAG , LogData.getP2pLinkedInfoCallback_successfulLog);
        console.log(TAG , "getP2pLinkedInfoCallback: " + JSON.stringify(WifiP2pLinkedInfo));
        message = "getP2pLinkedInfoCallback: " + JSON.stringify(WifiP2pLinkedInfo);
        AppStorage.setOrCreate("p2pLinkMessage" , message);
        console.log(TAG , LogData.testGetP2pLinkedInfoCallback_EndLog);
        prompt.showToast({ message : message });
      }
    });
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testGetP2pLinkedInfoCallback. message: ${ error.message }, code: ${ error.code }`);
    let message = `Failed to testGetP2pLinkedInfoCallback. message: ${ error.message }, code: ${ error.code }`;
    prompt.showToast({ message : message });
    return message
  }
}

export function testGetCurrentGroupPromise(): string {
  try {
    let message = (MessageData.testGetCurrentGroupPromise)
    console.log(TAG , LogData.testGetCurrentGroupPromise_StartLog);
    wifi.getCurrentGroup().then(wifiP2pGroupInfo => {
      console.log(TAG , LogData.testGetCurrentGroupPromise_successfulLog);
      console.log(TAG , "getCurrentGroupPromise: " + JSON.stringify(wifiP2pGroupInfo))
      message = "getCurrentGroupPromise: " + JSON.stringify(wifiP2pGroupInfo)
      AppStorage.setOrCreate("p2pGroupMessage" , message)
      console.log(TAG , LogData.testGetCurrentGroupPromise_EndLog);
      prompt.showToast({ message : message })
    }).catch((error: BusinessError) => {
      console.log(TAG , "testGetCurrentGroupPromise error :" + error)
    })
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testGetCurrentGroupPromise. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testGetCurrentGroupPromise. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testGetCurrentGroupCallback(): string {
  try {
    let message = MessageData.testGetCurrentGroupCallback;
    console.log(TAG , LogData.testGetCurrentGroupCallback_StartLog);
    wifi.getCurrentGroup((err , wifiP2pGroupInfo: wifi.WifiP2pGroupInfo) => {
      if ( err ) {
        console.error("testCurrentGroupCallback 异常");
        console.error('failed to get current group: ' + JSON.stringify(err));
        prompt.showToast({ message : 'failed to get current group: ' + JSON.stringify(err) });
      } else {
        console.log(TAG , "wifiP2pGroupInfo:" + JSON.stringify(wifiP2pGroupInfo))
        let p2pLinkedDeviceName =''
        if ( wifiP2pGroupInfo.ownerInfo ) {
          p2pLinkedDeviceName = wifiP2pGroupInfo.ownerInfo.deviceName
        } else {
          p2pLinkedDeviceName = '未连接'
        }
        console.log(TAG , LogData.getCurrentGroupCallback_successfulLog);
        console.log(TAG , "p2pLinkedDeviceName: " + JSON.stringify(p2pLinkedDeviceName));
        console.log(TAG , "getCurrentGroupCallback: " + JSON.stringify(wifiP2pGroupInfo));
        message = "getCurrentGroupCallback: " + JSON.stringify(wifiP2pGroupInfo);
        AppStorage.SetOrCreate("p2pGroupMessage" , message);
        AppStorage.SetOrCreate("p2pLinkedDeviceName" , p2pLinkedDeviceName);
        console.log(TAG , LogData.testGetCurrentGroupCallback_EndLog);
        prompt.showToast({ message : message });
      }
    });
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testGetCurrentGroupCallback. message: ${ error.message }, code: ${ error.code }`);
    let message = `Failed to testGetCurrentGroupCallback. message: ${ error.message }, code: ${ error.code }`;
    prompt.showToast({ message : message });
    return error
  }
}

export function testGetP2pPeerDevicesPromise() {
  try {
    let message = (MessageData.testGetP2pPeerDevicesPromise)
    console.log(TAG , LogData.testGetP2pPeerDevicesPromise_StartLog);
    wifi.getP2pPeerDevices().then(WifiP2pDevice => {
      console.log(TAG , $r("app.string.getP2pPeerDevicesPromise_successful"));
      console.log(TAG , "getP2pPeerDevicesPromise: " + JSON.stringify(WifiP2pDevice))
      message = "getP2pPeerDevicesPromise: " + JSON.stringify(WifiP2pDevice)
      AppStorage.setOrCreate("p2pPeerDeviceMessages" , message)
      console.log(TAG , LogData.testGetP2pPeerDevicesPromise_EndLog);
      prompt.showToast({ message : message })
    }).catch((error: BusinessError) => {
      console.log(TAG , "testGetP2pPeerDevicesPromise error :" + error)
    })
    prompt.showToast({ message : message })
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testGetP2pPeerDevicesPromise. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testGetP2pPeerDevicesPromise. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testGetP2pPeerDevicesCallback(): string {
  try {
    let message = MessageData.testGetP2pPeerDevicesCallback;
    console.log(TAG , LogData.testGetP2pPeerDevicesCallback_StartLog);
    wifi.getP2pPeerDevices((err: BusinessError , WifiP2pDevice) => {
      if ( err ) {
        console.error("getP2pPeerDevicesCallback 异常");
        message = `Failed to get peer devices: ${ JSON.stringify(err) }`;
        console.error(message);
        prompt.showToast({ message : message });
        console.log(TAG , LogData.testGetP2pPeerDevicesCallback_EndLog);
      } else {
        console.log(TAG , LogData.getP2pPeerDevicesCallback_successfulLog);
        message = "getP2pPeerDevicesCallback: " + JSON.stringify(WifiP2pDevice);
        console.log(message);
        AppStorage.setOrCreate("p2pPeerDeviceMessages" , message);
        let len = Object.keys(WifiP2pDevice).length;
        for ( let i = 0 ; i < len ; ++ i ) {
          if ( WifiP2pDevice[ i ].deviceName === "MyTestDevice" ) {
            console.log(TAG , "p2p connect to test device: " + WifiP2pDevice[ i ].deviceAddress);
            let config: wifi.WifiP2PConfig = {
              "deviceAddress" : WifiP2pDevice[ i ].deviceAddress ,
              "netId" : - 2 ,
              "passphrase" : "" ,
              "groupName" : "" ,
              "goBand" : 0 ,
            }
            AppStorage.setOrCreate("config" , config)
          }
        }
        console.log(TAG , LogData.testGetP2pPeerDevicesCallback_EndLog);
        prompt.showToast({ message : message });
      }
    });
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testGetP2pPeerDevicesCallback. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testGetP2pPeerDevicesCallback. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testCreateGroup(): string {
  try {
    let message = (MessageData.testCreateGroup)
    console.log(TAG , LogData.testCreateGroup_StartLog);
    let deviceAddress: string = AppStorage.get("deviceAddress") ! //非空断言操作符
    let netId: number = AppStorage.get("netId") ! //非空断言操作符
    let passphrase: string = AppStorage.get("passphrase") ! //非空断言操作符
    let groupName: string = AppStorage.get("groupName") ! //非空断言操作符
    let goBand: wifi.GroupOwnerBand = AppStorage.get("goBand") ! //非空断言操作符
    let wifiP2pConfig: wifi.WifiP2PConfig = {
      deviceAddress : deviceAddress ,
      netId : netId ,
      passphrase : passphrase ,
      groupName : groupName ,
      goBand : goBand
    }
    AppStorage.setOrCreate("wifiP2pConfig" , wifiP2pConfig)
    let ret = wifi.createGroup(wifiP2pConfig as wifi.WifiP2PConfig)
    message = "createGroup: " + ret
    console.log(TAG , JSON.stringify(wifiP2pConfig) + ",ret:" + ret)
    console.log(TAG , LogData.testCreateGroup_EndLog);
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testCreateGroup. message: ${ error }`)
    let message = `Failed to testCreateGroup. message: ${ error }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testRemoveGroup(): string {
  try {
    let message = (MessageData.testRemoveGroup)
    console.log(TAG , LogData.testRemoveGroup_StartLog);
    let ret = wifi.removeGroup()
    message = "removeGroup: " + ret
    prompt.showToast({ message : message })
    console.log(TAG , LogData.testRemoveGroup_EndLog);
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testRemoveGroup. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testRemoveGroup. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testP2pConnect(): string {
  try {
    let message = (MessageData.testP2pConnect)
    console.log(TAG , LogData.testP2pConnect_StartLog);
    let config: wifi.WifiP2PConfig = AppStorage.get("config") ! //非空断言操作符
    let ret = wifi.p2pConnect(config)
    message = "p2pConnect: " + ret
    prompt.showToast({ message : message })
    console.log(TAG , LogData.testP2pConnect_EndLog);
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testP2pConnect. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testP2pConnect. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testP2pCancelConnect(): string {
  try {
    let message = (MessageData.testP2pCancelConnect)
    console.log(TAG , LogData.testP2pCancelConnect_StartLog);
    let ret = wifi.p2pCancelConnect()
    message = "p2pCancelConnect: " + ret
    prompt.showToast({ message : message })
    console.log(TAG , LogData.testP2pCancelConnect_EndLog);
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testP2pCancelConnect. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testP2pCancelConnect. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testStartDiscoverDevices(): string {
  try {
    let message = (MessageData.testStartDiscoverDevices)
    console.log(TAG , LogData.testStartDiscoverDevices_StartLog);
    let ret = wifi.startDiscoverDevices()
    message = "startDiscoverDevices: " + ret
    router.pushUrl({ url : PAGE_URI_P2P_FOUND_MODE });
    prompt.showToast({ message : message })
    console.log(TAG , LogData.testStartDiscoverDevices_EndLog);
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testStartDiscoverDevices. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testStartDiscoverDevices. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testStopDiscoverDevices(): string {
  try {
    let message = (MessageData.testStopDiscoverDevices)
    console.log(TAG , LogData.testStopDiscoverDevices_StartLog);
    let ret = wifi.stopDiscoverDevices()
    message = "stopDiscoverDevices: " + ret
    prompt.showToast({ message : message })
    console.log(TAG , LogData.testStopDiscoverDevices_EndLog);
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testStopDiscoverDevices. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testStopDiscoverDevices. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testDeletePersistentGroup(): string {
  try {
    let message = (MessageData.testDeletePersistentGroup)
    console.log(TAG , LogData.testDeletePersistentGroup_StartLog);
    let netId: number = AppStorage.get("netId") ! //非空断言操作符
    let ret = wifi.deletePersistentGroup(netId)
    message = "deletePersistentGroup: " + ret
    prompt.showToast({ message : message })
    console.log(TAG , LogData.testDeletePersistentGroup_EndLog);
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testDeletePersistentGroup. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testDeletePersistentGroup. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

export function testSetDeviceName(): string {
  try {
    let message = (MessageData.testSetDeviceName)
    console.log(TAG , LogData.testSetDeviceName_StartLog);
    let deviceName: string = AppStorage.get('deviceName') !
    let ret = wifi.setDeviceName(deviceName)
    message = "设置：" + ret + ",设备名称为：" + deviceName;
    console.log(TAG , "设置：" + ret + ",设备名称为：" + deviceName);
    AppStorage.setOrCreate("p2pDeviceName" , deviceName)
    prompt.showToast({ message : message })
    console.log(TAG , LogData.testSetDeviceName_EndLog);
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testSetDeviceName. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testSetDeviceName. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

let p2pStateChange = false

export function testOnP2pStateChange(): string {
  try {
    let message = (MessageData.testOnP2pStateChange)
    console.log(TAG , LogData.testOnP2pStateChange_StartLog)
    if ( p2pStateChange ) {
      wifi.off("p2pStateChange" , () => {
        prompt.showToast({ message : (MessageData.offP2pStateChange) })
      })
      message = (MessageData.offP2pStateChangeTest)
    } else {
      wifi.on("p2pStateChange" , (number) => {
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
        AppStorage.setOrCreate("p2pStateMessage" , p2pStateMessage)
        prompt.showToast({ message : "状态: " + p2pStateMessage })
        console.log(TAG , LogData.testOnP2pStateChange_EndLog);
      })
      message = (MessageData.onP2pStateChangeTest)
      prompt.showToast({ message : message })
    }
    p2pStateChange = !p2pStateChange
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testOnP2pStateChange. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testOnP2pStateChange. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

let p2pConnectionChange = false

export function testOnP2pConnectionChange(): string {
  try {
    let message = (MessageData.testOnP2pConnectionChange)
    console.log(TAG , LogData.testOnP2pConnectionChange_StartLog)
    if ( p2pConnectionChange ) {
      wifi.off("p2pConnectionChange" , () => {
        prompt.showToast({ message : (MessageData.offP2pConnectionChange) })
      })
      message = (MessageData.offP2pConnectionChangeTest)
    } else {
      wifi.on("p2pConnectionChange" , (WifiP2pLinkedInfo) => {
        let connectState = WifiP2pLinkedInfo.connectState
        let p2pConnectionMessage = ""
        switch ( connectState ) {
          case 0:
            p2pConnectionMessage = "未连接";
            break;
          case 1:
            p2pConnectionMessage = "已连接";
            break;
          default:
            p2pConnectionMessage = '未知状态';
            break;
        }
        let isGroupOwner = WifiP2pLinkedInfo.isGroupOwner
        let groupOwnerAddr = WifiP2pLinkedInfo.groupOwnerAddr
        message = "Info : " + p2pConnectionMessage + ",isGroupOwner: " + isGroupOwner + ",groupOwnerAddr: " + groupOwnerAddr
        prompt.showToast({ message : message })
        AppStorage.setOrCreate("p2pConnectState" , connectState)
        AppStorage.setOrCreate("p2pLinkStateMessage" , message)
        console.log(TAG , LogData.testOnP2pConnectionChange_EndLog)
      })
      message = (MessageData.onP2pConnectionChangeTest)
      prompt.showToast({ message : message })
    }
    p2pConnectionChange = !p2pConnectionChange
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testOnP2pConnectionChange. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testOnP2pConnectionChange. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

let p2pDeviceChange = false

export function testOnP2pDeviceChange(): string {
  try {
    let message = (MessageData.testOnP2pDeviceChange)
    console.log(TAG , LogData.testOnP2pDeviceChange_StartLog)
    if ( p2pDeviceChange ) {
      wifi.off("p2pDeviceChange" , () => {
        prompt.showToast({ message : MessageData.offP2pDeviceChange })
      })
      message = (MessageData.offP2pDeviceChangeTest)
    } else {
      wifi.on("p2pDeviceChange" , (data) => {
        let p2pDeviceStatusMessage = ""
        console.log(TAG , "info:" + JSON.stringify(data))
        message = JSON.stringify(data)
        // message = "deviceName: " + deviceName + "\n" +
        // "deviceAddress: " + deviceAddress + "\n" +
        // "primaryDeviceType: " + primaryDeviceType + "\n" +
        // "deviceStatus: " + p2pDeviceStatusMessage + "\n" +
        // "groupCapabilitys: " + groupCapabilitys + "\n"
        AppStorage.setOrCreate("p2pDeviceMessage" , message)
        prompt.showToast({ message : message })
        console.log(TAG , LogData.testOnP2pDeviceChange_EndLog)
      })
      message = (MessageData.onP2pDeviceChangeTest)
      prompt.showToast({ message : message })
    }
    p2pDeviceChange = !p2pDeviceChange
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testOnP2pDeviceChange. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testOnP2pDeviceChange. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

let p2pPeerDeviceChange = false

export function testOnP2pPeerDeviceChange(): string {
  try {
    let message = (MessageData.testOnP2pPeerDeviceChange)
    console.log(TAG , LogData.testOnP2pPeerDeviceChange_StartLog)
    if ( p2pPeerDeviceChange ) {
      wifi.off("p2pPeerDeviceChange" , () => {
        prompt.showToast({ message : (MessageData.offP2pPeerDeviceChange) })
      })
      message = (MessageData.offP2pPeerDeviceChangeTest)
    } else {
      wifi.on("p2pPeerDeviceChange" , (data) => {
        let p2pPeerDeviceChangeMessage = ""
        console.log(TAG , "WifiP2pDevice: " + JSON.stringify(data))
        p2pPeerDeviceChangeMessage = "WifiP2pDevice: " + JSON.stringify(data)
        AppStorage.setOrCreate("p2pPeerDeviceMessage" , p2pPeerDeviceChangeMessage)
        prompt.showToast({ message : "状态 " + p2pPeerDeviceChangeMessage })
        console.log(TAG , LogData.testOnP2pPeerDeviceChange_EndLog)
      })
      message = (MessageData.onP2pPeerDeviceChangeTest)
      prompt.showToast({ message : message })
    }
    p2pPeerDeviceChange = !p2pPeerDeviceChange
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testOnP2pPeerDeviceChange. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testOnP2pPeerDeviceChange. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

let p2pPersistentGroupChange = false

export function testOnP2pPersistentGroupChange(): string {
  try {
    let message = (MessageData.testOnP2pPersistentGroupChange)
    console.log(TAG , LogData.testOnP2pPersistentGroupChange_StartLog)
    if ( p2pPersistentGroupChange ) {
      wifi.off("p2pPersistentGroupChange" , () => {
        prompt.showToast({ message : (MessageData.offP2pPersistentGroupChange) })
      })
      message = (MessageData.offP2pPersistentGroupChangeTest)
    } else {
      wifi.on("p2pPersistentGroupChange" , (data) => {
        let p2pPersistentGroupChangeMessage = ""
        console.log(TAG , "p2pPersistentGroupChange: " + data)
        p2pPersistentGroupChangeMessage = "p2pPersistentGroupChange: " + data
        prompt.showToast({ message : "状态: " + p2pPersistentGroupChangeMessage })
        console.log(TAG , LogData.testOnP2pPersistentGroupChange_EndLog)
      })
      message = (MessageData.onP2pPersistentGroupChangeTest)
      prompt.showToast({ message : message })
    }
    p2pPersistentGroupChange = !p2pPersistentGroupChange
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testOnP2pPersistentGroupChange. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testOnP2pPersistentGroupChange. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}

let p2pDiscoveryChange = false

export function testOnP2pDiscoveryChange(): string {
  try {
    let message = (MessageData.testOnP2pDiscoveryChange)
    console.log(TAG , LogData.testOnP2pDiscoveryChange_StartLog)
    if ( p2pDiscoveryChange ) {
      wifi.off("p2pDiscoveryChange" , () => {
        prompt.showToast({ message : (MessageData.offP2pDiscoveryChange) })
      })
      message = (MessageData.offP2pDiscoveryChangeTest)
    } else {
      wifi.on("p2pDiscoveryChange" , (number) => {
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
        AppStorage.setOrCreate("p2pDiscoveryMessage" , p2pDiscoveryChangeMessage)
        console.log(TAG , LogData.testOnP2pDiscoveryChange_EndLog)
      })
      message = (MessageData.onP2pDiscoveryChangeTest)
      prompt.showToast({ message : message })
    }
    p2pDiscoveryChange = !p2pDiscoveryChange
    return message
  } catch( error ) {
    console.log(TAG , `Failed to testOnP2pDiscoveryChange. message: ${ error.message }, code: ${ error.code }`)
    let message = `Failed to testOnP2pDiscoveryChange. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast({ message : message })
    return message
  }
}