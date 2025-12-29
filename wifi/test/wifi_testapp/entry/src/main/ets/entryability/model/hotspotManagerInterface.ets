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

import promptAction from '@ohos.promptAction';

import wifiManager from '@ohos.wifiManager';

const TAG = "wifiTestApp [hotspotManagerInterface]"
/**
 * hotspotManager Test Page Of Wifi test
 */

let hotspotManagerEnable = false

export function testIsMeteredHotspot() {
  try {
    let message = ''
    let ret = wifiManager.isMeteredHotspot()
    message = "DisconnectedReason:" + ret
    promptAction.showToast({ message: message });
    console.log(TAG + message);
    return message
  } catch( e) {
    console.log(TAG, `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message: message })
    return message
  }
}

export function testEnableHiLinkHandshake() {
  try {
    // let config:wifiManager.WifiDeviceConfig
    // wifiManager.enableHiLinkHandshake(true,'',config)
  } catch( e) {
  }
}

export function testFactoryReset() {
  try {
    let message = ''
    wifiManager.factoryReset()
    message = "factoryReset:"
    promptAction.showToast({ message: message })
    console.log(TAG + message);
    return message
  } catch( e) {
    console.log(TAG, `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message: message })
    return message
  }
}

export function testEnableHotspotManager() {
  try {
    let message = " enableHotspot test"
    if (hotspotManagerEnable) {
      message = "热点已经使能"
    } else {
      wifiManager.enableHotspot() //enableHotspot的返回值为void
      message = "热点使能执行结果：true"
      hotspotManagerEnable = true
      AppStorage.setOrCreate('hotspotIsOn', hotspotManagerEnable);
    }
    promptAction.showToast({ message: message })
    return message
  } catch( err) {
    console.log(TAG, `Failed to testEnableHotspotManager. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testEnableHotspotManager. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({ message: message })
    return message
  }
}

export function testDisableHotspotManager() {
  try {
    let message = "disableWifi test"
    if (!hotspotManagerEnable) {
      message = '热点还未使能';
    } else {
      wifiManager.disableHotspot(); //disableHotspot的返回值为void
      message = "热点去使能执行结果：true"
      hotspotManagerEnable = false;
      AppStorage.setOrCreate('hotspotIsOn', hotspotManagerEnable);
    }
    promptAction.showToast({ message: message })
    return message
  } catch( err) {
    console.log(TAG, `Failed to testDisableHotspotManager. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testDisableHotspotManager. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({ message: message })
    return message
  }
}

export function testIsHotspotDualBandSupportedManager(): string {
  try {
    let message = " isHotspotDualBandSupported test"
    let ret = wifiManager.isHotspotDualBandSupported()
    message = "热点支持双频结果：" + ret
    promptAction.showToast({ message: message })
    return message
  } catch( err) {
    console.log(TAG, `Failed to testIsHotspotDualBandSupportedManager. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testIsHotspotDualBandSupportedManager. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({ message: message })
    return message
  }
}

export function testIsHostActiveManager(): string {
  try {
    let message = "isHostActive test"
    let ret = wifiManager.isHotspotActive()
    if (ret) {
      hotspotManagerEnable = true
    } else {
      hotspotManagerEnable = false
    }
    message = "HostActive is " + ret
    promptAction.showToast({ message: message })
    return message
  } catch( err) {
    console.log(TAG, `Failed to testIsHostActiveManager. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testIsHostActiveManager. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({ message: message })
    return message
  }
}

export function testSetHotspotConfigManager(): string {
  try {
    let message = "SetHotspotConfig test"
    let ssid = "testApp123"
    let securityType = 3
    let band = 1;
    let preSharedKey = "12345678"
    let maxConn = 3
    let channel = 6
    // TODO: 设备调试时候需要打开
    ssid = AppStorage.get("h_ssid1")! //非空断言操作符
    //  let securityType=AppStorage.get("h_securityType1")
    //  let band = AppStorage.get("h_band1")
    preSharedKey = AppStorage.get("h_preSharedKey1")! //非空断言操作符
    //  let maxConn = AppStorage.get("h_maxConn1")
    let config: wifiManager.HotspotConfig = {
      ssid: ssid ,
      securityType: securityType ,
      band: band ,
      preSharedKey: preSharedKey ,
      maxConn: maxConn ,
    }
    let ret = wifiManager.setHotspotConfig(config)
    message = "SetHotspotConfig 调用成功"
    promptAction.showToast({ message: message })
    return message
  } catch( err) {
    console.log(TAG, `Failed to testSetHotspotConfigManager. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testSetHotspotConfigManager. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({ message: message })
    return message
  }
}

export function testGetHotspotConfigManager(): string {
  try {
    let message = "getHotspotConfig test"
    let ret = wifiManager.getHotspotConfig()
    message = "HotspotConfig is " + JSON.stringify(ret)
    let hotspotManagerSsid = ret.ssid
    AppStorage.setOrCreate("hotspotManagerSsid", hotspotManagerSsid)
    console.log(TAG, "HotspotConfig is" + JSON.stringify(ret))
    let getHotspotConfigManagerMessage = JSON.stringify(ret)
    AppStorage.setOrCreate("getHotspotConfigManagerMessage", getHotspotConfigManagerMessage)
    promptAction.showToast({ message: message })
    return message
  } catch( err) {
    console.log(TAG, `Failed to testGetHotspotConfigManager. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testGetHotspotConfigManager. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({ message: message })
    return message
  }
}

export function testGetHotspotStationsManager(): string {
  try {
    let message = "GetStations test"
    let ret = wifiManager.getStations()
    message = "GetStations is" + JSON.stringify(ret)
    console.log(TAG, "GetStations is" + JSON.stringify(ret))
    let getStationsManagerMessage = JSON.stringify(ret)
    AppStorage.setOrCreate("getStationsManagerMessage", getStationsManagerMessage)
    promptAction.showToast({ message: message })
    return message
  } catch( err) {
    console.log(TAG, `Failed to testGetHotspotStationsManager. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testGetHotspotStationsManager. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({ message: message })
    return message
  }
}

export function testAddHotspotBlockList() {
  try {
    // let stationInfo:wifiManager.StationInfo
    // wifiManager.addHotspotBlockList(stationInfo)
  } catch( e) {
  }
}

export function testDelHotspotBlockList() {
  try {
    // let stationInfo:wifiManager.StationInfo
    // wifiManager.delHotspotBlockList(stationInfo)
  } catch( e) {

  }
}

export function testGetHotspotBlockList() {
  try {
    let message = ''
    let ret = wifiManager.getHotspotBlockList()
    message = "DisconnectedReason:" + JSON.stringify(ret)
    promptAction.showToast({ message: message })
    console.log(TAG + message);
    return message
  } catch( e) {
    console.log(TAG, `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({ message: message })
    return message
  }
}

let hotspotStateChangeManager = false

export function testOnHotspotStateChangeManager(): string {
  try {
    let message = "onHotspotStateChange test"
    console.log(TAG, "testOnHotspotStateChange test");
    if (hotspotStateChangeManager) {
      wifiManager.off("hotspotStateChange", () => {
        promptAction.showToast({ message: "on.hotspotStateChange监听已关闭" })
      })
      message = "关闭注册热点状态改变事件"
    } else {
      wifiManager.on("hotspotStateChange", (number) => {
        let hotspotStateManagerMessage = ""
        switch (number) {
          case 0: hotspotStateManagerMessage = "inactive";
            break;
          case 1: hotspotStateManagerMessage = "active";
            break;
          case 2: hotspotStateManagerMessage = "activating";
            break;
          case 3: hotspotStateManagerMessage = "de-activating";
            break;
          default: hotspotStateManagerMessage = '未知状态';
            break;
        }
        promptAction.showToast({ message: "状态为:" + hotspotStateManagerMessage })
        AppStorage.setOrCreate("hotspotStateManagerMessage", hotspotStateManagerMessage)
      })
      message = "打开注册热点状态变化"
      promptAction.showToast({ message: message })
    }
    hotspotStateChangeManager = !hotspotStateChangeManager
    return message
  } catch( err) {
    console.log(TAG, `Failed to testOnHotspotStateChangeManager. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testOnHotspotStateChangeManager. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({ message: message })
    return message
  }
}

let hotspotStaJoinManager = false

export function testOnHotspotStaJoinManager() {
  try {
    let message = "onHotspotStaJoin test"
    console.log(TAG, " testOnHotspotStaJoin ")
    if (hotspotStaJoinManager) {
      wifiManager.off("hotspotStaJoin", () => {
        promptAction.showToast({ message: "on.hotspotStaJoin监听已关闭" })
      })
      message = "关闭注册Wi-Fi 热点 sta加入变化事件"
    } else {
      wifiManager.on("hotspotStaJoin", (data) => {
        let hotspotStaJoinManagerMessage = "name:" + data.name + ";macAddress:" + data.macAddress + ";ipAddress:" + data.ipAddress
        message = "状态为: " + JSON.stringify(data)
        AppStorage.setOrCreate("hotspotStaJoinManagerMessage", message)
        promptAction.showToast({ message: hotspotStaJoinManagerMessage })
      })
      message = "打开注册Wi-Fi 热点 sta加入变化"
      promptAction.showToast({ message: message })
    }
    hotspotStaJoinManager = !hotspotStaJoinManager
    return message
  } catch( err) {
    console.log(TAG, `Failed to testOnHotspotStaJoinManager. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testOnHotspotStaJoinManager. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({ message: message })
    return message
  }
}

let hotspotStaLeaveManager = false

export function testOnHotspotStaLeaveManager() {
  try {
    let message = "onHotspotStaLeave test"
    console.log(TAG, " testOnHotspotStaLeave ")
    if (hotspotStaLeaveManager) {
      wifiManager.off("hotspotStaLeave", () => {
        promptAction.showToast({ message: "on.hotspotStaLeave监听已关闭" })
      })
      message = "关闭注册Wi-Fi 热点 sta离开变化事件"
    } else {
      wifiManager.on("hotspotStaLeave", (data) => {
        let hotspotStaLeaveManagerMessage = "name:" + data.name + ";macAddress:" + data.macAddress + ";ipAddress:" + data.ipAddress
        message = "状态为: " + JSON.stringify(data)
        AppStorage.setOrCreate("hotspotStaLeaveManagerMessage", message)
        promptAction.showToast({ message: hotspotStaLeaveManagerMessage })
      })
      message = "打开注册Wi-Fi 热点 sta离开变化"
      promptAction.showToast({ message : message })
    }
    hotspotStaLeaveManager = !hotspotStaLeaveManager
    return message
  } catch( err) {
    console.log(TAG, `Failed to testOnHotspotStaLeaveManager. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testOnHotspotStaLeaveManager. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({ message: message })
    return message
  }
}

async function sleep(time: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    setTimeout(() => {
      resolve();
    }, time * 1000);
  });
}