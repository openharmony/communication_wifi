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

import hilog from '@ohos.hilog';
import promptAction from '@ohos.promptAction';
import router from '@ohos.router';
import wifi from '@ohos.wifi';
import ConfigData from "../../Utils/ConfigData";
import LogData from "../../Utils/LogData";
import MessageData from "../../Utils/MessageData";

const TAG = "wifiTestApp [hotspotInterface]"
/**
 * hotspot Test Page Of Wifi test
 */

let hotspotEnable = false

export function testEnableHotspot(): string {
  try {
    let message = (MessageData.testEnableHotspot)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testEnableHotspot_StartLog)
    if (hotspotEnable){
      message = (MessageData.hotspot_enable)
    } else {
      let ret = wifi.enableHotspot()
      if (ret){
        message = "热点使能执行结果：" + ret;
      } else {
        message = "使能结果：" + ret + "\n"
        message += "热点已打开或打开失败,请确认"
      }
      hotspotEnable = true
      AppStorage.setOrCreate('hotspotIsOn', hotspotEnable);
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testEnableHotspot_EndLog)
    return message
  } catch( err){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testEnableHotspot. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testEnableHotspot. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testDisableHotspot(): string {
  try {
    let message = (MessageData.testDisableHotspot)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testDisableHotspot_StartLog)
    if (!hotspotEnable){
      message = (MessageData.hotspot_disEnable)
    } else {
      let ret = wifi.disableHotspot();
      if (ret){
        message = "热点去使能执行结果：" + ret;
      } else {
        message = "去使能结果：" + ret + "\n"
        message += "热点已关闭或关闭失败,请确认"
      }
      hotspotEnable = false;
      AppStorage.setOrCreate('hotspotIsOn', hotspotEnable);
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testDisableHotspot_EndLog)
    return message
  } catch( err){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testDisableHotspot. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testDisableHotspot. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testIsHotspotDualBandSupported(): string {
  try {
    let message = (MessageData.testIsHotspotDualBandSupported)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testIsHotspotDualBandSupported_StartLog)
    let ret = wifi.isHotspotDualBandSupported()
    message = "热点支持双频结果：" + ret
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testIsHotspotDualBandSupported_EndLog)
    return message
  } catch( err){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testIsHotspotDualBandSupported. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testIsHotspotDualBandSupported. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testIsHostActive(): string {
  try {
    let message = (MessageData.testIsHotspotActive)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testIsHostActive_StartLog)
    let ret = wifi.isHotspotActive()
    if (ret){
      hotspotEnable = true
    } else {
      hotspotEnable = false
    }
    message = "热点使能结果为：" + ret
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testIsHostActive_EndLog)
    return message
  } catch( err){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testIsHostActive. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testIsHostActive. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testSetHotspotConfig(): string {
  try {
    let message = (MessageData.testSetHotspotConfig)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testSetHotspotConfig_StartLog)
    let ssid = "abc"
    let securityType = 3
    let band = 2;
    let preSharedKey = ConfigData.QV_MOCK_PRE_SHARED_KEY
    let maxConn = 3
    let channel = 36
    // TODO: 设备调试时候需要打开
    ssid = AppStorage.get("h_ssid") !//非空断言操作符
    //    let securityType=AppStorage.get("h_securityType")
    //    let band = AppStorage.get("h_band")
    preSharedKey = AppStorage.get("h_preSharedKey") !//非空断言操作符
    //    let maxConn = AppStorage.get("h_maxConn")
    //    let channel = AppStorage.get("h_channel")
    let hotspotConfigs: wifi.HotspotConfig = {
      ssid: ssid,
      securityType: securityType,
      band: band,
      preSharedKey: preSharedKey,
      maxConn: maxConn,
    }
    let ret = wifi.setHotspotConfig(hotspotConfigs)
    message = "SetHotspotConfig: " + ret
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testSetHotspotConfig_EndLog)
    return message
  } catch( err){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testSetHotspotConfig. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testSetHotspotConfig. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetHotspotConfig(): string {
  try {
    let message = (MessageData.testGetHotspotConfig)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testGetHotspotConfig_StartLog)
    let ret = wifi.getHotspotConfig()
    message = "HotspotConfig: " + JSON.stringify(ret)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "HotspotConfig is: " + JSON.stringify(ret))
    let hotspotSsid = ret.ssid
    AppStorage.setOrCreate("hotspotSsid", hotspotSsid)
    let getHotspotConfigMessage = JSON.stringify(ret)
    AppStorage.setOrCreate("getHotspotConfigMessage", getHotspotConfigMessage)
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testGetHotspotConfig_EndLog)
    return message
  } catch( err){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetHotspotConfig. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testGetHotspotConfig. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetStations(): string {
  try {
    let message = (MessageData.testGetStations)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testGetStations_StartLog)
    let ret = wifi.getStations()
    message = "GetStations is: " + JSON.stringify(ret)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "GetStations is: " + JSON.stringify(ret))
    let getStationsMessage = JSON.stringify(ret)
    AppStorage.setOrCreate("getStationsMessage", getStationsMessage)
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testGetStations_EndLog)
    return message
  } catch( err){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetStations. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testGetStations. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({message: message})
    return message
  }
}

let hotspotStateChange = false

export function testOnHotspotStateChange(): string {
  try {
    let message = (MessageData.testOnHotspotStateChange)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "testOnHotspotStateChange test");
    if (hotspotStateChange){
      wifi.off("hotspotStateChange", () => {
        promptAction.showToast({message: (MessageData.offHotspotStateChange)})
      })
      message = MessageData.offHotspotStateChangeTest
    } else {
      wifi.on("hotspotStateChange", (number) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testOnHotspotStateChange_StartLog);
        let hotspotStateMessage = ""
        switch (number){
          case 0: hotspotStateMessage = "inactive";
            break;
          case 1: hotspotStateMessage = "active";
            break;
          case 2: hotspotStateMessage = "activating";
            break;
          case 3: hotspotStateMessage = "de-activating";
            break;
          default: hotspotStateMessage = '未知状态';
            break;
        }
        promptAction.showToast({message: "状态为: " + hotspotStateMessage})
        AppStorage.setOrCreate("hotspotStateMessage", hotspotStateMessage)
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testOnHotspotStateChange_EndLog);
      })
      message = (MessageData.onHotspotStateChangeTest)
      promptAction.showToast({message: message})
    }
    hotspotStateChange = !hotspotStateChange
    return message
  } catch( err){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testOnHotspotStateChange. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testOnHotspotStateChange. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({message: message})
    return message
  }
}

let hotspotStaJoin = false

export function testOnHotspotStaJoin() {
  try {
    let message = (MessageData.testOnHotspotStaJoin)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, " testOnHotspotStaJoin test ")
    if (hotspotStaJoin){
      wifi.off("hotspotStaJoin", () => {
        promptAction.showToast({message: MessageData.offHotspotStaJoin})
      })
      message = (MessageData.offHotspotStaJoinTest)
    } else {
      wifi.on("hotspotStaJoin", (data) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testOnHotspotStaJoin_StartLog);
        let hotspotStaJoinMessage = "name:" + data.name + ";macAddress:" + data.macAddress + ";ipAddress:" + data.ipAddress
        message = "状态为: " + JSON.stringify(data)
        AppStorage.setOrCreate("hotspotStaJoinMessage", message)
        promptAction.showToast({message: hotspotStaJoinMessage})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testOnHotspotStaJoin_EndLog);
      })
      message = (MessageData.onHotspotStaJoinTest)
      promptAction.showToast({message: message})
    }
    hotspotStaJoin = !hotspotStaJoin
    return message
  } catch( err){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testOnHotspotStaJoin. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testOnHotspotStaJoin. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({message: message})
    return message
  }
}

let hotspotStaLeave = false

export function testOnHotspotStaLeave() {
  try {
    let message = (MessageData.testOnHotspotStaLeave)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, " testOnHotspotStaLeave test ")
    if (hotspotStaLeave){
      wifi.off("hotspotStaLeave", () => {
        promptAction.showToast({message: MessageData.offHotspotStaLeave})
      })
      message = (MessageData.offHotspotStaLeaveTest)
    } else {
      wifi.on("hotspotStaLeave", (data) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testOnHotspotStaLeave_StartLog);
        let hotspotStaLeaveMessage = "name:" + data.name + ";macAddress:" + data.macAddress + ";ipAddress:" + data.ipAddress
        message = "状态为: " + JSON.stringify(data)
        AppStorage.setOrCreate("hotspotStaLeaveMessage", message)
        promptAction.showToast({message: hotspotStaLeaveMessage})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogData.testOnHotspotStaLeave_EndLog);
      })
      message = (MessageData.onHotspotStaLeaveTest)
      promptAction.showToast({message: message})
    }
    hotspotStaLeave = !hotspotStaLeave
    return message
  } catch( err){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testOnHotspotStaLeave. message: ${ err.message }, code: ${ err.code }`)
    let message = `Failed to testOnHotspotStaLeave. message: ${ err.message }, code: ${ err.code }`
    promptAction.showToast({message: message})
    return message
  }
}

