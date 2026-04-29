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
import wifiManager from '@ohos.wifiManager';
import LogDataManager from '../../Utils/LogDataManager';
import MessageDataManager from '../../Utils/MessageDataManager';
import { BusinessError} from '@ohos.base';

const TAG = "wifiTestApp [wifiManagerInterface]";

interface WifiDeviceConfigManager {
  ssid: string,
  bssid: string,
  preSharedKey: string,
  isHiddenSsid: boolean,
  securityType: wifiManager.WifiSecurityType,
  creatorUid: number,
  disableReason: number,
  netId: number,
  randomMacType: number,
  randomMacAddr: string,
  ipType: wifiManager.IpType,
  staticIp: wifiManager.IpConfig
}

/**
 * WifiManager api Test Page Of wifi test
 */
const PAGE_URI_WIFI_FOUND_MODE = 'pages/subManualApiTest/subWifiTest/wifiFound';
let wifiManagerEnable = false

export function testEnableWifiManager() {
  try {
    let message = (MessageDataManager.testEnableWifi);
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testEnableWifiManager_StartLog)
    if (wifiManagerEnable){
      message = (MessageDataManager.testIsActive)
    } else {
      let ret = wifiManager.enableWifi();
      //enableWifi返回值为void,无法判断
      message = (MessageDataManager.testWifiEnableMaybe)
      wifiManagerEnable = true;
      AppStorage.setOrCreate('wifiManagerIsOn', wifiManagerEnable);
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testEnableWifiManager_EndLog)
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testEnableWifiManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testEnableWifiManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testDisableWifiManager() {
  try {
    let message = (MessageDataManager.testDisableWifi);
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testDisableWifiManager_StartLog)
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive)
    } else {
      let ret = wifiManager.disableWifi();
      //disableWifi返回值为void,无法判断
      message = (MessageDataManager.testWifiDisableMaybe)
      wifiManagerEnable = false;
      AppStorage.setOrCreate('wifiManagerIsOn', wifiManagerEnable);
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testDisableWifiManager_EndLog)
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testDisableWifiManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testDisableWifiManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testEnableSemiWifiManager() {
  try {
    let message = (MessageDataManager.testEnableSemiWifi);
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testEnableSemiWifi_StartLog)
    if (wifiManagerEnable){
      message = (MessageDataManager.testIsActive)
    } else {
      let ret = wifiManager.enableSemiWifi();
      //enableSemiWifi返回值为void,无法判断
      message = (MessageDataManager.testWifiEnableMaybe)
      wifiManagerEnable = true;
      AppStorage.setOrCreate('semiWifiManagerIsOn', wifiManagerEnable);
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testEnableSemiWifi_EndLog)
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testEnableWifiManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testEnableWifiManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testIsWifiActiveManager() {
  try {
    let message = (MessageDataManager.testIsActive);
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testIsWifiActiveManager_StartLog)
    let ret = wifiManager.isWifiActive();
    if (ret){
      wifiManagerEnable = true
    } else {
      wifiManagerEnable = false
    }
    message = (MessageDataManager.testIsActiveResult) + ret
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testIsWifiActiveManager_EndLog)
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testIsWifiActiveManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testIsWifiActiveManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testScanManager() {
  try {
    let message = (MessageDataManager.testScan)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testScanManager_StartLog)
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive)
    } else {
      let ret = wifiManager.scan()
      //scan返回值为void
      message = "scan 调用成功"
      router.pushUrl({url: PAGE_URI_WIFI_FOUND_MODE});
      promptAction.showToast({message: message})
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testScanManager_EndLog)
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testScanManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testScanManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testStartScanManager() {
  try {
    let message = (MessageDataManager.testStartScan)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testStartScanManager_StartLog)
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive)
    } else {
      let ret = wifiManager.startScan()
      //scan返回值为void
      message = "startScan 调用成功"
      router.pushUrl({url: PAGE_URI_WIFI_FOUND_MODE});
      promptAction.showToast({message: message})
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testStartScanManager_EndLog)
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testScanManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testScanManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetScanInfoListManager() {
  try {
    let message = (MessageDataManager.testGetScanInfoList)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetScanInfoListManager_StartLog);
    let ret = wifiManager.getScanInfoList()
    message = "扫描结果为：" + JSON.stringify(ret)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "扫描结果为：" + JSON.stringify(ret));
    let getScanInfoManagerMessage = JSON.stringify(ret)
    AppStorage.setOrCreate("getScanInfoManagerMessage", getScanInfoManagerMessage)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetScanInfoListManager_EndLog);
    promptAction.showToast({message: message})
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetScanInfoListManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetScanInfoListManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetScanResultsPromise() {
  try {
    let message = (MessageDataManager.testAddCandidateConfigPromise)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigPromiseManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive)
    } else {
      wifiManager.getScanResults().then(result => {
        //  @returns Returns {@code true} if the Candidate hotspot configuration is added, returns {@code false} otherwise.
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigPromiseManager_successfulLog)
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigManagerLog + JSON.stringify(result))
        message = (MessageDataManager.testAddCandidateConfig + JSON.stringify(result))
        promptAction.showToast({message: message})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigPromiseManager_EndLog)
      }).catch((err: BusinessError) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "testAddCandidateConfigManagerPromise err:" + JSON.stringify(err))
      })
    }
    promptAction.showToast({message: message})
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testAddCandidateConfigManagerPromise. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testAddCandidateConfigManagerPromise. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetScanResultsCallback() {
  try {
    let message = (MessageDataManager.testAddCandidateConfigCallback)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigCallbackManager_StartLog)
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive)
    } else {
      wifiManager.getScanResults((err, result) => {
        //  @returns Returns {@code true} if the Candidate hotspot configuration is added, returns {@code false} otherwise.
        if (err){
          hilog.error(0x1500, 'wifiTestApp', '%{public}s', "addCandidateConfigCallback error");
          return;
        }
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigCallbackManager_successfulLog)
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigManagerLog + JSON.stringify(result))
        message = (MessageDataManager.testAddCandidateConfig + JSON.stringify(result))
        promptAction.showToast({message: message})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigCallbackManager_EndLog)
      })
    }
    promptAction.showToast({message: message})
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testAddCandidateConfigManagerCallback. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testAddCandidateConfigManagerCallback. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetScanResultsSync() {
  try {
    let message = (MessageDataManager.testGetScanInfoList)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetScanInfoListManager_StartLog);
    let ret = wifiManager.getScanResultsSync()
    message = "扫描结果为：" + JSON.stringify(ret)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "扫描结果为：" + JSON.stringify(ret));
    let getScanInfoManagerMessage = JSON.stringify(ret)
    AppStorage.setOrCreate("getScanInfoManagerMessage", getScanInfoManagerMessage)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetScanInfoListManager_EndLog);
    promptAction.showToast({message: message})
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetScanInfoListManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetScanInfoListManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetWifiDetailState() {
  try {
    let message = (MessageDataManager.testGetScanInfoList)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetScanInfoListManager_StartLog);
    let ret = wifiManager.getWifiDetailState()
    let wifiDetailStateMessage = ''
    switch (ret){
      case - 1: wifiDetailStateMessage = "UNKNOWN";
        break;
      case 0: wifiDetailStateMessage = "INACTIVE";
        break;
      case 1: wifiDetailStateMessage = "ACTIVATED";
        break;
      case 2: wifiDetailStateMessage = "ACTIVATING";
        break;
      case 3: wifiDetailStateMessage = "DEACTIVATING";
        break;
      case 4: wifiDetailStateMessage = "SEMI_ACTIVATING";
        break;
      case 5: wifiDetailStateMessage = "SEMI_ACTIVE";
        break;
      default: wifiDetailStateMessage = '未知状态';
        break;
    }
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "状态为：" + JSON.stringify(ret));
    message = "状态为：" + wifiDetailStateMessage
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetScanInfoListManager_EndLog);
    promptAction.showToast({message: message})
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetScanInfoListManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetScanInfoListManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testSetScanAlwaysAllowed() {
  try {
    let isAllowed: number = AppStorage.get("isAllowed")!
    let message = ''
    let scanAllowed: boolean = true
    if (isAllowed == 0){
      scanAllowed = false
    } else {
      scanAllowed = true
    }
    wifiManager.setScanAlwaysAllowed(scanAllowed)
    message = "setScanAlwaysAllowed"
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', "setScanAlwaysAllowed")
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', `Failed to testGetProfileConnState1. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetProfileConnState1. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetScanAlwaysAllowed() {
  try {
    let message = (MessageDataManager.testGetScanInfoList)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetScanInfoListManager_StartLog);
    let ret: boolean = wifiManager.getScanAlwaysAllowed()
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "获取扫描始终允许标志为：" + JSON.stringify(ret));
    message = "获取扫描始终允许标志为：" + ret
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetScanInfoListManager_EndLog);
    promptAction.showToast({message: message})
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetScanInfoListManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetScanInfoListManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testAddDeviceConfigManagerPromise() {
  try {
    let message = (MessageDataManager.testAddDeviceConfigPromise)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddDeviceConfigPromiseManager_StartLog)
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let wifiDeviceConfigManager: WifiDeviceConfigManager = AppStorage.get("wifiDeviceConfigManager")!//非空断言操作符
      wifiManager.addDeviceConfig(wifiDeviceConfigManager).then(result => {
        //  @returns Returns {@code networkId} if the configuration is added; returns {@code - 1} otherwise.
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddDeviceConfigPromiseManager_successfulLog)
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddDeviceConfigManagerLog + result)
        message = (MessageDataManager.testAddDeviceConfig) + result
        promptAction.showToast({message: message})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddDeviceConfigPromiseManager_EndLog)
      }).catch((err: BusinessError) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "testAddDeviceConfigManagerPromise error:" + JSON.stringify(err))
      })
    }
    promptAction.showToast({message: message})
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testAddDeviceConfigManagerPromise. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testAddDeviceConfigManagerPromise. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testAddDeviceConfigManagerCallback() {
  try {
    let message = (MessageDataManager.testAddDeviceConfigCallback)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddDeviceConfigCallbackManager_StartLog)
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive)
    } else {
      let wifiDeviceConfigManager: WifiDeviceConfigManager = AppStorage.get("wifiDeviceConfigManager")!//非空断言操作符
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "testAddDeviceConfigManagerCallback wifiDeviceConfigManager:" + JSON.stringify(wifiDeviceConfigManager))
      wifiManager.addDeviceConfig(wifiDeviceConfigManager, (err, result) => {
        //  @returns Returns {@code networkId} if the configuration is added; returns {@code - 1} otherwise.
        if (err){
          hilog.error(0x1500, 'wifiTestApp', '%{public}s', "addDeviceConfigCallback error:" + err);
          return;
        }
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddDeviceConfigCallbackManager_successfulLog)
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddDeviceConfigManagerLog + result)
        message = (MessageDataManager.testAddDeviceConfig) + result
        promptAction.showToast({message: message})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddDeviceConfigCallbackManager_EndLog)
      });
    }
    promptAction.showToast({message: message})
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testAddDeviceConfigManagerCallback. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testAddDeviceConfigManagerCallback. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testAddCandidateConfigManagerPromise() {
  try {
    let message = (MessageDataManager.testAddCandidateConfigPromise)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigPromiseManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive)
    } else {
      let wifiDeviceConfigManager: WifiDeviceConfigManager = AppStorage.get("wifiDeviceConfigManager")!//非空断言操作符
      wifiManager.addCandidateConfig(wifiDeviceConfigManager).then(result => {
        //  @returns Returns {@code true} if the Candidate hotspot configuration is added, returns {@code false} otherwise.
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigPromiseManager_successfulLog)
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigManagerLog + result)
        message = (MessageDataManager.testAddCandidateConfig + result)
        promptAction.showToast({message: message})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigPromiseManager_EndLog)
      }).catch((err: BusinessError) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "testAddCandidateConfigManagerPromise err:" + JSON.stringify(err))
      })
    }
    promptAction.showToast({message: message})
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testAddCandidateConfigManagerPromise. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testAddCandidateConfigManagerPromise. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testAddCandidateConfigManagerCallback() {
  try {
    let message = (MessageDataManager.testAddCandidateConfigCallback)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigCallbackManager_StartLog)
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive)
    } else {
      let wifiDeviceConfigManager: WifiDeviceConfigManager = AppStorage.get("wifiDeviceConfigManager")!//非空断言操作符
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "testAddCandidateConfigManagerCallback wifiDeviceConfigManager:" + JSON.stringify(wifiDeviceConfigManager))
      wifiManager.addCandidateConfig(wifiDeviceConfigManager, (err, result) => {
        //  @returns Returns {@code true} if the Candidate hotspot configuration is added, returns {@code false} otherwise.
        if (err){
          hilog.error(0x1500, 'wifiTestApp', '%{public}s', "addCandidateConfigCallback error");
          return;
        }
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigCallbackManager_successfulLog)
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigManagerLog + result)
        message = (MessageDataManager.testAddCandidateConfig + result)
        promptAction.showToast({message: message})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testAddCandidateConfigCallbackManager_EndLog)
      })
    }
    promptAction.showToast({message: message})
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testAddCandidateConfigManagerCallback. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testAddCandidateConfigManagerCallback. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testRemoveCandidateConfigManagerPromise() {
  try {
    let message = (MessageDataManager.testRemoveCandidateConfigPromise)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveCandidateConfigPromiseManager_StartLog)
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let networkId: number = AppStorage.get("w_networkIdM")!//非空断言操作符
      wifiManager.removeCandidateConfig(networkId).then(result => {
        //  @returns Returns {@code true} if the Candidate hotspot configuration is removed, returns {@code false} otherwise.
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveCandidateConfigPromiseManager_successfulLog)
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveCandidateConfigManagerLog + result)
        message = MessageDataManager.testRemoveCandidateConfig + result
        promptAction.showToast({message: message})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveCandidateConfigPromiseManager_EndLog)
      }).catch((err: BusinessError) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "testRemoveCandidateConfigManagerPromise err:" + JSON.stringify(err))
      })
    }
    promptAction.showToast({message: message})
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testRemoveCandidateConfigManagerPromise. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testRemoveCandidateConfigManagerPromise. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testRemoveCandidateConfigManagerCallback() {
  try {
    let message = (MessageDataManager.testRemoveCandidateConfigCallback)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveCandidateConfigCallbackManager_StartLog)
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let networkId: number = AppStorage.get("w_networkIdM")!//非空断言操作符
      wifiManager.removeCandidateConfig(networkId, (err, result) => {
        //  @returns Returns {@code true} if the Candidate hotspot configuration is removed, returns {@code false} otherwise.
        if (err){
          hilog.error(0x1500, 'wifiTestApp', '%{public}s', "removeCandidateConfigCallback error");
          return;
        }
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveCandidateConfigCallbackManager_successfulLog)
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveCandidateConfigManagerLog + result)
        message = (MessageDataManager.testRemoveCandidateConfig + result)
        promptAction.showToast({message: message})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveCandidateConfigCallbackManager_EndLog)
      })
    }
    promptAction.showToast({message: message})
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testRemoveCandidateConfigManagerCallback. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testRemoveCandidateConfigManagerCallback. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetCandidateConfigsManager() {
  try {
    let message = (MessageDataManager.testGetCandidateConfigs)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetCandidateConfigsManager_StartLog)
    let ret = wifiManager.getCandidateConfigs()
    message = "候选配置：" + JSON.stringify(ret)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "候选配置：" + JSON.stringify(ret));
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetCandidateConfigsManager_EndLog)
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetCandidateConfigsManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetCandidateConfigsManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testConnectToCandidateConfigManager() {
  try {
    let message = (MessageDataManager.testConnectToCandidateConfig)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testConnectToCandidateConfigManager_StartLog)
    let networkId: number = AppStorage.get("w_networkIdM")!//非空断言操作符
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let ret = wifiManager.connectToCandidateConfig(networkId)
      //      connectToCandidateConfig的返回值为void，无法判断
      message = "connectToCandidateConfig 调用成功"
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "connectToCandidateConfig 调用成功")
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testConnectToCandidateConfigManager_EndLog)
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testConnectToCandidateConfigManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testConnectToCandidateConfigManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testConnectToNetworkManager() {
  try {
    let message = (MessageDataManager.testConnectToNetwork)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testConnectToNetworkManager_StartLog)
    let networkId: number = AppStorage.get("w_networkIdM")!//非空断言操作符
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let ret = wifiManager.connectToNetwork(networkId)
      //      connectToNetwork的返回值为void，无法判断
      message = "ConnectToNetwork 调用成功"
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "connectToCandidateConfig 调用成功")
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testConnectToNetworkManager_EndLog)
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testConnectToNetworkManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testConnectToNetworkManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testConnectToDeviceManager() {
  try {
    let message = (MessageDataManager.testConnectToDevice)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testConnectToDeviceManager_StartLog)
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let wifiDeviceConfigManager: WifiDeviceConfigManager = AppStorage.get("wifiDeviceConfigManager")!//非空断言操作符
      let ret = wifiManager.connectToDevice(wifiDeviceConfigManager)
      //      connectToDevice的返回值为void，无法判断
      message = "connectToDevice 调用成功"
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "connectToDevice 调用成功")
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testConnectToDeviceManager_EndLog)
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testConnectToDeviceManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testConnectToDeviceManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testDisconnectManager() {
  try {
    let message = (MessageDataManager.testDisconnect)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testDisconnectManager_StartLog)
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let ret = wifiManager.disconnect()
      //      disconnect的返回值为void
      message = "disconnect 调用成功"
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "disconnect 调用成功")
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testDisconnectManager_EndLog)
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testDisconnectManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testDisconnectManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetSignalLevelManager() {
  try {
    let message = (MessageDataManager.testGetSignalLevel)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetSignalLevelManager_StartLog)
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive)
    } else {
      let rssi: number = AppStorage.get("w_rssi1")!//非空断言操作符
      let band: number = AppStorage.get("w_band1")!//非空断言操作符
      let number = wifiManager.getSignalLevel(rssi, band)
      message = "getSignalLevel is: " + number
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "getSignalLevel is: " + number)
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetSignalLevelManager_EndLog)
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetSignalLevelManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetSignalLevelManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetLinkedInfoManagerPromise() {
  try {
    let message = (MessageDataManager.testGetLinkedInfoPromise)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetLinkedInfoPromiseManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive)
    } else {
      wifiManager.getLinkedInfo().then(data => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetLinkedInfoPromiseManager_successfulLog)
        message = "get wifi linked info: " + JSON.stringify(data)
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "get wifi linked info: " + JSON.stringify(data));
        promptAction.showToast({message: message})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetLinkedInfoPromiseManager_EndLog);
      }).catch((err: BusinessError) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "get linked info error:" + JSON.stringify(err));
      });
    }
    promptAction.showToast({message: message})
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetLinkedInfoManagerPromise. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetLinkedInfoManagerPromise. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetLinkedInfoManagerCallback() {
  try {
    let message = (MessageDataManager.testGetLinkedInfoCallback)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetLinkedInfoCallbackManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive)
    } else {
      wifiManager.getLinkedInfo((err, data) => {
        if (err){
          hilog.error(0x1500, 'wifiTestApp', '%{public}s', "get linked info error");
          message = "get linked info error"
          promptAction.showToast({message: message})
        }
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetLinkedInfoCallbackManager_successfulLog)
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "get wifi linked info: " + JSON.stringify(data));
        message = "get wifi linked info: " + JSON.stringify(data)
        let linkedInfoManagerMessage = JSON.stringify(data)
        AppStorage.setOrCreate("linkedInfoManagerMessage", linkedInfoManagerMessage)
        let ssid = data.ssid
        AppStorage.setOrCreate("pairedSsidM", ssid)
        let rssi = data.rssi
        let band = data.band
        let networkId = data.networkId
        AppStorage.setOrCreate("w_rssi1", rssi)
        AppStorage.setOrCreate("w_band1", band)
        AppStorage.setOrCreate("w_networkIdM", networkId)
        promptAction.showToast({message: message})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetLinkedInfoCallbackManager_EndLog);
      });
    }
    promptAction.showToast({message: message})
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetLinkedInfoManagerCallback. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetLinkedInfoManagerCallback. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testIsConnectedManager() {
  try {
    let message = (MessageDataManager.testIsConnected)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testIsConnectedManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let ret = wifiManager.isConnected()
      message = "isConnected: " + ret
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testIsConnectedManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testIsConnectedManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testIsConnectedManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetSupportedFeaturesManager() {
  try {
    let message = (MessageDataManager.testGetSupportedFeatures)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetSupportedFeaturesManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let ret = wifiManager.getSupportedFeatures()
      message = "GetSupportedFeatures: " + ret
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetSupportedFeaturesManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetSupportedFeaturesManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetSupportedFeaturesManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testIsFeatureSupportedManager() {
  try {
    let message = (MessageDataManager.testIsFeatureSupported)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testIsFeatureSupportedManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive)
    } else {
      let featureId: number = AppStorage.get("w_featureIdM")!//非空断言操作符
      let ret = wifiManager.isFeatureSupported(featureId)
      message = "isFeatureSupported: " + ret
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetSupportedFeaturesManager_EndLog)
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testIsFeatureSupportedManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testIsFeatureSupportedManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetDeviceMacAddressManager() {
  try {
    let message = (MessageDataManager.testGetDeviceMacAddress)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetDeviceMacAddressManager_StartLog)
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let macAddress = wifiManager.getDeviceMacAddress()
      message = "macAddress: " + macAddress
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetDeviceMacAddressManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetDeviceMacAddressManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetDeviceMacAddressManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetIpInfoManager() {
  try {
    let message = (MessageDataManager.testGetIpInfo)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetIpInfoManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let IpInfo = wifiManager.getIpInfo()
      message = "IpInfo: " + JSON.stringify(IpInfo)
      let ipInfoManagerMessage = IpInfo
      AppStorage.setOrCreate("ipInfoManagerMessage", ipInfoManagerMessage)
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetIpInfoManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetIpInfoManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetIpInfoManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetIpv6Info() {
  try {
    let message = (MessageDataManager.testGetCountryCode)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetCountryCodeManager_StartLog);
    let ret: wifiManager.Ipv6Info = wifiManager.getIpv6Info()
    message = "Ipv6Info: " + ret
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetCountryCodeManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetCountryCodeManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetCountryCodeManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetCountryCodeManager() {
  try {
    let message = (MessageDataManager.testGetCountryCode)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetCountryCodeManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive)
    } else {
      let ret = wifiManager.getCountryCode()
      message = "CountryCode is: " + ret
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetCountryCodeManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetCountryCodeManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetCountryCodeManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testReassociateManager() {
  try {
    let message = (MessageDataManager.testReassociate)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testReassociateManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let ret = wifiManager.reassociate()
      //      reassociate的返回值为void
      //      message = "reassociate is: " + ret
      message = "reassociate 调用成功"
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testReassociateManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testReassociateManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testReassociateManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testReconnectManager() {
  try {
    let message = (MessageDataManager.testReConnect)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testReConnectManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive)
    } else {
      let ret = wifiManager.reconnect()
      //      reconnect的返回值为void
      message = "reconnect 调用成功"
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testReConnectManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testReconnectManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testReconnectManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetDeviceConfigsManager() {
  try {
    let message = (MessageDataManager.testGetDeviceConfigs)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetDeviceConfigsManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let array = wifiManager.getDeviceConfigs()
      message = " DeviceConfigs is " + JSON.stringify(array)
      let getDeviceConfigsManagerMessage = JSON.stringify(array)
      AppStorage.setOrCreate("getDeviceConfigsManagerMessage", getDeviceConfigsManagerMessage)
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testGetDeviceConfigsManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetDeviceConfigsManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetDeviceConfigsManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testUpdateDeviceConfigManager() {
  try {
    let message = (MessageDataManager.testUpdateNetwork)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testUpdateNetworkManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let wifiDeviceConfigManager: WifiDeviceConfigManager = AppStorage.get("wifiDeviceConfigManager")!//非空断言操作符
      let ret: number = wifiManager.updateNetwork(wifiDeviceConfigManager)
      message = "updateNetwork: " + ret
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testUpdateNetworkManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testUpdateDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testUpdateDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testDisableDeviceConfigManager() {
  try {
    let message = (MessageDataManager.testDisableNetwork)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testDisableNetworkManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let networkId: number = AppStorage.get("w_networkIdM")!//非空断言操作符
      let ret = wifiManager.disableNetwork(networkId)
      // disableDeviceConfig的返回值为void
      message = "disableNetwork: " + ret
      message = "disableNetwork 调用成功"
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testDisableNetworkManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testDisableDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testDisableDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testRemoveAllDeviceConfigsManager() {
  try {
    let message = (MessageDataManager.testRemoveAllNetwork)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveAllNetworkManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let ret = wifiManager.removeAllNetwork()
      // removeAllDeviceConfigs的返回值为void
      message = "removeAllNetwork: " + ret
      message = "removeAllDeviceConfigs 调用成功"
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveAllNetworkManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testRemoveAllDeviceConfigsManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testRemoveAllDeviceConfigsManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testRemoveDeviceConfigManager() {
  try {
    let message = (MessageDataManager.testRemoveDevice)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveDeviceManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
    } else {
      let networkId: number = AppStorage.get("w_networkIdM")!//非空断言操作符
      let ret = wifiManager.removeDevice(networkId)
      //      removeDeviceConfig的返回值为void
      //      message = "removeDevice " + ret
      message = "removeDeviceConfig 调用成功"
    }
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveDeviceManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testIsBandTypeSupported() {
  try {
  // let bandType:wifiManager.WifiBandType
  // wifiManager.isBandTypeSupported(bandType)
  } catch( e){

  }
}

export function testGet5GChannelList() {
  try {
    let message = ''
    let ret = wifiManager.get5GChannelList()
    message = "get5GChannelList:" + ret
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveDeviceManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetDisconnectedReason() {
  try {
    let message = ''
    let ret = wifiManager.getDisconnectedReason()
    message = "DisconnectedReason:" + ret
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveDeviceManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testStartPortalCertification() {
  try {
    let message = ''
    wifiManager.startPortalCertification()
    message = "startPortalCertification 调用成功"
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveDeviceManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testStartWifiDetection() {
  try {
    let message = ''
    // wifiManager.StartWifiDetection()
    message = "StartWifiDetection 调用成功"
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testRemoveDeviceManager_EndLog);
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

let wifiStateChangeManager = false

export function testOnWifiStateChangeManager() {
  try {
    let message = "onWifiStateChange test"
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testOnWifiStateChangeManager_StartLog);
    if (wifiStateChangeManager){
      wifiManager.off("wifiStateChange", () => {
        promptAction.showToast({message: "on.WifiStateChange监听已关闭"})
      })
      message = "关闭注册WLAN状态改变事件"
    } else {
      wifiManager.on("wifiStateChange", (number) => {
        let wifiStateMessage = ""
        switch (number){
          case 0: wifiStateMessage = "inactive";
            break;
          case 1: wifiStateMessage = "active";
            break;
          case 2: wifiStateMessage = "activating";
            break;
          case 3: wifiStateMessage = "de-activating";
            break;
          default: wifiStateMessage = '未知状态';
            break;
        }
        promptAction.showToast({message: "状态:" + wifiStateMessage})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testOnWifiStateChangeManager_EndLog);
      })
      message = "打开注册WLAN状态变化"
      promptAction.showToast({message: message})
    }
    wifiStateChangeManager = !wifiStateChangeManager
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testOnWifiStateChangeManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testOnWifiStateChangeManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

let wifiConnectionChangeManager = false

export function testOnWifiConnectionChangeManager() {
  try {
    let message = "OnWifiConnectionChange test"
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testOnWifiConnectionChangeManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
      return message
    }
    if (wifiConnectionChangeManager){
      wifiManager.off("wifiConnectionChange", () => {
        promptAction.showToast({message: "on.wifiConnectionChange监听已关闭"})
      })
      message = "关闭WLAN连接状态改变事件"
    } else {
      wifiManager.on("wifiConnectionChange", (number) => {
        let wifiConnectionMessage = ""
        switch (number){
          case 0: wifiConnectionMessage = "disconnected";
            break;
          case 1: wifiConnectionMessage = "connected";
            break;
          default: wifiConnectionMessage = '未知状态';
            break;
        }
        promptAction.showToast({message: "状态: " + wifiConnectionMessage})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testOnWifiConnectionChangeManager_EndLog);
      })
      message = "打开注册WLAN连接状态变化"
      promptAction.showToast({message: message})
    }
    wifiConnectionChangeManager = !wifiConnectionChangeManager
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testOnWifiConnectionChangeManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testOnWifiConnectionChangeManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

let wifiScanStateChangeManager = false

export function testOnWifiScanStateChangeManager() {
  try {
    let message = "OnWifiScanStateChange test"
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testOnWifiScanStateChangeManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
      return message
    }
    if (wifiScanStateChangeManager){
      wifiManager.off("wifiScanStateChange", () => {
        promptAction.showToast({message: "on.wifiScanStateChange监听已关闭"})
      })
      message = "关闭扫描状态改变事件"
    } else {
      wifiManager.on("wifiScanStateChange", (number) => {
        let wifiScanStateMessage = ""
        switch (number){
          case 0: wifiScanStateMessage = "scan fail";
            break;
          case 1: wifiScanStateMessage = "scan success";
            break;
          default: wifiScanStateMessage = '未知状态';
            break;
        }
        promptAction.showToast({message: "状态: " + wifiScanStateMessage})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testOnWifiScanStateChangeManager_EndLog);
      })
      message = "打开注册扫描状态变化"
      promptAction.showToast({message: message})
    }
    wifiScanStateChangeManager = !wifiScanStateChangeManager
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testOnWifiScanStateChangeManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testOnWifiScanStateChangeManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

let wifiRssiChangeManager = false

export function testOnWifiRssiChangeManager() {
  try {
    let message = "OnWifiRssiChange test"
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testOnWifiRssiChangeManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
      return message
    }
    if (wifiRssiChangeManager){
      wifiManager.off("wifiRssiChange", () => {
        promptAction.showToast({message: "on.wifiRssiChange监听已关闭"})
      })
      message = "关闭RSSI状态变化事件"
    } else {
      wifiManager.on("wifiRssiChange", (number) => {
        promptAction.showToast({message: "rssi: " + number})
      })
      message = "打开注册RSSI状态变化"
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testOnWifiRssiChangeManager_EndLog);
      promptAction.showToast({message: message})
    }
    wifiRssiChangeManager = !wifiRssiChangeManager
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testOnWifiRssiChangeManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testOnWifiRssiChangeManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

let streamChangeManager = false

export function testOnStreamChangeManager() {
  try {
    let message = "onStreamChange test"
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testOnStreamChangeManager_StartLog);
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
      return message
    }
    if (streamChangeManager){
      wifiManager.off("streamChange", () => {
        promptAction.showToast({message: "on.streamChange监听已关闭"})
      })
      message = "关闭注册流改变事件"
    } else {
      wifiManager.on("streamChange", (number) => {
        let streamChangeMessage = ""
        switch (number){
          case 0: streamChangeMessage = "stream none";
            break;
          case 1: streamChangeMessage = "stream down";
            break;
          case 2: streamChangeMessage = "stream up";
            break;
          case 3: streamChangeMessage = "stream bidirectional";
            break;
          default: streamChangeMessage = '未知状态';
            break;
        }
        promptAction.showToast({message: "状态:" + streamChangeMessage})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testOnStreamChangeManager_EndLog);
      })
      message = "打开注册流变化"
      promptAction.showToast({message: message})
    }
    streamChangeManager = !streamChangeManager
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testOnStreamChangeManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testOnStreamChangeManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

export function testGetLinkedInfoSyncManager() {
  try {
    let message = ''
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "testGetLinkedInfoSyncManager_StartLog")
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
      return message
    }
    let linkedInfo = wifiManager.getLinkedInfoSync();
    message = "同步获取连接信息成功: " + JSON.stringify(linkedInfo)
    AppStorage.setOrCreate('linkedInfoSyncManagerMessage', JSON.stringify(linkedInfo));
    promptAction.showToast({message: message})
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "testGetLinkedInfoSyncManager_EndLog")
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testGetLinkedInfoSyncManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testGetLinkedInfoSyncManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}

let deviceConfigChange = false

export function testOnDeviceConfigChangeManager() {
  try {
    let message = "OnDeviceConfigChange test"
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testOnDeviceConfigChangeManager_StartLog);
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "testOnDeviceConfigChange test");
    if (!wifiManagerEnable){
      message = (MessageDataManager.testIsInactive);
      return message
    }
    if (deviceConfigChange){
      wifiManager.off("deviceConfigChange", () => {
        promptAction.showToast({message: "on.deviceConfigChange监听已关闭"})
      })
      message = "关闭注册设备配置改变事件"
    } else {
      wifiManager.on("deviceConfigChange", (number) => {
        let deviceConfigMessage = ""
        switch (number){
          case 0: deviceConfigMessage = "config is added";
            break;
          case 1: deviceConfigMessage = "config is changed";
            break;
          case 2: deviceConfigMessage = "config is removed";
            break;
          default: deviceConfigMessage = '未知状态';
            break;
        }
        promptAction.showToast({message: "状态:" + deviceConfigMessage})
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, LogDataManager.testOnDeviceConfigChangeManager_EndLog);
      })
      message = "打开注册设备配置变化"
      promptAction.showToast({message: message})
    }
    deviceConfigChange = !deviceConfigChange
    return message
  } catch( e){
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to testOnDeviceConfigChangeManager. message: ${ e.message }, code: ${ e.code }`)
    let message = `Failed to testOnDeviceConfigChangeManager. message: ${ e.message }, code: ${ e.code }`
    promptAction.showToast({message: message})
    return message
  }
}