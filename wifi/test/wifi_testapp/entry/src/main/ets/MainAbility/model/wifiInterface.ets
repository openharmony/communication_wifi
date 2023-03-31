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

// @ts-nocheck

/**
 *Wifi api Test Page Of wifi test
 */

import prompt from '@system.prompt';
import Router from '@system.router';
import wifi from '@ohos.wifi';

const PAGE_URI_WIFI_FOUND_MODE = '../subManualApiTest/subWifiTest/wifiFound';

let wifiEnable = false
export function testEnableWifi(): string {
  let message = ($r('app.string.testEnableWifi'));
  if (wifiEnable) {
    message = ($r('app.string.wifi_enable'));
  } else {
    let ret = wifi.enableWifi();
    if (ret) {
      message ="WiFi使能执行结果：" + ret
    } else {
      message ="使能结果：" + ret + "\n"
      message +="WiFi已打开或打开失败,请确认"
    }
    wifiEnable = true;
    AppStorage.SetOrCreate('wifiIsOn', wifiEnable);
  }
  prompt.showToast({ message: message })
  return message
}

export function testDisableWifi(): string {
  let message = ($r('app.string.testDisableWifi'));
  if (!wifiEnable) {
    message =  ($r('app.string.wifi_disEnable'));
  } else {
    let ret = wifi.disableWifi();
    if (ret) {
      message ="WiFi去使能执行结果："+ ret
    } else {
      message = "去使能结果："+ ret + "\n"
      message += "WiFi已关闭或关闭失败,请确认"
    }
    wifiEnable = false;
    AppStorage.SetOrCreate('wifiIsOn', wifiEnable);
  }
  prompt.showToast({ message: message })
  return message
}

export function testIsWifiActive(): string {
  let message = ($r('app.string.testIsWifiActive'));
//  if (!wifiEnable) {
//    message = 'WIFI还未使能';
//  } else {
  let ret = wifi.isWifiActive();
  if(ret){
    wifiEnable =true
  }else{
    wifiEnable =false
  }
  message = "wifi使能结果为："+ ret
//  }
  prompt.showToast({ message: message })
  return message
}

export function testScan(): string {
  let message = ($r('app.string.testScan'))
  if (!wifiEnable) {
    message = ($r('app.string.wifi_disEnable'));
  } else {
    let ret = wifi.scan()
    message = "scan: " + ret
    //    Router.push({ uri: PAGE_URI_WIFI_FOUND_MODE });
    prompt.showToast({ message: message })
  }
  prompt.showToast({ message: message })
  return message
}

export function testGetScanInfosPromise(): string {
  let message = ($r('app.string.testGetScanInfosPromise'))
  if (!wifiEnable) {
    message = ($r('app.string.wifi_disEnable'));
  } else {
    wifi.getScanInfos().then(result => {
      let len = Object.keys(result).length;
      console.log("wifi received scan info: -" + len);
      for (let i = 0; i < len; ++i) {
        console.info("ssid: " + result[i].ssid);
        console.info("bssid: " + result[i].bssid);
        console.info("capabilities: " + result[i].capabilities);
        console.info("securityType: " + result[i].securityType);
        console.info("rssi: " + result[i].rssi);
        console.info("band: " + result[i].band);
        console.info("frequency: " + result[i].frequency);
        console.info("channelWidth: " + result[i].channelWidth);
        console.info("timestamp: " + result[i].timestamp);
      }
      console.info("getScanInfos promise successful")
      message = "WifiScanInfo: " + JSON.stringify(result)
      prompt.showToast({ message: message })
    });
  }
  prompt.showToast({ message: message })
  return message
}

export function testGetScanInfosCallback(): string {
  let message = ($r('app.string.testGetScanInfosCallback'))
  if (!wifiEnable) {
    message =($r('app.string.wifi_disEnable'));
  } else {
    wifi.getScanInfos((err, result) => {
      if (err) {
        console.error("get scan info error");
        return;
      }
      let len = Object.keys(result).length;
      console.log("wifi received scan info: " + len);
      for (let i = 0; i < len; ++i) {
        console.info("ssid: " + result[i].ssid);
        console.info("bssid: " + result[i].bssid);
        console.info("capabilities: " + result[i].capabilities);
        console.info("securityType: " + result[i].securityType);
        console.info("rssi: " + result[i].rssi);
        console.info("band: " + result[i].band);
        console.info("frequency: " + result[i].frequency);
        console.info("channelWidth: " + result[i].channelWidth);
        console.info("timestamp: " + result[i].timestamp);
      }
      console.info("getScanInfos callback successful")
      message = "WifiScanInfo: " + JSON.stringify(result)
      let getScanInfoMessage = JSON.stringify(result)
      AppStorage.SetOrCreate("getScanInfoMessage",getScanInfoMessage)
      prompt.showToast({ message: message })
    });
  }
  prompt.showToast({ message: message })
  return message
}

export function testAddDeviceConfigPromise(): string {
  let message = ($r('app.string.testAddDeviceConfigPromise'))
  let ssid = AppStorage.Get("ssid")
  let bssid = AppStorage.Get("bssid")
  let preSharedKey = AppStorage.Get("preSharedKey")
  let isHiddenSsid = AppStorage.Get("isHiddenSsid")
  let securityType = AppStorage.Get("securityType")
  let creatorUid = AppStorage.Get("creatorUid")
  let disableReason = AppStorage.Get("disableReason")
  let netId = AppStorage.Get("netId")
  let randomMacType = AppStorage.Get("randomMacType")
  let randomMacAddr = AppStorage.Get("randomMacAddr")
  let ipType = AppStorage.Get("ipType")
  let staticIp_ipAddress = AppStorage.Get("staticIp_ipAddress")
  let staticIp_gateway = AppStorage.Get("staticIp_gateway")
  let staticIp_dnsServers = AppStorage.Get("staticIp_dnsServers")
  let staticIp_domains = AppStorage.Get("staticIp_domains")
  let staticIp = {
    ipAddress: staticIp_ipAddress,
    gateway: staticIp_gateway,
    dnsServers: staticIp_dnsServers,
    domains: staticIp_domains
  }
  let wifiDeviceConfig = {
    ssid: ssid,
    bssid: bssid,
    preSharedKey: preSharedKey,
    isHiddenSsid: isHiddenSsid,
    securityType: securityType,
    creatorUid: creatorUid,
    disableReason: disableReason,
    netId: netId,
    randomMacType: randomMacType,
    randomMacAddr: randomMacAddr,
    ipType: ipType,
    staticIp: staticIp
  }
  AppStorage.SetOrCreate("wifiDeviceConfig",wifiDeviceConfig)
  if (!wifiEnable) {
    message = ($r('app.string.wifi_disEnable'));
  } else {
    wifi.addDeviceConfig(wifiDeviceConfig).then(result => {
//  @returns Returns {@code networkId} if the configuration is added; returns {@code -1} otherwise.
      console.info("addDeviceConfig promise successful")
      message = "addDeviceConfig: " + result
      prompt.showToast({ message: message })
    });
  }
  prompt.showToast({ message: message })
  return message
}

export function testAddDeviceConfigCallback(): string {
  let message = ($r('app.string.testAddDeviceConfigCallback'))
  if (!wifiEnable) {
    message = ($r('app.string.wifi_disEnable'));
  } else {
    let wifiDeviceConfig =AppStorage.Get("wifiDeviceConfig")
    wifi.addDeviceConfig(wifiDeviceConfig, (err, result) => {
//  @returns Returns {@code networkId} if the configuration is added; returns {@code -1} otherwise.
      if (err) {
        console.error("addDeviceConfigCallback error:" + err);
        return;
      }
      console.info("addDeviceConfig Callback successful")
      message = "addDeviceConfig: " + result
      prompt.showToast({ message: message })
    });
  }
  prompt.showToast({ message: message })
  return message
}

export function testAddUntrustedConfigPromise(): string {
  let message =  ($r('app.string.testAddUntrustedConfigPromise'))
  if (!wifiEnable) {
    message = ($r('app.string.wifi_disEnable'));
  } else {
    let wifiDeviceConfig =AppStorage.Get("wifiDeviceConfig")
    wifi.addUntrustedConfig(wifiDeviceConfig).then(result => {
//  @returns Returns {@code true} if the untrusted hotspot configuration is added, returns {@code false} otherwise.
      console.info("addUntrustedConfig: " + result)
      console.info("addUntrustedConfig promise successful")
      message = "addUntrustedConfig: " + result
      prompt.showToast({ message: message })
    })
  }
  prompt.showToast({ message: message })
  return message
}

export function testAddUntrustedConfigCallback(): string {
  let message =  ($r('app.string.testAddUntrustedConfigCallback'))
  if (!wifiEnable) {
    message =($r('app.string.wifi_disEnable'));
  } else {
    let wifiDeviceConfig =AppStorage.Get("wifiDeviceConfig")
    wifi.addUntrustedConfig(wifiDeviceConfig, (err, result) => {
//  @returns Returns {@code true} if the untrusted hotspot configuration is added, returns {@code false} otherwise.
      if (err) {
        console.error("AddUntrustedConfigCallback error");
        return;
      }
      console.info("addUntrustedConfig: " + result)
      console.info("addUntrustedConfig Callback successful")
      message = "addUntrustedConfig: " + result
      prompt.showToast({ message: message })
    })
  }
  prompt.showToast({ message: message })
  return message
}

export function testRemoveUntrustedConfigPromise(): string {
  let message = ($r('app.string.testRemoveUntrustedConfigPromise'))
  if (!wifiEnable) {
    message = ($r('app.string.wifi_disEnable'))
  } else {
    let wifiDeviceConfig =AppStorage.Get("wifiDeviceConfig")
    wifi.removeUntrustedConfig(wifiDeviceConfig).then(result => {
//  @returns Returns {@code true} if the untrusted hotspot configuration is removed, returns {@code false} otherwise.
      console.info("removeUntrustedConfig: " + result)
      console.info("removeUntrustedConfig promise successful")
      message = "removeUntrustedConfig: "+ result
      prompt.showToast({ message: message })
    })
  }
  prompt.showToast({ message: message })
  return message
}

export function testRemoveUntrustedConfigCallback(): string {
  let message = ($r('app.string.testRemoveUntrustedConfigCallback'))
  if (!wifiEnable) {
    message =($r('app.string.wifi_disEnable'));
  } else {
    let wifiDeviceConfig =AppStorage.Get("wifiDeviceConfig")
    wifi.removeUntrustedConfig(wifiDeviceConfig, (err, result) => {
//  @returns Returns {@code true} if the untrusted hotspot configuration is removed, returns {@code false} otherwise.
      if (err) {
        console.error("removeUntrustedConfigCallback error");
        return;
      }
      console.info("removeUntrustedConfig: " + result)
      console.info("removeUntrustedConfig Callback successful")
      message = "removeUntrustedConfig: " + result
      prompt.showToast({ message: message })
    })
  }
  prompt.showToast({ message: message })
  return message
}

export function testConnectToNetwork(): string {
  let message = ($r('app.string.testConnectToNetwork'))
  let networkId = AppStorage.Get("networkId")
  if (!wifiEnable) {
    message = ($r('app.string.wifi_disEnable'));
  } else {
    let ret = wifi.connectToNetwork(networkId)
    message = "ConnectToNetwork: " + ret
  }
  prompt.showToast({ message: message })
  return message
}

export function testConnectToDevice(): string {
  let message =  ($r('app.string.testConnectToDevice'))
  if (!wifiEnable) {
    message = ($r('app.string.wifi_disEnable'));
  } else {
    let wifiDeviceConfig =AppStorage.Get("wifiDeviceConfig")
    let ret = wifi.connectToDevice(wifiDeviceConfig)
    message = "ConnectToDevice: " + ret
  }
  prompt.showToast({ message: message })
  return message
}

export function testDisconnect(): string {
  let message = ($r('app.string.testDisconnect'))
  if (!wifiEnable) {
    message = ($r('app.string.wifi_disEnable'));
  } else {
    let ret = wifi.disconnect()
    message = "disconnect: " + ret
  }
  prompt.showToast({ message: message })
  return message
}

export function testGetSignalLevel(): string {
  let message = ($r('app.string.testDisconnect'))
  if (!wifiEnable) {
    message = ($r('app.string.wifi_disEnable'));
  } else {
    let rssi = AppStorage.Get("rssi")
    let band = AppStorage.Get("band")
    let number = wifi.getSignalLevel(rssi, band)
    message = "getSignalLevel is: " + number
  }
  prompt.showToast({ message: message })
  return message
}

export function testGetLinkedInfoPromise(): string {
  let message = ($r('app.string.testGetLinkedInfoPromise'))
  if (!wifiEnable) {
    message = ($r('app.string.wifi_disEnable'));
  } else {
    wifi.getLinkedInfo().then(data => {
      console.info("getLinkedInfoPromise test successful")
      message = "get wifi linked info: "+ JSON.stringify(data)
      console.info("get wifi linked info: " + JSON.stringify(data));
    }).catch(error => {
      console.info("get linked info error");
    });
  }
  prompt.showToast({ message: message })
  return message
}

export function testGetLinkedInfoCallback(): string {
  let message =  ($r('app.string.testGetLinkedInfoCallback'))
  if (!wifiEnable) {
    message = ($r('app.string.wifi_disEnable'));
  } else {
    wifi.getLinkedInfo((err, data) => {
      if (err) {
        console.error("get linked info error");
        message = "get linked info error"
        prompt.showToast({ message: message })
      }
      console.info("getLinkedInfoCallback test successful")
      console.info("get wifi linked info: " + JSON.stringify(data));
      message = "get wifi linked info: " + JSON.stringify(data)
      let linkedInfoMessage = JSON.stringify(data)
      AppStorage.SetOrCreate("linkedInfoMessage", linkedInfoMessage)
      let rssi =data.rssi
      let band =data.band
      let networkId =data.networkId
      AppStorage.SetOrCreate("rssi",rssi)
      AppStorage.SetOrCreate("band",band)
      AppStorage.SetOrCreate("networkId",networkId)
      prompt.showToast({ message: message })
    });
  }
  prompt.showToast({ message: message })
  return message
}

export function testIsConnected(): string {
  let message = ($r('app.string.testIsConnected'))
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
  }else {
    let ret = wifi.isConnected()
    message = "isConnected: " + ret
  }
  prompt.showToast({ message: message })
  return message
}

export function testGetSupportedFeatures(): string {
  let message = ($r('app.string.testGetSupportedFeatures'))
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
  }else {
    let ret = wifi.getSupportedFeatures()
    message = "GetSupportedFeatures: " + ret
  }
  prompt.showToast({ message: message })
  return message
}

export function testIsFeatureSupported(): string {
  let message = ($r('app.string.testIsFeatureSupported'))
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
  }else {
    let featureId = AppStorage.Get("featureId")
    let ret = wifi.isFeatureSupported(featureId)
    message = "isFeatureSupported: " + ret
  }
  prompt.showToast({ message: message })
  return message
}

export function testGetDeviceMacAddress(): string {
  let message = ($r('app.string.testGetDeviceMacAddress'))
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
  }else {
    let macAddress = wifi.getDeviceMacAddress()
    message ="macAddress: "+ macAddress
  }
  prompt.showToast({ message: message })
  return message
}

export function testGetIpInfo(): string {
  let message = ($r('app.string.testGetIpInfo'))
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
  }else {
    let IpInfo = wifi.getIpInfo()
    message ="IpInfo: " + JSON.stringify(IpInfo)
    let ipInfoMessage = message
    AppStorage.SetOrCreate("ipInfoMessage", ipInfoMessage)
  }
  prompt.showToast({ message: message })
  return message
}

export function testGetCountryCode(): string {
  let message =($r('app.string.testGetCountryCode'))
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
  }else {
    let ret = wifi.getCountryCode()
    message = "CountryCode is: " + ret
  }
  prompt.showToast({ message: message })
  return message
}

export function testReassociate(): string {
  let message = ($r('app.string.testReassociate'))
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
  }else {
    let ret = wifi.reassociate()
    message ="reassociate is: "+ ret
  }
  prompt.showToast({ message: message })
  return message
}

export function testReConnect(): string {
  let message = ($r('app.string.testReConnect'))
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
  }else {
    let ret = wifi.reconnect()
    message = "reConnect is: " + ret
  }
  prompt.showToast({ message: message })
  return message
}

export function testGetDeviceConfigs() {
  let message = ($r('app.string.testGetDeviceConfigs'))
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
  }else {
    let array = wifi.getDeviceConfigs()
    message =($r('app.string.getDeviceConfigs')) + array
    let getDeviceConfigsMessage = array
    AppStorage.SetOrCreate("getDeviceConfigsMessage",getDeviceConfigsMessage)
  }
  prompt.showToast({ message: message })
  return message
}

export function testUpdateNetwork() {
  let message = ($r('app.string.testUpdateNetwork'))
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
  }else {
    let wifiDeviceConfig = AppStorage.Get("wifiDeviceConfig")
    let ret = wifi.updateNetwork(wifiDeviceConfig)
    message ="updateNetwork: " + ret
  }
  prompt.showToast({ message: message })
  return message
}

export function testDisableNetwork() {
  let message = ($r('app.string.testDisableNetwork'))
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
  }else {
    let netId = AppStorage.Get("netId")
    let ret = wifi.disableNetwork(netId)
    message = "disableNetwork: " + ret
  }
  prompt.showToast({ message: message })
  return message
}

export function testRemoveAllNetwork() {
  let message = ($r('app.string.testRemoveAllNetwork'))
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
  }else {
    let ret = wifi.removeAllNetwork()
    message ="removeAllNetwork: " + ret
  }
  prompt.showToast({ message: message })
  return message
}

export function testRemoveDevice() {
  let message = ($r('app.string.testRemoveDevice'))
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
  }else {
    let id = AppStorage.Get("id")
    let ret = wifi.removeDevice(id)
    message ="removeDevice: " + ret
  }
  prompt.showToast({ message: message })
  return message
}

let wifiStateChange = false
export function testOnWifiStateChange(): string {
  let message = ($r('app.string.testOnWifiStateChange'))
  console.log("testOnWifiStateChange test");
//  if(!wifiEnable){
//    message =($r('app.string.wifi_disEnable'));
//    return message
//  }
  if (wifiStateChange) {
    wifi.off("wifiStateChange", () => {
      prompt.showToast({ message: ($r('app.string.offWifiStateChange')) })
    })
    message = ($r('app.string.offWifiStateChangeTest'))
  } else {
    wifi.on("wifiStateChange", (number) => {
      let wifiStateMessage = ""
      switch (number) {
        case 0:
          wifiStateMessage = "inactive";
          break;
        case 1:
          wifiStateMessage = "active";
          break;
        case 2:
          wifiStateMessage = "activating";
          break;
        case 3:
          wifiStateMessage = "de-activating";
          break;
        default:
          wifiStateMessage = '未知状态';
          break;
      }
      prompt.showToast({ message: "wifi状态: " + wifiStateMessage })
    })
    message = ($r('app.string.onWifiStateChangeTest'))
    prompt.showToast({ message: message })
  }
  wifiStateChange = !wifiStateChange
  return message
}

let wifiConnectionChange = false
export function testOnWifiConnectionChange(): string {
  let message =  ($r('app.string.testOnWifiConnectionChange'))
  console.log("testOnWifiConnectionChange test");
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
    return message
  }
  if (wifiConnectionChange) {
    wifi.off("wifiConnectionChange", () => {
      prompt.showToast({ message: ($r('app.string.offWifiConnectionChange')) })
    })
    message = ($r('app.string.offWifiConnectionChangeTest'))
  } else {
    wifi.on("wifiConnectionChange", (number) => {
      let wifiConnectionMessage = ""
      switch (number) {
        case 0:
          wifiConnectionMessage = "disconnected";
          break;
        case 1:
          wifiConnectionMessage = "connected";
          break;
        default:
          wifiConnectionMessage = '未知状态';
          break;
      }
      prompt.showToast({ message:"连接状态: " + wifiConnectionMessage })
    })
    message =  ($r('app.string.onWifiConnectionChangeTest'))
    prompt.showToast({ message: message })
  }
  wifiConnectionChange = !wifiConnectionChange
  return message
}

let wifiScanStateChange = false
export function testOnWifiScanStateChange(): string {
  let message = ($r('app.string.testOnWifiScanStateChange'))
  console.log("testOnWifiScanStateChange test");
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
    return message
  }
  if (wifiScanStateChange) {
    wifi.off("wifiScanStateChange", () => {
      prompt.showToast({ message: ($r('app.string.offWifiScanStateChange')) })
    })
    message = ($r('app.string.offWifiScanStateChangeTest'))
  } else {
    wifi.on("wifiScanStateChange", (number) => {
      let wifiScanStateMessage = ""
      switch (number) {
        case 0:
          wifiScanStateMessage = "scan fail";
          break;
        case 1:
          wifiScanStateMessage = "scan success";
          break;
        default:
          wifiScanStateMessage = '未知状态';
          break;
      }
      prompt.showToast({ message:"scan状态: " + wifiScanStateMessage })
    })
    message = ($r('app.string.onWifiScanStateChangeTest'))
    prompt.showToast({ message: message })
  }
  wifiScanStateChange = !wifiScanStateChange
  return message
}

let wifiRssiChange = false
export function testOnWifiRssiChange(): string {
  let message = ($r('app.string.testOnWifiRssiChange'))
  console.log("testOnWifiRssiChange test");
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
    return message
  }
  if (wifiRssiChange) {
    wifi.off("wifiRssiChange", () => {
      prompt.showToast({ message: ($r('app.string.offWifiRssiChange')) })
    })
    message = ($r('app.string.offWifiRssiChangeTest'))
  } else {
    wifi.on("wifiRssiChange", (number) => {
      prompt.showToast({ message:"rssi: " + number })
    })
    message = ($r('app.string.onWifiRssiChangeTest'))
    prompt.showToast({ message: message })
  }
  wifiRssiChange = !wifiRssiChange
  return message
}

let streamChange =false
export function testOnStreamChange(){
  let message = ($r('app.string.testOnStreamChange'))
  console.log("testOnStreamChange test");
  if(!wifiEnable){
    message =($r('app.string.wifi_disEnable'));
    return message
  }
  if (streamChange) {
    wifi.off("streamChange", () => {
      prompt.showToast({ message: ($r('app.string.offStreamChange')) })
    })
    message = ($r('app.string.offStreamChangeTest'))
  } else {
    wifi.on("streamChange", (number) => {
      let streamChangeMessage = ""
      switch (number) {
        case 0:
          streamChangeMessage = "stream none";
          break;
        case 1:
          streamChangeMessage = "stream down";
          break;
        case 2:
          streamChangeMessage = "stream up";
          break;
        case 3:
          streamChangeMessage = "stream bidirectional";
          break;
        default:
          streamChangeMessage = '未知状态';
          break;
      }
      prompt.showToast({ message:"stream状态: "+ streamChangeMessage })
    })
    message = ($r('app.string.onStreamChangeTest'))
    prompt.showToast({ message: message })
  }
  streamChange = !streamChange
  return message
}
