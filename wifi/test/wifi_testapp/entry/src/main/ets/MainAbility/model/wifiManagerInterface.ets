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

import prompt from '@system.prompt';
import Router from '@system.router';
import wifiManager from '@ohos.wifiManager';
import ConfigData from "../../Utils/ConfigData"
import LogDataManager from "../../Utils/LogDataManager"
import MessageDataManager from "../../Utils/MessageDataManager"

/**
 * WifiManager api Test Page Of wifi test
 */
const PAGE_URI_WIFI_FOUND_MODE = 'pages/subManualApiTest/subWifiTest/wifiFound';
let wifiManagerEnable = false

export function testEnableWifiManager() {
  try {
    let message = ( MessageDataManager.testEnableWifi );
    console.log( LogDataManager.testEnableWifiManager_StartLog )
    if ( wifiManagerEnable ) {
      message = ( MessageDataManager.testIsActive )
    } else {
      let ret = wifiManager.enableWifi();
      //enableWifi返回值为void,无法判断
      //      if ( ret ) {
      //        message = "Wifi已打开或打开失败,请确认"
      //      }
      message = ( MessageDataManager.testWifiEnableMaybe )
      wifiManagerEnable = true;
      AppStorage.SetOrCreate( 'wifiManagerIsOn' , wifiManagerEnable );
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testEnableWifi_EndLo )
    return message
  } catch( e ) {
    console.log( `Failed to testEnableWifiManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testEnableWifiManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testDisableWifiManager() {
  try {
    let message = ( MessageDataManager.testDisableWifi );
    console.log( LogDataManager.testDisableWifiManager_StartLog )
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive )
    } else {
      let ret = wifiManager.disableWifi();
      //disableWifi返回值为void,无法判断
      //      if ( ret ) {
      //        message = "Wifi已关闭或关闭失败,请确认"
      //      }
      message = ( MessageDataManager.testWifiDisableMaybe )
      wifiManagerEnable = false;
      AppStorage.SetOrCreate( 'wifiManagerIsOn' , wifiManagerEnable );
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testDisableWifiManager_EndLog )
    return message
  } catch( e ) {
    console.log( `Failed to testDisableWifiManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testDisableWifiManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testIsWifiActiveManager() {
  try {
    let message = ( MessageDataManager.testIsActive );
    console.log( LogDataManager.testIsWifiActiveManager_StartLog )
    let ret = wifiManager.isWifiActive();
    if ( ret ) {
      wifiManagerEnable = true
    } else {
      wifiManagerEnable = false
    }
    message = ( MessageDataManager.testIsActiveResult ) + ret
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testIsWifiActiveManager_EndLog )
    return message
  } catch( e ) {
    console.log( `Failed to testIsWifiActiveManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testIsWifiActiveManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testScanManager() {
  try {
    let message = ( MessageDataManager.testScan )
    console.log( LogDataManager.testScanManager_StartLog )
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive )
    } else {
      let ret = wifiManager.scan()
      //scan返回值为void
      //      message = ( MessageDataManager.testScanResult ) + ret
      message = "scan 调用成功"
      Router.push( { uri : PAGE_URI_WIFI_FOUND_MODE } );
      prompt.showToast( { message : message } )
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testScanManager_EndLog )
    return message
  } catch( e ) {
    console.log( `Failed to testScanManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testScanManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetScanInfoListManager() {
  try {
    let message = ( MessageDataManager.testGetScanInfoList )
    console.log( LogDataManager.testGetScanInfoListManager_StartLog );
    let ret = wifiManager.getScanInfoList()
    message = "扫描结果为：" + JSON.stringify( ret )
    console.log( "扫描结果为：" + JSON.stringify( ret ) );
    let getScanInfoManagerMessage = JSON.stringify( ret )
    AppStorage.SetOrCreate( "getScanInfoManagerMessage" , getScanInfoManagerMessage )
    console.log( LogDataManager.testGetScanInfoListManager_EndLog );
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( `Failed to testGetScanInfoListManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetScanInfoListManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

//TODO: 设备调试时候需要打开
//let ssid1 = "TP-LINK_6365"
//let bssid1 = "6C:B1:58:75:63:65"
//let preSharedKey1 = "kaihong123"
//let isHiddenSsid1 = false
//let securityType1 = 3
//let creatorUid1 = 1
//let disableReason1 = 0
//let netId1 = 0
//let randomMacType1 = 0
//let randomMacAddr1 = "08:fb:ea:1b:38:aa"
//let ipType1 = 1
//let staticIp_ipAddress1 = 3232235880
//let staticIp_gateway1 = 3232235777
//let staticIp_dnsServers1 = 3716386629
//let staticIp_domains1 = [ "0", "1", "2" ]
//
//let staticIp1 = {
//  ipAddress : staticIp_ipAddress1 ,
//  gateway : staticIp_gateway1 ,
//  dnsServers : staticIp_dnsServers1 ,
//  domains : staticIp_domains1
//}
//
//let wifiDeviceConfigManager = {
//  ssid : ssid1 ,
//  bssid : bssid1 ,
//  preSharedKey : preSharedKey1 ,
//  isHiddenSsid : isHiddenSsid1 ,
//  securityType : securityType1 ,
//  creatorUid : creatorUid1 ,
//  disableReason : disableReason1 ,
//  netId : netId1 ,
//  randomMacType : randomMacType1 ,
//  randomMacAddr : randomMacAddr1 ,
//  ipType : ipType1 ,
//  staticIp : staticIp1
//}
//AppStorage.SetOrCreate( "wifiDeviceConfigManager" , wifiDeviceConfigManager )

export function testAddDeviceConfigManagerPromise() {
  try {
    let message = ( MessageDataManager.testAddDeviceConfigPromise )
    console.log( LogDataManager.testAddDeviceConfigPromiseManager_StartLog )
    let ssid1: string = AppStorage.Get( "w_ssid1" )
    let bssid1: string = AppStorage.Get( "w_bssid1" )
    let preSharedKey1: string = AppStorage.Get( "w_preSharedKey1" )
    let isHiddenSsid1: boolean = AppStorage.Get( "w_isHiddenSsid1" )
    let securityType1 = AppStorage.Get( "w_securityType1" )
    let creatorUid1 = AppStorage.Get( "w_creatorUid1" )
    let disableReason1 = AppStorage.Get( "w_disableReason1" )
    let netId1 = AppStorage.Get( "w_netId1" )
    let randomMacType1 = AppStorage.Get( "w_randomMacType1" )
    let randomMacAddr1 = AppStorage.Get( "w_randomMacAddr1" )
    let ipType1 = AppStorage.Get( "w_ipType1" )
    let staticIp_ipAddress1 = AppStorage.Get( "w_staticIp_ipAddress1" )
    let staticIp_gateway1 = AppStorage.Get( "w_staticIp_gateway1" )
    let staticIp_dnsServers1 = AppStorage.Get( "w_staticIp_dnsServers1" )
    let staticIp_domains1 = AppStorage.Get( "w_staticIp_domains1" )
    let staticIp1 = {
      ipAddress : staticIp_ipAddress1 ,
      gateway : staticIp_gateway1 ,
      dnsServers : staticIp_dnsServers1 ,
      domains : staticIp_domains1
    }
    let wifiDeviceConfigManager = {
      ssid : ssid1 ,
      bssid : bssid1 ,
      preSharedKey : preSharedKey1 ,
      isHiddenSsid : isHiddenSsid1 ,
      securityType : securityType1 ,
      creatorUid : creatorUid1 ,
      disableReason : disableReason1 ,
      netId : netId1 ,
      randomMacType : randomMacType1 ,
      randomMacAddr : randomMacAddr1 ,
      ipType : ipType1 ,
      staticIp : staticIp1
    }
    AppStorage.SetOrCreate( "wifiDeviceConfigManager" , wifiDeviceConfigManager )
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      wifiManager.addDeviceConfig( wifiDeviceConfigManager ).then( result => {
        //  @returns Returns {@code networkId} if the configuration is added; returns {@code -1} otherwise.
        console.log( LogDataManager.testAddDeviceConfigPromiseManager_successfulLog )
        console.log( LogDataManager.testAddDeviceConfigManagerLog + result )
        message = ( MessageDataManager.testAddDeviceConfig ) + result
        prompt.showToast( { message : message } )
        console.log( LogDataManager.testAddDeviceConfigPromiseManager_EndLog )
      } ).catch( err => {
        console.log( "testAddDeviceConfigManagerPromise error:" + err )
      } )
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( `Failed to testAddDeviceConfigManagerPromise. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testAddDeviceConfigManagerPromise. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testAddDeviceConfigManagerCallback() {
  try {
    let message = ( MessageDataManager.testAddDeviceConfigCallback )
    console.log( LogDataManager.testAddDeviceConfigCallbackManager_StartLog )

    //TODO: 设备调试时候需要打开
        let ssid1: string = AppStorage.Get( "w_ssid1" )
        let bssid1: string = AppStorage.Get( "w_bssid1" )
        let preSharedKey1: string = AppStorage.Get( "w_preSharedKey1" )
        let isHiddenSsid1: boolean = AppStorage.Get( "w_isHiddenSsid1" )
        let securityType1 = AppStorage.Get( "w_securityType1" )
        let creatorUid1 = AppStorage.Get( "w_creatorUid1" )
        let disableReason1 = AppStorage.Get( "w_disableReason1" )
        let netId1 = AppStorage.Get( "w_netId1" )
        let randomMacType1 = AppStorage.Get( "w_randomMacType1" )
        let randomMacAddr1 = AppStorage.Get( "w_randomMacAddr1" )
        let ipType1 = AppStorage.Get( "w_ipType1" )
        let staticIp_ipAddress1 = AppStorage.Get( "w_staticIp_ipAddress1" )
        let staticIp_gateway1 = AppStorage.Get( "w_staticIp_gateway1" )
        let staticIp_dnsServers1 = AppStorage.Get( "w_staticIp_dnsServers1" )
        let staticIp_domains1 = AppStorage.Get( "w_staticIp_domains1" )
        let staticIp1 = {
          ipAddress : staticIp_ipAddress1 ,
          gateway : staticIp_gateway1 ,
          dnsServers : staticIp_dnsServers1 ,
          domains : staticIp_domains1
        }
        let wifiDeviceConfigManager = {
          ssid : ssid1 ,
          bssid : bssid1 ,
          preSharedKey : preSharedKey1 ,
          isHiddenSsid : isHiddenSsid1 ,
          securityType : securityType1 ,
          creatorUid : creatorUid1 ,
          disableReason : disableReason1 ,
          netId : netId1 ,
          randomMacType : randomMacType1 ,
          randomMacAddr : randomMacAddr1 ,
          ipType : ipType1 ,
          staticIp : staticIp1
        }
        AppStorage.SetOrCreate( "wifiDeviceConfigManager" , wifiDeviceConfigManager )
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive )
    } else {
//      let wifiDeviceConfigManager = AppStorage.Get( "wifiDeviceConfigManager" )
      wifiManager.addDeviceConfig( wifiDeviceConfigManager , ( err , result ) => {
        //  @returns Returns {@code networkId} if the configuration is added; returns {@code -1} otherwise.
        if ( err ) {
          console.error( "addDeviceConfigCallback error:" + err );
          return;
        }
        console.log( LogDataManager.testAddDeviceConfigCallbackManager_successfulLog )
        console.log( LogDataManager.testAddDeviceConfigManagerLog + result )
        message = ( MessageDataManager.testAddDeviceConfig ) + result
        prompt.showToast( { message : message } )
        console.log( LogDataManager.testAddDeviceConfigCallbackManager_EndLog )
      } );
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( `Failed to testAddDeviceConfigManagerCallback. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testAddDeviceConfigManagerCallback. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testAddCandidateConfigManagerPromise() {
  try {
    let message = ( MessageDataManager.testAddCandidateConfigPromise )
    console.log( LogDataManager.testAddCandidateConfigPromiseManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive )
    } else {
      let wifiDeviceConfigManager = AppStorage.Get( "wifiDeviceConfigManager" )
      wifiManager.addCandidateConfig( wifiDeviceConfigManager ).then( result => {
        //  @returns Returns {@code true} if the Candidate hotspot configuration is added, returns {@code false} otherwise.
        console.log( LogDataManager.testAddCandidateConfigPromiseManager_successfulLog )
        console.log( LogDataManager.testAddCandidateConfigManagerLog + result )
        message = ( MessageDataManager.testAddCandidateConfig + result )
        prompt.showToast( { message : message } )
        console.log( LogDataManager.testAddCandidateConfigPromiseManager_EndLog )
      } ).catch( err => {
        console.log( "testAddCandidateConfigManagerPromise err:" + err )
      } )
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( `Failed to testAddCandidateConfigManagerPromise. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testAddCandidateConfigManagerPromise. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testAddCandidateConfigManagerCallback() {
  try {
    let message = ( MessageDataManager.testAddCandidateConfigCallback )
    console.log( LogDataManager.testAddCandidateConfigCallbackManager_StartLog )
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive )
    } else {
      let wifiDeviceConfigManager = AppStorage.Get( "wifiDeviceConfigManager" )
      wifiManager.addCandidateConfig( wifiDeviceConfigManager , ( err , result ) => {
        //  @returns Returns {@code true} if the Candidate hotspot configuration is added, returns {@code false} otherwise.
        if ( err ) {
          console.error( "addCandidateConfigCallback error" );
          return;
        }
        console.log( LogDataManager.testAddCandidateConfigCallbackManager_successfulLog )
        console.log( LogDataManager.testAddCandidateConfigManagerLog + result )
        message = ( MessageDataManager.testAddCandidateConfig + result )
        prompt.showToast( { message : message } )
        console.log( LogDataManager.testAddCandidateConfigCallbackManager_EndLog )
      } )
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( `Failed to testAddCandidateConfigManagerCallback. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testAddCandidateConfigManagerCallback. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testRemoveCandidateConfigManagerPromise() {
  try {
    let message = ( MessageDataManager.testRemoveCandidateConfigPromise )
    console.log( LogDataManager.testRemoveCandidateConfigPromiseManager_StartLog )
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let networkId: number = AppStorage.Get( "w_networkId1" )
      wifiManager.removeCandidateConfig( networkId ).then( result => {
        //  @returns Returns {@code true} if the Candidate hotspot configuration is removed, returns {@code false} otherwise.
        console.log( LogDataManager.testRemoveCandidateConfigPromiseManager_successfulLog )
        console.log( LogDataManager.testRemoveCandidateConfigManagerLog + result )
        message = MessageDataManager.testRemoveCandidateConfig + result
        prompt.showToast( { message : message } )
        console.log( LogDataManager.testRemoveCandidateConfigPromiseManager_EndLog )
      } ).catch( err => {
        console.log( "testRemoveCandidateConfigManagerPromise err:" + err )
      } )
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( `Failed to testRemoveCandidateConfigManagerPromise. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testRemoveCandidateConfigManagerPromise. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testRemoveCandidateConfigManagerCallback() {
  try {
    let message = ( MessageDataManager.testRemoveCandidateConfigCallback )
    console.log( LogDataManager.testRemoveCandidateConfigCallbackManager_StartLog )
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let networkId: number = AppStorage.Get( "w_networkId1" )
      wifiManager.removeCandidateConfig( networkId , ( err , result ) => {
        //  @returns Returns {@code true} if the Candidate hotspot configuration is removed, returns {@code false} otherwise.
        if ( err ) {
          console.error( "removeCandidateConfigCallback error" );
          return;
        }
        console.log( LogDataManager.testRemoveCandidateConfigCallbackManager_successfulLog )
        console.log( LogDataManager.testRemoveCandidateConfigManagerLog + result )
        message = ( MessageDataManager.testRemoveCandidateConfig + result )
        prompt.showToast( { message : message } )
        console.log( LogDataManager.testRemoveCandidateConfigCallbackManager_EndLog )
      } )
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( `Failed to testRemoveCandidateConfigManagerCallback. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testRemoveCandidateConfigManagerCallback. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetCandidateConfigsManager() {
  try {
    let message = ( MessageDataManager.testGetCandidateConfigs )
    console.log( LogDataManager.testGetCandidateConfigsManager_StartLog )
    let ret = wifiManager.getCandidateConfigs()
    message = "候选配置：" + JSON.stringify( ret )
    console.log( "候选配置：" + JSON.stringify( ret ) );
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testGetCandidateConfigsManager_EndLog )
    return message
  } catch( e ) {
    console.log( `Failed to testGetCandidateConfigsManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetCandidateConfigsManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testConnectToCandidateConfigManager() {
  try {
    let message = ( MessageDataManager.testConnectToCandidateConfig )
    console.log( LogDataManager.testConnectToCandidateConfigManager_StartLog )
    let networkId = AppStorage.Get( "w_networkId1" )
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let ret = wifiManager.connectToCandidateConfig( networkId )
      //      connectToCandidateConfig的返回值为void，无法判断
      //      message = "connectToCandidateConfig: " + ret
      message = "connectToCandidateConfig 调用成功"
      console.log( "connectToCandidateConfig 调用成功" )
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testConnectToCandidateConfigManager_EndLog )
    return message
  } catch( e ) {
    console.log( `Failed to testConnectToCandidateConfigManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testConnectToCandidateConfigManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testConnectToNetworkManager() {
  try {
    let message = ( MessageDataManager.testConnectToNetwork )
    console.log( LogDataManager.testConnectToNetworkManager_StartLog )
    let networkId: number = AppStorage.Get( "w_networkId1" )
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let ret = wifiManager.connectToNetwork( networkId )
      //      connectToNetwork的返回值为void，无法判断
      //      message = "ConnectToNetwork: " + ret
      message = "ConnectToNetwork 调用成功"
      console.log( "connectToCandidateConfig 调用成功" )
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testConnectToNetworkManager_EndLog )
    return message
  } catch( e ) {
    console.log( `Failed to testConnectToNetworkManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testConnectToNetworkManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testConnectToDeviceManager() {
  try {
    let message = ( MessageDataManager.testConnectToDevice )
    console.log( LogDataManager.testConnectToDeviceManager_StartLog )
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let wifiDeviceConfigManager = AppStorage.Get( "wifiDeviceConfigManager" )
      let ret = wifiManager.connectToDevice( wifiDeviceConfigManager )
      //      connectToDevice的返回值为void，无法判断
      //      message = "ConnectToDevice:" + ret
      message = "connectToDevice 调用成功"
      console.log( "connectToDevice 调用成功" )
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testConnectToNetworkManager_EndLog )
    return message
  } catch( e ) {
    console.log( `Failed to testConnectToDeviceManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testConnectToDeviceManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testDisconnectManager() {
  try {
    let message = ( MessageDataManager.testDisconnect )
    console.log( LogDataManager.testDisconnectManager_StartLog )
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let ret = wifiManager.disconnect()
      //      disconnect的返回值为void
      //      message = "disconnect: " + ret
      message = "disconnect 调用成功"
      console.log( "disconnect 调用成功" )
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testDisconnectManager_EndLog )
    return message
  } catch( e ) {
    console.log( `Failed to testDisconnectManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testDisconnectManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetSignalLevelManager() {
  try {
    let message = ( MessageDataManager.testGetSignalLevel )
    console.log( LogDataManager.testGetSignalLevelManager_StartLog )
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive )
    } else {
      let rssi: number = AppStorage.Get( "w_rssi1" )
      let band: number = AppStorage.Get( "w_band1" )
      let number = wifiManager.getSignalLevel( rssi , band )
      message = "getSignalLevel is: " + number
      console.log( "getSignalLevel is: " + number )
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testGetSignalLevelManager_EndLog )
    return message
  } catch( e ) {
    console.log( `Failed to testGetSignalLevelManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetSignalLevelManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetLinkedInfoManagerPromise() {
  try {
    let message = ( MessageDataManager.testGetLinkedInfoPromise )
    console.log( LogDataManager.testGetLinkedInfoPromiseManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive )
    } else {
      wifiManager.getLinkedInfo().then( data => {
        console.log( LogDataManager.testGetLinkedInfoPromiseManager_successfulLog )
        message = "get wifi linked info: " + JSON.stringify( data )
        console.log( "get wifi linked info: " + JSON.stringify( data ) );
        prompt.showToast( { message : message } )
        console.log( LogDataManager.testGetLinkedInfoPromiseManager_EndLog );
      } ).catch( error => {
        console.log( "get linked info error:" + error );
      } );
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( `Failed to testGetLinkedInfoManagerPromise. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetLinkedInfoManagerPromise. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetLinkedInfoManagerCallback() {
  try {
    let message = ( MessageDataManager.testGetLinkedInfoCallback )
    console.log( LogDataManager.testGetLinkedInfoCallbackManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive )
    } else {
      wifiManager.getLinkedInfo( ( err , data ) => {
        if ( err ) {
          console.error( "get linked info error" );
          message = "get linked info error"
          prompt.showToast( { message : message } )
        }
        console.log( LogDataManager.testGetLinkedInfoCallbackManager_successfulLog )
        console.log( "get wifi linked info: " + JSON.stringify( data ) );
        message = "get wifi linked info: " + JSON.stringify( data )
        let linkedInfoManagerMessage = JSON.stringify( data )
        AppStorage.SetOrCreate( "linkedInfoManagerMessage" , linkedInfoManagerMessage )
        let rssi = data.rssi
        let band = data.band
        let networkId = data.networkId
        AppStorage.SetOrCreate( "w_rssi1" , rssi )
        AppStorage.SetOrCreate( "w_band1" , band )
        AppStorage.SetOrCreate( "w_networkId1" , networkId )
        prompt.showToast( { message : message } )
        console.log( LogDataManager.testGetLinkedInfoCallbackManager_EndLog );
      } );
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( `Failed to testGetLinkedInfoManagerCallback. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetLinkedInfoManagerCallback. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testIsConnectedManager() {
  try {
    let message = ( MessageDataManager.testIsConnected )
    console.log( LogDataManager.testIsConnectedManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let ret = wifiManager.isConnected()
      message = "isConnected: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testIsConnectedManager_EndLog );
    return message
  } catch( e ) {
    console.log( `Failed to testIsConnectedManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testIsConnectedManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetSupportedFeaturesManager() {
  try {
    let message = ( MessageDataManager.testGetSupportedFeatures )
    console.log( LogDataManager.testGetSupportedFeaturesManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let ret = wifiManager.getSupportedFeatures()
      message = "GetSupportedFeatures: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testGetSupportedFeaturesManager_EndLog );
    return message
  } catch( e ) {
    console.log( `Failed to testGetSupportedFeaturesManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetSupportedFeaturesManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testIsFeatureSupportedManager() {
  try {
    let message = ( MessageDataManager.testIsFeatureSupported )
    console.log( LogDataManager.testIsFeatureSupportedManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive )
    } else {
      let featureId = AppStorage.Get( "w_featureId1" )
      let ret = wifiManager.isFeatureSupported( featureId )
      message = "isFeatureSupported: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testGetSupportedFeaturesManager_EndLog )
    return message
  } catch( e ) {
    console.log( `Failed to testIsFeatureSupportedManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testIsFeatureSupportedManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetDeviceMacAddressManager() {
  try {
    let message = ( MessageDataManager.testGetDeviceMacAddress )
    console.log( LogDataManager.testGetDeviceMacAddressManager_StartLog )
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let macAddress = wifiManager.getDeviceMacAddress()
      message = "macAddress: " + macAddress
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testGetDeviceMacAddressManager_EndLog );
    return message
  } catch( e ) {
    console.log( `Failed to testGetDeviceMacAddressManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetDeviceMacAddressManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetIpInfoManager() {
  try {
    let message = ( MessageDataManager.testGetIpInfo )
    console.log( LogDataManager.testGetIpInfoManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let IpInfo = wifiManager.getIpInfo()
      message = "IpInfo: " + JSON.stringify( IpInfo )
      let ipInfoManagerMessage = IpInfo
      AppStorage.SetOrCreate( "ipInfoManagerMessage" , ipInfoManagerMessage )
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testGetIpInfoManager_EndLog );
    return message
  } catch( e ) {
    console.log( `Failed to testGetIpInfoManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetIpInfoManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetCountryCodeManager() {
  try {
    let message = ( MessageDataManager.testGetCountryCode )
    console.log( LogDataManager.testGetCountryCodeManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive )
    } else {
      let ret = wifiManager.getCountryCode()
      message = "CountryCode is: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testGetCountryCodeManager_EndLog );
    return message
  } catch( e ) {
    console.log( `Failed to testGetCountryCodeManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetCountryCodeManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testReassociateManager() {
  try {
    let message = ( MessageDataManager.testReassociate )
    console.log( LogDataManager.testReassociateManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let ret = wifiManager.reassociate()
      //      reassociate的返回值为void
      //      message = "reassociate is: " + ret
      message = "reassociate 调用成功"
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testReassociateManager_EndLog );
    return message
  } catch( e ) {
    console.log( `Failed to testReassociateManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testReassociateManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testReconnectManager() {
  try {
    let message = ( MessageDataManager.testReConnect )
    console.log( LogDataManager.testReConnectManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive )
    } else {
      let ret = wifiManager.reconnect()
      //      reconnect的返回值为void
      //      message = " reConnect is: " + ret
      message = "reconnect 调用成功"
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testReConnectManager_EndLog );
    return message
  } catch( e ) {
    console.log( `Failed to testReconnectManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testReconnectManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetDeviceConfigsManager() {
  try {
    let message = ( MessageDataManager.testGetDeviceConfigs )
    console.log( LogDataManager.testGetDeviceConfigsManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let array = wifiManager.getDeviceConfigs()
      message = " DeviceConfigs is " + JSON.stringify( array )
      let getDeviceConfigsManagerMessage = JSON.stringify( array )
      AppStorage.SetOrCreate( "getDeviceConfigsManagerMessage" , getDeviceConfigsManagerMessage )
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testGetDeviceConfigsManager_EndLog );
    return message
  } catch( e ) {
    console.log( `Failed to testGetDeviceConfigsManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetDeviceConfigsManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testUpdateDeviceConfigManager() {
  try {
    let message = ( MessageDataManager.testUpdateNetwork )
    console.log( LogDataManager.testUpdateNetworkManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let wifiDeviceConfigManager = AppStorage.Get( "wifiDeviceConfigManager" )
      let ret = wifiManager.updateDeviceConfig( wifiDeviceConfigManager )
      message = "updateNetwork: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testUpdateNetworkManager_EndLog );
    return message
  } catch( e ) {
    console.log( `Failed to testUpdateDeviceConfigManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testUpdateDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testDisableDeviceConfigManager() {
  try {
    let message = ( MessageDataManager.testDisableNetwork )
    console.log( LogDataManager.testDisableNetworkManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let networkId = AppStorage.Get( "w_networkId1" )
      let ret = wifiManager.disableDeviceConfig( networkId )
      //      disableDeviceConfig的返回值为void
      //      message = "disableNetwork: " + ret
      message = "disableNetwork 调用成功"
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testDisableNetworkManager_EndLog );
    return message
  } catch( e ) {
    console.log( `Failed to testDisableDeviceConfigManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testDisableDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testRemoveAllDeviceConfigsManager() {
  try {
    let message = ( MessageDataManager.testRemoveAllNetwork )
    console.log( LogDataManager.testRemoveAllNetworkManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let ret = wifiManager.removeAllDeviceConfigs()
      //      removeAllDeviceConfigs的返回值为void
      //      message = "removeAllNetwork: " + ret
      message = "removeAllDeviceConfigs 调用成功"
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testRemoveAllNetworkManager_EndLog );
    return message
  } catch( e ) {
    console.log( `Failed to testRemoveAllDeviceConfigsManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testRemoveAllDeviceConfigsManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testRemoveDeviceConfigManager() {
  try {
    let message = ( MessageDataManager.testRemoveDevice )
    console.log( LogDataManager.testRemoveDeviceManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
    } else {
      let networkId = AppStorage.Get( "w_networkId1" )
      let ret = wifiManager.removeDeviceConfig( networkId )
      //      removeDeviceConfig的返回值为void
      //      message = "removeDevice " + ret
      message = "removeDeviceConfig 调用成功"
    }
    prompt.showToast( { message : message } )
    console.log( LogDataManager.testRemoveDeviceManager_EndLog );
    return message
  } catch( e ) {
    console.log( `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testRemoveDeviceConfigManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let wifiStateChangeManager = false

export function testOnWifiStateChangeManager() {
  try {
    let message = "onWifiStateChange test"
    console.log( LogDataManager.testOnWifiStateChangeManager_StartLog );
    if ( wifiStateChangeManager ) {
      wifiManager.off( "wifiStateChange" , () => {
        prompt.showToast( { message : "on.WifiStateChange监听已关闭" } )
      } )
      message = "关闭注册WLAN状态改变事件"
    } else {
      wifiManager.on( "wifiStateChange" , ( number ) => {
        let wifiStateMessage = ""
        switch ( number ) {
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
        prompt.showToast( { message : "状态:" + wifiStateMessage } )
        console.log( LogDataManager.testOnWifiStateChangeManager_EndLog );
      } )
      message = "打开注册WLAN状态变化"
      prompt.showToast( { message : message } )
    }
    wifiStateChangeManager = !wifiStateChangeManager
    return message
  } catch( e ) {
    console.log( `Failed to testOnWifiStateChangeManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testOnWifiStateChangeManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let wifiConnectionChangeManager = false

export function testOnWifiConnectionChangeManager() {
  try {
    let message = "OnWifiConnectionChange test"
    console.log( LogDataManager.testOnWifiConnectionChangeManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
      return message
    }
    if ( wifiConnectionChangeManager ) {
      wifiManager.off( "wifiConnectionChange" , () => {
        prompt.showToast( { message : "on.wifiConnectionChange监听已关闭" } )
      } )
      message = "关闭WLAN连接状态改变事件"
    } else {
      wifiManager.on( "wifiConnectionChange" , ( number ) => {
        let wifiConnectionMessage = ""
        switch ( number ) {
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
        prompt.showToast( { message : "状态: " + wifiConnectionMessage } )
        console.log( LogDataManager.testOnWifiConnectionChangeManager_EndLog );
      } )
      message = "打开注册WLAN连接状态变化"
      prompt.showToast( { message : message } )
    }
    wifiConnectionChangeManager = !wifiConnectionChangeManager
    return message
  } catch( e ) {
    console.log( `Failed to testOnWifiConnectionChangeManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testOnWifiConnectionChangeManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let wifiScanStateChangeManager = false

export function testOnWifiScanStateChangeManager() {
  try {
    let message = "OnWifiScanStateChange test"
    console.log( LogDataManager.testOnWifiScanStateChangeManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
      return message
    }
    if ( wifiScanStateChangeManager ) {
      wifiManager.off( "wifiScanStateChange" , () => {
        prompt.showToast( { message : "on.wifiScanStateChange监听已关闭" } )
      } )
      message = "关闭扫描状态改变事件"
    } else {
      wifiManager.on( "wifiScanStateChange" , ( number ) => {
        let wifiScanStateMessage = ""
        switch ( number ) {
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
        prompt.showToast( { message : "状态: " + wifiScanStateMessage } )
        console.log( LogDataManager.testOnWifiScanStateChangeManager_EndLog );
      } )
      message = "打开注册扫描状态变化"
      prompt.showToast( { message : message } )
    }
    wifiScanStateChangeManager = !wifiScanStateChangeManager
    return message
  } catch( e ) {
    console.log( `Failed to testOnWifiScanStateChangeManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testOnWifiScanStateChangeManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let wifiRssiChangeManager = false

export function testOnWifiRssiChangeManager() {
  try {
    let message = "OnWifiRssiChange test"
    console.log( LogDataManager.testOnWifiRssiChangeManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
      return message
    }
    if ( wifiRssiChangeManager ) {
      wifiManager.off( "wifiRssiChange" , () => {
        prompt.showToast( { message : "on.wifiRssiChange监听已关闭" } )
      } )
      message = "关闭RSSI状态变化事件"
    } else {
      wifiManager.on( "wifiRssiChange" , ( number ) => {
        prompt.showToast( { message : "rssi: " + number } )
      } )
      message = "打开注册RSSI状态变化"
      console.log( LogDataManager.testOnWifiRssiChangeManager_EndLog );
      prompt.showToast( { message : message } )
    }
    wifiRssiChangeManager = !wifiRssiChangeManager
    return message
  } catch( e ) {
    console.log( `Failed to testOnWifiRssiChangeManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testOnWifiRssiChangeManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let streamChangeManager = false

export function testOnStreamChangeManager() {
  try {
    let message = "onStreamChange test"
    console.log( LogDataManager.testOnStreamChangeManager_StartLog );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
      return message
    }
    if ( streamChangeManager ) {
      wifiManager.off( "streamChange" , () => {
        prompt.showToast( { message : "on.streamChange监听已关闭" } )
      } )
      message = "关闭注册流改变事件"
    } else {
      wifiManager.on( "streamChange" , ( number ) => {
        let streamChangeMessage = ""
        switch ( number ) {
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
        prompt.showToast( { message : "状态:" + streamChangeMessage } )
        console.log( LogDataManager.testOnStreamChangeManager_EndLog );
      } )
      message = "打开注册流变化"
      prompt.showToast( { message : message } )
    }
    streamChangeManager = !streamChangeManager
    return message
  } catch( e ) {
    console.log( `Failed to testOnStreamChangeManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testOnStreamChangeManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let deviceConfigChange = false

export function testOnDeviceConfigChangeManager() {
  try {
    let message = "OnDeviceConfigChange test"
    console.log( LogDataManager.testOnDeviceConfigChangeManager_StartLog );
    console.log( "testOnDeviceConfigChange test" );
    if ( !wifiManagerEnable ) {
      message = ( MessageDataManager.testIsInactive );
      return message
    }
    if ( deviceConfigChange ) {
      wifiManager.off( "deviceConfigChange" , () => {
        prompt.showToast( { message : "on.deviceConfigChange监听已关闭" } )
      } )
      message = "关闭注册设备配置改变事件"
    } else {
      wifiManager.on( "deviceConfigChange" , ( number ) => {
        let deviceConfigMessage = ""
        switch ( number ) {
          case 0:
            deviceConfigMessage = "config is added";
            break;
          case 1:
            deviceConfigMessage = "config is changed";
            break;
          case 2:
            deviceConfigMessage = "config is removed";
            break;
          default:
            deviceConfigMessage = '未知状态';
            break;
        }
        prompt.showToast( { message : "状态:" + deviceConfigMessage } )
        console.log( LogDataManager.testOnDeviceConfigChangeManager_EndLog );
      } )
      message = "打开注册设备配置变化"
      prompt.showToast( { message : message } )
    }
    deviceConfigChange = !deviceConfigChange
    return message
  } catch( e ) {
    console.log( `Failed to testOnDeviceConfigChangeManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testOnDeviceConfigChangeManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}