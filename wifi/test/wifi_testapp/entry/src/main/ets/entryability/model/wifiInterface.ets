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
import wifi from '@ohos.wifi';
import LogData from "../../utils/LogData"
import MessageData from "../../utils/MessageData"

const TAG = "[wifiInterface]";
/**
 * Wifi api Test Page Of wifi test
 */

const PAGE_URI_WIFI_FOUND_MODE = 'pages/subManualApiTest/subWifiTest/wifiFound';
let wifiEnable = false

export function testEnableWifi(): string {
  try {
    let message = ( MessageData.testEnableWifi );
    console.log( TAG , LogData.testEnableWifi_StartLog )
    if ( wifiEnable ) {
      message = ( MessageData.testIsActive )
    } else {
      let ret = wifi.enableWifi();
      if ( ret ) {
        message = ( MessageData.testWifiEnableResult ) + ret
      } else {
        message = ( MessageData.testEnableResult ) + ret + "\n"
        message += ( MessageData.testWifiEnableMaybe )
      }
      wifiEnable = true;
      AppStorage.SetOrCreate( 'wifiIsOn' , wifiEnable );
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testEnableWifi_EndLog )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testEnableWifi. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testEnableWifi. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testDisableWifi(): string {
  try {
    let message = ( MessageData.testDisableWifi );
    console.log( TAG , LogData.testDisableWifi_StartLog )
    if ( !wifiEnable ) {
      message = ( LogData.testIsInactive );
    } else {
      let ret = wifi.disableWifi();
      if ( ret ) {
        message = ( MessageData.testWifiDisableResult ) + ret
      } else {
        message = ( MessageData.testDisableResult ) + ret + "\n"
        message += ( MessageData.testWifiDisableMaybe )
      }
      wifiEnable = false;
      AppStorage.SetOrCreate( 'wifiIsOn' , wifiEnable );
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testDisableWifi_EndLog )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testDisableWifi. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testDisableWifi. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testIsWifiActive(): string {
  try {
    let message = ( MessageData.testIsActive );
    console.log( TAG , LogData.testIsWifiActive_StartLog )
    let ret = wifi.isWifiActive();
    if ( ret ) {
      wifiEnable = true
    } else {
      wifiEnable = false
    }
    message = ( MessageData.testIsActiveResult ) + ret
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testIsWifiActive_EndLog )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testIsWifiActive. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testIsWifiActive. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testScan(): string {
  try {
    let message = ( MessageData.testScan )
    console.log( TAG , LogData.testScan_StartLog )
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      let ret = wifi.scan()
      message = ( MessageData.testScanResult ) + ret
      Router.push( { uri : PAGE_URI_WIFI_FOUND_MODE } );
      prompt.showToast( { message : message } )
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testScan_EndLog )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testScan. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testScan. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testForcibleScan(): string {
  try {
    let message = ( MessageData.testForcibleScan )
    console.log( TAG , LogData.testForcibleScan_StartLog )
    let ret = wifi.scan()
    message = ( MessageData.testForcibleScanResult ) + ret
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testForcibleScan_EndLog )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testForcibleScan. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testForcibleScan. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetScanInfosPromise(): string {
  try {
    let message = ( MessageData.testGetScanInfosPromise )
    console.log( TAG , LogData.testGetScanInfosPromise_StartLog )
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      wifi.getScanInfos().then( result => {
        let len = Object.keys( result ).length;
        console.log( TAG , LogData.testGetScanInfos_infoLog + len );
        for ( let i = 0 ; i < len ; ++i ) {
          console.log( TAG , "ssid: " + result[i].ssid );
          console.log( TAG , "bssid: " + result[i].bssid );
          console.log( TAG , "capabilities: " + result[i].capabilities );
          console.log( TAG , "securityType: " + result[i].securityType );
          console.log( TAG , "rssi: " + result[i].rssi );
          console.log( TAG , "band: " + result[i].band );
          console.log( TAG , "frequency: " + result[i].frequency );
          console.log( TAG , "channelWidth: " + result[i].channelWidth );
          console.log( TAG , "timestamp: " + result[i].timestamp );
        }
        console.log( TAG , LogData.testGetScanInfosPromise_successfulLog )
        message = ( MessageData.testGetScanInfo ) + JSON.stringify( result )
        prompt.showToast( { message : message } )
        console.log( TAG , LogData.testGetScanInfosPromise_EndLog )
      } ).catch( error => {
        console.log( TAG , "testGetScanInfosPromise error:" + error )
      } )
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testGetScanInfosPromise. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetScanInfosPromise. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetScanInfosCallback(): string {
  try {
    let message = ( MessageData.testGetScanInfosCallback )
    console.log( TAG , LogData.testGetScanInfosCallback_StartLog )
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      wifi.getScanInfos( ( err , result ) => {
        if ( err ) {
          console.log( TAG , "get scan info error" );
          return;
        }
        let len = Object.keys( result ).length;
        console.log( TAG , LogData.testGetScanInfos_infoLog + len )
        for ( let i = 0 ; i < len ; ++i ) {
          console.log( TAG , "ssid: " + result[i].ssid );
          console.log( TAG , "bssid: " + result[i].bssid );
          console.log( TAG , "capabilities: " + result[i].capabilities );
          console.log( TAG , "securityType: " + result[i].securityType );
          console.log( TAG , "rssi: " + result[i].rssi );
          console.log( TAG , "band: " + result[i].band );
          console.log( TAG , "frequency: " + result[i].frequency );
          console.log( TAG , "channelWidth: " + result[i].channelWidth );
          console.log( TAG , "timestamp: " + result[i].timestamp );
        }
        console.log( TAG , LogData.testGetScanInfosCallback_successfulLog )
        message = ( MessageData.testGetScanInfo ) + JSON.stringify( result )
        let getScanInfoMessage = JSON.stringify( result )
        AppStorage.SetOrCreate( "getScanInfoMessage" , getScanInfoMessage )
        prompt.showToast( { message : message } )
        console.log( TAG , LogData.testGetScanInfosCallback_EndLog )
      } );
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testGetScanInfosCallback. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetScanInfosCallback. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

//TODO: 设备调试时候需要打开
//let ssid = "TP-LINK_6365"
//let bssid = "6C:B1:58:75:63:65"
//let preSharedKey = "12345678"
//let isHiddenSsid = false
//let securityType = 3
//let creatorUid = 1
//let disableReason = 0
//let netId = 0
//let randomMacType = 0
//let randomMacAddr = "08:fb:ea:1b:38:aa"
//let ipType = 1
//let staticIp_ipAddress = 3232235880
//let staticIp_gateway = 3232235777
//let staticIp_dnsServers = 3716386629
//let staticIp_domains = [ "0", "1", "2" ]
//
//let staticIp = {
//  ipAddress : staticIp_ipAddress ,
//  gateway : staticIp_gateway ,
//  dnsServers : staticIp_dnsServers ,
//  domains : staticIp_domains
//}
//
//let wifiDeviceConfig = {
//  ssid : ssid ,
//  bssid : bssid ,
//  preSharedKey : preSharedKey ,
//  isHiddenSsid : isHiddenSsid ,
//  securityType : securityType ,
//  creatorUid : creatorUid ,
//  disableReason : disableReason ,
//  netId : netId ,
//  randomMacType : randomMacType ,
//  randomMacAddr : randomMacAddr ,
//  ipType : ipType ,
//  staticIp : staticIp
//}
//AppStorage.SetOrCreate( "wifiDeviceConfig" , wifiDeviceConfig )

export function testAddDeviceConfigPromise(): string {
  try {
    let message = ( MessageData.testAddDeviceConfigPromise )
    console.log( TAG , LogData.testAddDeviceConfigPromise_StartLog )
    let ssid = AppStorage.Get( "w_ssid" )
    let bssid = AppStorage.Get( "w_bssid" )
    let preSharedKey = AppStorage.Get( "w_preSharedKey" )
    let isHiddenSsid = AppStorage.Get( "w_isHiddenSsid" )
    let securityType = AppStorage.Get( "w_securityType" )
    let creatorUid = AppStorage.Get( "w_creatorUid" )
    let disableReason = AppStorage.Get( "w_disableReason" )
    let netId = AppStorage.Get( "w_netId" )
    let randomMacType = AppStorage.Get( "w_randomMacType" )
    let randomMacAddr = AppStorage.Get( "w_randomMacAddr" )
    let ipType = AppStorage.Get( "w_ipType" )
    let staticIp_ipAddress = AppStorage.Get( "w_staticIp_ipAddress" )
    let staticIp_gateway = AppStorage.Get( "w_staticIp_gateway" )
    let staticIp_dnsServers = AppStorage.Get( "w_staticIp_dnsServers" )
    let staticIp_domains = AppStorage.Get( "w_staticIp_domains" )

    let staticIp = {
      ipAddress : staticIp_ipAddress ,
      gateway : staticIp_gateway ,
      dnsServers : staticIp_dnsServers ,
      domains : staticIp_domains
    }
    let wifiDeviceConfig = {
      ssid : ssid ,
      bssid : bssid ,
      preSharedKey : preSharedKey ,
      isHiddenSsid : isHiddenSsid ,
      securityType : securityType ,
      creatorUid : creatorUid ,
      disableReason : disableReason ,
      netId : netId ,
      randomMacType : randomMacType ,
      randomMacAddr : randomMacAddr ,
      ipType : ipType ,
      staticIp : staticIp
    }
    AppStorage.SetOrCreate( "wifiDeviceConfig" , wifiDeviceConfig )
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      let wifiDeviceConfig = AppStorage.Get( "wifiDeviceConfig" )
      wifi.addDeviceConfig( wifiDeviceConfig ).then( result => {
        //  @returns Returns {@code networkId} if the configuration is added; returns {@code -1} otherwise.
        console.log( TAG , LogData.testAddDeviceConfigPromise_successfulLog )
        console.log( TAG , LogData.testAddDeviceConfigLog + result )
        message = ( MessageData.testAddDeviceConfig ) + result
        prompt.showToast( { message : message } )
        console.log( TAG , LogData.testAddDeviceConfigPromise_EndLog )
      } ).catch( error => {
        console.log( TAG , "testAddDeviceConfigPromise error:" + error );
      } )
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testAddDeviceConfigPromise. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testAddDeviceConfigPromise. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testAddDeviceConfigCallback(): string {
  try {
    let message = ( MessageData.testAddDeviceConfigCallback )
    console.log( TAG , LogData.testAddDeviceConfigCallback_StartLog )

    //TODO: 设备调试时候需要打开
    let ssid = AppStorage.Get( "w_ssid" )
    let bssid = AppStorage.Get( "w_bssid" )
    let preSharedKey = AppStorage.Get( "w_preSharedKey" )
    let isHiddenSsid = AppStorage.Get( "w_isHiddenSsid" )
    let securityType = AppStorage.Get( "w_securityType" )
    let creatorUid = AppStorage.Get( "w_creatorUid" )
    let disableReason = AppStorage.Get( "w_disableReason" )
    let netId = AppStorage.Get( "w_netId" )
    let randomMacType = AppStorage.Get( "w_randomMacType" )
    let randomMacAddr = AppStorage.Get( "w_randomMacAddr" )
    let ipType = AppStorage.Get( "w_ipType" )
    let staticIp_ipAddress = AppStorage.Get( "w_staticIp_ipAddress" )
    let staticIp_gateway = AppStorage.Get( "w_staticIp_gateway" )
    let staticIp_dnsServers = AppStorage.Get( "w_staticIp_dnsServers" )
    let staticIp_domains = AppStorage.Get( "w_staticIp_domains" )
    let staticIp = {
      ipAddress : staticIp_ipAddress ,
      gateway : staticIp_gateway ,
      dnsServers : staticIp_dnsServers ,
      domains : staticIp_domains
    }
    let wifiDeviceConfig = {
      ssid : ssid ,
      bssid : bssid ,
      preSharedKey : preSharedKey ,
      isHiddenSsid : isHiddenSsid ,
      securityType : securityType ,
      creatorUid : creatorUid ,
      disableReason : disableReason ,
      netId : netId ,
      randomMacType : randomMacType ,
      randomMacAddr : randomMacAddr ,
      ipType : ipType ,
      staticIp : staticIp
    }
    AppStorage.SetOrCreate( "wifiDeviceConfig" , wifiDeviceConfig )

    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive )
    } else {
      let wifiDeviceConfig = AppStorage.Get( "wifiDeviceConfig" )
      wifi.addDeviceConfig( wifiDeviceConfig , ( err , result ) => {
        //  @returns Returns {@code networkId} if the configuration is added; returns {@code -1} otherwise.
        if ( err ) {
          console.log( TAG , "addDeviceConfigCallback error:" + err );
          return;
        }
        console.log( TAG , LogData.testAddDeviceConfigCallback_successfulLog )
        console.log( TAG , LogData.testAddDeviceConfigLog + result )
        message = ( MessageData.testAddDeviceConfig ) + result
        prompt.showToast( { message : message } )
        console.log( TAG , LogData.testAddDeviceConfigCallback_EndLog )
      } );
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testAddDeviceConfigCallback. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testAddDeviceConfigCallback. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testAddUntrustedConfigPromise(): string {
  try {
    let message = ( MessageData.testAddUntrustedConfigPromise )
    console.log( TAG , LogData.testAddUntrustedConfigPromise_StartLog )
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive )
    } else {
      let wifiDeviceConfig = AppStorage.Get( "wifiDeviceConfig" )
      wifi.addUntrustedConfig( wifiDeviceConfig ).then( result => {
        //  @returns Returns {@code true} if the untrusted hotspot configuration is added, returns {@code false} otherwise.
        console.log( TAG , LogData.testAddUntrustedConfigPromise_successfulLog )
        console.log( TAG , LogData.testAddUntrustedConfigLog + result )
        message = ( MessageData.testAddUntrustedConfig ) + result
        prompt.showToast( { message : message } )
        console.log( TAG , LogData.testAddUntrustedConfigPromise_EndLog )
      } ).catch( error => {
        console.log( TAG , "testAddUntrustedConfigPromise error:" + error )
      } )
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testAddUntrustedConfigPromise. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testAddUntrustedConfigPromise. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testAddUntrustedConfigCallback(): string {
  try {
    let message = ( MessageData.testAddUntrustedConfigCallback )
    console.log( TAG , LogData.testAddUntrustedConfigCallback_StartLog )
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive )
    } else {
      let wifiDeviceConfig = AppStorage.Get( "wifiDeviceConfig" )
      wifi.addUntrustedConfig( wifiDeviceConfig , ( err , result ) => {
        //  @returns Returns {@code true} if the untrusted hotspot configuration is added, returns {@code false} otherwise.
        if ( err ) {
          console.log( TAG , "AddUntrustedConfigCallback error" );
          return;
        }
        console.log( TAG , LogData.testAddUntrustedConfigCallback_successfulLog )
        console.log( TAG , LogData.testAddUntrustedConfigLog + result )
        message = ( MessageData.testAddUntrustedConfig ) + result
        prompt.showToast( { message : message } )
        console.log( TAG , LogData.testAddUntrustedConfigCallback_EndLog )
      } )
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testAddUntrustedConfigCallback. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testAddUntrustedConfigCallback. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testRemoveUntrustedConfigPromise(): string {
  try {
    let message = ( MessageData.testRemoveUntrustedConfigPromise )
    console.log( TAG , LogData.testRemoveUntrustedConfigPromise_StartLog )
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive )
    } else {
      let wifiDeviceConfig = AppStorage.Get( "wifiDeviceConfig" )
      wifi.removeUntrustedConfig( wifiDeviceConfig ).then( result => {
        //  @returns Returns {@code true} if the untrusted hotspot configuration is removed, returns {@code false} otherwise.
        console.log( TAG , LogData.testRemoveUntrustedConfigLog + result )
        console.log( TAG , LogData.testRemoveUntrustedConfigPromise_successfulLog )
        message = ( MessageData.testRemoveUntrustedConfig ) + result
        prompt.showToast( { message : message } )
        console.log( TAG , LogData.testRemoveUntrustedConfigPromise_EndLog )
      } ).catch( error => {
        console.log( TAG , "testRemoveUntrustedConfigPromise error:" + error )
      } )
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testRemoveUntrustedConfigPromise. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testRemoveUntrustedConfigPromise. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testRemoveUntrustedConfigCallback(): string {
  try {
    let message = ( MessageData.testRemoveUntrustedConfigCallback )
    console.log( TAG , LogData.testRemoveUntrustedConfigCallback_StartLog )
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive )
    } else {
      let wifiDeviceConfig = AppStorage.Get( "wifiDeviceConfig" )
      wifi.removeUntrustedConfig( wifiDeviceConfig , ( err , result ) => {
        //  @returns Returns {@code true} if the untrusted hotspot configuration is removed, returns {@code false} otherwise.
        if ( err ) {
          console.log( TAG , "removeUntrustedConfigCallback error" );
          return;
        }
        console.log( TAG , LogData.testRemoveUntrustedConfigLog + result )
        console.log( TAG , LogData.testRemoveUntrustedConfigCallback_successfulLog )
        message = ( MessageData.testRemoveUntrustedConfig ) + result
        prompt.showToast( { message : message } )
        console.log( TAG , LogData.testRemoveUntrustedConfigCallback_EndLog )
      } )
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testRemoveUntrustedConfigCallback. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testRemoveUntrustedConfigCallback. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testConnectToNetwork(): string {
  try {
    let message = ( MessageData.testConnectToNetwork )
    console.log( TAG , LogData.testConnectToNetwork_StartLog )
    //testGetLinkedInfoCallback()获取的，可能也是wifiDeviceConfig中的netId
    let networkId = AppStorage.Get( "w_networkId" )
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive )
    } else {
      let ret = wifi.connectToNetwork( networkId )
      message = "ConnectToNetwork: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testConnectToNetwork_EndLog )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testConnectToNetwork. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testConnectToNetwork. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testConnectToDevice(): string {
  try {
    let message = ( MessageData.testConnectToDevice )
    console.log( TAG , LogData.testConnectToDevice_StartLog )
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive )
    } else {
      let wifiDeviceConfig = AppStorage.Get( "wifiDeviceConfig" )
      let ret = wifi.connectToDevice( wifiDeviceConfig )
      message = "ConnectToDevice: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testConnectToDevice_EndLog )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testConnectToDevice. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testConnectToDevice. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testDisconnect(): string {
  try {
    let message = ( MessageData.testDisconnect )
    console.log( TAG , LogData.testDisconnect_StartLog )
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive )
    } else {
      let ret = wifi.disconnect()
      message = "disconnect: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testDisconnect_EndLog )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testDisconnect. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testDisconnect. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetLinkedInfoPromise(): string {
  try {
    let message = ( MessageData.testGetLinkedInfoPromise )
    console.log( TAG , LogData.testGetLinkedInfoPromise_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive )
    } else {
      wifi.getLinkedInfo().then( data => {
        console.log( TAG , LogData.testGetLinkedInfoPromise_successful )
        message = "get wifi linked info: " + JSON.stringify( data )
        console.log( TAG , "get wifi linked info: " + JSON.stringify( data ) );
        prompt.showToast( { message : message } )
        console.log( TAG , LogData.testGetLinkedInfoPromise_EndLog );
      } ).catch( error => {
        console.log( TAG , "get linked info error" );
        console.log( TAG , "error:" + error )
      } );
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testGetLinkedInfoPromise. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetLinkedInfoPromise. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetLinkedInfoCallback(): string {
  try {
    let message = ( MessageData.testGetLinkedInfoCallback )
    console.log( TAG , LogData.testGetLinkedInfoCallback_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive )
    } else {
      wifi.getLinkedInfo( ( err , data ) => {
        if ( err ) {
          console.log( TAG , "get linked info error" );
          message = "get linked info error"
          prompt.showToast( { message : message } )
        }
        console.log( TAG , LogData.testGetLinkedInfoCallback_successful )
        console.log( TAG , "get wifi linked info: " + JSON.stringify( data ) );
        message = "get wifi linked info: " + JSON.stringify( data )
        let linkedInfoMessage = JSON.stringify( data )
        AppStorage.SetOrCreate( "linkedInfoMessage" , linkedInfoMessage )
        let ssid = data.ssid
        AppStorage.SetOrCreate( "pairedSsid" , ssid )
        let rssi = data.rssi
        let band = data.band
        let networkId = data.networkId
        AppStorage.SetOrCreate( "w_rssi" , rssi )
        AppStorage.SetOrCreate( "w_band" , band )
        AppStorage.SetOrCreate( "w_networkId" , networkId )
        prompt.showToast( { message : message } )
        console.log( TAG , LogData.testGetLinkedInfoCallback_EndLog );
      } )
    }
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testGetLinkedInfoCallback. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetLinkedInfoCallback. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetSignalLevel(): string {
  try {
    let message = ( MessageData.testGetSignalLevel )
    console.log( TAG , LogData.testGetSignalLevel_StartLog )
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive )
    } else {
      //testGetLinkedInfoCallback()获取的
      let rssi = AppStorage.Get( "w_rssi" )
      let band = AppStorage.Get( "w_band" )
      let number = wifi.getSignalLevel( rssi , band )
      message = "getSignalLevel is: " + number
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testGetSignalLevel_EndLog )
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testGetSignalLevel. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetSignalLevel. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testIsConnected(): string {
  try {
    let message = ( MessageData.testIsConnected )
    console.log( TAG , LogData.testIsConnected_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      let ret = wifi.isConnected()
      message = "isConnected: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testIsConnected_EndLog );
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testIsConnected. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testIsConnected. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetSupportedFeatures(): string {
  try {
    let message = ( MessageData.testGetSupportedFeatures )
    console.log( TAG , LogData.testGetSupportedFeatures_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      let ret = wifi.getSupportedFeatures()
      message = "GetSupportedFeatures: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testGetSupportedFeatures_EndLog );
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testGetSupportedFeatures. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetSupportedFeatures. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testIsFeatureSupported(): string {
  try {
    let message = ( MessageData.testIsFeatureSupported )
    console.log( TAG , LogData.testIsFeatureSupported_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      let featureId = AppStorage.Get( "w_featureId" )
      let ret = wifi.isFeatureSupported( featureId )
      message = "isFeatureSupported: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testIsFeatureSupported_EndLog );
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testIsFeatureSupported. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testIsFeatureSupported. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetDeviceMacAddress(): string {
  try {
    let message = ( MessageData.testGetDeviceMacAddress )
    console.log( TAG , LogData.testGetDeviceMacAddress_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      let macAddress = wifi.getDeviceMacAddress()
      message = "macAddress: " + macAddress
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testGetDeviceMacAddress_EndLog );
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testGetDeviceMacAddress. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetDeviceMacAddress. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetIpInfo(): string {
  try {
    let message = ( MessageData.testGetIpInfo )
    console.log( TAG , LogData.testGetIpInfo_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      let IpInfo = wifi.getIpInfo()
      message = "IpInfo: " + JSON.stringify( IpInfo )
      let ipInfoMessage = message
      AppStorage.SetOrCreate( "ipInfoMessage" , ipInfoMessage )
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testGetIpInfo_EndLog );
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testGetIpInfo. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetIpInfo. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetCountryCode(): string {
  try {
    let message = ( MessageData.testGetCountryCode )
    console.log( TAG , LogData.testGetCountryCode_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      let ret = wifi.getCountryCode()
      message = "CountryCode is: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testGetCountryCode_EndLog );
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testGetCountryCode. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetCountryCode. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testReassociate(): string {
  try {
    let message = ( MessageData.testReassociate )
    console.log( TAG , LogData.testReassociate_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      let ret = wifi.reassociate()
      message = "reassociate is: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testReassociate_EndLog );
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testReassociate. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testReassociate. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testReConnect(): string {
  try {
    let message = ( MessageData.testReConnect )
    console.log( TAG , LogData.testReConnect_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      let ret = wifi.reconnect()
      message = "reConnect is: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testReConnect_EndLog );
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testReConnect. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testReConnect. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetDeviceConfigs() {
  try {
    let message = ( MessageData.testGetDeviceConfigs )
    console.log( TAG , LogData.testGetDeviceConfigs_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      let array = wifi.getDeviceConfigs()
      message = "DeviceConfigs is: " + JSON.stringify( array )
      let getDeviceConfigsMessage = JSON.stringify( array )
      AppStorage.SetOrCreate( "getDeviceConfigsMessage" , getDeviceConfigsMessage )
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testGetDeviceConfigs_EndLog );
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testGetDeviceConfigs. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetDeviceConfigs. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testUpdateNetwork() {
  try {
    let message = ( MessageData.testUpdateNetwork )
    console.log( TAG , LogData.testUpdateNetwork_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      let wifiDeviceConfig = AppStorage.Get( "wifiDeviceConfig" )
      let ret = wifi.updateNetwork( wifiDeviceConfig )
      message = "updateNetwork: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testUpdateNetwork_EndLog );
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testUpdateNetwork. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testUpdateNetwork. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testDisableNetwork() {
  try {
    let message = ( MessageData.testDisableNetwork )
    console.log( TAG , LogData.testDisableNetwork_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      let netId = AppStorage.Get( "w_netId" )
      let ret = wifi.disableNetwork( netId )
      message = "disableNetwork: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testDisableNetwork_EndLog );
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testDisableNetwork. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testDisableNetwork. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testRemoveAllNetwork() {
  try {
    let message = ( MessageData.testRemoveAllNetwork )
    console.log( TAG , LogData.testRemoveAllNetwork_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      let ret = wifi.removeAllNetwork()
      message = "removeAllNetwork: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testRemoveAllNetwork_EndLog );
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testRemoveAllNetwork. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testRemoveAllNetwork. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testRemoveDevice() {
  try {
    let message = ( MessageData.testRemoveDevice )
    console.log( TAG , LogData.testRemoveDevice_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
    } else {
      //testGetLinkedInfoCallback()获取的，可能也是wifiDeviceConfig中的netId
      let id = AppStorage.Get( "w_networkId" )
      let ret = wifi.removeDevice( id )
      message = "removeDevice: " + ret
    }
    prompt.showToast( { message : message } )
    console.log( TAG , LogData.testRemoveDevice_EndLog );
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testRemoveDevice. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testRemoveDevice. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}


let wifiStateChange = false

export function testOnWifiStateChange(): string {
  try {
    let message = ( MessageData.testOnWifiStateChange )
    console.log( TAG , LogData.testOnWifiStateChange_StartLog );
    if ( wifiStateChange ) {
      wifi.off( "wifiStateChange" , () => {
        prompt.showToast( { message : ( MessageData.offWifiStateChange ) } )
      } )
      message = ( MessageData.offWifiStateChangeTest )
    } else {
      wifi.on( "wifiStateChange" , ( number ) => {
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
        prompt.showToast( { message : "wifi状态: " + wifiStateMessage } )
        console.log( TAG , LogData.testOnWifiStateChange_EndLog );
      } )
      message = ( MessageData.onWifiStateChangeTest )
      prompt.showToast( { message : message } )
    }
    wifiStateChange = !wifiStateChange
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testOnWifiStateChange. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testOnWifiStateChange. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let wifiConnectionChange = false

export function testOnWifiConnectionChange(): string {
  try {
    let message = ( MessageData.testOnWifiConnectionChange )
    console.log( TAG , LogData.testOnWifiConnectionChange_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
      return message
    }
    if ( wifiConnectionChange ) {
      wifi.off( "wifiConnectionChange" , () => {
        prompt.showToast( { message : ( MessageData.offWifiConnectionChange ) } )
      } )
      message = ( MessageData.offWifiConnectionChangeTest )
    } else {
      wifi.on( "wifiConnectionChange" , ( number ) => {
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
        prompt.showToast( { message : "连接状态: " + wifiConnectionMessage } )
        console.log( TAG , LogData.testOnWifiConnectionChange_EndLog );
      } )
      message = ( MessageData.onWifiConnectionChangeTest )
      prompt.showToast( { message : message } )
    }
    wifiConnectionChange = !wifiConnectionChange
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testOnWifiConnectionChange. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testOnWifiConnectionChange. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let wifiScanStateChange = false

export function testOnWifiScanStateChange(): string {
  try {
    let message = ( MessageData.testOnWifiScanStateChange )
    console.log( TAG , LogData.testOnWifiScanStateChange_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
      return message
    }
    if ( wifiScanStateChange ) {
      wifi.off( "wifiScanStateChange" , () => {
        prompt.showToast( { message : ( MessageData.offWifiScanStateChange ) } )
      } )
      message = ( MessageData.offWifiScanStateChangeTest )
    } else {
      wifi.on( "wifiScanStateChange" , ( number ) => {
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
        prompt.showToast( { message : "scan状态: " + wifiScanStateMessage } )
        console.log( TAG , LogData.testOnWifiScanStateChange_EndLog );
      } )
      message = ( MessageData.onWifiScanStateChangeTest )
      prompt.showToast( { message : message } )
    }
    wifiScanStateChange = !wifiScanStateChange
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testOnWifiScanStateChange. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testOnWifiScanStateChange. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let wifiRssiChange = false

export function testOnWifiRssiChange(): string {
  try {
    let message = ( $r( 'app.string.testOnWifiRssiChange' ) )
    console.log( TAG , LogData.testOnWifiRssiChange_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
      return message
    }
    if ( wifiRssiChange ) {
      wifi.off( "wifiRssiChange" , () => {
        prompt.showToast( { message : ( $r( 'app.string.offWifiRssiChange' ) ) } )
      } )
      message = "关闭RSSI状态变化事件"
    } else {
      wifi.on( "wifiRssiChange" , ( number ) => {
        prompt.showToast( { message : "rssi: " + number } )
      } )
      message = "打开注册RSSI状态变化"
      console.log( TAG , LogData.testOnWifiRssiChange_EndLog );
      prompt.showToast( { message : message } )
    }
    wifiRssiChange = !wifiRssiChange
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testOnWifiRssiChange. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testOnWifiRssiChange. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let streamChange = false

export function testOnStreamChange() {
  try {
    let message = ( MessageData.testOnStreamChange )
    console.log( TAG , LogData.testOnStreamChange_StartLog );
    if ( !wifiEnable ) {
      message = ( MessageData.testIsInactive );
      return message
    }
    if ( streamChange ) {
      wifi.off( "streamChange" , () => {
        prompt.showToast( { message : ( MessageData.offStreamChange ) } )
      } )
      message = MessageData.offStreamChangeTest
    } else {
      wifi.on( "streamChange" , ( number ) => {
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
        prompt.showToast( { message : "stream状态: " + streamChangeMessage } )
        console.log( TAG , LogData.testOnStreamChange_EndLog );
      } )
      message = ( MessageData.onStreamChangeTest )
      prompt.showToast( { message : message } )
    }
    streamChange = !streamChange
    return message
  } catch( e ) {
    console.log( TAG , `Failed to testOnStreamChange. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testOnStreamChange. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}
