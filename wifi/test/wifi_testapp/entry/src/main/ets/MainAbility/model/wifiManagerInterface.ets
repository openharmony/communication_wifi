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
import LogData from "../../Utils/LogData"
import MessageData from "../../Utils/MessageData"

/**
 * WifiManager api Test Page Of wifi test
 */

let wifiManagerEnable = false

export function testEnableWifiManager() {
  try {
    let message = ( $r( 'app.string.testEnableWifi' ) )
    if ( wifiManagerEnable ) {
      message = "wifi已经使能"
    } else {
      let ret = wifiManager.enableWifi();
      if ( ret ) {
        message = "Wifi已打开或打开失败,请确认"
      }
      wifiManagerEnable = true;
      AppStorage.SetOrCreate( 'wifiManagerIsOn' , wifiManagerEnable );
    }
    prompt.showToast( { message : message } )
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
    let message = "disableWifi test"
    if ( !wifiManagerEnable ) {
      message = 'WIFI还未使能';
    } else {
      let ret = wifiManager.disableWifi();
      if ( ret ) {
        message += "Wifi已关闭或关闭失败,请确认"
      }
      wifiManagerEnable = false;
      AppStorage.SetOrCreate( 'wifiManagerIsOn' , wifiManagerEnable );
    }
    prompt.showToast( { message : message } )
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
    let message = "isWifiActive test"
    let ret = wifiManager.isWifiActive();
    if ( ret ) {
      wifiManagerEnable = true
    } else {
      wifiManagerEnable = false
    }
    message = "wifi使能结果为：" + ret;
    //  }
    prompt.showToast( { message : message } )
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
    let message = "scan test"
    if ( !wifiManagerEnable ) {
      message = 'WIFI还未使能';
    } else {
      let ret = wifiManager.scan()
      message = "scan: " + ret
      //    Router.push({ uri: PAGE_URI_WIFI_FOUND_MODE });
      prompt.showToast( { message : message } )
    }
    prompt.showToast( { message : message } )
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
    let message = "getScanInfoList test"
    console.log( "testGetScanInfoListManager start---------" );
    let ret = wifiManager.getScanInfoList()
    message = "扫描结果为：" + JSON.stringify( ret )
    let getScanInfoManagerMessage = ret
    AppStorage.SetOrCreate( "getScanInfoManagerMessage" , getScanInfoManagerMessage )
    console.log( "testGetScanInfoListManager end---------" );
    prompt.showToast( { message : message } )
    return message
  } catch( e ) {
    console.log( `Failed to testGetScanInfoListManager. message: ${ e.message }, code: ${ e.code }` )
    let message = `Failed to testGetScanInfoListManager. message: ${ e.message }, code: ${ e.code }`
    prompt.showToast( { message : message } )
    return message
  }
}


let ssid1 = "TP-LINK_6365"
let bssid1 = "6C:B1:58:75:63:65"
let preSharedKey1 = "kaihong123"
let isHiddenSsid1 = false
let securityType1 = 3
let creatorUid1 = 1
let disableReason1 = 0
let netId1 = 0
let randomMacType1 = 0
let randomMacAddr1 = "08:fb:ea:1b:38:aa"
let ipType1 = 1
let staticIp_ipAddress1 = 3232235880
let staticIp_gateway1 = 3232235777
let staticIp_dnsServers1 = 3716386629
let staticIp_domains1 = [ "0", "1", "2" ]

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

export function testAddDeviceConfigManagerPromise() {
  try {
    let message = "addDeviceConfigPromise test"
    let ssid1: string = AppStorage.Get( "ssidManager1" )
    let bssid1: string = AppStorage.Get( "bssidManager1" )
    let preSharedKey1: string = AppStorage.Get( "preSharedKeyManager1" )
    let isHiddenSsid1: boolean = AppStorage.Get( "isHiddenSsidManager1" )
    let securityType1 = AppStorage.Get( "securityTypeManager1" )
    let creatorUid1 = AppStorage.Get( "creatorUidManager1" )
    let disableReason1 = AppStorage.Get( "disableReasonManager1" )
    let netId1 = AppStorage.Get( "netIdManager1" )
    let randomMacType1 = AppStorage.Get( "randomMacTypeManager1" )
    let randomMacAddr1 = AppStorage.Get( "randomMacAddrManager1" )
    let ipType1 = AppStorage.Get( "ipTypeManager1" )
    let staticIp_ipAddress1 = AppStorage.Get( "staticIp_ipAddressManager1" )
    let staticIp_gateway1 = AppStorage.Get( "staticIp_gatewayManager1" )
    let staticIp_dnsServers1 = AppStorage.Get( "staticIp_dnsServersManager1" )
    let staticIp_domains1 = AppStorage.Get( "staticIp_domainsManager1" )
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
      message = "WIFI还未使能";
    } else {
      wifiManager.addDeviceConfig( wifiDeviceConfigManager ).then( result => {
        //  @returns Returns {@code networkId} if the configuration is added; returns {@code -1} otherwise.
        message = "addDeviceConfig: " + result
        prompt.showToast( { message : message } )
      } ).catch(err=>{
        console.log("testAddDeviceConfigManagerPromise error:"+err)
      })
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
    let message = "addDeviceConfigCallback test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let wifiDeviceConfigManager = AppStorage.Get( "wifiDeviceConfigManager" )
      wifiManager.addDeviceConfig( wifiDeviceConfigManager , ( err , result ) => {
        //  @returns Returns {@code networkId} if the configuration is added; returns {@code -1} otherwise.
        if ( err ) {
          console.error( "addDeviceConfigCallback error:" + err );
          return;
        }
        message = "getScanInfos callback successful"
        message = "addDeviceConfig: " + result
        prompt.showToast( { message : message } )
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
    let message = "AddCandidateConfigPromise test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let wifiDeviceConfigManager = AppStorage.Get( "wifiDeviceConfigManager" )
      wifiManager.addCandidateConfig( wifiDeviceConfigManager ).then( result => {
        //  @returns Returns {@code true} if the untrusted hotspot configuration is added, returns {@code false} otherwise.
        console.log( "addCandidateConfig: " + result )
        message = "addCandidateConfig: " + result
        prompt.showToast( { message : message } )
      } ).catch(err=>{
        console.log("testAddCandidateConfigManagerPromise err:"+err)
      })
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
    let message = "AddCandidateConfigCallback test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let wifiDeviceConfigManager = AppStorage.Get( "wifiDeviceConfigManager" )
      wifiManager.addCandidateConfig( wifiDeviceConfigManager , ( err , result ) => {
        //  @returns Returns {@code true} if the untrusted hotspot configuration is added, returns {@code false} otherwise.
        if ( err ) {
          console.error( "addCandidateConfigCallback error" );
          return;
        }
        console.log( "addCandidateConfig: " + result )
        message = "addCandidateConfig: " + result
        prompt.showToast( { message : message } )
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
    let message = "RemoveCandidateConfigPromise test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let networkId: number = AppStorage.Get( "networkId" )
      wifiManager.removeCandidateConfig( networkId ).then( result => {
        //  @returns Returns {@code true} if the untrusted hotspot configuration is removed, returns {@code false} otherwise.
        console.log( "removeCandidateConfig: " + result )
        message = "removeCandidateConfig: " + result
        prompt.showToast( { message : message } )
      } ).catch(err=>{
        console.log("testRemoveCandidateConfigManagerPromise err:"+err)
      })
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
    let message = "removeUntrustedConfigCallback test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let networkId: number = AppStorage.Get( "networkId" )
      wifiManager.removeCandidateConfig( networkId , ( err , result ) => {
        //  @returns Returns {@code true} if the untrusted hotspot configuration is removed, returns {@code false} otherwise.
        if ( err ) {
          console.error( "removeCandidateConfigCallback error" );
          return;
        }
        console.log( "removeCandidateConfig: " + result )
        message = "removeCandidateConfig: " + result
        prompt.showToast( { message : message } )
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
    let message = "GetCandidateConfigs test"
    let ret = wifiManager.getCandidateConfigs()
    message = "候选配置：" + JSON.stringify( ret )
    prompt.showToast( { message : message } )
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
    let message = "ConnectToCandidateConfig test"
    let networkId = AppStorage.Get( "networkId" )
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let ret = wifiManager.connectToCandidateConfig( networkId )
      message = "connectToCandidateConfig: " + ret
    }
    prompt.showToast( { message : message } )
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
    let message = "connectToNetwork test"
    let networkId: number = AppStorage.Get( "networkId" )
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let ret = wifiManager.connectToNetwork( networkId )
      message = "ConnectToNetwork: " + ret
    }
    prompt.showToast( { message : message } )
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
    let message = "connectToDevice test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let wifiDeviceConfig = AppStorage.Get( "wifiDeviceConfig" )
      let ret = wifiManager.connectToDevice( wifiDeviceConfig )
      message = "ConnectToDevice:" + ret
    }
    prompt.showToast( { message : message } )
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
    let message = "disconnect test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let ret = wifiManager.disconnect()
      message = "disconnect: " + ret
    }
    prompt.showToast( { message : message } )
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
    let message = "getSignalLevel test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let rssi: number = AppStorage.Get( "rssi" )
      let band: number = AppStorage.Get( "band" )
      let number = wifiManager.getSignalLevel( rssi , band )
      message = "getSignalLevel is: " + number
    }
    prompt.showToast( { message : message } )
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
    let message = "getLinkedInfoPromise test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      wifiManager.getLinkedInfo().then( data => {
        console.log( "get wifi linked info: " + JSON.stringify( data ) );
      } ).catch( error => {
        console.log( "get linked info error:"+error );
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
    let message = "getLinkedInfoCallback test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      wifiManager.getLinkedInfo( ( err , data ) => {
        if ( err ) {
          console.error( "get linked info error" );
          message = "get linked info error"
          prompt.showToast( { message : message } )
        }
        console.log( "get wifi linked info: " + JSON.stringify( data ) );
        message = "get wifi linked info: " + JSON.stringify( data )
        let linkedInfoManagerMessage = JSON.stringify( data )
        AppStorage.SetOrCreate( "linkedInfoManagerMessage" , linkedInfoManagerMessage )
        let rssi = data.rssi
        let band = data.band
        let networkId = data.networkId
        AppStorage.SetOrCreate( "rssi" , rssi )
        AppStorage.SetOrCreate( "band" , band )
        AppStorage.SetOrCreate( "networkId" , networkId )
        prompt.showToast( { message : message } )
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
    let message = " IsConnected test "
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let ret = wifiManager.isConnected()
      message = "isConnected: " + ret
    }
    prompt.showToast( { message : message } )
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
    let message = "getSupportedFeatures test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let ret = wifiManager.getSupportedFeatures()
      message = "GetSupportedFeatures: " + ret
    }
    prompt.showToast( { message : message } )
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
    let message = "isFeatureSupported test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let featureId = AppStorage.Get( "featureId" )
      let ret = wifiManager.isFeatureSupported( featureId )
      message = "isFeatureSupported: " + ret
    }
    prompt.showToast( { message : message } )
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
    let message = "GetDeviceMacAddress test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let macAddress = wifiManager.getDeviceMacAddress()
      message = "macAddress: " + macAddress
    }
    prompt.showToast( { message : message } )
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
    let message = "getIpInfo test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let IpInfo = wifiManager.getIpInfo()
      message = "IpInfo: " + JSON.stringify( IpInfo )
      let ipInfoManagerMessage = IpInfo
      AppStorage.SetOrCreate( "ipInfoManagerMessage" , ipInfoManagerMessage )
    }
    prompt.showToast( { message : message } )
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
    let message = "getCountryCode test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let ret = wifiManager.getCountryCode()
      message = "CountryCode is: " + ret
    }
    prompt.showToast( { message : message } )
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
    let message = "reassociate test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let ret = wifiManager.reassociate()
      message = "reassociate is: " + ret
    }
    prompt.showToast( { message : message } )
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
    let message = "reConnect test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let ret = wifiManager.reconnect()
      message = " reConnect is: " + ret
    }
    prompt.showToast( { message : message } )
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
    let message = "getDeviceConfigs test "
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let array = wifiManager.getDeviceConfigs()
      message = " DeviceConfigs is " + array
      let getDeviceConfigsManagerMessage = array
      AppStorage.SetOrCreate( "getDeviceConfigsManagerMessage" , getDeviceConfigsManagerMessage )
    }
    prompt.showToast( { message : message } )
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
    let message = "updateNetwork test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let wifiDeviceConfig = AppStorage.Get( "wifiDeviceConfig" )
      let ret = wifiManager.updateDeviceConfig( wifiDeviceConfig )
      message = "updateNetwork: " + ret
    }
    prompt.showToast( { message : message } )
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
    let message = "disableNetWork test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let networkId = AppStorage.Get( "networkId" )
      let ret = wifiManager.disableDeviceConfig( networkId )
      message = "disableNetwork: " + ret
    }
    prompt.showToast( { message : message } )
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
    let message = "removeAllNetwork test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let ret = wifiManager.removeAllDeviceConfigs()
      message = "removeAllNetwork: " + ret
    }
    prompt.showToast( { message : message } )
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
    let message = "removeDevice test"
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
    } else {
      let networkId = AppStorage.Get( "networkId" )
      let ret = wifiManager.removeDeviceConfig( networkId )
      message = "removeDevice " + ret
    }
    prompt.showToast( { message : message } )
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
    console.log( "testOnWifiStateChange test" );
    //  if(!wifiManagerEnable){
    //    message ="WIFI还未使能";
    //    return message
    //  }
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
    console.log( "testOnWifiConnectionChange test" );
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
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
    console.log( "testOnWifiScanStateChange test" );
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
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
    console.log( "testOnWifiRssiChange test" );
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
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
    console.log( "testOnStreamChange test" );
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
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
    let message = "onDeviceConfigChange test"
    console.log( "testOnDeviceConfigChange test" );
    if ( !wifiManagerEnable ) {
      message = "WIFI还未使能";
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