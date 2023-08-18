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
import ConfigData from "../../Utils/ConfigData"
import LogData from "../../Utils/LogData"
import MessageData from "../../Utils/MessageData"
const PAGE_URI_P2P_FOUND_MODE = 'pages/subManualApiTest/subP2pTest/p2pFound';
/**
 * p2p Test Page Of Wifi test
 */

export function testGetP2pLinkedInfoPromise(): string {
  try {
    let message = ( MessageData.testGetP2pLinkedInfoPromise )
    console.log( LogData.testGetP2pLinkedInfoPromise_StartLog );
    wifi.getP2pLinkedInfo().then( wifiP2pLinkedInfo => {
      console.log( LogData.getP2pLinkedInfoPromise_successfulLog )
      console.log( "getP2pLinkedInfoPromise: " + JSON.stringify( wifiP2pLinkedInfo ) )
      message = "getP2pLinkedInfoPromise: " + JSON.stringify( wifiP2pLinkedInfo )
      console.log( LogData.testGetP2pLinkedInfoPromise_EndLog );
      AppStorage.SetOrCreate("p2pLinkMessage",message)
      prompt.showToast( { message : message } )
    } ).catch( error => {
      console.log( "testGetP2pLinkedInfoPromise error :" + error )
    } )
    prompt.showToast( { message : message } )
    return message
  } catch( error ) {
    console.log( `Failed to testGetP2pLinkedInfoPromise. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testGetP2pLinkedInfoPromise. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetP2pLinkedInfoCallback(): string {
  try {
    let message = ( MessageData.testGetP2pLinkedInfoCallback )
    console.log( LogData.testGetP2pLinkedInfoCallback_StartLog );
    wifi.getP2pLinkedInfo( ( err , WifiP2pLinkedInfo ) => {
      if ( err ) {
        console.error( "getP2pLinkedInfoCallback error" )
        console.error( 'failed to get getP2pLinkedInfo: ' + JSON.stringify( err ) );
        return message;
      }
      console.log( LogData.getP2pLinkedInfoCallback_successfulLog )
      console.log( "getP2pLinkedInfoCallback: " + JSON.stringify( WifiP2pLinkedInfo ) )
      message = "getP2pLinkedInfoCallback: " + JSON.stringify( WifiP2pLinkedInfo )
      AppStorage.SetOrCreate("p2pLinkMessage",message)
      console.log( LogData.testGetP2pLinkedInfoCallback_EndLog );
      prompt.showToast( { message : message } )
    } )
    prompt.showToast( { message : message } )
    return message
  } catch( error ) {
    console.log( `Failed to testGetP2pLinkedInfoCallback. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testGetP2pLinkedInfoCallback. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetCurrentGroupPromise(): string {
  try {
    let message = ( MessageData.testGetCurrentGroupPromise )
    console.log( LogData.testGetCurrentGroupPromise_StartLog );
    wifi.getCurrentGroup().then( WifiP2pGroupInfo => {
      console.log( LogData.testGetCurrentGroupPromise_successfulLog );
      console.log( "getCurrentGroupPromise: " + JSON.stringify( WifiP2pGroupInfo ) )
      message = "getCurrentGroupPromise: " + JSON.stringify( WifiP2pGroupInfo )
      AppStorage.SetOrCreate("p2pGroupMessage",message)
      console.log( LogData.testGetCurrentGroupPromise_EndLog );
      prompt.showToast( { message : message } )
    } ).catch( error => {
      console.log( "testGetCurrentGroupPromise error :" + error )
    } )
    prompt.showToast( { message : message } )
    return message
  } catch( error ) {
    console.log( `Failed to testGetCurrentGroupPromise. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testGetCurrentGroupPromise. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetCurrentGroupCallback(): string {
  try {
    let message = ( MessageData.testGetCurrentGroupCallback )
    console.log( LogData.testGetCurrentGroupCallback_StartLog );
    wifi.getCurrentGroup( ( err , WifiP2pGroupInfo ) => {
      if ( err ) {
        console.error( $r( "app.string.testCurrentGroupCallback_error" ) )
        console.error( 'failed to get current group: ' + JSON.stringify( err ) );
        return message;
      }
      let p2pLinkedDeviceName =WifiP2pGroupInfo.ownerInfo.deviceName
      console.log( LogData.getCurrentGroupCallback_successfulLog )
      console.log( "getCurrentGroupCallback: " + JSON.stringify( WifiP2pGroupInfo ) )
      message = "getCurrentGroupCallback: " + JSON.stringify( WifiP2pGroupInfo )
      AppStorage.SetOrCreate("p2pGroupMessage",message)
      AppStorage.SetOrCreate("p2pLinkedDeviceName",p2pLinkedDeviceName)
      console.log( LogData.testGetCurrentGroupCallback_EndLog );
      prompt.showToast( { message : message } )
    } )
    prompt.showToast( { message : message } )
    return message
  } catch( error ) {
    console.log( `Failed to testGetCurrentGroupCallback. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testGetCurrentGroupCallback. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetP2pPeerDevicesPromise() {
  try {
    let message = ( MessageData.testGetP2pPeerDevicesPromise )
    console.log( LogData.testGetP2pPeerDevicesPromise_StartLog );
    wifi.getP2pPeerDevices().then( WifiP2pDevice => {
      console.log( $r( "app.string.getP2pPeerDevicesPromise_successful" ) );
      console.log( "getP2pPeerDevicesPromise: " + JSON.stringify( WifiP2pDevice ) )
      message = "getP2pPeerDevicesPromise: " + JSON.stringify( WifiP2pDevice )
      AppStorage.SetOrCreate("p2pPeerDeviceMessages",message)
      console.log( LogData.testGetP2pPeerDevicesPromise_EndLog );
      prompt.showToast( { message : message } )
    } ).catch( error => {
      console.log( "testGetP2pPeerDevicesPromise error :" + error )
    } )
    prompt.showToast( { message : message } )
    return message
  } catch( error ) {
    console.log( `Failed to testGetP2pPeerDevicesPromise. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testGetP2pPeerDevicesPromise. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetP2pPeerDevicesCallback() {
  try {
    let message = ( MessageData.testGetP2pPeerDevicesCallback )
    console.log( LogData.testGetP2pPeerDevicesCallback_StartLog );
    wifi.getP2pPeerDevices( ( err , WifiP2pDevice ) => {
      if ( err ) {
        console.error( $r( "app.string.getP2pPeerDevicesCallback_error" ) );
        console.error( 'failed to get peer devices: ' + JSON.stringify( err ) );
        return message;
      }
      console.log( LogData.getP2pPeerDevicesCallback_successfulLog );
      console.log( "getP2pPeerDevicesCallback: " + JSON.stringify( WifiP2pDevice ) )
      message = "getP2pPeerDevicesCallback: " + JSON.stringify( WifiP2pDevice )
      AppStorage.SetOrCreate("p2pPeerDeviceMessages",message)
      console.log( LogData.testGetP2pPeerDevicesCallback_EndLog );
      prompt.showToast( { message : message } )
      let len = Object.keys( WifiP2pDevice ).length;
      for ( let i = 0 ; i < len ; ++i ) {
        if ( WifiP2pDevice[i].deviceName === "MyTestDevice" ) {
          console.log( "p2p connect to test device: " + WifiP2pDevice[i].deviceAddress );
          let config = {
            "deviceAddress" : WifiP2pDevice[i].deviceAddress ,
            "netId" : - 2 ,
            "passphrase" : "" ,
            "groupName" : "" ,
            "goBand" : 0 ,
          }
          AppStorage.SetOrCreate( "config" , config )
          //        wifi.p2pConnect(config);
        }
      }
    } )
    prompt.showToast( { message : message } )
    return message
  } catch( error ) {
    console.log( `Failed to testGetP2pPeerDevicesCallback. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testGetP2pPeerDevicesCallback. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testCreateGroup(): string {
  try {
    let message = ( MessageData.testCreateGroup )
    console.log( LogData.testCreateGroup_StartLog );
    let deviceAddress = AppStorage.Get( "deviceAddress" )
    let netId = AppStorage.Get( "netId" )
    let passphrase = AppStorage.Get( "passphrase" )
    let groupName = AppStorage.Get( "groupName" )
    let goBand = AppStorage.Get( "goBand" )
    let wifiP2pConfig = {
      deviceAddress : deviceAddress ,
      netId : netId ,
      passphrase : passphrase ,
      groupName : groupName ,
      goBand : goBand
    }
    AppStorage.SetOrCreate( "wifiP2pConfig" , wifiP2pConfig )
    let ret = wifi.createGroup( wifiP2pConfig )
    message = "createGroup: " + ret
    console.log( LogData.testCreateGroup_EndLog );
    return message
  } catch( error ) {
    console.log( `Failed to testCreateGroup. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testCreateGroup. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testRemoveGroup(): string {
  try {
    let message = ( MessageData.testRemoveGroup )
    console.log( LogData.testRemoveGroup_StartLog );
    let ret = wifi.removeGroup()
    message = "removeGroup: " + ret
    prompt.showToast( { message : message } )
    console.log( LogData.testRemoveGroup_EndLog );
    return message
  } catch( error ) {
    console.log( `Failed to testRemoveGroup. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testRemoveGroup. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testP2pConnect(): string {
  try {
    let message = ( MessageData.testP2pConnect )
    console.log( LogData.testP2pConnect_StartLog );
    let wifiP2pConfig = AppStorage.Get( "wifiP2pConfig" )
    let config = AppStorage.Get( "config" )
    let ret = wifi.p2pConnect( config )
    message = "p2pConnect: " + ret
    prompt.showToast( { message : message } )
    console.log( LogData.testP2pConnect_EndLog );
    return message
  } catch( error ) {
    console.log( `Failed to testP2pConnect. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testP2pConnect. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testP2pCancelConnect(): string {
  try {
    let message = ( MessageData.testP2pCancelConnect )
    console.log( LogData.testP2pCancelConnect_StartLog );
    let ret = wifi.p2pCancelConnect()
    message = "p2pCancelConnect: " + ret
    prompt.showToast( { message : message } )
    console.log( LogData.testP2pCancelConnect_EndLog );
    return message
  } catch( error ) {
    console.log( `Failed to testP2pCancelConnect. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testP2pCancelConnect. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testStartDiscoverDevices(): string {
  try {
    let message = ( MessageData.testStartDiscoverDevices )
    console.log( LogData.testStartDiscoverDevices_StartLog );
    let ret = wifi.startDiscoverDevices()
    message = "startDiscoverDevices: " + ret
    Router.push( { uri : PAGE_URI_P2P_FOUND_MODE } );
    prompt.showToast( { message : message } )
    console.log( LogData.testStartDiscoverDevices_EndLog );
    return message
  } catch( error ) {
    console.log( `Failed to testStartDiscoverDevices. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testStartDiscoverDevices. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testStopDiscoverDevices(): string {
  try {
    let message = ( MessageData.testStopDiscoverDevices )
    console.log( LogData.testStopDiscoverDevices_StartLog );
    let ret = wifi.stopDiscoverDevices()
    message = "stopDiscoverDevices: " + ret
    prompt.showToast( { message : message } )
    console.log( LogData.testStopDiscoverDevices_EndLog );
    return message
  } catch( error ) {
    console.log( `Failed to testStopDiscoverDevices. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testStopDiscoverDevices. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testDeletePersistentGroup(): string {
  try {
    let message = ( MessageData.testDeletePersistentGroup )
    console.log( LogData.testDeletePersistentGroup_StartLog );
    let netId = AppStorage.Get( "netId" )
    let ret = wifi.deletePersistentGroup( netId )
    message = "deletePersistentGroup: " + ret
    prompt.showToast( { message : message } )
    console.log( LogData.testDeletePersistentGroup_EndLog );
    return message
  } catch( error ) {
    console.log( `Failed to testDeletePersistentGroup. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testDeletePersistentGroup. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testSetDeviceName( deviceName: string ): string {
  try {
    let message = ( MessageData.testSetDeviceName )
    console.log( LogData.testSetDeviceName_StartLog );
    //  let devName = AppStorage.Get("devName")
    let ret = wifi.setDeviceName( deviceName )
    message = "设置：" + ret + ",设备名称为：" + deviceName;
    console.log( "设置：" + ret + ",设备名称为：" + deviceName );
    prompt.showToast( { message : message } )
    console.log( LogData.testSetDeviceName_EndLog );
    return message
  } catch( error ) {
    console.log( `Failed to testSetDeviceName. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testSetDeviceName. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let p2pStateChange = false

export function testOnP2pStateChange(): string {
  try {
    let message = ( MessageData.testOnP2pStateChange )
    console.log( LogData.testOnP2pStateChange_StartLog )
    if ( p2pStateChange ) {
      wifi.off( "p2pStateChange" , () => {
        prompt.showToast( { message : ( MessageData.offP2pStateChange ) } )
      } )
      message = ( MessageData.offP2pStateChangeTest )
    } else {
      wifi.on( "p2pStateChange" , ( number ) => {
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
        AppStorage.SetOrCreate("p2pStateMessage",p2pStateMessage)
        prompt.showToast( { message : "状态: " + p2pStateMessage } )
        console.log( LogData.testOnP2pStateChange_EndLog );
      } )
      message = ( MessageData.onP2pStateChangeTest )
      prompt.showToast( { message : message } )
    }
    p2pStateChange = !p2pStateChange
    return message
  } catch( error ) {
    console.log( `Failed to testOnP2pStateChange. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testOnP2pStateChange. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let p2pConnectionChange = false

export function testOnP2pConnectionChange(): string {
  try {
    let message = ( MessageData.testOnP2pConnectionChange )
    console.log( LogData.testOnP2pConnectionChange_StartLog )
    if ( p2pConnectionChange ) {
      wifi.off( "p2pConnectionChange" , () => {
        prompt.showToast( { message : ( MessageData.offP2pConnectionChange ) } )
      } )
      message = ( MessageData.offP2pConnectionChangeTest )
    } else {
      wifi.on( "p2pConnectionChange" , ( WifiP2pLinkedInfo ) => {
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
        prompt.showToast( { message : message } )
        AppStorage.SetOrCreate("p2pConnectState",connectState)
        AppStorage.SetOrCreate("p2pLinkStateMessage",message)
        console.log( LogData.testOnP2pConnectionChange_EndLog )
      } )
      message = ( MessageData.onP2pConnectionChangeTest )
      prompt.showToast( { message : message } )
    }
    p2pConnectionChange = !p2pConnectionChange
    return message
  } catch( error ) {
    console.log( `Failed to testOnP2pConnectionChange. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testOnP2pConnectionChange. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let p2pDeviceChange = false

export function testOnP2pDeviceChange(): string {
  try {
    let message = ( MessageData.testOnP2pDeviceChange )
    console.log( LogData.testOnP2pDeviceChange_StartLog )
    if ( p2pDeviceChange ) {
      wifi.off( "p2pDeviceChange" , () => {
        prompt.showToast( { message : MessageData.offP2pDeviceChange } )
      } )
      message = ( MessageData.offP2pDeviceChangeTest )
    } else {
      wifi.on( "p2pDeviceChange" , ( data ) => {
        let p2pDeviceStatusMessage = ""
        let deviceName = data.deviceName
        let deviceAddress = data.deviceAddress
        let primaryDeviceType = data.primaryDeviceType
        let deviceStatus = data.deviceStatus
        let groupCapabilitys = data.groupCapabilitys
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
        console.log( "info:" + JSON.stringify( data ) )
        message = "deviceName: " + deviceName + "\n" +
        "deviceAddress: " + deviceAddress + "\n" +
        "primaryDeviceType: " + primaryDeviceType + "\n" +
        "deviceStatus: " + p2pDeviceStatusMessage + "\n" +
        "groupCapabilitys: " + groupCapabilitys + "\n"
        AppStorage.SetOrCreate("p2pDeviceMessage",message)
        prompt.showToast( { message : message } )
        console.log( LogData.testOnP2pDeviceChange_EndLog )
      } )
      message = ( MessageData.onP2pDeviceChangeTest )
      prompt.showToast( { message : message } )
    }
    p2pDeviceChange = !p2pDeviceChange
    return message
  } catch( error ) {
    console.log( `Failed to testOnP2pDeviceChange. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testOnP2pDeviceChange. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let p2pPeerDeviceChange = false

export function testOnP2pPeerDeviceChange(): string {
  try {
    let message = ( MessageData.testOnP2pPeerDeviceChange )
    console.log( LogData.testOnP2pPeerDeviceChange_StartLog )
    if ( p2pPeerDeviceChange ) {
      wifi.off( "p2pPeerDeviceChange" , () => {
        prompt.showToast( { message : ( MessageData.offP2pPeerDeviceChange ) } )
      } )
      message = ( MessageData.offP2pPeerDeviceChangeTest )
    } else {
      wifi.on( "p2pPeerDeviceChange" , ( data ) => {
        let p2pPeerDeviceChangeMessage = ""
        console.log( "WifiP2pDevice: " + JSON.stringify( data ) )
        p2pPeerDeviceChangeMessage = "WifiP2pDevice: " + JSON.stringify( data )
        AppStorage.SetOrCreate("p2pPeerDeviceMessage",p2pPeerDeviceChangeMessage)
        prompt.showToast( { message : "状态 " + p2pPeerDeviceChangeMessage } )
        console.log( LogData.testOnP2pPeerDeviceChange_EndLog )
      } )
      message = ( MessageData.onP2pPeerDeviceChangeTest )
      prompt.showToast( { message : message } )
    }
    p2pPeerDeviceChange = !p2pPeerDeviceChange
    return message
  } catch( error ) {
    console.log( `Failed to testOnP2pPeerDeviceChange. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testOnP2pPeerDeviceChange. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let p2pPersistentGroupChange = false

export function testOnP2pPersistentGroupChange(): string {
  try {
    let message = ( MessageData.testOnP2pPersistentGroupChange )
    console.log( LogData.testOnP2pPersistentGroupChange_StartLog )
    if ( p2pPersistentGroupChange ) {
      wifi.off( "p2pPersistentGroupChange" , () => {
        prompt.showToast( { message : ( MessageData.offP2pPersistentGroupChange ) } )
      } )
      message = ( MessageData.offP2pPersistentGroupChangeTest )
    } else {
      wifi.on( "p2pPersistentGroupChange" , ( data ) => {
        let p2pPersistentGroupChangeMessage = ""
        console.log( "p2pPersistentGroupChange: " + data )
        p2pPersistentGroupChangeMessage = "p2pPersistentGroupChange: " + data
        prompt.showToast( { message : "状态: " + p2pPersistentGroupChangeMessage } )
        console.log( LogData.testOnP2pPersistentGroupChange_EndLog )
      } )
      message = ( MessageData.onP2pPersistentGroupChangeTest )
      prompt.showToast( { message : message } )
    }
    p2pPersistentGroupChange = !p2pPersistentGroupChange
    return message
  } catch( error ) {
    console.log( `Failed to testOnP2pPersistentGroupChange. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testOnP2pPersistentGroupChange. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let p2pDiscoveryChange = false

export function testOnP2pDiscoveryChange(): string {
  try {
    let message = ( MessageData.testOnP2pDiscoveryChange )
    console.log( LogData.testOnP2pDiscoveryChange_StartLog )
    if ( p2pDiscoveryChange ) {
      wifi.off( "p2pDiscoveryChange" , () => {
        prompt.showToast( { message : ( MessageData.offP2pDiscoveryChange ) } )
      } )
      message = ( MessageData.offP2pDiscoveryChangeTest )
    } else {
      wifi.on( "p2pDiscoveryChange" , ( number ) => {
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
        prompt.showToast( { message : "发现状态：" + p2pDiscoveryChangeMessage } )
        AppStorage.SetOrCreate("p2pDiscoveryMessage",p2pDiscoveryChangeMessage)
        console.log( LogData.testOnP2pDiscoveryChange_EndLog )
      } )
      message = ( MessageData.onP2pDiscoveryChangeTest )
      prompt.showToast( { message : message } )
    }
    p2pDiscoveryChange = !p2pDiscoveryChange
    return message
  } catch( error ) {
    console.log( `Failed to testOnP2pDiscoveryChange. message: ${ error.message }, code: ${ error.code }` )
    let message = `Failed to testOnP2pDiscoveryChange. message: ${ error.message }, code: ${ error.code }`
    prompt.showToast( { message : message } )
    return message
  }
}