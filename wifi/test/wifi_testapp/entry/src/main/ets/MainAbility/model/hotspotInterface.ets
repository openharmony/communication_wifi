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

/**
 * hotspot Test Page Of Wifi test
 */

let hotspotEnable = false

export function testEnableHotspot(): string {
  try {
    let message = ( MessageData.testEnableHotspot )
    console.log( LogData.testEnableHotspot_StartLog )
    if ( hotspotEnable ) {
      message = ( MessageData.hotspot_enable )
    } else {
      let ret = wifi.enableHotspot()
      if ( ret ) {
        message = "热点使能执行结果：" + ret;
      } else {
        message = "使能结果：" + ret + "\n"
        message += "热点已打开或打开失败,请确认"
      }
      hotspotEnable = true
      AppStorage.SetOrCreate( 'hotspotIsOn' , hotspotEnable );
    }
    prompt.showToast( { message : message } )
    console.log( LogData.testEnableHotspot_EndLog )
    return message
  } catch( err ) {
    console.log( `Failed to testEnableHotspot. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testEnableHotspot. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testDisableHotspot(): string {
  try {
    let message = ( MessageData.testDisableHotspot )
    console.log( LogData.testDisableHotspot_StartLog )
    if ( !hotspotEnable ) {
      message = ( MessageData.hotspot_disEnable )
    } else {
      let ret = wifi.disableHotspot();
      if ( ret ) {
        message = "热点去使能执行结果：" + ret;
      } else {
        message = "去使能结果：" + ret + "\n"
        message += "热点已关闭或关闭失败,请确认"
      }
      hotspotEnable = false;
      AppStorage.SetOrCreate( 'hotspotIsOn' , hotspotEnable );
    }
    prompt.showToast( { message : message } )
    console.log( LogData.testDisableHotspot_EndLog )
    return message
  } catch( err ) {
    console.log( `Failed to testDisableHotspot. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testDisableHotspot. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testIsHotspotDualBandSupported(): string {
  try {
    let message = ( MessageData.testIsHotspotDualBandSupported )
    console.log( LogData.testIsHotspotDualBandSupported_StartLog )
    let ret = wifi.isHotspotDualBandSupported()
    message = "热点支持双频结果：" + ret
    prompt.showToast( { message : message } )
    console.log( LogData.testIsHotspotDualBandSupported_EndLog )
    return message
  } catch( err ) {
    console.log( `Failed to testIsHotspotDualBandSupported. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testIsHotspotDualBandSupported. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testIsHostActive(): string {
  try {
    let message = ( MessageData.testIsHotspotActive )
    console.log( LogData.testIsHostActive_StartLog )
    let ret = wifi.isHotspotActive()
    if ( ret ) {
      hotspotEnable = true
    } else {
      hotspotEnable = false
    }
    message = "热点使能结果为：" + ret
    prompt.showToast( { message : message } )
    console.log( LogData.testIsHostActive_EndLog )
    return message
  } catch( err ) {
    console.log( `Failed to testIsHostActive. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testIsHostActive. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testSetHotspotConfig(): string {
  try {
    let message = ( MessageData.testSetHotspotConfig )
    console.log( LogData.testSetHotspotConfig_StartLog )
    let ssid = "testApp"
    let securityType = 3
    let band = 1;
    let preSharedKey = "12345678"
    let maxConn = 3
    let channel = 6
    // TODO: 设备调试时候需要打开
    //  let ssid1 =AppStorage.Get("ssid1")
    //  let securityType1=AppStorage.Get("securityTpye1")
    //  let band1 = AppStorage.Get("band1")
    //  let preSharedKey1 = AppStorage.Get("preSharedKey1")
    //  let maxConn1 = AppStorage.Get("maxConn1")
    let hotspotConfigs = {
      ssid : ssid ,
      securityType : securityType ,
      band : band ,
      preSharedKey : preSharedKey ,
      maxConn : maxConn ,
      channel : channel
    }
    let ret = wifi.setHotspotConfig( hotspotConfigs )
    message = "SetHotspotConfig: " + ret
    prompt.showToast( { message : message } )
    console.log( LogData.testSetHotspotConfig_EndLog )
    return message
  } catch( err ) {
    console.log( `Failed to testSetHotspotConfig. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testSetHotspotConfig. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetHotspotConfig(): string {
  try {
    let message = ( MessageData.testGetHotspotConfig )
    console.log( LogData.testGetHotspotConfig_StartLog )
    let ret = wifi.getHotspotConfig()
    message = "HotspotConfig: " + JSON.stringify( ret )
    console.log( "HotspotConfig is: " + JSON.stringify( ret ) )
    let getHotspotConfigMessage = JSON.stringify( ret )
    AppStorage.SetOrCreate( "getHotspotConfigMessage" , getHotspotConfigMessage )
    prompt.showToast( { message : message } )
    console.log( LogData.testGetHotspotConfig_EndLog )
    return message
  } catch( err ) {
    console.log( `Failed to testGetHotspotConfig. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testGetHotspotConfig. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetStations(): string {
  try {
    let message = ( MessageData.testGetStations )
    console.log( LogData.testGetStations_StartLog )
    let ret = wifi.getStations()
    message = "GetStations is: " + JSON.stringify( ret )
    console.log( "GetStations is: " + JSON.stringify( ret ) )
    let getStationsMessage = JSON.stringify( ret )
    AppStorage.SetOrCreate( "getStationsMessage" , getStationsMessage )
    prompt.showToast( { message : message } )
    console.log( LogData.testGetStations_EndLog )
    return message
  } catch( err ) {
    console.log( `Failed to testGetStations. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testGetStations. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let hotspotStateChange = false

export function testOnHotspotStateChange(): string {
  try {
    let message = ( MessageData.testOnHotspotStateChange )
    console.log( "testOnHotspotStateChange test" );
    if ( hotspotStateChange ) {
      wifi.off( "hotspotStateChange" , () => {
        prompt.showToast( { message : ( MessageData.offHotspotStateChange ) } )
      } )
      message = MessageData.offHotspotStateChangeTest
    } else {
      wifi.on( "hotspotStateChange" , ( number ) => {
        console.log( LogData.testOnHotspotStateChange_StartLog );
        let hotspotStateMessage = ""
        switch ( number ) {
          case 0:
            hotspotStateMessage = "inactive";
            break;
          case 1:
            hotspotStateMessage = "active";
            break;
          case 2:
            hotspotStateMessage = "activating";
            break;
          case 3:
            hotspotStateMessage = "de-activating";
            break;
          default:
            hotspotStateMessage = '未知状态';
            break;
        }
        prompt.showToast( { message : "状态为: " + hotspotStateMessage } )
        AppStorage.SetOrCreate( "hotspotStateMessage" , hotspotStateMessage )
        console.log( LogData.testOnHotspotStateChange_EndLog );
      } )
      message = ( MessageData.onHotspotStateChangeTest )
      prompt.showToast( { message : message } )
    }
    hotspotStateChange = !hotspotStateChange
    return message
  } catch( err ) {
    console.log( `Failed to testOnHotspotStateChange. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testOnHotspotStateChange. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let hotspotStaJoin = false

export function testOnHotspotStaJoin() {
  try {
    let message = ( MessageData.testOnHotspotStaJoin )
    console.log( " testOnHotspotStaJoin test " )
    if ( hotspotStaJoin ) {
      wifi.off( "hotspotStaJoin" , () => {
        prompt.showToast( { message : MessageData.offHotspotStaJoin } )
      } )
      message = ( MessageData.offHotspotStaJoinTest )
    } else {
      wifi.on( "hotspotStaJoin" , ( data ) => {
        console.log( LogData.testOnHotspotStaJoin_StartLog );
        let hotspotStaJoinMessage = "name:" + data.name + ";macAddress:" + data.macAddress + ";ipAddress:" + data.ipAddress
        message = "状态为: " + JSON.stringify( data )
        AppStorage.SetOrCreate( "hotspotStaJoinMessage" , message )
        prompt.showToast( { message : hotspotStaJoinMessage } )
        console.log( LogData.testOnHotspotStaJoin_EndLog );
      } )
      message = ( MessageData.onHotspotStaJoinTest )
      prompt.showToast( { message : message } )
    }
    hotspotStaJoin = !hotspotStaJoin
    return message
  } catch( err ) {
    console.log( `Failed to testOnHotspotStaJoin. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testOnHotspotStaJoin. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let hotspotStaLeave = false

export function testOnHotspotStaLeave() {
  try {
    let message = ( MessageData.testOnHotspotStaLeave )
    console.log( " testOnHotspotStaLeave test " )
    if ( hotspotStaLeave ) {
      wifi.off( "hotspotStaLeave" , () => {
        prompt.showToast( { message : MessageData.offHotspotStaLeave } )
      } )
      message = ( MessageData.offHotspotStaLeaveTest )
    } else {
      wifi.on( "hotspotStaLeave" , ( data ) => {
        console.log( LogData.testOnHotspotStaLeave_StartLog );
        let hotspotStaLeaveMessage = "name:" + data.name + ";macAddress:" + data.macAddress + ";ipAddress:" + data.ipAddress
        message = "状态为: " + JSON.stringify( data )
        AppStorage.SetOrCreate( "hotspotStaLeaveMessage" , message )
        prompt.showToast( { message : hotspotStaLeaveMessage } )
        console.log( LogData.testOnHotspotStaLeave_EndLog );
      } )
      message = ( MessageData.onHotspotStaLeaveTest )
      prompt.showToast( { message : message } )
    }
    hotspotStaLeave = !hotspotStaLeave
    return message
  } catch( err ) {
    console.log( `Failed to testOnHotspotStaLeave. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testOnHotspotStaLeave. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

