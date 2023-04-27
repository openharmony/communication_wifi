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
 * hotspotManager Test Page Of Wifi test
 */

let hotspotManagerEnable = false

export function testEnableHotspotManager() {
  try {
    let message = " enableHotspot test"
    if ( hotspotManagerEnable ) {
      message = "热点已经使能"
    } else {
      wifiManager.enableHotspot()
      message = "热点使能执行结果：true"
      //    if(ret){
      //      message ="热点使能执行结果：" + ret;
      //    }else{
      //      message ="热点使能执行结果：" + ret+"\n"
      //      message += "热点已打开或打开失败,请确认"
      //    }
      hotspotManagerEnable = true
      AppStorage.SetOrCreate( 'hotspotIsOn' , hotspotManagerEnable );
    }
    prompt.showToast( { message : message } )
    return message
  } catch( err ) {
    console.log( `Failed to testEnableHotspotManager. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testEnableHotspotManager. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testDisableHotspotManager() {
  try {
    let message = "disableWifi test"
    if ( !hotspotManagerEnable ) {
      message = '热点还未使能';
    } else {
      wifiManager.disableHotspot();
      message = "热点去使能执行结果：true"
      //    if (ret) {
      //      message = "热点去使能执行结果：" + ret;
      //    } else {
      //      message = "热点去使能执行结果：" + ret + "\n"
      //      message += "热点已关闭或关闭失败,请确认"
      //    }
      hotspotManagerEnable = false;
      AppStorage.SetOrCreate( 'hotspotIsOn' , hotspotManagerEnable );
    }
    prompt.showToast( { message : message } )
    return message
  } catch( err ) {
    console.log( `Failed to testDisableHotspotManager. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testDisableHotspotManager. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testIsHotspotDualBandSupportedManager(): string {
  try {
    let message = " isHotspotDualBandSupported test"
    let ret = wifiManager.isHotspotDualBandSupported()
    message = "热点支持双频结果：" + ret
    prompt.showToast( { message : message } )
    return message
  } catch( err ) {
    console.log( `Failed to testIsHotspotDualBandSupportedManager. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testIsHotspotDualBandSupportedManager. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testIsHostActiveManager(): string {
  try {
    let message = "isHostActive test"
    let ret = wifiManager.isHotspotActive()
    if ( ret ) {
      hotspotManagerEnable = true
    } else {
      hotspotManagerEnable = false
    }
    message = "HostActive is " + ret
    prompt.showToast( { message : message } )
    return message
  } catch( err ) {
    console.log( `Failed to testIsHostActiveManager. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testIsHostActiveManager. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testSetHotspotConfigManager(): string {
  try {
    let message = "SetHotspotConfig test"
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
    let config = {
      ssid : ssid ,
      securityType : securityType ,
      band : band ,
      preSharedKey : preSharedKey ,
      maxConn : maxConn ,
      channel : channel
    }
    let ret = wifiManager.setHotspotConfig( config )
    message = "SetHotspotConfig is " + ret
    prompt.showToast( { message : message } )
    return message
  } catch( err ) {
    console.log( `Failed to testSetHotspotConfigManager. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testSetHotspotConfigManager. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetHotspotConfigManager(): string {
  try {
    let message = "getHotspotConfig test"
    let ret = wifiManager.getHotspotConfig()
    message = "HotspotConfig is " + JSON.stringify( ret )
    console.log( "HotspotConfig is" + JSON.stringify( ret ) )
    let getHotspotConfigManagerMessage = JSON.stringify( ret )
    AppStorage.SetOrCreate( "getHotspotConfigManagerMessage" , getHotspotConfigManagerMessage )
    prompt.showToast( { message : message } )
    return message
  } catch( err ) {
    console.log( `Failed to testGetHotspotConfigManager. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testGetHotspotConfigManager. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function testGetHotspotStationsManager(): string {
  try {
    let message = "GetStations test"
    let ret = wifiManager.getHotspotStations()
    message = "GetStations is" + JSON.stringify( ret )
    console.log( "GetStations is" + JSON.stringify( ret ) )
    let getStationsManagerMessage = JSON.stringify( ret )
    AppStorage.SetOrCreate( "getStationsManagerMessage" , getStationsManagerMessage )
    prompt.showToast( { message : message } )
    return message
  } catch( err ) {
    console.log( `Failed to testGetHotspotStationsManager. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testGetHotspotStationsManager. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let hotspotStateChangeManager = false

export function testOnHotspotStateChangeManager(): string {
  try {
    let message = "onHotspotStateChange test"
    console.log( "testOnHotspotStateChange test" );
    if ( hotspotStateChangeManager ) {
      wifiManager.off( "hotspotStateChange" , () => {
        prompt.showToast( { message : "on.hotspotStateChange监听已关闭" } )
      } )
      message = "关闭注册热点状态改变事件"
    } else {
      wifiManager.on( "hotspotStateChange" , ( number ) => {
        let hotspotStateManagerMessage = ""
        switch ( number ) {
          case 0:
            hotspotStateManagerMessage = "inactive";
            break;
          case 1:
            hotspotStateManagerMessage = "active";
            break;
          case 2:
            hotspotStateManagerMessage = "activating";
            break;
          case 3:
            hotspotStateManagerMessage = "de-activating";
            break;
          default:
            hotspotStateManagerMessage = '未知状态';
            break;
        }
        prompt.showToast( { message : "状态为:" + hotspotStateManagerMessage } )
        AppStorage.SetOrCreate( "hotspotStateManagerMessage" , hotspotStateManagerMessage )
      } )
      message = "打开注册热点状态变化"
      prompt.showToast( { message : message } )
    }
    hotspotStateChangeManager = !hotspotStateChangeManager
    return message
  } catch( err ) {
    console.log( `Failed to testOnHotspotStateChangeManager. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testOnHotspotStateChangeManager. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let hotspotStaJoinManager = false

export function testOnHotspotStaJoinManager() {
  try {
    let message = "onHotspotStaJoin test"
    console.log( " testOnHotspotStaJoin " )
    if ( hotspotStaJoinManager ) {
      wifiManager.off( "hotspotStaJoin" , () => {
        prompt.showToast( { message : "on.hotspotStaJoin监听已关闭" } )
      } )
      message = "关闭注册Wi-Fi 热点 sta加入变化事件"
    } else {
      wifiManager.on( "hotspotStaJoin" , ( data ) => {
        let hotspotStaJoinManagerMessage = "name:" + data.name + ";macAddress:" + data.macAddress + ";ipAddress:" + data.ipAddress
        message = "状态为: " + JSON.stringify( data )
        AppStorage.SetOrCreate( "hotspotStaJoinManagerMessage" , message )
        prompt.showToast( { message : hotspotStaJoinManagerMessage } )
      } )
      message = "打开注册Wi-Fi 热点 sta加入变化"
      prompt.showToast( { message : message } )
    }
    hotspotStaJoinManager = !hotspotStaJoinManager
    return message
  } catch( err ) {
    console.log( `Failed to testOnHotspotStaJoinManager. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testOnHotspotStaJoinManager. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

let hotspotStaLeaveManager = false

export function testOnHotspotStaLeaveManager() {
  try {
    let message = "onHotspotStaLeave test"
    console.log( " testOnHotspotStaLeave " )
    if ( hotspotStaLeaveManager ) {
      wifiManager.off( "hotspotStaLeave" , () => {
        prompt.showToast( { message : "on.hotspotStaLeave监听已关闭" } )
      } )
      message = "关闭注册Wi-Fi 热点 sta离开变化事件"
    } else {
      wifiManager.on( "hotspotStaLeave" , ( data ) => {
        let hotspotStaLeaveManagerMessage = "name:" + data.name + ";macAddress:" + data.macAddress + ";ipAddress:" + data.ipAddress
        message = "状态为: " + JSON.stringify( data )
        AppStorage.SetOrCreate( "hotspotStaLeaveManagerMessage" , message )
        prompt.showToast( { message : hotspotStaLeaveManagerMessage } )
      } )
      message = "打开注册Wi-Fi 热点 sta离开变化"
      prompt.showToast( { message : message } )
    }
    hotspotStaLeaveManager = !hotspotStaLeaveManager
    return message
  } catch( err ) {
    console.log( `Failed to testOnHotspotStaLeaveManager. message: ${ err.message }, code: ${ err.code }` )
    let message = `Failed to testOnHotspotStaLeaveManager. message: ${ err.message }, code: ${ err.code }`
    prompt.showToast( { message : message } )
    return message
  }
}

export function sleep( time ) {
  return new Promise(( resolve , reject ) => {
    setTimeout( () => {
      resolve()
    } , time * 1000 )
  })
}