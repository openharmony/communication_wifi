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
 * hotspotManager Test Page Of Wifi test
 */


import prompt from '@system.prompt';
import Router from '@system.router';

import wifiManager from '@ohos.wifiManager';


let hotspotEnable =false
export function testEnableHotspotManager(): string {
  let message = " enableHotspot test"
  if(hotspotEnable) {
    message ="热点已经使能"
  }else{
    let ret =wifiManager.enableHotspot()
    if(ret){
      message ="热点使能执行结果：" + ret;
    }else{
      message ="热点使能执行结果：" + ret+"\n"
      message += "热点已打开或打开失败,请确认"
    }
    hotspotEnable = true
    AppStorage.SetOrCreate('hotspotIsOn', hotspotEnable);
  }
  prompt.showToast({ message: message })
  return message
}

export function testDisableHotspotManager():string {
  let message = "disableWifi test"
  if (!hotspotEnable) {
    message = '热点还未使能';
  }else {
    let ret = wifiManager.disableHotspot();
    if (ret) {
      message = "热点去使能执行结果：" + ret;
    } else {
      message = "热点去使能执行结果：" + ret + "\n"
      message += "热点已关闭或关闭失败,请确认"
    }
    hotspotEnable = false;
    AppStorage.SetOrCreate('hotspotIsOn', hotspotEnable);
  }
  prompt.showToast({ message: message })
  return message
}

export function testIsHotspotDualBandSupportedManager(): string {
  let message =" isHotspotDualBandSupported test"
  let ret =wifiManager.isHotspotDualBandSupported()
  message ="热点支持双频结果：" + ret
  prompt.showToast({message:message})
  return message
}

export function testIsHostActiveManager():string {
  let message = "isHostActive test"
  let ret = wifiManager.isHotspotActive()
  message = "HostActive is " + ret
  prompt.showToast({ message : message })
  return message
}

export function testSetHotspotConfigManager(): string{
  let message = "SetHotspotConfig test"
  let ssid1 ="testApp"
  let securityType1 = 3
  let band1 = 2;
  let preSharedKey1 ="12345678"
  let maxConn1 =3
  //  let ssid1 =AppStorage.Get("ssid1")
  //  let securityType1=AppStorage.Get("securityTpye1")
  //  let band1 = AppStorage.Get("band1")
  //  let preSharedKey1 = AppStorage.Get("preSharedKey1")
  //  let maxConn1 = AppStorage.Get("maxConn1")
  let hotspotConfig ={
    ssid:ssid1,
    securityType :securityType1,
    band :band1,
    preSharedKey:preSharedKey1,
    maxConn:maxConn1
  }
  let ret = wifiManager.setHotspotConfig(hotspotConfig)
  message = "SetHotspotConfig is" + ret
  prompt.showToast({ message : message })
  return message
}

export function testGetHotspotConfigManager() :string{
  let message = "getHotspotConfig test"
  let ret = wifiManager.getHotspotConfig()
  message = "HotspotConfig is " +JSON.stringify(ret)
  console.info("HotspotConfig is" + JSON.stringify(ret))
  prompt.showToast({message : message})
  return message
}

export function testGetHotspotStationsManager(): string{
  let message = "GetStations test"
  let ret =wifiManager.getHotspotStations()
  message = "GetStations is" + JSON.stringify(ret)
  console.info("GetStations is" + JSON.stringify(ret))
  prompt.showToast({message : message})
  return message
}

let hotspotStateChangeManager =false
export function testOnHotspotStateChangeManager():string{
  let message ="onHotspotStateChange test"
  console.log("testOnHotspotStateChange test");
  if(hotspotStateChangeManager){
    wifiManager.off("hotspotStateChange",()=>{
      prompt.showToast({message:"on.hotspotStateChange监听已关闭"})
    })
    message = "关闭注册热点状态改变事件"
  }else{
    wifiManager.on("hotspotStateChange",(number)=>{
      let hotspotStateMessage =""
      switch(number){
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
      prompt.showToast({ message: "状态为:" + hotspotStateMessage })
    })
    message = "打开注册热点状态变化"
    prompt.showToast({ message: message })
  }
  hotspotStateChangeManager = !hotspotStateChangeManager
  return message
}

let hotspotStaJoinManager =false
export function testOnHotspotStaJoinManager(){
  let message = "onHotspotStaJoin test"
  console.log(" testOnHotspotStaJoin ")
  if(hotspotStaJoinManager){
    wifiManager.off("hotspotStaJoin",()=>{
      prompt.showToast({message:"on.hotspotStaJoin监听已关闭"})
    })
    message = "关闭注册Wi-Fi 热点 sta加入变化事件"
  }else{
    wifiManager.on("hotspotStaJoin",(data)=>{
      let hotspotStaJoinMessage = "name:"+ data.name+";macAddress:"+data.macAddress +";ipAddress:"+data.ipAddress
      message = JSON.stringify(data)
      prompt.showToast({ message: hotspotStaJoinMessage })
    })
    message = "打开注册Wi-Fi 热点 sta加入变化"
    prompt.showToast({ message: message })
  }
  hotspotStaJoinManager = !hotspotStaJoinManager
  return message
}

let hotspotStaLeaveManager =false
export function testOnHotspotStaLeaveManager(){
  let message = "onHotspotStaLeave test"
  console.log(" testOnHotspotStaLeave ")
  if(hotspotStaLeaveManager){
    wifiManager.off("hotspotStaLeave",()=>{
      prompt.showToast({message:"on.hotspotStaLeave监听已关闭"})
    })
    message = "关闭注册Wi-Fi 热点 sta离开变化事件"
  }else{
    wifiManager.on("hotspotStaLeave",(data)=>{
      let hotspotStaLeaveMessage = "name:"+ data.name+";macAddress:"+data.macAddress +";ipAddress:"+data.ipAddress
      message = JSON.stringify(data)
      prompt.showToast({ message: hotspotStaLeaveMessage })
    })
    message = "打开注册Wi-Fi 热点 sta离开变化"
    prompt.showToast({ message: message })
  }
  hotspotStaLeaveManager = !hotspotStaLeaveManager
  return message
}

