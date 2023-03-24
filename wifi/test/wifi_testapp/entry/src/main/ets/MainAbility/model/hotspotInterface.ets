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
 *hotspot Test Page Of Wifi test
 */


import prompt from '@system.prompt';
import Router from '@system.router';

import wifi from '@ohos.wifi';



let hotspotEnable =false
export function testEnableHotspot(): string {
  let message = " enableHotspot test"
  if(hotspotEnable) {
    message ="热点已经使能"
  }else{
    let ret =wifi.enableHotspot()
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

export function testDisableHotspot():string {
  let message = "disableWifi test"
  if (!hotspotEnable) {
    message = '热点还未使能';
  }else {
    let ret = wifi.disableHotspot();
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

export function testIsHotspotDualBandSupported(): string {
  let message =" isHotspotDualBandSupported test"
  let ret =wifi.isHotspotDualBandSupported()
  message ="热点支持双频结果：" + ret
  prompt.showToast({message:message})
  return message
}

export function testIsHostActive():string {
  let message = "isHostActive test"
  let ret = wifi.isHotspotActive()
  message = "HostActive is " + ret
  prompt.showToast({ message : message })
  return message
}

export function testSetHotspotConfig(): string{
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
  let hotspotConfigs ={
    ssid:ssid1,
    securityType :securityType1,
    band :band1,
    preSharedKey:preSharedKey1,
    maxConn:maxConn1
  }
  let ret = wifi.setHotspotConfig(hotspotConfigs)
  message = "SetHotspotConfig is" + ret
  prompt.showToast({ message : message })
  return message
}

export function testGetHotspotConfig() :string{
  let message = "getHotspotConfig test"
  let ret = wifi.getHotspotConfig()
  message = "HotspotConfig is " +JSON.stringify(ret)
  console.info("HotspotConfig is" + JSON.stringify(ret))
  prompt.showToast({message : message})
  return message
}

export function testGetStations(): string{
  let message = "GetStations test"
  let ret =wifi.getStations()
  message = "GetStations is" + JSON.stringify(ret)
  console.info("GetStations is" + JSON.stringify(ret))
  prompt.showToast({message : message})
  return message
}

let hotspotStateChange =false
export function testOnHotspotStateChange():string{
  let message ="onHotspotStateChange test"
  console.log("testOnHotspotStateChange test");
  if(hotspotStateChange){
    wifi.off("hotspotStateChange",()=>{
      prompt.showToast({message:"on.hotspotStateChange监听已关闭"})
    })
    message = "关闭注册热点状态改变事件"
  }else{
    wifi.on("hotspotStateChange",(number)=>{
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
  hotspotStateChange = !hotspotStateChange
  return message
}

let hotspotStaJoin =false
export function testOnHotspotStaJoin(){
  let message = "onHotspotStaJoin test"
  console.log(" testOnHotspotStaJoin ")
  if(hotspotStaJoin){
    wifi.off("hotspotStaJoin",()=>{
      prompt.showToast({message:"on.hotspotStaJoin监听已关闭"})
    })
    message = "关闭注册Wi-Fi 热点 sta加入变化事件"
  }else{
    wifi.on("hotspotStaJoin",(data)=>{
      let hotspotStaJoinMessage = "name:"+ data.name+";macAddress:"+data.macAddress +";ipAddress:"+data.ipAddress
      message = JSON.stringify(data)
      prompt.showToast({ message: hotspotStaJoinMessage })
    })
    message = "打开注册Wi-Fi 热点 sta加入变化"
    prompt.showToast({ message: message })
  }
  hotspotStaJoin = !hotspotStaJoin
  return message
}

let hotspotStaLeave =false
export function testOnHotspotStaLeave(){
  let message = "onHotspotStaLeave test"
  console.log(" testOnHotspotStaLeave ")
  if(hotspotStaLeave){
    wifi.off("hotspotStaLeave",()=>{
      prompt.showToast({message:"on.hotspotStaLeave监听已关闭"})
    })
    message = "关闭注册Wi-Fi 热点 sta离开变化事件"
  }else{
    wifi.on("hotspotStaLeave",(data)=>{
      let hotspotStaLeaveMessage = "name:"+ data.name+";macAddress:"+data.macAddress +";ipAddress:"+data.ipAddress
      message = JSON.stringify(data)
      prompt.showToast({ message: hotspotStaLeaveMessage })
    })
    message = "打开注册Wi-Fi 热点 sta离开变化"
    prompt.showToast({ message: message })
  }
  hotspotStaLeave = !hotspotStaLeave
  return message
}