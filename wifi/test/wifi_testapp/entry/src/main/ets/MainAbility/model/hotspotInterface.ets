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
  let message =  $r('app.string.testEnableHotspot')
  console.info("EnableHotspot start--------------")
  if(hotspotEnable) {
    message =$r('app.string.hotspot_enable')
  }else{
    let ret =wifi.enableHotspot()
    if(ret){
      message ="热点使能执行结果：" + ret;
    }else{
      message ="使能结果："+ ret+"\n"
      message +="热点已打开或打开失败,请确认"
    }
    hotspotEnable = true
    AppStorage.SetOrCreate('hotspotIsOn', hotspotEnable);
  }
  prompt.showToast({ message: message })
  return message
  console.info("EnableHotspot end--------------")
}

export function testDisableHotspot():string {
  let message =  $r('app.string.testDisableHotspot')
  if (!hotspotEnable) {
    message =$r('app.string.hotspot_disEnable')
  }else {
    let ret = wifi.disableHotspot();
    if (ret) {
      message ="热点去使能执行结果：" + ret;
    } else {
      message = "去使能结果："+ ret + "\n"
      message += "热点已关闭或关闭失败,请确认"
    }
    hotspotEnable = false;
    AppStorage.SetOrCreate('hotspotIsOn', hotspotEnable);
  }
  prompt.showToast({ message: message })
  return message
}

export function testIsHotspotDualBandSupported(): string {
  let message =$r('app.string.testIsHotspotDualBandSupported')
  let ret =wifi.isHotspotDualBandSupported()
  message ="热点支持双频结果：" + ret
  prompt.showToast({message:message})
  return message
}

export function testIsHostActive():string {
  let message = $r('app.string.testIsHotspotActive')
  let ret = wifi.isHotspotActive()
  if(ret){
    hotspotEnable =true
  }else{
    hotspotEnable =false
  }
  message = "热点使能结果为：" + ret
  prompt.showToast({ message : message })
  return message
}

export function testSetHotspotConfig(): string{
  let message = $r('app.string.testSetHotspotConfig')
  console.info("testSetHotspotConfig start-----------")
  let ssid ="testApp"
  let securityType = 3
  let band = 1;
  let preSharedKey ="12345678"
  let maxConn =3
  let channel = 6
//  let ssid1 =AppStorage.Get("ssid1")
//  let securityType1=AppStorage.Get("securityTpye1")
//  let band1 = AppStorage.Get("band1")
//  let preSharedKey1 = AppStorage.Get("preSharedKey1")
//  let maxConn1 = AppStorage.Get("maxConn1")
  let hotspotConfigs ={
    ssid:ssid,
    securityType :securityType,
    band :band,
    preSharedKey:preSharedKey,
    maxConn:maxConn,
    channel:channel
  }
  let ret = wifi.setHotspotConfig(hotspotConfigs)
  message = "SetHotspotConfig: " + ret
  prompt.showToast({ message : message })
  console.info("testSetHotspotConfig end-----------")
  return message
}

export function testGetHotspotConfig() :string{
  let message = $r('app.string.testGetHotspotConfig')
  let ret = wifi.getHotspotConfig()
  message = "HotspotConfig: " +JSON.stringify(ret)
  console.info("HotspotConfig is: " + JSON.stringify(ret))
  let getHotspotConfigMessage = JSON.stringify(ret)
  AppStorage.SetOrCreate("getHotspotConfigMessage",getHotspotConfigMessage)
  prompt.showToast({message : message})
  return message
}

export function testGetStations(): string{
  let message = $r('app.string.testGetStations')
  console.info("testGetStations start--------------------")
  let ret =wifi.getStations()
  message = "GetStations is: "+ JSON.stringify(ret)
  console.info("GetStations is: " + JSON.stringify(ret))
  let getStationsMessage = JSON.stringify(ret)
  AppStorage.SetOrCreate("getStationsMessage",getStationsMessage)
  console.info("testGetStations end--------------------")
  prompt.showToast({message : message})
  return message
}

let hotspotStateChange =false
export function testOnHotspotStateChange():string{
  let message = $r('app.string.testOnHotspotStateChange')
  console.log("testOnHotspotStateChange test");
  if(hotspotStateChange){
    wifi.off("hotspotStateChange",()=>{
      prompt.showToast({message: $r('app.string.offHotspotStateChange')})
    })
    message = $r('app.string.offHotspotStateChangeTest')
  }else{
    wifi.on("hotspotStateChange",(number)=>{
      console.log("on.hotspotStateChange start--------------------");
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
      prompt.showToast({ message: "状态为: "+ hotspotStateMessage })
      AppStorage.SetOrCreate("hotspotStateMessage",hotspotStateMessage)
      console.log("on.hotspotStateChange end--------------------");
    })
    message = $r('app.string.onHotspotStateChangeTest')
    prompt.showToast({ message: message })
  }
  hotspotStateChange = !hotspotStateChange
  return message
}

let hotspotStaJoin =false
export function testOnHotspotStaJoin(){
  let message = $r('app.string.testOnHotspotStaJoin')
  console.log(" testOnHotspotStaJoin ")
  if(hotspotStaJoin){
    wifi.off("hotspotStaJoin",()=>{
      prompt.showToast({message: $r('app.string.offHotspotStaJoin')})
    })
    message = $r('app.string.offHotspotStaJoinTest')
  }else{
    wifi.on("hotspotStaJoin",(data)=>{
      let hotspotStaJoinMessage = "name:"+ data.name+";macAddress:"+data.macAddress +";ipAddress:"+data.ipAddress
      message ="状态为: "+ JSON.stringify(data)
      AppStorage.SetOrCreate("hotspotStaJoinMessage",message)
      prompt.showToast({ message: hotspotStaJoinMessage })
    })
    message = $r('app.string.onHotspotStaJoinTest')
    prompt.showToast({ message: message })
  }
  hotspotStaJoin = !hotspotStaJoin
  return message
}

let hotspotStaLeave =false
export function testOnHotspotStaLeave(){
  let message = $r('app.string.testOnHotspotStaLeave')
  console.log(" testOnHotspotStaLeave ")
  if(hotspotStaLeave){
    wifi.off("hotspotStaLeave",()=>{
      prompt.showToast({message:$r('app.string.offHotspotStaLeave') })
    })
    message = $r('app.string.offHotspotStaLeaveTest')
  }else{
    wifi.on("hotspotStaLeave",(data)=>{
      let hotspotStaLeaveMessage = "name:"+ data.name+";macAddress:"+data.macAddress +";ipAddress:"+data.ipAddress
      message ="状态为: "+ JSON.stringify(data)
      AppStorage.SetOrCreate("hotspotStaLeaveMessage",message)
      prompt.showToast({ message: hotspotStaLeaveMessage })
    })
    message = $r('app.string.onHotspotStaLeaveTest')
    prompt.showToast({ message: message })
  }
  hotspotStaLeave = !hotspotStaLeave
  return message
}

