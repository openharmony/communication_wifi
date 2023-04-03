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
 *p2p Test Page Of Wifi test
 */


import prompt from '@system.prompt';
import Router from '@system.router';
import wifi from '@ohos.wifi';

export function testGetP2pLinkedInfoPromise():string{
  let message = ($r("app.string.testGetP2pLinkedInfoPromise"))
  wifi.getP2pLinkedInfo().then(wifiP2pLinkedInfo=>{
    console.info("getP2pLinkedInfoPromise successful")
    console.info("getP2pLinkedInfoPromise: " + JSON.stringify(wifiP2pLinkedInfo))
    message ="getP2pLinkedInfoPromise: " + JSON.stringify(wifiP2pLinkedInfo)
    prompt.showToast({message:message})
  })
  prompt.showToast({message:message})
  return message
}

export function testGetP2pLinkedInfoCallback():string{
  let message = ($r("app.string.testGetP2pLinkedInfoCallback"))
  wifi.getP2pLinkedInfo((err,WifiP2pLinkedInfo)=>{
    if(err) {
      console.error("getP2pLinkedInfoCallback error")
      return message;
    }
    console.info("getP2pLinkedInfoCallback successful")
    console.info("getP2pLinkedInfoCallback: " + JSON.stringify(WifiP2pLinkedInfo))
    message ="getP2pLinkedInfoCallback: " + JSON.stringify(WifiP2pLinkedInfo)
    prompt.showToast({message:message})
  })
  prompt.showToast({message:message})
  return message
}

export function testGetCurrentGroupPromise():string{
  let message =($r("app.string.testGetCurrentGroupPromise"))
  wifi.getCurrentGroup().then(WifiP2pGroupInfo=>{
    console.info("getCurrentGroupPromise successful")
    console.info("getCurrentGroupPromise: " + JSON.stringify(WifiP2pGroupInfo))
    message ="getCurrentGroupPromise: " + JSON.stringify(WifiP2pGroupInfo)
    prompt.showToast({ message:message })
  })
  prompt.showToast({ message:message })
  return message
}

export function testGetCurrentGroupCallback():string{
  let message =($r("app.string.testGetCurrentGroupCallback"))
  wifi.getCurrentGroup((err,WifiP2pGroupInfo)=>{
    if(err){
      console.error("getCurrentGroupCallback error")
      return message;
    }
    console.info("getCurrentGroupCallback successful")
    console.info("getCurrentGroupCallback: " + JSON.stringify(WifiP2pGroupInfo))
    message ="getCurrentGroupCallback: " + JSON.stringify(WifiP2pGroupInfo)
    prompt.showToast({ message:message })
  })
  prompt.showToast({message:message})
  return message
}

export function testGetP2pPeerDevicesPromise() {
  let message = ($r("app.string.testGetP2pPeerDevicesPromise"))
  wifi.getP2pPeerDevices().then(WifiP2pDevice=>{
    console.info("getP2pPeerDevicesPromise successful")
    console.info("getP2pPeerDevicesPromise: " + JSON.stringify(WifiP2pDevice))
    message ="getP2pPeerDevicesPromise: " + JSON.stringify(WifiP2pDevice)
    prompt.showToast({ message:message })
  })
  prompt.showToast({message:message})
  return message
}

export function testGetP2pPeerDevicesCallback() {
  let message = ($r("app.string.testGetP2pPeerDevicesCallback"))
  wifi.getP2pPeerDevices((err,WifiP2pDevice)=>{
    if(err){
      console.error("getP2pPeerDevicesCallback error")
      return message;
    }
    console.info("getP2pPeerDevicesPromise successful")
    console.info("getP2pPeerDevicesCallback: " + JSON.stringify(WifiP2pDevice))
    message ="getP2pPeerDevicesCallback: " + JSON.stringify(WifiP2pDevice)
    prompt.showToast({ message:message })
  })
  prompt.showToast({message:message})
  return message
}

export function testCreateGroup():string{
  let message =($r("app.string.testCreateGroup"))
  let deviceAddress = AppStorage.Get("deviceAddress")
  let netId = AppStorage.Get("netId")
  let passphrase = AppStorage.Get("passphrase")
  let groupName = AppStorage.Get("groupName")
  let goBand =AppStorage.Get("goBand")
  let wifiP2pConfig ={
    deviceAddress:deviceAddress,
    netId:netId,
    passphrase:passphrase,
    groupName:groupName,
    goBand:goBand
  }
  AppStorage.SetOrCreate("wifiP2pConfig",wifiP2pConfig)
  let ret =wifi.createGroup(wifiP2pConfig)
  message ="createGroup: "+ ret
  return message
}

export function testRemoveGroup():string{
  let message =($r("app.string.testRemoveGroup"))
  let ret =wifi.removeGroup()
  message ="removeGroup: "+ ret
  prompt.showToast({message:message})
  return message
}

export function testP2pConnect(): string{
  let message =($r("app.string.testP2pConnect"))
  let wifiP2pConfig =AppStorage.Get("wifiP2pConfig")
  let ret =wifi.p2pConnect(wifiP2pConfig)
  message ="p2pConnect: " + ret
  prompt.showToast({message:message})
  return message
}

export function testP2pCancelConnect():string{
  let message =($r("app.string.testP2pCancelConnect"))
  let ret =wifi.p2pCancelConnect()
  message ="p2pCancelConnect: "+ret
  prompt.showToast({message:message})
  return message
}

export function testStartDiscoverDevices():string{
  let message =($r("app.string.testStartDiscoverDevices"))
  let ret = wifi.startDiscoverDevices()
  message = "startDiscoverDevices: "+ ret
  prompt.showToast({message:message})
  return message
}

export function testStopDiscoverDevices():string{
  let message =($r("app.string.testStopDiscoverDevices"))
  let ret =wifi.stopDiscoverDevices()
  message= "stopDiscoverDevices: "+ret
  prompt.showToast({message:message})
  return message
}

export function testDeletePersistentGroup():string{
  let message =($r("app.string.testDeletePersistentGroup"))
  let netId =AppStorage.Get("netId")
  let ret=wifi.deletePersistentGroup(netId)
  message ="deletePersistentGroup: "+ ret
  prompt.showToast({message:message})
  return message
}

export function testSetDeviceName():string{
  let message =($r("app.string.testSetDeviceName"))
  let devName = AppStorage.Get("devName")
  let ret =wifi.setDeviceName(devName)
  message="setDeviceName: "+ ret
  prompt.showToast({message:message})
  return message
}

let p2pStateChange = false
export function testOnP2pStateChange():string{
  let message = ($r("app.string.testOnP2pStateChange"))
  console.log("testOnP2pStateChange test");
  if(p2pStateChange){
    wifi.off("p2pStateChange",()=>{
      prompt.showToast({message: ($r("app.string.offP2pStateChange"))})
    })
    message = ($r("app.string.offP2pStateChangeTest"))
  }else{
    wifi.on("p2pStateChange",(number)=>{
//  @returns Returns 1: idle, 2: starting, 3:started, 4: closing, 5: closed
      let p2pStateMessage =""
      switch(number){
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
      prompt.showToast({ message: "状态: " + p2pStateMessage })
    })
    message = ($r("app.string.onP2pStateChangeTest"))
    prompt.showToast({ message: message })
  }
  p2pStateChange = !p2pStateChange
  return message
}

let p2pConnectionChange =false
export function testOnP2pConnectionChange():string{
  let message = ($r("app.string.testOnP2pConnectionChange"))
  console.log("testOnP2pConnectionChange test");
  if(p2pConnectionChange){
    wifi.off("p2pConnectionChange",()=>{
      prompt.showToast({message:($r("app.string.offP2pConnectionChange"))})
    })
    message = ($r("app.string.offP2pConnectionChangeTest"))
  }else{
    wifi.on("p2pConnectionChange",(WifiP2pLinkedInfo)=>{
      let connectState = WifiP2pLinkedInfo.connectState
      let p2pConnectionMessage=""
      switch(connectState){
        case 0:
          p2pConnectionMessage = "DISCONNECTED!";
          break;
        case 1:
          p2pConnectionMessage = "CONNECTED！";
          break;
        default:
          p2pConnectionMessage = '未知状态';
          break;
      }
      let isGroupOwner = WifiP2pLinkedInfo.isGroupOwner
      let groupOwnerAddr = WifiP2pLinkedInfo.groupOwnerAddr
      message= "Info : "+ p2pConnectionMessage + ",isGroupOwner: "+ isGroupOwner + ",groupOwnerAddr: " + groupOwnerAddr
      prompt.showToast({ message: message})
    })
    message = ($r("app.string.onP2pConnectionChangeTest"))
    prompt.showToast({ message: message })
  }
  p2pConnectionChange = !p2pConnectionChange
  return message
}

let p2pDeviceChange =false
export function testOnP2pDeviceChange():string{
  let message =($r("app.string.testOnP2pDeviceChange"))
  console.log("testOnP2pDeviceChange test")
  if(p2pDeviceChange){
    wifi.off("p2pDeviceChange",()=>{
      prompt.showToast({message:($r("app.string.offP2pDeviceChange"))})
    })
    message = ($r("app.string.offP2pDeviceChangeTest"))
  }else{
    wifi.on("p2pDeviceChange",(data)=>{
//      let p2pDeviceChangeMessage =""
      let p2pDeviceStatusMessage =""
      let deviceName = data.deviceName
      let deviceAddress = data.deviceAddress
      let primaryDeviceType =data.primaryDeviceType
      let deviceStatus =data.deviceStatus
      let groupCapabilitys = data.groupCapabilitys
      switch(deviceStatus){
        case 0 :
          p2pDeviceStatusMessage ="CONNECTED"
          break;
        case 1 :
          p2pDeviceStatusMessage ="INVITED"
          break;
        case 2 :
          p2pDeviceStatusMessage ="FAILED"
          break;
        case 3 :
          p2pDeviceStatusMessage ="AVAILABLE"
          break;
        case 4 :
          p2pDeviceStatusMessage ="UNAVAILABLE"
          break;
        default:
          p2pDeviceStatusMessage = '未知状态';
          break;
      }
      console.info("info:"+JSON.stringify(data))
      message = "deviceName: "+deviceName+"\n"+
                "deviceAddress: "+deviceAddress+"\n"+
                "primaryDeviceType: "+primaryDeviceType+"\n"+
                "deviceStatus: "+p2pDeviceStatusMessage+"\n"+
                "groupCapabilitys: "+groupCapabilitys+"\n"
      prompt.showToast({message:message})
    })
    message = ($r("app.string.onP2pDeviceChangeTest"))
    prompt.showToast({ message: message })
  }
  p2pDeviceChange = !p2pDeviceChange
  return message
}

let p2pPeerDeviceChange =false
export function testOnP2pPeerDeviceChange():string{
  let message =($r("app.string.testOnP2pPeerDeviceChange"))
  console.log("testOnP2pPeerDeviceChange test")
  if(p2pPeerDeviceChange){
    wifi.off("p2pPeerDeviceChange",()=>{
      prompt.showToast({message:($r("app.string.offP2pPeerDeviceChange")) })
    })
    message = ($r("app.string.offP2pPeerDeviceChangeTest"))
  }else{
    wifi.on("p2pPeerDeviceChange",(data)=>{
      let p2pPeerDeviceChangeMessage =""
      console.info("WifiP2pDevice: "+JSON.stringify(data))
      p2pPeerDeviceChangeMessage = "WifiP2pDevice: "+JSON.stringify(data)
      prompt.showToast({message:"状态 "+ p2pPeerDeviceChangeMessage})
    })
    message = ($r("app.string.onP2pPeerDeviceChangeTest"))
    prompt.showToast({ message: message })
  }
  p2pPeerDeviceChange = !p2pPeerDeviceChange
  return message
}

let p2pPersistentGroupChange =false
export function testOnP2pPersistentGroupChange():string{
  let message =($r("app.string.testOnP2pPersistentGroupChange"))
  console.log("testOnP2pPersistentGroupChange test")
  if(p2pPersistentGroupChange){
    wifi.off("p2pPersistentGroupChange",()=>{
      prompt.showToast({message:($r("app.string.offP2pPersistentGroupChange"))})
    })
    message = ($r("app.string.offP2pPersistentGroupChangeTest"))
  }else{
    wifi.on("p2pPersistentGroupChange",(data)=>{
      let p2pPersistentGroupChangeMessage =""
      console.info("p2pPersistentGroupChange: "+ data)
      p2pPersistentGroupChangeMessage = "p2pPersistentGroupChange: "+ data
      prompt.showToast({message:"状态: "+ p2pPersistentGroupChangeMessage})
    })
    message = ($r("app.string.onP2pPersistentGroupChangeTest"))
    prompt.showToast({ message: message })
  }
  p2pPersistentGroupChange = !p2pPersistentGroupChange
  return message
}

let p2pDiscoveryChange = false
export function testOnP2pDiscoveryChange():string{
  let message =($r("app.string.testOnP2pDiscoveryChange"))
  console.log("testOnP2pDiscoveryChange test")
  if(p2pDiscoveryChange){
    wifi.off("p2pDiscoveryChange",()=>{
      prompt.showToast({message:($r("app.string.offP2pDiscoveryChange"))})
    })
    message = ($r("app.string.offP2pDiscoveryChangeTest"))
  }else{
    wifi.on("p2pDiscoveryChange",(number)=>{
//      @returns Returns 0: initial state, 1: discovery succeeded
      let p2pDiscoveryChangeMessage =""
      switch(number){
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
      prompt.showToast({message:"发现状态："+ p2pDiscoveryChangeMessage})
    })
    message =($r("app.string.onP2pDiscoveryChangeTest"))
    prompt.showToast({ message: message })
  }
  p2pDiscoveryChange = !p2pDiscoveryChange
  return message
}



