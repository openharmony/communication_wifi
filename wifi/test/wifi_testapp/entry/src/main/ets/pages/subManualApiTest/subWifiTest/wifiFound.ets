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

import wifi from '@ohos.wifi'
import { AvailableWifi } from '../../../Component/availableWifi'
import { TitleBar } from '../../../Component/titleBar'
import ConfigData from '../../../Utils/ConfigData'

const TAG = '[wifiFound]'

/**
 * wifi Found Test Page Of Wifi test
 */
@Entry
@Component
struct WifiFound {
  private testItem: string = "Wlan扫描"
  private isScanning: boolean = false;
  @State wifiList: Array<wifi.WifiScanInfo> = []
  @State isLinked: boolean = false
  @State isSwitchOn: boolean = false
  @State linkedInfo: wifi.WifiLinkedInfo = {
    ssid : '' ,
    bssid : '' ,
    networkId : 0 ,
    rssi : 0 ,
    band : 0 ,
    linkSpeed : 0 ,
    frequency : 0 ,
    isHidden : false ,
    isRestricted : false ,
    chload : 0 ,
    snr : 0 ,
    macAddress : '' ,
    ipAddress : 0 ,
    suppState : wifi.SuppState.DISCONNECTED ,
    connState : wifi.ConnState.DISCONNECTED
  }

  scan() {
    if ( !this.isScanning ) {
      return; // 如果不需要扫描，则直接返回
    } else {
      wifi.getScanInfos((err , result) => {
        if ( err ) {
          console.log(TAG , `scan info err: ${ JSON.stringify(err) }`)
        }
        console.log(TAG , `scan info call back: ${ result.length }`)
        for ( let i = 0 ; i < result.length ; ++i ) {
          this.wifiList.push({
            ssid : result[ i ].ssid ,
            bssid : result[ i ].bssid ,
            capabilities : result[ i ].capabilities ,
            securityType : result[ i ].securityType ,
            rssi : result[ i ].rssi ,
            band : result[ i ].band ,
            frequency : result[ i ].frequency ,
            channelWidth : result[ i ].channelWidth ,
            timestamp : result[ i ].timestamp ,
          })
        }
        console.log(TAG , "wifiList:" + JSON.stringify(this.wifiList))
        if ( this.isScanning ) { // 再次检查是否还需要继续扫描
          setTimeout(() => {
            this.scan()
          } , 2000)
        }
      })
    }
  }

  getLinkedInfo() {
    wifi.getLinkedInfo((err , linkedInfo) => {
      if ( err ) {
        console.log(TAG , `getLinkedInfo err: ${ JSON.stringify(err) }`)
        return
      }
      console.log(TAG , `linkedInfo: ${ JSON.stringify(linkedInfo) }`)
      if ( linkedInfo === null || linkedInfo.bssid === '' ) {
        this.isLinked = false
        // this.linkedInfo.ssid ='空'
        return
      } else {
        this.isLinked = true
        this.linkedInfo = linkedInfo
      }
    })
  }

  addListener() {
    wifi.on('wifiConnectionChange' , state => {
      console.log(TAG , `wifiConnectionChange: ${ state }`)
      this.getLinkedInfo()
    })
    wifi.on('wifiStateChange' , state => {
      console.log(TAG , `wifiStateLisener state: ${ state }`)
      this.wifiList = []
      if ( state === 1 ) { // 1: wifi is enable, 0:wifi is disable
        wifi.scan()
        this.scan()
      }
    })
  }

  aboutToAppear() {
    if ( wifi.isWifiActive() ) {
      console.log(TAG , 'wifi is active')
      this.isSwitchOn = true
      this.isScanning = true; // 在页面出现时开始扫描
      wifi.scan()
      this.scan()
      this.getLinkedInfo()
    }
    this.addListener()
  }

  build() {
    Column() {
      Stack({ alignContent : Alignment.TopStart }) {
        TitleBar({ detail : this.testItem })
      }

      Row() {
        Text($r('app.string.wlan'))
          .fontSize(22)
          .fontWeight(FontWeight.Bold)
          .layoutWeight(1)
          .align(Alignment.TopStart)
        Column() {
          Toggle({ type : ToggleType.Switch , isOn : this.isSwitchOn })
            .onChange((isOn: boolean) => {
              console.log(TAG , `wifi swtich is: ${ isOn }`)
              this.wifiList = []
              if ( isOn ) {
                this.isSwitchOn = true
                wifi.enableWifi()
                wifi.scan()
                this.scan()
                return
              }
              this.isSwitchOn = false
              this.isLinked = false
              wifi.disconnect()
              wifi.disableWifi()
            })
        }
      }
      .width(ConfigData.WH_95_100)

      if ( this.isLinked ) {
        Text($r('app.string.wlanIsConnected'))
          .fontSize(22)
          .width(ConfigData.WH_95_100)
          .align(Alignment.TopStart)
        Row() {
          Text(this.linkedInfo.ssid)
            .fontSize(20)
            .fontColor(Color.Black)
            .layoutWeight(1)
          Text($r('app.string.wlanIsConnected'))
            .fontSize(18)
            .fontColor(Color.Black)
        }
        .width(ConfigData.WH_95_100)
        .padding(10)
        .margin(10)
        .border({ radius : 15 , color : Color.Gray , width : 1 })
        .backgroundColor(Color.White)
      }
      AvailableWifi({ wifiList : $wifiList , linkedInfo : $linkedInfo })
    }
    .size({ width : ConfigData.WH_100_100 , height : ConfigData.WH_100_100 })
    .backgroundColor('#F5F5F5')
  }

  aboutToDisappear() {
    this.isScanning = false; // 设置标志，告诉scan方法停止新的扫描
    wifi.off('wifiConnectionChange')
    wifi.off('wifiStateChange')
  }
}