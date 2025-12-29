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

import { PswDialog } from '../component/pswDialog';
import { WifiModel } from '../entryability/model/wifiModel';
import { WifiView } from '../component/wifiView';
import wifiManager from '@ohos.wifiManager';
import ConfigData from '../utils/ConfigData';
import promptAction from '@ohos.promptAction';

const TAG = "wifiTestApp [availableWiFi]"

/**
 * available wifi page of WiFi test
 */

@Component
export struct AvailableWifi {
  private wifiModel: WifiModel = new WifiModel()
  @Link wifiList!: Array<wifiManager.WifiScanInfo>
  @Link linkedInfo!: wifiManager.WifiLinkedInfo
  @State selectIndex: number = - 1
  private pswDialogController: CustomDialogController = new CustomDialogController({
    builder: PswDialog({ scanInfo: this.wifiList[this.selectIndex], action: this.onAccept }) ,
    autoCancel: true
  })

  onAccept(scanInfo: wifiManager.WifiScanInfo, psw: string) {
    console.log(TAG, 'connect wifi')
    let connectInfo: wifiManager.WifiDeviceConfig
    connectInfo = {
      ssid: scanInfo.ssid ,
      bssid: scanInfo.bssid ,
      bssidType:scanInfo.bssidType,
      preSharedKey: psw ,
      securityType: scanInfo.securityType
    };
    connectInfo.ssid = scanInfo.ssid;
    connectInfo.bssid =scanInfo.bssid;
    connectInfo.bssidType =scanInfo.bssidType;
    connectInfo.preSharedKey = psw;
    connectInfo.securityType = scanInfo.securityType;
    console.log(TAG, "connectInfo:" +JSON.stringify(connectInfo))
    promptAction.showToast({ message: 'connecting' })
    console.log(TAG, `connectNetwork bssid=${ connectInfo.bssid }`)
    try {
      wifiManager.connectToDevice(connectInfo)
      console.log(TAG, `connectToDevice success`)
    } catch( error) {
      console.log(TAG, `connectToDevice fail. message: ${ error.message }, code: ${ error.code }`)
    }
  }

  aboutToAppear() {
    console.info(TAG, "wifiList:" + JSON.stringify(this.wifiList))
  }

  build() {
    Column() {
      Row() {
        Text($r('app.string.wlan_available'))
          .fontSize(22)
          .layoutWeight(1)
          .align(Alignment.TopStart)
      }
      .width(ConfigData.WH_95_100)

      List() {
        ForEach(this.wifiList, (item: wifiManager.WifiScanInfo, index) => {
          ListItem() {
            WifiView({ wifiScanInfo: item })
          }
          .onClick(() => {
            console.log(TAG, 'wifi click')
            this.selectIndex = index
            if (this.linkedInfo !== null && item.ssid === this.linkedInfo.ssid) {
              promptAction.showToast({ message: 'this wifi is connected' })
              return
            }
            if (item.securityType === 0 || item.securityType === 1) {
              let connectInfo: wifiManager.WifiDeviceConfig
              connectInfo = {
                ssid: item.ssid ,
                preSharedKey: '' ,
                securityType: item.securityType
              }
              this.wifiModel.connectNetwork(connectInfo)
              return
            }
            this.pswDialogController.open()
          })
        }, (item: wifiManager.WifiScanInfo) => JSON.stringify(item))
      }
      .layoutWeight(1)
      .divider({ strokeWidth: 1, color: Color.Gray, startMargin: 10, endMargin: 10 })
      .margin(10)
    }
    .margin({ top: 15, bottom: 100 })
  }
}