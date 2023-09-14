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

import prompt from '@ohos.prompt'
import { PswDialog } from '../Component/pswDialog'
import { WifiModel } from '../MainAbility/model/wifiModel'
import { WifiView } from '../Component/wifiView'
import wifi from '@ohos.wifi'

const TAG = "[availableWiFi]"
let self = null

/**
 * available wifi page of WiFi test
 */

@Component
export struct AvailableWifi {
  private wifiModel: WifiModel = new WifiModel()
  @Prop wifiList:Array<wifi.WifiScanInfo>
  @Prop linkedInfo: any
  @State selectIndex: number = -1
  private pswDialogController: CustomDialogController = new CustomDialogController({
    builder: PswDialog({ scanInfo: this.wifiList[this.selectIndex], action: this.onAccept }),
    autoCancel: true
  })

  onAccept(scanInfo, psw) {
   console.log(TAG, 'connect wifi')
    self.wifiModel.connectNetwork(scanInfo, psw)
  }

  aboutToAppear() {
    self = this
  }

  build() {
    Column() {
      Row() {
        Text($r('app.string.wlan_available'))
          .fontSize(22)
          .layoutWeight(1)
          .align(Alignment.TopStart)
      }
      .width('95%')

      List() {
        ForEach(this.wifiList, (item, index) => {
          ListItem() {
            WifiView({ wifi: item })
          }
          .onClick(() => {
           console.log(TAG, 'wifi click')
            this.selectIndex = index
            if (this.linkedInfo !== null && item.ssid === this.linkedInfo.ssid) {
              prompt.showToast({ message: 'this wifi is connected' })
              return
            }
            if (item.securityType === 0 || item.securityType === 1) {
              this.wifiModel.connectNetwork(item, '')
              return
            }
            this.pswDialogController.open()
          })
        }, item => JSON.stringify(item))
      }
      .layoutWeight(1)
      .divider({ strokeWidth: 1, color: Color.Gray, startMargin: 10, endMargin: 10 })
      .margin(10)
    }
    .margin({ top: 15, bottom: 100 })
  }
}