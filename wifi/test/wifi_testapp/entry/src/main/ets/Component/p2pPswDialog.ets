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

import wifi from '@ohos.wifi';
import wifiManager from '@ohos.wifiManager';
import ConfigData from '../Utils/ConfigData';
/**
 * PswDialog page of WiFi test
 */

@CustomDialog
export struct P2pPswDialog {
  private p2pScanInfo!: wifiManager.WifiP2pDevice
  private psw: string = ''
  private controller: CustomDialogController
  private action!: (p2pScanInfo: wifiManager.WifiP2pDevice, psw: string) => void

  build() {
    Column() {
      Text(this.p2pScanInfo.deviceName)
        .fontSize(ConfigData.VP_20)
        .width(ConfigData.WH_95_100)
      TextInput({placeholder: $r('app.string.wifitest_text_ip')})
        .key('input')
        .type(InputType.Password)
        .placeholderColor($r('app.color.color_999999_grey'))
        .fontSize(ConfigData.VP_19)
        .margin({top: ConfigData.VP_15})
        .width(ConfigData.WH_95_100)
        .onChange((value: string) => {
          this.psw = value
        })
      Row() {
        Button() {
          Text($r('app.string.sure'))
            .fontColor($r('app.color.main_blue'))
            .fontSize(ConfigData.VP_17)
        }
        .layoutWeight(7)
        .backgroundColor($r('app.color.white'))
        .margin(ConfigData.VP_5)
        .onClick(() => {
          this.controller.close()
          this.action(this.p2pScanInfo, this.psw)
        })

        Text()
          .width(ConfigData.VP_1).height(ConfigData.VP_35)
          .backgroundColor($r("app.color.ohcc_hex_8f8f8f"))
        Button() {
          Text($r('app.string.cancel'))
            .fontColor($r('app.color.red'))
            .fontSize(ConfigData.VP_17)
        }
        .layoutWeight(7)
        .backgroundColor($r('app.color.white'))
        .margin(ConfigData.VP_5)
        .onClick(() => {
          this.controller.close()
        })
      }
      .width(ConfigData.WH_100_100)
      .margin({top: ConfigData.WH_3_100})
    }
    .padding(ConfigData.VP_15)
  }
}