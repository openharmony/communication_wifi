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

import hilog from '@ohos.hilog';
import ConfigData from '../Utils/ConfigData';
import wifiManager from '@ohos.wifiManager';

/**
 * WifiView Component of wifi test
 */

const TAG = "wifiTestAppApp [wifiView]"

@Component
export struct WifiView {
  private wifiScanInfo!: wifiManager.WifiScanInfo;
  private securityString: Resource = $r('app.string.encryption')
  @State isLock: boolean = true

  aboutToAppear() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `aboutToAppear ${ JSON.stringify(this.wifiScanInfo) }`)
    if (this.wifiScanInfo){
      if (this.wifiScanInfo.securityType){
        if (this.wifiScanInfo.securityType === 1){
          this.securityString = $r('app.string.open')
          this.isLock = false
        } else {
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "this.wifi.securityType != 0 && this.wifi.securityType != 1")
        }
      } else {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "this.wifi.securityType is false")
      }
    } else {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "this.wifi is false")
    }
  }

  build() {
    Row() {
      Column() {
        if (this.wifiScanInfo){
          if (this.wifiScanInfo.ssid){
            Text(this.wifiScanInfo.ssid)
              .fontSize(ConfigData.VP_20)
              .width(ConfigData.WH_100_100)
          }
        }
        Text(this.securityString)
          .fontSize(ConfigData.VP_18)
          .fontColor($r('app.color.color_999999_grey'))
          .width(ConfigData.WH_100_100)
      }
      .layoutWeight(1)

      Stack({alignContent: Alignment.BottomEnd}){
        Image($r('app.media.wifi'))
          .height(ConfigData.VP_30).width(ConfigData.VP_30)
          .objectFit(ImageFit.Contain)
        if (this.isLock){
          Image($r('app.media.lock'))
            .objectFit(ImageFit.Contain)
            .width(ConfigData.VP_15).height(ConfigData.VP_15)
        }
      }
      .width(ConfigData.VP_40).height(ConfigData.VP_40)
      .margin({right: ConfigData.VP_10})
    }
    .backgroundColor($r('app.color.white'))
    .width(ConfigData.WH_100_100)
    .padding(ConfigData.VP_10)
  }
}