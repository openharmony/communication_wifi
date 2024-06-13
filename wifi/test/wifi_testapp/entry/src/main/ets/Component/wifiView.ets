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

import ConfigData from '../utils/ConfigData';
import wifi from '@ohos.wifi';

/**
 * WifiView Component of wifi test
 */

const TAG = "[wifiView]"

@Component
export struct WifiView {
  private wifi!: wifi.WifiScanInfo;
  private securityString: Resource = $r('app.string.encryption')
  @State isLock: boolean = true

  aboutToAppear() {
    console.log(TAG , `aboutToAppear ${ JSON.stringify(this.wifi) }`)
    if ( this.wifi ) {
      if ( this.wifi.securityType ) {
        if ( this.wifi.securityType === 1 ) {
          this.securityString = $r('app.string.open')
          this.isLock = false
        } else {
          console.log(TAG , "this.wifi.securityType /= 0 && this.wifi.securityType /= 1")
        }
      } else {
        console.log(TAG , "this.wifi.securityType is false")
      }
    } else {
      console.log(TAG , "this.wifi is false")
    }
  }

  build() {
    Row() {
      Column() {
        if ( this.wifi ) {
          if ( this.wifi.ssid ) {
            Text(this.wifi.ssid)
              .fontSize(20)
              .width(ConfigData.WH_100_100)
          }
        }
        Text(this.securityString)
          .fontSize(18)
          .fontColor(Color.Gray)
          .width(ConfigData.WH_100_100)
      }
      .layoutWeight(1)

      Stack({ alignContent : Alignment.BottomEnd }) {
        Image($r('app.media.wifi'))
          .height(30).width(30)
          .objectFit(ImageFit.Contain)
        if ( this.isLock ) {
          Image($r('app.media.lock'))
            .objectFit(ImageFit.Contain)
            .width(15).height(15)
        }
      }
      .width(40).height(40)
      .margin({ right : 10 })
    }
    .backgroundColor(Color.White)
    .width(ConfigData.WH_100_100)
    .padding(10)
  }
}