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
import { testOnP2pConnectionChange, testGetCurrentGroupCallback} from '../entryability/model/p2pInterface';
import wifi from '@ohos.wifi';
import wifiManager from '@ohos.wifiManager';

/**
 * P2pView Component of p2p test
 */
const TAG = "wifiTestApp [P2pView]"

@Component
export struct P2pView {
  private p2p!: wifiManager.WifiP2pDevice
  private securityString: Resource = $r('app.string.useful')
  private p2pConnectState: number = 0
  @StorageLink("p2pLinkedDeviceName") p2pLinkedDeviceName: string = ""
  @State isLock: boolean = true

  aboutToAppear() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `aboutToAppear ${ JSON.stringify(this.p2p) }`)
    testOnP2pConnectionChange();
    testGetCurrentGroupCallback();

    this.p2pConnectState = AppStorage.get("p2pConnectState") !//非空断言操作符
    this.p2pLinkedDeviceName = AppStorage.get("p2pLinkedDeviceName") !//非空断言操作符
    if (this.p2p){
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "this.p2p is true")
    } else {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "this.p2p is false")
    }
  }

  build() {
    Row() {
      Column() {
        if (this.p2p){
          if (this.p2p.deviceName){
            Text(this.p2p.deviceName)
              .fontSize(ConfigData.VP_20)
              .width(ConfigData.WH_100_100)
          }
        }
        if (this.p2pConnectState == 1 && this.p2pLinkedDeviceName == this.p2p.deviceName){
          // Text(this.securityString = $r('app.string.p2pConnected'))
          Text($r('app.string.p2pConnected'))
            .fontSize(ConfigData.VP_18)
            .fontColor($r('app.color.color_999999_grey'))
            .width(ConfigData.WH_100_100)
        } else {
          Text($r('app.string.useful'))
            // Text(this.securityString)
            .fontSize(ConfigData.VP_18)
            .fontColor($r('app.color.color_999999_grey'))
            .width(ConfigData.WH_100_100)
        }
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