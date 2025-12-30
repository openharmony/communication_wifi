/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
import { NormalNav } from "./components/NormalNav";
import { wifiManager } from "@kit.ConnectivityKit";

@Component
export struct ChangeNameView {

  @Consume('p2pPathInfo') pathInfo: NavPathStack
  @State device: null | wifiManager.WifiP2pDevice = null
  @State deviceStr: string = ''

  async aboutToAppear() {
    this.device =  await wifiManager.getP2pLocalDevice()
    this.deviceStr = this.device.deviceName
  }

  build() {
    NavDestination() {
      Column() {
        NormalNav({title: $r('app.string.device_name')})
        Row() {
          TextInput({text: $$this.deviceStr})
        }.padding({left: 20, right: 20})
        Text($r('app.string.change_name_tip'))
          .margin({ top: 20, left: 20, right: 20 })
        Blank()
          .layoutWeight(1)
        Row({space: 40 }) {
          Button($r('app.string.cancel_button'))
            .onClick(() => {
              this.pathInfo.pop()
            })
            .normalButtonStyle()
          Button($r('app.string.confirm_button'))
            .onClick(() => {
              if (this.deviceStr.length > 0) {
                wifiManager.setDeviceName(this.deviceStr)
                this.pathInfo.pop(null, true)
              }
            })
            .normalButtonStyle()
        }
        .margin({ bottom: 45 })
      }
    }
    .hideTitleBar(true)
  }
}

@Extend(Button)
function normalButtonStyle() {
  .width(150)
  .height(40)
  .backgroundColor('#F2F2F2')
  .fontColor(Color.Blue)
}