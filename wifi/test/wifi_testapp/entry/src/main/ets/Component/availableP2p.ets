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

import promptAction from '@ohos.promptAction';
import { P2pPswDialog } from '../component/p2pPswDialog';
import { P2pModel } from '../entryability/model/p2pModel';
import { P2pView } from '../component/p2pView';
import wifi from '@ohos.wifi';
import ConfigData from '../utils/ConfigData';
import wifiManager from '@ohos.wifiManager';

const TAG = "wifiTestApp [availableP2p]"

/**
 * available p2p page of WiFi test
 */

@Component
export struct AvailableP2p {
  private p2pModel: P2pModel = new P2pModel()
  @Link p2pList!: Array<wifiManager.WifiP2pDevice>
  @Link p2pLinkedInfo!: wifiManager.WifiP2pLinkedInfo
  private selectIndex: number = - 1
  private p2pPswDialogController: CustomDialogController = new CustomDialogController({
    builder: P2pPswDialog({ p2pScanInfo: this.p2pList[this.selectIndex], action: this.onAccept }) ,
    autoCancel: true
  })

  onAccept(p2pScanInfo: wifiManager.WifiP2pDevice) {
    console.log(TAG, 'connect p2p')
    this.p2pModel.connectP2p(p2pScanInfo)
  }

  build() {
    Column() {
      Row() {
        Text($r('app.string.p2p_available'))
          .align(Alignment.TopStart)
          .fontSize(22)
          .layoutWeight(1)
      }
      .width(ConfigData.WH_95_100)

      List() {
        ForEach(this.p2pList, (item: wifiManager.WifiP2pDevice, index: number) => {
          ListItem() {
            P2pView({ p2p: item })
          }
          .onClick(() => {
            console.log(TAG, 'p2p click')
            this.selectIndex = index
            if (this.p2pLinkedInfo !== null && this.p2pLinkedInfo.connectState == 1) {
              promptAction.showToast({ message: 'this p2p is connected' })
              return
            }
            this.p2pModel.connectP2p(item)
            //            this.p2pPswDialogController.open()
          })
        }, (item: wifiManager.WifiP2pDevice) => JSON.stringify(item))
      }
      .layoutWeight(1)
      .divider({ strokeWidth: 1, color: Color.Gray, startMargin: 10, endMargin: 10 })
      .margin(10)
    }
    .margin({ top: 15, bottom: 100 })
  };
}