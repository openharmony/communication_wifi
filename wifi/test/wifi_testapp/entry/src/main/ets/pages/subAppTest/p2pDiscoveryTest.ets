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

import wifiManager from '@ohos.wifiManager';
import { AvailableP2p } from '../../component/availableP2p';
import { TestData } from '../../entryability/model/testData';
import router from '@ohos.router';
import { PageTitle } from '../../component/pageTitle';
import { TestImageDisplay } from '../../component/testImageDisplay';
import { P2pModel } from '../../entryability/model/p2pModel';
import ConfigData from '../../utils/ConfigData';

interface myParams extends Object {
  testItem: TestData
}

const TAG = 'wifiTestApp [p2pScan]'

/**
 * p2p Found Test Page Of Wifi test
 */
@Entry
@Component
struct P2pFound {
  private p2pModel: P2pModel = new P2pModel()
  private testItem: TestData = (router.getParams() as myParams).testItem;
  private isScanning: boolean = false;
  @State p2pList: Array<wifiManager.WifiP2pDevice> = []
  @State p2pIsLinked: boolean = false
  @State p2pIsSwitchOn: boolean = false
  @State p2pLinkedInfo: wifiManager.WifiP2pLinkedInfo = {
    connectState: wifiManager.P2pConnectState.DISCONNECTED ,
    isGroupOwner: false ,
    groupOwnerAddr: '' ,
  }

  async scan() {
    if (!this.isScanning) {
      return; // 如果不需要扫描，则直接返回
    } else {
      this.p2pModel.getP2pPeerDevices((result: wifiManager.WifiP2pDevice[]) => {
        if (this.p2pIsSwitchOn) {
          result.forEach(item => {
            if (item.deviceName) {
              this.p2pList.push({
                deviceName: item.deviceName,
                deviceAddress: item.deviceAddress,
                deviceAddressType: item.deviceAddressType,
                primaryDeviceType: item.primaryDeviceType,
                deviceStatus: item.deviceStatus,
                groupCapabilities: item.groupCapabilities,
              });
            }
          });
          console.log(TAG, 'scan p2pList:' + JSON.stringify(this.p2pList))
          if (this.isScanning) { // 再次检查是否还需要继续扫描
            setTimeout(() => {
              this.scan()
            }, 2000)
          }
        }
      })
    }
  }

  getP2pLinkedInfo() {
    wifiManager.getP2pLinkedInfo((err, p2pLinkedInfo) => {
      if (err) {
        console.log(TAG, `getLinkedInfo err: ${ JSON.stringify(err) }`)
        return
      }
      console.log(TAG, `p2pLinkedInfo: ${ JSON.stringify(p2pLinkedInfo) }`)
      if (p2pLinkedInfo === null || p2pLinkedInfo.connectState === 0) {
        this.p2pIsLinked = false
        this.p2pLinkedInfo = {
          connectState: 0,
          isGroupOwner: false ,
          groupOwnerAddr: ''
        }
        return
      }
      this.p2pIsLinked = true
      this.p2pLinkedInfo = p2pLinkedInfo
    })
  }

  addP2pListener() {
    wifiManager.on('p2pConnectionChange', wifiP2pLinkedInfo => {
      let state = wifiP2pLinkedInfo.connectState
      console.log(TAG, `p2pConnectionChange: ${ state }`)
      this.getP2pLinkedInfo()
    })
    wifiManager.on('p2pStateChange', state => {
      console.log(TAG, `p2pStateLisener state: ${ state }`)
      this.p2pList = []
      if (state === 3) { //1: idle, 2: starting, 3:started, 4: closing, 5: closed
        wifiManager.startDiscoverDevices()
        this.scan()
      }
    })
  }

  aboutToAppear() {
    console.log(TAG,"test" + wifiManager.isWifiActive())
    if (wifiManager.isWifiActive()) {
      console.log(TAG, 'wifi is active')
      this.p2pIsSwitchOn = true
      this.isScanning = true; // 在页面出现时开始扫描
      wifiManager.startDiscoverDevices()
      this.scan()
      this.getP2pLinkedInfo()
    } else {
      this.p2pIsSwitchOn = false;
    }
    this.addP2pListener()
  }

  build() {
    Column() {
      Stack({ alignContent: Alignment.TopStart }) {
        TestImageDisplay({ testItem: this.testItem })
        PageTitle({ testItem: this.testItem })
      }

      Row() {
        Text($r('app.string.wlan'))
          .fontSize(22)
          .fontWeight(FontWeight.Bold)
          .layoutWeight(1)
          .align(Alignment.TopStart)
        Column() {
          Toggle({ type: ToggleType.Switch, isOn: this.p2pIsSwitchOn })
            .onChange(async(isOn: boolean) => {
              console.log(TAG, `wifi swtich is: ${ isOn }`)
              this.p2pList = []
              if (isOn) {
                try {
                  this.p2pIsSwitchOn = true
                  this.isScanning = true;
                  await wifiManager.enableWifi()
                  // wifiManager.startDiscoverDevices()
                  // 延迟执行startScan，确保WiFi服务已经准备好
                  setTimeout(() => {
                    this.scan();
                  }, 2000);
                } catch( error) {
                  console.error(TAG, `Failed to enable Wi - Fi: ${ error }`);
                }
              } else {
                this.p2pIsSwitchOn = false
                this.p2pIsLinked = false
                this.isScanning = false;
                try {
                  await wifiManager.disconnect();
                  await wifiManager.disableWifi();
                } catch( error) {
                  console.error(TAG, `Failed to disable Wi - Fi: ${ error }`);
                }
                this.p2pList = [];
              }
            })
        }
      }
      .width(ConfigData.WH_95_100)

      AvailableP2p({ p2pList: $p2pList, p2pLinkedInfo: $p2pLinkedInfo })
    }
    .size({ width: ConfigData.WH_100_100, height: ConfigData.WH_100_100 })
    .backgroundColor('#F5F5F5')
  }

  aboutToDisappear() {
    this.isScanning = false; // 设置标志，告诉scan方法停止新的扫描
    this.p2pIsSwitchOn = false
    wifiManager.off('p2pConnectionChange')
    wifiManager.off('p2pStateChange')
  }
}