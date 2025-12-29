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

import { PageTitle } from '../../component/pageTitle';
import { TestImageDisplay } from '../../component/testImageDisplay';
import { ContentTable } from '../../component/contentTable';
import router from '@ohos.router';
import ConfigData from '../../utils/ConfigData';
import { initNewWifiManagerApiData } from '../../entryability/model/newWifiManagerTestData';
import { TestData } from '../../entryability/model/testData';
import wifiManager from '@ohos.wifiManager';

interface myParams extends Object {
  testItem: TestData
}

const TAG = 'wifiTestApp [QuickVerifyTest]'

/**
 * 快速验证测试页面 - 基于wifiManager接口
 */
interface wifiDeviceConfigManager {
  ssid: string,
  bssid: string,
  preSharedKey: string,
  isHiddenSsid: boolean,
  securityType: wifiManager.WifiSecurityType,
  creatorUid: number,
  disableReason: number,
  netId: number,
  randomMacType: number,
  randomMacAddr: string,
  ipType: wifiManager.IpType,
  staticIp: wifiManager.IpConfig
}

@Component
struct QuickVerifyDeviceSetting {
  @StorageLink('isAllowedQuick') isAllowedQuick: number = 1;
  @StorageLink('w_networkIdMQuick') w_networkIdMQuick: number = 0;
  @StorageLink('w_featureIdMQuick') w_featureIdMQuick: number = 1;
  @StorageLink('wifiDeviceConfigManagerQuick') wifiDeviceConfigManagerQuick: wifiManager.WifiDeviceConfig = {
    ssid: "TP-LINK_6365",
    bssid: "6C:B1:58:75:63:65",
    preSharedKey: "12345678",
    isHiddenSsid: false,
    securityType: 3,
    creatorUid: 1,
    disableReason: 0,
    netId: 1,
    randomMacType: 0,
    randomMacAddr: "08:fb:ea:1b:38:aa",
    ipType: 1,
    staticIp: {
      ipAddress: 3232235880,
      gateway: 3232235777,
      prefixLength: 0,
      dnsServers: [3716386629],
      domains: ["0", "1", "2"]
    }
  }

  aboutToAppear() {
  }

  build() {
    Column() {
      Row() {
        Text("SetScanAlwaysAllowed:").fontSize("17vp").width(200)
        TextInput({ text: this.isAllowedQuick.toString(), placeholder: "1" })
          .fontSize("15vp")
          .onChange((strInput: string) => {
            if (strInput.length >= 1) {
              this.isAllowedQuick = Number(strInput);
            }
          })
          .width(ConfigData.WH_50_100)
          .borderRadius(1)
      }
      .backgroundColor($r("app.color.moon"))
      .padding(5)
      .justifyContent(FlexAlign.Start)
      .alignItems(VerticalAlign.Center)

      Row() {
        Text("ssidM:").fontSize("17vp").width(70)
        TextInput({ text: this.wifiDeviceConfigManagerQuick.ssid, placeholder:"TP-LINK_6365" })
          .fontSize("15vp")
          .onChange((strInput: string) => {
            if (strInput.length >= 1) {
              this.wifiDeviceConfigManagerQuick.ssid = strInput;
            }
          })
          .width(ConfigData.WH_80_100)
          .borderRadius(1)
      }
      .backgroundColor($r("app.color.moon"))
      .padding(5)
      .justifyContent(FlexAlign.Start)
      .alignItems(VerticalAlign.Center)

      Scroll() {
        Column() {
          Stack().height("0.25vp").backgroundColor("#000000");
          Column() {
            Row() {
              Text("bssidM:").fontSize("15vp").width(60);
              TextInput({ text: this.wifiDeviceConfigManagerQuick.bssid, placeholder: "6c:b1:58:75:63:67" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  if (strInput.length >= 1) {
                    this.wifiDeviceConfigManagerQuick!.bssid = strInput;
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .padding(3)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))

            Row() {
              Text("preSharedKeyM:").fontSize("15vp").width(110);
              TextInput({ text: this.wifiDeviceConfigManagerQuick.preSharedKey, placeholder: "12345678" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  if (strInput.length >= 1) {
                    this.wifiDeviceConfigManagerQuick!.preSharedKey = strInput;
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("securityTypeM:").fontSize(15).width(100);
              Column() {
                Select([
                  { value: 'WIFI_SEC_TYPE_INVALID' },
                  { value: 'WIFI_SEC_TYPE_OPEN' },
                  { value: 'WIFI_SEC_TYPE_WEP' },
                  { value: 'WIFI_SEC_TYPE_PSK' },
                  { value: 'WIFI_SEC_TYPE_SAE' }
])
                  .selected(3)
                  .value('WIFI_SEC_TYPE_PSK')
                  .font({ size: 17 })
                  .selectedOptionFont({ size: 17 })
                  .optionFont({ size: 15 })
                  .width(ConfigData.WH_80_100)
                  .onSelect((index: number) => {
                    console.log(TAG, "Select:" + index)
                    this.wifiDeviceConfigManagerQuick!.securityType = index;
                  })
              }
              .width(ConfigData.WH_80_100)
              .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
          }

          Stack().height("0.25vp").backgroundColor("#000000");
        }
      }
      .scrollBarWidth(10)
      .scrollBar(BarState.On)
    }
    .height(ConfigData.WH_58_100)
  }
}

@Entry
@Component
struct QuickVerifyTest {
  @State showList: boolean = false;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State message: string = "";
  @State deviceId: string = '';
  @State currentClick: number = - 1;
  @StorageLink('isAllowedQuick') isAllowedQuick: number = 1;
  @StorageLink('pairedSsidMQuick') pairedSsidMQuick: string = "";
  @StorageLink('w_networkIdMQuick') w_networkIdMQuick: number = 0;
  @StorageLink('w_featureIdMQuick') w_featureIdMQuick: number = 1;
  @StorageLink('ipInfoManagerMessageQuick') ipInfoManagerMessageQuick: string = '';
  @StorageLink('linkedInfoManagerMessageQuick') linkedInfoManagerMessageQuick: string = '';
  @StorageLink('getDeviceConfigsManagerMessageQuick') getDeviceConfigsManagerMessageQuick: string = '';
  @StorageLink('getScanInfoManagerMessageQuick') getScanInfoManagerMessageQuick: string = '';
  @StorageLink('wifiDeviceConfigManagerQuick') wifiDeviceConfigManagerQuick: wifiManager.WifiDeviceConfig = {
    ssid: "TP-LINK_6365",
    bssid: "6C:B1:58:75:63:65",
    preSharedKey: "12345678",
    isHiddenSsid: false,
    securityType: 3,
    creatorUid: 1,
    disableReason: 0,
    netId: 100,
    randomMacType: 0,
    randomMacAddr: "08:fb:ea:1b:38:aa",
    ipType: 1,
    staticIp: {
      ipAddress: 3232235880,
      gateway: 3232235777,
      prefixLength: 0,
      dnsServers: [3716386629],
      domains: ["0", "1", "2"]
    }
  }

  aboutToAppear() {

  }

  init() {
    console.log("QuickVerifyTest init-----------")
  }

  build() {
    Column() {
      Stack({ alignContent: Alignment.TopStart }) {
        TestImageDisplay({ testItem: this.testItem })
        PageTitle({ testItem: this.testItem })
      }

      Stack().height("0.5vp").backgroundColor("#000000");
      Column() {
        Row() {
          Text("已连接的WiFi:")
            .fontSize("17vp")
            .height(40)
            .width(ConfigData.WH_30_100)
            .align(Alignment.Start)

          TextInput({ text: this.pairedSsidMQuick, placeholder: "请在右侧输入WiFi的配置" })
            .height(40)
            .borderStyle(BorderStyle.Dashed)
            .backgroundColor($r("app.color.white"))
            .onChange((str) => {
              this.deviceId = str;
            })
            .width(ConfigData.WH_45_100)
            .padding({ top: 5, left: 5 })
          Image($r('app.media.Switch'))
            .height(50)
            .padding({ top: 5, bottom: 5, left: 10 })
            .width(ConfigData.WH_15_100)
            .onClick(() => {
              this.showList = !this.showList;
            })
        }
      }
      .align(Alignment.Start)

      if (this.showList) {
        QuickVerifyDeviceSetting()
      } else {
        Column() {
          Scroll() {
            Column() {
              Text("WLAN连接信息:" + this.linkedInfoManagerMessageQuick)
                .fontSize("17vp")
                .margin({ top: "5vp", left: "10vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("IP信息:" + this.ipInfoManagerMessageQuick)
                .fontSize("17vp")
                .margin({ top: "5vp", left: "10vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("获取网络配置:" + this.getDeviceConfigsManagerMessageQuick)
                .fontSize("17vp")
                .margin({ top: "5vp", left: "10vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("扫描结果:" + this.getScanInfoManagerMessageQuick)
                .fontSize("17vp")
                .margin({ top: "5vp", left: "10vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
            }
            .width(ConfigData.WH_100_100)
          }
          .scrollBarWidth(10)
          .scrollBar(BarState.Auto)
        }
        .height(100)
        .width(ConfigData.WH_95_100)
        .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))

        ContentTable({
          testItem: this.testItem, apiItems: initNewWifiManagerApiData()
        })
      }
    }
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r("app.color.lead"))
    .height(ConfigData.WH_100_100)
  }
}