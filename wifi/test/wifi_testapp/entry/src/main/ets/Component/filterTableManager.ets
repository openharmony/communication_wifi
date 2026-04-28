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
import { TestData, TestApi} from '../entryability/model/testData';
import { initHotspotManagerApiData} from '../entryability/model/testDataModels';
import ConfigData from '../Utils/ConfigData';

const TAG = "wifiTestApp [filterTableManager]"
/**
 * FilterTable Manager Of WiFi test
 */

@Component
export struct FilterTableManager {
  private testItem!: TestData
  @State apiItems: TestApi[] = initHotspotManagerApiData()
  @State changeIndex: number = ConfigData.ITEM_CLICK_NONE
  // input ble scan parameters:
  /*ScanFilter*/
  @State cbxBleScanFilter: boolean = false;
  @State h_ssid1: string = ConfigData.SCENARIO_HS_SSID;
  @State h_securityType1: number = ConfigData.QV_MOCK_SECURITY_TYPE;
  @State h_band1: number = ConfigData.SCENARIO_HS_BAND;
  @State h_preSharedKey1: string = ConfigData.QV_MOCK_PRE_SHARED_KEY;
  @State h_maxConn1: number = ConfigData.SCENARIO_HS_MAX_CONN;
  @State h_channel1: number = ConfigData.SCENARIO_HS_CHANNEL;

  getCurrentState(index: number){
    return this.apiItems[index].result
  }

  aboutToAppear() {
    AppStorage.setOrCreate("h_ssid1", this.h_ssid1)
    AppStorage.setOrCreate("h_securityType1", this.h_securityType1)
    AppStorage.setOrCreate("h_band1", this.h_band1)
    AppStorage.setOrCreate("h_preSharedKey1", this.h_preSharedKey1)
    AppStorage.setOrCreate("h_maxConn1", this.h_maxConn1)
    AppStorage.setOrCreate("h_channel1", this.h_channel1)
  }

  build() {
    Scroll() {
      Column() {
        Column() {
          Column() {
            Row() {
              Text($r('app.string.wifitest_text_s')).fontSize(ConfigData.VP_17).width(ConfigData.VP_60);
              TextInput({text: this.h_ssid1, placeholder: "testApp123"})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  this.h_ssid1 = strInput;
                  AppStorage.setOrCreate("h_ssid1", this.h_ssid1);
                })
                .width(ConfigData.WH_80_100)
                .borderRadius($r('app.float.wh_value_1'))
            }
            .backgroundColor($r("app.color.moon"))
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text($r('app.string.wifitest_text_s_4')).fontSize(ConfigData.VP_17).width(ConfigData.VP_110);
              TextInput({text: this.h_securityType1.toString(), placeholder: "3"})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  this.h_securityType1 = Number(strInput);
                  AppStorage.setOrCreate('h_securityType1', this.h_securityType1);
                })
                .width(ConfigData.WH_80_100)
                .borderRadius($r('app.float.wh_value_1'))
            }
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))

            Row() {
              Text($r('app.string.wifitest_text_m')).fontSize(ConfigData.VP_17).width(ConfigData.VP_80)
              Column() {
                Select([
                  { value: ConfigData.QV_MOCK_DOMAIN_1},
                  { value: ConfigData.QV_MOCK_DOMAIN_2},
                  { value: '3'}
])
                  .selected(2)
                  .value('3')
                  .font({size: ConfigData.VP_17})
                  .selectedOptionFont({size: ConfigData.VP_17})
                  .optionFont({size: ConfigData.VP_15})
                  .width(ConfigData.WH_80_100)
                  .onSelect((index: number) => {
                    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "Select:" + index)
                    AppStorage.setOrCreate('h_maxConn1', index);
                  })
              }
              .width(ConfigData.WH_80_100)
            }
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))

            Row() {
              Text($r('app.string.wifitest_text_b')).fontSize(ConfigData.VP_17).width(ConfigData.VP_60);
              TextInput({text: this.h_band1.toString(), placeholder: ConfigData.QV_MOCK_DOMAIN_2})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  this.h_band1 = Number(strInput);
                  AppStorage.setOrCreate('h_band1', this.h_band1);
                })
                .width(ConfigData.WH_80_100)
                .borderRadius($r('app.float.wh_value_1'))
            }
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))

            Row() {
              Text($r('app.string.wifitest_text_p_1')).fontSize(ConfigData.VP_17).width(ConfigData.VP_120)
              TextInput({text: this.h_preSharedKey1, placeholder: $r('app.string.wifitest_text_1_3')})
                .fontSize(ConfigData.VP_17)
                .onChange((strInput: string) => {
                  this.h_preSharedKey1 = strInput;
                  AppStorage.setOrCreate('h_preSharedKey1', this.h_preSharedKey1);
                })
                .width(ConfigData.WH_80_100)
            }
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))

            Row() {
              Text($r('app.string.wifitest_text_c')).fontSize(ConfigData.VP_17).width(ConfigData.VP_120)
              TextInput({text: this.h_channel1.toString(), placeholder: $r('app.string.wifitest_text_3')})
                .fontSize(ConfigData.VP_17)
                .onChange((strInput: string) => {
                  this.h_channel1 = Number(strInput);
                  AppStorage.setOrCreate('h_channel1', this.h_channel1);
                })
                .width(ConfigData.WH_80_100)
            }
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))
          }
          .height(ConfigData.VP_300)
          .width(ConfigData.WH_100_100)
          .padding(ConfigData.VP_5)
        }
        .borderColor($r("app.color.lead"))
        .borderWidth(ConfigData.VP_1)
      }
      .height(ConfigData.WH_100_100)
      .backgroundColor($r("app.color.lead"))
    }
    .scrollBarWidth(ConfigData.VP_20)
    .padding({bottom: ConfigData.VP_10})
  }
}