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

import { TestData , TestApi } from '../entryability/model/testData'
import { initHotspotManagerApIData } from '../entryability/model/testDataModels'
import ConfigData from '../utils/ConfigData';

const TAG = "[filterTableManager]"
/**
 * FilterTable Manager Of WiFi test
 */

@Component
export struct FilterTableManager {
  private testItem!: TestData
  @State apiItems: TestApi[] = initHotspotManagerApIData()
  @State changeIndex: number = - 1
  // input ble scan parameters:
  /*ScanFilter*/
  @State cbxBleScanFilter: boolean = false;
  @State h_ssid1: string = "testApp1";
  @State h_securityType1: number = 3;
  @State h_band1: number = 2;
  @State h_preSharedKey1: string = "12345678";
  @State h_maxConn1: number = 3;
  @State h_channel1: number = 36;

  getCurrentState(index: number) {
    return this.apiItems[ index ].result
  }

  aboutToAppear() {
    AppStorage.setOrCreate("h_ssid1" , this.h_ssid1)
    AppStorage.setOrCreate("h_securityType1" , this.h_securityType1)
    AppStorage.setOrCreate("h_band1" , this.h_band1)
    AppStorage.setOrCreate("h_preSharedKey1" , this.h_preSharedKey1)
    AppStorage.setOrCreate("h_maxConn1" , this.h_maxConn1)
    AppStorage.setOrCreate("h_channel1" , this.h_channel1)
  }

  build() {
    Scroll() {
      Column() {
        Column() {
          Column() {
            Row() {
              Text("ssid").fontSize("17vp").width(60);
              TextInput({ text : this.h_ssid1 , placeholder : "testApp123" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.h_ssid1 = strInput;
                  AppStorage.setOrCreate("h_ssid1" , this.h_ssid1);
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.moon"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("securityType").fontSize(17).width(110);
              TextInput({ text : this.h_securityType1.toString() , placeholder : "3" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.h_securityType1 = Number(strInput);
                  AppStorage.setOrCreate('h_securityType1' , this.h_securityType1);
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))

            Row() {
              Text("maxConn").fontSize(17).width(80)
              Column() {
                Select([
                  { value : '1' },
                  { value : '2' },
                  { value : '3' }
                ])
                  .selected(2)
                  .value('3')
                  .font({ size : 17 })
                  .selectedOptionFont({ size : 17 })
                  .optionFont({ size : 15 })
                  .width(ConfigData.WH_80_100)
                  .onSelect((index: number) => {
                    console.log(TAG , "Select:" + index)
                    AppStorage.setOrCreate('h_maxConn1' , index);
                  })
              }
              .width(ConfigData.WH_80_100)
            }
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))

            Row() {
              Text("band").fontSize(17).width(60);
              TextInput({ text : this.h_band1.toString() , placeholder : "2" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.h_band1 = Number(strInput);
                  AppStorage.setOrCreate('h_band1' , this.h_band1);
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))

            Row() {
              Text("preSharedKey").fontSize(17).width(120)
              TextInput({ text : this.h_preSharedKey1 , placeholder : "12345678" })
                .fontSize("17vp")
                .onChange((strInput: string) => {
                  this.h_preSharedKey1 = strInput;
                  AppStorage.setOrCreate('h_preSharedKey1' , this.h_preSharedKey1);
                })
                .width(ConfigData.WH_80_100)
            }
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))

            Row() {
              Text("channel").fontSize(17).width(120)
              TextInput({ text : this.h_channel1.toString() , placeholder : "36" })
                .fontSize("17vp")
                .onChange((strInput: string) => {
                  this.h_channel1 = Number(strInput);
                  AppStorage.setOrCreate('h_channel1' , this.h_channel1);
                })
                .width(ConfigData.WH_80_100)
            }
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))
          }
          .height(300)
          .width(ConfigData.WH_100_100)
          .padding(5)
        }
        .borderColor($r("app.color.lead"))
        .borderWidth(1)
      }
      .height(ConfigData.WH_100_100)
      .backgroundColor($r("app.color.lead"))
    }
    .scrollBarWidth(20)
    .padding({ bottom : 10 })
  }
}