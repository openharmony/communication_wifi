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
import { initHotspotApIData } from '../entryability/model/testDataModels'
import ConfigData from '../utils/ConfigData';

const TAG = "[filterTable]"
/**
 * FilterTable Of WiFi test
 */

@Component
export struct FilterTable {
  private testItem!: TestData
  @State apiItems: TestApi[] = initHotspotApIData()
  @State changeIndex: number = - 1
  // input ble scan parameters:
  /*ScanFilter*/
  @State cbxBleScanFilter: boolean = false;
  @State h_ssid: string = "testApp1";
  @State h_securityType: number = 3;
  @State h_band: number = 2;
  @State h_preSharedKey: string = "12345678";
  @State h_maxConn: number = 3;
  @State h_channel: number = 36;

  getCurrentState(index: number) {
    return this.apiItems[ index ].result
  }

  aboutToAppear() {
    AppStorage.setOrCreate("h_ssid" , this.h_ssid)
    AppStorage.setOrCreate("h_securityType" , this.h_securityType)
    AppStorage.setOrCreate("h_band" , this.h_band)
    AppStorage.setOrCreate("h_preSharedKey" , this.h_preSharedKey)
    AppStorage.setOrCreate("h_maxConn" , this.h_maxConn)
    AppStorage.setOrCreate("h_channel" , this.h_channel)
  }

  build() {
    Scroll() {
      Column() {
        Column() {
          Column() {
            Row() {
              Text("ssid").fontSize("17vp").width(60);
              TextInput({ text : this.h_ssid , placeholder : "testApp1" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.h_ssid = strInput;
                  AppStorage.setOrCreate("h_ssid" , this.h_ssid);
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
              TextInput({ text : this.h_securityType.toString() , placeholder : "3" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.h_securityType = Number(strInput);
                  AppStorage.setOrCreate('h_securityType' , this.h_securityType);
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
                    AppStorage.setOrCreate('h_maxConn' , index);
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
              TextInput({ text : this.h_band.toString() , placeholder : "2" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.h_band = Number(strInput);
                  AppStorage.setOrCreate('h_band' , this.h_band);
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
              TextInput({ text : this.h_preSharedKey , placeholder : "12345678" })
                .fontSize("17vp")
                .onChange((strInput: string) => {
                  this.h_preSharedKey = strInput;
                  AppStorage.setOrCreate('h_preSharedKey' , this.h_preSharedKey);
                })
                .width(ConfigData.WH_80_100)
            }
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))

            Row() {
              Text("channel").fontSize(17).width(120)
              TextInput({ text : this.h_channel.toString() , placeholder : "36" })
                .fontSize("17vp")
                .onChange((strInput: string) => {
                  this.h_channel = Number(strInput);
                  AppStorage.setOrCreate('h_channel' , this.h_channel);
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