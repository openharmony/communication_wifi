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

// @ts-nocheck
import { TestData, TestApi } from '../MainAbility/model/testData'
import { initWiFiApiData } from '../MainAbility/model/testDataModels'

/**
 * BleFilterTable Of Bluetooth test
 */

@Component
export struct FilterTable {
  private testItem: TestData
  @State apiItems: TestApi[] = initWiFiApiData()
  @State changeIndex: number = -1
  // input ble scan parameters:
  /*ScanFilter*/
  @State cbxBleScanFilter: boolean = false;
  @State ssid: string = "testApp";
  @State securityType: number = 3;
  @State band: number = 2;
  @State preSharedKey: string = "12345678";
  @State maxConn: number = 32 ;
  @State channel: number = 6 ;

  getCurrentState(index: number) {
    //    console.log("currentState:" + index.toString() + this.apiItems[index].result)
    return this.apiItems[index].result
  }

  aboutToAppear() {
    //    AppStorage.SetOrCreate('txtScanFilterDeviceId', this.txtScanFilter_deviceId);
    //    AppStorage.SetOrCreate('txtScanFilterName', this.txtScanFilter_name);
    //    AppStorage.SetOrCreate('txtScanFilterServiceUuid', this.txtScanFilter_serviceUuid);
    //    AppStorage.SetOrCreate('txtScanOptions_interval', this.txtScanOptions_interval);
    //    AppStorage.SetOrCreate('txtScanOptionsDutyMode', '0');
    //    AppStorage.SetOrCreate('txtScanOptionsMatchMode', '0');
    //    AppStorage.SetOrCreate('cbxBleScanFilter', this.cbxBleScanFilter);
    //    AppStorage.SetOrCreate('cbxBleScanOptions', this.cbxBleScanOptions);
  }

  build() {
    Scroll() {
      Column() {
        Column() {
          Column() {
            Row() {
              Text("ssid").fontSize("17vp").width(60);
              TextInput({ text: this.ssid, placeholder: "testApp" })
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.ssid = strInput;
                  AppStorage.SetOrCreate("ssid", strInput);
                })
                .width("80%")
                .borderRadius(1)
            }
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("securityType").fontSize(17).width(110);
              TextInput({ text: this.securityType, placeholder: "3" })
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.securityType = strInput;
                  AppStorage.SetOrCreate('securityType', strInput);
                })
                .width("80%")
                .borderRadius(1)
            }
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("maxConn").fontSize(17).width(80)
              Column() {
                Select([
                  { value: '8' },
                  { value: '16' },
                  { value: '32' }
                ])
                  .selected(2)
                  .value('32')
                  .font({ size: 17 })
                  .selectedOptionFont({ size: 17 })
                  .optionFont({ size: 15 })
                  .width("80%")
                  .onSelect((index: number) => {
                    console.info("Select:" + index)
                    AppStorage.SetOrCreate('maxConn', index);
                  })
              }
              .width("80%")
            }
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("band").fontSize(17).width(60);
              TextInput({ text: this.band, placeholder: "1" })
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.band = strInput;
                  AppStorage.SetOrCreate('band', strInput);
                })
                .width("80%")
                .borderRadius(1)
            }
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)


            Row() {
              Text("preSharedKey").fontSize(17).width(120)
              TextInput({ text: this.preSharedKey, placeholder: "12345678" })
                .fontSize("17vp")
                .onChange((strInput) => {
                  this.preSharedKey = strInput;
                  AppStorage.SetOrCreate('preSharedKey', strInput);
                })
                .width("80%")
            }
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            Row() {
              Text("channel").fontSize(17).width(120)
              TextInput({ text: this.channel, placeholder: "6" })
                .fontSize("17vp")
                .onChange((strInput) => {
                  this.channel = strInput;
                  AppStorage.SetOrCreate('channel', strInput);
                })
                .width("80%")
            }
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
//            Row() {
//              Text("maxConn").fontSize(17).width(80)
//              Column() {
//                Select([
//                  { value: 'LOW_POWER' },
//                  { value: 'BALANCED' },
//                  { value: 'LOW_LATENCY' }
//                ])
//                  .selected(2)
//                  .value('LOW_POWER')
//                  .font({ size: 17 })
//                  .selectedOptionFont({ size: 17 })
//                  .optionFont({ size: 15 })
//                  .width("80%")
//                  .onSelect((index: number) => {
//                    console.info("Select:" + index)
//                    AppStorage.SetOrCreate('txtScanOptionsDutyMode', index);
//                  })
//              }
//              .width("80%")
//            }
//            .padding(5)
//            .justifyContent(FlexAlign.Start)
//            .alignItems(VerticalAlign.Center)
          }
          .height(300)
          .width('100%')
          .padding(5)
        }
        .borderColor($r("app.color.lead"))
        .borderWidth(1)
      }
      .height("100%")
      .backgroundColor($r("app.color.white"))
    }
    .scrollBarWidth(20)
    .padding({ bottom: 10 })
  }
}