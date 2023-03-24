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
import { initHotspotApIData } from '../MainAbility/model/testDataModels'

/**
  * FilterTable Of Wifi test
  */

@Component
export struct FilterTable {
  private testItem: TestData
  @State apiItems: TestApi[] = initHotspotApIData()

  @State ssid: string = "dayu200";
  @State securityType: string = "3";//00:1A:7D:DA:71:15
  @State band: string = "2";
  @State preSharedKey: string = "123456";
  @State maxConn: string = "最大连接设备数量";

  getCurrentState(index: number) {
    //    console.log("currentState:" + index.toString() + this.apiItems[index].result)
    return this.apiItems[index].result
  }

  aboutToAppear() {
    AppStorage.SetOrCreate('ssid', this.ssid);
    AppStorage.SetOrCreate('securityType', this.securityType);
    AppStorage.SetOrCreate('band', this.band);
    AppStorage.SetOrCreate('preSharedKey', this.preSharedKey);
    AppStorage.SetOrCreate('maxConn', this.maxConn);

  }
  build() {
    Scroll() {
      Column() {
//        Row() {
//          Text("BLE扫描过滤参数:")
//            .fontSize("17vp")
//            .fontColor("#4444444")
//            .width("80%")
//            .padding({left: 10})
//          Checkbox({ name: 'bleScanFilter', group: 'checkboxGroup99' })
//            .select(this.cbxBleScanFilter)
//            .selectedColor(0x39a2db)
//            .onChange((value) => {
//              if (value) {
//                this.cbxBleScanFilter = true;
//              } else {
//                this.cbxBleScanFilter = false;
//              }
//              AppStorage.SetOrCreate('cbxBleScanFilter', value);
//            })
//            .width(15)
//        }
//        .height(30)
//        .width("100%")
//        .borderWidth(1)
//        .borderColor($r("app.color.lead"))
        Column() {
          Column() {
            Column() {
              Row(){
                Text("ssid").fontSize("17vp").width(60);
                TextInput({ text: this.ssid, placeholder: "dayu200" })
                  .fontSize("15vp")
                  .onChange((strInput) => {
                    this.ssid = strInput;
                    AppStorage.SetOrCreate('ssid', strInput);
                  })
                  .width("80%")
                  .borderRadius(1)
              }
              .padding(5)
              .justifyContent(FlexAlign.Start)
              .alignItems(VerticalAlign.Center)

              Row(){
                Text("securityType").fontSize(17).width(60);
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
                Text("band").fontSize(17).width(60);
                TextInput({ text: this.band, placeholder: "2" })
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
                Text("preSharedKey").fontSize(17).width(80)
                TextInput({ text: this.preSharedKey, placeholder: "123456" })
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
                Text("maxConn").fontSize(17).width(80)
                TextInput({ text: this.maxConn, placeholder: "最大连接设备数量" })
                  .fontSize("17vp")
                  .onChange((strInput) => {
                    this.maxConn = strInput;
                    AppStorage.SetOrCreate('maxConn', strInput);
                  })
                  .width("80%")
              }
              .padding(5)
              .justifyContent(FlexAlign.Start)
              .alignItems(VerticalAlign.Center)


            }
            .height(300)
            .width('100%')
            .padding(5)
          }
          .borderColor($r("app.color.lead"))
          .borderWidth(1)



          Column() {
            Column() {
            }
            .width('100%')
            .padding(5)
          }
          .height(240)
          .borderWidth(1)
          .borderColor($r("app.color.lead"))
        }
      }
      .height("100%")
      .backgroundColor($r("app.color.white"))
    }
    .scrollBarWidth(20)
    .padding({ bottom: 10})
  }
}