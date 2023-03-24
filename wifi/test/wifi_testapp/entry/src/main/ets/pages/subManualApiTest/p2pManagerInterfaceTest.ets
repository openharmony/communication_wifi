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
/**
 * p2p Test Page Of Wifi test
 */
import { PageTitle } from '../../Component/pageTitle';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { ContentTable } from '../../Component/contentTable';
import Router from '@system.router';
import ConfigData from '../../Utils/ConfigData';
import LogUtil from '../../Utils/LogUtil';
import { initP2pApiData } from '../../MainAbility/model/testDataModels'
import { TestData } from '../../MainAbility/model/testData'
const G_MAC = '6c:96:d7:3d:87:6f'

@Component
struct p2pSetting {
  private peripheralDeviceId = G_MAC;// '10:2C:6B:11:B3:17';DaYu200//

  aboutToAppear() {
  }

  build() {
    //    Column() {
    //      Row() {
    //        Text("外围设备MAC:").fontSize(16).width(70)
    //        TextInput({ text: this.peripheralDeviceId, placeholder: "input peripheral deviceId." })
    //          .fontSize("15vp")
    //          .onChange((strInput) => {
    //            this.peripheralDeviceId = strInput;
    //            //判断合法性
    //            if (strInput.length >= 17) {
    //              AppStorage.SetOrCreate('peripheralDeviceId', strInput);
    //            }
    //          })
    //          .width("80%")
    //          .borderRadius(1)
    //      }
    //      .backgroundColor($r("app.color.moon"))
    //      .padding(5)
    //      .justifyContent(FlexAlign.Start)
    //      .alignItems(VerticalAlign.Center)
    //
    //      Column() {
    //        Stack().height("0.25vp").backgroundColor("#000000");
    //        Column() {
    //          Row() {
    //            Text("服务UUID:").fontSize(15).width(60);
    //            TextInput({ text: this.serviceUUID, placeholder: "input Service UUID" })
    //              .fontSize("15vp")
    //              .onChange((strInput) => {
    //                this.serviceUUID = strInput;
    //                if (strInput.length >= 36) {
    //                  AppStorage.SetOrCreate('serviceUUID', strInput);
    //                }
    //              })
    //              .width("80%")
    //              .borderRadius(1)
    //          }
    //          .padding(5)
    //          .justifyContent(FlexAlign.Start)
    //          .alignItems(VerticalAlign.Center)
    //          .backgroundColor($r("app.color.spring"))
    //
    //          Row() {
    //            Text("特征值UUID:").fontSize(15).width(60);
    //            TextInput({ text: this.characteristicUUID, placeholder: "input Characteristic UUID" })
    //              .fontSize("15vp")
    //              .onChange((strInput) => {
    //                this.characteristicUUID = strInput;
    //                if (strInput.length >= 36) {
    //                  AppStorage.SetOrCreate('characteristicUUID', strInput);
    //                }
    //              })
    //              .width("80%")
    //              .borderRadius(1)
    //          }
    //          .backgroundColor($r("app.color.spring"))
    //          .padding(5)
    //          .justifyContent(FlexAlign.Start)
    //          .alignItems(VerticalAlign.Center)
    //
    //          Row() {
    //            Text("特征值Value:").fontSize(15).width(60);
    //            TextInput({ text: this.characteristicUUID, placeholder: "Characteristic Value" })
    //              .fontSize("15vp")
    //              .onChange((strInput) => {
    //                this.characteristicValue = strInput;
    //                if (strInput.length >= 1) {
    //                  AppStorage.SetOrCreate('characteristicValue', strInput);
    //                }
    //              })
    //              .width("80%")
    //              .borderRadius(1)
    //          }
    //          .backgroundColor($r("app.color.spring"))
    //          .padding(5)
    //          .justifyContent(FlexAlign.Start)
    //          .alignItems(VerticalAlign.Center)
    //
    //          Row() {
    //            Text("描述符UUID:").fontSize(15).width(60);
    //            TextInput({ text: this.descriptorUUID, placeholder: "input descriptor UUID" })
    //              .fontSize("15vp")
    //              .onChange((strInput) => {
    //                this.descriptorUUID = strInput;
    //                if (strInput.length >= 36) {
    //                  AppStorage.SetOrCreate('descriptorUUID', strInput);
    //                }
    //              })
    //              .width("80%")
    //              .borderRadius(1)
    //          }
    //          .backgroundColor($r("app.color.spring"))
    //          .padding(5)
    //          .justifyContent(FlexAlign.Start)
    //          .alignItems(VerticalAlign.Center)
    //
    //          Row() {
    //            Text("描述符Value:").fontSize(15).width(60);
    //            TextInput({ text: this.descriptorUUID, placeholder: "descriptor Value" })
    //              .fontSize("15vp")
    //              .onChange((strInput) => {
    //                this.descriptorValue = strInput;
    //                if (strInput.length >= 1) {
    //                  AppStorage.SetOrCreate('descriptorValue', strInput);
    //                }
    //              })
    //              .width("80%")
    //              .borderRadius(1)
    //          }
    //          .backgroundColor($r("app.color.spring"))
    //          .padding(5)
    //          .justifyContent(FlexAlign.Start)
    //          .alignItems(VerticalAlign.Center)
    //        }
    //        Stack().height("0.25vp").backgroundColor("#000000");
    //      }
    //    }
  }
}

@Entry
@Component
struct Index {
  @State showList: boolean = false;
  private testItem: TestData = Router.getParams().testId;
  @State message: string = "";
  @StorageLink('setLocalNameRet') setLocalNameRet: boolean = false;
  @StorageLink('setScanModeRet') setScanModeRet: boolean = false;
  @State deviceId: string = '';
  @State currentClick: number = -1;
  @StorageLink('pairedDeviceId') pairedDeviceId: string = '';

  aboutToAppear() {
  }

  init() {
    console.log("init-----------")
  }

  build() {
    Column() {
      Stack({ alignContent: Alignment.TopStart }) {
        TestImageDisplay({ testItem: this.testItem })
        PageTitle({testItem: this.testItem})
      }
      Stack().height("0.5vp").backgroundColor("#000000");

      Column() {
        Text("目标设备MAC：")
          .fontSize("20vp")
          .height(50)
          .width('100%')
          .padding({top: 10, left: 10})

        Row(){
          TextInput({ text: this.pairedMac, placeholder: "请输入即将连接的设备MAC" })
            .height(50)
            .borderStyle(BorderStyle.Dashed)
            .backgroundColor($r("app.color.white"))
            .onChange((str) => {
              this.deviceId = str;
            })
            .width('75%')
            .padding({top: 10, left: 10})
          Image($r('app.media.Switch'))
            .height(48)
            .width(48)
            .padding({ top: 10, bottom: 10, left: 10 })
            .onClick(() => {
              this.showList = !this.showList;
            })
        }
      }
      .align(Alignment.TopStart)
      if (this.showList) {
        p2pSetting()
      }else{
        ContentTable({ testItem: this.testItem, apiItems: initP2pApiData() })
      }
    }
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r("app.color.lead"))
    .height("100%")
  }
}


