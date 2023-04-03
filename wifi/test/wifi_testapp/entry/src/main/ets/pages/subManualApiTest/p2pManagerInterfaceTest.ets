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
  @State deviceAddressManager : string = '6c:96:d7:3d:87:6f';
  @State netIdManager : number = -2 ;
  @State passphraseManager : string = "12345678" ;
  @State groupNameManager : string ="testGroup"
  @State goBandManager : number = 0 ;
  @State devNameManager : string ="test"

  aboutToAppear() {
    AppStorage.SetOrCreate("deviceAddressManager",this.deviceAddressManager)
    AppStorage.SetOrCreate("netIdManager",this.netIdManager)
    AppStorage.SetOrCreate("passphraseManager",this.passphraseManager)
    AppStorage.SetOrCreate("groupNameManager",this.groupNameManager)
    AppStorage.SetOrCreate("goBandManager",this.goBandManager)
    AppStorage.SetOrCreate("devNameManager",this.devNameManager)
  }

  build() {
    Column() {
      Row() {
        Text("deviceAddressManager:").fontSize(16).width(120)
        TextInput({ text: this.deviceAddressManager, placeholder: "input peripheral deviceId." })
          .fontSize("15vp")
          .onChange((strInput) => {
            this.deviceAddressManager = strInput;
            //判断合法性
            if (strInput.length >= 1) {
              AppStorage.SetOrCreate('deviceAddressManager', strInput);
            }
          })
          .width("80%")
          .borderRadius(1)
      }
      .backgroundColor($r("app.color.moon"))
      .padding(5)
      .justifyContent(FlexAlign.Start)
      .alignItems(VerticalAlign.Center)

      Column() {
        Stack().height("0.25vp").backgroundColor("#000000");
        Column() {
          Row() {
            Text("netIdManager:").fontSize(15).width(60);
            TextInput({ text: this.netIdManager, placeholder: "input netId" })
              .fontSize("15vp")
              .onChange((strInput) => {
                this.netIdManager = strInput;
                //判断合法性
                if (strInput.length >= 1) {
                  AppStorage.SetOrCreate('netIdManager', strInput);
                }
              })
              .width("80%")
              .borderRadius(1)
          }
          .padding(5)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)
          .backgroundColor($r("app.color.spring"))

          Row() {
            Text("passphraseManager:").fontSize(15).width(100);
            TextInput({ text: this.passphraseManager, placeholder: "input passphrase" })
              .fontSize("15vp")
              .onChange((strInput) => {
                this.passphraseManager = strInput;
                if (strInput.length >= 1) {
                  AppStorage.SetOrCreate('passphraseManager', strInput);
                }
              })
              .width("80%")
              .borderRadius(1)
          }
          .backgroundColor($r("app.color.spring"))
          .padding(5)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)

          Row() {
            Text("groupNameManager:").fontSize(15).width(100);
            TextInput({ text: this.groupNameManager, placeholder: "groupNameManager" })
              .fontSize("15vp")
              .onChange((strInput) => {
                this.groupNameManager = strInput;
                if (strInput.length >= 1) {
                  AppStorage.SetOrCreate('groupNameManager', strInput);
                }
              })
              .width("80%")
              .borderRadius(1)
          }
          .backgroundColor($r("app.color.spring"))
          .padding(5)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)

          Row() {
            Text("goBandManager:").fontSize(15).width(80);
            TextInput({ text: this.goBandManager, placeholder: "input descriptor UUID" })
              .fontSize("15vp")
              .onChange((strInput) => {
                this.goBandManager = strInput;
                if (strInput.length >= 1) {
                  AppStorage.SetOrCreate('goBandManager', strInput);
                }
              })
              .width("80%")
              .borderRadius(1)
          }
          .backgroundColor($r("app.color.spring"))
          .padding(5)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)

          Row() {
            Text("devNameManager:").fontSize(15).width(60);
            TextInput({ text: this.devNameManager, placeholder: "descriptor devNameManager" })
              .fontSize("15vp")
              .onChange((strInput) => {
                this.devNameManager = strInput;
                if (strInput.length >= 1) {
                  AppStorage.SetOrCreate('devNameManager', strInput);
                }
              })
              .width("80%")
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
  @State deviceAddressManager : string = '6c:96:d7:3d:87:6f';
  @State netIdManager : number = -2 ;
  @State passphraseManager : string = "12345678" ;
  @State groupNameManager : string ="testGroup"
  @State goBandManager : number = 0 ;
  @State devNameManager : string ="test"
  @StorageLink('p2pStateManagerMessage') p2pStateManagerMessage: string = "";
  @StorageLink('p2pLinkManagerMessage') p2pLinkManagerMessage: string = "";
  @StorageLink('p2pGroupManagerMessage') p2pGroupManagerMessage: string = "";
  @StorageLink('p2pDevicManagereMessage') p2pDeviceManagerMessage: string = "";

  aboutToAppear() {
    AppStorage.SetOrCreate("deviceAddressManager",this.deviceAddressManager)
    AppStorage.SetOrCreate("netIdManager",this.netIdManager)
    AppStorage.SetOrCreate("passphraseManager",this.passphraseManager)
    AppStorage.SetOrCreate("groupNameManager",this.groupNameManager)
    AppStorage.SetOrCreate("goBandManager",this.goBandManager)
    AppStorage.SetOrCreate("devNameManager",this.devNameManager)
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
        Row() {
          Text("目标设备IP：")
            .fontSize("20vp")
            .height(40)
            .padding({ top: 5})
            .width("28%")
            .align(Alignment.Start)

          TextInput({ text: this.pairedMac, placeholder: "请输入即将连接的设备MAC" })
            .height(40)
            .borderStyle(BorderStyle.Dashed)
            .backgroundColor($r("app.color.white"))
            .onChange((str) => {
              this.deviceId = str;
            })
            .width("45%")
            .padding({ top: 5, left: 5 })
          Image($r('app.media.Switch'))
            .height(50)
            .padding({ top: 5, bottom: 5, left: 10 })
            .width('15%')
            .onClick(() => {
              this.showList = !this.showList;
            })
        }
      }
      .align(Alignment.TopStart)
      if (this.showList) {
        p2pSetting()
      }else{
        Column() {
          Scroll(){
            Column(){
//              Text("当前配置:")
//                .fontSize("17vp")
//                .margin({ top: "5vp", left: "10vp" })
//                .textAlign(TextAlign.Start)
//                .width("100%")
              Text("开关结果:" + this.p2pStateManagerMessage)
                .fontSize("17vp")
                .margin({ top: "5vp", left: "15vp" })
                .textAlign(TextAlign.Start)
                .width("90%")
              Text("连接信息:" + this.p2pLinkManagerMessage)
                .fontSize("17vp")
                .margin({ top: "5vp", left: "15vp" })
                .textAlign(TextAlign.Start)
                .width("90%")
              Text("组信息:" + this.p2pGroupManagerMessage)
                .fontSize("17vp")
                .margin({ top: "5vp", left: "15vp" })
                .textAlign(TextAlign.Start)
                .width("90%")
              Text("对端信息:" + this.p2pDeviceManagerMessage)
                .fontSize("17vp")
                .margin({ top: "5vp", left: "15vp"  })
                .textAlign(TextAlign.Start)
                .width("90%")
            }
            .width("100%")
          }
          .scrollBarWidth(10)
          .scrollBar(BarState.Auto)
        }
        .height(100)
        .width("95%")
        .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))
        ContentTable({ testItem: this.testItem, apiItems: initP2pApiData() })

      }
    }
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r("app.color.lead"))
    .height("100%")
  }
}


