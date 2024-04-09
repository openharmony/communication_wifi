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

import { PageTitle } from '../../Component/pageTitle';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { ContentTable } from '../../Component/contentTable';
import router from '@ohos.router';
import ConfigData from '../../utils/ConfigData';
import { initP2pApiData } from '../../entryability/model/testDataModels'
import { TestData } from '../../entryability/model/testData'

interface myParams extends Object {
  testItem: TestData
}

/**
 * p2p Test Page Of Wifi test
 */

@Component
struct p2pSetting {
  @State deviceAddress: string = '6c:96:d7:3d:87:6f';
  @State netId: number = - 2;
  @State passphrase: string = "12345678";
  @State groupName: string = "testGroup"
  @State goBand: number = 0;
  @State deviceName: string = "MyTestDevice"

  aboutToAppear() {
    AppStorage.setOrCreate("deviceAddress" , this.deviceAddress)
    AppStorage.setOrCreate("netId" , this.netId)
    AppStorage.setOrCreate("passphrase" , this.passphrase)
    AppStorage.setOrCreate("groupName" , this.groupName)
    AppStorage.setOrCreate("goBand" , this.goBand)
    AppStorage.setOrCreate("deviceName" , this.deviceName)
  }

  build() {
    Column() {
      Row() {
        Text("deviceAddress:").fontSize(16).width(120)
        TextInput({ text : this.deviceAddress , placeholder : "input peripheral deviceId." })
          .fontSize("15vp")
          .onChange((strInput: string) => {
            this.deviceAddress = strInput;
            //判断合法性
            if ( strInput.length >= 1 ) {
              AppStorage.setOrCreate('deviceAddress' , this.deviceAddress);
            }
          })
          .width(ConfigData.WH_80_100)
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
            Text("netId:").fontSize(15).width(60);
            TextInput({ text : this.netId.toString() , placeholder : "-2" })
              .fontSize("15vp")
              .onChange((strInput: string) => {
                this.netId = parseInt(strInput);
                //判断合法性
                if ( strInput.length >= 1 ) {
                  AppStorage.setOrCreate('netId' , this.netId);
                }
              })
              .width(ConfigData.WH_80_100)
              .borderRadius(1)
          }
          .padding(5)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)
          .backgroundColor($r("app.color.spring"))

          Row() {
            Text("passphrase:").fontSize(15).width(100);
            TextInput({ text : this.passphrase , placeholder : "input passphrase" })
              .fontSize("15vp")
              .onChange((strInput: string) => {
                this.passphrase = strInput;
                if ( strInput.length >= 1 ) {
                  AppStorage.setOrCreate('passphrase' , this.passphrase);
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
            Text("groupName:").fontSize(15).width(100);
            TextInput({ text : this.groupName , placeholder : "testGroup" })
              .fontSize("15vp")
              .onChange((strInput: string) => {
                this.groupName = strInput;
                if ( strInput.length >= 1 ) {
                  AppStorage.setOrCreate('groupName' , this.groupName);
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
            Text("goBand:").fontSize(15).width(80);
            TextInput({ text : this.goBand.toString() , placeholder : "0" })
              .fontSize("15vp")
              .onChange((strInput: string) => {
                this.goBand = Number(strInput);
                if ( strInput.length >= 1 ) {
                  AppStorage.setOrCreate('goBand' , this.goBand);
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
            Text("deviceName:").fontSize(15).width(100);
            TextInput({ text : this.deviceName , placeholder : "MyTestDevice" })
              .fontSize("15vp")
              .onChange((strInput: string) => {
                this.deviceName = strInput;
                if ( strInput.length >= 1 ) {
                  AppStorage.setOrCreate('deviceName' , strInput);
                }
              })
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
  }
}

@Entry
@Component
struct P2pInterfaceTest {
  @State showList: boolean = false;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State message: string = "";
  @State deviceId: string = '';
  @State currentClick: number = - 1;
  @State pairPinCode: string = '';
  @State isStateChangeClick: boolean = false;
  @State deviceAddress: string = '6c:96:d7:3d:87:6f';
  @State netId: number = - 2;
  @State passphrase: string = "12345678";
  @State groupName: string = "testGroup"
  @State goBand: number = 0;
  @State deviceName: string = "MyTestDevice"
  @State connectedIp: string = "192.168.1.107"
  @StorageLink('p2pDeviceName') p2pDeviceName: string = "";
  @StorageLink('p2pStateMessage') p2pStateMessage: string = "";
  @StorageLink('p2pDeviceMessage') p2pDeviceMessage: string = "";
  @StorageLink('p2pLinkStateMessage') p2pLinkStateMessage: string = "";
  @StorageLink('p2pLinkMessage') p2pLinkMessage: string = "";
  @StorageLink('p2pPeerDeviceMessage') p2pPeerDeviceMessage: string = "";
  @StorageLink('p2pPeerDeviceMessages') p2pPeerDeviceMessages: string = "";
  @StorageLink('p2pDiscoveryMessage') p2pDiscoveryMessage: string = "";
  @StorageLink('p2pGroupMessage') p2pGroupMessage: string = "";

  aboutToAppear() {
    AppStorage.setOrCreate("deviceAddress" , this.deviceAddress)
    AppStorage.setOrCreate("netId" , this.netId)
    AppStorage.setOrCreate("passphrase" , this.passphrase)
    AppStorage.setOrCreate("groupName" , this.groupName)
    AppStorage.setOrCreate("goBand" , this.goBand)
    AppStorage.setOrCreate("deviceName" , this.deviceName)
  }

  init() {
    console.log("init-----------")
  }

  build() {
    Column() {
      Stack({ alignContent : Alignment.TopStart }) {
        TestImageDisplay({ testItem : this.testItem })
        PageTitle({ testItem : this.testItem })
      }

      Stack().height("0.5vp").backgroundColor("#000000");

      Column() {
        Row() {
          Text("本设备名称：")
            .fontSize("20vp")
            .height(40)
            .padding({ top : 5 })
            .width(ConfigData.WH_28_100)
            .align(Alignment.Start)

          TextInput({ text : this.p2pDeviceName , placeholder : "请在右侧输入p2p的配置" })
            .height(40)
            .borderStyle(BorderStyle.Dashed)
            .backgroundColor($r("app.color.white"))
            .onChange((str) => {
              this.p2pDeviceName = str;
            })
            .width(ConfigData.WH_45_100)
            .padding({ top : 5 , left : 5 })
          Image($r('app.media.Switch'))
            .height(50)
            .padding({ top : 5 , bottom : 5 , left : 10 })
            .width(ConfigData.WH_15_100)
            .onClick(() => {
              this.showList = !this.showList;
            })
        }
      }
      .align(Alignment.TopStart)

      if ( this.showList ) {
        p2pSetting()
      } else {
        Column() {
          Scroll() {
            Column() {
              Text("开关结果:" + this.p2pStateMessage)
                .fontSize("17vp")
                .margin({ top : "5vp" , left : "10vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("本机信息:" + this.p2pDeviceMessage)
                .fontSize("17vp")
                .margin({ top : "5vp" , left : "10vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("发现信息:" + this.p2pDiscoveryMessage)
                .fontSize("17vp")
                .margin({ top : "5vp" , left : "10vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("连接状态:" + this.p2pLinkStateMessage)
                .fontSize("17vp")
                .margin({ top : "5vp" , left : "10vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("连接信息:" + this.p2pLinkMessage)
                .fontSize("17vp")
                .margin({ top : "5vp" , left : "10vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("对端设备:" + this.p2pPeerDeviceMessage)
                .fontSize("17vp")
                .margin({ top : "5vp" , left : "10vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("对端设备[]:" + this.p2pPeerDeviceMessages)
                .fontSize("17vp")
                .margin({ top : "5vp" , left : "10vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("组信息:" + this.p2pGroupMessage)
                .fontSize("17vp")
                .margin({ top : "5vp" , left : "10vp" })
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

        ContentTable({ testItem : this.testItem , apiItems : initP2pApiData() })
      }
    }
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r("app.color.lead"))
    .height(ConfigData.WH_100_100)
  }
}

