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
import { PageTitle} from '../../Component/pageTitle';
import { TestImageDisplay} from '../../Component/testImageDisplay';
import { ContentTable} from '../../Component/contentTable';
import router from '@ohos.router';
import ConfigData from '../../Utils/ConfigData';
import { initP2pApiData} from '../../entryability/model/testDataModels';
import { TestData} from '../../entryability/model/testData';

interface myParams extends Object {
  testItem: TestData
}

/**
 * p2p Test Page Of Wifi test
 */

@Component
struct p2pSetting {
  @State deviceAddress: string = ConfigData.P2P_DEMO_ADDRESS;
  @State netId: number = ConfigData.P2P_DEMO_NET_ID;
  @State passphrase: string = ConfigData.P2P_DEMO_PASSPHRASE;
  @State groupName: string = ConfigData.P2P_DEMO_GROUP_NAME;
  @State goBand: number = ConfigData.P2P_DEMO_GO_BAND;
  @State deviceName: string = ConfigData.P2P_DEMO_DEVICE_NAME;

  aboutToAppear() {
    AppStorage.setOrCreate("deviceAddress", this.deviceAddress)
    AppStorage.setOrCreate("netId", this.netId)
    AppStorage.setOrCreate("passphrase", this.passphrase)
    AppStorage.setOrCreate("groupName", this.groupName)
    AppStorage.setOrCreate("goBand", this.goBand)
    AppStorage.setOrCreate("deviceName", this.deviceName)
  }

  build() {
    Column() {
      Row() {
        Text($r('app.string.wifitest_text_d_1')).fontSize(ConfigData.VP_16).width(ConfigData.VP_120)
        TextInput({text: this.deviceAddress, placeholder: $r('app.string.wifitest_text_ipd')})
          .fontSize(ConfigData.VP_15)
          .onChange((strInput: string) => {
            this.deviceAddress = strInput;
            //判断合法性
            if (strInput.length >= 1){
              AppStorage.setOrCreate('deviceAddress', this.deviceAddress);
            }
          })
          .width(ConfigData.WH_80_100)
          .borderRadius($r('app.float.wh_value_1'))
      }
      .backgroundColor($r("app.color.moon"))
      .padding(ConfigData.VP_5)
      .justifyContent(FlexAlign.Start)
      .alignItems(VerticalAlign.Center)

      Column() {
        Stack().height(ConfigData.VP_0_25).backgroundColor($r("app.color.black"));
        Column() {
          Row() {
            Text($r('app.string.wifitest_text_n')).fontSize(ConfigData.VP_15).width(ConfigData.VP_60);
            TextInput({text: this.netId.toString(), placeholder: $r('app.string.wifitest_text_2')})
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                this.netId = parseInt(strInput);
                //判断合法性
                if (strInput.length >= 1){
                  AppStorage.setOrCreate('netId', this.netId);
                }
              })
              .width(ConfigData.WH_80_100)
              .borderRadius($r('app.float.wh_value_1'))
          }
          .padding(ConfigData.VP_5)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)
          .backgroundColor($r("app.color.spring"))

          Row() {
            Text($r('app.string.wifitest_text_p')).fontSize(ConfigData.VP_15).width(ConfigData.VP_100);
            TextInput({text: this.passphrase, placeholder: $r('app.string.wifitest_text_ip_1')})
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                this.passphrase = strInput;
                if (strInput.length >= 1){
                  AppStorage.setOrCreate('passphrase', this.passphrase);
                }
              })
              .width(ConfigData.WH_80_100)
              .borderRadius($r('app.float.wh_value_1'))
          }
          .backgroundColor($r("app.color.spring"))
          .padding(ConfigData.VP_5)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)

          Row() {
            Text($r('app.string.wifitest_text_g_1')).fontSize(ConfigData.VP_15).width(ConfigData.VP_100);
            TextInput({text: this.groupName, placeholder: ConfigData.P2P_DEMO_GROUP_NAME})
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                this.groupName = strInput;
                if (strInput.length >= 1){
                  AppStorage.setOrCreate('groupName', this.groupName);
                }
              })
              .width(ConfigData.WH_80_100)
              .borderRadius($r('app.float.wh_value_1'))
          }
          .backgroundColor($r("app.color.spring"))
          .padding(ConfigData.VP_5)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)

          Row() {
            Text($r('app.string.wifitest_text_g')).fontSize(ConfigData.VP_15).width(ConfigData.VP_80);
            TextInput({text: this.goBand.toString(), placeholder: ConfigData.QV_MOCK_DOMAIN_0})
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                this.goBand = Number(strInput);
                if (strInput.length >= 1){
                  AppStorage.setOrCreate('goBand', this.goBand);
                }
              })
              .width(ConfigData.WH_80_100)
              .borderRadius($r('app.float.wh_value_1'))
          }
          .backgroundColor($r("app.color.spring"))
          .padding(ConfigData.VP_5)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)


          Row() {
            Text($r('app.string.wifitest_text_d')).fontSize(ConfigData.VP_15).width(ConfigData.VP_100);
            TextInput({text: this.deviceName, placeholder: ConfigData.P2P_DEMO_DEVICE_NAME})
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                this.deviceName = strInput;
                if (strInput.length >= 1){
                  AppStorage.setOrCreate('deviceName', strInput);
                }
              })
              .width(ConfigData.WH_80_100)
              .borderRadius($r('app.float.wh_value_1'))
          }
          .backgroundColor($r("app.color.spring"))
          .padding(ConfigData.VP_5)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)
        }

        Stack().height(ConfigData.VP_0_25).backgroundColor($r("app.color.black"));
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
  @State currentClick: number = ConfigData.ITEM_CLICK_NONE;
  @State pairPinCode: string = '';
  @State isStateChangeClick: boolean = false;
  @State deviceAddress: string = ConfigData.P2P_DEMO_ADDRESS;
  @State netId: number = ConfigData.P2P_DEMO_NET_ID;
  @State passphrase: string = ConfigData.P2P_DEMO_PASSPHRASE;
  @State groupName: string = ConfigData.P2P_DEMO_GROUP_NAME;
  @State goBand: number = ConfigData.P2P_DEMO_GO_BAND;
  @State deviceName: string = ConfigData.P2P_DEMO_DEVICE_NAME;
  @State connectedIp: string = ConfigData.P2P_DEMO_PEER_IP
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
    AppStorage.setOrCreate("deviceAddress", this.deviceAddress)
    AppStorage.setOrCreate("netId", this.netId)
    AppStorage.setOrCreate("passphrase", this.passphrase)
    AppStorage.setOrCreate("groupName", this.groupName)
    AppStorage.setOrCreate("goBand", this.goBand)
    AppStorage.setOrCreate("deviceName", this.deviceName)
  }

  init() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', "init-----------")
  }

  build() {
    Column() {
      Stack({alignContent: Alignment.TopStart}){
        TestImageDisplay({testItem: this.testItem})
        PageTitle({testItem: this.testItem})
      }

      Stack().height(ConfigData.VP_0_5).backgroundColor($r("app.color.black"));

      Column() {
        Row() {
          Text($r('app.string.wifitest_text_bsbmc'))
            .fontSize(ConfigData.VP_20)
            .height(ConfigData.VP_40)
            .padding({top: ConfigData.VP_5})
            .width(ConfigData.WH_28_100)
            .align(Alignment.Start)

          TextInput({text: this.p2pDeviceName, placeholder: $r('app.string.wifitest_text_qzycsrpdpz')})
            .height(ConfigData.VP_40)
            .borderStyle(BorderStyle.Dashed)
            .backgroundColor($r("app.color.white"))
            .onChange((str) => {
              this.p2pDeviceName = str;
            })
            .width(ConfigData.WH_45_100)
            .padding({top: ConfigData.VP_5, left: ConfigData.VP_5})
          Image($r('app.media.Switch'))
            .height(ConfigData.VP_50)
            .padding({top: ConfigData.VP_5, bottom: ConfigData.VP_5, left: ConfigData.VP_10})
            .width(ConfigData.WH_15_100)
            .onClick(() => {
              this.showList = !this.showList;
            })
        }
      }
      .align(Alignment.TopStart)

      if (this.showList){
        p2pSetting()
      } else {
        Column() {
          Scroll() {
            Column() {
              Text() {
                Span($r('app.string.wifitest_text_p2p_switch'))
                Span(this.p2pStateMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_p2p_local'))
                Span(this.p2pDeviceMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_p2p_discover'))
                Span(this.p2pDiscoveryMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_p2p_link_state'))
                Span(this.p2pLinkStateMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_p2p_link_info'))
                Span(this.p2pLinkMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_p2p_peer'))
                Span(this.p2pPeerDeviceMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_p2p_peers'))
                Span(this.p2pPeerDeviceMessages)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_p2p_group'))
                Span(this.p2pGroupMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
            }
            .width(ConfigData.WH_100_100)
          }
          .scrollBarWidth(ConfigData.VP_10)
          .scrollBar(BarState.Auto)
        }
        .height(ConfigData.VP_100)
        .width(ConfigData.WH_95_100)
        .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))

        ContentTable({testItem: this.testItem, apiItems: initP2pApiData()})
      }
    }
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r("app.color.lead"))
    .height(ConfigData.WH_100_100)
  }
}
