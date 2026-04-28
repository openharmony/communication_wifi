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
import { initP2pManagerApiData} from '../../entryability/model/testDataModels';
import { TestData} from '../../entryability/model/testData';

interface myParams extends Object {
  testItem: TestData
}

/**
 * p2pManager Test Page Of Wifi test
 */

@Component
struct p2pManagerSetting {
  @State deviceAddressManager: string = ConfigData.P2P_DEMO_ADDRESS;
  @State netIdManager: number = ConfigData.P2P_DEMO_NET_ID;
  @State passphraseManager: string = ConfigData.QV_MOCK_PRE_SHARED_KEY;
  @State groupNameManager: string = ConfigData.P2P_DEMO_GROUP_NAME
  @State goBandManager: number = 0;
  @State devNameManager: string = ConfigData.P2P_DEMO_DEVICE_NAME

  aboutToAppear() {
    AppStorage.setOrCreate("deviceAddressManager", this.deviceAddressManager)
    AppStorage.setOrCreate("netIdManager", this.netIdManager)
    AppStorage.setOrCreate("passphraseManager", this.passphraseManager)
    AppStorage.setOrCreate("groupNameManager", this.groupNameManager)
    AppStorage.setOrCreate("goBandManager", this.goBandManager)
    AppStorage.setOrCreate("devNameManager", this.devNameManager)
  }

  build() {
    Column() {
      Row() {
        Text($r('app.string.wifitest_text_d_6')).fontSize(ConfigData.VP_16).width(ConfigData.VP_120)
        TextInput({text: this.deviceAddressManager, placeholder: $r('app.string.wifitest_text_69d386')})
          .fontSize(ConfigData.VP_15)
          .onChange((strInput: string) => {
            this.deviceAddressManager = strInput;
            //判断合法性
            if (strInput.length >= 1){
              AppStorage.setOrCreate('deviceAddressManager', strInput);
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
            Text($r('app.string.wifitest_text_n_3')).fontSize(ConfigData.VP_15).width(ConfigData.VP_60);
            TextInput({text: this.netIdManager.toString(), placeholder: $r('app.string.wifitest_text_2')})
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                this.netIdManager = parseInt(strInput);
                //判断合法性
                if (strInput.length >= 1){
                  AppStorage.setOrCreate('netIdManager', strInput);
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
            Text($r('app.string.wifitest_text_p_5')).fontSize(ConfigData.VP_15).width(ConfigData.VP_100);
            TextInput({text: this.passphraseManager, placeholder: $r('app.string.wifitest_text_ip_1')})
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                this.passphraseManager = strInput;
                if (strInput.length >= 1){
                  AppStorage.setOrCreate('passphraseManager', strInput);
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
            Text($r('app.string.wifitest_text_g_3')).fontSize(ConfigData.VP_15).width(ConfigData.VP_100);
            TextInput({text: this.groupNameManager, placeholder: ConfigData.P2P_DEMO_GROUP_NAME})
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                this.groupNameManager = strInput;
                if (strInput.length >= 1){
                  AppStorage.setOrCreate('groupNameManager', strInput);
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
            Text($r('app.string.wifitest_text_g_2')).fontSize(ConfigData.VP_15).width(ConfigData.VP_80);
            TextInput({text: this.goBandManager.toString(), placeholder: ConfigData.QV_MOCK_DOMAIN_0})
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                this.goBandManager = Number(strInput);
                if (strInput.length >= 1){
                  AppStorage.setOrCreate('goBandManager', strInput);
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
            Text($r('app.string.wifitest_text_d_3')).fontSize(ConfigData.VP_15).width(ConfigData.VP_100);
            TextInput({text: this.devNameManager, placeholder: ConfigData.P2P_DEMO_DEVICE_NAME})
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                this.devNameManager = strInput;
                if (strInput.length >= 1){
                  AppStorage.setOrCreate('devNameManager', strInput);
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
struct P2pManagerInterfaceTest {
  @State showList: boolean = false;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State message: string = "";
  @State deviceId: string = '';
  @State currentClick: number = ConfigData.ITEM_CLICK_NONE;
  @StorageLink('pairedDeviceId') pairedDeviceId: string = '';
  @State deviceAddressManager: string = ConfigData.P2P_DEMO_ADDRESS;
  @State netIdManager: number = ConfigData.P2P_DEMO_NET_ID;
  @State passphraseManager: string = ConfigData.QV_MOCK_PRE_SHARED_KEY;
  @State groupNameManager: string = ConfigData.P2P_DEMO_GROUP_NAME
  @State goBandManager: number = 0;
  @State devNameManager: string = ConfigData.P2P_DEMO_DEV_NAME
  @State connectedIp: string = ConfigData.P2P_DEMO_PEER_IP
  @StorageLink('p2pManagerDeviceName') p2pManagerDeviceName: string = "";
  @StorageLink('p2pStateManagerMessage') p2pStateManagerMessage: string = "";
  @StorageLink('p2pDeviceManagerMessage') p2pDeviceManagerMessage: string = "";
  @StorageLink('p2pLinkStateManagerMessage') p2pLinkStateManagerMessage: string = "";
  @StorageLink('p2pLinkManagerMessage') p2pLinkManagerMessage: string = "";
  @StorageLink('p2pPeerDeviceManagerMessage') p2pPeerDeviceManagerMessage: string = "";
  @StorageLink('p2pPeerDeviceManagerMessages') p2pPeerDeviceManagerMessages: string = "";
  @StorageLink('p2pDiscoveryManagerMessage') p2pDiscoveryManagerMessage: string = "";
  @StorageLink('p2pGroupManagerMessage') p2pGroupManagerMessage: string = "";

  aboutToAppear() {
    AppStorage.setOrCreate("deviceAddressManager", this.deviceAddressManager)
    AppStorage.setOrCreate("netIdManager", this.netIdManager)
    AppStorage.setOrCreate("passphraseManager", this.passphraseManager)
    AppStorage.setOrCreate("groupNameManager", this.groupNameManager)
    AppStorage.setOrCreate("goBandManager", this.goBandManager)
    AppStorage.setOrCreate("devNameManager", this.devNameManager)
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

          TextInput({text: this.p2pManagerDeviceName, placeholder: $r('app.string.wifitest_text_qzycsrpdpz')})
            .height(ConfigData.VP_40)
            .borderStyle(BorderStyle.Dashed)
            .backgroundColor($r("app.color.white"))
            .onChange((str) => {
              this.p2pManagerDeviceName = str;
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
        p2pManagerSetting()
      } else {
        Column() {
          Scroll() {
            Column() {
              Text() {
                Span($r('app.string.wifitest_text_p2p_switch'))
                Span(this.p2pStateManagerMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_p2p_local'))
                Span(this.p2pDeviceManagerMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_p2p_discover'))
                Span(this.p2pDiscoveryManagerMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_p2p_link_state'))
                Span(this.p2pLinkStateManagerMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_p2p_link_info'))
                Span(this.p2pLinkManagerMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_p2p_peer'))
                Span(this.p2pPeerDeviceManagerMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_p2p_peers'))
                Span(this.p2pPeerDeviceManagerMessages)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_p2p_group'))
                Span(this.p2pGroupManagerMessage)
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

        ContentTable({testItem: this.testItem, apiItems: initP2pManagerApiData()})
      }
    }
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r("app.color.lead"))
    .height(ConfigData.WH_100_100)
  }
}
