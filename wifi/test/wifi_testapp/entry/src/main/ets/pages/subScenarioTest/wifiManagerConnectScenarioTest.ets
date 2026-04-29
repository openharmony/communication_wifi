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
import promptAction from '@ohos.promptAction';
import router from '@ohos.router';
import { PageTitle} from '../../Component/pageTitle';
import { TestImageDisplay} from '../../Component/testImageDisplay';
import { TestData} from '../../entryability/model/testData';
import { ScenarioContentTable} from '../../Component/scenarioContentTable';
import {
  WifiManagerConnectScenarioTestCase,
  initWifiManagerConnectScenarioData
} from '../../entryability/model/scenarioTestDataModels'
import * as WifiManagerInterface from '../../entryability/model/wifiManagerInterface';
import ConfigData from '../../Utils/ConfigData';

/**
 * WiFiManager Connect Scenario Test Page Of WiFi test
 */

interface myParams extends Object {
  testItem: TestData
}

interface IWifiAutoArrayItem {
  name: string;
  para: string[];
}

@Entry
@Component
struct wifiManagerConnectScenarioTest {
  @State message: string = ConfigData.TAG_MSG_WIFI_M_CONN;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State changeIndex: number = ConfigData.ITEM_CLICK_NONE
  @StorageLink("wifiManagerConnectScenarioMessage") wifiManagerConnectScenarioMessage: string = ""
  @State w_ssid1: string = ConfigData.QV_MOCK_SSID;
  @State w_bssid1: string = ConfigData.QV_MOCK_BSSID;
  @State w_preSharedKey1: string = ConfigData.QV_MOCK_PRE_SHARED_KEY;
  @State w_isHiddenSsid1: boolean = false;
  @State w_securityType1: number = ConfigData.QV_MOCK_SECURITY_TYPE;
  @State w_creatorUid1: number = ConfigData.QV_MOCK_CREATOR_UID;
  @State w_disableReason1: number = ConfigData.QV_MOCK_DISABLE_REASON;
  @State w_netId1: number = ConfigData.SCENARIO_WM_NET_ID;
  @State w_randomMacType1: number = ConfigData.QV_MOCK_RANDOM_MAC_TYPE;
  @State w_randomMacAddr1: string = ConfigData.QV_MOCK_RANDOM_MAC_ADDR
  @State w_ipType1: number = ConfigData.QV_MOCK_IP_TYPE;
  @State w_staticIp_ipAddress1: number = ConfigData.QV_MOCK_STATIC_IP_ADDRESS;
  @State w_staticIp_gateway1: number = ConfigData.QV_MOCK_STATIC_GATEWAY;
  @State w_staticIp_dnsServers1: number = ConfigData.QV_MOCK_STATIC_DNS;
  @State w_staticIp_domains1: Array<string> = [ConfigData.QV_MOCK_DOMAIN_0, ConfigData.QV_MOCK_DOMAIN_1, ConfigData.QV_MOCK_DOMAIN_2];
  @State w_networkIdM: number = ConfigData.SCENARIO_WM_NET_ID;
  @State w_featureIdM: number = ConfigData.QV_MOCK_CREATOR_UID;

  aboutToAppear() {
    AppStorage.setOrCreate('w_ssid1', this.w_ssid1);
    AppStorage.setOrCreate('w_bssid1', this.w_bssid1);
    AppStorage.setOrCreate('w_preSharedKey1', this.w_preSharedKey1);
    AppStorage.setOrCreate('w_isHiddenSsid1', this.w_isHiddenSsid1);
    AppStorage.setOrCreate('w_securityType1', this.w_securityType1);
    AppStorage.setOrCreate('w_creatorUid1', this.w_creatorUid1);
    AppStorage.setOrCreate('w_disableReason1', this.w_disableReason1);
    AppStorage.setOrCreate('w_netId1', this.w_netId1);
    AppStorage.setOrCreate('w_randomMacType1', this.w_randomMacType1);
    AppStorage.setOrCreate('w_randomMacAddr1', this.w_randomMacAddr1);
    AppStorage.setOrCreate('w_ipType1', this.w_ipType1);
    AppStorage.setOrCreate('w_staticIp_ipAddress1', this.w_staticIp_ipAddress1);
    AppStorage.setOrCreate('w_staticIp_gateway1', this.w_staticIp_gateway1);
    AppStorage.setOrCreate('w_staticIp_dnsServers1', this.w_staticIp_dnsServers1);
    AppStorage.setOrCreate('w_staticIp_domains1', this.w_staticIp_domains1);
    AppStorage.setOrCreate('w_networkIdM', this.w_networkIdM);
    AppStorage.setOrCreate('w_featureIdM', this.w_featureIdM);
  }

  build() {
    Column() {
      Stack({alignContent: Alignment.TopStart}){
        TestImageDisplay({testItem: this.testItem})
        PageTitle({testItem: this.testItem})
      }

      Stack().height(ConfigData.VP_1).backgroundColor($r("app.color.black"));
      Column() {
        Scroll() {
          Column() {
            Text($r('app.string.wifitest_text_cjlcyz'))
              .fontSize(ConfigData.VP_17)
              .margin({top: ConfigData.VP_10, bottom: ConfigData.VP_10, left: ConfigData.VP_20})
              .textAlign(TextAlign.Start)
              .width(ConfigData.WH_100_100)
            ScenarioContentTable({
              // testItem: this.testItem ,
              scenarioItems: initWifiManagerConnectScenarioData(),
              //            testMessage: this.testMessage,  优化时修改
              changeIndex: this.changeIndex
            })
          }
          .width(ConfigData.WH_100_100)
          .height(ConfigData.VP_280)
        }
        .scrollBarWidth(ConfigData.VP_10)
        .scrollBar(BarState.Auto)

        Stack().height(ConfigData.VP_1).backgroundColor($r("app.color.black"));

        Scroll() {
          Column() {
            Text($r('app.string.wifitest_text_lcrz'))
              .fontSize(ConfigData.VP_17)
              .margin({top: ConfigData.VP_8, bottom: ConfigData.VP_8, left: ConfigData.VP_20})
              .textAlign(TextAlign.Start)
              .width(ConfigData.WH_100_100)
            List() {
              ListItem() {
                Text(this.wifiManagerConnectScenarioMessage)
                  .fontSize(ConfigData.VP_17)
                  .margin({top: ConfigData.VP_5, left: ConfigData.VP_30, right: ConfigData.VP_10})
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_90_100)
              }
            }
            .height(ConfigData.WH_80_100)
            .width(ConfigData.WH_90_100)
            .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))
          }
          .width(ConfigData.WH_100_100)
          .height(ConfigData.VP_260)
        }
        .scrollBarWidth(ConfigData.VP_10)
        .scrollBar(BarState.On)
      }
      .height(ConfigData.VP_500)
      .width(ConfigData.WH_100_100)
      .backgroundColor($r("sys.color.ohos_id_color_sub_background"))


      Stack().height(ConfigData.VP_1).backgroundColor($r("app.color.black"));
      Column() {
        Flex({alignItems: ItemAlign.Center, justifyContent: FlexAlign.SpaceBetween}){
          Button({type: ButtonType.Normal, stateEffect: true}){
            Text($r('app.string.wifitest_text_cjcsks')).fontSize(ConfigData.VP_24).fontColor($r('app.color.white')).margin({left: ConfigData.VP_5, right: ConfigData.VP_5})
          }
          .borderRadius($r('app.float.wh_value_8'))
          .backgroundColor($r("app.color.blue"))
          .width(ConfigData.VP_100)
          .height(ConfigData.VP_66)
          .margin({top: ConfigData.VP_15, left: ConfigData.VP_20})
          .align(Alignment.Start)
          .onClick(async(event: ClickEvent) => {
            promptAction.showToast({message: $r('app.string.wifitest_toast_start_wifi_scenario')})
            await this.forLoop()
          })

          Button({type: ButtonType.Normal, stateEffect: true}){
            Row() {
              Text($r('app.string.wifitest_text_cjcsjs')).fontSize(ConfigData.VP_24).fontColor($r('app.color.white')).margin({left: ConfigData.VP_5, right: ConfigData.VP_5})
            }.alignItems(VerticalAlign.Center)
          }
          .borderRadius($r('app.float.wh_value_8'))
          .backgroundColor($r("app.color.blue"))
          .width(ConfigData.VP_100)
          .height(ConfigData.VP_66)
          .margin({top: ConfigData.VP_15, left: ConfigData.VP_10, right: ConfigData.VP_10})
          .align(Alignment.Start)
          .onClick(async(event: ClickEvent) => {
            let wifiManagerConnectScenarioMessage = ""
            // 断开连接
            wifiManagerConnectScenarioMessage += WifiManagerInterface.testDisconnectManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testDisconnect success")
            await sleep(1)
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage", wifiManagerConnectScenarioMessage)

            // 移除所有网络配置
            wifiManagerConnectScenarioMessage += WifiManagerInterface.testRemoveAllDeviceConfigsManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testRemoveAllNetwork success")
            await sleep(1)
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage", wifiManagerConnectScenarioMessage)

            // 关闭WLAN状态改变事件
            wifiManagerConnectScenarioMessage += WifiManagerInterface.testOnWifiStateChangeManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffWifiStateChange success")
            await sleep(1)
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage", wifiManagerConnectScenarioMessage)

            //关闭WLAN连接状态改变事件
            wifiManagerConnectScenarioMessage += WifiManagerInterface.testOnWifiConnectionChangeManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffWifiConnectionChange success")
            await sleep(1)
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage", wifiManagerConnectScenarioMessage)

            //关闭扫描状态改变事件
            wifiManagerConnectScenarioMessage += WifiManagerInterface.testOnWifiScanStateChangeManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffWifiScanStateChange success")
            await sleep(1)
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage", wifiManagerConnectScenarioMessage)

            //关闭RSSI状态改变事件
            wifiManagerConnectScenarioMessage += WifiManagerInterface.testOnWifiRssiChangeManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffWifiRssiChange success")
            await sleep(1)
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage", wifiManagerConnectScenarioMessage)

            //关Wifi
            wifiManagerConnectScenarioMessage += WifiManagerInterface.testDisableWifiManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testDisableWifi success")
            await sleep(1)
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage", wifiManagerConnectScenarioMessage)
          })

          Button({type: ButtonType.Normal, stateEffect: true}){
            Row() {
              Text($r('app.string.wifitest_text_qkrz')).fontSize(ConfigData.VP_24).fontColor($r('app.color.white')).margin({left: ConfigData.VP_5, right: ConfigData.VP_5})
            }.alignItems(VerticalAlign.Center)
          }
          .borderRadius($r('app.float.wh_value_8'))
          .backgroundColor($r("app.color.moon"))
          .width(ConfigData.VP_80)
          .height(ConfigData.VP_66)
          .margin({top: ConfigData.VP_15, right: ConfigData.VP_20})
          .align(Alignment.Start)
          .onClick(async(event: ClickEvent) => {
            let wifiManagerConnectScenarioMessage = ""
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage", wifiManagerConnectScenarioMessage)
          })
        }
        .backgroundColor($r("sys.color.ohos_id_color_sub_background"))
        .width(ConfigData.WH_100_100)
      }
      .backgroundColor($r("sys.color.ohos_id_color_sub_background"))
      .width(ConfigData.WH_100_100)
      .height(ConfigData.WH_100_100);
    }
  }


  //循环调用
  async forLoop() {
    let wifiManagerConnectScenarioMessage = ""
    let wifiManagerScenarioArray: IWifiAutoArrayItem[] = []

    //拼装数组
    let Interface = WifiManagerConnectScenarioTestCase.map(i => {
      // 查找与条件匹配的元素，并且确保其不是undefined
      const foundItem = wifiManagerScenarioArray.find(itm => itm.name === i.api.name);
      let para: string[] = foundItem ? foundItem.para: [];
      return { name: i.api.name, para} as IWifiAutoArrayItem;
    })
    for(let m = 0 ; m<Interface.length ; m++){
      wifiManagerConnectScenarioMessage += await WifiManagerConnectScenarioTestCase[m].api(... Interface[m].para) + "\n"
      this.changeIndex = m
      await sleep(1)
      AppStorage.setOrCreate("wifiManagerConnectScenarioMessage", wifiManagerConnectScenarioMessage)
    }
  }
}

async function sleep(time: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    setTimeout(() => {
      resolve();
    }, time * 1000);
  });
}