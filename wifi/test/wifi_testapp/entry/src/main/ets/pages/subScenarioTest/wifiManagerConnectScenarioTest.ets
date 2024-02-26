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

import prompt from '@system.prompt';
import router from '@ohos.router';
import { PageTitle } from '../../Component/pageTitle';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { TestData } from '../../entryability/model/testData'
import { ScenarioContentTable } from '../../Component/scenarioContentTable'
import {
  WifiManagerConnectScenarioTestCase ,
  initWifiManagerConnectScenarioData
} from '../../entryability/model/scenarioTestDataModels'
import * as WifiManagerInterface from '../../entryability/model/wifiManagerInterface'
import ConfigData from '../../utils/ConfigData';

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
  @State message: string = 'wifiManagerConnectScenarioTest';
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State changeIndex: number = - 1
  @StorageLink("wifiManagerConnectScenarioMessage") wifiManagerConnectScenarioMessage: string = ""
  @State w_ssid1: string = "TP-LINK_6365";
  @State w_bssid1: string = "6C:B1:58:75:63:65";
  @State w_preSharedKey1: string = "12345678";
  @State w_isHiddenSsid1: boolean = false;
  @State w_securityType1: number = 3;
  @State w_creatorUid1: number = 1;
  @State w_disableReason1: number = 0;
  @State w_netId1: number = 0;
  @State w_randomMacType1: number = 0;
  @State w_randomMacAddr1: string = "08:fb:ea:1b:38:aa"
  @State w_ipType1: number = 1;
  @State w_staticIp_ipAddress1: number = 3232235880;
  @State w_staticIp_gateway1: number = 3232235777;
  @State w_staticIp_dnsServers1: number = 3716386629;
  @State w_staticIp_domains1: Array<string> = [ "0", "1", "2" ];
  @State w_networkIdM: number = 0;
  @State w_featureIdM: number = 1;

  aboutToAppear() {
    AppStorage.setOrCreate('w_ssid1' , this.w_ssid1);
    AppStorage.setOrCreate('w_bssid1' , this.w_bssid1);
    AppStorage.setOrCreate('w_preSharedKey1' , this.w_preSharedKey1);
    AppStorage.setOrCreate('w_isHiddenSsid1' , this.w_isHiddenSsid1);
    AppStorage.setOrCreate('w_securityType1' , this.w_securityType1);
    AppStorage.setOrCreate('w_creatorUid1' , this.w_creatorUid1);
    AppStorage.setOrCreate('w_disableReason1' , this.w_disableReason1);
    AppStorage.setOrCreate('w_netId1' , this.w_netId1);
    AppStorage.setOrCreate('w_randomMacType1' , this.w_randomMacType1);
    AppStorage.setOrCreate('w_randomMacAddr1' , this.w_randomMacAddr1);
    AppStorage.setOrCreate('w_ipType1' , this.w_ipType1);
    AppStorage.setOrCreate('w_staticIp_ipAddress1' , this.w_staticIp_ipAddress1);
    AppStorage.setOrCreate('w_staticIp_gateway1' , this.w_staticIp_gateway1);
    AppStorage.setOrCreate('w_staticIp_dnsServers1' , this.w_staticIp_dnsServers1);
    AppStorage.setOrCreate('w_staticIp_domains1' , this.w_staticIp_domains1);
    AppStorage.setOrCreate('w_networkIdM' , this.w_networkIdM);
    AppStorage.setOrCreate('w_featureIdM' , this.w_featureIdM);
  }

  build() {
    Column() {
      Stack({ alignContent : Alignment.TopStart }) {
        TestImageDisplay({ testItem : this.testItem })
        PageTitle({ testItem : this.testItem })
      }

      Stack().height("1vp").backgroundColor("#000000");
      Column() {
        Scroll() {
          Column() {
            Text("场景流程验证:")
              .fontSize("17vp")
              .margin({ top : "10vp" , bottom : "10vp" , left : "20vp" })
              .textAlign(TextAlign.Start)
              .width(ConfigData.WH_100_100)
            ScenarioContentTable({
              // testItem : this.testItem ,
              scenarioItems : initWifiManagerConnectScenarioData() ,
              //            testMessage: this.testMessage,  优化时修改
              changeIndex : this.changeIndex
            })
          }
          .width(ConfigData.WH_100_100)
          .height(280)
        }
        .scrollBarWidth(10)
        .scrollBar(BarState.Auto)

        Stack().height("1vp").backgroundColor("#000000");

        Scroll() {
          Column() {
            Text("流程日志:")
              .fontSize("17vp")
              .margin({ top : "8vp" , bottom : "8vp" , left : "20vp" })
              .textAlign(TextAlign.Start)
              .width(ConfigData.WH_100_100)
            List() {
              ListItem() {
                Text(this.wifiManagerConnectScenarioMessage)
                  .fontSize("17vp")
                  .margin({ top : "5vp" , left : "30vp" , right : "10vp" })
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_90_100)
              }
            }
            .height(ConfigData.WH_80_100)
            .width(ConfigData.WH_90_100)
            .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))
          }
          .width(ConfigData.WH_100_100)
          .height(260)
        }
        .scrollBarWidth(10)
        .scrollBar(BarState.On)
      }
      .height(500)
      .width(ConfigData.WH_100_100)
      .backgroundColor($r("sys.color.ohos_id_color_sub_background"))


      Stack().height("1vp").backgroundColor("#000000");
      Column() {
        Flex({ alignItems : ItemAlign.Center , justifyContent : FlexAlign.SpaceBetween }) {
          Button({ type : ButtonType.Normal , stateEffect : true }) {
            Text('场景测试开始').fontSize("24vp").fontColor(0xffffff).margin({ left : 5 , right : 5 })
          }
          .borderRadius(8)
          .backgroundColor($r("app.color.blue"))
          .width(100)
          .height(66)
          .margin({ top : "15vp" , left : "20vp" })
          .align(Alignment.Start)
          .onClick(async(event: ClickEvent) => {
            prompt.showToast({ message : '开始wifi连接场景测试' })
            await this.forLoop()
          })

          Button({ type : ButtonType.Normal , stateEffect : true }) {
            Row() {
              Text('场景测试结束').fontSize("24vp").fontColor(0xffffff).margin({ left : 5 , right : 5 })
            }.alignItems(VerticalAlign.Center)
          }
          .borderRadius(8)
          .backgroundColor($r("app.color.blue"))
          .width(100)
          .height(66)
          .margin({ top : "15vp" , left : "10vp" , right : "10vp" })
          .align(Alignment.Start)
          .onClick(async(event: ClickEvent) => {
            let wifiManagerConnectScenarioMessage = ""
            // 断开连接
            wifiManagerConnectScenarioMessage += WifiManagerInterface.testDisconnectManager() + "\n"
            console.log("testDisconnect success")
            await sleep(1)
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage" , wifiManagerConnectScenarioMessage)

            // 移除所有网络配置
            wifiManagerConnectScenarioMessage += WifiManagerInterface.testRemoveAllDeviceConfigsManager() + "\n"
            console.log("testRemoveAllNetwork success")
            await sleep(1)
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage" , wifiManagerConnectScenarioMessage)

            // 关闭WLAN状态改变事件
            wifiManagerConnectScenarioMessage += WifiManagerInterface.testOnWifiStateChangeManager() + "\n"
            console.log("testOffWifiStateChange success")
            await sleep(1)
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage" , wifiManagerConnectScenarioMessage)

            //关闭WLAN连接状态改变事件
            wifiManagerConnectScenarioMessage += WifiManagerInterface.testOnWifiConnectionChangeManager() + "\n"
            console.log("testOffWifiConnectionChange success")
            await sleep(1)
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage" , wifiManagerConnectScenarioMessage)

            //关闭扫描状态改变事件
            wifiManagerConnectScenarioMessage += WifiManagerInterface.testOnWifiScanStateChangeManager() + "\n"
            console.log("testOffWifiScanStateChange success")
            await sleep(1)
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage" , wifiManagerConnectScenarioMessage)

            //关闭RSSI状态改变事件
            wifiManagerConnectScenarioMessage += WifiManagerInterface.testOnWifiRssiChangeManager() + "\n"
            console.log("testOffWifiRssiChange success")
            await sleep(1)
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage" , wifiManagerConnectScenarioMessage)

            //关Wifi
            wifiManagerConnectScenarioMessage += WifiManagerInterface.testDisableWifiManager() + "\n"
            console.log("testDisableWifi success")
            await sleep(1)
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage" , wifiManagerConnectScenarioMessage)
          })

          Button({ type : ButtonType.Normal , stateEffect : true }) {
            Row() {
              Text('清空日志').fontSize("24vp").fontColor(0xffffff).margin({ left : 5 , right : 5 })
            }.alignItems(VerticalAlign.Center)
          }
          .borderRadius(8)
          .backgroundColor($r("app.color.moon"))
          .width(80)
          .height(66)
          .margin({ top : "15vp" , right : "20vp" })
          .align(Alignment.Start)
          .onClick(async(event: ClickEvent) => {
            let wifiManagerConnectScenarioMessage = ""
            AppStorage.setOrCreate("wifiManagerConnectScenarioMessage" , wifiManagerConnectScenarioMessage)
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
      let para: string[] = foundItem ? foundItem.para : [];
      return { name : i.api.name , para } as IWifiAutoArrayItem;
    })
    for ( let m = 0 ; m < Interface.length ; m ++ ) {
      wifiManagerConnectScenarioMessage += await WifiManagerConnectScenarioTestCase[ m ].api(... Interface[ m ].para) + "\n"
      this.changeIndex = m
      await sleep(1)
      AppStorage.setOrCreate("wifiManagerConnectScenarioMessage" , wifiManagerConnectScenarioMessage)
    }
  }
}

async function sleep(time: number): Promise<void> {
  return new Promise<void>((resolve , reject) => {
    setTimeout(() => {
      resolve();
    } , time * 1000);
  });
}