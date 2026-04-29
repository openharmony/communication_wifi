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
  P2pManagerConnectScenarioTestCase,
  initP2pManagerConnectScenarioData
} from '../../entryability/model/scenarioTestDataModels'
import * as P2pManagerInterface from '../../entryability/model/p2pManagerInterface';
import ConfigData from '../../Utils/ConfigData';

interface myParams extends Object {
  testItem: TestData
}

interface IWifiAutoArrayItem {
  name: string;
  para: string[];// 替换any[]为实际参数类型
}

/**
 * p2pManager Connect Scenario Test Page Of WiFi test
 */
@Entry
@Component
struct p2pManagerConnectScenarioTest {
  @State message: string = ConfigData.TAG_MSG_P2P_M_CONN;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State changeIndex: number = ConfigData.ITEM_CLICK_NONE
  @StorageLink("p2pManagerConnectScenarioMessage") p2pManagerConnectScenarioMessage: string = ""
  @State deviceAddressManager: string = ConfigData.P2P_DEMO_ADDRESS;
  @State netIdManager: number = ConfigData.P2P_DEMO_NET_ID;
  @State passphraseManager: string = ConfigData.QV_MOCK_PRE_SHARED_KEY;
  @State groupNameManager: string = ConfigData.P2P_DEMO_GROUP_NAME;
  @State goBandManager: number = ConfigData.P2P_DEMO_GO_BAND;
  @State devNameManager: string = ConfigData.P2P_DEMO_DEVICE_NAME;

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
              // testItem: this.testItem,
              scenarioItems: initP2pManagerConnectScenarioData(),
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
                Text(this.p2pManagerConnectScenarioMessage)
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
            promptAction.showToast({message: $r('app.string.wifitest_toast_start_p2p_scenario')})
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
            let p2pManagerConnectScenarioMessage = ""
            // 停止发现设备
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testStopDiscoverP2pDevicesManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testStopDiscoverP2pDevicesManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage", p2pManagerConnectScenarioMessage)

            //取消P2P连接
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testP2pCancelConnectManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testP2pCancelConnectManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage", p2pManagerConnectScenarioMessage)

            //移除群组
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testRemoveP2pGroupManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testRemoveP2pGroupManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage", p2pManagerConnectScenarioMessage)

            //删除永久组
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testDeletePersistentP2pGroupManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testDeletePersistentP2pGroupManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage", p2pManagerConnectScenarioMessage)

            //关闭P2P开关状态改变事件
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testOnP2pStateChangeManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffP2pStateChangeManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage", p2pManagerConnectScenarioMessage)

            //关闭P2P连接状态改变事件
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testOnP2pConnectionChangeManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffP2pConnectionChangeManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage", p2pManagerConnectScenarioMessage)

            //关闭P2P设备状态改变事件
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testOnP2pDeviceChangeManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffP2pDeviceChangeManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage", p2pManagerConnectScenarioMessage)

            //关闭P2P对端设备状态改变事件
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testOnP2pPeerDeviceChangeManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffP2pPeerDeviceChangeManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage", p2pManagerConnectScenarioMessage)

            //关闭P2P永久组状态改变事件
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testOnP2pPersistentGroupChangeManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffP2pPersistentGroupChangeManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage", p2pManagerConnectScenarioMessage)

            //关闭发现设备状态改变事件
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testOnP2pDiscoveryChangeManager() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffP2pDiscoveryChangeManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage", p2pManagerConnectScenarioMessage)
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
            let p2pManagerConnectScenarioMessage = ""
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage", p2pManagerConnectScenarioMessage)
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
    let p2pManagerConnectScenarioMessage = ""
    let hotspotManagerScenarioArray: IWifiAutoArrayItem[] = [{
      name: "testSetDeviceNameManager",
      para: [ConfigData.P2P_DEMO_DEVICE_NAME]
    }]

    //拼装数组
    let Interface = P2pManagerConnectScenarioTestCase.map(i => {
      // 查找与条件匹配的元素，并且确保其不是undefined
      const foundItem = hotspotManagerScenarioArray.find(itm => itm.name === i.api.name);
      let para: string[] = foundItem ? foundItem.para: [];
      return { name: i.api.name, para} as IWifiAutoArrayItem
    })

    for(let m = 0 ; m<Interface.length ; m++){
      p2pManagerConnectScenarioMessage += P2pManagerConnectScenarioTestCase[m].api(... Interface[m].para) + "\n"
      this.changeIndex = m
      await sleep(1)
      AppStorage.setOrCreate("p2pManagerConnectScenarioMessage", p2pManagerConnectScenarioMessage)
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