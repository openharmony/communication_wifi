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
import ConfigData from '../../Utils/ConfigData';
import promptAction from '@ohos.promptAction';
import router from '@ohos.router';
import { PageTitle} from '../../Component/pageTitle';
import { TestImageDisplay} from '../../Component/testImageDisplay';
import { TestData} from '../../entryability/model/testData';
import { ScenarioContentTable} from '../../Component/scenarioContentTable';
import {
  P2pConnectScenarioTestCase,
  initP2pConnectScenarioData
} from '../../entryability/model/scenarioTestDataModels'
import * as P2pInterface from '../../entryability/model/p2pInterface';

/**
 * Classic p2p Connect Scenario Test Page Of WiFi test
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
struct p2pConnectScenarioTest {
  @State message: string = ConfigData.TAG_MSG_P2P_CONN;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State changeIndex: number = ConfigData.ITEM_CLICK_NONE
  @StorageLink("p2pConnectScenarioMessage") p2pConnectScenarioMessage: string = ""
  @State deviceAddress: string = ConfigData.P2P_DEMO_ADDRESS;
  @State netId: number = ConfigData.P2P_DEMO_NET_ID;
  @State passphrase: string = ConfigData.QV_MOCK_PRE_SHARED_KEY;
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
              scenarioItems: initP2pConnectScenarioData(),
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
                Text(this.p2pConnectScenarioMessage)
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
          .width(ConfigData.value_100)
          .height(ConfigData.VP_66)
          .margin({top: ConfigData.VP_15, left: ConfigData.VP_10, right: ConfigData.VP_10})
          .align(Alignment.Start)
          .onClick(async(event: ClickEvent) => {
            let p2pConnectScenarioMessage = ""
            // 停止发现设备
            p2pConnectScenarioMessage += P2pInterface.testStopDiscoverDevices() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testStopDiscoverDevices success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage", p2pConnectScenarioMessage)

            //取消P2P连接
            p2pConnectScenarioMessage += P2pInterface.testP2pCancelConnect() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testP2pCancelConnect success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage", p2pConnectScenarioMessage)

            //移除群组
            p2pConnectScenarioMessage += P2pInterface.testRemoveGroup() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testRemoveGroup success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage", p2pConnectScenarioMessage)

            //删除永久组
            p2pConnectScenarioMessage += P2pInterface.testDeletePersistentGroup() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testDeletePersistentGroup success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage", p2pConnectScenarioMessage)

            //关闭P2P开关状态改变事件
            p2pConnectScenarioMessage += P2pInterface.testOnP2pStateChange() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffP2pStateChange success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage", p2pConnectScenarioMessage)

            //关闭P2P连接状态改变事件
            p2pConnectScenarioMessage += P2pInterface.testOnP2pConnectionChange() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffP2pConnectionChange success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage", p2pConnectScenarioMessage)

            //关闭P2P设备状态改变事件
            p2pConnectScenarioMessage += P2pInterface.testOnP2pDeviceChange() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffP2pDeviceChange success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage", p2pConnectScenarioMessage)

            //关闭P2P对端设备状态改变事件
            p2pConnectScenarioMessage += P2pInterface.testOnP2pPeerDeviceChange() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffP2pPeerDeviceChange success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage", p2pConnectScenarioMessage)

            //关闭P2P永久组状态改变事件
            p2pConnectScenarioMessage += P2pInterface.testOnP2pPersistentGroupChange() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffP2pPersistentGroupChange success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage", p2pConnectScenarioMessage)

            //关闭发现设备状态改变事件
            p2pConnectScenarioMessage += P2pInterface.testOnP2pDiscoveryChange() + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', "testOffP2pDiscoveryChange success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage", p2pConnectScenarioMessage)
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
            let p2pConnectScenarioMessage = ""
            AppStorage.setOrCreate("p2pConnectScenarioMessage", p2pConnectScenarioMessage)
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
    let p2pConnectScenarioMessage = ""
    let hotspotScenarioArray: IWifiAutoArrayItem[] = [{ name: "testSetDeviceName", para: [ConfigData.P2P_DEMO_DEVICE_NAME]}]

    //拼装数组
    let Interface = P2pConnectScenarioTestCase.map(i => {
      // 查找与条件匹配的元素，并且确保其不是undefined
      const foundItem = hotspotScenarioArray.find(itm => itm.name === i.api.name);
      let para: string[] = foundItem ? foundItem.para: [];
      return { name: i.api.name, para} as IWifiAutoArrayItem;
    })
    for(let m = 0 ; m<Interface.length ; m++){
      p2pConnectScenarioMessage += P2pConnectScenarioTestCase[m].api(... Interface[m].para) + "\n"
      this.changeIndex = m
      await sleep(1)
      AppStorage.setOrCreate("p2pConnectScenarioMessage", p2pConnectScenarioMessage)
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