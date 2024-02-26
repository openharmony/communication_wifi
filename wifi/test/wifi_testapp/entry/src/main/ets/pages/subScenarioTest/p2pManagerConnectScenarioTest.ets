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
  P2pManagerConnectScenarioTestCase ,
  initP2pManagerConnectScenarioData
} from '../../entryability/model/scenarioTestDataModels'
import * as P2pManagerInterface from '../../entryability/model/p2pManagerInterface'
import ConfigData from '../../utils/ConfigData';

interface myParams extends Object {
  testItem: TestData
}

interface IWifiAutoArrayItem {
  name: string;
  para: string[]; // 替换any[]为实际参数类型
}

/**
 * p2pManager Connect Scenario Test Page Of WiFi test
 */
@Entry
@Component
struct p2pManagerConnectScenarioTest {
  @State message: string = 'p2pManagerConnectScenarioTest';
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State changeIndex: number = - 1
  @StorageLink("p2pManagerConnectScenarioMessage") p2pManagerConnectScenarioMessage: string = ""
  @State deviceAddressManager: string = '6c:96:d7:3d:87:6f';
  @State netIdManager: number = - 2;
  @State passphraseManager: string = "12345678";
  @State groupNameManager: string = "testGroup"
  @State goBandManager: number = 0;
  @State devNameManager: string = "MyTestDevice"

  aboutToAppear() {
    AppStorage.setOrCreate("deviceAddressManager" , this.deviceAddressManager)
    AppStorage.setOrCreate("netIdManager" , this.netIdManager)
    AppStorage.setOrCreate("passphraseManager" , this.passphraseManager)
    AppStorage.setOrCreate("groupNameManager" , this.groupNameManager)
    AppStorage.setOrCreate("goBandManager" , this.goBandManager)
    AppStorage.setOrCreate("devNameManager" , this.devNameManager)
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
              scenarioItems : initP2pManagerConnectScenarioData() ,
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
                Text(this.p2pManagerConnectScenarioMessage)
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
            prompt.showToast({ message : '开始p2p连接场景测试' })
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
            let p2pManagerConnectScenarioMessage = ""
            // 停止发现设备
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testStopDiscoverP2pDevicesManager() + "\n"
            console.log("testStopDiscoverP2pDevicesManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage" , p2pManagerConnectScenarioMessage)

            //取消P2P连接
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testP2pCancelConnectManager() + "\n"
            console.log("testP2pCancelConnectManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage" , p2pManagerConnectScenarioMessage)

            //移除群组
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testRemoveP2pGroupManager() + "\n"
            console.log("testRemoveP2pGroupManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage" , p2pManagerConnectScenarioMessage)

            //删除永久组
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testDeletePersistentP2pGroupManager() + "\n"
            console.log("testDeletePersistentP2pGroupManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage" , p2pManagerConnectScenarioMessage)

            //关闭P2P开关状态改变事件
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testOnP2pStateChangeManager() + "\n"
            console.log("testOffP2pStateChangeManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage" , p2pManagerConnectScenarioMessage)

            //关闭P2P连接状态改变事件
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testOnP2pConnectionChangeManager() + "\n"
            console.log("testOffP2pConnectionChangeManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage" , p2pManagerConnectScenarioMessage)

            //关闭P2P设备状态改变事件
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testOnP2pDeviceChangeManager() + "\n"
            console.log("testOffP2pDeviceChangeManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage" , p2pManagerConnectScenarioMessage)

            //关闭P2P对端设备状态改变事件
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testOnP2pPeerDeviceChangeManager() + "\n"
            console.log("testOffP2pPeerDeviceChangeManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage" , p2pManagerConnectScenarioMessage)

            //关闭P2P永久组状态改变事件
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testOnP2pPersistentGroupChangeManager() + "\n"
            console.log("testOffP2pPersistentGroupChangeManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage" , p2pManagerConnectScenarioMessage)

            //关闭发现设备状态改变事件
            p2pManagerConnectScenarioMessage += P2pManagerInterface.testOnP2pDiscoveryChangeManager() + "\n"
            console.log("testOffP2pDiscoveryChangeManager success")
            await sleep(1)
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage" , p2pManagerConnectScenarioMessage)
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
            let p2pManagerConnectScenarioMessage = ""
            AppStorage.setOrCreate("p2pManagerConnectScenarioMessage" , p2pManagerConnectScenarioMessage)
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
    let hotspotManagerScenarioArray: IWifiAutoArrayItem[] = [ {
      name : "testSetDeviceNameManager" ,
      para : [ "MyTestDevice" ]
    } ]

    //拼装数组
    let Interface = P2pManagerConnectScenarioTestCase.map(i => {
      // 查找与条件匹配的元素，并且确保其不是undefined
      const foundItem = hotspotManagerScenarioArray.find(itm => itm.name === i.api.name);
      let para: string[] = foundItem ? foundItem.para : [];
      return { name : i.api.name , para } as IWifiAutoArrayItem
    })

    for ( let m = 0 ; m < Interface.length ; m ++ ) {
      p2pManagerConnectScenarioMessage += P2pManagerConnectScenarioTestCase[ m ].api(... Interface[ m ].para) + "\n"
      this.changeIndex = m
      await sleep(1)
      AppStorage.setOrCreate("p2pManagerConnectScenarioMessage" , p2pManagerConnectScenarioMessage)
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