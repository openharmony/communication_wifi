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

import ConfigData from '../../utils/ConfigData';
import prompt from '@system.prompt';
import router from '@ohos.router';
import { PageTitle } from '../../Component/pageTitle';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { TestData } from '../../entryability/model/testData'
import { ScenarioContentTable } from '../../Component/scenarioContentTable'
import {
  P2pConnectScenarioTestCase ,
  initP2pConnectScenarioData
} from '../../entryability/model/scenarioTestDataModels'
import * as P2pInterface from '../../entryability/model/p2pInterface'

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
  @State message: string = 'p2pConnectScenarioTest';
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State changeIndex: number = - 1
  @StorageLink("p2pConnectScenarioMessage") p2pConnectScenarioMessage: string = ""
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
              scenarioItems : initP2pConnectScenarioData() ,
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
                Text(this.p2pConnectScenarioMessage)
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
          .width(ConfigData.value_100)
          .height(66)
          .margin({ top : "15vp" , left : "10vp" , right : "10vp" })
          .align(Alignment.Start)
          .onClick(async(event: ClickEvent) => {
            let p2pConnectScenarioMessage = ""
            // 停止发现设备
            p2pConnectScenarioMessage += P2pInterface.testStopDiscoverDevices() + "\n"
            console.log("testStopDiscoverDevices success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage" , p2pConnectScenarioMessage)

            //取消P2P连接
            p2pConnectScenarioMessage += P2pInterface.testP2pCancelConnect() + "\n"
            console.log("testP2pCancelConnect success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage" , p2pConnectScenarioMessage)

            //移除群组
            p2pConnectScenarioMessage += P2pInterface.testRemoveGroup() + "\n"
            console.log("testRemoveGroup success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage" , p2pConnectScenarioMessage)

            //删除永久组
            p2pConnectScenarioMessage += P2pInterface.testDeletePersistentGroup() + "\n"
            console.log("testDeletePersistentGroup success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage" , p2pConnectScenarioMessage)

            //关闭P2P开关状态改变事件
            p2pConnectScenarioMessage += P2pInterface.testOnP2pStateChange() + "\n"
            console.log("testOffP2pStateChange success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage" , p2pConnectScenarioMessage)

            //关闭P2P连接状态改变事件
            p2pConnectScenarioMessage += P2pInterface.testOnP2pConnectionChange() + "\n"
            console.log("testOffP2pConnectionChange success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage" , p2pConnectScenarioMessage)

            //关闭P2P设备状态改变事件
            p2pConnectScenarioMessage += P2pInterface.testOnP2pDeviceChange() + "\n"
            console.log("testOffP2pDeviceChange success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage" , p2pConnectScenarioMessage)

            //关闭P2P对端设备状态改变事件
            p2pConnectScenarioMessage += P2pInterface.testOnP2pPeerDeviceChange() + "\n"
            console.log("testOffP2pPeerDeviceChange success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage" , p2pConnectScenarioMessage)

            //关闭P2P永久组状态改变事件
            p2pConnectScenarioMessage += P2pInterface.testOnP2pPersistentGroupChange() + "\n"
            console.log("testOffP2pPersistentGroupChange success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage" , p2pConnectScenarioMessage)

            //关闭发现设备状态改变事件
            p2pConnectScenarioMessage += P2pInterface.testOnP2pDiscoveryChange() + "\n"
            console.log("testOffP2pDiscoveryChange success")
            await sleep(1)
            AppStorage.setOrCreate("p2pConnectScenarioMessage" , p2pConnectScenarioMessage)
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
            let p2pConnectScenarioMessage = ""
            AppStorage.setOrCreate("p2pConnectScenarioMessage" , p2pConnectScenarioMessage)
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
    let hotspotScenarioArray: IWifiAutoArrayItem[] = [ { name : "testSetDeviceName" , para : [ "MyTestDevice" ] } ]

    //拼装数组
    let Interface = P2pConnectScenarioTestCase.map(i => {
      // 查找与条件匹配的元素，并且确保其不是undefined
      const foundItem = hotspotScenarioArray.find(itm => itm.name === i.api.name);
      let para: string[] = foundItem ? foundItem.para : [];
      return { name : i.api.name , para } as IWifiAutoArrayItem;
    })
    for ( let m = 0 ; m < Interface.length ; m ++ ) {
      p2pConnectScenarioMessage += P2pConnectScenarioTestCase[ m ].api(... Interface[ m ].para) + "\n"
      this.changeIndex = m
      await sleep(1)
      AppStorage.setOrCreate("p2pConnectScenarioMessage" , p2pConnectScenarioMessage)
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