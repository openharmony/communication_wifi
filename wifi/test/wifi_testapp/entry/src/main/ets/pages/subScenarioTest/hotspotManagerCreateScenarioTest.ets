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
  HotspotManagerCreateScenarioTestCase ,
  initHotspotManagerCreateScenarioData
} from '../../entryability/model/scenarioTestDataModels'
import * as HotspotManagerInterface from '../../entryability/model/hotspotManagerInterface'
import ConfigData from '../../utils/ConfigData';
/**
 * hotspotManager Create Scenario Test Page Of WiFi test
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
struct hotspotManagerCreateScenarioTest {
  @State message: string = 'hotspotManagerCreateScenarioTest';
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State changeIndex: number = - 1
  @StorageLink("hotspotManagerCreateScenarioMessage") hotspotManagerCreateScenarioMessage: string = ""
  @State h_ssid1: string = "testApp1";
  @State h_securityType1: number = 3;
  @State h_band1: number = 2;
  @State h_preSharedKey1: string = "12345678";
  @State h_maxConn1: number = 3;
  @State h_channel1: number = 36;

  aboutToAppear() {
    AppStorage.setOrCreate("h_ssid1" , this.h_ssid1)
    AppStorage.setOrCreate("h_securityType1" , this.h_securityType1)
    AppStorage.setOrCreate("h_band1" , this.h_band1)
    AppStorage.setOrCreate("h_preSharedKey1" , this.h_preSharedKey1)
    AppStorage.setOrCreate("h_maxConn1" , this.h_maxConn1)
    AppStorage.setOrCreate("h_channel1" , this.h_channel1)
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
              scenarioItems : initHotspotManagerCreateScenarioData() ,
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
                Text(this.hotspotManagerCreateScenarioMessage)
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
            prompt.showToast({ message : '开始热点创建场景测试' })
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
            let hotspotManagerCreateScenarioMessage = ""
            // 关闭热点状态改变事件
            hotspotManagerCreateScenarioMessage += HotspotManagerInterface.testOnHotspotStateChangeManager() + "\n"
            console.log("testStopBluetoothDiscovery success")
            AppStorage.setOrCreate("hotspotManagerCreateScenarioMessage" , hotspotManagerCreateScenarioMessage)
            await sleep(1)

            //去使能热点
            hotspotManagerCreateScenarioMessage += HotspotManagerInterface.testDisableHotspotManager() + "\n"
            console.log("testOffStateChange success")
            AppStorage.setOrCreate("hotspotManagerCreateScenarioMessage" , hotspotManagerCreateScenarioMessage)
            await sleep(1)

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
            let hotspotManagerCreateScenarioMessage = ""
            AppStorage.setOrCreate("hotspotManagerCreateScenarioMessage" , hotspotManagerCreateScenarioMessage)
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
    let hotspotManagerCreateScenarioMessage = ""
    let hotspotManagerScenarioArray: IWifiAutoArrayItem[] = []

    //拼装数组
    let Interface = HotspotManagerCreateScenarioTestCase.map(i => {
      // 查找与条件匹配的元素，并且确保其不是undefined
      const foundItem = hotspotManagerScenarioArray.find(itm => itm.name === i.api.name);
      let para: string[] = foundItem ? foundItem.para : [];
      return { name : i.api.name , para } as IWifiAutoArrayItem;
    })
    for ( let m = 0 ; m < Interface.length ; m ++ ) {
      hotspotManagerCreateScenarioMessage += HotspotManagerCreateScenarioTestCase[ m ].api(... Interface[ m ].para) + "\n"
      this.changeIndex = m
      await sleep(1)
      AppStorage.setOrCreate("hotspotManagerCreateScenarioMessage" , hotspotManagerCreateScenarioMessage)
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