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
  HotspotCreateScenarioTestCase ,
  initHotspotCreateScenarioData
} from '../../entryability/model/scenarioTestDataModels'
import * as HotspotInterface from '../../entryability/model/hotspotInterface'
import ConfigData from '../../utils/ConfigData';
/**
 * hotspot Create Scenario Test Page Of WiFi test
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
struct hotspotCreateScenarioTest {
  @State message: string = 'hotspotCreateScenarioTest';
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State changeIndex: number = - 1
  @StorageLink("hotspotCreateScenarioMessage") hotspotCreateScenarioMessage: string = ""
  @State h_ssid: string = "testApp1";
  @State h_securityType: number = 3;
  @State h_band: number = 2;
  @State h_preSharedKey: string = "12345678";
  @State h_maxConn: number = 3;
  @State h_channel: number = 36;

  aboutToAppear() {
    AppStorage.setOrCreate("h_ssid" , this.h_ssid)
    AppStorage.setOrCreate("h_securityType" , this.h_securityType)
    AppStorage.setOrCreate("h_band" , this.h_band)
    AppStorage.setOrCreate("h_preSharedKey" , this.h_preSharedKey)
    AppStorage.setOrCreate("h_maxConn" , this.h_maxConn)
    AppStorage.setOrCreate("h_channel" , this.h_channel)
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
              scenarioItems : initHotspotCreateScenarioData() ,
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
                Text(this.hotspotCreateScenarioMessage)
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
            Row() {
              Text('场景测试开始').fontSize("24vp").fontColor(0xffffff).margin({ left : 5 , right : 5 })
            }.alignItems(VerticalAlign.Center)
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
            let hotspotCreateScenarioMessage = ""
            // 关闭热点状态改变事件
            hotspotCreateScenarioMessage += HotspotInterface.testOnHotspotStateChange() + "\n"
            console.log("testOnHotspotStateChange success")
            AppStorage.setOrCreate("hotspotCreateScenarioMessage" , hotspotCreateScenarioMessage)
            await sleep(1)

            //去使能热点
            hotspotCreateScenarioMessage += HotspotInterface.testDisableHotspot() + "\n"
            console.log("testDisableHotspot success")
            AppStorage.setOrCreate("hotspotCreateScenarioMessage" , hotspotCreateScenarioMessage)
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
            let hotspotCreateScenarioMessage = ""
            AppStorage.setOrCreate("hotspotCreateScenarioMessage" , hotspotCreateScenarioMessage)
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
    let hotspotCreateScenarioMessage = ""
    let hotspotScenarioArray: IWifiAutoArrayItem[] = []
    //拼装数组
    let Interface = HotspotCreateScenarioTestCase.map(i => {
      // 查找与条件匹配的元素，并且确保其不是undefined
      const foundItem = hotspotScenarioArray.find(itm => itm.name === i.api.name);
      let para: string[] = foundItem ? foundItem.para : [];
      return { name : i.api.name , para } as IWifiAutoArrayItem;
    })

    for ( let m = 0 ; m < Interface.length ; m ++ ) {
      hotspotCreateScenarioMessage += HotspotCreateScenarioTestCase[ m ].api(... Interface[ m ].para) + "\n"
      this.changeIndex = m
      await sleep(1)
      AppStorage.setOrCreate("hotspotCreateScenarioMessage" , hotspotCreateScenarioMessage)
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