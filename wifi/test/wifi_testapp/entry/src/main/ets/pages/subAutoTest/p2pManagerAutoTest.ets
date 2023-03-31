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

// @ts-nocheck
import ConfigData from '../../Utils/ConfigData';
import router from '@system.router';
import { TestData } from '../../MainAbility/model/testData'
import { PageTitle } from '../../Component/pageTitle';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { P2pManagerAutoTestCase , initP2pManagerAutoData} from '../../MainAbility/model/autoTestDataModels'
import { AutoContentTable } from '../../Component/autoContentTable'

import * as P2pManagerInterface from '../../MainAbility/model/p2pManagerInterface'
import prompt from '@system.prompt';
import emitter from '@ohos.events.emitter'

/**
 *  wifiAutoTest Page Of wifi test
 */
@Entry
@Component
struct P2pManagerAutoTest {
  @State message: string = 'P2pManagerAutoTest';
  //  @State textMessage: string = 'null';
  //  @State testState: boolean = false;
  private testItem: TestData = router.getParams().testId;
  @State changeIndex:number = -1
  //  @State autoTextMessage: string ="None";
  @StorageLink ("p2pManagerAutoTestMessage") p2pManagerAutoTestMessage:string =""

  build() {
    Column() {
      Stack({ alignContent: Alignment.TopStart }) {
        TestImageDisplay({ testItem: this.testItem })
        PageTitle({ testItem: this.testItem })
      }
      Stack().height("1vp").backgroundColor("#000000");
      Column() {
        Scroll() {
          Column() {
            Text("API验证:")
              .fontSize("17vp")
              .margin({ top: "10vp", bottom:"10vp",left: "15vp" })
              .textAlign(TextAlign.Start)
              .width("100%")
            AutoContentTable({
              testItem: this.testItem,
              autoItems: initP2pManagerAutoData(),
              //             testMessage: this.testMessage,  优化时修改
              changeIndex:this.changeIndex
            })
          }
          .width("100%")
          .height(280)
        }
        .scrollBarWidth(10)
        .scrollBar(BarState.Auto)

        Stack().height("1vp").backgroundColor("#000000");

        Scroll() {
          Column() {
            Text("Debug日志:")
              .fontSize("17vp")
              .margin({ top: "8vp", bottom: "8vp", left: "15vp" })
              .textAlign(TextAlign.Start)
              .width("100%")
            List(){
              ListItem(){
                Text("log:" + "\n"  + this.p2pManagerAutoTestMessage)
                  .fontSize("17vp")
                  .margin({ top: "5vp", left: "30vp", right: "10vp" })
                  .textAlign(TextAlign.Start)
                  .width("90%")
              }
            }
            .height("80%")
            .width("90%")
            .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))
          }
          .width("100%")
          .height(260)
        }
        .scrollBarWidth(10)
        .scrollBar(BarState.On)
      }
      .height(500)
      .width("100%")
      .backgroundColor($r("sys.color.ohos_id_color_sub_background"))


      Stack().height("1vp").backgroundColor("#000000");
      Column() {
        Button({ type: ButtonType.Normal, stateEffect: true }) {
          Row() {
            Text('自动测试').fontSize("24vp").fontColor(0xffffff).margin({ left: 5, right: 5 })
          }.alignItems(VerticalAlign.Center)
        }
        .borderRadius(8)
        .backgroundColor($r("app.color.blue"))
        .width(180)
        .height(50)
        .margin({ top: "15vp"})
        .onClick(async(event: ClickEvent) => {
          let self = this
          let p2pManagerAutoTestMessage =""

          //拼装数组
          let p2pManagerAutoArray=[{name:"testSetLocalName",para:["DaYuBlue"]},
                           {name:"testSetBluetoothScanMode",para:[4,0]}]
          let Interface = P2pAutoTestCase.map(i=>{
            let para = p2pAutoArray.some(itm=>itm.name===i.api.name)?p2pAutoArray.find(itm=>itm.name===i.api.name).para:[]
            return {name:i.api.name,para}
          })

          //循环调用
          async function forLoop() {
            for (let m=0 ; m<Interface.length ; m++){
              p2pManagerAutoTestMessage += P2pAutoTestCase[m]["api"](...Interface[m].para) + "\n"
              self.changeIndex=m
              await sleep(1)
              AppStorage.SetOrCreate("p2pManagerAutoTestMessage", p2pManagerAutoTestMessage)
            }
          }
          forLoop()

          let msg = ""
          msg = "测试"
          console.log(msg)
          prompt.showToast({ message: msg })
        })
      }
      .backgroundColor($r("sys.color.ohos_id_color_sub_background"))
      .width(ConfigData.WH_100_100)
      .height(ConfigData.WH_100_100);
    }
  }
}

function sleep(time) {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      resolve()
    }, time * 1000)
  })
}