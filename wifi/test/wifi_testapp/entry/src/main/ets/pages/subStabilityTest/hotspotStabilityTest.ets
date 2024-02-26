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

import { PageTitle } from '../../Component/pageTitle';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import router from '@ohos.router';
import ConfigData from '../../Utils/ConfigData';
import { TestData } from '../../entryability/model/testData'
import wifi from '@ohos.wifi';
import wifiManager from '@ohos.wifiManager';
import prompt from '@system.prompt';

interface myParams extends Object {
  testItem: TestData
}

/**
 * WiFiSwitchStabilityTest Page Of wifi test
 */
const TAG = '[HotspotStabilityTest]'

@Entry
@Component
struct HotspotStabilityTest {
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State open_StartTime: number = 0
  @State open_EndTime: number = 0
  @State open_SpendTime: number = 0
  @State close_StartTime: number = 0
  @State close_EndTime: number = 0
  @State close_SpendTime: number = 0
  @State openHotspotNumber: number = 0 // 打开Hotspot的次数
  @State closeHotspotNumber: number = 0 // 关闭Hotspot的次数
  @State openSuccessNumber: number = 0 // 打开Hotspot的成功次数
  @State openFailNumber: number = 0 // 打开Hotspot的失败次数
  @State closeSuccessNumber: number = 0 // 关闭Hotspot的成功次数
  @State closeFailNumber: number = 0 // 关闭Hotspot的失败次数

  @State message: string = "测试结果:"
  @State testNumbers: number = 30 //测试次数
  @State successTimes: number = 0
  @State failTimes: number = 0
  @State hotspotMessage: string = ""
  @State hotspotMessageLog: string = ""
  @State hotspotLoopState: Boolean = true

  build() {
    Column() {
      Stack({ alignContent : Alignment.TopStart }) {
        TestImageDisplay({ testItem : this.testItem })
        PageTitle({ testItem : this.testItem })
      }

      Stack().height("1vp").backgroundColor($r("app.color.black"));

      Column() {
        Row() {
          Text("测试次数：").fontSize($r('app.float.font_18')).width(ConfigData.WH_25_100).padding({ left : "10vp" })
          TextInput({ placeholder : "请输入循环次数，默认为：30" })
            .placeholderColor(Color.Grey)
            .placeholderFont({ size : $r('app.float.font_16') })
            .caretColor(Color.Blue)
            .width(ConfigData.WH_70_100)
            .fontSize($r('app.float.font_16'))
            .fontColor($r('app.color.title_black_color'))
            .onChange((value: string) => {
              this.testNumbers = parseInt(value);
            })
        }

        Column() {
          Text("测试结果：")
            .fontSize("22vp")
            .width(ConfigData.WH_95_100)
            .align(Alignment.TopStart)
            .padding({ top : "10vp" })
          Scroll() {
            Column() {
              Text("测试次数：" + this.testNumbers)
                .fontSize("18vp")
                .margin({ top : "5vp" , left : "10vp" , right : "5vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("打开热点的成功次数：" + this.openSuccessNumber)
                .fontSize("18vp")
                .margin({ top : "5vp" , left : "10vp" , right : "5vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("打开热点的失败次数：" + this.openFailNumber)
                .fontSize("18vp")
                .margin({ top : "5vp" , left : "10vp" , right : "5vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("关闭热点的成功次数：" + this.closeSuccessNumber)
                .fontSize("18vp")
                .margin({ top : "5vp" , left : "10vp" , right : "5vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("关闭热点的失败次数：" + this.closeFailNumber)
                .fontSize("18vp")
                .margin({ top : "5vp" , left : "10vp" , right : "5vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
            }
            .width(ConfigData.WH_95_100)
            .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))
          }
          .scrollBarWidth(10)
          .scrollBar(BarState.Auto)
        }.width(ConfigData.WH_100_100).height(ConfigData.WH_30_100)

        Column() {
          Text("log显示：")
            .fontSize("22vp")
            .height(ConfigData.WH_15_100)
            .width(ConfigData.WH_95_100)
            .align(Alignment.TopStart)
            .padding({ top : "18vp" })
          List() {
            ListItem() {
              Text(this.hotspotMessageLog)
                .fontSize("18vp")
                .margin({ top : "5vp" , left : "20vp" , right : "5vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
            }
          }
          .height(ConfigData.WH_83_100)
          .width(ConfigData.WH_95_100)
          .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))
        }.width(ConfigData.WH_100_100).height(ConfigData.WH_60_100)

      }.width(ConfigData.WH_100_100).height(ConfigData.WH_67_100).backgroundColor($r("app.color.lead"))

      Stack().height("1vp").backgroundColor($r("app.color.black"));

      Column() {
        Row() {
          Button("开始热点测试")
            .operateButtonStyle($r('app.color.main_blue'))
            .padding({ right : "10vp" })
            .onClick(async(event: ClickEvent) => {
              console.log(TAG , "start HotspotSwitch test-------------")
              await this.forLoop()
            })

          Blank().width(ConfigData.WH_10_100)

          Button("关闭热点测试")
            .operateButtonStyle($r('app.color.main_blue'))
            .padding({ right : "10vp" })
            .onClick(async(event: ClickEvent) => {
              this.hotspotLoopState = false
              console.log(TAG , "准备测试停止 -------------")
              this.hotspotMessageLog = ""
              this.openHotspotNumber = 0
            })
        }
      }.width(ConfigData.WH_100_100).height(ConfigData.WH_25_100).backgroundColor($r("app.color.lead"))
    }.height(ConfigData.WH_100_100).width(ConfigData.WH_100_100).backgroundColor($r("app.color.lead"))
  }

  onHotspotStateChange() {
    console.log(TAG , "on.hotspotStateChange start--------")
    wifi.on("hotspotStateChange" , (number) => {
      console.log(TAG , " on.hotspotStateChange --------")
      let hotspotStateMessage = ""
      switch ( number ) {
        case 0:
          hotspotStateMessage = "inactive";
          break;
        case 1:
          hotspotStateMessage = "active";
          break;
        case 2:
          hotspotStateMessage = "activating";
          break;
        case 3:
          hotspotStateMessage = "de-activating";
          break;
        default:
          hotspotStateMessage = '未知状态';
          break;
      }
      console.log(TAG , "热点开关状态为:" + hotspotStateMessage)
      if ( number == 1 ) {
        // 打时间戳
        this.open_EndTime = new Date().getTime()
        console.log(TAG , "热点使能结束时间: " + this.open_EndTime + "ms")
      } else if ( number == 0 ) {
        this.close_EndTime = new Date().getTime()
        console.log(TAG , "热点去使能结束时间: " + this.close_EndTime + "ms")
      }
      console.log(TAG , " on.hotspotStateChange callback success --------")
      prompt.showToast({ message : "热点状态: " + hotspotStateMessage })
      this.hotspotMessage = hotspotStateMessage
      AppStorage.setOrCreate("hotspotMessage" , this.hotspotMessage)
      console.log(TAG , " on.hotspotStateChange callback end--------")
      return this.hotspotMessage
    })
    return this.hotspotMessage
  }

  aboutToDisappear() {
    wifi.off("hotspotStateChange")
  }

  async forLoop() {
    this.hotspotLoopState = true
    this.openHotspotNumber = 0
    this.closeHotspotNumber = 0
    this.openSuccessNumber = 0
    this.openFailNumber = 0
    this.closeSuccessNumber = 0
    this.closeFailNumber = 0

    this.hotspotMessageLog = ""
    this.onHotspotStateChange() // 监听函数
    let funcMessage = false // 函数信息
    for ( this.openHotspotNumber ; this.openHotspotNumber < this.testNumbers ; this.openHotspotNumber ++ ) {
      if ( !this.hotspotLoopState ) {
        console.log(TAG , "测试结束------------")
        break;
      } else {
        let wifiState = wifiManager.isWifiActive()
        if ( wifiState ) {
          wifi.disableWifi()
          console.log(TAG , "wifi当前已使能，已经去使能，正常开始测试------")
        } else {
          console.log(TAG , "wifi当前未使能，正常开始测试------")
        }
        await sleep(3)

        funcMessage = wifi.enableHotspot()
        // 打时间戳
        this.open_StartTime = new Date().getTime()
        console.log(TAG , "第" + (this.openHotspotNumber + 1) + "次热点使能-----")
        console.log(TAG , "第" + (this.openHotspotNumber + 1) + "次热点使能开始时间: " + this.open_StartTime + "ms")
        this.hotspotMessageLog += "第" + (this.openHotspotNumber + 1) + "次热点使能结果：" + funcMessage + "\n"
        console.log(TAG , "第" + (this.openHotspotNumber + 1) + "次热点使能结果：" + funcMessage)
        await sleep(10)
        this.hotspotMessage = AppStorage.get("hotspotMessage") ! //非空断言操作符
        // prompt.showToast( { message : funcMessage } )
        if ( this.hotspotMessage == "active" ) {
          this.open_SpendTime = this.open_EndTime - this.open_StartTime
          this.hotspotMessageLog += "第" + (this.openHotspotNumber + 1) + "次热点使能耗时: " + this.open_SpendTime + "ms" + "\n"
          console.log(TAG , "第" + (this.openHotspotNumber + 1) + "次热点使能耗时: " + this.open_SpendTime + "ms")
          this.openSuccessNumber = this.openSuccessNumber + 1
          this.hotspotMessageLog += "热点使能成功的次数：" + this.openSuccessNumber + "\n"
          console.log(TAG , "热点使能成功的次数：" + this.openSuccessNumber)
          funcMessage = wifi.disableHotspot()
          this.closeHotspotNumber = this.closeHotspotNumber + 1
          this.close_StartTime = new Date().getTime()
          console.log(TAG , "第" + this.closeHotspotNumber + "次热点去使能-----")
          console.log(TAG , "第" + this.closeHotspotNumber + "次热点去使能开始时间: " + this.close_StartTime + "ms")
          this.hotspotMessageLog += "第" + this.closeHotspotNumber + "次热点去使能结果：" + funcMessage + "\n"
          console.log(TAG , "第" + this.closeHotspotNumber + "次热点去使能结果：" + funcMessage)
          console.log(TAG , "closeHotspotNumber: " + this.closeHotspotNumber)
          await sleep(10)
          this.hotspotMessage = AppStorage.get("hotspotMessage") ! //非空断言操作符
          if ( this.hotspotMessage == "inactive" ) {
            this.close_SpendTime = this.close_EndTime - this.close_StartTime
            this.hotspotMessageLog += "第" + this.closeHotspotNumber + "次热点去使能耗时: " + this.close_SpendTime + "ms" + "\n"
            console.log(TAG , "第" + this.closeHotspotNumber + "次热点去使能耗时: " + this.close_SpendTime + "ms")
            this.closeSuccessNumber = this.closeSuccessNumber + 1
            this.hotspotMessageLog += "热点去使能成功的次数：" + this.closeSuccessNumber + "\n"
            console.log(TAG , "热点去使能成功的次数：" + this.closeSuccessNumber)
            await sleep(7)
          } else {
            this.closeFailNumber = this.closeFailNumber + 1
            console.log(TAG , "热点去使能失败的次数：" + this.closeFailNumber)
            console.log(TAG , "第" + this.closeHotspotNumber + "次热点去使能失败")
          }
        } else if ( this.hotspotMessage == "inactive" ) {
          this.openFailNumber = this.openFailNumber + 1
          console.log(TAG , "热点使能失败的次数：" + this.openFailNumber)
          console.log(TAG , "第" + (this.openHotspotNumber + 1) + "次热点使能失败")
          break;
        } else {
          console.log("第" + (this.openHotspotNumber + 1) + "次开热点后状态不清楚");
          break;
        }
      }
    }
    console.log(TAG , "测试结束 -------------")
  }
}

/**
 * Custom button style.
 */
@Extend(Button) function operateButtonStyle(color: Resource) {
  .width($r('app.float.button_width'))
  .height($r('app.float.button_height'))
  .fontSize($r('app.float.font_16'))
  .fontWeight(500)
  .fontColor(color)
  .backgroundColor($r('app.color.button_background'))
}

async function sleep(time: number): Promise<void> {
  return new Promise<void>((resolve , reject) => {
    setTimeout(() => {
      resolve();
    } , time * 1000);
  });
}