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
 * WiFiScanStabilityTest Page Of wifi test
 */
const TAG = '[wifiTest_WiFiScanStabilityTest]'

@Entry
@Component
struct WiFiScanStabilityTest {
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State scan_StartTime: number = 0
  @State scan_EndTime: number = 0
  @State scan_SpendTime: number = 0
  @State stop_StartTime: number = 0
  @State stop_EndTime: number = 0
  @State stop_SpendTime: number = 0
  @State openScanNumber: number = 0
  @State openScanSuccessNumber: number = 0
  @State openScanFailNumber: number = 0
  @State scanInfo: number = 0
  @State message: string = "测试结果"
  @State testNumbers: number = 30 //测试次数
  @State successTimes: number = 0
  @State failTimes: number = 0
  @State scanStateMessage: string = ""
  @State scanStateMessageLog: string = ""
  @State scanLoopState: Boolean = true

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
          TextInput({ placeholder : "请输入循环次数，默认30" })
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
              Text("scan的成功次数：" + this.openScanSuccessNumber)
                .fontSize("18vp")
                .margin({ top : "5vp" , left : "10vp" , right : "5vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("scan的失败次数：" + this.openScanFailNumber)
                .fontSize("18vp")
                .margin({ top : "5vp" , left : "10vp" , right : "5vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("scan的扫描个数：" + this.scanInfo)
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
            .padding({ top : "10vp" })
          List() {
            ListItem() {
              Text(this.scanStateMessageLog)
                .fontSize("18vp")
                .margin({ top : "5vp" , left : "10vp" , right : "5vp" })
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
          Button("开始扫描测试")
            .operateButtonStyle($r('app.color.main_blue'))
            .padding({ right : "10vp" })
            .onClick(async(event: ClickEvent) => {
              console.log(TAG , "start scan test-------------")
              await this.forLoop()
            })

          Blank().width(ConfigData.WH_10_100)

          Button("关闭扫描测试")
            .operateButtonStyle($r('app.color.main_blue'))
            .padding({ right : "10vp" })
            .onClick(async(event: ClickEvent) => {
              this.scanLoopState = false
              console.log(TAG , "准备测试停止 -------------")
              this.scanStateMessageLog = ""
              this.openScanNumber = 0
            })
        }
      }.width(ConfigData.WH_100_100).height(ConfigData.WH_25_100).backgroundColor($r("app.color.lead"))
    }.height(ConfigData.WH_100_100).width(ConfigData.WH_100_100).backgroundColor($r("app.color.lead"))
  }

  onWifiScanState() {
    console.log(TAG , "on.wifiScanStateChange start--------")
    wifi.on("wifiScanStateChange" , (number) => {
      console.log(TAG , " on.wifiScanStateChange success--------")
      let wifiScanStateMessage = ""
      switch ( number ) {
        case 0:
          wifiScanStateMessage = "scan fail";
          break;
        case 1:
          wifiScanStateMessage = "scan success";
          break;
        default:
          wifiScanStateMessage = '未知状态';
          break;
      }
      console.log(TAG , "WiFi扫描状态为:" + wifiScanStateMessage)
      if ( number == 1 ) {
        // 打时间戳
        this.scan_EndTime = new Date().getTime()
        console.log(TAG , "WIFI扫描成功时间: " + this.scan_EndTime + "ms")
        this.scanInfo = wifiManager.getScanResultsSync().length
        console.log(TAG , "WIFI扫描结果个数: " + this.scanInfo + "; WIFI扫描结果个数: " + JSON.stringify(wifiManager.getScanResultsSync()))
      } else {
        console.log(TAG , "WIFI扫描还未成功------")
      }
      console.log(TAG , " on.wifiScanStateChange  callback success --------")
      prompt.showToast({ message : "wifiScan状态: " + wifiScanStateMessage })
      this.scanStateMessage = wifiScanStateMessage
      AppStorage.setOrCreate("scanStateMessage" , this.scanStateMessage)
      console.log(TAG , " on.wifiStateChange callback end--------")
      return this.scanStateMessage
    })
  }

  aboutToDisappear() {
    wifi.off("wifiScanStateChange")
  }

  async forLoop() {
    this.scanLoopState = true
    this.openScanNumber = 0
    this.openScanSuccessNumber = 0
    this.openScanFailNumber = 0
    this.scanStateMessageLog = ""
    wifiManager.setScanAlwaysAllowed(false)
    let funcMessage = false
    funcMessage = wifiManager.getScanAlwaysAllowed()
    console.log(TAG , "getScanAlwaysAllowed:" + funcMessage)
    for ( this.openScanNumber ; this.openScanNumber < this.testNumbers ; this.openScanNumber ++ ) {
      if ( !this.scanLoopState ) {
        console.log(TAG , "测试结束------------")
        break;
      } else {
        let wifiState = wifiManager.isWifiActive()
        if ( !wifiState ) {
          wifi.enableWifi()
          console.log(TAG , "wifi当前未使能，已经使能，正常开始测试------")
        } else {
          console.log(TAG , "wifi当前使能，正常开始测试------")
        }
        this.onWifiScanState()
        await sleep(5)
        wifiManager.startScan()
        this.scan_StartTime = new Date().getTime()
        console.log(TAG , "第" + (this.openScanNumber + 1) + "次WIFI扫描-----")
        console.log(TAG , "第" + (this.openScanNumber + 1) + "次WIFI扫描开始时间: " + this.scan_StartTime + "ms")
        console.log(TAG , "第" + (this.openScanNumber + 1) + "次WIFI扫描接口的调用成功")
        await sleep(10)
        this.scanStateMessage = AppStorage.get("scanStateMessage") ! //非空断言操作符
        if ( this.scanStateMessage == "scan success" ) {
          this.scanStateMessageLog += "第" + (this.openScanNumber + 1) + "次WIFI扫描成功" + "\n"
          this.scan_SpendTime = this.scan_EndTime - this.scan_StartTime
          this.scanStateMessageLog += "第" + (this.openScanNumber + 1) + "次WIFI扫描耗时: " + this.scan_SpendTime + "ms" + "\n"
          this.scanStateMessageLog += "第" + (this.openScanNumber + 1) + "次WIFI扫描结果个数: " + this.scanInfo + "\n"
          console.log(TAG , "第" + (this.openScanNumber + 1) + "次WIFI扫描耗时: " + this.scan_SpendTime + "ms")
          this.openScanSuccessNumber = this.openScanSuccessNumber + 1
          this.scanStateMessageLog += "扫描成功的次数：" + this.openScanSuccessNumber + "\n"
          console.log(TAG , "扫描成功的次数：" + this.openScanSuccessNumber)
          await sleep(10)
          this.scanStateMessage = AppStorage.get("scanStateMessage") ! //非空断言操作符
        } else if ( this.scanStateMessage == "scan fail" ) {
          this.openScanFailNumber = this.openScanFailNumber + 1
          this.scanStateMessageLog += "第" + (this.openScanNumber + 1) + "次WIFI扫描失败" + "\n"
          console.log(TAG , "扫描失败的次数：" + this.openScanFailNumber)
          console.log(TAG , "第" + (this.openScanNumber + 1) + "次WIFI扫描失败")
          break;
        } else {
          this.scanStateMessageLog += "第" + (this.openScanNumber + 1) + "次WIFI扫描情况未知" + "\n"
          console.log(TAG ,"第" + (this.openScanNumber + 1) + "次扫描后状态不清楚");
          break;
        }
        wifi.off("wifiScanStateChange")
        console.log(TAG ,"off.wifiScanStateChange success--------");
        await sleep(5)
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