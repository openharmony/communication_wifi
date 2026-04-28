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
import { PageTitle} from '../../Component/pageTitle';
import { TestImageDisplay} from '../../Component/testImageDisplay';
import router from '@ohos.router';
import ConfigData from '../../Utils/ConfigData';
import { TestData} from '../../entryability/model/testData';
import wifi from '@ohos.wifi';
import wifiManager from '@ohos.wifiManager';
import promptAction from '@ohos.promptAction';
import common from '@ohos.app.ability.common';
import wantAgent, { WantAgent} from '@ohos.app.ability.wantAgent';
import ohosWantAgentInfo from '@ohos.wantAgent';
import backgroundTaskManager from '@ohos.resourceschedule.backgroundTaskManager';
import { BusinessError} from '@ohos.base';
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import notificationManager from '@ohos.notificationManager';

interface myParams extends Object {
  testItem: TestData
}

/**
 * WiFiScanStabilityTest Page Of wifi test
 */
const TAG = 'wifiTestApp [wifiTest_WiFiScanStabilityTest]'

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
  @State message: string = ConfigData.STABILITY_STR_TEST_RESULT
  @State testNumbers: number = ConfigData.DEFAULT_TEST_LOOP_COUNT
  @State successTimes: number = 0
  @State failTimes: number = 0
  @State scanStateMessage: string = ""
  @State scanStateMessageLog: string = ""
  @State scanLoopState: Boolean = true

  aboutToAppear() {
    // 请求发送通知的许可
    notificationManager.requestEnableNotification().then(() => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', `[EntryAbility] requestEnableNotification success`);
      // 申请WiFi相关权限
      let atManager = abilityAccessCtrl.createAtManager();
      try {
        atManager.requestPermissionsFromUser(getContext(this), [
          'ohos.permission.INTERNET',
          'ohos.permission.SET_WIFI_INFO',
          'ohos.permission.GET_WIFI_INFO',
          'ohos.permission.MANAGE_WIFI_CONNECTION',
          'ohos.permission.GET_WIFI_PEERS_MAC',
          'ohos.permission.MANAGE_WIFI_CONNECTION',
          'ohos.permission.SET_WIFI_CONFIG',
          "ohos.permission.GET_WIFI_CONFIG",
          "ohos.permission.GET_WIFI_LOCAL_MAC",
          "ohos.permission.MANAGE_WIFI_HOTSPOT",
          "ohos.permission.GET_WIFI_INFO_INTERNAL"
])
          .then((data) => {
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', `[EntryAbility], data: ${ JSON.stringify(data) }`);
          })
          .catch((err: BusinessError) => {
            hilog.info(0x1500, 'wifiTestApp', '%{public}s', `[EntryAbility], err: ${ JSON.stringify(err) }`);
          })
      } catch( err){
        hilog.info(0x1500, 'wifiTestApp', '%{public}s', `[EntryAbility], catch err->${ JSON.stringify(err) }`);
      }
    }).catch((err: BusinessError) => {
      hilog.error(0x1500, 'wifiTestApp', '%{public}s', `[EntryAbility] requestEnableNotification failed, code is ${ err.code }, message is ${ err.message }`);
    });
  }

  // 开始长时任务
  startContinuousTask() {
    let context: Context = getContext(this);
    // 通知参数，指定点击长时任务通知后跳转的应用
    let wantAgentInfo: wantAgent.WantAgentInfo = {
      wants: [
        {
          bundleName: (context as common.UIAbilityContext).abilityInfo.bundleName,
          abilityName: (context as common.UIAbilityContext).abilityInfo.name
        }
],
      operationType: ohosWantAgentInfo.OperationType.START_ABILITY,
      requestCode: 0,
      wantAgentFlags: [wantAgent.WantAgentFlags.UPDATE_PRESENT_FLAG]
    };
    wantAgent.getWantAgent(wantAgentInfo).then((wantAgentObj: WantAgent) => {
      backgroundTaskManager.startBackgroundRunning(context,
        backgroundTaskManager.BackgroundMode.DATA_TRANSFER, wantAgentObj).then(() => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s', `Succeeded in operationing startBackgroundRunning.`);
      }).catch((err: BusinessError) => {
        hilog.error(0x1500, 'wifiTestApp', '%{public}s', `Failed to operation startBackgroundRunning. Code is ${ err.code }, message is ${ err.message }`);
      });
    });
  }

  // 停止长时任务
  stopContinuousTask() {
    backgroundTaskManager.stopBackgroundRunning(getContext()).then(() => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', `Succeeded in operationing stopBackgroundRunning.`);
    }).catch((err: BusinessError) => {
      hilog.error(0x1500, 'wifiTestApp', '%{public}s', `Failed to operation stopBackgroundRunning. Code is ${ err.code }, message is ${ err.message }`);
    });
  }

  build() {
    Column() {
      Stack({alignContent: Alignment.TopStart}){
        TestImageDisplay({testItem: this.testItem})
        PageTitle({testItem: this.testItem})
      }

      Stack().height(ConfigData.VP_1).backgroundColor($r("app.color.black"));

      Column() {
        Row() {
          Text($r('app.string.wifitest_text_cscs_1')).fontSize($r('app.float.font_18')).width(ConfigData.WH_25_100).padding({left: ConfigData.VP_10})
          TextInput({placeholder: $r('app.string.wifitest_text_qsrxhcsmr3')})
            .placeholderColor($r('app.color.color_999999_grey'))
            .placeholderFont({size: $r('app.float.font_16')})
            .caretColor($r('app.color.main_blue'))
            .width(ConfigData.WH_70_100)
            .fontSize($r('app.float.font_16'))
            .fontColor($r('app.color.title_black_color'))
            .onChange((value: string) => {
              this.testNumbers = parseInt(value);
            })
        }

        Column() {
          Text($r('app.string.wifitest_text_csjg'))
            .fontSize(ConfigData.VP_22)
            .width(ConfigData.WH_95_100)
            .align(Alignment.TopStart)
            .padding({top: ConfigData.VP_10})
          Scroll() {
            Column() {
              Text() {
                Span($r('app.string.wifitest_text_cscs_1'))
                Span('' + this.testNumbers)
              }
                .fontSize(ConfigData.VP_18)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, right: ConfigData.VP_5})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_scan_ok'))
                Span('' + this.openScanSuccessNumber)
              }
                .fontSize(ConfigData.VP_18)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, right: ConfigData.VP_5})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_scan_fail'))
                Span('' + this.openScanFailNumber)
              }
                .fontSize(ConfigData.VP_18)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, right: ConfigData.VP_5})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_scan_count'))
                Span('' + this.scanInfo)
              }
                .fontSize(ConfigData.VP_18)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, right: ConfigData.VP_5})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
            }
            .width(ConfigData.WH_95_100)
            .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))
          }
          .scrollBarWidth(ConfigData.VP_10)
          .scrollBar(BarState.Auto)
        }.width(ConfigData.WH_100_100).height(ConfigData.WH_30_100)

        Column() {
          Text($r('app.string.wifitest_text_lxs'))
            .fontSize(ConfigData.VP_22)
            .height(ConfigData.WH_15_100)
            .width(ConfigData.WH_95_100)
            .align(Alignment.TopStart)
            .padding({top: ConfigData.VP_10})
          List() {
            ListItem() {
              Text(this.scanStateMessageLog)
                .fontSize(ConfigData.VP_18)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, right: ConfigData.VP_5})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
            }
          }
          .height(ConfigData.WH_83_100)
          .width(ConfigData.WH_95_100)
          .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))
        }.width(ConfigData.WH_100_100).height(ConfigData.WH_60_100)

      }.width(ConfigData.WH_100_100).height(ConfigData.WH_67_100).backgroundColor($r("app.color.lead"))

      Stack().height(ConfigData.VP_1).backgroundColor($r("app.color.black"));

      Column() {
        Row() {
          Button("开始扫描测试")
            .operateButtonStyle($r('app.color.main_blue'))
            .padding({right: ConfigData.VP_10})
            .onClick(async(event: ClickEvent) => {
              hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "start scan test-------------")
              this.startContinuousTask();
              await this.forLoop()
            })

          Blank().width(ConfigData.WH_10_100)

          Button("关闭扫描测试")
            .operateButtonStyle($r('app.color.main_blue'))
            .padding({right: ConfigData.VP_10})
            .onClick(async(event: ClickEvent) => {
              this.scanLoopState = false
              hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "准备测试停止 -------------")
              this.scanStateMessageLog = ""
              this.openScanNumber = 0;
              this.stopContinuousTask();
            })
        }
      }.width(ConfigData.WH_100_100).height(ConfigData.WH_25_100).backgroundColor($r("app.color.lead"))
    }.height(ConfigData.WH_100_100).width(ConfigData.WH_100_100).backgroundColor($r("app.color.lead"))
  }

  onWifiScanState() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "on.wifiScanStateChange start--------")
    wifiManager.on("wifiScanStateChange", (number) => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, " on.wifiScanStateChange success--------")
      let wifiScanStateMessage = ""
      switch (number){
        case 0: wifiScanStateMessage = "scan fail";
          break;
        case 1: wifiScanStateMessage = "scan success";
          break;
        default: wifiScanStateMessage = '未知状态';
          break;
      }
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "WiFi扫描状态为:" + wifiScanStateMessage)
      if (number == 1){
        // 打时间戳
        this.scan_EndTime = new Date().getTime()
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "WIFI扫描成功时间: " + this.scan_EndTime + "ms")
        this.scanInfo = wifiManager.getScanResultsSync().length
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "WIFI扫描结果个数: " + this.scanInfo + "; WIFI扫描结果个数: " + JSON.stringify(wifiManager.getScanResultsSync()))
      } else {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "WIFI扫描还未成功------")
      }
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, " on.wifiScanStateChange  callback success --------")
      promptAction.showToast({message: "wifiScan状态: " + wifiScanStateMessage})
      this.scanStateMessage = wifiScanStateMessage
      AppStorage.setOrCreate("scanStateMessage", this.scanStateMessage)
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, " on.wifiStateChange callback end--------")
      return this.scanStateMessage
    })
  }

  aboutToDisappear() {
    wifiManager.off("wifiScanStateChange")
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
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "getScanAlwaysAllowed:" + funcMessage)
    for(this.openScanNumber ; this.openScanNumber<this.testNumbers ; this.openScanNumber++){
      if (!this.scanLoopState){
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "测试结束------------")
        break;
      } else {
        let wifiState = wifiManager.isWifiActive()
        if (!wifiState){
          wifiManager.enableWifi()
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "wifi当前未使能，已经使能，正常开始测试------")
        } else {
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "wifi当前使能，正常开始测试------")
        }
        this.onWifiScanState()
        await sleep(5)
        wifiManager.startScan()
        this.scan_StartTime = new Date().getTime()
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openScanNumber + 1) + "次WIFI扫描-----")
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openScanNumber + 1) + "次WIFI扫描开始时间: " + this.scan_StartTime + "ms")
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openScanNumber + 1) + "次WIFI扫描接口的调用成功")
        await sleep(10)
        this.scanStateMessage = AppStorage.get("scanStateMessage")!//非空断言操作符
        if (this.scanStateMessage == "scan success"){
          this.scanStateMessageLog += "第" + (this.openScanNumber + 1) + "次WIFI扫描成功" + "\n"
          this.scan_SpendTime = this.scan_EndTime - this.scan_StartTime
          this.scanStateMessageLog += "第" + (this.openScanNumber + 1) + "次WIFI扫描耗时: " + this.scan_SpendTime + "ms" + "\n"
          this.scanStateMessageLog += "第" + (this.openScanNumber + 1) + "次WIFI扫描结果个数: " + this.scanInfo + "\n"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openScanNumber + 1) + "次WIFI扫描耗时: " + this.scan_SpendTime + "ms")
          this.openScanSuccessNumber = this.openScanSuccessNumber + 1
          this.scanStateMessageLog += "扫描成功的次数：" + this.openScanSuccessNumber + "\n"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "扫描成功的次数：" + this.openScanSuccessNumber)
          await sleep(10)
          this.scanStateMessage = AppStorage.get("scanStateMessage")!//非空断言操作符
        } else if (this.scanStateMessage == "scan fail"){
          this.openScanFailNumber = this.openScanFailNumber + 1
          this.scanStateMessageLog += "第" + (this.openScanNumber + 1) + "次WIFI扫描失败" + "\n"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "扫描失败的次数：" + this.openScanFailNumber)
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openScanNumber + 1) + "次WIFI扫描失败")
        } else {
          this.scanStateMessageLog += "第" + (this.openScanNumber + 1) + "次WIFI扫描情况未知" + "\n"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openScanNumber + 1) + "次扫描后状态不清楚");
        }
        wifiManager.off("wifiScanStateChange")
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "off.wifiScanStateChange success--------");
        await sleep(5)
      }
    }
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "测试结束 -------------")
    this.stopContinuousTask();
  }
}

/**
 * Custom button style.
 */
@Extend(Button)
function operateButtonStyle(color: Resource){
  .width($r('app.float.button_width'))
  .height($r('app.float.button_height'))
  .fontSize($r('app.float.font_16'))
  .fontWeight(500)
  .fontColor(color)
  .backgroundColor($r('app.color.button_background'))
}

async function sleep(time: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    setTimeout(() => {
      resolve();
    }, time * 1000);
  });
}