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
 * WiFiSwitchStabilityTest Page Of wifi test
 */
const TAG = 'wifiTestApp [HotspotStabilityTest]'

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
  @State openHotspotNumber: number = 0// 打开Hotspot的次数
  @State closeHotspotNumber: number = 0// 关闭Hotspot的次数
  @State openSuccessNumber: number = 0// 打开Hotspot的成功次数
  @State openFailNumber: number = 0// 打开Hotspot的失败次数
  @State closeSuccessNumber: number = 0// 关闭Hotspot的成功次数
  @State closeFailNumber: number = 0// 关闭Hotspot的失败次数

  @State message: string = ConfigData.STABILITY_STR_TEST_RESULT_COLON
  @State testNumbers: number = ConfigData.DEFAULT_TEST_LOOP_COUNT
  @State successTimes: number = 0
  @State failTimes: number = 0
  @State hotspotMessage: string = ""
  @State hotspotMessageLog: string = ""
  @State hotspotLoopState: Boolean = true

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
          TextInput({placeholder: $r('app.string.wifitest_text_qsrxhcsmrw3_1')})
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
                Span($r('app.string.wifitest_text_hs_open_ok'))
                Span('' + this.openSuccessNumber)
              }
                .fontSize(ConfigData.VP_18)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, right: ConfigData.VP_5})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_hs_open_fail'))
                Span('' + this.openFailNumber)
              }
                .fontSize(ConfigData.VP_18)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, right: ConfigData.VP_5})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_hs_close_ok'))
                Span('' + this.closeSuccessNumber)
              }
                .fontSize(ConfigData.VP_18)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, right: ConfigData.VP_5})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_hs_close_fail'))
                Span('' + this.closeFailNumber)
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
            .padding({top: ConfigData.VP_18})
          List() {
            ListItem() {
              Text(this.hotspotMessageLog)
                .fontSize(ConfigData.VP_18)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_20, right: ConfigData.VP_5})
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
          Button("开始热点测试")
            .operateButtonStyle($r('app.color.main_blue'))
            .padding({right: ConfigData.VP_10})
            .onClick(async(event: ClickEvent) => {
              hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "start HotspotSwitch test-------------")
              this.startContinuousTask();
              await this.forLoop()
            })

          Blank().width(ConfigData.WH_10_100)

          Button("关闭热点测试")
            .operateButtonStyle($r('app.color.main_blue'))
            .padding({right: ConfigData.VP_10})
            .onClick(async(event: ClickEvent) => {
              this.hotspotLoopState = false
              hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "准备测试停止 -------------")
              this.hotspotMessageLog = ""
              this.openHotspotNumber = 0
              this.stopContinuousTask();
            })
        }
      }.width(ConfigData.WH_100_100).height(ConfigData.WH_25_100).backgroundColor($r("app.color.lead"))
    }.height(ConfigData.WH_100_100).width(ConfigData.WH_100_100).backgroundColor($r("app.color.lead"))
  }

  onHotspotStateChange() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "on.hotspotStateChange start--------")
    wifiManager.on("hotspotStateChange", (number) => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, " on.hotspotStateChange --------")
      let hotspotStateMessage = ""
      switch (number){
        case 0: hotspotStateMessage = "inactive";
          break;
        case 1: hotspotStateMessage = "active";
          break;
        case 2: hotspotStateMessage = "activating";
          break;
        case 3: hotspotStateMessage = "de-activating";
          break;
        default: hotspotStateMessage = '未知状态';
          break;
      }
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "热点开关状态为:" + hotspotStateMessage)
      if (number == 1){
        // 打时间戳
        this.open_EndTime = new Date().getTime()
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "热点使能结束时间: " + this.open_EndTime + "ms")
      } else if (number == 0){
        this.close_EndTime = new Date().getTime()
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "热点去使能结束时间: " + this.close_EndTime + "ms")
      }
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, " on.hotspotStateChange callback success --------")
      promptAction.showToast({message: "热点状态: " + hotspotStateMessage})
      this.hotspotMessage = hotspotStateMessage
      AppStorage.setOrCreate("hotspotMessage", this.hotspotMessage)
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, " on.hotspotStateChange callback end--------")
      return this.hotspotMessage
    })
    return this.hotspotMessage
  }

  aboutToDisappear() {
    wifiManager.off("hotspotStateChange")
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
    this.onHotspotStateChange()// 监听函数
    let funcMessage = false// 函数信息
    for(this.openHotspotNumber ; this.openHotspotNumber<this.testNumbers ; this.openHotspotNumber++){
      if (!this.hotspotLoopState){
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "测试结束------------")
        break;
      } else {
        let wifiState = wifiManager.isWifiActive()
        if (wifiState){
          wifiManager.disableWifi()
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "wifi当前已使能，已经去使能，正常开始测试------")
        } else {
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "wifi当前未使能，正常开始测试------")
        }
        await sleep(3)

        // funcMessage = wifiManager.enableHotspot()
        // 打时间戳
        this.open_StartTime = new Date().getTime()
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openHotspotNumber + 1) + "次热点使能-----")
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openHotspotNumber + 1) + "次热点使能开始时间: " + this.open_StartTime + "ms")
        this.hotspotMessageLog += "第" + (this.openHotspotNumber + 1) + "次热点使能结果：" + funcMessage + "\n"
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openHotspotNumber + 1) + "次热点使能结果：" + funcMessage)
        await sleep(10)
        this.hotspotMessage = AppStorage.get("hotspotMessage") !//非空断言操作符
        // promptAction.showToast( { message: funcMessage })
        if (this.hotspotMessage == "active"){
          this.open_SpendTime = this.open_EndTime - this.open_StartTime
          this.hotspotMessageLog += "第" + (this.openHotspotNumber + 1) + "次热点使能耗时: " + this.open_SpendTime + "ms" + "\n"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openHotspotNumber + 1) + "次热点使能耗时: " + this.open_SpendTime + "ms")
          this.openSuccessNumber = this.openSuccessNumber + 1
          this.hotspotMessageLog += "热点使能成功的次数：" + this.openSuccessNumber + "\n"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "热点使能成功的次数：" + this.openSuccessNumber)
          // funcMessage = wifiManager.disableHotspot()
          this.closeHotspotNumber = this.closeHotspotNumber + 1
          this.close_StartTime = new Date().getTime()
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.closeHotspotNumber + "次热点去使能-----")
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.closeHotspotNumber + "次热点去使能开始时间: " + this.close_StartTime + "ms")
          this.hotspotMessageLog += "第" + this.closeHotspotNumber + "次热点去使能结果：" + funcMessage + "\n"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.closeHotspotNumber + "次热点去使能结果：" + funcMessage)
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "closeHotspotNumber: " + this.closeHotspotNumber)
          await sleep(10)
          this.hotspotMessage = AppStorage.get("hotspotMessage") !//非空断言操作符
          if (this.hotspotMessage == "inactive"){
            this.close_SpendTime = this.close_EndTime - this.close_StartTime
            this.hotspotMessageLog += "第" + this.closeHotspotNumber + "次热点去使能耗时: " + this.close_SpendTime + "ms" + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.closeHotspotNumber + "次热点去使能耗时: " + this.close_SpendTime + "ms")
            this.closeSuccessNumber = this.closeSuccessNumber + 1
            this.hotspotMessageLog += "热点去使能成功的次数：" + this.closeSuccessNumber + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "热点去使能成功的次数：" + this.closeSuccessNumber)
            await sleep(7)
          } else {
            this.closeFailNumber = this.closeFailNumber + 1
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "热点去使能失败的次数：" + this.closeFailNumber)
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.closeHotspotNumber + "次热点去使能失败")
          }
        } else if (this.hotspotMessage == "inactive"){
          this.openFailNumber = this.openFailNumber + 1
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "热点使能失败的次数：" + this.openFailNumber)
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openHotspotNumber + 1) + "次热点使能失败")
        } else {
          hilog.info(0x1500, 'wifiTestApp', '%{public}s', "第" + (this.openHotspotNumber + 1) + "次开热点后状态不清楚");
        }
      }
    }
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "测试结束 -------------")
    this.stopContinuousTask();
  }
}

/**
 * Custom button style.
 */
@Extend(Button) function operateButtonStyle(color: Resource){
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