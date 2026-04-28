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
import fs from '@ohos.file.fs';
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

/**
 * WiFiSwitchStabilityTest Page Of wifi test
 */
const TAG = 'wifiTestApp [WiFiSwitchStabilityTest]'

@Entry
@Component
struct WiFiSwitchStabilityTest {
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State open_StartTime: number = 0
  @State open_EndTime: number = 0
  @State open_SpendTime: number = 0
  @State close_StartTime: number = 0
  @State close_EndTime: number = 0
  @State close_SpendTime: number = 0
  @State openWifiNumber: number = 0// 打开WiFi的次数
  @State closeWifiNumber: number = 0// 关闭WiFi的次数
  @State openSuccessNumber: number = 0// 打开WiFi的成功次数
  @State openFailNumber: number = 0// 打开WiFi的失败次数
  @State closeSuccessNumber: number = 0// 关闭WiFi的成功次数
  @State closeFailNumber: number = 0// 关闭WiFi的失败次数
  @State message: string = ConfigData.STABILITY_STR_TEST_RESULT_COLON
  @State testNumbers: number = ConfigData.DEFAULT_TEST_LOOP_COUNT
  @State successTimes: number = 0
  @State failTimes: number = 0
  @State stateMessage: string = ""
  @State stateMessageLog: string = ""
  @State switchLoopState: Boolean = true;
  @State fileData: string = "";
  @State filePath: string = ""
  private file!: fs.File
  @StorageLink("pathDir") pathDir: string = ""
  private isWifiStateListenerRegistered: boolean = false// 标记是否已注册WiFi状态监听器

  async openLogFile() {
    let time: number = new Date().getTime()
    let currentTime: string = timestampToDate(time)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "当前时间: " + currentTime)
    this.filePath = this.pathDir + ("/" + currentTime + ".txt");
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "沙箱路径为: " + this.filePath)
    this.file = fs.openSync(this.filePath, fs.OpenMode.READ_WRITE | fs.OpenMode.CREATE);
    AppStorage.setOrCreate("fsFile", this.file)
    AppStorage.setOrCreate("openWifiNumber", this.openWifiNumber)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "数据文件的沙箱路径为: " + this.filePath)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "file fd: " + this.file.fd);
  }

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
                Span($r('app.string.wifitest_text_wlan_on_ok'))
                Span('' + this.openSuccessNumber)
              }
                .fontSize(ConfigData.VP_18)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, right: ConfigData.VP_5})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_wlan_on_fail'))
                Span('' + this.openFailNumber)
              }
                .fontSize(ConfigData.VP_18)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, right: ConfigData.VP_5})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_wlan_off_ok'))
                Span('' + this.closeSuccessNumber)
              }
                .fontSize(ConfigData.VP_18)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, right: ConfigData.VP_5})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_wlan_off_fail'))
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
              Text(this.stateMessageLog)
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
          Button("开始WiFi测试")
            .operateButtonStyle($r('app.color.main_blue'))
            .padding({right: ConfigData.VP_10})
            .onClick(async(event: ClickEvent) => {
              hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "start WiFiSwitch test-------------")
              this.startContinuousTask();
              await this.openLogFile()
              await this.forLoop()
            })

          Blank().width(ConfigData.WH_10_100)

          Button("关闭WiFi测试")
            .operateButtonStyle($r('app.color.main_blue'))
            .padding({right: ConfigData.VP_10})
            .onClick(async(event: ClickEvent) => {
              this.switchLoopState = false
              hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "准备测试停止 -------------")
              // 注销WiFi状态监听器
              if (this.isWifiStateListenerRegistered){
                try {
                  wifiManager.off("wifiStateChange")
                  this.isWifiStateListenerRegistered = false
                  hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "off.wifiStateChange on stop test")
              } catch( error){
                  hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to unregister wifiStateChange on stop. Error: ${ JSON.stringify(error) }`)
                  this.isWifiStateListenerRegistered = false
              }
              }
              this.stateMessageLog = ""
              this.openWifiNumber = 0
              AppStorage.setOrCreate("openWifiNumber", this.openWifiNumber)
              fs.closeSync(this.file);
              this.stopContinuousTask();
            })
        }
      }.width(ConfigData.WH_100_100).height(ConfigData.WH_25_100).backgroundColor($r("app.color.lead"))
    }.height(ConfigData.WH_100_100).width(ConfigData.WH_100_100).backgroundColor($r("app.color.lead"))
  }

  onWifiState() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "on.wifiStateChange start--------")
    wifiManager.on("wifiStateChange", (number) => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, " on.wifiStateChange --------")
      let wifiStateMessage = ""
      switch (number){
        case 0: wifiStateMessage = "inactive";
          break;
        case 1: wifiStateMessage = "active";
          break;
        case 2: wifiStateMessage = "activating";
          break;
        case 3: wifiStateMessage = "de-activating";
          break;
        default: wifiStateMessage = '未知状态';
          break;
      }
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "WiFi开关状态为:" + wifiStateMessage)
      if (number == 1){
        // 打时间戳
        this.open_EndTime = new Date().getTime()
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "WIFI使能结束时间: " + this.open_EndTime + "ms")
      } else if (number == 0){
        this.close_EndTime = new Date().getTime()
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "WIFI去使能结束时间: " + this.close_EndTime + "ms")
      }
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, " on.wifiStateChange callback success --------")
      promptAction.showToast({message: "wifi状态: " + wifiStateMessage})
      this.stateMessage = wifiStateMessage
      AppStorage.setOrCreate("stateMessage", this.stateMessage)
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, " on.wifiStateChange callback end--------")
      return this.stateMessage
    })
    this.isWifiStateListenerRegistered = true// 标记已注册监听器
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "on.wifiStateChange registered successfully--------")
  }

  aboutToDisappear() {
    // 只有在已注册监听器的情况下才注销
    if (this.isWifiStateListenerRegistered){
      try {
        wifiManager.off("wifiStateChange")
        this.isWifiStateListenerRegistered = false
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "off.wifiStateChange unregistered successfully")
      } catch( error){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to unregister wifiStateChange. Error: ${ JSON.stringify(error) }`)
        // 即使注销失败也将标志设为false，避免重复尝试
        this.isWifiStateListenerRegistered = false
      }
    } else {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "wifiStateChange listener was not registered, no need to unregister")
    }
  }

  async forLoop() {
    this.switchLoopState = true
    this.openWifiNumber = 0
    this.closeWifiNumber = 0
    this.openSuccessNumber = 0
    this.openFailNumber = 0
    this.closeSuccessNumber = 0
    this.closeFailNumber = 0

    this.stateMessageLog = ""
    this.onWifiState()// 监听函数
    let funcMessage = false// 函数信息
    for(this.openWifiNumber ; this.openWifiNumber<this.testNumbers ; this.openWifiNumber++){
      if (!this.switchLoopState){
        this.openWifiNumber = 0;
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
        // funcMessage = wifiManager.enableWifi()
        // 打时间戳
        this.open_StartTime = new Date().getTime()
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openWifiNumber + 1) + "次WIFI使能-----")
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openWifiNumber + 1) + "次WIFI使能开始时间: " + this.open_StartTime + "ms")
        this.stateMessageLog += "第" + (this.openWifiNumber + 1) + "次WIFI使能接口的调用结果：" + funcMessage + "\n"
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openWifiNumber + 1) + "次WIFI使能接口的调用结果：" + funcMessage)
        await sleep(15)
        this.stateMessage = AppStorage.get("stateMessage")!//非空断言操作符
        if (this.stateMessage == "active"){
          this.open_SpendTime = this.open_EndTime - this.open_StartTime
          this.stateMessageLog += "第" + (this.openWifiNumber + 1) + "次WIFI使能耗时: " + this.open_SpendTime + "ms" + "\n"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openWifiNumber + 1) + "次WIFI使能耗时: " + this.open_SpendTime + "ms")
          this.openSuccessNumber = this.openSuccessNumber + 1
          this.stateMessageLog += "使能成功的次数：" + this.openSuccessNumber + "\n"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "使能成功的次数：" + this.openSuccessNumber)
          // funcMessage = wifiManager.disableWifi()
          this.closeWifiNumber = this.closeWifiNumber + 1
          this.close_StartTime = new Date().getTime()
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.closeWifiNumber + "次WIFI去使能-----")
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.closeWifiNumber + "次WIFI去使能开始时间: " + this.close_StartTime + "ms")
          this.stateMessageLog += "第" + this.closeWifiNumber + "次WIFI去使能接口的调用结果：" + funcMessage + "\n"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.closeWifiNumber + "次WIFI去使能接口的调用结果：" + funcMessage)
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "closeWifiNumber: " + this.closeWifiNumber)
          await sleep(15)
          this.stateMessage = AppStorage.get("stateMessage")!//非空断言操作符
          if (this.stateMessage == "inactive"){
            this.close_SpendTime = this.close_EndTime - this.close_StartTime
            this.stateMessageLog += "第" + this.closeWifiNumber + "次WIFI去使能耗时: " + this.close_SpendTime + "ms" + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.closeWifiNumber + "次WIFI去使能耗时: " + this.close_SpendTime + "ms")
            this.closeSuccessNumber = this.closeSuccessNumber + 1
            this.stateMessageLog += "去使能成功的次数：" + this.closeSuccessNumber + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "去使能成功的次数：" + this.closeSuccessNumber)
            await sleep(7)
          } else {
            this.closeFailNumber = this.closeFailNumber + 1
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "去使能失败的次数：" + this.closeFailNumber)
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.closeWifiNumber + "次WIFI去使能失败")
          }
        } else if (this.stateMessage == "inactive"){
          this.openFailNumber = this.openFailNumber + 1
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "使能失败的次数：" + this.openFailNumber)
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openWifiNumber + 1) + "次WIFI使能失败")
        } else {
          hilog.info(0x1500, 'wifiTestApp', '%{public}s', "第" + (this.openWifiNumber + 1) + "次开wifi后状态不清楚");
        }
      }
    }
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "测试结束 -------------")
    this.stopContinuousTask();
  }
}

export function timestampToDate(timestamp: number): string {
  const date = new Date(timestamp);
  let year = date.getFullYear();
  let month: string | number = date.getMonth() + 1;
  month = month >= 10 ? month: (ConfigData.QV_MOCK_DOMAIN_0 + month);
  let day: string | number = date.getDate();
  day = day >= 10 ? day: (ConfigData.QV_MOCK_DOMAIN_0 + day);
  let hours: string | number = date.getHours();
  hours = hours >= 10 ? hours: (ConfigData.QV_MOCK_DOMAIN_0 + hours);
  let minutes: string | number = date.getMinutes();
  minutes = minutes >= 10 ? minutes: (ConfigData.QV_MOCK_DOMAIN_0 + minutes);
  let seconds: string | number = date.getSeconds();
  seconds = seconds >= 10 ? seconds: (ConfigData.QV_MOCK_DOMAIN_0 + seconds);
  return `${ year }${ month }${ day }_${ hours }${ minutes }${ seconds }`;
}

async function sleep(time: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    setTimeout(() => {
      resolve();
    }, time * 1000);
  });
}