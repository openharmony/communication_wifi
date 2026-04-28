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
import wifi from '@ohos.wifi';
import wifiManager from '@ohos.wifiManager';
import { PageTitle} from '../../Component/pageTitle';
import router from '@ohos.router';
import mediaquery from '@ohos.mediaquery';
import parameter from '@ohos.systemparameter';
import { TabletTitle, BrowserTabs, WebTab} from '../../Component/webTitleBar';
import { PhoneLayout} from '../../Component/phoneLayout';
import { Browser, LoadingStatus} from '../../entryability/model/bowser';
import ConfigData from '../../Utils/ConfigData';
import fs from '@ohos.file.fs';
import http from '@ohos.net.http';
import { TestData} from '../../entryability/model/testData';
import promptAction from '@ohos.promptAction';
import common from '@ohos.app.ability.common';
import wantAgent, { WantAgent} from '@ohos.app.ability.wantAgent';
import ohosWantAgentInfo from '@ohos.wantAgent';
import backgroundTaskManager from '@ohos.resourceschedule.backgroundTaskManager';
import { BusinessError} from '@ohos.base';
import abilityAccessCtrl from '@ohos.abilityAccessCtrl';
import notificationManager from '@ohos.notificationManager';

const TAG = 'wifiTestApp [webLatencyTest]';

interface myParams extends Object {
  testItem: TestData
}

@Extend(Button) function operateButtonStyle(color: Resource){
  .width($r('app.float.button_width'))
  .height($r('app.float.button_height'))
  .fontSize($r('app.float.font_16'))
  .fontWeight(500)
  .fontColor(color)
  .backgroundColor($r('app.color.button_background'))
}

/**
 * wifi Found Test Page Of Wifi test
 */
@Entry
@Component
struct webLatencyTest {
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State isPhone: boolean = true;
  @State testNumbers: number = ConfigData.DEFAULT_TEST_LOOP_COUNT
  @State openWebNumbers: number = 0// 打开Web的次数
  @State closeWebNumbers: number = 0// 关闭Web的次数
  @State openSuccessNumbers: number = 0;
  @State openFailNumbers: number = 0;
  @State progressStatus: number = 0;
  @State browser: Browser = new Browser();
  @StorageLink("pageCostTime") pageCostTime: number = 0
  @StorageLink("pathDir") pathDir: string = ""
  @State addr: string = ConfigData.WEB_DEMO_ADDR_BAIDU
  @State filePath: string = ""
  private isInit: Boolean = false;
  @State pairedSsid: string = "";
  @State wifiConnectionMessage: string = ""
  @State webLoopState: Boolean = true
  @State webMessage: string = ""
  @State webMessageLog: string = ""
  @State requestStartTime: number = 0
  @State requestEndTime: number = 0
  @State requestCostTime: number = 0
  private file!: fs.File
  @State fileData: string = "";

  listener = mediaquery.matchMediaSync('(orientation:landscape)');

  async openLogFile() {
    let time: number = new Date().getTime()
    let currentTime: string = timestampToDate(time)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "当前时间: " + currentTime)
    this.filePath = this.pathDir + ("/" + currentTime + ".txt");
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "沙箱路径为: " + this.filePath)
    this.file = fs.openSync(this.filePath, fs.OpenMode.READ_WRITE | fs.OpenMode.CREATE);
    AppStorage.setOrCreate("fsFile", this.file)
    AppStorage.setOrCreate("openWebNumbers", this.openWebNumbers)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "数据文件的沙箱路径为: " + this.filePath)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "file fd: " + this.file.fd);
  }

  aboutToAppear() {
    try {
      let deviceType = parameter.getSync("const.build.characteristics");
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "deviceType：" + deviceType)
      if (deviceType === 'default'){
        this.isPhone = true;
      }
    } catch( e){
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `getSync unexpected error: ${ e }`);
    }
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "aboutToAppear")
    let wifiState = wifiManager.isConnected()
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "aboutToAppear,isConnected:" + wifiState)
    if (wifiState){
      this.wifiConnectionMessage = "connected";
      wifiManager.getLinkedInfo((err, data) => {
        if (err){
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "get linked info error");
        }
        let linkedInfoMessage = JSON.stringify(data)
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "aboutToAppear, linkedInfo:" + linkedInfoMessage)
        this.pairedSsid = data.ssid
        AppStorage.setOrCreate("pairedSsid", this.pairedSsid)
      })
    } else {
      this.wifiConnectionMessage = "disconnected";
      promptAction.showToast({message: $r('app.string.wifitest_toast_pls_connect_wifi')})
    }
    this.filePath = this.pathDir + ("/loadlog.txt");
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "沙箱路径为: " + this.filePath)
    this.file = fs.openSync(this.filePath, fs.OpenMode.READ_WRITE | fs.OpenMode.CREATE);
    AppStorage.setOrCreate("fsFile", this.file)
    AppStorage.setOrCreate("openWebNumbers", this.openWebNumbers)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "数据文件的沙箱路径为: " + this.filePath)
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "file fd: " + this.file.fd);

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

  aboutToDisappear() {
  }

  build() {
    Column() {
      Stack({alignContent: Alignment.TopStart}){
        PageTitle({testItem: this.testItem})
      }

      Stack().height(ConfigData.VP_0_5).backgroundColor($r("app.color.black"));

      Column() {
        Text() {
          Span($r('app.string.wifitest_text_wifi_link_status'))
          Span(this.wifiConnectionMessage)
        }
          .fontSize(ConfigData.VP_17)
          .margin({top: ConfigData.VP_8, bottom: ConfigData.VP_4, left: ConfigData.VP_15})
          .textAlign(TextAlign.Start)
          .width(ConfigData.WH_100_100)
        Text() {
          Span($r('app.string.wifitest_text_yljdw'))
          Span(this.pairedSsid)
        }
          .fontSize(ConfigData.VP_17)
          .margin({top: ConfigData.VP_4, bottom: ConfigData.VP_8, left: ConfigData.VP_15})
          .textAlign(TextAlign.Start)
          .width(ConfigData.WH_100_100)
        Row() {
          Text($r('app.string.wifitest_text_cscs'))
            .fontSize(ConfigData.VP_17)
            .width(ConfigData.WH_25_100)
            .margin({top: ConfigData.VP_8, bottom: ConfigData.VP_8, left: ConfigData.VP_5})
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

        TabletTitle({browser: $browser})

        Column() {
          Row() {
            Button($r('app.string.wifitest_btn_start_web_test'))
              .operateButtonStyle($r('app.color.main_blue'))
              .align(Alignment.Center)
              .onClick(async(event: ClickEvent) => {
                let wifiState = wifiManager.isConnected()
                if (wifiState){
                  hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "start web test-------------")
                  this.webLoopState = true
                  this.openWebNumbers = 0
                  this.openSuccessNumbers = 0
                  this.openFailNumbers = 0
                  await this.openLogFile()
                  this.startContinuousTask();
                  await this.forLoop()
                } else {
                  promptAction.showToast({message: $r('app.string.wifitest_toast_pls_connect_wifi_to_start')});
                }

              })

            Blank().width(ConfigData.WH_10_100)

            Button($r('app.string.wifitest_btn_close_web_test'))
              .operateButtonStyle($r('app.color.main_blue'))
              .align(Alignment.Center)
              .onClick(async(event: ClickEvent) => {
                this.webLoopState = false
                hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "准备测试停止 -------------")
                this.openWebNumbers = 0
                AppStorage.setOrCreate("openWebNumbers", this.openWebNumbers)
                this.webMessageLog = ""
                fs.closeSync(this.file);
                this.stopContinuousTask();
              })
          }
        }.width(ConfigData.WH_100_100).backgroundColor($r("app.color.ohcc_hex_f5f5f5")).padding({top: " 5vp"})

        Column() {
          Column() {
            Text($r('app.string.wifitest_text_csjg'))
              .fontSize(ConfigData.VP_18)
              .width(ConfigData.WH_95_100)
              .align(Alignment.TopStart)
              .padding({top: " 5vp"})
            Scroll() {
              Column() {
                Text() {
                  Span($r('app.string.wifitest_text_cscs_1'))
                  Span('' + this.testNumbers)
                }
                  .fontSize(ConfigData.VP_18)
                  .margin({top: ConfigData.VP_3, left: ConfigData.VP_5, right: ConfigData.VP_5})
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_95_100)
                Text() {
                  Span($r('app.string.wifitest_text_open_web_ok'))
                  Span('' + this.openSuccessNumbers)
                }
                  .fontSize(ConfigData.VP_18)
                  .margin({top: ConfigData.VP_3, left: ConfigData.VP_5, right: ConfigData.VP_5})
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_95_100)
                Text() {
                  Span($r('app.string.wifitest_text_open_web_fail'))
                  Span('' + this.openFailNumbers)
                }
                  .fontSize(ConfigData.VP_18)
                  .margin({top: ConfigData.VP_3, left: ConfigData.VP_5, right: ConfigData.VP_5})
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_95_100)
                Text() {
                  Span($r('app.string.wifitest_text_test_progress'))
                  Span('' + this.browser.progress)
                  Span($r('app.string.wifitest_text_unit_space_percent'))
                }
                  .fontSize(ConfigData.VP_18)
                  .margin({top: ConfigData.VP_3, left: ConfigData.VP_5, right: ConfigData.VP_5})
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_95_100)
                Text() {
                  Span($r('app.string.wifitest_text_http_request_time'))
                  Span('' + this.requestCostTime)
                  Span($r('app.string.wifitest_text_unit_sp_ms'))
                }
                  .fontSize(ConfigData.VP_18)
                  .margin({top: ConfigData.VP_3, left: ConfigData.VP_5, right: ConfigData.VP_5})
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_95_100)
                Text() {
                  Span($r('app.string.wifitest_text_sandbox_path'))
                  Span(this.filePath)
                }
                  .fontSize(ConfigData.VP_18)
                  .margin({top: ConfigData.VP_3, left: ConfigData.VP_5, right: ConfigData.VP_5})
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_95_100)
              }
              .width(ConfigData.WH_95_100)
              .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))
            }
            .scrollBarWidth(ConfigData.VP_10)
            .scrollBar(BarState.Auto)
          }
          .width(ConfigData.WH_100_100)
        }
        .height(ConfigData.WH_60_100)
        .width(ConfigData.WH_100_100)
      }
      .width(ConfigData.WH_100_100)
      .height(ConfigData.WH_60_100)

      Column() {
        if (this.isPhone){
          Progress({value: this.browser.progress, total: ConfigData.PROGRESS_MAX_PERCENT})
            .color($r("app.color.ohcc_hex_0000ff"))
            .visibility(this.browser.hideProgress ? Visibility.None: Visibility.Visible)
          BrowserTabs({browser: $browser})
          Divider().color($r("app.color.ohcc_hex_c6c6c6")).width(ConfigData.WH_100_100).flexShrink(0)
          WebTab({browser: $browser, isPhone: $isPhone})
        } else {
          PhoneLayout({browser: $browser})
        }
      }
      .width(ConfigData.WH_100_100)
      .height(ConfigData.WH_35_100)

    }
    .width(ConfigData.WH_100_100)
    .height(ConfigData.WH_100_100)
    .backgroundColor($r("app.color.ohcc_hex_f5f5f5"))
  }

  onBackPress(): boolean {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `enter onBackPress`);
    if (this.browser.webControllerArray[this.browser.tabArrayIndex].controller.accessBackward() ||
    this.browser.loadingStatus === LoadingStatus.LOADING){
      this.browser.webControllerArray[this.browser.tabArrayIndex].controller.backward();
      return true;
    }

    return false;
  }

  onDeviceChange() {
    this.browser = new Browser();
  }

  async forLoop() {
    this.webMessageLog = ""
    let funcMessage = ""// 函数信息
    for(this.openWebNumbers ; this.openWebNumbers<this.testNumbers ; this.openWebNumbers++){
      if (!this.webLoopState){
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "web测试结束------------")
        this.openWebNumbers = 0
        AppStorage.setOrCreate("openWebNumbers", this.openWebNumbers)
        break;
      } else {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "测试开始--------")
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s %{public}s', TAG, "this.addr:", this.addr)
        AppStorage.setOrCreate("openWebNumbers", this.openWebNumbers)
        let time1: number = new Date().getTime()
        let currentTime1: string = timestampToDateFormat(time1)
        this.fileData = currentTime1 + " 第" + (this.openWebNumbers + 1) + "次网页测试开始! Start loading website" + "\n"
        this.fileData += currentTime1 + " nextWebUrl: " + this.addr + "\n"
        this.fileData += currentTime1 + " loadUrl: " + this.addr + "\n"
        fs.writeSync(this.file.fd, this.fileData);

        let httpRequest = http.createHttp();
        this.requestStartTime = new Date().getTime()
        console.time("request")
        httpRequest.request(ConfigData.WEB_DEMO_ADDR_BAIDU, (err: Error, data: http.HttpResponse) => {
          if (!err){
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'Result:' + data.result);
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'code:' + data.responseCode);
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'header:' + JSON.stringify(data.header));
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'cookies:' + data.cookies);
            console.timeEnd("request")
            this.requestEndTime = new Date().getTime()
            this.requestCostTime = this.requestEndTime - this.requestStartTime
            let time2: number = new Date().getTime()
            let currentTime2: string = timestampToDateFormat(time2)
            this.fileData = currentTime2 + " 第" + (this.openWebNumbers + 1) + "次http request的耗时： " + this.requestCostTime + "ms" + "\n"
            fs.writeSync(this.file.fd, this.fileData);
            this.openSuccessNumbers++
          } else {
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'error:' + JSON.stringify(err));
            this.openFailNumbers++
          }
        });
        this.browser.loadUrl(this.addr)
        await sleep(10)
        this.browser.loadUrl($rawfile('phone.html'))// pad.html
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.openWebNumbers + 1) + "次测试结束--------")
        let time3: number = new Date().getTime()
        let currentTime3: string = timestampToDateFormat(time3)
        this.fileData = currentTime3 + " 第" + (this.openWebNumbers + 1) + "次网页测试结束! ------------" + "\n"
        fs.writeSync(this.file.fd, this.fileData);
        AppStorage.setOrCreate("openWebNumbers", this.openWebNumbers)
        await sleep(5)
      }
    }
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "测试结束 -------------")
    fs.closeSync(this.file);
    this.stopContinuousTask();
    AppStorage.setOrCreate("openWebNumbers", this.openWebNumbers)
    this.webMessageLog = ""
  }
}

async function sleep(time: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    setTimeout(() => {
      resolve();
    }, time * 1000);
  });
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

export function timestampToDateFormat(timestamp: number): string {
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
  let milliSeconds: string | number = date.getMilliseconds();
  milliSeconds = milliSeconds >= 10 ? (milliSeconds >= 100 ? milliSeconds: (ConfigData.QV_MOCK_DOMAIN_0 + milliSeconds)) : ('00' + milliSeconds);
  return `${ year }-${ month }-${ day }·${ hours }:${ minutes }:${ seconds }.${ milliSeconds }·`;
}