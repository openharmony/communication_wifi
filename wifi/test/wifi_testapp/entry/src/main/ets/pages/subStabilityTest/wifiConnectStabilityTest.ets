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
 * WiFiConnectStabilityTest Page Of wifi test
 */
const TAG = 'wifiTestApp [WiFiConnectStabilityTest]'

@Entry
@Component
struct WiFiConnectStabilityTest {
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State connect_StartTime: number = 0
  @State connect_EndTime: number = 0
  @State connect_SpendTime: number = 0
  @State disconnect_StartTime: number = 0
  @State disconnect_EndTime: number = 0
  @State disconnect_SpendTime: number = 0
  @State connectNumber: number = 0// 打开WiFi的次数
  @State disconnectNumber: number = 0// 关闭WiFi的次数
  @State connectSuccessNumber: number = 0// 打开WiFi的成功次数
  @State connectFailNumber: number = 0// 打开WiFi的失败次数
  @State disconnectSuccessNumber: number = 0// 关闭WiFi的成功次数
  @State disconnectFailNumber: number = 0// 关闭WiFi的失败次数
  @State message: string = ConfigData.STABILITY_STR_TEST_RESULT
  @State testNumbers: number = ConfigData.DEFAULT_TEST_LOOP_COUNT
  @State successTimes: number = 0
  @State failTimes: number = 0
  @State connectionMessage: string = ""
  @State connectionMessageLog: string = ""
  @State connectionLoopState: Boolean = true;
  @State showList: boolean = false;
  @State ipInfo: number = 0
  @StorageLink('wifiConfig') wifiConfig: wifiManager.WifiDeviceConfig = {
    ssid: ConfigData.QV_MOCK_SSID,
    preSharedKey: ConfigData.QV_MOCK_PRE_SHARED_KEY,
    securityType: 3,
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
          TextInput({placeholder: $r('app.string.wifitest_text_qsrxhcsmrw3')})
            .placeholderColor($r('app.color.color_999999_grey'))
            .placeholderFont({size: $r('app.float.font_16')})
            .caretColor($r('app.color.main_blue'))
            .width(ConfigData.WH_50_100)
            .fontSize($r('app.float.font_16'))
            .fontColor($r('app.color.title_black_color'))
            .onChange((value: string) => {
              this.testNumbers = parseInt(value);
            })
          Image($r('app.media.Switch'))
            .height(ConfigData.VP_50)
            .padding({top: ConfigData.VP_5, bottom: ConfigData.VP_5, left: ConfigData.VP_5})
            .width(ConfigData.WH_15_100)
            .onClick(() => {
              this.showList = !this.showList;
            })
        }
      }.width(ConfigData.WH_100_100).height(ConfigData.WH_6_100).backgroundColor($r("app.color.lead"))

      if (this.showList){
        setWifiDevice()
      } else {
        Column() {

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
                  Span($r('app.string.wifitest_text_wifi_connect_ok'))
                  Span('' + this.connectSuccessNumber)
                }
                  .fontSize(ConfigData.VP_18)
                  .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, right: ConfigData.VP_5})
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_90_100)
                Text() {
                  Span($r('app.string.wifitest_text_wifi_connect_fail'))
                  Span('' + this.connectFailNumber)
                }
                  .fontSize(ConfigData.VP_18)
                  .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, right: ConfigData.VP_5})
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_90_100)
                Text() {
                  Span($r('app.string.wifitest_text_wifi_disc_ok'))
                  Span('' + this.disconnectSuccessNumber)
                }
                  .fontSize(ConfigData.VP_18)
                  .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, right: ConfigData.VP_5})
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_90_100)
                Text() {
                  Span($r('app.string.wifitest_text_wifi_disc_fail'))
                  Span('' + this.disconnectFailNumber)
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

          }.width(ConfigData.WH_100_100).height(ConfigData.WH_35_100)

          Column() {
            Text($r('app.string.wifitest_text_lxs'))
              .fontSize(ConfigData.VP_22)
              .width(ConfigData.WH_95_100)
              .align(Alignment.TopStart)
              .padding({top: ConfigData.VP_10})
            List() {
              ListItem() {
                Text(this.connectionMessageLog)
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
        }.width(ConfigData.WH_100_100).height(ConfigData.WH_60_100).backgroundColor($r("app.color.lead"))

        Stack().height(ConfigData.VP_1).backgroundColor($r("app.color.black"));

        Column() {
          Row() {
            Button("开始连接测试")
              .operateButtonStyle($r('app.color.main_blue'))
              .padding({right: ConfigData.VP_10})
              .onClick(async(event: ClickEvent) => {
                hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "start WiFiConnect test-------------")
                this.startContinuousTask();
                await this.forLoop()
              })

            Blank().width(ConfigData.WH_10_100)

            Button("关闭连接测试")
              .operateButtonStyle($r('app.color.main_blue'))
              .padding({right: ConfigData.VP_10})
              .onClick(async(event: ClickEvent) => {
                this.connectionLoopState = false
                hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "准备测试停止 -------------")
                this.connectionMessageLog = ""
                this.connectNumber = 0;
                this.stopContinuousTask();
              })
          }
        }.width(ConfigData.WH_100_100).height(ConfigData.WH_25_100).backgroundColor($r("app.color.lead"))
      }
    }.height(ConfigData.WH_100_100).width(ConfigData.WH_100_100).backgroundColor($r("app.color.lead"))
  }

  onConnectionState() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "on.wifiConnectionChange start--------")
    wifiManager.on("wifiConnectionChange", (number) => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, " on.wifiConnectionChange --------")
      let wifiConnectionMessage = ""
      switch (number){
        case 0: wifiConnectionMessage = "disconnected";
          break;
        case 1: wifiConnectionMessage = "connected";
          break;
        default: wifiConnectionMessage = '未知状态';
          break;
      }
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "wifi连接状态为:" + wifiConnectionMessage)
      if (number == 1){
        // 打时间戳
        this.connect_EndTime = new Date().getTime()
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "WIFI连接结束时间: " + this.connect_EndTime + "ms")
        this.ipInfo = wifiManager.getIpInfo().ipAddress
      } else if (number == 0){
        this.disconnect_EndTime = new Date().getTime()
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "WIFI断连结束时间: " + this.disconnect_EndTime + "ms")
        let removeMessage = wifiManager.removeAllNetwork()
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "移除网络配置接口的调用结果: " + removeMessage)
      }
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, " on.wifiConnectionChange callback success --------")
      promptAction.showToast({message: "wifi连接状态: " + wifiConnectionMessage})
      this.connectionMessage = wifiConnectionMessage
      AppStorage.setOrCreate("connectionMessage", this.connectionMessage)
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, " on.wifiConnectionChange callback end--------")
      return this.connectionMessage
    })
  }

  aboutToDisappear() {
    wifiManager.off("wifiConnectionChange")
  }

  async forLoop() {
    this.connectionLoopState = true
    this.connectNumber = 0
    this.connectSuccessNumber = 0
    this.connectFailNumber = 0
    this.disconnectNumber = 0
    this.disconnectSuccessNumber = 0
    this.disconnectFailNumber = 0

    this.connectionMessageLog = ""
    this.onConnectionState()// 监听函数
    let funcMessage = false// 函数信息
    for(this.connectNumber ; this.connectNumber<this.testNumbers ; this.connectNumber++){
      if (!this.connectionLoopState){
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
        await sleep(3)

        wifiManager.connectToDevice(this.wifiConfig)
        // 打时间戳
        this.connect_StartTime = new Date().getTime()
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.connectNumber + 1) + "次WIFI连接-----")
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.connectNumber + 1) + "次WIFI连接开始时间: " + this.connect_StartTime + "ms")
        this.connectionMessageLog += "第" + (this.connectNumber + 1) + "次WIFI连接接口的调用" + "\n"
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.connectNumber + 1) + "次WIFI连接接口的调用")
        await sleep(15)
        this.connectionMessage = AppStorage.get("connectionMessage")!//非空断言操作符
        // promptAction.showToast( { message: funcMessage })
        if (this.connectionMessage == "connected"){
          this.connect_SpendTime = this.connect_EndTime - this.connect_StartTime
          this.connectionMessageLog += "第" + (this.connectNumber + 1) + "次WIFI连接耗时: " + this.connect_SpendTime + "ms; IP: " + this.ipInfo + "\n"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.connectNumber + 1) + "次WIFI连接耗时: " + this.connect_SpendTime + "ms; IP: " + this.ipInfo)
          this.connectSuccessNumber = this.connectSuccessNumber + 1
          this.connectionMessageLog += "连接成功的次数：" + this.connectSuccessNumber + "\n"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "连接成功的次数：" + this.connectSuccessNumber)
          // funcMessage = wifiManager.disconnect()
          this.disconnectNumber = this.disconnectNumber + 1
          this.disconnect_StartTime = new Date().getTime()
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.disconnectNumber + "次WIFI断连-----")
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.disconnectNumber + "次WIFI断连开始时间: " + this.disconnect_StartTime + "ms")
          this.connectionMessageLog += "第" + this.disconnectNumber + "次WIFI断连接口的调用结果：" + funcMessage + "\n"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.disconnectNumber + "次WIFI断连接口的调用结果：" + funcMessage)
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "disconnectNumber: " + this.disconnectNumber)
          await sleep(15)
          // promptAction.showToast( { message: funcMessage })
          this.connectionMessage = AppStorage.get("connectionMessage")!//非空断言操作符
          if (this.connectionMessage == "disconnected"){
            this.disconnect_SpendTime = this.disconnect_EndTime - this.disconnect_StartTime
            this.connectionMessageLog += "第" + this.disconnectNumber + "次WIFI断连耗时: " + this.disconnect_SpendTime + "ms" + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.disconnectNumber + "次WIFI断连耗时: " + this.disconnect_SpendTime + "ms")
            this.disconnectSuccessNumber = this.disconnectSuccessNumber + 1
            this.connectionMessageLog += "断连成功的次数：" + this.disconnectSuccessNumber + "\n"
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "断连成功的次数：" + this.disconnectSuccessNumber)
            await sleep(15)
          } else {
            this.disconnectFailNumber = this.disconnectFailNumber + 1
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "断连失败的次数：" + this.disconnectFailNumber)
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + this.disconnectNumber + "次WIFI断连失败")
          }
        } else if (this.connectionMessage == "disconnected"){
          this.connectFailNumber = this.connectFailNumber + 1
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "连接失败的次数：" + this.connectFailNumber)
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "第" + (this.connectNumber + 1) + "次WIFI连接失败")
        } else {
          hilog.info(0x1500, 'wifiTestApp', '%{public}s', "第" + (this.connectNumber + 1) + "次连接后状态不清楚");
        }
      }
    }
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "测试结束 -------------")
    this.stopContinuousTask();
  }
}

@Component
struct setWifiDevice {
  @StorageLink('w_networkIdM') w_networkIdM: number = 0;// id,netId,networkId是一个值嘛？
  @StorageLink('w_featureIdM') w_featureIdM: number = 1;
  @StorageLink('wifiConfig') wifiConfig: wifiManager.WifiDeviceConfig = {
    ssid: ConfigData.QV_MOCK_SSID,
    preSharedKey: ConfigData.QV_MOCK_PRE_SHARED_KEY,
    securityType: 3,
  }

  aboutToAppear() {

  }

  build() {
    Column() {
      Row() {
        Text($r('app.string.wifitest_text_s_3')).fontSize(ConfigData.VP_18).width(ConfigData.VP_70)
        TextInput({text: this.wifiConfig.ssid, placeholder: $r('app.string.wifitest_text_tl6')})
          .fontSize(ConfigData.VP_15)
          .onChange((strInput: string) => {
            //判断合法性
            if (strInput.length >= 1){
              this.wifiConfig.ssid = strInput;
            }
          })
          .width(ConfigData.WH_80_100)
          .borderRadius($r('app.float.wh_value_1'))
      }
      .backgroundColor($r("app.color.moon"))
      .padding(ConfigData.VP_5)
      .justifyContent(FlexAlign.Start)
      .alignItems(VerticalAlign.Center)

      Scroll() {
        Column() {
          Stack().height(ConfigData.VP_0_25).backgroundColor($r("app.color.black"));
          Column() {
            Row() {
              Text($r('app.string.wifitest_text_p_4')).fontSize(ConfigData.VP_15).width(ConfigData.VP_120);
              TextInput({text: this.wifiConfig.preSharedKey, placeholder: $r('app.string.wifitest_text_1_3')})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  //判断合法性
                  if (strInput.length >= 1){
                    this.wifiConfig.preSharedKey = strInput;
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius($r('app.float.wh_value_1'))
            }
            .backgroundColor($r("app.color.spring"))
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text($r('app.string.wifitest_text_s_7')).fontSize(ConfigData.VP_15).width(ConfigData.VP_110);
              Column() {
                Select([
                  { value: 'WIFI_SEC_TYPE_INVALID'},
                  { value: 'WIFI_SEC_TYPE_OPEN'},
                  { value: 'WIFI_SEC_TYPE_WEP'},
                  { value: 'WIFI_SEC_TYPE_PSK'},
                  { value: 'WIFI_SEC_TYPE_SAE'}
])
                  .selected(3)
                  .value('WIFI_SEC_TYPE_PSK')
                  .font({size: ConfigData.VP_17})
                  .selectedOptionFont({size: ConfigData.VP_17})
                  .optionFont({size: ConfigData.VP_15})
                  .width(ConfigData.WH_80_100)
                  .onSelect((index: number) => {
                    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "Select:" + index)
                    this.wifiConfig.securityType = index;
                  })
              }
              .width(ConfigData.WH_80_100)
              .borderRadius($r('app.float.wh_value_1'))
            }
            .backgroundColor($r("app.color.spring"))
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
          }

          Stack().height(ConfigData.VP_0_25).backgroundColor($r("app.color.black"));
        }
      }
      .scrollBarWidth(ConfigData.VP_10)
      .scrollBar(BarState.On)
    }
    .height(ConfigData.WH_58_100)
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