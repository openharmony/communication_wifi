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
 * WiFiConnectStabilityTest Page Of wifi test
 */
const TAG = '[WiFiConnectStabilityTest]'

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
  @State connectNumber: number = 0 // 打开WiFi的次数
  @State disconnectNumber: number = 0 // 关闭WiFi的次数
  @State connectSuccessNumber: number = 0 // 打开WiFi的成功次数
  @State connectFailNumber: number = 0 // 打开WiFi的失败次数
  @State disconnectSuccessNumber: number = 0 // 关闭WiFi的成功次数
  @State disconnectFailNumber: number = 0 // 关闭WiFi的失败次数
  @State message: string = "测试结果"
  @State testNumbers: number = 30 //测试次数
  @State successTimes: number = 0
  @State failTimes: number = 0
  @State connectionMessage: string = ""
  @State connectionMessageLog: string = ""
  @State connectionLoopState: Boolean = true
  @State showList: boolean = false;
  @State ipInfo: number = 0
  @StorageLink('wifiConfig') wifiConfig: wifiManager.WifiDeviceConfig = {
    ssid : "TP-LINK_6365" ,
    preSharedKey : "12345678" ,
    securityType : 3 ,
  }

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
          TextInput({ placeholder : "请输入循环次数，默认为30" })
            .placeholderColor(Color.Grey)
            .placeholderFont({ size : $r('app.float.font_16') })
            .caretColor(Color.Blue)
            .width(ConfigData.WH_50_100)
            .fontSize($r('app.float.font_16'))
            .fontColor($r('app.color.title_black_color'))
            .onChange((value: string) => {
              this.testNumbers = parseInt(value);
            })
          Image($r('app.media.Switch'))
            .height(50)
            .padding({ top : 5 , bottom : 5 , left : 5 })
            .width(ConfigData.WH_15_100)
            .onClick(() => {
              this.showList = !this.showList;
            })
        }
      }.width(ConfigData.WH_100_100).height(ConfigData.WH_6_100).backgroundColor($r("app.color.lead"))

      if ( this.showList ) {
        setWifiDevice()
      } else {
        Column() {

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
                Text("连接的成功次数：" + this.connectSuccessNumber)
                  .fontSize("18vp")
                  .margin({ top : "5vp" , left : "10vp" , right : "5vp" })
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_90_100)
                Text("连接的失败次数：" + this.connectFailNumber)
                  .fontSize("18vp")
                  .margin({ top : "5vp" , left : "10vp" , right : "5vp" })
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_90_100)
                Text("断连的成功次数：" + this.disconnectSuccessNumber)
                  .fontSize("18vp")
                  .margin({ top : "5vp" , left : "10vp" , right : "5vp" })
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_90_100)
                Text("断连的失败次数：" + this.disconnectFailNumber)
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

          }.width(ConfigData.WH_100_100).height(ConfigData.WH_35_100)

          Column() {
            Text("log显示：")
              .fontSize("22vp")
              .width(ConfigData.WH_95_100)
              .align(Alignment.TopStart)
              .padding({ top : "10vp" })
            List() {
              ListItem() {
                Text(this.connectionMessageLog)
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
        }.width(ConfigData.WH_100_100).height(ConfigData.WH_60_100).backgroundColor($r("app.color.lead"))

        Stack().height("1vp").backgroundColor($r("app.color.black"));

        Column() {
          Row() {
            Button("开始连接测试")
              .operateButtonStyle($r('app.color.main_blue'))
              .padding({ right : "10vp" })
              .onClick(async(event: ClickEvent) => {
                console.log(TAG , "start WiFiConnect test-------------")
                await this.forLoop()
              })

            Blank().width(ConfigData.WH_10_100)

            Button("关闭连接测试")
              .operateButtonStyle($r('app.color.main_blue'))
              .padding({ right : "10vp" })
              .onClick(async(event: ClickEvent) => {
                this.connectionLoopState = false
                console.log(TAG , "准备测试停止 -------------")
                this.connectionMessageLog = ""
                this.connectNumber = 0
              })
          }
        }.width(ConfigData.WH_100_100).height(ConfigData.WH_25_100).backgroundColor($r("app.color.lead"))
      }
    }.height(ConfigData.WH_100_100).width(ConfigData.WH_100_100).backgroundColor($r("app.color.lead"))
  }

  onConnectionState() {
    console.log(TAG , "on.wifiConnectionChange start--------")
    wifi.on("wifiConnectionChange" , (number) => {
      console.log(TAG , " on.wifiConnectionChange --------")
      let wifiConnectionMessage = ""
      switch ( number ) {
        case 0:
          wifiConnectionMessage = "disconnected";
          break;
        case 1:
          wifiConnectionMessage = "connected";
          break;
        default:
          wifiConnectionMessage = '未知状态';
          break;
      }
      console.log(TAG , "wifi连接状态为:" + wifiConnectionMessage)
      if ( number == 1 ) {
        // 打时间戳
        this.connect_EndTime = new Date().getTime()
        console.log(TAG , "WIFI连接结束时间: " + this.connect_EndTime + "ms")
        this.ipInfo = wifiManager.getIpInfo().ipAddress
      } else if ( number == 0 ) {
        this.disconnect_EndTime = new Date().getTime()
        console.log(TAG , "WIFI断连结束时间: " + this.disconnect_EndTime + "ms")
        let removeMessage = wifi.removeAllNetwork()
        console.log(TAG , "移除网络配置接口的调用结果: " + removeMessage)
      }
      console.log(TAG , " on.wifiConnectionChange callback success --------")
      prompt.showToast({ message : "wifi连接状态: " + wifiConnectionMessage })
      this.connectionMessage = wifiConnectionMessage
      AppStorage.setOrCreate("connectionMessage" , this.connectionMessage)
      console.log(TAG , " on.wifiConnectionChange callback end--------")
      return this.connectionMessage
    })
  }

  aboutToDisappear() {
    wifi.off("wifiConnectionChange")
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
    this.onConnectionState() // 监听函数
    let funcMessage = false // 函数信息
    for ( this.connectNumber ; this.connectNumber < this.testNumbers ; this.connectNumber ++ ) {
      if ( !this.connectionLoopState ) {
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
        await sleep(3)

        wifiManager.connectToDevice(this.wifiConfig)
        // 打时间戳
        this.connect_StartTime = new Date().getTime()
        console.log(TAG , "第" + (this.connectNumber + 1) + "次WIFI连接-----")
        console.log(TAG , "第" + (this.connectNumber + 1) + "次WIFI连接开始时间: " + this.connect_StartTime + "ms")
        this.connectionMessageLog += "第" + (this.connectNumber + 1) + "次WIFI连接接口的调用" + "\n"
        console.log(TAG , "第" + (this.connectNumber + 1) + "次WIFI连接接口的调用")
        await sleep(15)
        this.connectionMessage = AppStorage.get("connectionMessage") ! //非空断言操作符
        // prompt.showToast( { message : funcMessage } )
        if ( this.connectionMessage == "connected" ) {
          this.connect_SpendTime = this.connect_EndTime - this.connect_StartTime
          this.connectionMessageLog += "第" + (this.connectNumber + 1) + "次WIFI连接耗时: " + this.connect_SpendTime + "ms; IP: " + this.ipInfo + "\n"
          console.log(TAG , "第" + (this.connectNumber + 1) + "次WIFI连接耗时: " + this.connect_SpendTime + "ms; IP: " + this.ipInfo)
          this.connectSuccessNumber = this.connectSuccessNumber + 1
          this.connectionMessageLog += "连接成功的次数：" + this.connectSuccessNumber + "\n"
          console.log(TAG , "连接成功的次数：" + this.connectSuccessNumber)
          funcMessage = wifi.disconnect()
          this.disconnectNumber = this.disconnectNumber + 1
          this.disconnect_StartTime = new Date().getTime()
          console.log(TAG , "第" + this.disconnectNumber + "次WIFI断连-----")
          console.log(TAG , "第" + this.disconnectNumber + "次WIFI断连开始时间: " + this.disconnect_StartTime + "ms")
          this.connectionMessageLog += "第" + this.disconnectNumber + "次WIFI断连接口的调用结果：" + funcMessage + "\n"
          console.log(TAG , "第" + this.disconnectNumber + "次WIFI断连接口的调用结果：" + funcMessage)
          console.log(TAG , "disconnectNumber: " + this.disconnectNumber)
          await sleep(15)
          // prompt.showToast( { message : funcMessage } )
          this.connectionMessage = AppStorage.get("connectionMessage") ! //非空断言操作符
          if ( this.connectionMessage == "disconnected" ) {
            this.disconnect_SpendTime = this.disconnect_EndTime - this.disconnect_StartTime
            this.connectionMessageLog += "第" + this.disconnectNumber + "次WIFI断连耗时: " + this.disconnect_SpendTime + "ms" + "\n"
            console.log(TAG , "第" + this.disconnectNumber + "次WIFI断连耗时: " + this.disconnect_SpendTime + "ms")
            this.disconnectSuccessNumber = this.disconnectSuccessNumber + 1
            this.connectionMessageLog += "断连成功的次数：" + this.disconnectSuccessNumber + "\n"
            console.log(TAG , "断连成功的次数：" + this.disconnectSuccessNumber)
            await sleep(15)
          } else {
            this.disconnectFailNumber = this.disconnectFailNumber + 1
            console.log(TAG , "断连失败的次数：" + this.disconnectFailNumber)
            console.log(TAG , "第" + this.disconnectNumber + "次WIFI断连失败")
          }
        } else if ( this.connectionMessage == "disconnected" ) {
          this.connectFailNumber = this.connectFailNumber + 1
          console.log(TAG , "连接失败的次数：" + this.connectFailNumber)
          console.log(TAG , "第" + (this.connectNumber + 1) + "次WIFI连接失败")
          break;
        } else {
          console.log("第" + (this.connectNumber + 1) + "次连接后状态不清楚");
          break;
        }
      }
    }
    console.log(TAG , "测试结束 -------------")
  }
}

@Component
struct setWifiDevice {
  @StorageLink('w_networkIdM') w_networkIdM: number = 0; // id,netId,networkId是一个值嘛？
  @StorageLink('w_featureIdM') w_featureIdM: number = 1;
  @StorageLink('wifiConfig') wifiConfig: wifiManager.WifiDeviceConfig = {
    ssid : "TP-LINK_6365" ,
    preSharedKey : "12345678" ,
    securityType : 3 ,
  }

  aboutToAppear() {

  }

  build() {
    Column() {
      Row() {
        Text("ssidM:").fontSize("18vp").width(70)
        TextInput({ text : this.wifiConfig.ssid , placeholder : "TP-LINK_6365" })
          .fontSize("15vp")
          .onChange((strInput: string) => {
            //判断合法性
            if ( strInput.length >= 1 ) {
              this.wifiConfig.ssid = strInput;
            }
          })
          .width(ConfigData.WH_80_100)
          .borderRadius(1)
      }
      .backgroundColor($r("app.color.moon"))
      .padding(5)
      .justifyContent(FlexAlign.Start)
      .alignItems(VerticalAlign.Center)

      Scroll() {
        Column() {
          Stack().height("0.25vp").backgroundColor("#000000");
          Column() {
            Row() {
              Text("preSharedKeyM:").fontSize("15vp").width(120);
              TextInput({ text : this.wifiConfig.preSharedKey , placeholder : "12345678" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiConfig.preSharedKey = strInput;
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("securityTypeM:").fontSize("15vp").width(110);
              Column() {
                Select([
                  { value : 'WIFI_SEC_TYPE_INVALID' },
                  { value : 'WIFI_SEC_TYPE_OPEN' },
                  { value : 'WIFI_SEC_TYPE_WEP' },
                  { value : 'WIFI_SEC_TYPE_PSK' },
                  { value : 'WIFI_SEC_TYPE_SAE' }
                ])
                  .selected(3)
                  .value('WIFI_SEC_TYPE_PSK')
                  .font({ size : 17 })
                  .selectedOptionFont({ size : 17 })
                  .optionFont({ size : 15 })
                  .width(ConfigData.WH_80_100)
                  .onSelect((index: number) => {
                    console.log(TAG , "Select:" + index)
                    this.wifiConfig.securityType = index;
                  })
              }
              .width(ConfigData.WH_80_100)
              .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
          }
          Stack().height("0.25vp").backgroundColor("#000000");
        }
      }
      .scrollBarWidth(10)
      .scrollBar(BarState.On)
    }
    .height(ConfigData.WH_58_100)
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