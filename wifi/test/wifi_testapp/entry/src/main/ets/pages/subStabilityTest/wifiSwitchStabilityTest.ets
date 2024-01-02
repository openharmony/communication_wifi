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

import { PageTitle } from '../../Component/pageTitle';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import Router from '@system.router';
import ConfigData from '../../Utils/ConfigData';
import { TestData } from '../../entryability/model/testData'
import wifi from '@ohos.wifi';
import wifiManager from '@ohos.wifiManager';
import prompt from '@system.prompt';

/**
 * WiFiSwitchStabilityTest Page Of wifi test
 */
const TAG = '[WiFiSwitchStabilityTest]'

@Entry
@Component
struct WiFiSwitchStabilityTest {
  private testItem : TestData = Router.getParams().testId;
  @State open_StartTime : Number = 0
  @State open_EndTime : Number = 0
  @State open_SpendTime : Number = 0
  @State close_StartTime : Number = 0
  @State close_EndTime : Number = 0
  @State close_SpendTime : Number = 0
  @State openWifiNumber : Number = 0 // 打开WiFi的次数
  @State closeWifiNumber : Number = 0 // 关闭WiFi的次数
  @State openSuccessNumber : Number = 0 // 打开WiFi的成功次数
  @State openFailNumber : Number = 0 // 打开WiFi的失败次数
  @State closeSuccessNumber : Number = 0 // 关闭WiFi的成功次数
  @State closeFailNumber : Number = 0 // 关闭WiFi的失败次数
  @State message : string = "测试结果:"
  @State testNumbers : Number = 30 //测试次数
  @State successTimes : Number = 0
  @State failTimes : Number = 0
  @State stateMessage : String = ""
  @State stateMessageLog : String = ""
  @State switchLoopState : Boolean = true

  build() {
    Column() {
      Stack( { alignContent : Alignment.TopStart } ) {
        TestImageDisplay( { testItem : this.testItem } )
        PageTitle( { testItem : this.testItem } )
      }

      Stack().height( "1vp" ).backgroundColor( $r( "app.color.black" ) );

      Column() {
        Row() {
          Text( "测试次数：" ).fontSize( $r( 'app.float.font_18' ) ).width( "25%" ).padding( { left : "10vp" } )
          TextInput( { placeholder : "请输入循环次数，默认为：30" } )
            .placeholderColor( Color.Grey )
            .placeholderFont( { size : $r( 'app.float.font_16' ) } )
            .caretColor( Color.Blue )
            .width( "70%" )
            .fontSize( $r( 'app.float.font_16' ) )
            .fontColor( $r( 'app.color.title_black_color' ) )
            .onChange( ( value : string ) => {
              this.testNumbers = parseInt( value );
            } )
        }

        Column() {
          Text( "测试结果：" )
            .fontSize( "22vp" )
            .width( ConfigData.WH_95_100 )
            .align( Alignment.TopStart )
            .padding( { top : "10vp" } )
          Scroll() {
            Column() {
              Text( "测试次数：" + this.testNumbers )
                .fontSize( "18vp" )
                .margin( { top : "5vp" , left : "10vp" , right : "5vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "打开WiFi的成功次数：" + this.openSuccessNumber )
                .fontSize( "18vp" )
                .margin( { top : "5vp" , left : "10vp" , right : "5vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "打开WiFi的失败次数：" + this.openFailNumber )
                .fontSize( "18vp" )
                .margin( { top : "5vp" , left : "10vp" , right : "5vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "关闭WiFi的成功次数：" + this.closeSuccessNumber )
                .fontSize( "18vp" )
                .margin( { top : "5vp" , left : "10vp" , right : "5vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "关闭WiFi的失败次数：" + this.closeFailNumber )
                .fontSize( "18vp" )
                .margin( { top : "5vp" , left : "10vp" , right : "5vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
            }
            .width( ConfigData.WH_95_100 )
            .backgroundColor( $r( "sys.color.ohos_id_color_foreground_contrary" ) )
          }
          .scrollBarWidth( 10 )
          .scrollBar( BarState.Auto )
        }.width( "100%" ).height( "30%" )

        Column() {
          Text( "log显示：" )
            .fontSize( "22vp" )
            .height( ConfigData.WH_15_100 )
            .width( ConfigData.WH_95_100 )
            .align( Alignment.TopStart )
            .padding( { top : "18vp" } )
          List() {
            ListItem() {
              Text( this.stateMessageLog )
                .fontSize( "18vp" )
                .margin( { top : "5vp" , left : "20vp" , right : "5vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
            }
          }
          .height( ConfigData.WH_83_100 )
          .width( ConfigData.WH_95_100 )
          .backgroundColor( $r( "sys.color.ohos_id_color_foreground_contrary" ) )
        }.width( ConfigData.WH_100_100 ).height( ConfigData.WH_60_100 )

      }.width( "100%" ).height( "67%" ).backgroundColor( $r( "app.color.lead" ) )

      Stack().height( "1vp" ).backgroundColor( $r( "app.color.black" ) );

      Column() {
        Row() {
          Button( "开始WiFi测试" )
            .operateButtonStyle( $r( 'app.color.main_blue' ) )
            .padding( { right : "10vp" } )
            .onClick( async( event : ClickEvent ) => {
              console.log( TAG , "start WiFiSwitch test-------------" )
              let self = this
              self.switchLoopState = true
              self.openWifiNumber = 0
              self.closeWifiNumber = 0
              self.openSuccessNumber = 0
              self.openFailNumber = 0
              self.closeSuccessNumber = 0
              self.closeFailNumber = 0

              async function forLoop() {
                self.stateMessageLog = ""
                self.onWifiState() // 监听函数
                let funcMessage = "" // 函数信息
                for( self.openWifiNumber ; self.openWifiNumber < self.testNumbers ; self.openWifiNumber ++ ) {
                  if( !self.switchLoopState ) {
                    self.openWifiNumber = 0;
                    console.log( TAG , "测试结束------------" )
                    break;
                  } else {
                    let wifiState = wifiManager.isWifiActive()
                    if( wifiState ) {
                      wifi.disableWifi()
                      console.log( TAG , "wifi当前已使能，已经去使能，正常开始测试------" )
                    } else {
                      console.log( TAG , "wifi当前未使能，正常开始测试------" )
                    }
                    await sleep( 3 )

                    funcMessage = wifi.enableWifi()
                    // 打时间戳
                    self.open_StartTime = new Date().getTime()
                    console.log( TAG , "第" + ( self.openWifiNumber + 1 ) + "次WIFI使能-----" )
                    console.log( TAG , "第" + ( self.openWifiNumber + 1 ) + "次WIFI使能开始时间: " + self.open_StartTime + "ms" )
                    self.stateMessageLog += "第" + ( self.openWifiNumber + 1 ) + "次WIFI使能接口的调用结果：" + funcMessage + "\n"
                    console.log( TAG , "第" + ( self.openWifiNumber + 1 ) + "次WIFI使能接口的调用结果：" + funcMessage )
                    await sleep( 15 )
                    self.stateMessage = AppStorage.Get( "stateMessage" )
                    // prompt.showToast( { message : funcMessage } )
                    if( self.stateMessage == "active" ) {
                      self.open_SpendTime = self.open_EndTime - self.open_StartTime
                      self.stateMessageLog += "第" + ( self.openWifiNumber + 1 ) + "次WIFI使能耗时: " + self.open_SpendTime + "ms" + "\n"
                      console.log( TAG , "第" + ( self.openWifiNumber + 1 ) + "次WIFI使能耗时: " + self.open_SpendTime + "ms" )
                      self.openSuccessNumber = self.openSuccessNumber + 1
                      self.stateMessageLog += "使能成功的次数：" + self.openSuccessNumber + "\n"
                      console.log( TAG , "使能成功的次数：" + self.openSuccessNumber )
                      funcMessage = wifi.disableWifi()
                      self.closeWifiNumber = self.closeWifiNumber + 1
                      self.close_StartTime = new Date().getTime()
                      console.log( TAG , "第" + self.closeWifiNumber + "次WIFI去使能-----" )
                      console.log( TAG , "第" + self.closeWifiNumber + "次WIFI去使能开始时间: " + self.close_StartTime + "ms" )
                      self.stateMessageLog += "第" + self.closeWifiNumber + "次WIFI去使能接口的调用结果：" + funcMessage + "\n"
                      console.log( TAG , "第" + self.closeWifiNumber + "次WIFI去使能接口的调用结果：" + funcMessage )
                      console.log( TAG , "closeWifiNumber: " + self.closeWifiNumber )
                      await sleep( 15 )
                      // prompt.showToast( { message : funcMessage } )
                      self.stateMessage = AppStorage.Get( "stateMessage" )
                      if( self.stateMessage == "inactive" ) {
                        self.close_SpendTime = self.close_EndTime - self.close_StartTime
                        self.stateMessageLog += "第" + self.closeWifiNumber + "次WIFI去使能耗时: " + self.close_SpendTime + "ms" + "\n"
                        console.log( TAG , "第" + self.closeWifiNumber + "次WIFI去使能耗时: " + self.close_SpendTime + "ms" )
                        self.closeSuccessNumber = self.closeSuccessNumber + 1
                        self.stateMessageLog += "去使能成功的次数：" + self.closeSuccessNumber + "\n"
                        console.log( TAG , "去使能成功的次数：" + self.closeSuccessNumber )
                        await sleep( 7 )
                      } else {
                        self.closeFailNumber = self.closeFailNumber + 1
                        console.log( TAG , "去使能失败的次数：" + self.closeFailNumber )
                        console.log( TAG , "第" + self.closeWifiNumber + "次WIFI去使能失败" )
                      }
                    } else if( self.stateMessage == "inactive" ) {
                      self.openFailNumber = self.openFailNumber + 1
                      console.log( TAG , "使能失败的次数：" + self.openFailNumber )
                      console.log( TAG , "第" + ( self.openWifiNumber + 1 ) + "次WIFI使能失败" )
                      break;
                    } else {
                      console.log( "第" + ( self.openWifiNumber + 1 ) + "次开wifi后状态不清楚" );
                      break;
                    }
                  }
                }
                console.log( TAG , "测试结束 -------------" )
              }

              forLoop()

            } )

          Blank().width( "10%" )

          Button( "关闭WiFi测试" )
            .operateButtonStyle( $r( 'app.color.main_blue' ) )
            .padding( { right : "10vp" } )
            .onClick( async( event : ClickEvent ) => {
              let self = this
              self.switchLoopState = false
              console.log( TAG , "准备测试停止 -------------" )
              self.stateMessageLog = ""
              self.openWifiNumber = 0
            } )
        }

      }.width( "100%" ).height( "25%" ).backgroundColor( $r( "app.color.lead" ) )

    }.height( "100%" ).width( "100%" ).backgroundColor( $r( "app.color.lead" ) )
  }

  onWifiState() {
    console.log( TAG , "on.wifiStateChange start--------" )
    wifi.on( "wifiStateChange" , ( number ) => {
      console.log( TAG , " on.wifiStateChange --------" )
      let wifiStateMessage = ""
      switch( number ) {
        case 0:
          wifiStateMessage = "inactive";
          break;
        case 1:
          wifiStateMessage = "active";
          break;
        case 2:
          wifiStateMessage = "activating";
          break;
        case 3:
          wifiStateMessage = "de-activating";
          break;
        default:
          wifiStateMessage = '未知状态';
          break;
      }
      console.log( TAG , "WiFi开关状态为:" + wifiStateMessage )
      if( number == 1 ) {
        // 打时间戳
        this.open_EndTime = new Date().getTime()
        console.log( TAG , "WIFI使能结束时间: " + this.open_EndTime + "ms" )
      } else if( number == 0 ) {
        this.close_EndTime = new Date().getTime()
        console.log( TAG , "WIFI去使能结束时间: " + this.close_EndTime + "ms" )
      }
      console.log( TAG , " on.wifiStateChange callback success --------" )
      prompt.showToast( { message : "wifi状态: " + wifiStateMessage } )
      this.stateMessage = wifiStateMessage
      AppStorage.SetOrCreate( "stateMessage" , this.stateMessage )
      console.log( TAG , " on.wifiStateChange callback end--------" )
      return this.stateMessage
    } )
  }

  aboutToDisappear() {
    wifi.off( "wifiStateChange" )
  }
}

/**
 * Custom button style.
 */
@Extend( Button )
function operateButtonStyle( color : Resource ) {
  .width( $r( 'app.float.button_width' ) )
  .height( $r( 'app.float.button_height' ) )
  .fontSize( $r( 'app.float.font_16' ) )
  .fontWeight( 500 )
  .fontColor( color )
  .backgroundColor( $r( 'app.color.button_background' ) )
}

function sleep( time ) {
  return new Promise(( resolve , reject ) => {
    setTimeout( () => {
      resolve()
    } , time * 1000 )
  })
}