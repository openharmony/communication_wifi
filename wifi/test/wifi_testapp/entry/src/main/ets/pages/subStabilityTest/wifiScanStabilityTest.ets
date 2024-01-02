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
import { ContentTable } from '../../Component/contentTable';
import Router from '@system.router';
import ConfigData from '../../Utils/ConfigData';
import { initWifiApiData } from '../../entryability/model/testDataModels'
import { TestData } from '../../entryability/model/testData'
import wifi from '@ohos.wifi';
import wifiManager from '@ohos.wifiManager';
import prompt from '@system.prompt';

/**
 * WiFiScanStabilityTest Page Of wifi test
 */
const TAG = '[WiFiScanStabilityTest]'

@Entry
@Component
struct WiFiScanStabilityTest {
  private testItem : TestData = Router.getParams().testId;
  @State scan_StartTime : Number = 0
  @State scan_EndTime : Number = 0
  @State scan_SpendTime : Number = 0
  @State stop_StartTime : Number = 0
  @State stop_EndTime : Number = 0
  @State stop_SpendTime : Number = 0
  @State openScanNumber : Number = 0
  @State openScanSuccessNumber : Number = 0
  @State openScanFailNumber : Number = 0
  @State scanInfo : String = 0
  @State message : string = "测试结果"
  @State testNumbers : Number = 30 //测试次数
  @State successTimes : Number = 0
  @State failTimes : Number = 0
  @State scanStateMessage : String = ""
  @State scanStateMessageLog : String = ""
  @State scanLoopState : Boolean = true

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
          TextInput( { placeholder : "请输入循环次数，默认30" } )
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
              Text( "scan的成功次数：" + this.openScanSuccessNumber )
                .fontSize( "18vp" )
                .margin( { top : "5vp" , left : "10vp" , right : "5vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "scan的失败次数：" + this.openScanFailNumber )
                .fontSize( "18vp" )
                .margin( { top : "5vp" , left : "10vp" , right : "5vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "scan的扫描个数：" + this.scanInfo )
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
            .padding( { top : "10vp" } )
          List() {
            ListItem() {
              Text( this.scanStateMessageLog )
                .fontSize( "18vp" )
                .margin( { top : "5vp" , left : "10vp" , right : "5vp" } )
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
          Button( "开始扫描测试" )
            .operateButtonStyle( $r( 'app.color.main_blue' ) )
            .padding( { right : "10vp" } )
            .onClick( async( event : ClickEvent ) => {
              console.log( TAG , "start scan test-------------" )
              let self = this
              self.scanLoopState = true
              self.openScanNumber = 0
              self.openScanSuccessNumber = 0
              self.openScanFailNumber = 0

              async function forLoop() {
                self.scanStateMessageLog = ""
                self.onWifiScanState()
                wifiManager.setScanAlwaysAllowed( false )
                let funcMessage = ""
                funcMessage = wifiManager.getScanAlwaysAllowed
                console.log( TAG , "getScanAlwaysAllowed:" + funcMessage )
                for( self.openScanNumber ; self.openScanNumber < self.testNumbers ; self.openScanNumber ++ ) {
                  if( !self.scanLoopState ) {
                    console.log( TAG , "测试结束------------" )
                    break;
                  } else {
                    let wifiState = wifiManager.isWifiActive()
                    if( !wifiState ) {
                      wifi.enableWifi()
                      console.log( TAG , "wifi当前未使能，已经使能，正常开始测试------" )
                    } else {
                      console.log( TAG , "wifi当前使能，正常开始测试------" )
                    }
                    await sleep( 3 )

                    funcMessage = wifi.scan()
                    self.scan_StartTime = new Date().getTime()
                    console.log( TAG , "第" + ( self.openScanNumber + 1 ) + "次WIFI使能-----" )
                    console.log( TAG , "第" + ( self.openScanNumber + 1 ) + "次WIFI使能开始时间: " + self.scan_StartTime + "ms" )
                    self.scanStateMessageLog += "第" + ( self.openScanNumber + 1 ) + "次WIFI扫描接口的调用结果：" + funcMessage + "\n"
                    console.log( TAG , "第" + ( self.openScanNumber + 1 ) + "次WIFI扫描接口的调用结果：" + funcMessage )
                    await sleep( 10 )
                    self.scanStateMessage = AppStorage.Get( "scanStateMessage" )
                    if( self.scanStateMessage == "scan success" ) {
                      self.scan_SpendTime = self.scan_EndTime - self.scan_StartTime
                      self.scanStateMessageLog += "第" + ( self.openScanNumber + 1 ) + "次WIFI扫描耗时: " + self.scan_SpendTime + "ms" + "\n"
                      self.scanStateMessageLog += "第" + ( self.openScanNumber + 1 ) + "次WIFI扫描结果个数: " + self.scanInfo + "\n"
                      console.log( TAG , "第" + ( self.openScanNumber + 1 ) + "次WIFI扫描耗时: " + self.scan_SpendTime + "ms" )
                      self.openScanSuccessNumber = self.openScanSuccessNumber + 1
                      self.scanStateMessageLog += "扫描成功的次数：" + self.openScanSuccessNumber + "\n"
                      console.log( TAG , "扫描成功的次数：" + self.openScanSuccessNumber )
                      await sleep( 10 )
                      self.scanStateMessage = AppStorage.Get( "scanStateMessage" )
                    } else if( self.scanStateMessage == "scan fail" ) {
                      self.openScanFailNumber = self.openScanFailNumber + 1
                      console.log( TAG , "扫描失败的次数：" + self.openScanFailNumber )
                      console.log( TAG , "第" + ( self.openScanNumber + 1 ) + "次WIFI扫描失败" )
                      break;
                    } else {
                      console.log( "第" + ( self.openScanNumber + 1 ) + "次扫描后状态不清楚" );
                      break;
                    }
                  }
                }
                console.log( TAG , "测试结束 -------------" )
              }

              forLoop()

            } )

          Blank().width( "10%" )

          Button( "关闭扫描测试" )
            .operateButtonStyle( $r( 'app.color.main_blue' ) )
            .padding( { right : "10vp" } )
            .onClick( async( event : ClickEvent ) => {
              let self = this
              self.scanLoopState = false
              console.log( TAG , "准备测试停止 -------------" )
              self.scanStateMessageLog = ""
              self.openScanNumber = 0
            } )
        }

      }.width( "100%" ).height( "25%" ).backgroundColor( $r( "app.color.lead" ) )

    }.height( "100%" ).width( "100%" ).backgroundColor( $r( "app.color.lead" ) )
  }

  onWifiScanState() {
    console.log( TAG , "on.wifiScanStateChange start--------" )
    wifi.on( "wifiScanStateChange" , ( number ) => {
      console.log( TAG , " on.wifiScanStateChange success--------" )
      let wifiScanStateMessage = ""
      switch( number ) {
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
      console.log( TAG , "WiFi扫描状态为:" + wifiScanStateMessage )
      if( number == 1 ) {
        // 打时间戳
        this.scan_EndTime = new Date().getTime()
        console.log( TAG , "WIFI扫描成功时间: " + this.scan_EndTime + "ms" )
        this.scanInfo = wifiManager.getScanResultsSync().length
        console.log( TAG , "WIFI扫描结果个数: " + this.scanInfo + "; WIFI扫描结果个数: " + JSON.stringify( wifiManager.getScanResultsSync() ) )
      } else {
        console.log( TAG , "WIFI扫描还未成功------" )
      }
      console.log( TAG , " on.wifiScanStateChange  callback success --------" )
      prompt.showToast( { message : "wifiScan状态: " + wifiScanStateMessage } )
      this.scanStateMessage = wifiScanStateMessage
      AppStorage.SetOrCreate( "scanStateMessage" , this.scanStateMessage )
      console.log( TAG , " on.wifiStateChange callback end--------" )
      return this.scanStateMessage
    } )
  }

  aboutToDisappear() {
    wifi.off( "wifiScanStateChange" )
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