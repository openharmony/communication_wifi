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
import { initWifiApiData } from '../../MainAbility/model/testDataModels'
import { TestData } from '../../MainAbility/model/testData'
import wifi from '@ohos.wifi';
import prompt from '@system.prompt';

/**
 * WiFiScanStabilityTest Page Of wifi test
 */
const TAG = '[WiFiScanStabilityTest]'

@Entry
@Component
struct WiFiScanStabilityTest {
  private testItem: TestData = Router.getParams().testId;
  @State message: string = "测试结果"
  @State testNumbers: Number = 30 //测试次数
  @State successTimes: Number = 0
  @State failTimes: Number = 0
  @State scanStateMessage: String = ""
  @State stateMessageLog: String = ""
  @State switchLoopState: Boolean = true

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
            .onChange( ( value: string ) => {
              this.testNumbers = Number( value );
            } )
        }

        Column() {
          Text( "测试结果：" )
            .fontSize( "22vp" )
            .width( '95%' )
            .align( Alignment.TopStart )
            .padding( { top : "10vp" } )
        }.width( "100%" ).height( "30%" )

        Column() {
          Text( "log显示：" )
            .fontSize( "22vp" )
            .width( '95%' )
            .align( Alignment.TopStart )
            .padding( { top : "10vp" } )
          List() {
            ListItem() {
              Text( this.stateMessageLog )
                .fontSize( "20vp" )
                .margin( { top : "5vp" , left : "30vp" , right : "10vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
            }
          }
          .height( ConfigData.WH_80_100 )
          .width( ConfigData.WH_90_100 )
          .backgroundColor( $r( "sys.color.ohos_id_color_foreground_contrary" ) )
        }.width( "100%" ).height( "60%" )

      }.width( "100%" ).height( "67%" ).backgroundColor( $r( "app.color.lead" ) )

      Stack().height( "1vp" ).backgroundColor( $r( "app.color.black" ) );

      Column() {
        Row() {
          Button( "开始扫描测试" )
            .operateButtonStyle( $r( 'app.color.main_blue' ) )
            .padding( { right : "10vp" } )
            .onClick( async( event: ClickEvent ) => {
              console.log( TAG , "start scan test-------------" )
              let self = this

              async function forLoop() {
                self.stateMessageLog = ""

                let openScanNumber = 0
                let closeScanNumber = 0
                self.onWifiScanState()
                let openSuccessNumber = 0
                let openFailNumber = 0
                let closeSuccessNumber = 0
                let closeFailNumber = 0
                let funcMessage = ""
                for ( openScanNumber ; openScanNumber < 30 ; openScanNumber ++ ) {
                  funcMessage = wifi.enableWifi()
                  self.stateMessageLog += "第" + ( openScanNumber + 1 ) + "次WIFI使能结果：" + funcMessage + "\n"
                  console.log( TAG , "第" + ( openScanNumber + 1 ) + "次WIFI使能结果：" + funcMessage )
                  await sleep( 3 )

                  funcMessage = wifi.scan()
                  self.stateMessageLog += "第" + ( openScanNumber + 1 ) + "次WIFI扫描结果：" + funcMessage + "\n"
                  console.log( TAG , "第" + ( openScanNumber + 1 ) + "次WIFI扫描结果：" + funcMessage )
                  await sleep( 5 )
                  self.scanStateMessage = AppStorage.Get( "scanStateMessage" )
                  console.log( TAG , "scanStateMessage：" + self.scanStateMessage )
                  // prompt.showToast( { message : funcMessage } )
                  if ( self.scanStateMessage == "scan success" ) {
                    openSuccessNumber = openSuccessNumber + 1
                    self.stateMessageLog += "扫描成功的次数：" + openSuccessNumber + "\n"
                    console.log( TAG , "扫描成功的次数：" + openSuccessNumber )
                    funcMessage = wifi.disableWifi()
                    self.stateMessageLog += "第" + ( closeScanNumber + 1 ) + "次WIFI去使能结果：" + funcMessage + "\n"
                    console.log( TAG , "第" + ( closeScanNumber + 1 ) + "次WIFI去使能结果：" + funcMessage )
                    closeScanNumber = closeScanNumber + 1
                    await sleep( 5 )
                    // prompt.showToast( { message : funcMessage } )
                    self.scanStateMessage = AppStorage.Get( "scanStateMessage" )
                    if ( self.scanStateMessage == "scan fail" ) {
                      closeSuccessNumber = closeSuccessNumber + 1
                      self.stateMessageLog += "去使能成功的次数：" + openSuccessNumber + "\n"
                      console.log( TAG , "去使能成功的次数：" + openSuccessNumber )
                      await sleep( 3 )
                    } else {
                      closeFailNumber = closeFailNumber + 1
                    }
                  } else if ( self.scanStateMessage == "scan fail" ) {
                    openFailNumber = openFailNumber + 1
                    break;
                  } else {
                    console.log( "第" + m + "次开wifi后状态不清楚" );
                    break;
                  }
                }
              }

              forLoop()

            } )

          Button( "关闭WiFi测试" )
            .operateButtonStyle( $r( 'app.color.main_blue' ) )
            .padding( { right : "10vp" } )
            .onClick( async( event: ClickEvent ) => {
              let self = this
              self.switchLoopState = false
              console.log( TAG , "准备测试停止 -------------" )
              self.stateMessageLog = ""
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
      console.log( TAG , " on.wifiScanStateChange  callback success --------" )
      prompt.showToast( { message : "wifiScan状态: " + wifiScanStateMessage } )
      this.scanStateMessage = wifiScanStateMessage
      console.log( TAG , "wifiStateMessage:" + this.scanStateMessage )
      AppStorage.SetOrCreate( "scanStateMessage" , this.scanStateMessage )
      console.log( TAG , " on.wifiStateChange end--------" )
      return this.scanStateMessage
    } )
    return this.scanStateMessage
  }
}

/**
 * Custom button style.
 */
@Extend( Button ) function operateButtonStyle( color: Resource ) {
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