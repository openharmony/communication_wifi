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
import prompt from '@system.prompt';
import wifi from '@ohos.wifi'

import { PageTitle } from '../../Component/pageTitle';
import Router from '@system.router';
import mediaquery from '@ohos.mediaquery';
// @ts-ignore
import parameter from '@ohos.systemparameter';
import { TabletTitle , BrowserTabs , WebTab } from '../../Component/webTitleBar';
import { PhoneLayout } from '../../Component/phoneLayout';
import { Browser , LoadingStatus } from '../../entryability/model/bowser';
import ConfigData from '../../utils/ConfigData';
import { ConfigData } from '../../utils/ConfigData';
import fs from '@ohos.file.fs';
import http from '@ohos.net.http';

const TAG = '[webLatencyTest]';

/**
 * wifi Found Test Page Of Wifi test
 */
@Entry
@Component
struct webLatencyTest {
  private testItem : TestData = Router.getParams().testId;
  @State isPhone : boolean = true;
  @State testNumbers : Number = 30 //测试次数
  @State openWebNumbers : Number = 0 // 打开Web的次数
  @State closeWebNumbers : Number = 0 // 关闭Web的次数
  @State openSuccessNumbers : Number = 0;
  @State openFailNumbers : Number = 0;
  @State progressStatus : Number = 0;
  @State browser : Browser = new Browser();
  @StorageLink( "pageCostTime" ) pageCostTime : number = 0
  @StorageLink( "pathDir" ) pathDir : string = ""
  @State addr : string = "www.baidu.com"
  @State filePath : string = ""
  private isInit : Boolean = false;
  @State pairedSsid : string = "";
  @State wifiConnectionMessage : String = ""
  @State webLoopState : Boolean = true
  @State webMessage : String = ""
  @State webMessageLog : String = ""
  @State requestStartTime : Number = 0
  @State requestEndTime : Number = 0
  @State requestCostTime : Number = 0
  @State file : fs.File = null
  @State fileData : string = "";
  listener = mediaquery.matchMediaSync( '(orientation:landscape)' );

  async openLogFile() {
    let time : number = new Date().getTime()
    let currentTime : string = timestampToDate( time )
    console.log( TAG , "当前时间: " + currentTime )
    this.filePath = this.pathDir + ( "/" + currentTime + ".txt" );
    console.log( TAG , "沙箱路径为: " + this.filePath )
    this.file = fs.openSync( this.filePath , fs.OpenMode.READ_WRITE | fs.OpenMode.CREATE );
    AppStorage.setOrCreate( "fsFile" , this.file )
    AppStorage.setOrCreate( "openWebNumbers" , this.openWebNumbers )
    console.log( TAG , "数据文件的沙箱路径为: " + this.filePath )
    console.log( TAG , "file fd: " + this.file.fd );
  }

  aboutToAppear() {
    try {
      let deviceType = parameter.getSync( "const.build.characteristics" );
      console.log( TAG , "deviceType：" + deviceType )
      if( deviceType === 'default' ) {
        this.isPhone = true;
      }
    } catch( e ) {
      console.log( TAG , `getSync unexpected error: ${ e }` );
    }
    console.log( TAG , "aboutToAppear" )
    let wifiState = wifi.isConnected()
    console.log( TAG , "aboutToAppear,isConnected:" + wifiState )
    if( wifiState ) {
      this.wifiConnectionMessage = "connected";
      wifi.getLinkedInfo( ( err , data ) => {
        if( err ) {
          console.log( TAG , "get linked info error" );
        }
        let linkedInfoMessage = JSON.stringify( data )
        console.log( TAG , "aboutToAppear, linkedInfo:" + linkedInfoMessage )
        this.pairedSsid = data.ssid
        AppStorage.SetOrCreate( "pairedSsid" , this.pairedSsid )
      } )
    } else {
      this.wifiConnectionMessage = "disconnected";
      prompt.showToast( { message : 'wifi还未连接，请先连接WiFi' } )
    }
    this.filePath = this.pathDir + ( "/loadlog.txt" );
    console.log( TAG , "沙箱路径为: " + this.filePath )
    this.file = fs.openSync( this.filePath , fs.OpenMode.READ_WRITE | fs.OpenMode.CREATE );
    AppStorage.setOrCreate( "fsFile" , this.file )
    AppStorage.setOrCreate( "openWebNumbers" , this.openWebNumbers )
    console.log( TAG , "数据文件的沙箱路径为: " + this.filePath )
    console.log( TAG , "file fd: " + this.file.fd );
  }

  aboutToDisappear() {
  }

  build() {
    Column() {
      Stack( { alignContent : Alignment.TopStart } ) {
        // TestImageDisplay( { testItem : this.testItem } )
        PageTitle( { testItem : this.testItem } )
      }

      Stack().height( "0.5vp" ).backgroundColor( "#000000" );

      Column() {
        Text( "WiFi连接情况：" + this.wifiConnectionMessage )
          .fontSize( "17vp" )
          .margin( { top : "8vp" , bottom : "4vp" , left : "15vp" } )
          .textAlign( TextAlign.Start )
          .width( ConfigData.WH_100_100 )
        Text( "已连接的WiFi：" + this.pairedSsid )
          .fontSize( "17vp" )
          .margin( { top : "4vp" , bottom : "8vp" , left : "15vp" } )
          .textAlign( TextAlign.Start )
          .width( ConfigData.WH_100_100 )
        Row() {
          Text( "测试次数:" )
            .fontSize( "17vp" )
            .width( "25%" )
            .margin( { top : "8vp" , bottom : "8vp" , left : "5vp" } )
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

        TabletTitle( { browser : $browser } )

        Column() {
          Row() {
            Button( "开始web测试" )
              .operateButtonStyle( $r( 'app.color.main_blue' ) )
              .align( Alignment.Center )
              .onClick( async( event : ClickEvent ) => {
                console.log( TAG , "start web test-------------" )
                let self = this
                self.webLoopState = true
                self.openWebNumbers = 0
                self.openSuccessNumbers = 0
                self.openFailNumbers = 0
                await this.openLogFile()

                async function forLoop() {
                  self.stateMessageLog = ""
                  let funcMessage = "" // 函数信息
                  for( self.openWebNumbers ; self.openWebNumbers < self.testNumbers ; self.openWebNumbers ++ ) {
                    if( !self.webLoopState ) {
                      console.log( TAG , "web测试结束------------" )
                      self.openWebNumbers = 0
                      AppStorage.SetOrCreate( "openWebNumbers" , self.openWebNumbers )
                      break;
                    } else {
                      console.log( TAG , "测试开始--------" )
                      console.log( TAG , "self.addr:" , self.addr )
                      AppStorage.setOrCreate( "openWebNumbers" , self.openWebNumbers )
                      let time1 : number = new Date().getTime()
                      let currentTime1 : string = timestampToDateFormat( time1 )
                      self.fileData = currentTime1 + " 第" + ( self.openWebNumbers + 1 ) + "次网页测试开始! Start loading website" + "\n"
                      self.fileData += currentTime1 + " nextWebUrl: " + self.addr + "\n"
                      self.fileData += currentTime1 + " loadUrl: " + self.addr + "\n"
                      fs.writeSync( self.file.fd , self.fileData );

                      let httpRequest = http.createHttp();
                      self.requestStartTime = new Date().getTime()
                      console.time( "request" )
                      httpRequest.request( "www.baidu.com" , ( err : Error , data : http.HttpResponse ) => {
                        if( !err ) {
                          console.log( TAG , 'Result:' + data.result );
                          console.log( TAG , 'code:' + data.responseCode );
                          console.log( TAG , 'header:' + JSON.stringify( data.header ) );
                          console.log( TAG , 'cookies:' + data.cookies );
                          console.timeEnd( "request" )
                          self.requestEndTime = new Date().getTime()
                          self.requestCostTime = self.requestEndTime - self.requestStartTime
                          let time2 : number = new Date().getTime()
                          let currentTime2 : string = timestampToDateFormat( time2 )
                          self.fileData = currentTime2 + " 第" + ( self.openWebNumbers + 1 ) + "次http request的耗时： " + self.requestCostTime + "ms" + "\n"
                          fs.writeSync( self.file.fd , self.fileData );
                        } else {
                          console.log( TAG , 'error:' + JSON.stringify( err ) );
                        }
                      } );
                      self.browser.loadUrl( self.addr )
                      await sleep( 10 )
                      self.openSuccessNumbers ++
                      self.browser.loadUrl( {
                        url : $rawfile( 'phone.html' )  // pad.html
                      } )
                      console.log( TAG , "第" + ( self.openWebNumbers + 1 ) + "次测试结束--------" )
                      let time3 : number = new Date().getTime()
                      let currentTime3 : string = timestampToDateFormat( time3 )
                      self.fileData = currentTime3 + " 第" + ( self.openWebNumbers + 1 ) + "次网页测试结束! ------------" + "\n"
                      fs.writeSync( self.file.fd , self.fileData );
                      AppStorage.SetOrCreate( "openWebNumbers" , self.openWebNumbers )
                      await sleep( 5 )
                    }

                  }
                  console.log( TAG , "测试结束 -------------" )
                  fs.closeSync( self.file );
                  AppStorage.SetOrCreate( "openWebNumbers" , self.openWebNumbers )
                  self.webMessageLog = ""
                }

                forLoop()

              } )

            Blank().width( "10%" )

            Button( "关闭Web测试" )
              .operateButtonStyle( $r( 'app.color.main_blue' ) )
              .align( Alignment.Center )
              .onClick( async( event : ClickEvent ) => {
                let self = this
                self.webLoopState = false
                console.log( TAG , "准备测试停止 -------------" )
                self.openWebNumbers = 0
                AppStorage.SetOrCreate( "openWebNumbers" , self.openWebNumbers )
                self.webMessageLog = ""
                fs.closeSync( self.file );
              } )
          }
        }.width( "100%" ).backgroundColor( '#F5F5F5' ).padding( { top : " 5vp" } )


        Column() {
          Column() {
            Text( "测试结果：" )
              .fontSize( "18vp" )
              .width( ConfigData.WH_95_100 )
              .align( Alignment.TopStart )
              .padding( { top : " 5vp" } )
            Scroll() {
              Column() {
                Text( "测试次数：" + this.testNumbers )
                  .fontSize( "18vp" )
                  .margin( { top : "3vp" , left : "5vp" , right : "5vp" } )
                  .textAlign( TextAlign.Start )
                  .width( ConfigData.WH_95_100 )
                Text( "打开web的成功次数：" + this.openSuccessNumbers )
                  .fontSize( "18vp" )
                  .margin( { top : "3vp" , left : "5vp" , right : "5vp" } )
                  .textAlign( TextAlign.Start )
                  .width( ConfigData.WH_95_100 )
                Text( "打开web的失败次数：" + this.openFailNumbers )
                  .fontSize( "18vp" )
                  .margin( { top : "3vp" , left : "5vp" , right : "5vp" } )
                  .textAlign( TextAlign.Start )
                  .width( ConfigData.WH_95_100 )
                Text( "测试进度状态：" + this.browser.progress + " %" )
                  .fontSize( "18vp" )
                  .margin( { top : "3vp" , left : "5vp" , right : "5vp" } )
                  .textAlign( TextAlign.Start )
                  .width( ConfigData.WH_95_100 )
                Text( "httpRequest耗时：" + this.requestCostTime + " ms" )
                  .fontSize( "18vp" )
                  .margin( { top : "3vp" , left : "5vp" , right : "5vp" } )
                  .textAlign( TextAlign.Start )
                  .width( ConfigData.WH_95_100 )
                Text( "数据文件沙箱路径：" + this.filePath )
                  .fontSize( "18vp" )
                  .margin( { top : "3vp" , left : "5vp" , right : "5vp" } )
                  .textAlign( TextAlign.Start )
                  .width( ConfigData.WH_95_100 )
              }
              .width( ConfigData.WH_95_100 )
              .backgroundColor( $r( "sys.color.ohos_id_color_foreground_contrary" ) )
            }
            .scrollBarWidth( 10 )
            .scrollBar( BarState.Auto )
          }
          .width( ConfigData.WH_100_100 )
        }
        .height( ConfigData.WH_60_100 )
        .width( ConfigData.WH_100_100 )
      }
      .width( ConfigData.WH_100_100 )
      .height( ConfigData.WH_60_100 )

      Column() {
        if( this.isPhone ) {
          Progress( { value : this.browser.progress , total : 100 } )
            .color( '#0000ff' )
            .visibility( this.browser.hideProgress ? Visibility.None : Visibility.Visible )
          BrowserTabs( { browser : $browser } )
          Divider().color( '#c6c6c6' ).width( '100%' ).flexShrink( 0 )
          WebTab( { browser : $browser , isPhone : $isPhone } )
        } else {
          PhoneLayout( { browser : $browser } )
        }
      }
      .width( ConfigData.WH_100_100 )
      .height( ConfigData.WH_35_100 )

    }
    .width( ConfigData.WH_100_100 )
    .height( ConfigData.WH_100_100 )
    .backgroundColor( '#F5F5F5' )
  }

  orientationCallback( result ) {
    if( !this.isInit ) {
      if( result.matches ) {
        this.isPhone = false;
      } else {
        this.isPhone = true;
      }
      this.isInit = true;
    }
    console.log( TAG , `orientationCallback end,isPhone=${ this.isPhone }` );
  }

  onBackPress() : boolean {
    console.log( TAG , `enter onBackPress` );
    if( this.browser.webControllerArray[ this.browser.tabArrayIndex ].controller.accessBackward() ||
      this.browser.loadingStatus === LoadingStatus.LOADING ) {
      this.browser.webControllerArray[ this.browser.tabArrayIndex ].controller.backward();
      return true;
    }

    return false;
  }

  onDeviceChange() {
    this.browser = new Browser();
  }
}

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

export function timestampToDate( timestamp : number ) : string {
  const date = new Date(timestamp);
  let year = date.getFullYear();
  let month : string | number = date.getMonth() + 1;
  month = month >= 10 ? month : ( '0' + month );
  let day : string | number = date.getDate();
  day = day >= 10 ? day : ( '0' + day );
  let hours : string | number = date.getHours();
  hours = hours >= 10 ? hours : ( '0' + hours );
  let minutes : string | number = date.getMinutes();
  minutes = minutes >= 10 ? minutes : ( '0' + minutes );
  let seconds : string | number = date.getSeconds();
  seconds = seconds >= 10 ? seconds : ( '0' + seconds );
  return `${ year }${ month }${ day }_${ hours }${ minutes }${ seconds }`;
}

export function timestampToDateFormat( timestamp : number ) : string {
  const date = new Date(timestamp);
  let year = date.getFullYear();
  let month : string | number = date.getMonth() + 1;
  month = month >= 10 ? month : ( '0' + month );
  let day : string | number = date.getDate();
  day = day >= 10 ? day : ( '0' + day );
  let hours : string | number = date.getHours();
  hours = hours >= 10 ? hours : ( '0' + hours );
  let minutes : string | number = date.getMinutes();
  minutes = minutes >= 10 ? minutes : ( '0' + minutes );
  let seconds : string | number = date.getSeconds();
  seconds = seconds >= 10 ? seconds : ( '0' + seconds );
  let milliSeconds : string | number = date.getMilliseconds();
  milliSeconds = milliSeconds >= 10 ? ( milliSeconds >= 100 ? milliSeconds : ( '0' + milliSeconds ) ) : ( '00' + milliSeconds );
  return `${ year }-${ month }-${ day }·${ hours }:${ minutes }:${ seconds }.${ milliSeconds }·`;
}