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

import prompt from '@ohos.prompt';
import router from '@system.router'
import { PageTitle } from '../../Component/pageTitle'
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { TestData } from '../../MainAbility/model/testData'
import { initWifiManagerBenchmarkData } from '../../MainAbility/model/scenarioTestDataModels'
import * as WifiManagerInterface from '../../MainAbility/model/wifiManagerInterface'
import { WifiManagerBenchmarkTestCase } from '../../MainAbility/model/benchmarkTestDataModels'
import ConfigData from "../../Utils/ConfigData"
import wifi from '@ohos.wifi';
import wifiManager from '@ohos.wifiManager';
import { resolveIP } from '../../Utils/Util'
import socket from '@ohos.net.socket';
import http from '@ohos.net.http'
import request from '@ohos.request'
import resourceManager from '@ohos.resourceManager'
import featureAbility from '@ohos.ability.featureAbility'

const TAG = '[Benchmark]'

let localAddr = {
  // 调用Manager时，preview会报错
  //  address : resolveIP( wifiManager.getIpInfo().ipAddress )
  address : resolveIP( wifi.getIpInfo().ipAddress ) ,
  family : 1 ,
  port : 9090
}
let oppositeAddr = {
  address : '' ,
  family : 1 ,
  port : 0
}
let loginCount = 0

let udp = socket.constructUDPSocketInstance()

/**
 *  WifiManager benchmark Test Page of wifi test
 */

@Entry
@Component
struct WifiManagerBenchmarkTest {
  @State showList: boolean = false;
  @State message: string = 'WifiManagerBenchmarkTest';
  private testItem: TestData = router.getParams().testId;
  @State changeIndex: number = - 1
  @StorageLink( "wifiManagerBenchmarkTestMessage" ) wifiManagerBenchmarkTestMessage: string = ""
  @State w_ssid1: string = "TP-LINK_6365";
  @State w_bssid1: string = "6C:B1:58:75:63:65";
  @State w_preSharedKey1: string = "12345678";
  @State w_isHiddenSsid1: boolean = false;
  @State w_securityType1: number = 3
  @State w_creatorUid1: number = 1;
  @State w_disableReason1: number = 0;
  @State w_netId1: number = 0 ;
  @State w_randomMacType1: number = 0 ;
  @State w_randomMacAddr1: string = "08:fb:ea:1b:38:aa"
  @State w_ipType1: number = 1 ;
  @State w_staticIp_ipAddress1: number = 3232235880 ;
  @State w_staticIp_gateway1: number = 3232235777 ;
  @State w_staticIp_dnsServers1: number = 3716386629 ;
  @State w_staticIp_domains1: Array<string> = [ "0", "1", "2" ] ;
  @State w_networkIdM: number = 0 ;
  @State w_featureIdM: number = 1 ;
  //  @State login_feng: boolean = false
  //  @State login_wen: boolean = false
  //  @State user: string = ''
  //  @State roomDialog: boolean = false
  //  @State confirmDialog: boolean = false
  //  @State ipDialog: boolean = true
  //  @State txtDialog: boolean = true
  //  @State warnDialog: boolean = false
  //  @State warnText: string = ''
  //  @State roomNumber: string = ''
  //  @State receiveMsg: string = '待接收数据'
  @State receivedSize: number = 0
  @State totalSize: number = 0
  @State message: string = ''
  @State files: Array<string> = []
  @State uploads: Array<string> = []
  @StorageLink( 'wifiManagerBenchmarkTime' ) wifiManagerBenchmarkTime: number = 0;

  aboutToAppear() {
    AppStorage.SetOrCreate( 'w_ssid1' , this.w_ssid1 );
    AppStorage.SetOrCreate( 'w_bssid1' , this.w_bssid1 );
    AppStorage.SetOrCreate( 'w_preSharedKey1' , this.w_preSharedKey1 );
    AppStorage.SetOrCreate( 'w_isHiddenSsid1' , this.w_isHiddenSsid1 );
    AppStorage.SetOrCreate( 'w_securityType1' , this.w_securityType1 );
    AppStorage.SetOrCreate( 'w_creatorUid1' , this.w_creatorUid1 );
    AppStorage.SetOrCreate( 'w_disableReason1' , this.w_disableReason1 );
    AppStorage.SetOrCreate( 'w_netId1' , this.w_netId1 );
    AppStorage.SetOrCreate( 'w_randomMacType1' , this.w_randomMacType1 );
    AppStorage.SetOrCreate( 'w_randomMacAddr1' , this.w_randomMacAddr1 );
    AppStorage.SetOrCreate( 'w_ipType1' , this.w_ipType1 );
    AppStorage.SetOrCreate( 'w_staticIp_ipAddress1' , this.w_staticIp_ipAddress1 );
    AppStorage.SetOrCreate( 'w_staticIp_gateway1' , this.w_staticIp_gateway1 );
    AppStorage.SetOrCreate( 'w_staticIp_dnsServers1' , this.w_staticIp_dnsServers1 );
    AppStorage.SetOrCreate( 'w_staticIp_domains1' , this.w_staticIp_domains1 );
    AppStorage.SetOrCreate( 'w_networkIdM' , this.w_networkIdM );
    AppStorage.SetOrCreate( 'w_featureIdM' , this.w_featureIdM );
  }

  build() {
    Column() {
      Stack( { alignContent : Alignment.TopStart } ) {
        TestImageDisplay( { testItem : this.testItem } )
        PageTitle( { testItem : this.testItem } )
      }

      Stack().height( "1vp" ).backgroundColor( "#000000" );

      Column() {
        Scroll() {
          Column() {
            Text( "性能测试: 测试wifiManager连接时的数据收发性能" )
              .fontSize( "18vp" )
              .margin( { top : "5vp" , bottom : "5vp" , left : "5vp" } )
              .textAlign( TextAlign.Start )
              .width( ConfigData.WH_100_100 )
          }
          .width( ConfigData.WH_100_100 )
          .height( 60 )
        }
        .scrollBarWidth( 10 )
        .scrollBar( BarState.Auto )

        Stack().height( "1vp" ).backgroundColor( "#000000" )

        Column() {
          Text( "性能测试时间：" + this.wifiManagerBenchmarkTime + "ms" )
            .fontSize( "20vp" )
            .margin( { top : "5vp" , left : "10vp" , bottom : "5vp" } )
            .textAlign( TextAlign.Start )
            .width( ConfigData.WH_90_100 )
            .backgroundColor( $r( "sys.color.ohos_id_color_sub_background" ) )

          Flex( { alignItems : ItemAlign.Center , justifyContent : FlexAlign.SpaceBetween } ) {
            Button( { type : ButtonType.Normal , stateEffect : true } ) {
              Text( '传输数据' ).fontSize( "24vp" ).fontColor( 0xffffff ).margin( { left : 5 , right : 5 } )
            }
            .borderRadius( 8 )
            .backgroundColor( $r( "app.color.blue" ) )
            .width( 120 )
            .height( 60 )
            .margin( { top : "5vp" , left : "50vp" , bottom : "5vp" } )
            .align( Alignment.Start )
            .onClick( async( event: ClickEvent ) => {
              this.showList = false
            } )

            Button( { type : ButtonType.Normal , stateEffect : true } ) {
              Row() {
                Text( '上传下载' ).fontSize( "24vp" ).fontColor( 0xffffff ).margin( { left : 5 , right : 5 } )
              }.alignItems( VerticalAlign.Center )
            }
            .borderRadius( 8 )
            .backgroundColor( $r( "app.color.blue" ) )
            .width( 120 )
            .height( 60 )
            .margin( { top : "5vp" , right : "50vp" , bottom : "5vp" } )
            .align( Alignment.Start )
            .onClick( async( event: ClickEvent ) => {
              this.showList = true;
            } )

          }
          .backgroundColor( $r( "sys.color.ohos_id_color_sub_background" ) )
          .width( ConfigData.WH_100_100 )
        }
        .backgroundColor( $r( "sys.color.ohos_id_color_sub_background" ) )
        .width( ConfigData.WH_100_100 )
        .height( 100 )

        Stack().height( "1vp" ).backgroundColor( "#000000" )

        Column() {
          if ( !this.showList ) {
            socketTest()
          } else {
            upDownLoad()
          }
        }
        .backgroundColor( $r( "sys.color.ohos_id_color_sub_background" ) )
        .width( ConfigData.WH_100_100 )
        .height( ConfigData.WH_100_100 );
      }
    }
  }
}

@Component
struct socketTest {
  @State login_feng: boolean = false
  @State login_wen: boolean = false
  @State user: string = ''
  @State roomDialog: boolean = false
  @State confirmDialog: boolean = false
  @State ipDialog: boolean = true
  @State txtDialog: boolean = true
  @State warnDialog: boolean = false
  @State warnText: string = ''
  @State roomNumber: string = ''
  @State bindMsg: string = "未绑定"
  @State receiveMsg: string = '待接收数据'

  bindOption() {
    let bindOption = udp.bind( localAddr )
    bindOption.then( () => {
      console.log( TAG , 'bind success' )
      this.bindMsg = "绑定成功"
    } ).catch( err => {
      console.log( TAG , 'bind fail' + err )
      this.bindMsg = "绑定失败"
    } )
    udp.on( 'message' , data => {
      console.log( TAG , `data:${ JSON.stringify( data ) }` )
      let buffer = data.message
      let dataView = new DataView(buffer)
      console.log( TAG , `length = ${ dataView.byteLength }` )
      let str = ""
      for ( let i = 0 ;i < dataView.byteLength ; ++i ) {
        let c = String.fromCharCode( dataView.getUint8( i ) )
        if ( c != "\n" ) {
          str += c
        }
      }
      //      if ( str == 'ok' ) {
      //        router.clear()
      //        loginCount += 1
      //        router.push( {
      //          url : 'pages/Index' ,
      //          params : { address : oppositeAddr.address , port : oppositeAddr.port , loginCount : loginCount }
      //        } )
      //      }
      //      else {
      this.receiveMsg = str
      this.confirmDialog = true
      //      }
    } )
  }

  build() {
    Stack( { alignContent : Alignment.Center } ) {
      Column() {
        //        if ( !this.ipDialog ) {
        //          Column() {
        //            Image( this.login_feng ? $r( 'app.color.blue' ) : $r( 'app.color.moon' ) )
        //              .width( 100 )
        //              .height( 100 )
        //              .objectFit( ImageFit.Fill )
        //            Text( '用户名：' + this.user ).fontSize( 25 ).margin( { top : 50 } )
        //
        //            Button() {
        //              Text( $r( 'app.string.create_room' ) ).fontSize( 25 ).fontColor( Color.White )
        //            }
        //            .width( '150' )
        //            .height( 50 )
        //            .margin( { top : 30 } )
        //            .type( ButtonType.Capsule )
        //            .onClick( () => {
        //              this.roomDialog = true
        //              this.bindOption()
        //            } )
        //          }.width( '90%' ).margin( { top : 100 } )
        //        }

        if ( this.ipDialog ) {
          Column() {
            Text( '本地IP：' + localAddr.address )
              .fontSize( 25 )
              .margin( { top : 10 } )
            TextInput( { placeholder : '请输入对端ip' } )
              .width( 200 )
              .fontSize( 25 )
              .margin( { top : 10 } )
              .onChange( ( value: string ) => {
                oppositeAddr.address = value
                oppositeAddr.port = 9090
              } )

            if ( this.warnDialog ) {
              Text( this.warnText )
                .width( 200 )
                .fontSize( 10 )
                .fontColor( Color.Red ).margin( { top : 5 } )
            }
            Row() {
              Button( $r( 'app.string.confirm' ) )
                .fontColor( Color.Black )
                .height( 40 )
                .width( 130 )
                .fontSize( 25 )
                .margin( { bottom : 10 } )
                .onClick( () => {
                  if ( oppositeAddr.address === '' ) {
                    this.warnDialog = true
                    this.warnText = '请先输入对端IP'
                  } else {
                    this.bindOption()
                    this.txtDialog = true
                    console.log( TAG , `peer ip=${ oppositeAddr.address }` )
                    console.log( TAG , `peer port=${ oppositeAddr.port }` )
                    console.log( TAG , `peer port=${ localAddr.port }` )
                  }
                } )
                .backgroundColor( 0xffffff )

              Button( $r( 'app.string.send_message' ) )
                .fontColor( Color.Black )
                .height( 40 )
                .width( 130 )
                .fontSize( 25 )
                .margin( { bottom : 10 } )
                .onClick( () => {
                  {
                    //发送数据
                    udp.send( {
                      data : 'online' ,
                      address : oppositeAddr
                    } ).then( data => {
                      console.log( TAG , `send sucess : ${ data }` )
                    } ).catch( function( err ) {
                      console.log( TAG , `TAG,send : ${ JSON.stringify( err ) }` )
                    } )

                    console.log( TAG , `send peer ip=${ oppositeAddr.address }` )
                    console.log( TAG , `send peer port=${ oppositeAddr.port }` )
                    console.log( TAG , `send peer port=${ localAddr.port }` )
                  }
                } )
                .backgroundColor( 0xffffff )
            }

            Text( this.bindMsg )
              .width( 200 )
              .fontSize( 25 )
              .fontColor( Color.Red ).margin( { top : 3 } )
          }
          .width( '80%' )
          .height( 200 )
          .margin( { top : '3%' } )
          .backgroundColor( Color.White )
          .border( { radius : 10 , width : 3 } )
        }

        if ( this.txtDialog ) {
          Column() {
            Text( '接收本地IP：' + localAddr.address )
              .fontSize( 25 )
              .margin( { top : 10 } )

            Text( this.receiveMsg )
              .width( 200 )
              .fontSize( 25 )
              .fontColor( Color.Red ).margin( { top : 5 } )


          }
          .width( '80%' )
          .height( 200 )
          .margin( { top : '3%' } )
          .backgroundColor( Color.White )
          .border( { radius : 10 , width : 3 } )
        }

      }.width( '100%' ).height( '100%' )
    }
  }
}

@Component
struct upDownLoad {
  @State receivedSize: number = 0
  @State totalSize: number = 0
  @State message: string = ''
  @State files: Array<string> = []
  @State uploads: Array<string> = []
  private downloadConfig = {
    url : 'http://192.168.62.127:8000' ,
    filePath : ""
  }
  handlerClickButton = () => {
    featureAbility.terminateSelf()
  }

  aboutToAppear() {
    console.log( TAG , `enter Index aboutToAppear` )
    featureAbility.getContext()
      .requestPermissionsFromUser( [ 'ohos.permission.INTERNET' ] , 2 , ( result ) => {
        console.log( TAG , `grantPermission,requestPermissionsFromUser,result.requestCode=${ result }` )
      } )
    this.files.push( "http://192.168.62.127:8000" )
    let httpRequest = http.createHttp()
    httpRequest.request(
      'http://192.168.0.123/?tpl=list&folders-filter=&recursive' ,
      {
        method : http.RequestMethod.GET ,
        header : {
          'Content-Type' : 'text/plain'
        }
      } , ( err , data ) => {
      console.log( TAG , `error = ${ JSON.stringify( err ) }` )
      if ( !err ) {
        console.log( TAG , `data = ${ JSON.stringify( data ) }` )
        let result: string = data.result.toString()
        console.log( TAG , `Result = ${ result }` )

        let tempFiles = result.split( '\r\n' )
        for ( let i = 0 ; i < tempFiles.length ; i ++ ) {
          let splitFiles = tempFiles[i].split( '//' )[1].split( '/' )
          console.log( TAG , `splitFiles = ${ JSON.stringify( splitFiles ) }` )
          if ( splitFiles.indexOf( 'upload' ) === - 1 ) {
            this.files.push( tempFiles[i] )
          }
        }
        console.log( TAG , `files = ${ JSON.stringify( this.files ) }` )
      } else {
        console.log( TAG , `error: ${ JSON.stringify( err ) }` )
        httpRequest.destroy()
      }
    } )
  }

  build() {
    Column() {
      Scroll() {
        Column() {
          Text( $r( 'app.string.choice_download_file' ) )
            .fontSize( 25 )
            .alignSelf( ItemAlign.Start )
            .margin( { top : 20 , left : 10 } )
          ForEach( this.files , ( item , index ) => {
            Divider()
              .margin( { top : 20 } )
            Row() {
              Text( item )
                .fontSize( 25 )
                .constraintSize( { maxWidth : '75%' } )
                .fontWeight( FontWeight.Bold )
                .margin( { top : 20 , left : 10 } )
              Blank()

              Button( $r( 'app.string.click_download' ) )
                .margin( { top : 20 , right : 10 } )
                .onClick( async() => {
                  let fileindex = 1;
                  setInterval( () => {
                    //                    let resourceManage = await resourceManager.getResourceManager()
                    //                    let downloadSuccess = await resourceManage.getString($r('app.string.download_success').id)
                    this.downloadConfig.url = item
                    console.log( TAG , `downloadConfig.url = ${ JSON.stringify( this.downloadConfig.url ) }` )
                    this.downloadConfig.filePath = `/data/storage/el2/base/haps/entry/cache/ ${
                    item.split( '//' )[1].split( '/' )[1] + fileindex }`
                    //                    /data/storage/el2/base/haps/entry/cache/
                    fileindex += 1
                    console.log( TAG , `downloadConfig.filePath = ${ JSON.stringify( this.downloadConfig.filePath ) }` )
                    request.download( this.downloadConfig , ( err , downloadTask ) => {
                      console.log( TAG , `download enter` )
                      if ( err ) {
                        console.log( TAG , `download err = ${ JSON.stringify( err ) }` )
                        return
                      }
                      console.log( TAG , `download data = ${ JSON.stringify( downloadTask ) }` )

                      console.log( TAG , `download end` )
                    } )
                  } , 1000 )

                } )
            }
            .width( '100%' )

            //            if (index === this.files.length - 1) {
            //              Divider().margin({ top: 20 })
            //            }
          } )
          Button( $r( 'app.string.upload_page' ) )
            .fontSize( 30 )
            .width( 180 )
            .height( 50 )
            .margin( { top : 30 } )
            .key( 'uploadBtn' )
            .onClick( () => {
              router.push( {
                url : 'pages/Upload' ,
                params : { uploads : this.uploads }
              } )
            } )

        }
        .width( '100%' )
      }
      .constraintSize( { maxHeight : '87%' } )

      if ( this.receivedSize !== 0 && this.totalSize !== 0 && this.files.length > 0 ) {
        Row() {
          Text( $r( 'app.string.download_progress' ) )
            .fontSize( 25 )
            .fontWeight( FontWeight.Bold )
            .margin( { left : 10 } )
          Progress( { value : this.receivedSize , total : this.totalSize , type : ProgressType.Capsule } )
            .color( Color.Grey )
            .width( '40%' )
            .height( 10 )
            .margin( { left : 10 } )
          Text( `${ JSON.stringify( Math.floor( this.receivedSize / this.totalSize * 100 ) ) }%` )
            .margin( { left : 10 } )
        }
        .margin( { top : 10 } )
        .alignSelf( ItemAlign.Center )
      }
    }
  }
}

export function testFunc( func ) {
  let start = new Date().getTime()
  switch ( func ) {
    case testSetDeviceName: {
      func( "MyTestDevice" )
    }
      break;
    default: {
      func()
    }
      break;
  }
  let end = new Date().getTime()
  console.log( "开始:" + Number( start ) + "ms" )
  console.log( "结束:" + Number( end ) + "ms" )

  console.log( "花费:" + Number( end - start ) + "ms" )
  let message = ""
  message += "花费:" + Number( end - start ) + "ms" + "\n"
  message += "开始:" + Number( start ) + "ms; " + "结束:" + Number( end ) + "ms" + "\n"
  return message
}

function sleep( time ) {
  return new Promise(( resolve , reject ) => {
    setTimeout( () => {
      resolve()
    } , time * 1000 )
  })
}