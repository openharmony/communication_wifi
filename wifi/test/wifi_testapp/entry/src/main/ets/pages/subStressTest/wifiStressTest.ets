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
import { PageTitle } from '../../Component/pageTitle';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { StressContentTable } from '../../Component/stressContentTable';
import router from '@system.router';
import ConfigData from '../../Utils/ConfigData';
import LogUtil from '../../Utils/LogUtil';
import { initWifiStressData } from '../../MainAbility/model/stressTestDataModels'
import { TestData } from '../../MainAbility/model/testData'
import wifi from '@ohos.wifi';
import { resolveIP } from '../../Utils/Util'
import socket from '@ohos.net.socket';
import http from '@ohos.net.http'
import request from '@ohos.request'
import resourceManager from '@ohos.resourceManager'
import featureAbility from '@ohos.ability.featureAbility'

const TAG = '[Stress]'

let localAddr = {
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
 * wifi StressTest Page Of Wifi test
 */

@Entry
@Component
struct WifiStressTest {
  @State showList: boolean = false;
  @State showListItems: boolean = false;
  @State showListItem: boolean = false;
  private testItem: TestData = router.getParams().testId;
  @State message: string = "";
  @State deviceId: string = '';
  @State currentClick: number = - 1;
  @StorageLink( 'pairedMac' ) pairedMac: string = "";
  @State w_ssid: string = "TP-LINK_6365";
  @State w_bssid: string = "6C:B1:58:75:63:65";
  @State w_preSharedKey: string = "kaihong123";
  @State w_isHiddenSsid: boolean = false;
  @State w_securityType: number = 3
  @State w_creatorUid: number = 1;
  @State w_disableReason: number = 0;
  @State w_netId: number = 100 ;
  @State w_randomMacType: number = 0 ;
  @State w_randomMacAddr: string = "08:fb:ea:1b:38:aa"
  @State w_ipType: number = 1 ;
  @State w_staticIp_ipAddress: number = 3232235880 ;
  @State w_staticIp_gateway: number = 3232235777 ;
  @State w_staticIp_dnsServers: number = 3716386629 ;
  @State w_staticIp_domains: Array<string> = [ "0", "1", "2" ] ;
  @State w_networkId: number = 0 ; // id,netId,networkId是一个值嘛？
  @State w_featureId: number = 1 ;
  @StorageLink( 'stressNumber' ) stressNumber: number = 0 ;
  @StorageLink( 'stressTime' ) stressTime: number = 0;
  //  @StorageLink('getDeviceConfigsMessage') getDeviceConfigsMessage: string = '';
  //  @StorageLink('getScanInfoMessage') getScanInfoMessage: string = '';

  aboutToAppear() {
    AppStorage.SetOrCreate( 'w_ssid' , this.w_ssid );
    AppStorage.SetOrCreate( 'w_bssid' , this.w_bssid );
    AppStorage.SetOrCreate( 'w_preSharedKey' , this.w_preSharedKey );
    AppStorage.SetOrCreate( 'w_isHiddenSsid' , this.w_isHiddenSsid );
    AppStorage.SetOrCreate( 'w_securityType' , this.w_securityType );
    AppStorage.SetOrCreate( 'w_creatorUid' , this.w_creatorUid );
    AppStorage.SetOrCreate( 'w_disableReason' , this.w_disableReason );
    AppStorage.SetOrCreate( 'w_netId' , this.w_netId );
    AppStorage.SetOrCreate( 'w_randomMacType' , this.w_randomMacType );
    AppStorage.SetOrCreate( 'w_randomMacAddr' , this.w_randomMacAddr );
    AppStorage.SetOrCreate( 'w_ipType' , this.w_ipType );
    AppStorage.SetOrCreate( 'w_staticIp_ipAddress' , this.w_staticIp_ipAddress );
    AppStorage.SetOrCreate( 'w_staticIp_gateway' , this.w_staticIp_gateway );
    AppStorage.SetOrCreate( 'w_staticIp_dnsServers' , this.w_staticIp_dnsServers );
    AppStorage.SetOrCreate( 'w_staticIp_domains' , this.w_staticIp_domains );
    AppStorage.SetOrCreate( 'w_networkId' , this.w_networkId );
    AppStorage.SetOrCreate( 'w_featureId' , this.w_featureId );
  }

  init() {
    console.log( "init-----------" )
  }

  build() {
    Column() {
      Stack( { alignContent : Alignment.TopStart } ) {
        TestImageDisplay( { testItem : this.testItem } )
        PageTitle( { testItem : this.testItem } )
      }

      Stack().height( "0.5vp" ).backgroundColor( "#000000" );
      Column() {
        Row() {
          Text( "目标设备IP：" )
            .fontSize( "20vp" )
            .height( 40 )
            .padding( { top : 5 } )
            .width( ConfigData.WH_28_100 )
            .align( Alignment.Start )

          TextInput( { text : this.pairedMac , placeholder : "请输入即将连接的设备MAC" } )
            .height( 40 )
            .borderStyle( BorderStyle.Dashed )
            .backgroundColor( $r( "app.color.white" ) )
            .onChange( ( str ) => {
              this.deviceId = str;
            } )
            .width( ConfigData.WH_45_100 )
            .padding( { top : 5 , left : 5 } )
          Image( $r( 'app.media.Switch' ) )
            .height( 50 )
            .padding( { top : 5 , bottom : 5 , left : 10 } )
            .width( ConfigData.WH_15_100 )
            .onClick( () => {
              this.showList = !this.showList;
            } )
        }
      }
      .align( Alignment.Start )

      if ( this.showList ) {
        WifiDeviceSetting()
      } else {
        Column() {
          Scroll() {
            Column() {
              Text( "stress测试：" )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_100_100 )
              Text( "stress测试次数:" + this.stressNumber )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "stress测试时间：" + this.stressTime + "ms" )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Flex( { alignItems : ItemAlign.Center , justifyContent : FlexAlign.SpaceBetween } ) {
                Button( { type : ButtonType.Normal , stateEffect : true } ) {
                  Text( '传输数据' ).fontSize( "20vp" ).fontColor( 0xffffff ).margin( { left : 2 , right : 2 } )
                }
                .borderRadius( 8 )
                .backgroundColor( $r( "app.color.blue" ) )
                .width( 100 )
                .height( 60 )
                .margin( { top : "5vp" , left : "10vp" , bottom : "5vp" } )
                .align( Alignment.Start )
                .onClick( async( event: ClickEvent ) => {
                  this.showListItems = true
                  this.showListItem = false
                } )

                Button( { type : ButtonType.Normal , stateEffect : true } ) {
                  Row() {
                    Text( '上传下载' ).fontSize( "20vp" ).fontColor( 0xffffff ).margin( { left : 2 , right : 2 } )
                  }.alignItems( VerticalAlign.Center )
                }
                .borderRadius( 8 )
                .backgroundColor( $r( "app.color.blue" ) )
                .width( 100 )
                .height( 60 )
                .margin( { top : "5vp" , left : "10vp" , right : "10vp" , bottom : "5vp" } )
                .align( Alignment.Center )
                .onClick( async( event: ClickEvent ) => {
                  this.showListItem = true
                  this.showListItems = false
                } )

                Button( { type : ButtonType.Normal , stateEffect : true } ) {
                  Row() {
                    Text( '返回接口' ).fontSize( "20vp" ).fontColor( 0xffffff ).margin( { left : 2 , right : 2 } )
                  }.alignItems( VerticalAlign.Bottom )
                }
                .borderRadius( 8 )
                .backgroundColor( $r( "app.color.blue" ) )
                .width( 100 )
                .height( 60 )
                .margin( { top : "5vp" , right : "10vp" , bottom : "5vp" } )
                .align( Alignment.End )
                .onClick( async( event: ClickEvent ) => {
                  this.showListItem = false
                  this.showListItems = false
                } )
              }
              .backgroundColor( $r( "sys.color.ohos_id_color_sub_background" ) )
              .width( ConfigData.WH_100_100 )
            }
            .width( ConfigData.WH_100_100 )
          }
          .scrollBarWidth( 10 )
          .scrollBar( BarState.Auto )
        }
        .height( 130 )
        .width( ConfigData.WH_95_100 )
        .backgroundColor( $r( "sys.color.ohos_id_color_foreground_contrary" ) )

        if ( this.showListItems == true && this.showListItem == false ) {
          socketTest()
        } else if ( this.showListItems == false && this.showListItem == true ) {
          upDownLoad()
        } else {
          StressContentTable( {
            testItem : this.testItem , apiItems : initWifiStressData()
          } )
        }
      }
    }
    .alignItems( HorizontalAlign.Center )
    .backgroundColor( $r( "app.color.lead" ) )
    .height( ConfigData.WH_100_100 )
  }
}

@Component
struct WifiDeviceSetting {
  @State w_ssid: string = "TP-LINK_6365"; //TP-LINK_6365
  @State w_bssid: string = "6C:B1:58:75:63:65"; //6C:B1:58:75:63:65
  @State w_preSharedKey: string = "kaihong123"; //kaihong123
  @State w_isHiddenSsid: boolean = false;
  @State w_securityType: number = 3
  @State w_creatorUid: number = 1;
  @State w_disableReason: number = 0;
  @State w_netId: number = 100 ;
  @State w_randomMacType: number = 0 ;
  @State w_randomMacAddr: string = "08:fb:ea:1b:38:aa"
  @State w_ipType: number = 1 ;
  @State w_staticIp_ipAddress: number = 3232235880 ;
  @State w_staticIp_gateway: number = 3232235777 ;
  @State w_staticIp_dnsServers: number = 3716386629 ;
  @State w_staticIp_domains: Array<string> = [ "0", "1", "2" ] ;
  @State w_networkId: number = 0 ; // id,netId,networkId是一个值嘛？
  @State w_featureId: number = 1 ;

  aboutToAppear() {
    AppStorage.SetOrCreate( 'w_ssid' , this.w_ssid );
    AppStorage.SetOrCreate( 'w_bssid' , this.w_bssid );
    AppStorage.SetOrCreate( 'w_preSharedKey' , this.w_preSharedKey );
    AppStorage.SetOrCreate( 'w_isHiddenSsid' , this.w_isHiddenSsid );
    AppStorage.SetOrCreate( 'w_securityType' , this.w_securityType );
    AppStorage.SetOrCreate( 'w_creatorUid' , this.w_creatorUid );
    AppStorage.SetOrCreate( 'w_disableReason' , this.w_disableReason );
    AppStorage.SetOrCreate( 'w_netId' , this.w_netId );
    AppStorage.SetOrCreate( 'w_randomMacType' , this.w_randomMacType );
    AppStorage.SetOrCreate( 'w_randomMacAddr' , this.w_randomMacAddr );
    AppStorage.SetOrCreate( 'w_ipType' , this.w_ipType );
    AppStorage.SetOrCreate( 'w_staticIp_ipAddress' , this.w_staticIp_ipAddress );
    AppStorage.SetOrCreate( 'w_staticIp_gateway' , this.w_staticIp_gateway );
    AppStorage.SetOrCreate( 'w_staticIp_dnsServers' , this.w_staticIp_dnsServers );
    AppStorage.SetOrCreate( 'w_staticIp_domains' , this.w_staticIp_domains );
    AppStorage.SetOrCreate( 'w_networkId' , this.w_networkId );
    AppStorage.SetOrCreate( 'w_featureId' , this.w_featureId );
  }

  build() {
    Column() {
      Row() {
        Text( "ssid:" ).fontSize( "17vp" ).width( 70 )
        TextInput( { text : this.w_ssid , placeholder : "TP-LINK_6365" } ) //TP-LINK_6365
          .fontSize( "15vp" )
          .onChange( ( strInput ) => {
            this.w_ssid = strInput;
            AppStorage.SetOrCreate( 'w_ssid' , this.w_ssid );
          } )
          .width( ConfigData.WH_80_100 )
          .borderRadius( 1 )
      }
      .backgroundColor( $r( "app.color.moon" ) )
      .padding( 5 )
      .justifyContent( FlexAlign.Start )
      .alignItems( VerticalAlign.Center )

      Scroll() {
        Column() {
          Stack().height( "0.25vp" ).backgroundColor( "#000000" );
          Column() {
            Row() {
              Text( "bssid:" ).fontSize( "15vp" ).width( 60 );
              TextInput( { text : this.w_bssid , placeholder : "6c:b1:58:75:63:67" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_bssid = strInput;
                  AppStorage.SetOrCreate( 'w_bssid' , this.w_bssid );
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .padding( 3 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )
            .backgroundColor( $r( "app.color.spring" ) )

            Row() {
              Text( "preSharedKey:" ).fontSize( "15vp" ).width( 110 );
              TextInput( { text : this.w_preSharedKey , placeholder : "kaihong123" } ) //kaihong123
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_preSharedKey = strInput;
                  AppStorage.SetOrCreate( 'w_preSharedKey' , this.w_preSharedKey );
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .backgroundColor( $r( "app.color.spring" ) )
            .padding( 5 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )

            Row() {
              Text( "isHiddenSsid:" ).fontSize( 15 ).width( 110 );
              TextInput( { text : this.w_isHiddenSsid , placeholder : "false" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_isHiddenSsid = strInput;
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_isHiddenSsid' , this.w_isHiddenSsid );
                  }
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .backgroundColor( $r( "app.color.spring" ) )
            .padding( 5 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )

            Row() {
              Text( "securityType:" ).fontSize( 15 ).width( ConfigData.value_100 );
              Column() {
                Select( [
                  { value : 'WIFI_SEC_TYPE_INVALID' },
                  { value : 'WIFI_SEC_TYPE_OPEN' },
                  { value : 'WIFI_SEC_TYPE_WEP' },
                  { value : 'WIFI_SEC_TYPE_PSK' },
                  { value : 'WIFI_SEC_TYPE_SAE' }
                ] )
                  .selected( 3 )
                  .value( 'WIFI_SEC_TYPE_PSK' )
                  .font( { size : 17 } )
                  .selectedOptionFont( { size : 17 } )
                  .optionFont( { size : 15 } )
                  .width( ConfigData.WH_80_100 )
                  .onSelect( ( index: number ) => {
                    console.log( "Select:" + index )
                    this.w_securityType = index;
                    AppStorage.SetOrCreate( 'w_securityType' , this.w_securityType );
                  } )
              }
              .width( ConfigData.WH_80_100 )
              .borderRadius( 1 )
            }
            .backgroundColor( $r( "app.color.spring" ) )
            .padding( 5 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )

            Row() {
              Text( "creatorUid:" ).fontSize( 15 ).width( 100 );
              TextInput( { text : this.w_creatorUid , placeholder : "1" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_creatorUid = strInput;
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_creatorUid' , this.w_creatorUid );
                  }
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .backgroundColor( $r( "app.color.spring" ) )
            .padding( 5 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )

            Row() {
              Text( "disableReason:" ).fontSize( 15 ).width( 120 );
              TextInput( { text : this.w_disableReason , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_disableReason = strInput;
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_disableReason' , this.w_disableReason );
                  }
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .backgroundColor( $r( "app.color.spring" ) )
            .padding( 5 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )

            Row() {
              Text( "netId:" ).fontSize( 15 ).width( 60 );
              TextInput( { text : this.w_netId , placeholder : "100" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_netId = strInput;
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_netId' , this.w_netId );
                  }
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .backgroundColor( $r( "app.color.spring" ) )
            .padding( 5 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )

            Row() {
              Text( "randomMacType:" ).fontSize( 15 ).width( 140 );
              TextInput( { text : this.w_randomMacType , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_randomMacType = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_randomMacType' , this.w_randomMacType );
                  }
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .backgroundColor( $r( "app.color.spring" ) )
            .padding( 5 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )

            Row() {
              Text( "randomMacAddr:" ).fontSize( 15 ).width( 140 );
              TextInput( { text : this.w_randomMacAddr , placeholder : "08:fb:ea:1b:38:aa" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_randomMacAddr = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_randomMacAddr' , this.w_randomMacAddr );
                  }
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .backgroundColor( $r( "app.color.spring" ) )
            .padding( 5 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )

            Row() {
              Text( "ipType:" ).fontSize( 15 ).width( 60 );
              TextInput( { text : this.w_ipType , placeholder : "1" } ) //DHCP
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_ipType = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_ipType' , this.w_ipType );
                  }
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .backgroundColor( $r( "app.color.spring" ) )
            .padding( 5 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )

            Row() {
              Text( "staticIp_ipAddress:" ).fontSize( 15 ).width( 135 );
              TextInput( { text : this.w_staticIp_ipAddress , placeholder : "3232235880" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_staticIp_ipAddress = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_staticIp_ipAddress' , this.w_staticIp_ipAddress );
                  }
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .backgroundColor( $r( "app.color.moon" ) )
            .padding( 5 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )

            Row() {
              Text( "staticIp_gateway:" ).fontSize( 15 ).width( 130 );
              TextInput( { text : this.w_staticIp_gateway , placeholder : "3232235777" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_staticIp_gateway = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_staticIp_gateway' , this.w_staticIp_gateway );
                  }
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .backgroundColor( $r( "app.color.moon" ) )
            .padding( 5 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )

            Row() {
              Text( "staticIp_dnsServers:" ).fontSize( 15 ).width( 140 );
              TextInput( { text : this.w_staticIp_dnsServers , placeholder : "3716386629" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_staticIp_dnsServers = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_staticIp_dnsServers' , this.w_staticIp_dnsServers );
                  }
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .backgroundColor( $r( "app.color.moon" ) )
            .padding( 5 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )

            Row() {
              Text( "staticIp_domains:" ).fontSize( 15 ).width( 125 );
              TextInput( { text : this.w_staticIp_domains , placeholder : [ "0", "1", "2" ] } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_staticIp_domains = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_staticIp_domains' , this.w_staticIp_domains );
                  }
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .backgroundColor( $r( "app.color.moon" ) )
            .padding( 5 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )
          }

          Stack().height( "0.25vp" ).backgroundColor( "#000000" );
        }
      }
      .scrollBarWidth( 10 )
      .scrollBar( BarState.On )
    }
    .height( ConfigData.WH_58_100 )
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
    let bindOption = udp.bind( localAddr );
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
          .height( 180 )
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