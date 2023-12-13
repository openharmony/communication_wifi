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
import ConfigData from '../../utils/ConfigData';
import { initWifiApiData } from '../../entryability/model/testDataModels'
import { TestData } from '../../entryability/model/testData'

const TAG = "[Wifi]"

/**
 * wifi Test Page Of Wifi test
 */

@Component
struct WifiDeviceSetting {
  @StorageLink( 'w_ssid' ) w_ssid: string = "TP-LINK_6365"; //TP-LINK_6365
  @StorageLink( 'w_bssid' ) w_bssid: string = "6C:B1:58:75:63:65"; //6C:B1:58:75:63:65
  @StorageLink( 'w_preSharedKey' ) w_preSharedKey: string = "12345678"; //kaihong123
  @StorageLink( 'w_isHiddenSsid' ) w_isHiddenSsid: boolean = false;
  @StorageLink( 'w_securityType' ) w_securityType: Number = 3
  @StorageLink( 'w_creatorUid' ) w_creatorUid: Number = 1;
  @StorageLink( 'w_disableReason' ) w_disableReason: Number = 0;
  @StorageLink( 'w_netId' ) w_netId: Number = 100 ;
  @StorageLink( 'w_randomMacType' ) w_randomMacType: Number = 0 ;
  @StorageLink( 'w_randomMacAddr' ) w_randomMacAddr: string = "08:fb:ea:1b:38:aa"
  @StorageLink( 'w_ipType' ) w_ipType: Number = 1 ;
  @StorageLink( 'w_staticIp_ipAddress' ) w_staticIp_ipAddress: Number = 3232235880 ;
  @StorageLink( 'w_staticIp_gateway' ) w_staticIp_gateway: Number = 3232235777 ;
  @StorageLink( 'w_staticIp_dnsServers' ) w_staticIp_dnsServers: Number = 3716386629 ;
  @StorageLink( 'w_staticIp_domains' ) w_staticIp_domains: Array<string> = [ "0", "1", "2" ] ;
  @StorageLink( 'w_networkId' ) w_networkId: Number = 0 ; // id,netId,networkId是一个值嘛？
  @StorageLink( 'w_featureId' ) w_featureId: Number = 1 ;

  aboutToAppear() {
//    AppStorage.SetOrCreate( 'w_ssid' , this.w_ssid );
//    AppStorage.SetOrCreate( 'w_bssid' , this.w_bssid );
//    AppStorage.SetOrCreate( 'w_preSharedKey' , this.w_preSharedKey );
//    AppStorage.SetOrCreate( 'w_isHiddenSsid' , this.w_isHiddenSsid );
//    AppStorage.SetOrCreate( 'w_securityType' , this.w_securityType );
//    AppStorage.SetOrCreate( 'w_creatorUid' , this.w_creatorUid );
//    AppStorage.SetOrCreate( 'w_disableReason' , this.w_disableReason );
//    AppStorage.SetOrCreate( 'w_netId' , this.w_netId );
//    AppStorage.SetOrCreate( 'w_randomMacType' , this.w_randomMacType );
//    AppStorage.SetOrCreate( 'w_randomMacAddr' , this.w_randomMacAddr );
//    AppStorage.SetOrCreate( 'w_ipType' , this.w_ipType );
//    AppStorage.SetOrCreate( 'w_staticIp_ipAddress' , this.w_staticIp_ipAddress );
//    AppStorage.SetOrCreate( 'w_staticIp_gateway' , this.w_staticIp_gateway );
//    AppStorage.SetOrCreate( 'w_staticIp_dnsServers' , this.w_staticIp_dnsServers );
//    AppStorage.SetOrCreate( 'w_staticIp_domains' , this.w_staticIp_domains );
//    AppStorage.SetOrCreate( 'w_networkId' , this.w_networkId );
//    AppStorage.SetOrCreate( 'w_featureId' , this.w_featureId );
    let w_staticIp = {
      ipAddress : this.w_staticIp_ipAddress ,
      gateway : this.w_staticIp_gateway ,
      dnsServers : this.w_staticIp_dnsServers ,
      domains : this.w_staticIp_domains
    }
    let wifiDeviceConfig = {
      ssid : this.w_ssid ,
      bssid : this.w_bssid ,
      preSharedKey : this.w_preSharedKey ,
      isHiddenSsid : this.w_isHiddenSsid ,
      securityType : this.w_securityType ,
      creatorUid : this.w_creatorUid ,
      disableReason : this.w_disableReason ,
      netId : this.w_netId ,
      randomMacType : this.w_randomMacType ,
      randomMacAddr : this.w_randomMacAddr ,
      ipType : this.w_ipType ,
      staticIp : w_staticIp
    }
    AppStorage.SetOrCreate( "wifiDeviceConfig" , wifiDeviceConfig )
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
              TextInput( { text : this.w_preSharedKey , placeholder : "12345678" } ) //kaihong123
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
                  .size( 2 )
                  .selected( 0 )
                  .value( 'WIFI_SEC_TYPE_PSK' )
                  .font( { size : 17 } )
                  .selectedOptionFont( { size : 17 } )
                  .optionFont( { size : 15 } )
                  .width( ConfigData.WH_80_100 )
                  .onSelect( ( index: Number ) => {
                    console.log( TAG , "Select:" + index )
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
                  this.w_creatorUid = Number( strInput );
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
                  //判断合法性
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
                  //判断合法性
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

@Entry
@Component
struct WifiInterfaceTest {
  @State showList: boolean = false;
  private testItem: TestData = Router.getParams().testId;
  @State message: string = "";
  @State deviceId: string = '';
  @State currentClick: Number = - 1;
  @StorageLink( 'pairedSsid' ) pairedSsid: string = "";
  @State w_ssid: string = "TP-LINK_6365"; //TP-LINK_6365
  @State w_bssid: string = "6C:B1:58:75:63:65"; //6C:B1:58:75:63:65
  @State w_preSharedKey: string = "12345678"; //kaihong123
  @State w_isHiddenSsid: boolean = false;
  @State w_securityType: Number = 3
  @State w_creatorUid: Number = 1;
  @State w_disableReason: Number = 0;
  @State w_netId: Number = 100 ;
  @State w_randomMacType: Number = 0 ;
  @State w_randomMacAddr: string = "08:fb:ea:1b:38:aa"
  @State w_ipType: Number = 1 ;
  @State w_staticIp_ipAddress: Number = 3232235880 ;
  @State w_staticIp_gateway: Number = 3232235777 ;
  @State w_staticIp_dnsServers: Number = 3716386629 ;
  @State w_staticIp_domains: Array<string> = [ "0", "1", "2" ] ;
  @State w_networkId: Number = 0 ; // id,netId,networkId是一个值嘛？
  @State w_featureId: Number = 1 ;
  @StorageLink( 'linkedInfoMessage' ) linkedInfoMessage: string = '';
  @StorageLink( 'ipInfoMessage' ) ipInfoMessage: string = '';
  @StorageLink( 'getDeviceConfigsMessage' ) getDeviceConfigsMessage: string = '';
  @StorageLink( 'getScanInfoMessage' ) getScanInfoMessage: string = '';

  aboutToAppear() {
//    AppStorage.SetOrCreate( 'w_ssid' , this.w_ssid );
//    AppStorage.SetOrCreate( 'w_bssid' , this.w_bssid );
//    AppStorage.SetOrCreate( 'w_preSharedKey' , this.w_preSharedKey );
//    AppStorage.SetOrCreate( 'w_isHiddenSsid' , this.w_isHiddenSsid );
//    AppStorage.SetOrCreate( 'w_securityType' , this.w_securityType );
//    AppStorage.SetOrCreate( 'w_creatorUid' , this.w_creatorUid );
//    AppStorage.SetOrCreate( 'w_disableReason' , this.w_disableReason );
//    AppStorage.SetOrCreate( 'w_netId' , this.w_netId );
//    AppStorage.SetOrCreate( 'w_randomMacType' , this.w_randomMacType );
//    AppStorage.SetOrCreate( 'w_randomMacAddr' , this.w_randomMacAddr );
//    AppStorage.SetOrCreate( 'w_ipType' , this.w_ipType );
//    AppStorage.SetOrCreate( 'w_staticIp_ipAddress' , this.w_staticIp_ipAddress );
//    AppStorage.SetOrCreate( 'w_staticIp_gateway' , this.w_staticIp_gateway );
//    AppStorage.SetOrCreate( 'w_staticIp_dnsServers' , this.w_staticIp_dnsServers );
//    AppStorage.SetOrCreate( 'w_staticIp_domains' , this.w_staticIp_domains );
//    AppStorage.SetOrCreate( 'w_networkId' , this.w_networkId );
//    AppStorage.SetOrCreate( 'w_featureId' , this.w_featureId );
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
          Text( "已连接的WiFi:" )
            .fontSize( "17vp" )
            .height( 40 )
            .width( ConfigData.WH_30_100 )
            .align( Alignment.Start )

          TextInput( { text : this.pairedSsid , placeholder : "请在右侧输入WiFi的配置" } )
            .height( 40 )
            .borderStyle( BorderStyle.Dashed )
            .backgroundColor( $r( "app.color.white" ) )
            .onChange( ( str ) => {
              this.deviceId = str;
            } )
            .width( ConfigData.WH_50_100 )
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
              Text( "WLAN连接信息:" + this.linkedInfoMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "10vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "IP信息:" + this.ipInfoMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "10vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "获取网络配置:" + this.getDeviceConfigsMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "10vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "扫描结果:" + this.getScanInfoMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "10vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
            }
            .width( ConfigData.WH_100_100 )
          }
          .scrollBarWidth( 10 )
          .scrollBar( BarState.Auto )
        }
        .height( 100 )
        .width( ConfigData.WH_95_100 )
        .backgroundColor( $r( "sys.color.ohos_id_color_foreground_contrary" ) )

        ContentTable( {
          testItem : this.testItem , apiItems : initWifiApiData()
        } )
      }
    }
    .alignItems( HorizontalAlign.Center )
    .backgroundColor( $r( "app.color.lead" ) )
    .height( ConfigData.WH_100_100 )
  }
}
