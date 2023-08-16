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
import LogUtil from '../../Utils/LogUtil';
import { initWifiApiData } from '../../MainAbility/model/testDataModels'
import { TestData } from '../../MainAbility/model/testData'

const G_NAME = 'DaYu200'

/**
 * wifi Test Page Of Wifi test
 */

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
                  .size(2)
                  .selected( 0 )
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
                  this.w_creatorUid = Number(strInput);
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

@Entry
@Component
struct WifiInterfaceTest {
  @State showList: boolean = false;
  private testItem: TestData = Router.getParams().testId;
  @State message: string = "";
  @State deviceId: string = '';
  @State currentClick: number = - 1;
  @StorageLink( 'pairedMac' ) pairedMac: string = "32:32:235:878";
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
  @StorageLink( 'linkedInfoMessage' ) linkedInfoMessage: string = '';
  @StorageLink( 'ipInfoMessage' ) ipInfoMessage: string = '';
  @StorageLink( 'getDeviceConfigsMessage' ) getDeviceConfigsMessage: string = '';
  @StorageLink( 'getScanInfoMessage' ) getScanInfoMessage: string = '';

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
              //              Text("当前配置:")
              //                .fontSize("17vp")
              //                .margin({ top: "5vp", left: "10vp" })
              //                .textAlign(TextAlign.Start)
              //                .width(ConfigData.WH_100_100)
              Text( "WLAN连接信息:" + this.linkedInfoMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "IP信息:" + this.ipInfoMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "获取网络配置:" + this.getDeviceConfigsMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "扫描结果:" + this.getScanInfoMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
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
