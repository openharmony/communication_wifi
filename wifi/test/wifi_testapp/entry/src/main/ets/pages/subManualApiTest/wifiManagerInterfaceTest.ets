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
import { initWifiManagerApiData } from '../../MainAbility/model/testDataModels'
import { TestData } from '../../MainAbility/model/testData'

/**
 * wifiManager Test Page Of Wifi test
 */

const G_NAME = 'DaYu200'

@Component
struct WifiManagerDeviceSetting {
  private w_ssid1 = "TP-LINK_6365";
  private w_bssid1 = "6C:B1:58:75:63:65";
  private w_preSharedKey1 = "kaihong123";
  private w_isHiddenSsid1 = "false";
  @State w_securityType1: number = 3;
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
  @State w_networkId1: number = 0 ;
  @State w_featureId1: number = 1 ;

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
    AppStorage.SetOrCreate( 'w_staticIp_gateway1' , this.w_taticIp_gateway1 );
    AppStorage.SetOrCreate( 'w_staticIp_dnsServers1' , this.w_staticIp_dnsServers1 );
    AppStorage.SetOrCreate( 'w_staticIp_domains1' , this.w_staticIp_domains1 );
    AppStorage.SetOrCreate( 'w_networkId1' , this.w_networkId1 );
    AppStorage.SetOrCreate( 'w_featureId1' , this.w_featureId1 );
  }

  build() {
    Column() {
      Row() {
        Text( "ssid1:" ).fontSize( "17vp" ).width( 70 )
        TextInput( { text : this.w_ssid1 , placeholder : "TP-LINK_6365" } )
          .fontSize( "15vp" )
          .onChange( ( strInput ) => {
            this.w_ssid1 = strInput;
            AppStorage.SetOrCreate( 'w_ssid1' , strInput );
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
              Text( "bssid1:" ).fontSize( "15vp" ).width( 60 );
              TextInput( { text : this.w_bssid1 , placeholder : "6c:b1:58:75:63:67" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_bssid1 = strInput;
                  AppStorage.SetOrCreate( 'w_bssid1' , strInput );
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .padding( 3 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )
            .backgroundColor( $r( "app.color.spring" ) )

            Row() {
              Text( "preSharedKey1:" ).fontSize( "15vp" ).width( 110 );
              TextInput( { text : this.w_preSharedKey1 , placeholder : "kaihong123" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_preSharedKey1 = strInput;
                  AppStorage.SetOrCreate( 'w_preSharedKey1' , strInput );
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .backgroundColor( $r( "app.color.spring" ) )
            .padding( 5 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )

            Row() {
              Text( "isHiddenSsid1:" ).fontSize( 15 ).width( 110 );
              TextInput( { text : this.w_isHiddenSsid1 , placeholder : "false" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_isHiddenSsid1 = strInput;
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_isHiddenSsid1' , strInput );
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
              Text( "securityType1:" ).fontSize( 15 ).width( 100 );
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
                    this.w_securityType1 = index;
                    AppStorage.SetOrCreate( 'w_securityType1' , index );
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
              Text( "creatorUid1:" ).fontSize( 15 ).width( 100 );
              TextInput( { text : this.w_creatorUid1 , placeholder : "1" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_creatorUid1 = Number(strInput);
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_creatorUid1' , strInput );
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
              Text( "disableReason1:" ).fontSize( 15 ).width( 120 );
              TextInput( { text : this.w_disableReason1 , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_disableReason1 = strInput;
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_disableReason1' , strInput );
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
              Text( "netId1:" ).fontSize( 15 ).width( 60 );
              TextInput( { text : this.w_netId1 , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_netId1 = strInput;
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_netId1' , strInput );
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
              Text( "randomMacType1:" ).fontSize( 15 ).width( 140 );
              TextInput( { text : this.w_randomMacType1 , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_randomMacType1 = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_randomMacType1' , strInput );
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
              Text( "randomMacAddr1:" ).fontSize( 15 ).width( 140 );
              TextInput( { text : this.w_randomMacAddr1 , placeholder : "08:fb:ea:1b:38:aa" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_randomMacAddr1 = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_randomMacAddr1' , strInput );
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
              Text( "ipType1:" ).fontSize( 15 ).width( 60 );
              TextInput( { text : this.w_ipType1 , placeholder : "1" } ) //DHCP
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_ipType1 = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_ipType1' , strInput );
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
              Text( "staticIp_ipAddress1:" ).fontSize( 15 ).width( 135 );
              TextInput( { text : this.w_staticIp_ipAddress1 , placeholder : "3232235880" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_staticIp_ipAddress1 = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_staticIp_ipAddress1' , strInput );
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
              Text( "staticIp_gateway1:" ).fontSize( 15 ).width( 130 );
              TextInput( { text : this.w_staticIp_gateway1 , placeholder : "3232235777" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_staticIp_gateway1 = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_staticIp_gateway1' , strInput );
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
              Text( "staticIp_dnsServers1:" ).fontSize( 15 ).width( 140 );
              TextInput( { text : this.w_staticIp_dnsServers1 , placeholder : "3716386629" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_staticIp_dnsServers1 = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_staticIp_dnsServers1' , strInput );
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
              Text( "staticIp_domains1:" ).fontSize( 15 ).width( 125 );
              TextInput( { text : this.w_staticIp_domains1 , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.w_staticIp_domains1 = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'w_staticIp_domains1' , strInput );
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
struct WifiManagerInterfaceTest {
  @State showList: boolean = false;
  private testItem: TestData = Router.getParams().testId;
  @State message: string = "";
  @State deviceId: string = '';
  @State currentClick: number = - 1;
  @StorageLink( 'pairedMac' ) pairedMac: string = "32:32:235:878";
  @State w_ssid1: string = "TP-LINK_6365"; //TP-LINK_6365
  @State w_bssid1: string = "6C:B1:58:75:63:65"; //6C:B1:58:75:63:65
  @State w_preSharedKey1: string = "kaihong123"; //kaihong123
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
  @State w_networkId1: number = 0 ;
  @State w_featureId1: number = 1 ;
  @StorageLink( 'ipInfoManagerMessage' ) ipInfoManagerMessage: string = '';
  @StorageLink( 'linkedInfoManagerMessage' ) linkedInfoManagerMessage: string = '';
  @StorageLink( 'getDeviceConfigsManagerMessage' ) getDeviceConfigsManagerMessage: string = '';
  @StorageLink( 'getScanInfoManagerMessage' ) getScanInfoManagerMessage: string = '';

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
    AppStorage.SetOrCreate( 'w_networkId1' , this.w_networkId1 );
    AppStorage.SetOrCreate( 'w_featureId1' , this.w_featureId1 );
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
        WifiManagerDeviceSetting()
      } else {
        Column() {
          Scroll() {
            Column() {
              Text( "WLAN连接信息:" + this.linkedInfoManagerMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "IP信息:" + this.ipInfoManagerMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "获取网络配置:" + this.getDeviceConfigsManagerMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "扫描结果:" + this.getScanInfoManagerMessage )
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
          testItem : this.testItem , apiItems : initWifiManagerApiData()
        } )
      }
    }
    .alignItems( HorizontalAlign.Center )
    .backgroundColor( $r( "app.color.lead" ) )
    .height( ConfigData.WH_100_100 )
  }
}
