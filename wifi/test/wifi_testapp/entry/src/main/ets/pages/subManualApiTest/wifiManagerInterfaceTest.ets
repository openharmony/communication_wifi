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
  private ssid1 = "TP-LINK_6365";
  private bssid1 = "6C:B1:58:75:63:65";
  private preSharedKey1 = "kaihong123";
  private isHiddenSsid1 = "false";
  @State securityType1: number = 3
  @State creatorUid1: string = "1";
  @State disableReason1: number = 0;
  @State netId1: number = 0 ;
  @State randomMacType1: number = 0 ;
  @State randomMacAddr1: string = "08:fb:ea:1b:38:aa"
  @State ipType1: number = 1 ;
  @State staticIp_ipAddress1: number = 3232235880 ;
  @State staticIp_gateway1: number = 3232235777 ;
  @State staticIp_dnsServers1: number = 3716386629 ;
  @State staticIp_domains1: Array<string> = [ "0", "1", "2" ] ;

  aboutToAppear() {
    AppStorage.SetOrCreate( 'ssid1' , this.ssid1 );
    AppStorage.SetOrCreate( 'bssid1' , this.bssid1 );
    AppStorage.SetOrCreate( 'preSharedKey1' , this.preSharedKey1 );
    AppStorage.SetOrCreate( 'isHiddenSsid1' , this.isHiddenSsid1 );
    AppStorage.SetOrCreate( 'securityType1' , this.securityType1 );
    AppStorage.SetOrCreate( 'creatorUid1' , this.creatorUid1 );
    AppStorage.SetOrCreate( 'disableReason1' , this.disableReason1 );
    AppStorage.SetOrCreate( 'netId1' , this.netId1 );
    AppStorage.SetOrCreate( 'randomMacType1' , this.randomMacType1 );
    AppStorage.SetOrCreate( 'randomMacAddr1' , this.randomMacAddr1 );
    AppStorage.SetOrCreate( 'ipType1' , this.ipType1 );
    AppStorage.SetOrCreate( 'staticIp_ipAddress1' , this.staticIp_ipAddress1 );
    AppStorage.SetOrCreate( 'staticIp_gateway1' , this.staticIp_gateway1 );
    AppStorage.SetOrCreate( 'staticIp_dnsServers1' , this.staticIp_dnsServers1 );
    AppStorage.SetOrCreate( 'staticIp_domains1' , this.staticIp_domains1 );
  }

  build() {
    Column() {
      Row() {
        Text( "ssid1:" ).fontSize( "17vp" ).width( 70 )
        TextInput( { text : this.ssid1 , placeholder : "TP-LINK_6365" } )
          .fontSize( "15vp" )
          .onChange( ( strInput ) => {
            this.ssid1 = strInput;
            AppStorage.SetOrCreate( 'ssid1' , strInput );
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
              TextInput( { text : this.bssid1 , placeholder : "6c:b1:58:75:63:67" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.bssid1 = strInput;
                  AppStorage.SetOrCreate( 'bssid1' , strInput );
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
              TextInput( { text : this.preSharedKey1 , placeholder : "kaihong123" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.preSharedKey1 = strInput;
                  AppStorage.SetOrCreate( 'preSharedKey1' , strInput );
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
              TextInput( { text : this.isHiddenSsid1 , placeholder : "false" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.isHiddenSsid1 = strInput;
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'isHiddenSsid1' , strInput );
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
                    this.securityType1 = index;
                    AppStorage.SetOrCreate( 'securityType1' , index );
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
              TextInput( { text : this.creatorUid1 , placeholder : "1" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.creatorUid1 = strInput;
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'creatorUid1' , strInput );
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
              TextInput( { text : this.disableReason1 , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.disableReason1 = strInput;
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'disableReason1' , strInput );
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
              TextInput( { text : this.netId1 , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.netId1 = strInput;
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'netId1' , strInput );
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
              TextInput( { text : this.randomMacType1 , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.randomMacType1 = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'randomMacType1' , strInput );
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
              TextInput( { text : this.randomMacAddr1 , placeholder : "08:fb:ea:1b:38:aa" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.randomMacAddr1 = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'randomMacAddr1' , strInput );
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
              TextInput( { text : this.ipType1 , placeholder : "1" } ) //DHCP
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.ipType1 = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'ipType1' , strInput );
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
              TextInput( { text : this.staticIp_ipAddress1 , placeholder : "3232235880" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.staticIp_ipAddress1 = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'staticIp_ipAddress1' , strInput );
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
              TextInput( { text : this.staticIp_gateway1 , placeholder : "3232235777" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.staticIp_gateway1 = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'staticIp_gateway1' , strInput );
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
              TextInput( { text : this.staticIp_dnsServers1 , placeholder : "3716386629" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.staticIp_dnsServers1 = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'staticIp_dnsServers1' , strInput );
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
              TextInput( { text : this.staticIp_domains1 , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  this.staticIp_domains1 = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.SetOrCreate( 'staticIp_domains1' , strInput );
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
  @StorageLink( 'setLocalNameRet' ) setLocalNameRet: boolean = false;
  @StorageLink( 'setScanModeRet' ) setScanModeRet: boolean = false;
  @State deviceId: string = '';
  @State currentClick: number = - 1;
  @StorageLink( 'pairedMac' ) pairedMac: string = "32:32:235:878";
  private ssid1 = "TP-LINK_6365";
  private bssid1 = "6C:B1:58:75:63:65";
  private preSharedKey1 = "kaihong123";
  private isHiddenSsid1 = false;
  @State securityType1: number = 3
  @State creatorUid1: number = 1;
  @State disableReason1: number = 0;
  @State netId1: number = 0 ;
  @State randomMacType1: number = 0 ;
  @State randomMacAddr1: string = "08:fb:ea:1b:38:aa"
  @State ipType1: number = 1 ;
  @State staticIp_ipAddress1: number = 3232235880 ;
  @State staticIp_gateway1: number = 3232235777 ;
  @State staticIp_dnsServers1: number = 3716386629 ;
  @State staticIp_domains1: Array<string> = [ "0", "1", "2" ] ;
  @StorageLink( 'ipInfoManagerMessage' ) ipInfoManagerMessage: string = '';
  @StorageLink( 'linkedInfoManagerMessage' ) linkedInfoManagerMessage: string = '';
  @StorageLink( 'getDeviceConfigsManagerMessage' ) getDeviceConfigsManagerMessage: string = '';
  @StorageLink( 'getScanInfoManagerMessage' ) getScanInfoManagerMessage: string = '';

  aboutToAppear() {
    AppStorage.SetOrCreate( 'ssid1' , this.ssid1 );
    AppStorage.SetOrCreate( 'bssid1' , this.bssid1 );
    AppStorage.SetOrCreate( 'preSharedKey1' , this.preSharedKey1 );
    AppStorage.SetOrCreate( 'isHiddenSsid1' , this.isHiddenSsid1 );
    AppStorage.SetOrCreate( 'securityType1' , this.securityType1 );
    AppStorage.SetOrCreate( 'creatorUid1' , this.creatorUid1 );
    AppStorage.SetOrCreate( 'disableReason1' , this.disableReason1 );
    AppStorage.SetOrCreate( 'netId1' , this.netId1 );
    AppStorage.SetOrCreate( 'randomMacType1' , this.randomMacType1 );
    AppStorage.SetOrCreate( 'randomMacAddr1' , this.randomMacAddr1 );
    AppStorage.SetOrCreate( 'ipType1' , this.ipType1 );
    AppStorage.SetOrCreate( 'staticIp_ipAddress1' , this.staticIp_ipAddress1 );
    AppStorage.SetOrCreate( 'staticIp_gateway1' , this.staticIp_gateway1 );
    AppStorage.SetOrCreate( 'staticIp_dnsServers1' , this.staticIp_dnsServers1 );
    AppStorage.SetOrCreate( 'staticIp_domains1' , this.staticIp_domains1 );
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
              //              Text("当前配置:")
              //                .fontSize("17vp")
              //                .margin({ top: "5vp", left: "10vp" })
              //                .textAlign(TextAlign.Start)
              //                .width(ConfigData.WH_100_100)
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

