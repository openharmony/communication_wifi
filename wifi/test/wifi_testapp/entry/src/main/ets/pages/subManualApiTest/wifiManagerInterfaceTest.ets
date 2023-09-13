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
import { initWifiManagerApiData } from '../../MainAbility/model/testDataModels'
import { TestData } from '../../MainAbility/model/testData'

const TAG = '[WifiManager]'

/**
 * wifiManager Test Page Of Wifi test
 */

@Component
struct WifiManagerDeviceSetting {
  @StorageLink( 'w_networkIdM' ) w_networkIdM: number = 0; // id,netId,networkId是一个值嘛？
  @StorageLink( 'w_featureIdM' ) w_featureIdM: number = 1;
  @StorageLink( 'wifiDeviceConfigManager' ) wifiDeviceConfigManager: Object = {
    ssid : String = "TP-LINK_6365" ,
    bssid : String = "6C:B1:58:75:63:65" ,
    preSharedKey : String = "kaihong123" ,
    isHiddenSsid : Boolean = false ,
    securityType : Number = 3 ,
    creatorUid : Number = 1 ,
    disableReason : Number = 0 ,
    netId : Number = 1 ,
    randomMacType : Number = 0 ,
    randomMacAddr : String = "08:fb:ea:1b:38:aa" ,
    ipType : Number = 1 ,
    staticIp : {
      ipAddress : Number = 3232235880 ,
      gateway : Number = 3232235777 ,
      dnsServers : Number = 3716386629 ,
      domains : [] = [ "0", "1", "2" ] ,
    }
  }

  aboutToAppear() {

  }

  build() {
    Column() {
      Row() {
        Text( "ssidM:" ).fontSize( "17vp" ).width( 70 )
        TextInput( { text : this.wifiDeviceConfigManager.ssid , placeholder : "TP-LINK_6365" } )
          .fontSize( "15vp" )
          .onChange( ( strInput ) => {
            //判断合法性
            if ( strInput.length >= 1 ) {
              this.wifiDeviceConfigManager.ssid = strInput;
            }
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
              Text( "bssidM:" ).fontSize( "15vp" ).width( 60 );
              TextInput( { text : this.wifiDeviceConfigManager.bssid , placeholder : "6c:b1:58:75:63:67" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiDeviceConfigManager.bssid = strInput;
                  }
                } )
                .width( ConfigData.WH_80_100 )
                .borderRadius( 1 )
            }
            .padding( 3 )
            .justifyContent( FlexAlign.Start )
            .alignItems( VerticalAlign.Center )
            .backgroundColor( $r( "app.color.spring" ) )

            Row() {
              Text( "preSharedKeyM:" ).fontSize( "15vp" ).width( 110 );
              TextInput( { text : this.wifiDeviceConfigManager.preSharedKey , placeholder : "kaihong123" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiDeviceConfigManager.preSharedKey = strInput;
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
              Text( "isHiddenSsidM:" ).fontSize( 15 ).width( 110 );
              TextInput( { text : this.wifiDeviceConfigManager.w_isHiddenSsidM , placeholder : "false" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiDeviceConfigManager.isHiddenSsid = strInput;
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
              Text( "securityTypeM:" ).fontSize( 15 ).width( 100 );
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
                    console.log( TAG , "Select:" + index )
                    this.wifiDeviceConfigManager.securityType = index;
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
              Text( "creatorUidM:" ).fontSize( 15 ).width( 100 );
              TextInput( { text : this.wifiDeviceConfigManager.creatorUid , placeholder : "1" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiDeviceConfigManager.creatorUid = Number( strInput );
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
              Text( "disableReasonM:" ).fontSize( 15 ).width( 120 );
              TextInput( { text : this.wifiDeviceConfigManager.disableReason , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiDeviceConfigManager.disableReason = Number( strInput );
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
              Text( "netIdM:" ).fontSize( 15 ).width( 60 );
              TextInput( { text : this.wifiDeviceConfigManager.netId , placeholder : "1" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiDeviceConfigManager.netId = Number( strInput );
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
              Text( "randomMacTypeM:" ).fontSize( 15 ).width( 140 );
              TextInput( { text : this.wifiDeviceConfigManager.randomMacType , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiDeviceConfigManager.randomMacType = Number( strInput );
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
              Text( "randomMacAddrM:" ).fontSize( 15 ).width( 140 );
              TextInput( { text : this.wifiDeviceConfigManager.randomMacAddr , placeholder : "08:fb:ea:1b:38:aa" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiDeviceConfigManager.randomMacAddr = strInput;
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
              Text( "ipTypeM:" ).fontSize( 15 ).width( 60 );
              TextInput( { text : this.wifiDeviceConfigManager.IpType , placeholder : "1" } ) //DHCP
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiDeviceConfigManager.IpType = Number( strInput );
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
              Text( "staticIp_ipAddressM:" ).fontSize( 15 ).width( 135 );
              TextInput( { text : this.wifiDeviceConfigManager.staticIp.ipAddress , placeholder : "3232235880" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiDeviceConfigManager.staticIp.ipAddress = Number( strInput );
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
              Text( "staticIp_gatewayM:" ).fontSize( 15 ).width( 130 );
              TextInput( { text : this.wifiDeviceConfigManager.staticIp.gateway , placeholder : "3232235777" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiDeviceConfigManager.staticIp.gateway = Number( strInput );
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
              Text( "staticIp_dnsServersM:" ).fontSize( 15 ).width( 140 );
              TextInput( { text : this.wifiDeviceConfigManager.staticIp.dnsServers , placeholder : "3716386629" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiDeviceConfigManager.staticIp.dnsServers = Number( strInput );
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
              Text( "staticIp_domainsM:" ).fontSize( 15 ).width( 125 );
              TextInput( { text : this.wifiDeviceConfigManager.staticIp.domains , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  if ( strInput.length >= 1 ) {
                    this.wifiDeviceConfigManager.staticIp.domains = strInput;
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
  @StorageLink( 'pairedSsidM' ) pairedSsidM: string = "";
  @StorageLink( 'w_networkIdM' ) w_networkIdM: number = 0;
  @StorageLink( 'w_featureIdM' ) w_featureIdM: number = 1;
  @StorageLink( 'ipInfoManagerMessage' ) ipInfoManagerMessage: string = '';
  @StorageLink( 'linkedInfoManagerMessage' ) linkedInfoManagerMessage: string = '';
  @StorageLink( 'getDeviceConfigsManagerMessage' ) getDeviceConfigsManagerMessage: string = '';
  @StorageLink( 'getScanInfoManagerMessage' ) getScanInfoManagerMessage: string = '';
  @StorageLink( 'wifiDeviceConfigManager' ) wifiDeviceConfigManager: Object = {
    ssid : String = "TP-LINK_6365" ,
    bssid : String = "6C:B1:58:75:63:65" ,
    preSharedKey : String = "kaihong123" ,
    isHiddenSsid : Boolean = false ,
    securityType : Number = 3 ,
    creatorUid : Number = 1 ,
    disableReason : Number = 0 ,
    netId : Number = 100 ,
    randomMacType : Number = 0 ,
    randomMacAddr : String = "08:fb:ea:1b:38:aa" ,
    ipType : Number = 1 ,
    staticIp : {
      ipAddress : Number = 3232235880 ,
      gateway : Number = 3232235777 ,
      dnsServers : Number = 3716386629 ,
      domains : [] = [ "0", "1", "2" ] ,
    }
  }

  aboutToAppear() {

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

          TextInput( { text : this.pairedSsidM , placeholder : "请在右侧输入WiFi的配置" } )
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