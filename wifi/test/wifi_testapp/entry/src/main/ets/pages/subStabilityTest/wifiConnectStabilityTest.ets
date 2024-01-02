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
 * WiFiConnectStabilityTest Page Of wifi test
 */
const TAG = '[WiFiConnectStabilityTest]'

@Entry
@Component
struct WiFiConnectStabilityTest {
  private testItem: TestData = Router.getParams().testId;
  @State connect_StartTime: Number = 0
  @State connect_EndTime: Number = 0
  @State connect_SpendTime: Number = 0
  @State disconnect_StartTime: Number = 0
  @State disconnect_EndTime: Number = 0
  @State disconnect_SpendTime: Number = 0
  @State connectNumber: Number = 0 // 打开WiFi的次数
  @State disconnectNumber: Number = 0 // 关闭WiFi的次数
  @State connectSuccessNumber: Number = 0 // 打开WiFi的成功次数
  @State connectFailNumber: Number = 0 // 打开WiFi的失败次数
  @State disconnectSuccessNumber: Number = 0 // 关闭WiFi的成功次数
  @State disconnectFailNumber: Number = 0 // 关闭WiFi的失败次数
  @State message: string = "测试结果"
  @State testNumbers: Number = 30 //测试次数
  @State successTimes: Number = 0
  @State failTimes: Number = 0
  @State connectionMessage: String = ""
  @State connectionMessageLog: String = ""
  @State connectionLoopState: Boolean = true
  @State showList: boolean = false;
  @State ipInfo: string = ""
  @StorageLink( 'wifiConfig' ) wifiConfig: Object = {
    ssid : String = "TP-LINK_6365" ,
    bssid : String = "6C:B1:58:75:63:65" ,
    preSharedKey : String = "12345678" ,
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
          TextInput( { placeholder : "请输入循环次数，默认为30" } )
            .placeholderColor( Color.Grey )
            .placeholderFont( { size : $r( 'app.float.font_16' ) } )
            .caretColor( Color.Blue )
            .width( "50%" )
            .fontSize( $r( 'app.float.font_16' ) )
            .fontColor( $r( 'app.color.title_black_color' ) )
            .onChange( ( value: string ) => {
              this.testNumbers = parseInt( value );
            } )
          Image( $r( 'app.media.Switch' ) )
            .height( 50 )
            .padding( { top : 5 , bottom : 5 , left : 5 } )
            .width( ConfigData.WH_15_100 )
            .onClick( () => {
              this.showList = !this.showList;
            } )
        }
      }.width( "100%" ).height( "6%" ).backgroundColor( $r( "app.color.lead" ) )

      if ( this.showList ) {
        setWifiDevice()
      } else {
        Column() {

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
                Text( "连接的成功次数：" + this.connectSuccessNumber )
                  .fontSize( "18vp" )
                  .margin( { top : "5vp" , left : "10vp" , right : "5vp" } )
                  .textAlign( TextAlign.Start )
                  .width( ConfigData.WH_90_100 )
                Text( "连接的失败次数：" + this.connectFailNumber )
                  .fontSize( "18vp" )
                  .margin( { top : "5vp" , left : "10vp" , right : "5vp" } )
                  .textAlign( TextAlign.Start )
                  .width( ConfigData.WH_90_100 )
                Text( "断连的成功次数：" + this.disconnectSuccessNumber )
                  .fontSize( "18vp" )
                  .margin( { top : "5vp" , left : "10vp" , right : "5vp" } )
                  .textAlign( TextAlign.Start )
                  .width( ConfigData.WH_90_100 )
                Text( "断连的失败次数：" + this.disconnectFailNumber )
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

          }.width( "100%" ).height( "35%" )

          Column() {
            Text( "log显示：" )
              .fontSize( "22vp" )
              .width( ConfigData.WH_95_100 )
              .align( Alignment.TopStart )
              .padding( { top : "10vp" } )
            List() {
              ListItem() {
                Text( this.connectionMessageLog )
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

        }.width( "100%" ).height( "60%" ).backgroundColor( $r( "app.color.lead" ) )

        Stack().height( "1vp" ).backgroundColor( $r( "app.color.black" ) );

        Column() {
          Row() {
            Button( "开始连接测试" )
              .operateButtonStyle( $r( 'app.color.main_blue' ) )
              .padding( { right : "10vp" } )
              .onClick( async( event: ClickEvent ) => {
                console.log( TAG , "start WiFiConnect test-------------" )
                let self = this
                self.connectionLoopState = true
                self.connectNumber = 0
                self.connectSuccessNumber = 0
                self.connectFailNumber = 0
                self.disconnectNumber = 0
                self.disconnectSuccessNumber = 0
                self.disconnectFailNumber = 0

                async function forLoop() {
                  self.connectionMessageLog = ""
                  self.onConnectionState() // 监听函数
                  let funcMessage = "" // 函数信息
                  for ( self.connectNumber ; self.connectNumber < self.testNumbers ; self.connectNumber ++ ) {
                    if ( !self.connectionLoopState ) {
                      console.log( TAG , "测试结束------------" )
                      break;
                    } else {
                      let wifiState = wifiManager.isWifiActive()
                      if ( !wifiState ) {
                        wifi.enableWifi()
                        console.log( TAG , "wifi当前未使能，已经使能，正常开始测试------" )
                      } else {
                        console.log( TAG , "wifi当前使能，正常开始测试------" )
                      }
                      await sleep( 3 )

                      funcMessage = wifi.connectToDevice( self.wifiConfig )
                      // 打时间戳
                      self.connect_StartTime = new Date().getTime()
                      console.log( TAG , "第" + ( self.connectNumber + 1 ) + "次WIFI连接-----" )
                      console.log( TAG , "第" + ( self.connectNumber + 1 ) + "次WIFI连接开始时间: " + self.connect_StartTime + "ms" )
                      self.connectionMessageLog += "第" + ( self.connectNumber + 1 ) + "次WIFI连接接口的调用结果：" + funcMessage + "\n"
                      console.log( TAG , "第" + ( self.connectNumber + 1 ) + "次WIFI连接接口的调用结果：" + funcMessage )
                      await sleep( 15 )
                      self.connectionMessage = AppStorage.Get( "connectionMessage" )
                      // prompt.showToast( { message : funcMessage } )
                      if ( self.connectionMessage == "connected" ) {
                        self.connect_SpendTime = self.connect_EndTime - self.connect_StartTime
                        self.connectionMessageLog += "第" + ( self.connectNumber + 1 ) + "次WIFI连接耗时: " + self.connect_SpendTime + "ms; IP: " + self.ipInfo + "\n"
                        console.log( TAG , "第" + ( self.connectNumber + 1 ) + "次WIFI连接耗时: " + self.connect_SpendTime + "ms; IP: " + self.ipInfo )
                        self.connectSuccessNumber = self.connectSuccessNumber + 1
                        self.connectionMessageLog += "连接成功的次数：" + self.connectSuccessNumber + "\n"
                        console.log( TAG , "连接成功的次数：" + self.connectSuccessNumber )
                        funcMessage = wifi.disconnect()
                        self.disconnectNumber = self.disconnectNumber + 1
                        self.disconnect_StartTime = new Date().getTime()
                        console.log( TAG , "第" + self.disconnectNumber + "次WIFI断连-----" )
                        console.log( TAG , "第" + self.disconnectNumber + "次WIFI断连开始时间: " + self.disconnect_StartTime + "ms" )
                        self.connectionMessageLog += "第" + self.disconnectNumber + "次WIFI断连接口的调用结果：" + funcMessage + "\n"
                        console.log( TAG , "第" + self.disconnectNumber + "次WIFI断连接口的调用结果：" + funcMessage )
                        console.log( TAG , "disconnectNumber: " + self.disconnectNumber )
                        await sleep( 15 )
                        // prompt.showToast( { message : funcMessage } )
                        self.connectionMessage = AppStorage.Get( "connectionMessage" )
                        if ( self.connectionMessage == "disconnected" ) {
                          self.disconnect_SpendTime = self.disconnect_EndTime - self.disconnect_StartTime
                          self.connectionMessageLog += "第" + self.disconnectNumber + "次WIFI断连耗时: " + self.disconnect_SpendTime + "ms" + "\n"
                          console.log( TAG , "第" + self.disconnectNumber + "次WIFI断连耗时: " + self.disconnect_SpendTime + "ms" )
                          self.disconnectSuccessNumber = self.disconnectSuccessNumber + 1
                          self.connectionMessageLog += "断连成功的次数：" + self.disconnectSuccessNumber + "\n"
                          console.log( TAG , "断连成功的次数：" + self.disconnectSuccessNumber )
                          await sleep( 15 )
                        } else {
                          self.disconnectFailNumber = self.disconnectFailNumber + 1
                          console.log( TAG , "断连失败的次数：" + self.disconnectFailNumber )
                          console.log( TAG , "第" + self.disconnectNumber + "次WIFI断连失败" )
                        }
                      } else if ( self.connectionMessage == "disconnected" ) {
                        self.connectFailNumber = self.connectFailNumber + 1
                        console.log( TAG , "连接失败的次数：" + self.connectFailNumber )
                        console.log( TAG , "第" + ( self.connectNumber + 1 ) + "次WIFI连接失败" )
                        break;
                      } else {
                        console.log( "第" + ( self.connectNumber + 1 ) + "次连接后状态不清楚" );
                        break;
                      }
                    }
                  }
                  console.log( TAG , "测试结束 -------------" )
                }

                forLoop()

              } )

            Blank().width( "10%" )

            Button( "关闭连接测试" )
              .operateButtonStyle( $r( 'app.color.main_blue' ) )
              .padding( { right : "10vp" } )
              .onClick( async( event: ClickEvent ) => {
                let self = this
                self.connectionLoopState = false
                console.log( TAG , "准备测试停止 -------------" )
                self.connectionMessageLog = ""
                self.connectNumber = 0
              } )

          }

        }.width( "100%" ).height( "25%" ).backgroundColor( $r( "app.color.lead" ) )

      }

    }.height( "100%" ).width( "100%" ).backgroundColor( $r( "app.color.lead" ) )
  }

  onConnectionState() {
    console.log( TAG , "on.wifiConnectionChange start--------" )
    wifi.on( "wifiConnectionChange" , ( number ) => {
      console.log( TAG , " on.wifiConnectionChange --------" )
      let wifiConnectionMessage = ""
      switch ( number ) {
        case 0:
          wifiConnectionMessage = "disconnected";
          break;
        case 1:
          wifiConnectionMessage = "connected";
          break;
        default:
          wifiConnectionMessage = '未知状态';
          break;
      }
      console.log( TAG , "wifi连接状态为:" + wifiConnectionMessage )
      if ( number == 1 ) {
        // 打时间戳
        this.connect_EndTime = new Date().getTime()
        console.log( TAG , "WIFI连接结束时间: " + this.connect_EndTime + "ms" )
        this.ipInfo = wifiManager.getIpInfo().ipAddress
      } else if ( number == 0 ) {
        this.disconnect_EndTime = new Date().getTime()
        console.log( TAG , "WIFI断连结束时间: " + this.disconnect_EndTime + "ms" )
        let removeMessage = wifi.removeAllNetwork()
        console.log( TAG , "移除网络配置接口的调用结果: " + removeMessage )
      }
      console.log( TAG , " on.wifiConnectionChange callback success --------" )
      prompt.showToast( { message : "wifi连接状态: " + wifiConnectionMessage } )
      this.connectionMessage = wifiConnectionMessage
      AppStorage.SetOrCreate( "connectionMessage" , this.connectionMessage )
      console.log( TAG , " on.wifiConnectionChange callback end--------" )
      return this.connectionMessage
    } )
  }

  aboutToDisappear() {
    wifi.off( "wifiConnectionChange" )
  }
}

@Component
struct setWifiDevice {
  @StorageLink( 'w_networkIdM' ) w_networkIdM: Number = 0; // id,netId,networkId是一个值嘛？
  @StorageLink( 'w_featureIdM' ) w_featureIdM: Number = 1;
  @StorageLink( 'wifiConfig' ) wifiConfig: Object = {
    ssid : String = "TP-LINK_6365" ,
    bssid : String = "6C:B1:58:75:63:65" ,
    preSharedKey : String = "12345678" ,
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
        TextInput( { text : this.wifiConfig.ssid , placeholder : "TP-LINK_6365" } )
          .fontSize( "15vp" )
          .onChange( ( strInput ) => {
            //判断合法性
            if ( strInput.length >= 1 ) {
              this.wifiConfig.ssid = strInput;
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
              TextInput( { text : this.wifiConfig.bssid , placeholder : "6c:b1:58:75:63:67" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiConfig.bssid = strInput;
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
              TextInput( { text : this.wifiConfig.preSharedKey , placeholder : "12345678" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiConfig.preSharedKey = strInput;
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
              TextInput( { text : this.wifiConfig.w_isHiddenSsidM , placeholder : "false" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiConfig.isHiddenSsid = strInput;
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
                  .onSelect( ( index: Number ) => {
                    console.log( TAG , "Select:" + index )
                    this.wifiConfig.securityType = index;
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
              TextInput( { text : this.wifiConfig.creatorUid , placeholder : "1" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiConfig.creatorUid = parseInt( strInput );
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
              TextInput( { text : this.wifiConfig.disableReason , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiConfig.disableReason = parseInt( strInput );
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
              TextInput( { text : this.wifiConfig.netId , placeholder : "1" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiConfig.netId = parseInt( strInput );
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
              TextInput( { text : this.wifiConfig.randomMacType , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiConfig.randomMacType = parseInt( strInput );
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
              TextInput( { text : this.wifiConfig.randomMacAddr , placeholder : "08:fb:ea:1b:38:aa" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiConfig.randomMacAddr = strInput;
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
              TextInput( { text : this.wifiConfig.IpType , placeholder : "1" } )//DHCP
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiConfig.IpType = parseInt( strInput );
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
              TextInput( { text : this.wifiConfig.staticIp.ipAddress , placeholder : "3232235880" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiConfig.staticIp.ipAddress = parseInt( strInput );
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
              TextInput( { text : this.wifiConfig.staticIp.gateway , placeholder : "3232235777" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiConfig.staticIp.gateway = parseInt( strInput );
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
              TextInput( { text : this.wifiConfig.staticIp.dnsServers , placeholder : "3716386629" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    this.wifiConfig.staticIp.dnsServers = parseInt( strInput );
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
              TextInput( { text : this.wifiConfig.staticIp.domains , placeholder : "0" } )
                .fontSize( "15vp" )
                .onChange( ( strInput ) => {
                  if ( strInput.length >= 1 ) {
                    this.wifiConfig.staticIp.domains = strInput;
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

/**
 * Custom button style.
 */
@Extend( Button )
function operateButtonStyle( color: Resource ) {
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