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

import ConfigData from '../../Utils/ConfigData';
import router from '@system.router';
import { TestData } from '../../MainAbility/model/testData'
import { PageTitle } from '../../Component/pageTitle';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { WifiAutoTestCase , initWifiAutoData } from '../../MainAbility/model/autoTestDataModels'
import { AutoContentTable } from '../../Component/autoContentTable'

import * as wifiInterface from '../../MainAbility/model/wifiInterface'
import prompt from '@system.prompt';
import emitter from '@ohos.events.emitter'

/**
 *  wifiAutoTest Page Of wifi test
 */

@Entry
@Component
struct WifiAutoTest {
  @State message: string = 'WifiAutoTest';
  //  @State textMessage: string = 'null';
  //  @State testState: boolean = false;
  private testItem: TestData = router.getParams().testId;
  @State changeIndex: number = - 1
  //  @State autoTextMessage: string ="None";
  @StorageLink( "wifiAutoTestMessage" ) wifiAutoTestMessage: string = ""
  private ssid = "TP-LINK_6365";
  private bssid = "6C:B1:58:75:63:65";
  private preSharedKey = "kaihong123";
  private isHiddenSsid = false;
  @State securityType: number = 3
  @State creatorUid: number = 1;
  @State disableReason: number = 0;
  @State netId: number = 100 ;
  @State randomMacType: number = 0 ;
  @State randomMacAddr: string = "08:fb:ea:1b:38:aa"
  @State ipType: number = 1 ;
  @State staticIp_ipAddress: number = 3232235880 ;
  @State staticIp_gateway: number = 3232235777 ;
  @State staticIp_dnsServers: number = 3716386629 ;
  @State staticIp_domains: Array<string> = [ "0", "1", "2" ] ;

  aboutToAppear() {
    AppStorage.SetOrCreate( 'ssid' , this.ssid );
    AppStorage.SetOrCreate( 'bssid' , this.bssid );
    AppStorage.SetOrCreate( 'preSharedKey' , this.preSharedKey );
    AppStorage.SetOrCreate( 'isHiddenSsid' , this.isHiddenSsid );
    AppStorage.SetOrCreate( 'securityType' , this.securityType );
    AppStorage.SetOrCreate( 'creatorUid' , this.creatorUid );
    AppStorage.SetOrCreate( 'disableReason' , this.disableReason );
    AppStorage.SetOrCreate( 'netId' , this.netId );
    AppStorage.SetOrCreate( 'randomMacType' , this.randomMacType );
    AppStorage.SetOrCreate( 'randomMacAddr' , this.randomMacAddr );
    AppStorage.SetOrCreate( 'ipType' , this.ipType );
    AppStorage.SetOrCreate( 'staticIp_ipAddress' , this.staticIp_ipAddress );
    AppStorage.SetOrCreate( 'staticIp_gateway' , this.staticIp_gateway );
    AppStorage.SetOrCreate( 'staticIp_dnsServers' , this.staticIp_dnsServers );
    AppStorage.SetOrCreate( 'staticIp_domains' , this.staticIp_domains );
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
            Text( "API验证:" )
              .fontSize( "17vp" )
              .margin( { top : "10vp" , bottom : "10vp" , left : "15vp" } )
              .textAlign( TextAlign.Start )
              .width( ConfigData.WH_100_100 )
            AutoContentTable( {
              testItem : this.testItem ,
              autoItems : initWifiAutoData() ,
              //             testMessage: this.testMessage,  优化时修改
              changeIndex : this.changeIndex
            } )
          }
          .width( ConfigData.WH_100_100 )
          .height( 280 )
        }
        .scrollBarWidth( 10 )
        .scrollBar( BarState.Auto )

        Stack().height( "1vp" ).backgroundColor( "#000000" );

        Scroll() {
          Column() {
            Text( "Debug日志:" )
              .fontSize( "17vp" )
              .margin( { top : "8vp" , bottom : "8vp" , left : "15vp" } )
              .textAlign( TextAlign.Start )
              .width( ConfigData.WH_100_100 )
            List() {
              ListItem() {
                Text( this.wifiAutoTestMessage )
                  //                Text("log:" + "\n"  + this.wifiAutoTestMessage)
                  .fontSize( "17vp" )
                  .margin( { top : "5vp" , left : "30vp" , right : "10vp" } )
                  .textAlign( TextAlign.Start )
                  .width( ConfigData.WH_90_100 )
              }
            }
            .height( ConfigData.WH_80_100 )
            .width( ConfigData.WH_90_100 )
            .backgroundColor( $r( "sys.color.ohos_id_color_foreground_contrary" ) )
          }
          .width( ConfigData.WH_100_100 )
          .height( 260 )
        }
        .scrollBarWidth( 10 )
        .scrollBar( BarState.On )
      }
      .height( 500 )
      .width( ConfigData.WH_100_100 )
      .backgroundColor( $r( "sys.color.ohos_id_color_sub_background" ) )


      Stack().height( "1vp" ).backgroundColor( "#000000" );
      Column() {
        Button( { type : ButtonType.Normal , stateEffect : true } ) {
          Row() {
            Text( '自动测试' ).fontSize( "24vp" ).fontColor( 0xffffff ).margin( { left : 5 , right : 5 } )
          }.alignItems( VerticalAlign.Center )
        }
        .borderRadius( 8 )
        .backgroundColor( $r( "app.color.blue" ) )
        .width( 180 )
        .height( 50 )
        .margin( { top : "15vp" } )
        .onClick( async( event: ClickEvent ) => {
          console.log( "wifiAutoTest start-------------" )
          let self = this
          let wifiAutoTestMessage = ""

          //拼装数组
          let wifiAutoArray = []
          let Interface = WifiAutoTestCase.map( i => {
            let para = wifiAutoArray.some( itm => itm.name === i.api.name ) ? wifiAutoArray.find( itm => itm.name === i.api.name ).para : []
            return { name : i.api.name , para }
          } )

          //循环调用
          async function forLoop() {
            for ( let m = 0 ; m < Interface.length ; m ++ ) {
              wifiAutoTestMessage = WifiAutoTestCase[m]["api"]( ... Interface[m].para )
              self.changeIndex = m
              await sleep( 2 )
              AppStorage.SetOrCreate( "wifiAutoTestMessage" , wifiAutoTestMessage )
            }
          }

          forLoop()

          let msg = ""
          msg = "测试"
          console.log( msg )
          prompt.showToast( { message : msg } )

          console.log( "wifiAutoTest end-------------" )
        } )
      }
      .backgroundColor( $r( "sys.color.ohos_id_color_sub_background" ) )
      .width( ConfigData.WH_100_100 )
      .height( ConfigData.WH_100_100 );
    }
  }
}


function sleep( time ) {
  return new Promise(( resolve , reject ) => {
    setTimeout( () => {
      resolve()
    } , time * 1000 )
  })
}