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
import { WifiManagerAutoTestCase , initWifiManagerAutoData } from '../../MainAbility/model/autoTestDataModels'
import { AutoContentTable } from '../../Component/autoContentTable'
import * as WifiManagerInterface from '../../MainAbility/model/wifiManagerInterface'
import prompt from '@system.prompt';
import emitter from '@ohos.events.emitter'

/**
 *  wifiManagerAutoTest Page Of wifi test
 */
@Entry
@Component
struct WifiManagerAutoTest {
  @State message: string = 'WifiManagerAutoTest';
  //  @State textMessage: string = 'null';
  //  @State testState: boolean = false;
  private testItem: TestData = router.getParams().testId;
  @State changeIndex: number = - 1
  //  @State autoTextMessage: string ="None";
  @StorageLink( "wifiManagerAutoTestMessage" ) wifiManagerAutoTestMessage: string = ""
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
              autoItems : initWifiManagerAutoData() ,
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
                Text( "log:" + "\n" + this.wifiManagerAutoTestMessage )
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
          let self = this
          let wifiManagerAutoTestMessage = ""

          //拼装数组
          let wifiManagerAutoArray = [ { name : "testSetLocalName" , para : [ "DaYuBlue" ] },
                                       { name : "testSetBluetoothScanMode" , para : [ 4, 0 ] } ]
          let Interface = WifiManagerAutoTestCase.map( i => {
            let para = wifiManagerAutoArray.some( itm => itm.name === i.api.name ) ? wifiManagerAutoArray.find( itm => itm.name === i.api.name ).para : []
            return { name : i.api.name , para }
          } )

          //循环调用
          async function forLoop() {
            for ( let m = 0 ; m < Interface.length ; m ++ ) {
              wifiManagerAutoTestMessage += WifiManagerAutoTestCase[m]["api"]( ... Interface[m].para ) + "\n"
              self.changeIndex = m
              await sleep( 2 )
              AppStorage.SetOrCreate( "wifiManagerAutoTestMessage" , wifiManagerAutoTestMessage )
            }
          }

          forLoop()

          let msg = ""
          msg = "测试"
          console.log( msg )
          prompt.showToast( { message : msg } )
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