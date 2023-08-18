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
import { HotspotAutoTestCase , initHotspotAutoData } from '../../MainAbility/model/autoTestDataModels'
import { AutoContentTable } from '../../Component/autoContentTable'
import * as hotspotInterface from '../../MainAbility/model/hotspotInterface'
import prompt from '@system.prompt';
import emitter from '@ohos.events.emitter'

/**
 *  hotspotAutoTest Page Of wifi test
 */
@Entry
@Component
struct HotspotAutoTest {
  @State message: string = 'HotspotAutoTest';
  //  @State textMessage: string = 'null';
  //  @State testState: boolean = false;
  private testItem: TestData = router.getParams().testId;
  @State changeIndex: number = - 1
  //  @State autoTextMessage: string ="None";
  @StorageLink( "hotspotAutoTestMessage" ) hotspotAutoTestMessage: string = ""
  @State h_ssid: string = "testApp1";
  @State h_securityType: number = 3;
  @State h_band: number = 2;
  @State h_preSharedKey: string = "12345678";
  @State h_maxConn: number = 3 ;
  @State h_channel: number = 36 ;

  aboutToAppear() {
    AppStorage.SetOrCreate( "h_ssid" , this.h_ssid )
    AppStorage.SetOrCreate( "h_securityType" , this.h_securityType )
    AppStorage.SetOrCreate( "h_band" , this.h_band )
    AppStorage.SetOrCreate( "h_preSharedKey" , this.h_preSharedKey )
    AppStorage.SetOrCreate( "h_maxConn" , this.h_maxConn )
    AppStorage.SetOrCreate( "h_channel" , this.h_channel )
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
              autoItems : initHotspotAutoData() ,
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
                Text( "log:" + "\n" + this.hotspotAutoTestMessage )
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
          let hotspotAutoTestMessage = ""

          //拼装数组
          let hotspotAutoArray = [ /*{ name : "testSetLocalName" , para : [ "DaYuBlue" ] },
                                   { name : "testSetBluetoothScanMode" , para : [ 4, 0 ] } */
          ]
          let Interface = HotspotAutoTestCase.map( i => {
            let para = hotspotAutoArray.some( itm => itm.name === i.api.name ) ? hotspotAutoArray.find( itm => itm.name === i.api.name ).para : []
            return { name : i.api.name , para }
          } )

          //循环调用
          async function forLoop() {
            for ( let m = 0 ; m < Interface.length ; m ++ ) {
              hotspotAutoTestMessage += HotspotAutoTestCase[m]["api"]( ... Interface[m].para ) + "\n"
              self.changeIndex = m
              await sleep( 2 )
              AppStorage.SetOrCreate( "hotspotAutoTestMessage" , hotspotAutoTestMessage )
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