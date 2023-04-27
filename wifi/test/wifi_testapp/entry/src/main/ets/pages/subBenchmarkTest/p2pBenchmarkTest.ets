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
import router from '@system.router'
import { PageTitle } from '../../Component/pageTitle'
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { TestData } from '../../MainAbility/model/testData'
import { initP2pBenchmarkData } from '../../MainAbility/model/benchmarkTestDataModels'
import * as WifiInterface from '../../MainAbility/model/wifiInterface'
import { P2pBenchmarkTestCase } from '../../MainAbility/model/benchmarkTestDataModels'
import ConfigData from "../../Utils/ConfigData"
/**
 *  classic p2p benchmark Test Page of wifi test
 */

@Entry
@Component
struct P2PBenchmarkTest {
  @State message: string = 'WifiBenchmarkTest';
  private testItem: TestData = router.getParams().testId;
  @State changeIndex: number = - 1
  @StorageLink( "wifiBenchmarkTestMessage" ) wifiBenchmarkTestMessage: string = ""

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
            Text( "性能测试:" )
              .fontSize( "17vp" )
              .margin( { top : "10vp" , bottom : "10vp" , left : "20vp" } )
              .textAlign( TextAlign.Start )
              .width( ConfigData.WH_100_100 )
            Text( "Wifi的性能测试是测试在发现wifi时的时间性能和稳定性能" )
              .fontSize( "17vp" )
              .margin( { left : "10vp" } )
          }
          .width( ConfigData.WH_100_100 )
          .height( 100 )

        }
        .scrollBarWidth( 10 )
        .scrollBar( BarState.Auto )

        Stack().height( "1vp" ).backgroundColor( "#000000" )

        Scroll() {
          Column() {
            Text( "日志:" )
              .fontSize( "17vp" )
              .margin( { top : "8vp" , bottom : "8vp" , left : "10vp" } )
              .textAlign( TextAlign.Start )
              .width( ConfigData.WH_100_100 )
            List() {
              ListItem() {
                Text( this.wifiBenchmarkTestMessage )
                  .fontSize( "17vp" )
                  .margin( { top : "5vp" , left : "10vp" , right : "10vp" } )
                  .textAlign( TextAlign.Start )
                  .width( ConfigData.WH_90_100 )
              }
            }
            .height( ConfigData.WH_90_100 )
            .width( ConfigData.WH_90_100 )
            .backgroundColor( $r( "sys.color.ohos_id_color_foreground_contrary" ) )
          }
          .width( ConfigData.WH_100_100 )
          .height( 400 )
        }
        .scrollBarWidth( 10 )
        .scrollBar( BarState.On )

      }
      .width( ConfigData.WH_100_100 )
      .backgroundColor( $r( "sys.color.ohos_id_color_sub_background" ) )

      Column() {
        Flex( { alignItems : ItemAlign.Center , justifyContent : FlexAlign.SpaceBetween } ) {
          Button( { type : ButtonType.Normal , stateEffect : true } ) {
            Text( '性能测试准备' ).fontSize( "24vp" ).fontColor( 0xffffff ).margin( { left : 5 , right : 5 } )
          }
          .borderRadius( 8 )
          .backgroundColor( $r( "app.color.blue" ) )
          .width( 100 )
          .height( 66 )
          .margin( { top : "15vp" , left : "5vp" } )
          .align( Alignment.Start )
          .onClick( async( event: ClickEvent ) => {
            let wifiBenchmarkTestMessage = ""
            //拼装数组
            var wifiBenchmarkArray = [ /*{ name: "testSetLocalName", para: ["DaYuBlue"] },
                                    { name: "testSetBluetoothScanMode", para: [4, 0] }*/
            ]
            let Interface = WifiBenchmarkTestCase.map( i => {
              let para = wifiBenchmarkArray.some( itm => itm.name === i.api.name ) ? wifiBenchmarkArray.find( itm => itm.name === i.api.name ).para : []
              return { name : i.api.name , para }
            } )

            async function forLoop() {
              for ( let m = 0 ; m < Interface.length ; m ++ ) {
                wifiBenchmarkTestMessage += wifiBenchmarkTestCase[m]["name"] + "," + testFunc( WifiBenchmarkTestCase[m]["api"] ) + "\n"
                AppStorage.SetOrCreate( "wifiBenchmarkTestMessage" , wifiBenchmarkTestMessage )
                await sleep( 1 )
              }
            }

            forLoop()

          } )

          Button( { type : ButtonType.Normal , stateEffect : true } ) {
            Row() {
              Text( '时间性能测试' ).fontSize( "24vp" ).fontColor( 0xffffff ).margin( { left : 5 , right : 5 } )
            }.alignItems( VerticalAlign.Center )
          }
          .borderRadius( 8 )
          .backgroundColor( $r( "app.color.blue" ) )
          .width( 100 )
          .height( 66 )
          .margin( { top : "15vp" , left : "5vp" , right : "5vp" } )
          .align( Alignment.Start )
          .onClick( async( event: ClickEvent ) => {
            let wifiBenchmarkTestMessage = ""
            brBenchmarkTestMessage += "subscribeBluetoothDeviceFind:" + testFunc( subscribeBluetoothDeviceFind ) + "\n"
            AppStorage.SetOrCreate( "wifiBenchmarkTestMessage" , wifiBenchmarkTestMessage )
            await sleep( 1 )
            brBenchmarkTestMessage += "startBluetoothDiscovery 执行：" + testFunc( WifiInterface.startBluetoothDiscovery ) + "\n"
            AppStorage.SetOrCreate( "wifiBenchmarkTestMessage" , wifiBenchmarkTestMessage )
            //            await sleep(1)
            //            subscribeBluetoothDeviceFind() + "\n"
            await sleep( 10 )
            brBenchmarkTestMessage += "stopBluetoothDiscovery 执行：" + testFunc( WifiInterface.testStopBluetoothDiscovery ) + "\n"
            AppStorage.SetOrCreate( "wifiBenchmarkTestMessage" , wifiBenchmarkTestMessage )
            await sleep( 1 )
            brBenchmarkTestMessage += "testOffStateChange:" + testFunc( WifiInterface.testOnStateChange ) + "\n"
            AppStorage.SetOrCreate( "wifiBenchmarkTestMessage" , wifiBenchmarkTestMessage )
            await sleep( 1 )
          } )


          Button( { type : ButtonType.Normal , stateEffect : true } ) {
            Row() {
              Image( $r( 'app.media.ic_public_delete_filled' ) ).width( 30 ).height( 40 ).margin( { left : 5 } )
              //              Text('清空').fontSize("24vp").fontColor(0xffffff).margin({ left: 5, right: 10 })
            }.alignItems( VerticalAlign.Center )
          }
          .borderRadius( 8 )
          .backgroundColor( $r( "app.color.moon" ) )
          .width( 50 )
          .height( 66 )
          .margin( { top : "15vp" , right : "5vp" } )
          .align( Alignment.Start )
          .onClick( async( event: ClickEvent ) => {
            let wifiBenchmarkTestMessage = ""
            AppStorage.SetOrCreate( "wifiBenchmarkTestMessage" , wifiBenchmarkTestMessage )
          } )
        }
        .backgroundColor( $r( "sys.color.ohos_id_color_sub_background" ) )
        .width( ConfigData.WH_100_100 )
      }
      .backgroundColor( $r( "sys.color.ohos_id_color_sub_background" ) )
      .width( ConfigData.WH_100_100 )
      .height( ConfigData.WH_100_100 );
    }
  }
}

export function test( func ) {
  var start = new Date().getTime(); //起始时间
  func(); //执行待测函数
  var end = new Date().getTime(); //接受时间
  return ( end - start ) + "ms"; //返回函数执行需要时间
}


//let arr = []
export function testFunc( func ) {
  let start = new Date().getTime()
  //  for (let index = 0; index < 10000; index++) {
  //    arr.push(index)
  //    // ...Do something
  //  }
  switch ( func ) {
    case testSetLocalName: {
      func( "DaYuBlue" )
    }
      break;
    case testSetBluetoothScanMode: {
      func( 4 , 0 )
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