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
import { P2pAutoTestCase , initP2pAutoData } from '../../MainAbility/model/autoTestDataModels'
import { AutoContentTable } from '../../Component/autoContentTable'
import * as p2pInterface from '../../MainAbility/model/p2pInterface'
import prompt from '@system.prompt';
import emitter from '@ohos.events.emitter'

/**
 *  p2pAutoTest Page Of wifi test
 */

@Entry
@Component
struct P2pAutoTest {
  @State message: string = 'P2pAutoTest';
  //  @State textMessage: string = 'null';
  //  @State testState: boolean = false;
  private testItem: TestData = router.getParams().testId;
  @State changeIndex: number = - 1
  //  @State autoTextMessage: string ="None";
  @StorageLink( "p2pAutoTestMessage" ) p2pAutoTestMessage: string = ""
  @State deviceAddress: string = '6c:96:d7:3d:87:6f';
  @State netId: number = - 2 ;
  @State passphrase: string = "12345678" ;
  @State groupName: string = "testGroup"
  @State goBand: number = 0 ;
  @State deviceName: string = "MyTestDevice"

  aboutToAppear() {
    AppStorage.SetOrCreate( "deviceAddress" , this.deviceAddress )
    AppStorage.SetOrCreate( "netId" , this.netId )
    AppStorage.SetOrCreate( "passphrase" , this.passphrase )
    AppStorage.SetOrCreate( "groupName" , this.groupName )
    AppStorage.SetOrCreate( "goBand" , this.goBand )
    AppStorage.SetOrCreate( "deviceName" , this.deviceName )
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
              autoItems : initP2pAutoData() ,
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
                Text( "log:" + "\n" + this.p2pAutoTestMessage )
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
          let p2pAutoTestMessage = ""

          //拼装数组
          let p2pAutoArray = [ { name : "testSetDeviceName" , para : [ "MyTestDevice" ] } ]
          let Interface = P2pAutoTestCase.map( i => {
            let para = p2pAutoArray.some( itm => itm.name === i.api.name ) ? p2pAutoArray.find( itm => itm.name === i.api.name ).para : []
            return { name : i.api.name , para }
          } )

          //循环调用
          async function forLoop() {
            for ( let m = 0 ; m < Interface.length ; m ++ ) {
              p2pAutoTestMessage += P2pAutoTestCase[m]["api"]( ... Interface[m].para ) + "\n"
              self.changeIndex = m
              await sleep( 2 )
              AppStorage.SetOrCreate( "p2pAutoTestMessage" , p2pAutoTestMessage )
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