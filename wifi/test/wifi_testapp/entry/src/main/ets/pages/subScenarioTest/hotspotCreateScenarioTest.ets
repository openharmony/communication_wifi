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

import prompt from '@system.prompt';
import router from '@system.router';
import { PageTitle } from '../../Component/pageTitle';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { TestData } from '../../MainAbility/model/testData'
import { ScenarioContentTable } from '../../Component/scenarioContentTable'
import {
  HotspotCreateScenarioTestCase ,
  initHotspotCreateScenarioData
} from '../../MainAbility/model/scenarioTestDataModels'
import * as HotspotInterface from '../../MainAbility/model/hotspotInterface'
import ConfigData from '../../Utils/ConfigData';
/**
 * hotspot Create Scenario Test Page Of WiFi test
 */

@Entry
@Component
struct hotspotCreateScenarioTest {
  @State message: string = 'hotspotCreateScenarioTest';
  private testItem: TestData = router.getParams().testId;
  @State changeIndex: number = - 1
  @StorageLink( "hotspotCreateScenarioMessage" ) hotspotCreateScenarioMessage: string = ""

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
            Text( "场景流程验证:" )
              .fontSize( "17vp" )
              .margin( { top : "10vp" , bottom : "10vp" , left : "20vp" } )
              .textAlign( TextAlign.Start )
              .width( ConfigData.WH_100_100 )
            ScenarioContentTable( {
              testItem : this.testItem ,
              scenarioItems : initHotspotCreateScenarioData() ,
              //            testMessage: this.testMessage,  优化时修改
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
            Text( "流程日志:" )
              .fontSize( "17vp" )
              .margin( { top : "8vp" , bottom : "8vp" , left : "20vp" } )
              .textAlign( TextAlign.Start )
              .width( ConfigData.WH_100_100 )
            List() {
              ListItem() {
                Text( this.hotspotCreateScenarioMessage )
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
        Flex( { alignItems : ItemAlign.Center , justifyContent : FlexAlign.SpaceBetween } ) {
          Button( { type : ButtonType.Normal , stateEffect : true } ) {
            Text( '场景测试开始' ).fontSize( "24vp" ).fontColor( 0xffffff ).margin( { left : 5 , right : 5 } )
          }
          .borderRadius( 8 )
          .backgroundColor( $r( "app.color.blue" ) )
          .width( 100 )
          .height( 66 )
          .margin( { top : "15vp" , left : "20vp" } )
          .align( Alignment.Start )
          .onClick( async( event: ClickEvent ) => {
            prompt.showToast( { message : '开始热点创建场景测试' } )

            let self = this
            let hotspotCreateScenarioMessage = ""

            //拼装数组
            var hotspotScenarioArray = []
            let Interface = HotspotCreateScenarioTestCase.map( i => {
              let para = hotspotScenarioArray.some( itm => itm.name === i.api.name ) ? hotspotScenarioArray.find( itm => itm.name === i.api.name ).para : []
              return { name : i.api.name , para }
            } )

            //循环调用
            async function forLoop() {
              for ( let m = 0 ; m < Interface.length ; m ++ ) {
                hotspotCreateScenarioMessage += HotspotCreateScenarioTestCase[m]["api"]( ... Interface[m].para ) + "\n"
                self.changeIndex = m
                await sleep( 1 )
                AppStorage.SetOrCreate( "hotspotCreateScenarioMessage" , hotspotCreateScenarioMessage )
              }
            }

            forLoop()
          } )

          Button( { type : ButtonType.Normal , stateEffect : true } ) {
            Row() {
              Text( '场景测试结束' ).fontSize( "24vp" ).fontColor( 0xffffff ).margin( { left : 5 , right : 5 } )
            }.alignItems( VerticalAlign.Center )
          }
          .borderRadius( 8 )
          .backgroundColor( $r( "app.color.blue" ) )
          .width( 100 )
          .height( 66 )
          .margin( { top : "15vp" , left : "10vp" , right : "10vp" } )
          .align( Alignment.Start )
          .onClick( async( event: ClickEvent ) => {
            let self = this
            //            const arr = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
            let hotspotCreateScenarioMessage = ""
            // 关闭热点状态改变事件
            hotspotCreateScenarioMessage += HotspotInterface.testOnHotspotStateChange() + "\n"
            console.log( "testOnHotspotStateChange success" )
            AppStorage.SetOrCreate( "hotspotCreateScenarioMessage" , hotspotCreateScenarioMessage )
            await sleep( 1 )

            //去使能热点
            hotspotCreateScenarioMessage += HotspotInterface.testDisableHotspot() + "\n"
            console.log( "testDisableHotspot success" )
            AppStorage.SetOrCreate( "hotspotCreateScenarioMessage" , hotspotCreateScenarioMessage )
            await sleep( 1 )

          } )

          Button( { type : ButtonType.Normal , stateEffect : true } ) {
            Row() {
              Text( '清空日志' ).fontSize( "24vp" ).fontColor( 0xffffff ).margin( { left : 5 , right : 5 } )
            }.alignItems( VerticalAlign.Center )
          }
          .borderRadius( 8 )
          .backgroundColor( $r( "app.color.moon" ) )
          .width( 80 )
          .height( 66 )
          .margin( { top : "15vp" , right : "20vp" } )
          .align( Alignment.Start )
          .onClick( async( event: ClickEvent ) => {
            let hotspotCreateScenarioMessage = ""
            AppStorage.SetOrCreate( "hotspotCreateScenarioMessage" , hotspotCreateScenarioMessage )
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

function sleep( time ) {
  return new Promise(( resolve , reject ) => {
    setTimeout( () => {
      resolve()
    } , time * 1000 )
  })
}