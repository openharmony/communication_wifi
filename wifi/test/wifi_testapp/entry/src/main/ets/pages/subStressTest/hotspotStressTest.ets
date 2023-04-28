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
import { PageTitle } from '../../Component/pageTitle';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { StressContentTable } from '../../Component/stressContentTable';
import Router from '@system.router';
import ConfigData from '../../Utils/ConfigData';
import LogUtil from '../../Utils/LogUtil';
import { initHotspotStressData } from '../../MainAbility/model/stressTestDataModels'
import { TestData } from '../../MainAbility/model/testData'
import { FilterTable } from '../../Component/filterTable';

const G_NAME = 'DaYu200'

/**
 * hotspot StressTest Page Of Wifi test
 */

@Entry
@Component
struct hotspotStressTest {
  @State showList: boolean = true;
  private testItem: TestData = Router.getParams().testId;
  @State message: string = "";
  @StorageLink( 'stressNumber' ) stressNumber: number = 0 ;
  @StorageLink( 'stressTime' ) stressTime: number = 0;

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
          Text( "热点IP" )
            .fontSize( "18vp" )
            .height( 60 )
            .width( ConfigData.WH_20_100 )
            .padding( { left : 10 } )
          TextInput( { text : this.peripheralDeviceId , placeholder : "input peripheral deviceId." } )
            .fontSize( "18vp" )
            .onChange( ( strInput ) => {
              this.peripheralDeviceId = strInput;
              AppStorage.SetOrCreate( "peripheralDeviceId" , strInput )
            } )
            .width( ConfigData.WH_65_100 )
          Image( $r( 'app.media.Switch' ) )
            .height( 40 )
            .width( 40 )
            .padding( { top : 10 , bottom : 10 , left : 2 } )
            .onClick( () => {
              this.showList = !this.showList;
            } )
        }
        .margin( { top : "10vp" , left : "20vp" , right : "20vp" } )
        .alignItems( VerticalAlign.Center )
        .backgroundColor( $r( "app.color.white" ) )
        .width( ConfigData.WH_100_100 )
        .height( 60 )
      }
      .align( Alignment.Start )

      if ( this.showList ) {
        Column() {
          Scroll() {
            Column() {
              Text( "stress测试：" )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_100_100 )
              Text( "stress测试次数:" + this.stressNumber )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "stress测试时间：" + this.stressTime + "ms" )
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

        StressContentTable( {
          testItem : this.testItem , apiItems : initHotspotStressData()
        } )
      } else {
        FilterTable( { testItem : this.testItem } )
      }
    }
    .alignItems( HorizontalAlign.Center )
    .backgroundColor( $r( "app.color.lead" ) )
    .height( ConfigData.WH_100_100 )
  }
}