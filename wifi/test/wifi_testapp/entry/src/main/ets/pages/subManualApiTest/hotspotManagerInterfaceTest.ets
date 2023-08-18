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
import { initHotspotManagerApIData } from '../../MainAbility/model/testDataModels'
import { TestData } from '../../MainAbility/model/testData'
import { FilterTableManager } from '../../Component/filterTableManager';

/**
 * hotspotManager Test Page Of Wifi test
 */

@Entry
@Component
struct hotspotManagerInterfaceTest {
  @State showList: boolean = true;
  private testItem: TestData = Router.getParams().testId;
  @State message: string = "";
  @State h_ssid1: string = "testApp1";
  @State h_securityType1: number = 3;
  @State h_band1: number = 2;
  @State h_preSharedKey1: string = "12345678";
  @State h_maxConn1: number = 3 ;
  @State h_channel1: number = 36 ;
  @StorageLink( 'hotspotStateManagerMessage' ) hotspotStateManagerMessage: string = "";
  @StorageLink( 'getStationsManagerMessage' ) getStationsManagerMessage: string = "";
  @StorageLink( 'getHotspotConfigManagerMessage' ) getHotspotConfigManagerMessage: string = "";
  @StorageLink( 'hotspotStaJoinManagerMessage' ) hotspotStaJoinManagerMessage: string = "";
  @StorageLink( 'hotspotStaLeaveManagerMessage' ) hotspotStaLeaveManagerMessage: string = "";

  aboutToAppear() {
    AppStorage.SetOrCreate( "h_ssid1" , this.h_ssid1 )
    AppStorage.SetOrCreate( "h_securityType1" , this.h_securityType1 )
    AppStorage.SetOrCreate( "h_band1" , this.h_band1 )
    AppStorage.SetOrCreate( "h_preSharedKey1" , this.h_preSharedKey1 )
    AppStorage.SetOrCreate( "h_maxConn1" , this.h_maxConn1 )
    AppStorage.SetOrCreate( "h_channel1" , this.h_channel1 )
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
      .align( Alignment.TopStart )

      if ( this.showList ) {
        Column() {
          Scroll() {
            Column() {
              //              Text("当前配置:")
              //                .fontSize("17vp")
              //                .margin({ top: "5vp", left: "10vp" })
              //                .textAlign(TextAlign.Start)
              //                .width(ConfigData.WH_100_100)
              Text( "热点状态:" + this.hotspotStateManagerMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "热点配置:" + this.getHotspotConfigManagerMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "连接设备:" + this.getStationsManagerMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "加入状态:" + this.hotspotStaJoinManagerMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "15vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "离开状态:" + this.hotspotStaLeaveManagerMessage )
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
          testItem : this.testItem , apiItems : initHotspotManagerApIData()
        } )
      } else {
        FilterTableManager( { testItem : this.testItem } )
      }

    }
    .alignItems( HorizontalAlign.Center )
    .backgroundColor( $r( "app.color.lead" ) )
    .height( ConfigData.WH_100_100 )
  }
}

