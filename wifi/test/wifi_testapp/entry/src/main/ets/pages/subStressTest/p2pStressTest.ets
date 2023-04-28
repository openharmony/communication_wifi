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
import { initP2pStressData } from '../../MainAbility/model/stressTestDataModels'
import { TestData } from '../../MainAbility/model/testData'
import ConfigData from '../../Utils/ConfigData';

const G_NAME = 'DaYu200'

/**
 * p2p StressTest of Wifi test
 */

@Entry
@Component
struct P2pStressTest {
  @State showList: boolean = false;
  private testItem: TestData = Router.getParams().testId;
  @State message: string = "";
  @StorageLink( 'setLocalNameRet' ) setLocalNameRet: boolean = false;
  @StorageLink( 'setScanModeRet' ) setScanModeRet: boolean = false;
  @State deviceId: string = '';
  @State currentClick: number = - 1;
  @State deviceAddress: string = '6c:96:d7:3d:87:6f';
  @State netId: number = - 2 ;
  @State passphrase: string = "12345678" ;
  @State groupName: string = "testGroup"
  @State goBand: number = 0 ;
  @State devName: string = "test"
  @StorageLink( 'stressNumber' ) stressNumber: number = 0 ;
  @StorageLink( 'stressTime' ) stressTime: number = 0;

  aboutToAppear() {
    AppStorage.SetOrCreate( "deviceAddress" , this.deviceAddress )
    AppStorage.SetOrCreate( "netId" , this.netId )
    AppStorage.SetOrCreate( "passphrase" , this.passphrase )
    AppStorage.SetOrCreate( "groupName" , this.groupName )
    AppStorage.SetOrCreate( "goBand" , this.goBand )
    AppStorage.SetOrCreate( "devName" , this.devName )
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
          Text( "目标设备IP：" )
            .fontSize( "20vp" )
            .height( 40 )
            .padding( { top : 5 } )
            .width( ConfigData.WH_28_100 )
            .align( Alignment.Start )

          TextInput( { text : this.pairedMac , placeholder : "请输入即将连接的设备MAC" } )
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
        //        WifiDeviceSetting()
      } else {
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
          testItem : this.testItem , apiItems : initP2pStressData()
        } )
      }
    }
    .alignItems( HorizontalAlign.Center )
    .backgroundColor( $r( "app.color.lead" ) )
    .height( ConfigData.WH_100_100 )
  }
}