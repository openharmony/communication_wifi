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
import ConfigData from '../../utils/ConfigData';
import LogUtil from '../../utils/LogUtil';
import { initP2pApiData } from '../../entryability/model/testDataModels'
import { TestData } from '../../entryability/model/testData'

/**
 * p2pManager Test Page Of Wifi test
 */

@Component
struct p2pManagerSetting {
  @State deviceAddressManager: string = '6c:96:d7:3d:87:6f';
  @State netIdManager: Number = - 2 ;
  @State passphraseManager: string = "12345678" ;
  @State groupNameManager: string = "testGroup"
  @State goBandManager: Number = 0 ;
  @State devNameManager: string = "MyTestDevice"

  aboutToAppear() {
    AppStorage.SetOrCreate( "deviceAddressManager" , this.deviceAddressManager )
    AppStorage.SetOrCreate( "netIdManager" , this.netIdManager )
    AppStorage.SetOrCreate( "passphraseManager" , this.passphraseManager )
    AppStorage.SetOrCreate( "groupNameManager" , this.groupNameManager )
    AppStorage.SetOrCreate( "goBandManager" , this.goBandManager )
    AppStorage.SetOrCreate( "devNameManager" , this.devNameManager )
  }

  build() {
    Column() {
      Row() {
        Text( "deviceAddressManager:" ).fontSize( 16 ).width( 120 )
        TextInput( { text : this.deviceAddressManager , placeholder : '6c:96:d7:3d:87:6f' } )
          .fontSize( "15vp" )
          .onChange( ( strInput ) => {
            this.deviceAddressManager = strInput;
            //判断合法性
            if ( strInput.length >= 1 ) {
              AppStorage.SetOrCreate( 'deviceAddressManager' , strInput );
            }
          } )
          .width( ConfigData.WH_80_100 )
          .borderRadius( 1 )
      }
      .backgroundColor( $r( "app.color.moon" ) )
      .padding( 5 )
      .justifyContent( FlexAlign.Start )
      .alignItems( VerticalAlign.Center )

      Column() {
        Stack().height( "0.25vp" ).backgroundColor( "#000000" );
        Column() {
          Row() {
            Text( "netIdManager:" ).fontSize( 15 ).width( 60 );
            TextInput( { text : this.netIdManager , placeholder : "-2" } )
              .fontSize( "15vp" )
              .onChange( ( strInput ) => {
                this.netIdManager = strInput;
                //判断合法性
                if ( strInput.length >= 1 ) {
                  AppStorage.SetOrCreate( 'netIdManager' , strInput );
                }
              } )
              .width( ConfigData.WH_80_100 )
              .borderRadius( 1 )
          }
          .padding( 5 )
          .justifyContent( FlexAlign.Start )
          .alignItems( VerticalAlign.Center )
          .backgroundColor( $r( "app.color.spring" ) )

          Row() {
            Text( "passphraseManager:" ).fontSize( 15 ).width( 100 );
            TextInput( { text : this.passphraseManager , placeholder : "input passphrase" } )
              .fontSize( "15vp" )
              .onChange( ( strInput ) => {
                this.passphraseManager = strInput;
                if ( strInput.length >= 1 ) {
                  AppStorage.SetOrCreate( 'passphraseManager' , strInput );
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
            Text( "groupNameManager:" ).fontSize( 15 ).width( 100 );
            TextInput( { text : this.groupNameManager , placeholder : "testGroup" } )
              .fontSize( "15vp" )
              .onChange( ( strInput ) => {
                this.groupNameManager = strInput;
                if ( strInput.length >= 1 ) {
                  AppStorage.SetOrCreate( 'groupNameManager' , strInput );
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
            Text( "goBandManager:" ).fontSize( 15 ).width( 80 );
            TextInput( { text : this.goBandManager , placeholder : "0" } )
              .fontSize( "15vp" )
              .onChange( ( strInput ) => {
                this.goBandManager = strInput;
                if ( strInput.length >= 1 ) {
                  AppStorage.SetOrCreate( 'goBandManager' , strInput );
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
            Text( "devNameManager:" ).fontSize( 15 ).width( 100 );
            TextInput( { text : this.devNameManager , placeholder : "MyTestDevice" } )
              .fontSize( "15vp" )
              .onChange( ( strInput ) => {
                this.devNameManager = strInput;
                if ( strInput.length >= 1 ) {
                  AppStorage.SetOrCreate( 'devNameManager' , strInput );
                }
              } )
              .width( ConfigData.WH_80_100 )
              .borderRadius( 1 )
          }
          .backgroundColor( $r( "app.color.spring" ) )
          .padding( 5 )
          .justifyContent( FlexAlign.Start )
          .alignItems( VerticalAlign.Center )
        }

        Stack().height( "0.25vp" ).backgroundColor( "#000000" );
      }
    }
  }
}

@Entry
@Component
struct P2pManagerInterfaceTest {
  @State showList: boolean = false;
  private testItem: TestData = Router.getParams().testId;
  @State message: string = "";
  @State deviceId: string = '';
  @State currentClick: Number = - 1;
  @StorageLink( 'pairedDeviceId' ) pairedDeviceId: string = '';
  @State deviceAddressManager: string = '6c:96:d7:3d:87:6f';
  @State netIdManager: Number = - 2 ;
  @State passphraseManager: string = "12345678" ;
  @State groupNameManager: string = "testGroup"
  @State goBandManager: Number = 0 ;
  @State devNameManager: string = "test"
  @State connectedIp: sting = "192.168.1.107"
  @StorageLink( 'p2pManagerDeviceName' ) p2pManagerDeviceName: String = "";
  @StorageLink( 'p2pStateManagerMessage' ) p2pStateManagerMessage: string = "";
  @StorageLink( 'p2pDeviceManagerMessage' ) p2pDeviceManagerMessage: string = "";
  @StorageLink( 'p2pLinkStateManagerMessage' ) p2pLinkStateManagerMessage: string = "";
  @StorageLink( 'p2pLinkManagerMessage' ) p2pLinkManagerMessage: string = "";
  @StorageLink( 'p2pPeerDeviceManagerMessage' ) p2pPeerDeviceManagerMessage: string = "";
  @StorageLink( 'p2pPeerDeviceManagerMessages' ) p2pPeerDeviceManagerMessages: string = "";
  @StorageLink( 'p2pDiscoveryManagerMessage' ) p2pDiscoveryManagerMessage: string = "";
  @StorageLink( 'p2pGroupManagerMessage' ) p2pGroupManagerMessage: string = "";

  aboutToAppear() {
    AppStorage.SetOrCreate( "deviceAddressManager" , this.deviceAddressManager )
    AppStorage.SetOrCreate( "netIdManager" , this.netIdManager )
    AppStorage.SetOrCreate( "passphraseManager" , this.passphraseManager )
    AppStorage.SetOrCreate( "groupNameManager" , this.groupNameManager )
    AppStorage.SetOrCreate( "goBandManager" , this.goBandManager )
    AppStorage.SetOrCreate( "devNameManager" , this.devNameManager )
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
          Text( "本设备名称：" )
            .fontSize( "20vp" )
            .height( 40 )
            .padding( { top : 5 } )
            .width( ConfigData.WH_28_100 )
            .align( Alignment.Start )

          TextInput( { text : this.p2pManagerDeviceName , placeholder : "请在右侧输入p2p的配置" } )
            .height( 40 )
            .borderStyle( BorderStyle.Dashed )
            .backgroundColor( $r( "app.color.white" ) )
            .onChange( ( str ) => {
              this.p2pManagerDeviceName = str;
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
      .align( Alignment.TopStart )

      if ( this.showList ) {
        p2pManagerSetting()
      } else {
        Column() {
          Scroll() {
            Column() {
              Text( "开关结果:" + this.p2pStateManagerMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "10vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "本机信息:" + this.p2pDeviceManagerMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "10vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "发现信息:" + this.p2pDiscoveryManagerMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "10vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "连接状态:" + this.p2pLinkStateManagerMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "10vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "连接信息:" + this.p2pLinkManagerMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "10vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "对端设备:" + this.p2pPeerDeviceManagerMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "10vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "对端设备[]:" + this.p2pPeerDeviceManagerMessages )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "10vp" } )
                .textAlign( TextAlign.Start )
                .width( ConfigData.WH_90_100 )
              Text( "组信息:" + this.p2pGroupManagerMessage )
                .fontSize( "17vp" )
                .margin( { top : "5vp" , left : "10vp" } )
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

        ContentTable( { testItem : this.testItem , apiItems : initP2pApiData() } )
      }
    }
    .alignItems( HorizontalAlign.Center )
    .backgroundColor( $r( "app.color.lead" ) )
    .height( ConfigData.WH_100_100 )
  }
}

