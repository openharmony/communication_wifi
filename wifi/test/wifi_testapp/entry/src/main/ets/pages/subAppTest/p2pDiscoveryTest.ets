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

import featureAbility from '@ohos.ability.featureAbility'
import wifi from '@ohos.wifi'
import { AvailableP2p } from '../../Component/availableP2p'
import { TestData } from '../../entryability/model/testData'
import router from '@system.router';
import { P2pTitleBar } from '../../Component/p2pTitleBar'
import { PageTitle } from '../../Component/pageTitle'
import { TestImageDisplay } from '../../Component/testImageDisplay'
import { P2pModel } from '../../entryability/model/p2pModel'

const TAG = '[p2pScan]'
const PERMISSION_P2P_NAME: string = 'ohos.permission.LOCATION'
/**
 * p2p Found Test Page Of Wifi test
 */
@Entry
@Component
struct P2pFound {
  private p2pModel: P2pModel = new P2pModel()
  private testItem: TestData = router.getParams().testId;
  // private testItem: string = "p2p扫描"
  private p2pLinkedInfo: any = {
    deviceName : "" ,
    deviceAddress : "" ,
    groupOwnerAddr : "" ,
    groupName : "" ,
    goBand : 0
  }
  @State p2pList: Array<any> = []
  @State p2pIsLinked: boolean = false
  @State p2pIsSwitchOn: boolean = false

  scan() {
    this.p2pModel.getP2pPeerDevices( ( result ) => {
      if ( this.p2pIsSwitchOn ) {
        this.p2pList = result
        console.log( 'scan p2pList:' + JSON.stringify( this.p2pList ) )
        setTimeout( () => {
          this.scan()
        } , 2000 )
      }
    } )
  }

  getP2pLinkedInfo() {
    wifi.getP2pLinkedInfo( ( err , p2pLinkedInfo ) => {
      if ( err ) {
        console.log( TAG , `getLinkedInfo err: ${ JSON.stringify( err ) }` )
        return
      }
      console.log( TAG , `p2pLinkedInfo: ${ JSON.stringify( p2pLinkedInfo ) }` )
      if ( p2pLinkedInfo === null || p2pLinkedInfo.connectState === 0 ) {
        this.p2pIsLinked = false
        this.p2pLinkedInfo = {
          deviceName : "" ,
          deviceAddress : "" ,
          groupOwnerAddr : "" ,
          groupName : "" ,
          goBand : 0
        }
        return
      }
      this.p2pIsLinked = true
      this.p2pLinkedInfo = p2pLinkedInfo
    } )
  }

  addP2pListener() {
    wifi.on( 'p2pConnectionChange' , wifiP2pLinkedInfo => {
      let state = wifiP2pLinkedInfo.connectState
      console.log( TAG , `p2pConnectionChange: ${ state }` )
      this.getP2pLinkedInfo()
    } )
    wifi.on( 'p2pStateChange' , state => {
      console.log( TAG , `p2pStateLisener state: ${ state }` )
      this.p2pList = []
      if ( state === 1 ) { // 1: wifi is enable, 0:wifi is disable
        wifi.startDiscoverDevices()
        this.scan()
      }
    } )
  }

  aboutToAppear() {
    if ( wifi.isWifiActive() ) {
      console.log( TAG , 'wifi is active' )
      this.p2pIsSwitchOn = true
      wifi.startDiscoverDevices()
      this.scan()
      this.getP2pLinkedInfo()
    }
    this.addP2pListener()
  }

  build() {
    Column() {
      Stack( { alignContent : Alignment.TopStart } ) {
        TestImageDisplay( { testItem : this.testItem } )
        PageTitle( { testItem : this.testItem } )
        // P2pTitleBar( { testItem : this.testItem } )
      }

      Row() {
        Text( $r( 'app.string.wlan' ) )
          .fontSize( 22 )
          .fontWeight( FontWeight.Bold )
          .layoutWeight( 1 )
          .align( Alignment.TopStart )
        Column() {
          Toggle( { type : ToggleType.Switch , isOn : this.p2pIsSwitchOn } )
            .onChange( ( isOn: boolean ) => {
              console.log( TAG , `wifi swtich is: ${ isOn }` )
              this.p2pList = []
              if ( isOn ) {
                this.p2pIsSwitchOn = true
                wifi.enableWifi()
                wifi.startDiscoverDevices()
                this.scan()
                return
              }
              this.p2pIsSwitchOn = false
              this.p2pIsLinked = false
              wifi.disconnect()
              wifi.disableWifi()
            } )
        }
      }
      .width( '95%' )

      AvailableP2p( { p2pList : this.p2pList , p2pLinkedInfo : this.p2pLinkedInfo } )
    }
    .size( { width : '100%' , height : '100%' } )
    .backgroundColor( '#F5F5F5' )
  }

  aboutToDisappear() {
    wifi.off( 'wifiConnectionChange' )
    wifi.off( 'wifiStateChange' )
  }
}