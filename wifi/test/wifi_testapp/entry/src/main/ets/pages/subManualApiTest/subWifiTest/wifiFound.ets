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

import wifi from '@ohos.wifi'
import { AvailableWifi } from '../../../Component/availableWifi'

import { TitleBar } from '../../../Component/titleBar'

const TAG = '[wifiFound]'
const PERMISSION_NAME: string = 'ohos.permission.LOCATION'
/**
 * wifi Found Test Page Of Wifi test
 */
@Entry
@Component
struct WifiFound {
  private testItem: string = "Wlan扫描"
  @State linkedInfo: any = {
    ssid : "" ,
    bssid : "" ,
    networkId : 0 ,
    rssi : 0 ,
    band : 0
  }
  @State wifiList: Array<wifi.WifiScanInfo> = []
  @State isLinked: boolean = false
  @State isSwitchOn: boolean = false

  scan() {
    wifi.getScanInfos( ( err , result ) => {
      if ( err ) {
        console.log( TAG , `scan info err: ${ JSON.stringify( err ) }` )
      }
      console.log( TAG , `scan info call back: ${ result.length }` )
      for ( let i = 0 ; i < result.length ; ++i ) {
        this.wifiList.push( {
          ssid : result[ i ].ssid ,
          bssid : result[ i ].bssid ,
          securityType : result[ i ].securityType ,
          rssi : result[ i ].rssi ,
          band : result[ i ].band ,
          frequency : result[ i ].frequency ,
          timestamp : result[ i ].timestamp ,
        } )
      }
      console.log( TAG , "wifiList:" + JSON.stringify( this.wifiList ) )
      setTimeout( () => {
        this.scan()
      } , 2000 )
    } )
  }

  getLinkedInfo() {
    wifi.getLinkedInfo( ( err , linkedInfo ) => {
      if ( err ) {
        console.log( TAG , `getLinkedInfo err: ${ JSON.stringify( err ) }` )
        return
      }
      console.log( TAG , `linkedInfo: ${ JSON.stringify( linkedInfo ) }` )
      if ( linkedInfo === null || linkedInfo.bssid === '' ) {
        this.isLinked = false
        this.linkedInfo = {
          ssid : "" ,
          bssid : "" ,
          networkId : 0 ,
          rssi : 0 ,
          band : 0
        }
        return
      }
      this.isLinked = true
      this.linkedInfo = linkedInfo
    } )
  }

  addListener() {
    wifi.on( 'wifiConnectionChange' , state => {
      console.log( TAG , `wifiConnectionChange: ${ state }` )
      this.getLinkedInfo()
    } )
    wifi.on( 'wifiStateChange' , state => {
      console.log( TAG , `wifiStateLisener state: ${ state }` )
      this.wifiList = []
      if ( state === 1 ) { // 1: wifi is enable, 0:wifi is disable
        wifi.scan()
        this.scan()
      }
    } )
  }

  aboutToAppear() {
    // let context = featureAbility.getContext()
    // context.requestPermissionsFromUser( [ PERMISSION_NAME ] , 3 , function( result ) {
    //   console.log( TAG , `wifi grantPermission,requestPermissionsFromUser,result.requestCode: ${ result }` )
    // } )
    if ( wifi.isWifiActive() ) {
      console.log( TAG , 'wifi is active' )
      this.isSwitchOn = true
      wifi.scan()
      this.scan()
      this.getLinkedInfo()
    }
    this.addListener()
  }

  build() {
    Column() {
      Stack( { alignContent : Alignment.TopStart } ) {
        TitleBar( { testItem : this.testItem } )
      }

      Row() {
        Text( $r( 'app.string.wlan' ) )
          .fontSize( 22 )
          .fontWeight( FontWeight.Bold )
          .layoutWeight( 1 )
          .align( Alignment.TopStart )
        Column() {
          Toggle( { type : ToggleType.Switch , isOn : this.isSwitchOn } )
            .onChange( ( isOn: boolean ) => {
              console.log( TAG , `wifi swtich is: ${ isOn }` )
              this.wifiList = []
              if ( isOn ) {
                this.isSwitchOn = true
                wifi.enableWifi()
                wifi.scan()
                this.scan()
                return
              }
              this.isSwitchOn = false
              this.isLinked = false
              wifi.disconnect()
              wifi.disableWifi()
            } )
        }
      }
      .width( '95%' )

      if ( this.isLinked ) {
        Text( $r( 'app.string.wlanIsConnected' ) )
          .fontSize( 22 )
          .width( '95%' )
          .align( Alignment.TopStart )
        Row() {
          Text( this.linkedInfo.ssid )
            .fontSize( 20 )
            .fontColor( Color.Black )
            .layoutWeight( 1 )
          Text( $r( 'app.string.wlanIsConnected' ) )
            .fontSize( 18 )
            .fontColor( Color.Black )
        }
        .width( '95%' )
        .padding( 10 )
        .margin( 10 )
        .border( { radius : 15 , color : Color.Gray , width : 1 } )
        .backgroundColor( Color.White )
      }
      AvailableWifi( { wifiList : this.wifiList , linkedInfo : this.linkedInfo } )
    }
    .size( { width : '100%' , height : '100%' } )
    .backgroundColor( '#F5F5F5' )
  }

  aboutToDisappear() {
    wifi.off( 'wifiConnectionChange' )
    wifi.off( 'wifiStateChange' )
  }
}