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

const TAG = "[P2pView]"
import ConfigData from '../utils/ConfigData';
import { testOnP2pConnectionChange , testGetCurrentGroupCallback } from '../entryability/model/p2pInterface'
/**
 * P2pView Component of p2p test
 */

@Component
export struct P2pView {
  private p2p: any = null
  private securityString: Resource = $r( 'app.string.useful' )
  private p2pConnectState: Number = 0
  private p2pLinkedDeviceName: string = ""
  @State isLock: boolean = true

  aboutToAppear() {
    console.log( TAG , `aboutToAppear ${ JSON.stringify( this.p2p ) }` )
    testOnP2pConnectionChange()
    testGetCurrentGroupCallback()
    this.p2pConnectState = AppStorage.Get( "p2pConnectState" )
    this.p2pLinkedDeviceName = AppStorage.Get( "p2pLinkedDeviceName" )
    if ( this.p2p ) {
      console.log( TAG , "this.p2p is true" )
    } else {
      console.log( TAG , "this.p2p is false" )
    }
  }

  build() {
    Row() {
      Column() {
        if ( this.p2p ) {
          if ( this.p2p.deviceName ) {
            Text( this.p2p.deviceName )
              .fontSize( 20 )
              .width( ConfigData.WH_100_100 )
          }
        }
        if ( this.p2pConnectState == 1 && this.p2pLinkedDeviceName == this.p2p.deviceName ) {
          Text( this.securityString = $r( 'app.string.p2pConnected' ) )
            .fontSize( 18 )
            .fontColor( Color.Gray )
            .width( ConfigData.WH_100_100 )
        } else {
          Text( this.securityString )
            .fontSize( 18 )
            .fontColor( Color.Gray )
            .width( ConfigData.WH_100_100 )
        }
      }
      .layoutWeight( 1 )

      Stack( { alignContent : Alignment.BottomEnd } ) {
        Image( $r( 'app.media.wifi' ) )
          .height( 30 ).width( 30 )
          .objectFit( ImageFit.Contain )
        if ( this.isLock ) {
          Image( $r( 'app.media.lock' ) )
            .objectFit( ImageFit.Contain )
            .width( 15 ).height( 15 )
        }
      }
      .width( 40 ).height( 40 )
      .margin( { right : 10 } )
    }
    .backgroundColor( Color.White )
    .width( ConfigData.WH_100_100 )
    .padding( 10 )
  }
}