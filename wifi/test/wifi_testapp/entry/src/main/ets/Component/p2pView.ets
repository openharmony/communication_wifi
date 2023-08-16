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

import Logger from '../MainAbility/model/Logger'

const TAG: string = 'P2pView'
import ConfigData from '../Utils/ConfigData';
/**
 * P2pView Component of p2p test
 */

@Component
export struct P2pView {
  private p2p: any = null
  private securityString: Resource = $r( 'app.string.useful' )
  @State isLock: boolean = true

  aboutToAppear() {
    Logger.debug( TAG , `aboutToAppear ${ JSON.stringify( this.p2p ) }` )
    if ( this.p2p ) {
      console.log( "this.p2p is true" )
    } else {
      console.log( "this.p2p is false" )
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
        Text( this.securityString )
          .fontSize( 18 )
          .fontColor( Color.Gray )
          .width( ConfigData.WH_100_100 )
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