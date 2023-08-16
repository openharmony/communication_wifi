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

import { WifiModel } from '../../../MainAbility/model/wifiModel'
import { InfoView } from '../../../Component/infoView'
import ConfigData from '../../../Utils/ConfigData';
import Router from '@system.router';
/**
 * about Test Page Of Wifi test
 */
@Entry
@Component
struct About {
  private wifiModel: WifiModel = new WifiModel()

  build() {
    Column() {
      Flex( { alignItems : ItemAlign.Start } ) {
        Button() {
          Image( $r( 'app.media.Back' ) )
            .width( ConfigData.WH_60_100 )
            .height( ConfigData.WH_60_100 )
        }
        .type( ButtonType.Normal )
        .width( ConfigData.WH_20_100 )
        .height( ConfigData.WH_100_100 )
        .backgroundColor( $r( "app.color.blue" ) )
        .padding( { left : 1 , top : 15 } )
        .onClick( () => {
          Router.back()
        } )

        Text( $r( 'app.string.about' ) )
          .fontColor( Color.White )
          .fontSize( 24 )
          .margin( { left : 3 } )
          .padding( { top : 18 } )
      }
      .height( 61 )
      .backgroundColor( '#FFedf2f5' )
      .padding( { left : 10 } )
      .borderColor( $r( "app.color.black" ) )
      .backgroundColor( $r( "app.color.blue" ) )

      Scroll() {
        Column() {
          InfoView({ infoList: this.wifiModel.getIpInfo() })
          InfoView({ infoList: this.wifiModel.getCountryCode() })
          InfoView({ infoList: this.wifiModel.getFeatureSupport() })
        }
      }
      .layoutWeight(1)
    }
    .size( { width : '100%' , height : '100%' } )
    .backgroundColor( '#F5F5F5' )
  }
}