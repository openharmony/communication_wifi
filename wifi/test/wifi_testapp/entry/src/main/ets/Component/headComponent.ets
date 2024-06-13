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

import ConfigData from '../utils/ConfigData';
import router from '@ohos.router';

const TAG = "[headComponent]"
/**
 * head custom component Of WiFi test
 */

@Component
export default struct HeadComponent {
  private isActive: boolean = true;
  private icBackIsVisibility: boolean = true;
  private headName: string | Resource = '';
  @State isTouch: boolean = false;

  build() {
    Row() {
      Stack({ alignContent : Alignment.Center }) {
        Image($r('app.media.ic_back'))
          .width($r('app.float.wh_value_30'))
          .height($r('app.float.wh_value_30'))
      }
      .margin({ left : $r('app.float.distance_4') , right : $r('app.float.distance_16') })
      .backgroundColor(this.isTouch ? $r('app.color.color_E3E3E3_grey') : $r('app.color.color_00000000_transparent'))
      .visibility(this.icBackIsVisibility ? Visibility.Visible : Visibility.None)
      .onClick(() => {
        router.back();
      })
      .onTouch((event: TouchEvent) => {
        if ( event.type === TouchType.Down ) {
          this.isTouch = true;
        } else if ( event.type === TouchType.Up ) {
          this.isTouch = false;
        } else {
          console.log(TAG , "event.type /= TouchType.Down")
          console.log(TAG , "event.type /= TouchType.Up")
        }
      });

      Text(this.headName)
        .fontSize($r('app.float.font_24'))
        .lineHeight($r('app.float.wh_value_33'))
        .fontFamily('HarmonyHeiTi-Bold')
        .fontWeight(FontWeight.Bold)
        .fontColor($r('app.color.font_color_182431'))
        .maxLines(ConfigData.MAX_LINES_1)
        .textOverflow({ overflow : TextOverflow.Ellipsis })
        .textAlign(TextAlign.Start)
        .margin({ top : $r('app.float.distance_13') , bottom : $r('app.float.distance_15') });
    }
    .width(ConfigData.WH_100_100)
    .padding({ left : $r('app.float.distance_8') })
    .height($r('app.float.wh_value_56'))
    .alignItems(VerticalAlign.Center)
    .align(Alignment.Start);
  }
}