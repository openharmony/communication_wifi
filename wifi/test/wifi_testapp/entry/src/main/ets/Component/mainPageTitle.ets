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

import hilog from '@ohos.hilog';
import screenshot from '@ohos.screenshot';
import image from '@ohos.multimedia.image';
import MediaUtils from '../entryability/model/MediaUtils';
import ConfigData from '../Utils/ConfigData';

const TAG = "wifiTestApp [mainPageTitle]"

/**
 * Main-Page Title Of WiFi test
 */

@Component
export struct MainPageTitle {
  @State colOpacity: number = 1
  @State count: number = 0
  @State myborderWidth: number = 0
  @State myborderRadius: number = 0
  @State offsetX: number = 0
  @State offsetY: number = 0
  @State myscale: number = 1
  @State angle: number = 0
  getScreen = (isFullScreen: boolean) => {
    let screenshotOptions: screenshot.ScreenshotOptions = {
      screenRect: { left: 0, top: 0, width: 400, height: 400},
      imageSize: { width: 400, height: 400},
      rotation: 0,
      displayId: 0
    }
    if (isFullScreen){
      screenshotOptions = {
        rotation: 0
      }
    } else {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "error-----")
    }
    try {
      screenshot.save(screenshotOptions, (err, data: image.PixelMap) => {
        if (err){
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Failed to save the screenshot. Error:${ JSON.stringify(err) }`)
        }
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'save callback')
        MediaUtils.savePicture(data, getContext(this))
      })
    } catch( err){
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `save failed, code is ${ err.code }, message is ${ err.message }`)
    }
  }

  @Builder
  CustomBtn(text: Resource, isFullScreen: boolean){
    Button() {
      Image($r('app.media.screenShot'))
        .height(ConfigData.VP_50)
        .width(ConfigData.VP_50)
    }
    .key(isFullScreen + 'FullScreenShot')
    .type(ButtonType.Normal)
    .backgroundColor($r("app.color.blue"))
    .height(ConfigData.WH_100_100)
    .width(ConfigData.WH_100_100)
    .margin({left: ConfigData.VP_6, right: ConfigData.VP_6, top: ConfigData.VP_3})
    .onClick(() => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'onClick,screenshot')
      this.getScreen(isFullScreen)
    })
  }

  build() {
    Flex({alignItems: ItemAlign.Start}){
      Text($r('app.string.wifitest_text_wtszs'))
        .fontSize(ConfigData.VP_26)
        .margin({left: ConfigData.VP_15})
        .padding({top: ConfigData.VP_28})
      Scroll() {
        Column() {
          this.CustomBtn($r('app.string.btn_fullscreen'), true)
        }
        .width(ConfigData.WH_100_100)
        .height(ConfigData.WH_100_100)
        .borderWidth(this.myborderWidth)
        .borderRadius(this.myborderRadius)
        .borderColor($r('app.color.green'))
        .gesture(
          GestureGroup(GestureMode.Parallel,
            TapGesture({count: 2, fingers: 1})
              .onAction(() => {
                this.myborderWidth += 1
        }),
            LongPressGesture({fingers: 1, repeat: true, duration: 1000})
              .onAction((event: GestureEvent) => {
                this.colOpacity -= 0.1
                if (event.repeat){
                  this.count++
                }
              })
              .onActionEnd(() => {
                this.colOpacity = 1;
                this.count = 0;
        }),
            PanGesture({fingers: 1, direction: PanDirection.All, distance: 5.0})
              .onActionStart(() => {
                hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'Pan start')
              })
              .onActionUpdate((event: GestureEvent) => {
                this.offsetY = event.offsetY;
                this.offsetX = event.offsetX;
              })
              .onActionEnd(() => {
                hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'Pan end')
        }),
            PinchGesture({fingers: 2, distance: 4})
              .onActionStart(() => {
                hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'PinchGesture start')
              })
              .onActionUpdate((event: GestureEvent) => {
                this.myscale = event.scale
                this.myborderRadius = 10
              })
              .onActionEnd(() => {
                hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'PinchGesture end')
                this.getScreen(true);
        }),
            RotationGesture({fingers: 2, angle: 2})
              .onActionStart(() => {
                hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'RotationGesture start')
              })
              .onActionUpdate((event: GestureEvent) => {
                this.angle = event.angle
              })
              .onActionEnd(() => {
                hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'RotationGesture end')
              })
          )
            .onCancel(() => {
              hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'Parallel gesture canceled')
            })
        )
      }
      .layoutWeight(1)
    }
    .height(ConfigData.VP_80)
    .backgroundColor($r("app.color.blue"))
    .padding({left: ConfigData.VP_20})
  }
}