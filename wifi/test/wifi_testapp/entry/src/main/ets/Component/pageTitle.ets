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

import { TestData } from '../entryability/model/testData'
import router from '@ohos.router';
import screenshot from '@ohos.screenshot'
import image from '@ohos.multimedia.image'
import MediaUtils from '../entryability/model/MediaUtils'
import ConfigData from '../utils/ConfigData';

const TAG = "[pageTitle]"

/**
 * Page-Title Of Wifi test
 */

@Component
export struct PageTitle {
  private testItem!: TestData
  private detail: string = 'PageTitle'
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
      screenRect : { left : 0 , top : 0 , width : 400 , height : 400 } ,
      imageSize : { width : 400 , height : 400 } ,
      rotation : 0 ,
      displayId : 0
    }
    if ( isFullScreen ) {
      screenshotOptions = {
        rotation : 0
      }
    } else {
      console.log(TAG , "error -----------")
    }
    try {
      screenshot.save(screenshotOptions , (err , data: image.PixelMap) => {
        if ( err ) {
          console.log(TAG , `Failed to save the screenshot. Error:${ JSON.stringify(err) }`)
        }
        console.log(TAG , 'save callback')
        MediaUtils.savePicture(data , getContext(this))
      })
    } catch( err ) {
      console.log(TAG , `save failed, code is ${ err.code }, message is ${ err.message }`)
    }
  }

  @Builder
  CustomBtn(text: Resource , isFullScreen: boolean) {
    Button() {
      Image($r('app.media.screenShot'))
        .height(40)
        .width(40)
    }
    .key(isFullScreen + 'FullScreenShot')
    .type(ButtonType.Normal)
    .backgroundColor($r("app.color.blue"))
    .height(ConfigData.WH_100_100)
    .width(ConfigData.WH_100_100)
    .margin({ left : 3 , right : 3 , top : 2 })
    .onClick(() => {
      console.log(TAG , 'onClick,screenshot')
      this.getScreen(isFullScreen)
    })
  }

  build() {
    Column() {
      Flex({ alignItems : ItemAlign.Start }) {
        Button() {
          Image($r('app.media.Back'))
            .width(ConfigData.WH_60_100)
            .height(ConfigData.WH_60_100)
        }
        .type(ButtonType.Normal)
        .width(ConfigData.WH_20_100)
        .height(ConfigData.WH_100_100)
        .backgroundColor($r("app.color.blue"))
        .padding({ left : 1 , top : 15 })
        .onClick(() => {
          router.back()
        })

        Text(this.testItem != null ? this.testItem.detail : this.detail)
          .fontSize(24)
          .margin({ left : 3 })
          .padding({ top : 18 })

        Scroll() {
          Column() {
            this.CustomBtn($r('app.string.btn_fullscreen') , true)
          }
          .width(ConfigData.WH_100_100)
          .height(ConfigData.WH_100_100)
          .borderWidth(this.myborderWidth)
          .borderRadius(this.myborderRadius)
          .borderColor(Color.Green)
          .gesture(
            GestureGroup(GestureMode.Parallel ,
              TapGesture({ count : 2 , fingers : 1 })
                .onAction(() => {
                  this.myborderWidth += 1
                }) ,
              LongPressGesture({ fingers : 1 , repeat : true , duration : 1000 })
                .onAction((event: GestureEvent) => {
                  this.colOpacity -= 0.1
                  if ( event.repeat ) {
                    this.count ++
                  }
                })
                .onActionEnd(() => {
                  this.colOpacity = 1;
                  this.count = 0;
                }) ,
              PanGesture({ fingers : 1 , direction : PanDirection.All , distance : 5.0 })
                .onActionStart(() => {
                  console.log(TAG , 'Pan start')
                })
                .onActionUpdate((event: GestureEvent) => {
                  this.offsetY = event.offsetY;
                  this.offsetX = event.offsetX;
                })
                .onActionEnd(() => {
                  console.log(TAG , 'Pan end')
                }) ,
              PinchGesture({ fingers : 2 , distance : 4 })
                .onActionStart(() => {
                  console.log(TAG , 'PinchGesture start')
                })
                .onActionUpdate((event: GestureEvent) => {
                  this.myscale = event.scale
                  this.myborderRadius = 10
                })
                .onActionEnd(() => {
                  console.log(TAG , 'PinchGesture end')
                  this.getScreen(true);
                }) ,
              RotationGesture({ fingers : 2 , angle : 2 })
                .onActionStart(() => {
                  console.log(TAG , 'RotationGesture start')
                })
                .onActionUpdate((event: GestureEvent) => {
                  this.angle = event.angle
                })
                .onActionEnd(() => {
                  console.log(TAG , 'RotationGesture end')
                })
            )
              .onCancel(() => {
                console.log(TAG , 'Parallel gesture canceled')
              })
          )
        }
        .layoutWeight(1)
      }
      .height(61)
      .backgroundColor('#FFedf2f5')
      .padding({ left : 10 })
      .borderColor($r("app.color.black"))
      .backgroundColor($r("app.color.blue"))
    }
  }
}