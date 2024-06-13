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

import { TestData , TestApi } from '../entryability/model/testData'
import prompt from '@system.prompt';
import ConfigData from '../utils/ConfigData';

const TAG = "[contentTable]"

/**
 *  ContentTable Component Page Of Wifi test
 */

@Component
export struct ContentTable {
  private testItem!: TestData
  private currentApiItem!: TestApi
  @State apiItems: TestApi[] = [];
  @State changeIndex: number = - 1
  @State localName: string = 'MyTestDevice'
  @State currentIndex: number = 1
  @StorageLink('pairedMac') pairedMac: string = "";

  onCancel() {
    console.log(TAG , '取消1')
  }

  onAccept(text: string) {
    console.log(TAG , 'input text:' , text)
  }

  @Builder IngredientItem(apiItem: TestApi , index: number) {
    Stack() {
      Flex() {
        Flex({ alignItems : ItemAlign.Center }) {
          Image($r('app.media.WLAN'))
            .objectFit(ImageFit.Contain)
            .autoResize(false)
            .height(50)
            .width(40)
            .padding({ top : "15vp" })
        }
        .layoutWeight(1)
        .padding({ left : 10 })

        Flex({ direction : FlexDirection.Column , alignItems : ItemAlign.Start }) {
          Text(apiItem.name)
            .fontSize(17.4)
            .fontWeight(FontWeight.Bold)
            .layoutWeight(1)
            .padding({ left : "10vp" , top : "10vp" })
          Text(apiItem.method)
            .fontSize(17.4)
            .fontWeight(FontWeight.Bold)
            .layoutWeight(1)
            .padding({ left : "10vp" , top : "5vp" })
        }
        .layoutWeight(6)
        .width(ConfigData.WH_80_100)

        Flex({ alignItems : ItemAlign.Center }) {
          Text(this.changeIndex >= 0 ? this.getCurrentState(index) : apiItem.result)
            .fontSize(17.4)
            .flexGrow(1)
            .padding({ top : "15vp" })
        }
        .layoutWeight(3)
        .padding({ left : 25 })
      }
    }
    .height(80)
    .borderRadius(10)
    .margin({ top : 5 , bottom : 5 })
    .backgroundColor($r("app.color.white"))
    .onClick(() => {
      switch ( apiItem.method ) {
        case "pairDevice": {
          let message: string = apiItem.api!(this.pairedMac);
          apiItem.result = message;
          this.currentIndex += 1;
          this.changeIndex = this.currentIndex;
          prompt.showToast({ message : message });
        }
          break;
        case "unpairDevice": {
          let message: string = apiItem.api!(this.pairedMac);
          apiItem.result = message;
          this.currentIndex += 1;
          this.changeIndex = this.currentIndex;
          prompt.showToast({ message : message });
        }
          break;
        case "getDeviceName": {
          let message: string = apiItem.api!(this.pairedMac);
          apiItem.result = message;
          this.currentIndex += 1;
          this.changeIndex = this.currentIndex;
          prompt.showToast({ message : message });
        }
          break;
        case "getDeviceType": {
          let message: string = apiItem.api!(this.pairedMac);
          apiItem.result = message;
          this.currentIndex += 1;
          this.changeIndex = this.currentIndex;
          prompt.showToast({ message : message });
        }
          break;
        default: {
          let message: string = apiItem.api!();
          apiItem.result = message;
          this.currentIndex += 1;
          this.changeIndex = this.currentIndex;
          prompt.showToast({ message : message });
        }
          break;
      }
    })
  }

  getCurrentState(index: number) {
    return this.apiItems[ index ].result
  }

  build() {
    Column() {
      Scroll() {
        Flex({
          direction : FlexDirection.Column ,
          justifyContent : FlexAlign.SpaceBetween ,
          alignItems : ItemAlign.Start
        }) {
          ForEach(this.apiItems , (item: TestApi , index: number) => {
            this.IngredientItem(item , index)
          })
        }
      }
      .scrollBarWidth(20)
    }
    .height(ConfigData.WH_60_100)
    .padding({ top : 5 , right : 10 , left : 10 })
  }
}