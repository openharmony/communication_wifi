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
import { TestData , TestApi , TestStress } from '../entryability/model/testData'
import prompt from '@system.prompt';

const TAG = "[stressContentTable]"

/**
 * ContentTable
 */
@Component
export struct StressContentTable {
  private testItem!: TestData
  @State apiItems: TestStress[] = []
  private currentApiItem!: TestApi
  @State changeIndex: number = - 1
  @State localName: string = 'DaYuBlue1'
  @State currentIndex: number = 1
  @StorageLink('pairedMac') pairedMac: string = "";

  onCancel() {
    console.log('取消')
  }

  onAccept(text: string) {
    console.log('input text:' , text)
  }

  @Builder IngredientItem(apiItem: TestApi , index: number) {
    Stack() {
      Flex() {
        Flex({ alignItems : ItemAlign.Center }) {
          Image($r('app.media.WLAN'))
            .objectFit(ImageFit.Contain)
            .autoResize(false)
            .height(30)
            .width(30)
        }
        .layoutWeight(1)
        .padding({ left : 10 })

        Flex({ direction : FlexDirection.Column , alignItems : ItemAlign.Start }) {
          Text(apiItem.name)
            .fontSize(17.4)
            .fontWeight(FontWeight.Bold)
            .layoutWeight(1)
            .padding({ left : 10 , top : 15 })
          Text(apiItem.method)
            .fontSize(17.4)
            .fontWeight(FontWeight.Bold)
            .layoutWeight(1)
            .padding({ left : 10 , top : 5 })
        }
        .layoutWeight(6)
        .width(ConfigData.WH_80_100)

        Flex({ alignItems : ItemAlign.Center }) {
          Text(this.changeIndex >= 0 ? this.getCurrentState(index) : apiItem.result)
            .fontSize(17.4)
            .flexGrow(1)
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
        case "testScan": {
          let message: string = apiItem.api!();
          apiItem.result = message;
          this.currentIndex += 1;
          this.changeIndex = this.currentIndex;
          prompt.showToast({ message : message });
        }
        default: {
          let StartTime = new Date().getTime()
          for ( let indexNumber = 1 ; indexNumber < 101 ; indexNumber ++ ) {
            let message: string = apiItem.api!();
            apiItem.result = message;
            prompt.showToast({ message : message });
            this.currentIndex += 1;
            this.changeIndex = this.currentIndex;
            AppStorage.setOrCreate('stressNumber' , indexNumber);
            console.log(TAG , apiItem.method + "indexNumber is ------: " + indexNumber);
          }
          let EndTime = new Date().getTime()
          console.log(TAG , "开始:" + Number(StartTime) + "ms")
          console.log(TAG , "结束:" + Number(EndTime) + "ms")
          console.log(TAG , "花费:" + Number(EndTime - StartTime) + "ms")
          let stressTime = EndTime - StartTime
          AppStorage.setOrCreate('stressTime' , stressTime);
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