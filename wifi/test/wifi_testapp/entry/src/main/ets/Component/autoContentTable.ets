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

import { TestData , TestAuto } from '../entryability/model/testData'
import ConfigData from '../utils/ConfigData';

const TAG = "[autoContentTable]"
/**
 *  Auto Test ContentTable Component Page Of WIFI test
 */

@Component
export struct AutoContentTable {
  private autoItemsX!: TestAuto[];
  private testItem!: TestData
  @State autoItems: TestAuto[] = [];
  @State localName: string = 'DaYuBlue'
  @Prop changeIndex: number;

  @Builder IngredientItem(autoItem: TestAuto , index: number) {
    Stack() {
      Flex() {
        Flex({ alignItems : ItemAlign.Center }) {
          Image($r('app.media.wifi'))
            .objectFit(ImageFit.Contain)
            .autoResize(false)
            .height(26)
            .width(25)
        }
        .height(30)
        .width(ConfigData.WH_10_100)
        .padding({ left : 10 })

        Flex({ direction : FlexDirection.Column , alignItems : ItemAlign.Start }) {
          Row() {
            Text(autoItem.method)
              .fontSize("17vp")
              .margin({ top : "3vp" , bottom : "3vp" , left : "10vp" })
              .textAlign(TextAlign.Start)
              .height(40)
              .width(200)
          }
          .height(30)
          .width(ConfigData.WH_70_100)
        }
        .height(30)
        .layoutWeight(6)

        Flex({ alignItems : ItemAlign.Center }) {
          Text(this.changeIndex >= 0 ? this.getCurrentState(index) : autoItem.result)
            .margin({ left : "10vp" })
            .fontSize("17vp")
            .flexGrow(1)
        }
        .layoutWeight(3)
        .padding({ left : 10 })
      }
    }
    .height(40)
    .borderRadius(10)
    .margin({ top : 3 , bottom : 3 })
    .backgroundColor($r("app.color.white"))
  }

  getCurrentState(index: number) {
    if ( index <= this.changeIndex ) {
      this.autoItemsX[ index ].result = 'pass';
    } else {
      console.log(TAG , "index > this.changeIndex")
    }
    return this.autoItemsX[ index ].result
  }

  aboutToAppear(): void {
    console.log("auto组件构建完毕")
    //初始化私有变量
    this.autoItemsX = this.autoItems
  }

  build() {
    Column() {
      Scroll() {
        Flex({
          direction : FlexDirection.Column ,
          justifyContent : FlexAlign.SpaceBetween ,
          alignItems : ItemAlign.Start
        }) {
          ForEach(this.autoItems , (item: TestAuto , index: number) => {
            this.IngredientItem(item , index)
          })
        }
      }
      .scrollBarWidth(20)
    }
    .height(ConfigData.WH_80_100)
    .padding({ top : 5 , right : 10 , left : 10 })
  }
}