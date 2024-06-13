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
import router from '@ohos.router'
import ConfigData from '../utils/ConfigData';
/**
 * Test-GridItem page of wifi test
 */

@Component
export struct TestGridItem {
  private testItem!: TestData

  build() {
    Column() {
      Row() {
        Image(this.testItem.image)
          .objectFit(ImageFit.Contain)
          .height(152)
          .width(ConfigData.WH_100_100)
      }.backgroundColor('#FFf1f3f5')

      Flex({ justifyContent : FlexAlign.Start , alignItems : ItemAlign.Center }) {
        Text(this.testItem.name)
          .fontSize(14)
          .flexGrow(1)
          .padding({ left : 8 })
        Text(this.testItem.detail)
          .fontSize(14)
          .margin({ right : 6 })
      }
      .height(32)
      .width(ConfigData.WH_100_100)
      .backgroundColor('#FFe5e5e5')
    }
    .height(184)
    .width(ConfigData.WH_100_100)
    .onClick(() => {
      router.pushUrl({ url : 'MainAbility/pagesTestDetail' , params : { testId : this.testItem } })
    })
  }
}