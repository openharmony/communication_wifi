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

import { TestData, TestApi} from '../entryability/model/testData';
import promptAction from '@ohos.promptAction';
import ConfigData from '../Utils/ConfigData';
/**
 * AutoVerificationTable of wifi test
 */

@Component
export struct AutoVerificationTable {
  private testItem!: TestData
  @State apiItems: TestApi[] = [];
  @State changeIndex: number = ConfigData.ITEM_CLICK_NONE
  @State localName: string = 'DaYuBlue'
  @State currentIndex: number = 1
  @StorageLink('pairedMac') pairedMac: string = "";

  @Builder IngredientItem(apiItem: TestApi, index: number){
    Stack() {
      Flex() {
        Flex({alignItems: ItemAlign.Center}){
          Image($r('app.media.wifi'))
            .objectFit(ImageFit.Contain)
            .autoResize(false)
            .height(ConfigData.VP_30)
            .width(ConfigData.VP_30)
        }
        .layoutWeight(1)
        .padding({left: ConfigData.VP_10})

        Flex({direction: FlexDirection.Column, alignItems: ItemAlign.Start}){
          Text(apiItem.name)
            .fontSize(ConfigData.VP_17_4)
            .fontWeight(FontWeight.Bold)
            .layoutWeight(1)
            .padding({left: ConfigData.VP_10, top: ConfigData.VP_15})
          Text(apiItem.detail)
            .fontSize(ConfigData.VP_17_4)
            .fontWeight(FontWeight.Bold)
            .layoutWeight(1)
            .padding({left: ConfigData.VP_10, top: ConfigData.VP_5})
        }
        .layoutWeight(6)

        Flex({alignItems: ItemAlign.Center}){
          Text(this.changeIndex >= 0 ? this.getCurrentState(index) : apiItem.result)
            .fontSize(ConfigData.VP_17_4)
            .flexGrow(1)
        }
        .layoutWeight(3)
        .padding({left: ConfigData.VP_10})
      }
    }
    .height(ConfigData.VP_80)
    .borderRadius($r('app.float.wh_value_10'))
    .margin({top: ConfigData.VP_5, bottom: ConfigData.VP_5})
    .backgroundColor($r("app.color.white"))
    .onClick(() => {
      switch (apiItem.method){
        default: {
          let message = apiItem.api();
          apiItem.result = message;
          this.currentIndex += 1;
          this.changeIndex = this.currentIndex;
          promptAction.showToast({message: message});
        }
          break;
      }
    })
  }

  getCurrentState(index: number){
    return this.apiItems[index].result
  }

  build() {
    Column() {
      Scroll() {
        Flex({
          direction: FlexDirection.Column,
          justifyContent: FlexAlign.SpaceBetween,
          alignItems: ItemAlign.Start
        }){
          ForEach(this.apiItems, (item: TestApi, index: number) => {
            this.IngredientItem(item, index)
          })
        }
      }
      .scrollBarWidth(ConfigData.VP_20)
    }
    .height(ConfigData.WH_88_100)
    .padding({top: ConfigData.VP_5, right: ConfigData.VP_10, left: ConfigData.VP_10})
  }
}