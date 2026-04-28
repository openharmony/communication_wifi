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
import ConfigData from '../Utils/ConfigData';
import { TestScenario} from '../entryability/model/testData';
import promptAction from '@ohos.promptAction';

const TAG = "wifiTestApp [scenarioContentTable]"
/**
 *  Scenario Test ContentTable Component Page Of Wifi test
 */

@Component
export struct ScenarioContentTable {
  @State scenarioItems: TestScenario[] = [];
  private scenarioItemsX!: TestScenario[]
  @Prop changeIndex: number;
  @State localName: string = 'DaYuBlue'

  @Builder IngredientItem(scenarioItem: TestScenario, index: number){
    Stack() {
      Flex() {
        Flex({direction: FlexDirection.Column, alignItems: ItemAlign.Start}){
          Row() {
            Text(scenarioItem.detail)
              .fontSize(ConfigData.VP_17)
              .margin({top: ConfigData.VP_3, bottom: ConfigData.VP_3, left: ConfigData.VP_10})
              .textAlign(TextAlign.Start)
              .height(ConfigData.VP_40)
              .width(ConfigData.VP_30)

            Text(scenarioItem.method)
              .fontSize(ConfigData.VP_17)
              .margin({top: ConfigData.VP_3, bottom: ConfigData.VP_3, left: ConfigData.VP_10})
              .textAlign(TextAlign.Start)
              .height(ConfigData.VP_40)
              .width(ConfigData.VP_240)
          }
          .height(ConfigData.VP_30)
          .width(ConfigData.WH_70_100)
        }
        .height(ConfigData.VP_30)
        .layoutWeight(6)

        Flex({alignItems: ItemAlign.Center}){
          Text(this.changeIndex >= 0 ? this.getCurrentState(index) : scenarioItem.result)
            .margin({left: ConfigData.VP_10})
            .fontSize(ConfigData.VP_17)
            .flexGrow(1)
        }
        .layoutWeight(3)
        .padding({left: ConfigData.VP_10})
        .margin({left: ConfigData.VP_10})
      }
    }
    .height(ConfigData.VP_40)
    .borderRadius($r('app.float.wh_value_10'))
    .margin({top: ConfigData.VP_3, bottom: ConfigData.VP_3})
    .backgroundColor($r("app.color.white"))
  }

  getCurrentState(index: number){
    if (index <= this.changeIndex){
      this.scenarioItemsX[index].result = 'pass';
    } else {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "index > this.changeIndex")
    }
    return this.scenarioItemsX[index].result
  }

  aboutToAppear(): void {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "scenario组件构建完毕")
    //初始化私有变量
    this.scenarioItemsX = this.scenarioItems
  }

  build() {
    Column() {
      Scroll() {
        Flex({
          direction: FlexDirection.Column,
          justifyContent: FlexAlign.SpaceBetween,
          alignItems: ItemAlign.Start
        }){
          ForEach(this.scenarioItems, (item: TestScenario, index: number) => {
            this.IngredientItem(item, index)
          })
        }
      }
      .scrollBarWidth(ConfigData.VP_20)
    }
    .height(ConfigData.WH_80_100)
    .padding({top: ConfigData.VP_5, right: ConfigData.VP_10, left: ConfigData.VP_10})
  }
}