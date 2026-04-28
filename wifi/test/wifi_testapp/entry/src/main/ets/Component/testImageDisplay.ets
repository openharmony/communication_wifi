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

import { TestData} from '../entryability/model/testData';
import ConfigData from '../Utils/ConfigData';

/**
 * Test - ImageDisplay page of wifi test
 */

@Component
export struct TestImageDisplay {
  private testItem!: TestData

  build() {
    Stack({alignContent: Alignment.BottomStart}){
      Flex({alignItems: ItemAlign.Start}){
        Stack() {
          Image(this.testItem.image)
            .height(ConfigData.VP_100)
            .width(ConfigData.VP_100)
            .margin({left: ConfigData.VP_20, top: ConfigData.VP_20})
        }
        .width(ConfigData.WH_20_100)

        Column() {
          Text(this.testItem.name)
            .fontSize(ConfigData.VP_26)
            .fontWeight(500)
            .margin({left: ConfigData.VP_26, top: ConfigData.VP_20})
            .width(ConfigData.WH_90_100)
          Text(this.testItem.detail)
            .fontSize(ConfigData.VP_18)
            .fontWeight(500)
            .margin({top: ConfigData.VP_8})
            .width(ConfigData.WH_80_100)
        }
        .width(ConfigData.WH_70_100)
        .padding({left: ConfigData.VP_20, top: ConfigData.VP_15})
      }
    }
    .backgroundColor($r("app.color.ohcc_hex_ffedf2f5"))
    .height(ConfigData.VP_160)
  }
}