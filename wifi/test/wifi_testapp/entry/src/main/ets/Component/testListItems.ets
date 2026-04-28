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
import { TestData} from '../entryability/model/testData';

/**
 * Test - ListItem component of wifi test
 */

@Component
export struct TestListItem {
  private testItem!: TestData

  aboutToAppear() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', "TestListItem testItem:" + JSON.stringify(this.testItem))
  }

  build() {
    Navigator({target: this.testItem.url}){
      Flex({justifyContent: FlexAlign.Start, alignItems: ItemAlign.Center}){
        Row() {
          Image(this.testItem.image)
            .objectFit(ImageFit.Contain)
            .autoResize(false)
            .height(ConfigData.VP_60)
            .width(ConfigData.VP_60)
        }
        .backgroundColor($r("app.color.white"))
        .width(ConfigData.WH_30_100)

        Text(this.testItem.name)
          .fontSize(ConfigData.VP_20)
          .flexGrow(1)
          .margin({left: ConfigData.VP_12})
          .width(ConfigData.WH_45_100)
        Text(this.testItem.detail)
          .fontSize(ConfigData.VP_17)
          .margin({left: ConfigData.VP_10, right: ConfigData.VP_5})
          .width(ConfigData.WH_45_100)
      }
      .height(ConfigData.VP_85)
    }
    .params({testItem: this.testItem})
    .margin({right: ConfigData.VP_10, left: ConfigData.VP_10, top: ConfigData.VP_10})
    .padding({left: ConfigData.VP_15, right: ConfigData.VP_15})
    .borderRadius($r('app.float.wh_value_10'))
    .backgroundColor($r("app.color.white"))
  }
}