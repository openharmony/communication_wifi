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

import { Category , TestData } from '../entryability/model/testData'
import { initTestData } from '../entryability/model/testDataModels'
import { MainPageTitle } from '../Component/mainPageTitle';
import { ManualApiTest } from '../Component/manualApiTestComponent';
import { ManualSceneTest } from '../Component/manualSceneTest';
import { AutoTest } from '../Component/autoTest';
import { AppTest } from '../Component/appTest';
import { StabilityTest } from "../Component/stabilityTest"
import { BenchmarkTest } from '../Component/benchmarkTest';
import { StressTest } from "../Component/stressTest"
import ConfigData from '../utils/ConfigData';

const TAG = '[homePage]'

/**
 * homepage of wifi test
 */

@Component
struct TestCategory {
  private testItems!: TestData[]

  build() {
    Stack() {
      Tabs() {
        TabContent() {
          AppTest({ testItems : this.testItems.filter(item => (item.category === Category.App)) })
        }.tabBar($r("app.string.App")).margin({ top : $r("app.float.distance_5") })

        TabContent() {
          ManualApiTest({ testItems : this.testItems.filter(item => (item.category === Category.API)) })
        }.tabBar($r("app.string.api")).margin({ top : $r("app.float.distance_5") })

        TabContent() {
          StabilityTest({ testItems : this.testItems.filter(item => (item.category === Category.Stability)) })
        }.tabBar($r("app.string.stability")).margin({ top : $r("app.float.distance_5") })

        TabContent() {
          AutoTest({ testItems : this.testItems.filter(item => (item.category === Category.AutoTest)) })
        }.tabBar($r("app.string.autotest")).margin({ top : $r("app.float.distance_5") })

        TabContent() {
          ManualSceneTest({ testItems : this.testItems.filter(item => (item.category === Category.Scenario)) })
        }.tabBar($r("app.string.scenario")).margin({ top : $r("app.float.distance_5") })

        TabContent() {
          BenchmarkTest({ testItems : this.testItems.filter(item => (item.category === Category.BenchMark)) })
        }.tabBar($r("app.string.benchmark")).margin({ top : $r("app.float.distance_5") })

        TabContent() {
          StressTest({ testItems : this.testItems.filter(item => (item.category === Category.Stress)) })
        }.tabBar($r("app.string.stress")).margin({ top : $r("app.float.distance_5") })
      }
      .barWidth(ConfigData.WH_80_100)
      .barHeight("40vp")
      .align(Alignment.TopStart)
      .barMode(BarMode.Scrollable)
      .backgroundColor($r("app.color.white"))
    }
  }
}

/**
 * Home Page Of wifi test
 */
@Entry
@Component
struct HomePage {
  private testItems: TestData[] = initTestData()

  build() {
    Column() {
      MainPageTitle()
      Stack({ alignContent : Alignment.TopEnd }) {
        TestCategory({ testItems : this.testItems })
        Image($r('app.media.Switch'))
          .height(30)
          .width(30)
          .margin({ top : $r("app.float.distance_5") , right : $r("app.float.distance_10") })
          .onClick(() => {
          })
      }
      .height(ConfigData.WH_100_100)
    }
  }
}
