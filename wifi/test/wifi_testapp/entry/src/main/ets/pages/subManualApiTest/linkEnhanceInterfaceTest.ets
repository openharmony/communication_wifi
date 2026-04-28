/**
 * Copyright (c) 2025 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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
import { PageTitle} from '../../Component/pageTitle';
import { TestImageDisplay} from '../../Component/testImageDisplay';
import { ContentTable} from '../../Component/contentTable';
import router from '@ohos.router';
import ConfigData from '../../Utils/ConfigData';
import { initLinkEnhanceApiData} from '../../entryability/model/testDataModels';
import { TestData} from '../../entryability/model/testData';
import linkEnhance from '@ohos.distributedsched.linkEnhance';

interface myParams extends Object {
  testItem: TestData
}

const TAG = "linkEnhanceTestApp [LinkEnhance]"

/**
 * LinkEnhance Test Page Of LinkEnhance test
 */

@Component
struct LinkEnhanceDeviceSetting {
  @StorageLink('le_serverName') le_serverName: string = ConfigData.LE_DEMO_SERVER_NAME;
  @StorageLink('le_deviceId') le_deviceId: string = ConfigData.LE_DEMO_DEVICE_ID;
  @StorageLink('le_testMessage') le_testMessage: string = ConfigData.LE_DEMO_TEST_MESSAGE;
  @StorageLink('le_connectionTimeout') le_connectionTimeout: number = ConfigData.LE_DEMO_CONNECTION_TIMEOUT_MS;
  @StorageLink('le_dataSize') le_dataSize: number = ConfigData.LE_DEMO_DATA_SIZE;

  aboutToAppear() {
    // 初始化LinkEnhance配置参数
    AppStorage.setOrCreate("linkEnhanceConfig", {
      serverName: this.le_serverName,
      deviceId: this.le_deviceId,
      testMessage: this.le_testMessage,
      connectionTimeout: this.le_connectionTimeout,
      dataSize: this.le_dataSize
    });
  }

  build() {
    Column() {
      Scroll() {
        Column() {
          Row() {
            Text($r('app.string.wifitest_text_fwqmc')).fontSize(ConfigData.VP_16).width(ConfigData.VP_150)
            TextInput({text: this.le_serverName, placeholder: "TestLinkEnhanceServer"})
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                this.le_serverName = strInput;
                AppStorage.setOrCreate('le_serverName', this.le_serverName);
              })
              .width(ConfigData.WH_80_100)
              .borderRadius($r('app.float.wh_value_1'))
          }
          .backgroundColor($r("app.color.moon"))
          .padding(ConfigData.VP_2)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)

          Row() {
            Text($r('app.string.wifitest_text_sbi')).fontSize(ConfigData.VP_16).width(ConfigData.VP_150)
            TextInput({text: this.le_deviceId, placeholder: "test_device_12345"})
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                this.le_deviceId = strInput;
                AppStorage.setOrCreate('le_deviceId', this.le_deviceId);
              })
              .width(ConfigData.WH_80_100)
              .borderRadius($r('app.float.wh_value_1'))
          }
          .backgroundColor($r("app.color.moon"))
          .padding(ConfigData.VP_2)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)

          Row() {
            Text($r('app.string.wifitest_text_csxx')).fontSize(ConfigData.VP_16).width(ConfigData.VP_150)
            TextInput({text: this.le_testMessage, placeholder: $r('app.string.wifitest_text_hl')})
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                this.le_testMessage = strInput;
                AppStorage.setOrCreate('le_testMessage', this.le_testMessage);
              })
              .width(ConfigData.WH_80_100)
              .borderRadius($r('app.float.wh_value_1'))
          }
          .backgroundColor($r("app.color.moon"))
          .padding(ConfigData.VP_2)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)

          Row() {
            Text($r('app.string.wifitest_text_ljcsm')).fontSize(ConfigData.VP_16).width(ConfigData.VP_150)
            TextInput({text: this.le_connectionTimeout.toString(), placeholder: $r('app.string.wifitest_text_1_2')})
              .fontSize(ConfigData.VP_15)
              .type(InputType.Number)
              .onChange((strInput: string) => {
                this.le_connectionTimeout = parseInt(strInput) || 10000;
                AppStorage.setOrCreate('le_connectionTimeout', this.le_connectionTimeout);
              })
              .width(ConfigData.WH_80_100)
              .borderRadius($r('app.float.wh_value_1'))
          }
          .backgroundColor($r("app.color.moon"))
          .padding(ConfigData.VP_2)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)

          Row() {
            Text($r('app.string.wifitest_text_sjdxzj')).fontSize(ConfigData.VP_16).width(ConfigData.VP_150)
            TextInput({text: this.le_dataSize.toString(), placeholder: $r('app.string.wifitest_text_1_1')})
              .fontSize(ConfigData.VP_15)
              .type(InputType.Number)
              .onChange((strInput: string) => {
                this.le_dataSize = parseInt(strInput) || 1024;
                AppStorage.setOrCreate('le_dataSize', this.le_dataSize);
              })
              .width(ConfigData.WH_80_100)
              .borderRadius($r('app.float.wh_value_1'))
          }
          .backgroundColor($r("app.color.moon"))
          .padding(ConfigData.VP_2)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)
        }
      }
      .scrollBarWidth(ConfigData.VP_10)
      .scrollBar(BarState.Auto)
    }
    .width(ConfigData.WH_100_100)
  }
}

@Entry
@Component
struct LinkEnhanceInterfaceTest {
  private testItem: TestData = (router.getParams() as myParams).testItem
  @StorageLink('le_serverName') le_serverName: string = ConfigData.LE_DEMO_SERVER_NAME;
  @StorageLink('le_deviceId') le_deviceId: string = ConfigData.LE_DEMO_DEVICE_ID;
  @StorageLink('le_testMessage') le_testMessage: string = ConfigData.LE_DEMO_TEST_MESSAGE;
  @StorageLink('le_connectionTimeout') le_connectionTimeout: number = ConfigData.LE_DEMO_CONNECTION_TIMEOUT_MS;
  @StorageLink('le_dataSize') le_dataSize: number = ConfigData.LE_DEMO_DATA_SIZE;

  aboutToAppear() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "this.testItem:" + JSON.stringify(this.testItem))
  }

  build() {
    Column() {
      Stack({alignContent: Alignment.TopStart}){
        TestImageDisplay({testItem: this.testItem})
        PageTitle({testItem: this.testItem})
      }

      Stack().height(ConfigData.VP_0_5).backgroundColor($r("app.color.black"));

      Column() {
        LinkEnhanceDeviceSetting()
      }
      .height(ConfigData.VP_150)
      .width(ConfigData.WH_95_100)
      .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))

      Stack().height(ConfigData.VP_0_5).backgroundColor($r("app.color.black"));

      ContentTable({testItem: this.testItem, apiItems: initLinkEnhanceApiData()})
    }
    .backgroundColor($r("app.color.lead"))
  }
}