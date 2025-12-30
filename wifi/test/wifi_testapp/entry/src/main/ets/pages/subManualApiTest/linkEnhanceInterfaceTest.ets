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

import { PageTitle } from '../../component/pageTitle';
import { TestImageDisplay } from '../../component/testImageDisplay';
import { ContentTable } from '../../component/contentTable';
import router from '@ohos.router';
import ConfigData from '../../utils/ConfigData';
import { initLinkEnhanceApiData } from '../../entryability/model/testDataModels';
import { TestData } from '../../entryability/model/testData';
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
  @StorageLink('le_serverName') le_serverName: string = "TestLinkEnhanceServer";
  @StorageLink('le_deviceId') le_deviceId: string = "test_device_12345";
  @StorageLink('le_testMessage') le_testMessage: string = "Hello LinkEnhance!";
  @StorageLink('le_connectionTimeout') le_connectionTimeout: number = 10000;
  @StorageLink('le_dataSize') le_dataSize: number = 1024;

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
            Text("服务器名称:").fontSize("16vp").width(150)
            TextInput({ text: this.le_serverName, placeholder: "TestLinkEnhanceServer" })
              .fontSize("15vp")
              .onChange((strInput: string) => {
                this.le_serverName = strInput;
                AppStorage.setOrCreate('le_serverName', this.le_serverName);
              })
              .width(ConfigData.WH_80_100)
              .borderRadius(1)
          }
          .backgroundColor($r("app.color.moon"))
          .padding(2)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)

          Row() {
            Text("设备ID:").fontSize("16vp").width(150)
            TextInput({ text: this.le_deviceId, placeholder: "test_device_12345" })
              .fontSize("15vp")
              .onChange((strInput: string) => {
                this.le_deviceId = strInput;
                AppStorage.setOrCreate('le_deviceId', this.le_deviceId);
              })
              .width(ConfigData.WH_80_100)
              .borderRadius(1)
          }
          .backgroundColor($r("app.color.moon"))
          .padding(2)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)

          Row() {
            Text("测试消息:").fontSize("16vp").width(150)
            TextInput({ text: this.le_testMessage, placeholder: "Hello LinkEnhance!" })
              .fontSize("15vp")
              .onChange((strInput: string) => {
                this.le_testMessage = strInput;
                AppStorage.setOrCreate('le_testMessage', this.le_testMessage);
              })
              .width(ConfigData.WH_80_100)
              .borderRadius(1)
          }
          .backgroundColor($r("app.color.moon"))
          .padding(2)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)

          Row() {
            Text("连接超时(ms):").fontSize("16vp").width(150)
            TextInput({ text: this.le_connectionTimeout.toString(), placeholder: "10000" })
              .fontSize("15vp")
              .type(InputType.Number)
              .onChange((strInput: string) => {
                this.le_connectionTimeout = parseInt(strInput) || 10000;
                AppStorage.setOrCreate('le_connectionTimeout', this.le_connectionTimeout);
              })
              .width(ConfigData.WH_80_100)
              .borderRadius(1)
          }
          .backgroundColor($r("app.color.moon"))
          .padding(2)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)

          Row() {
            Text("数据大小(字节):").fontSize("16vp").width(150)
            TextInput({ text: this.le_dataSize.toString(), placeholder: "1024" })
              .fontSize("15vp")
              .type(InputType.Number)
              .onChange((strInput: string) => {
                this.le_dataSize = parseInt(strInput) || 1024;
                AppStorage.setOrCreate('le_dataSize', this.le_dataSize);
              })
              .width(ConfigData.WH_80_100)
              .borderRadius(1)
          }
          .backgroundColor($r("app.color.moon"))
          .padding(2)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)
        }
      }
      .scrollBarWidth(10)
      .scrollBar(BarState.Auto)
    }
    .width(ConfigData.WH_100_100)
  }
}

@Entry
@Component
struct LinkEnhanceInterfaceTest {
  private testItem: TestData = (router.getParams() as myParams).testItem
  @StorageLink('le_serverName') le_serverName: string = "TestLinkEnhanceServer";
  @StorageLink('le_deviceId') le_deviceId: string = "test_device_12345";
  @StorageLink('le_testMessage') le_testMessage: string = "Hello LinkEnhance!";
  @StorageLink('le_connectionTimeout') le_connectionTimeout: number = 10000;
  @StorageLink('le_dataSize') le_dataSize: number = 1024;

  aboutToAppear() {
    console.info(TAG, "this.testItem:" + JSON.stringify(this.testItem))
  }

  build() {
    Column() {
      Stack({ alignContent: Alignment.TopStart }) {
        TestImageDisplay({ testItem: this.testItem })
        PageTitle({ testItem: this.testItem })
      }

      Stack().height("0.5vp").backgroundColor("#000000");

      Column() {
        LinkEnhanceDeviceSetting()
      }
      .height(150)
      .width(ConfigData.WH_95_100)
      .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))

      Stack().height("0.5vp").backgroundColor("#000000");

      ContentTable({ testItem: this.testItem, apiItems: initLinkEnhanceApiData() })
    }
    .backgroundColor($r("app.color.lead"))
  }
}