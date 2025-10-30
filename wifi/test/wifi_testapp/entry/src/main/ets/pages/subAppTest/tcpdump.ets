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

import chrlogservice from '@hms.chr.chrlogservice';
import hilog from '@ohos.hilog';

@Entry
@Component
struct TcpDumpOpen {
  @State tcpStatusMsg: string = '等待获取...'; // 状态文本

  async updateTcpStatus() {
    hilog.info(0x0000, 'testTag', 'updateTcpStatus start-------------');
    try {
      let result: boolean = await chrlogservice.getTcpdumpStatus();
      hilog.info(0x0000, 'testTag', `updateTcpStatus result: ${result}`);
      if (result === true) {
        this.tcpStatusMsg = 'TCP已打开';
      } else if (result === false) {
        this.tcpStatusMsg = 'TCP已关闭';
      }
    } catch (err) {
      this.tcpStatusMsg = '状态获取失败';
      hilog.error(0x0000, 'testTag', `setTcpStatusAndUpdateUI error: ${JSON.stringify(err)}`);
    }
  }

  async setTcpStatusAndUpdateUI(status: boolean) {
    hilog.info(0x0000, 'testTag', `setTcpStatusAndUpdateUI called, status=${status}`);
    try {
      await chrlogservice.handleTcpdumpSwitch(status);
      hilog.info(0x0000, 'testTag', `handleTcpdumpSwitch success, status=${status}`);
      await this.updateTcpStatus();
    } catch (err) {
      hilog.error(0x0000, 'testTag', `setTcpStatusAndUpdateUI error: ${JSON.stringify(err)}`);
      this.tcpStatusMsg = '状态获取失败';
    }
  }

  aboutToAppearAppear() {
    hilog.info(0x0000, 'testTag', 'aboutToAppearAppear');
    // 页面初始化时获取一次状态
    this.updateTcpStatus();
  }

  build() {
    Column() {
      Text(this.tcpStatusMsg)
        .fontSize('22vp')
        .fontColor(0x333333)
        .margin({ bottom: '20vp' })

      Button({ type: ButtonType.Normal, stateEffect: true }) {
        Row() {
          Text('tcp开启')
            .fontSize("24vp")
            .fontColor(0xffffff)
            .margin({ left: 5, right: 5 })
        }.alignItems(VerticalAlign.Center)
      }
      .borderRadius(8)
      .backgroundColor($r("app.color.blue"))
      .width(180)
      .height(50)
      .margin({ top: "10vp", bottom: "10vp" })
      .onClick(() => {
        this.setTcpStatusAndUpdateUI(true);
      })

      Button({ type: ButtonType.Normal, stateEffect: true }) {
        Row() {
          Text('tcp关闭')
            .fontSize("24vp")
            .fontColor(0xffffff)
            .margin({ left: 5, right: 5 })
        }.alignItems(VerticalAlign.Center)
      }
      .borderRadius(8)
      .backgroundColor($r("app.color.blue"))
      .width(180)
      .height(50)
      .margin({ top: "10vp", bottom: "10vp" })
      .onClick(() => {
        this.setTcpStatusAndUpdateUI(false);
      })
    }
    .width('100%')
    .height('100%')
    .justifyContent(FlexAlign.Center)
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r("sys.color.ohos_id_color_sub_background"))
  }
}
