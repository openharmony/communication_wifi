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

import ConfigData from '../../Utils/ConfigData';
import chrlogservice from '@hms.chr.chrlogservice';
import hilog from '@ohos.hilog';

@Entry
@Component
struct TcpDumpOpen {
  @State tcpStatusMsg: string = ConfigData.TCPDUMP_STR_WAIT;// 状态文本

  async updateTcpStatus() {
    hilog.info(0x0000, 'testTag', 'updateTcpStatus start-------------');
    try {
      let result: boolean = await chrlogservice.getTcpdumpStatus();
      hilog.info(0x0000, 'testTag', `updateTcpStatus result: ${result}`);
      if (result === true){
        this.tcpStatusMsg = ConfigData.TCPDUMP_STR_ON;
      } else if (result === false){
        this.tcpStatusMsg = ConfigData.TCPDUMP_STR_OFF;
      }
    } catch (err){
      this.tcpStatusMsg = ConfigData.TCPDUMP_STR_FETCH_FAIL;
      hilog.error(0x0000, 'testTag', `setTcpStatusAndUpdateUI error: ${JSON.stringify(err)}`);
    }
  }

  async setTcpStatusAndUpdateUI(status: boolean){
    hilog.info(0x0000, 'testTag', `setTcpStatusAndUpdateUI called, status=${status}`);
    try {
      await chrlogservice.handleTcpdumpSwitch(status);
      hilog.info(0x0000, 'testTag', `handleTcpdumpSwitch success, status=${status}`);
      await this.updateTcpStatus();
    } catch (err){
      hilog.error(0x0000, 'testTag', `setTcpStatusAndUpdateUI error: ${JSON.stringify(err)}`);
      this.tcpStatusMsg = ConfigData.TCPDUMP_STR_FETCH_FAIL;
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
        .fontSize(ConfigData.VP_22)
        .fontColor($r('app.color.color_333333_grey'))
        .margin({bottom: ConfigData.VP_20})

      Button({type: ButtonType.Normal, stateEffect: true}){
        Row() {
          Text($r('app.string.wifitest_text_tkq'))
            .fontSize(ConfigData.VP_24)
            .fontColor($r('app.color.white'))
            .margin({left: ConfigData.VP_5, right: ConfigData.VP_5})
        }.alignItems(VerticalAlign.Center)
      }
      .borderRadius($r('app.float.wh_value_8'))
      .backgroundColor($r("app.color.blue"))
      .width(ConfigData.VP_180)
      .height(ConfigData.VP_50)
      .margin({top: ConfigData.VP_10, bottom: ConfigData.VP_10})
      .onClick(() => {
        this.setTcpStatusAndUpdateUI(true);
      })

      Button({type: ButtonType.Normal, stateEffect: true}){
        Row() {
          Text($r('app.string.wifitest_text_tgb'))
            .fontSize(ConfigData.VP_24)
            .fontColor($r('app.color.white'))
            .margin({left: ConfigData.VP_5, right: ConfigData.VP_5})
        }.alignItems(VerticalAlign.Center)
      }
      .borderRadius($r('app.float.wh_value_8'))
      .backgroundColor($r("app.color.blue"))
      .width(ConfigData.VP_180)
      .height(ConfigData.VP_50)
      .margin({top: ConfigData.VP_10, bottom: ConfigData.VP_10})
      .onClick(() => {
        this.setTcpStatusAndUpdateUI(false);
      })
    }
    .width(ConfigData.WH_100_100)
    .height(ConfigData.WH_100_100)
    .justifyContent(FlexAlign.Center)
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r("sys.color.ohos_id_color_sub_background"))
  }
}
