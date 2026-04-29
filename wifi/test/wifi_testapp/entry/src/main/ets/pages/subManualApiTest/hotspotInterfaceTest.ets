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
import { PageTitle} from '../../Component/pageTitle';
import { TestImageDisplay} from '../../Component/testImageDisplay';
import { ContentTable} from '../../Component/contentTable';
import router from '@ohos.router';
import ConfigData from '../../Utils/ConfigData';
import { initHotspotApIData} from '../../entryability/model/testDataModels';
import { TestData} from '../../entryability/model/testData';
import { FilterTable} from '../../Component/filterTable';

interface myParams extends Object {
  testItem: TestData
}

/**
 * hotspot Test Page Of Wifi test
 */

@Entry
@Component
struct hotspotInterfaceTest {
  @State showList: boolean = true;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State message: string = "";
  @State h_ssid: string = ConfigData.SCENARIO_HS_SSID;
  @State h_securityType: number = ConfigData.QV_MOCK_SECURITY_TYPE;
  @State h_band: number = ConfigData.SCENARIO_HS_BAND;
  @State h_preSharedKey: string = ConfigData.QV_MOCK_PRE_SHARED_KEY;
  @State h_maxConn: number = ConfigData.SCENARIO_HS_MAX_CONN;
  @State h_channel: number = ConfigData.SCENARIO_HS_CHANNEL;
  @StorageLink('hotspotSsid') hotspotSsid: string = "";
  @StorageLink('hotspotStateMessage') hotspotStateMessage: string = "";
  @StorageLink('getStationsMessage') getStationsMessage: string = "";
  @StorageLink('getHotspotConfigMessage') getHotspotConfigMessage: string = "";
  @StorageLink('hotspotStaJoinMessage') hotspotStaJoinMessage: string = "";
  @StorageLink('hotspotStaLeaveMessage') hotspotStaLeaveMessage: string = "";

  aboutToAppear() {
    AppStorage.setOrCreate("h_ssid", this.h_ssid)
    AppStorage.setOrCreate("h_securityType", this.h_securityType)
    AppStorage.setOrCreate("h_band", this.h_band)
    AppStorage.setOrCreate("h_preSharedKey", this.h_preSharedKey)
    AppStorage.setOrCreate("h_maxConn", this.h_maxConn)
    AppStorage.setOrCreate("h_channel", this.h_channel)
  }

  init() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', "init-----------")
  }

  build() {
    Column() {
      Stack({alignContent: Alignment.TopStart}){
        TestImageDisplay({testItem: this.testItem})
        PageTitle({testItem: this.testItem})
      }

      Stack().height(ConfigData.VP_0_5).backgroundColor($r("app.color.black"));

      Column() {
        Row() {
          Text($r('app.string.wifitest_text_bsbrdm'))
            .fontSize(ConfigData.VP_17)
            .height(ConfigData.VP_60)
            .width(ConfigData.WH_30_100)
            .padding({left: ConfigData.VP_10})
          TextInput({text: this.hotspotSsid, placeholder: $r('app.string.wifitest_text_zycsrrddpz')})
            .fontSize(ConfigData.VP_17)
            .backgroundColor($r("app.color.white"))
            .onChange((strInput: string) => {
              this.hotspotSsid = strInput;
            })
            .width(ConfigData.WH_50_100)
          Image($r('app.media.Switch'))
            .height(ConfigData.VP_50)
            .padding({top: ConfigData.VP_5, bottom: ConfigData.VP_5, left: ConfigData.VP_10})
            .width(ConfigData.WH_15_100)
            .onClick(() => {
              this.showList = !this.showList;
            })
        }
        .margin({top: ConfigData.VP_10, left: ConfigData.VP_20, right: ConfigData.VP_20})
        .alignItems(VerticalAlign.Center)
        .width(ConfigData.WH_100_100)
        .height(ConfigData.VP_60)
      }
      .align(Alignment.TopStart)

      if (this.showList){
        Column() {
          Scroll() {
            Column() {
              Text() {
                Span($r('app.string.wifitest_text_hs_state'))
                Span(this.hotspotStateMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_hs_cfg'))
                Span(this.getHotspotConfigMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_hs_stations'))
                Span(this.getStationsMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_hs_join'))
                Span(this.hotspotStaJoinMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_hs_leave'))
                Span(this.hotspotStaLeaveMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
            }
            .width(ConfigData.WH_100_100)
          }
          .scrollBarWidth(ConfigData.VP_10)
          .scrollBar(BarState.Auto)
        }
        .height(ConfigData.VP_100)
        .width(ConfigData.WH_95_100)
        .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))

        ContentTable({
          testItem: this.testItem, apiItems: initHotspotApIData()
        })
      } else {
        FilterTable({testItem: this.testItem})
      }
    }
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r("app.color.lead"))
    .height(ConfigData.WH_100_100)
  }
}

