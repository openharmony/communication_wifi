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
import ConfigData from '../../Utils/ConfigData';
import router from '@ohos.router';
import { TestData} from '../../entryability/model/testData';
import { PageTitle} from '../../Component/pageTitle';
import { TestImageDisplay} from '../../Component/testImageDisplay';
import { HotspotAutoTestCase, initHotspotAutoData} from '../../entryability/model/autoTestDataModels';
import { AutoContentTable} from '../../Component/autoContentTable';
import promptAction from '@ohos.promptAction';

interface myParams extends Object {
  testItem: TestData
}

interface IWifiAutoArrayItem {
  name: string;
  para: string[];
}

/**
 *  hotspotAutoTest Page Of wifi test
 */
@Entry
@Component
struct HotspotAutoTest {
  @State message: string = ConfigData.PAGE_TAG_HS_AUTO;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State changeIndex: number = ConfigData.ITEM_CLICK_NONE
  //  @State autoTextMessage: string ="None";
  @StorageLink("hotspotAutoTestMessage") hotspotAutoTestMessage: string = ""
  @State h_ssid: string = ConfigData.SCENARIO_HS_SSID;
  @State h_securityType: number = ConfigData.QV_MOCK_SECURITY_TYPE;
  @State h_band: number = ConfigData.SCENARIO_HS_BAND;
  @State h_preSharedKey: string = ConfigData.QV_MOCK_PRE_SHARED_KEY;
  @State h_maxConn: number = ConfigData.SCENARIO_HS_MAX_CONN;
  @State h_channel: number = ConfigData.SCENARIO_HS_CHANNEL;

  aboutToAppear() {
    AppStorage.setOrCreate("h_ssid", this.h_ssid)
    AppStorage.setOrCreate("h_securityType", this.h_securityType)
    AppStorage.setOrCreate("h_band", this.h_band)
    AppStorage.setOrCreate("h_preSharedKey", this.h_preSharedKey)
    AppStorage.setOrCreate("h_maxConn", this.h_maxConn)
    AppStorage.setOrCreate("h_channel", this.h_channel)
  }

  build() {
    Column() {
      Stack({alignContent: Alignment.TopStart}){
        TestImageDisplay({testItem: this.testItem})
        PageTitle({testItem: this.testItem})
      }

      Stack().height(ConfigData.VP_1).backgroundColor($r("app.color.black"));
      Column() {
        Scroll() {
          Column() {
            Text($r('app.string.wifitest_text_ayz'))
              .fontSize(ConfigData.VP_17)
              .margin({top: ConfigData.VP_10, bottom: ConfigData.VP_10, left: ConfigData.VP_15})
              .textAlign(TextAlign.Start)
              .width(ConfigData.WH_100_100)
            AutoContentTable({
              testItem: this.testItem,
              autoItems: initHotspotAutoData(),
              //             testMessage: this.testMessage,  优化时修改
              changeIndex: this.changeIndex
            })
          }
          .width(ConfigData.WH_100_100)
          .height(ConfigData.VP_280)
        }
        .scrollBarWidth(ConfigData.VP_10)
        .scrollBar(BarState.Auto)

        Stack().height(ConfigData.VP_1).backgroundColor($r("app.color.black"));

        Scroll() {
          Column() {
            Text($r('app.string.wifitest_text_drz'))
              .fontSize(ConfigData.VP_17)
              .margin({top: ConfigData.VP_8, bottom: ConfigData.VP_8, left: ConfigData.VP_15})
              .textAlign(TextAlign.Start)
              .width(ConfigData.WH_100_100)
            List() {
              ListItem() {
                Text() {
                  Span($r('app.string.wifitest_text_log_label'))
                  Span(this.hotspotAutoTestMessage)
                }
                  .fontSize(ConfigData.VP_17)
                  .margin({top: ConfigData.VP_5, left: ConfigData.VP_30, right: ConfigData.VP_10})
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_90_100)
              }
            }
            .height(ConfigData.WH_80_100)
            .width(ConfigData.WH_90_100)
            .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))
          }
          .width(ConfigData.WH_100_100)
          .height(ConfigData.VP_260)
        }
        .scrollBarWidth(ConfigData.VP_10)
        .scrollBar(BarState.On)
      }
      .height(ConfigData.VP_500)
      .width(ConfigData.WH_100_100)
      .backgroundColor($r("sys.color.ohos_id_color_sub_background"))


      Stack().height(ConfigData.VP_1).backgroundColor($r("app.color.black"));
      Column() {
        Button({type: ButtonType.Normal, stateEffect: true}){
          Row() {
            Text($r('app.string.autotest')).fontSize(ConfigData.VP_24).fontColor($r('app.color.white')).margin({left: ConfigData.VP_5, right: ConfigData.VP_5})
          }.alignItems(VerticalAlign.Center)
        }
        .borderRadius($r('app.float.wh_value_8'))
        .backgroundColor($r("app.color.blue"))
        .width(ConfigData.VP_180)
        .height(ConfigData.VP_50)
        .margin({top: ConfigData.VP_15})
        .onClick(async(event: ClickEvent) => {
          await this.forLoop()

          let msg = ""
          msg = "测试"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s', msg)
          promptAction.showToast({message: msg})
        })
      }
      .backgroundColor($r("sys.color.ohos_id_color_sub_background"))
      .width(ConfigData.WH_100_100)
      .height(ConfigData.WH_100_100);
    }
  }

  //循环调用
  async forLoop() {
    let hotspotAutoTestMessage = ""
    let hotspotAutoArray: IWifiAutoArrayItem[] = [];

    //拼装数组
    let Interface = HotspotAutoTestCase.map(i => {
      // 查找与条件匹配的元素，并且确保其不是undefined
      const foundItem = hotspotAutoArray.find(itm => itm.name === i.api.name);
      let para: string[] = foundItem ? foundItem.para: [];
      return { name: i.api.name, para} as IWifiAutoArrayItem;
    });

    for(let m = 0 ; m<Interface.length ; m++){
      hotspotAutoTestMessage += await HotspotAutoTestCase[m].api(... Interface[m].para) + "\n"
      this.changeIndex = m
      await sleep(2)
      AppStorage.setOrCreate("hotspotAutoTestMessage", hotspotAutoTestMessage)
    }
  }
}

async function sleep(time: number): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    setTimeout(() => {
      resolve();
    }, time * 1000);
  });
}