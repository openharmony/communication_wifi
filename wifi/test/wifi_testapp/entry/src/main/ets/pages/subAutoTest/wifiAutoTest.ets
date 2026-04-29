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
import { WifiAutoTestCase, initWifiAutoData} from '../../entryability/model/autoTestDataModels';
import { AutoContentTable} from '../../Component/autoContentTable';
import promptAction from '@ohos.promptAction';

interface myParams extends Object {
  testItem: TestData
}

interface IWifiAutoArrayItem {
  name: string;
  para: string[];// 替换any[]为实际参数类型
}
/**
 *  wifiAutoTest Page Of wifi test
 */

@Entry
@Component
struct WifiAutoTest {
  @State message: string = ConfigData.PAGE_TAG_WIFI_AUTO;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State changeIndex: number = ConfigData.ITEM_CLICK_NONE
  //  @State autoTextMessage: string ="None";
  @StorageLink("wifiAutoTestMessage") wifiAutoTestMessage: string = ""
  @State w_ssid: string = ConfigData.QV_MOCK_SSID;
  @State w_bssid: string = ConfigData.QV_MOCK_BSSID;
  @State w_preSharedKey: string = ConfigData.QV_MOCK_PRE_SHARED_KEY;
  @State w_isHiddenSsid: boolean = false;
  @State w_securityType: number = ConfigData.QV_MOCK_SECURITY_TYPE
  @State w_creatorUid: number = ConfigData.QV_MOCK_CREATOR_UID;
  @State w_disableReason: number = ConfigData.QV_MOCK_DISABLE_REASON;
  @State w_netId: number = ConfigData.QV_MOCK_NET_ID;
  @State w_randomMacType: number = ConfigData.QV_MOCK_RANDOM_MAC_TYPE;
  @State w_randomMacAddr: string = ConfigData.QV_MOCK_RANDOM_MAC_ADDR
  @State w_ipType: number = ConfigData.QV_MOCK_IP_TYPE;
  @State w_staticIp_ipAddress: number = ConfigData.QV_MOCK_STATIC_IP_ADDRESS;
  @State w_staticIp_gateway: number = ConfigData.QV_MOCK_STATIC_GATEWAY;
  @State w_staticIp_dnsServers: number = ConfigData.QV_MOCK_STATIC_DNS;
  @State w_staticIp_domains: Array<string> = [ConfigData.QV_MOCK_DOMAIN_0, ConfigData.QV_MOCK_DOMAIN_1, ConfigData.QV_MOCK_DOMAIN_2];
  @State w_networkId: number = ConfigData.SCENARIO_WM_NET_ID;// id,netId,networkId是一个值嘛？
  @State w_featureId: number = ConfigData.WIFI_DEMO_FEATURE_ID;

  aboutToAppear() {
    AppStorage.setOrCreate('w_ssid', this.w_ssid);
    AppStorage.setOrCreate('w_bssid', this.w_bssid);
    AppStorage.setOrCreate('w_preSharedKey', this.w_preSharedKey);
    AppStorage.setOrCreate('w_isHiddenSsid', this.w_isHiddenSsid);
    AppStorage.setOrCreate('w_securityType', this.w_securityType);
    AppStorage.setOrCreate('w_creatorUid', this.w_creatorUid);
    AppStorage.setOrCreate('w_disableReason', this.w_disableReason);
    AppStorage.setOrCreate('w_netId', this.w_netId);
    AppStorage.setOrCreate('w_randomMacType', this.w_randomMacType);
    AppStorage.setOrCreate('w_randomMacAddr', this.w_randomMacAddr);
    AppStorage.setOrCreate('w_ipType', this.w_ipType);
    AppStorage.setOrCreate('w_staticIp_ipAddress', this.w_staticIp_ipAddress);
    AppStorage.setOrCreate('w_staticIp_gateway', this.w_staticIp_gateway);
    AppStorage.setOrCreate('w_staticIp_dnsServers', this.w_staticIp_dnsServers);
    AppStorage.setOrCreate('w_staticIp_domains', this.w_staticIp_domains);
    AppStorage.setOrCreate('w_networkId', this.w_networkId);
    AppStorage.setOrCreate('w_featureId', this.w_featureId);
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
              autoItems: initWifiAutoData(),
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
                Text(this.wifiAutoTestMessage)
                  //                Text() { Span($r('app.string.wifitest_text_log_label')) Span(this.wifiAutoTestMessage) }
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
          hilog.info(0x1500, 'wifiTestApp', '%{public}s', "wifiAutoTest start-------------")
          await this.forLoop()

          let msg = ""
          msg = "测试"
          hilog.info(0x1500, 'wifiTestApp', '%{public}s', msg)
          promptAction.showToast({message: msg})

          hilog.info(0x1500, 'wifiTestApp', '%{public}s', "wifiAutoTest end-------------")
        })
      }
      .backgroundColor($r("sys.color.ohos_id_color_sub_background"))
      .width(ConfigData.WH_100_100)
      .height(ConfigData.WH_100_100);
    }
  }

  //循环调用
  async forLoop() {
    let wifiAutoTestMessage: string = ""
    let wifiAutoArray: IWifiAutoArrayItem[] = []

    //拼装数组
    let Interface = WifiAutoTestCase.map(i => {
      // 查找与条件匹配的元素，并且确保其不是undefined
      const foundItem = wifiAutoArray.find(itm => itm.name === i.api.name);
      let para: string[] = foundItem ? foundItem.para: [];
      return { name: i.api.name, para} as IWifiAutoArrayItem;
    })

    for(let m = 0 ; m<Interface.length ; m++){
      wifiAutoTestMessage += await WifiAutoTestCase[m].api(... Interface[m].para) + "\n"
      this.changeIndex = m
      await sleep(2)
      AppStorage.setOrCreate("wifiAutoTestMessage", wifiAutoTestMessage)
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