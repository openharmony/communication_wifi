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
import { initNewWifiManagerApiData} from '../../entryability/model/newWifiManagerTestData';
import { TestData} from '../../entryability/model/testData';
import wifiManager from '@ohos.wifiManager';

interface myParams extends Object {
  testItem: TestData
}

const TAG = 'wifiTestApp [QuickVerifyTest]'

/**
 * 快速验证测试页面 - 基于wifiManager接口
 */
interface wifiDeviceConfigManager {
  ssid: string,
  bssid: string,
  preSharedKey: string,
  isHiddenSsid: boolean,
  securityType: wifiManager.WifiSecurityType,
  creatorUid: number,
  disableReason: number,
  netId: number,
  randomMacType: number,
  randomMacAddr: string,
  ipType: wifiManager.IpType,
  staticIp: wifiManager.IpConfig
}

@Component
struct QuickVerifyDeviceSetting {
  @StorageLink('isAllowedQuick') isAllowedQuick: number = 1;
  @StorageLink('w_networkIdMQuick') w_networkIdMQuick: number = 0;
  @StorageLink('w_featureIdMQuick') w_featureIdMQuick: number = 1;
  @StorageLink('wifiDeviceConfigManagerQuick') wifiDeviceConfigManagerQuick: wifiManager.WifiDeviceConfig = {
    ssid: ConfigData.QV_MOCK_SSID,
    bssid: ConfigData.QV_MOCK_BSSID,
    preSharedKey: ConfigData.QV_MOCK_PRE_SHARED_KEY,
    isHiddenSsid: false,
    securityType: 3,
    creatorUid: 1,
    disableReason: 0,
    netId: 1,
    randomMacType: 0,
    randomMacAddr: ConfigData.QV_MOCK_RANDOM_MAC_ADDR,
    ipType: 1,
    staticIp: {
      ipAddress: ConfigData.QV_MOCK_STATIC_IP_ADDRESS,
      gateway: ConfigData.QV_MOCK_STATIC_GATEWAY,
      prefixLength: ConfigData.QV_MOCK_STATIC_PREFIX_LENGTH,
      dnsServers: [ConfigData.QV_MOCK_STATIC_DNS],
      domains: [ConfigData.QV_MOCK_DOMAIN_0, ConfigData.QV_MOCK_DOMAIN_1, ConfigData.QV_MOCK_DOMAIN_2]
    }
  }

  aboutToAppear() {
  }

  build() {
    Column() {
      Row() {
        Text($r('app.string.wifitest_text_s_8')).fontSize(ConfigData.VP_17).width(ConfigData.VP_200)
        TextInput({text: this.isAllowedQuick.toString(), placeholder: ConfigData.QV_MOCK_DOMAIN_1})
          .fontSize(ConfigData.VP_15)
          .onChange((strInput: string) => {
            if (strInput.length >= 1){
              this.isAllowedQuick = Number(strInput);
            }
          })
          .width(ConfigData.WH_50_100)
          .borderRadius($r('app.float.wh_value_1'))
      }
      .backgroundColor($r("app.color.moon"))
      .padding(ConfigData.VP_5)
      .justifyContent(FlexAlign.Start)
      .alignItems(VerticalAlign.Center)

      Row() {
        Text($r('app.string.wifitest_text_s_3')).fontSize(ConfigData.VP_17).width(ConfigData.VP_70)
        TextInput({text: this.wifiDeviceConfigManagerQuick.ssid, placeholder: $r('app.string.wifitest_text_tl6')})
          .fontSize(ConfigData.VP_15)
          .onChange((strInput: string) => {
            if (strInput.length >= 1){
              this.wifiDeviceConfigManagerQuick.ssid = strInput;
            }
          })
          .width(ConfigData.WH_80_100)
          .borderRadius($r('app.float.wh_value_1'))
      }
      .backgroundColor($r("app.color.moon"))
      .padding(ConfigData.VP_5)
      .justifyContent(FlexAlign.Start)
      .alignItems(VerticalAlign.Center)

      Scroll() {
        Column() {
          Stack().height(ConfigData.VP_0_25).backgroundColor($r("app.color.black"));
          Column() {
            Row() {
              Text($r('app.string.wifitest_text_b_4')).fontSize(ConfigData.VP_15).width(ConfigData.VP_60);
              TextInput({text: this.wifiDeviceConfigManagerQuick.bssid, placeholder: $r('app.string.wifitest_text_6b5766')})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  if (strInput.length >= 1){
                    this.wifiDeviceConfigManagerQuick!.bssid = strInput;
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius($r('app.float.wh_value_1'))
            }
            .padding(ConfigData.VP_3)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))

            Row() {
              Text($r('app.string.wifitest_text_p_4')).fontSize(ConfigData.VP_15).width(ConfigData.VP_110);
              TextInput({text: this.wifiDeviceConfigManagerQuick.preSharedKey, placeholder: $r('app.string.wifitest_text_1_3')})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  if (strInput.length >= 1){
                    this.wifiDeviceConfigManagerQuick!.preSharedKey = strInput;
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius($r('app.float.wh_value_1'))
            }
            .backgroundColor($r("app.color.spring"))
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text($r('app.string.wifitest_text_s_7')).fontSize(ConfigData.VP_15).width(ConfigData.VP_100);
              Column() {
                Select([
                  { value: 'WIFI_SEC_TYPE_INVALID'},
                  { value: 'WIFI_SEC_TYPE_OPEN'},
                  { value: 'WIFI_SEC_TYPE_WEP'},
                  { value: 'WIFI_SEC_TYPE_PSK'},
                  { value: 'WIFI_SEC_TYPE_SAE'}
])
                  .selected(3)
                  .value('WIFI_SEC_TYPE_PSK')
                  .font({size: ConfigData.VP_17})
                  .selectedOptionFont({size: ConfigData.VP_17})
                  .optionFont({size: ConfigData.VP_15})
                  .width(ConfigData.WH_80_100)
                  .onSelect((index: number) => {
                    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "Select:" + index)
                    this.wifiDeviceConfigManagerQuick!.securityType = index;
                  })
              }
              .width(ConfigData.WH_80_100)
              .borderRadius($r('app.float.wh_value_1'))
            }
            .backgroundColor($r("app.color.spring"))
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
          }

          Stack().height(ConfigData.VP_0_25).backgroundColor($r("app.color.black"));
        }
      }
      .scrollBarWidth(ConfigData.VP_10)
      .scrollBar(BarState.On)
    }
    .height(ConfigData.WH_58_100)
  }
}

@Entry
@Component
struct QuickVerifyTest {
  @State showList: boolean = false;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State message: string = "";
  @State deviceId: string = '';
  @State currentClick: number = ConfigData.ITEM_CLICK_NONE;
  @StorageLink('isAllowedQuick') isAllowedQuick: number = 1;
  @StorageLink('pairedSsidMQuick') pairedSsidMQuick: string = "";
  @StorageLink('w_networkIdMQuick') w_networkIdMQuick: number = 0;
  @StorageLink('w_featureIdMQuick') w_featureIdMQuick: number = 1;
  @StorageLink('ipInfoManagerMessageQuick') ipInfoManagerMessageQuick: string = '';
  @StorageLink('linkedInfoManagerMessageQuick') linkedInfoManagerMessageQuick: string = '';
  @StorageLink('getDeviceConfigsManagerMessageQuick') getDeviceConfigsManagerMessageQuick: string = '';
  @StorageLink('getScanInfoManagerMessageQuick') getScanInfoManagerMessageQuick: string = '';
  @StorageLink('wifiDeviceConfigManagerQuick') wifiDeviceConfigManagerQuick: wifiManager.WifiDeviceConfig = {
    ssid: ConfigData.QV_MOCK_SSID,
    bssid: ConfigData.QV_MOCK_BSSID,
    preSharedKey: ConfigData.QV_MOCK_PRE_SHARED_KEY,
    isHiddenSsid: false,
    securityType: ConfigData.QV_MOCK_SECURITY_TYPE,
    creatorUid: ConfigData.QV_MOCK_CREATOR_UID,
    disableReason: ConfigData.QV_MOCK_DISABLE_REASON,
    netId: ConfigData.QV_MOCK_NET_ID,
    randomMacType: ConfigData.QV_MOCK_RANDOM_MAC_TYPE,
    randomMacAddr: ConfigData.QV_MOCK_RANDOM_MAC_ADDR,
    ipType: ConfigData.QV_MOCK_IP_TYPE,
    staticIp: {
      ipAddress: ConfigData.QV_MOCK_STATIC_IP_ADDRESS,
      gateway: ConfigData.QV_MOCK_STATIC_GATEWAY,
      prefixLength: ConfigData.QV_MOCK_STATIC_PREFIX_LENGTH,
      dnsServers: [ConfigData.QV_MOCK_STATIC_DNS],
      domains: [ConfigData.QV_MOCK_DOMAIN_0, ConfigData.QV_MOCK_DOMAIN_1, ConfigData.QV_MOCK_DOMAIN_2]
    }
  }

  aboutToAppear() {

  }

  init() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', "QuickVerifyTest init-----------")
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
          Text($r('app.string.wifitest_text_yljdw'))
            .fontSize(ConfigData.VP_17)
            .height(ConfigData.VP_40)
            .width(ConfigData.WH_30_100)
            .align(Alignment.Start)

          TextInput({text: this.pairedSsidMQuick, placeholder: $r('app.string.wifitest_text_qzycsrwdpz')})
            .height(ConfigData.VP_40)
            .borderStyle(BorderStyle.Dashed)
            .backgroundColor($r("app.color.white"))
            .onChange((str) => {
              this.deviceId = str;
            })
            .width(ConfigData.WH_45_100)
            .padding({top: ConfigData.VP_5, left: ConfigData.VP_5})
          Image($r('app.media.Switch'))
            .height(ConfigData.VP_50)
            .padding({top: ConfigData.VP_5, bottom: ConfigData.VP_5, left: ConfigData.VP_10})
            .width(ConfigData.WH_15_100)
            .onClick(() => {
              this.showList = !this.showList;
            })
        }
      }
      .align(Alignment.Start)

      if (this.showList){
        QuickVerifyDeviceSetting()
      } else {
        Column() {
          Scroll() {
            Column() {
              Text() {
                Span($r('app.string.wifitest_text_quick_wlan_link'))
                Span(this.linkedInfoManagerMessageQuick)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_quick_ip'))
                Span(this.ipInfoManagerMessageQuick)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_quick_net_cfg'))
                Span(this.getDeviceConfigsManagerMessageQuick)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_quick_scan'))
                Span(this.getScanInfoManagerMessageQuick)
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
          testItem: this.testItem, apiItems: initNewWifiManagerApiData()
        })
      }
    }
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r("app.color.lead"))
    .height(ConfigData.WH_100_100)
  }
}