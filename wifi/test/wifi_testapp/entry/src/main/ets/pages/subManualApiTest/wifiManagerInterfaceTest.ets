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
import { initWifiManagerApiData} from '../../entryability/model/testDataModels';
import { TestData} from '../../entryability/model/testData';
import wifiManager from '@ohos.wifiManager';

interface myParams extends Object {
  testItem: TestData
}

const TAG = 'wifiTestApp [WifiManager]'

/**
 * wifiManager Test Page Of Wifi test
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
struct WifiManagerDeviceSetting {
  @StorageLink('isAllowed') isAllowed: number = 1;
  @StorageLink('w_networkIdM') w_networkIdM: number = 0;// id,netId,networkId是一个值嘛？
  @StorageLink('w_featureIdM') w_featureIdM: number = 1;
  @StorageLink('wifiDeviceConfigManager') wifiDeviceConfigManager: wifiManager.WifiDeviceConfig = {
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
      domains: [ConfigData.QV_MOCK_DOMAIN_0, ConfigData.QV_MOCK_DOMAIN_1, ConfigData.QV_MOCK_DOMAIN_2],
    }
  }

  aboutToAppear() {
  }

  build() {
    Column() {
      Row() {
        Text($r('app.string.wifitest_text_s_8')).fontSize(ConfigData.VP_17).width(ConfigData.VP_200)
        TextInput({text: this.isAllowed.toString(), placeholder: ConfigData.QV_MOCK_DOMAIN_1})
          .fontSize(ConfigData.VP_15)
          .onChange((strInput: string) => {
            //判断合法性
            if (strInput.length >= 1){
              this.isAllowed = Number(strInput);
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
        TextInput({text: this.wifiDeviceConfigManager.ssid, placeholder: $r('app.string.wifitest_text_tl6')})
          .fontSize(ConfigData.VP_15)
          .onChange((strInput: string) => {
            //判断合法性
            if (strInput.length >= 1){
              this.wifiDeviceConfigManager.ssid = strInput;
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
              TextInput({text: this.wifiDeviceConfigManager.bssid, placeholder: $r('app.string.wifitest_text_6b5766')})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  //判断合法性
                  if (strInput.length >= 1){
                    this.wifiDeviceConfigManager!.bssid = strInput;
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
              TextInput({text: this.wifiDeviceConfigManager.preSharedKey, placeholder: $r('app.string.wifitest_text_1_3')})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  //判断合法性
                  if (strInput.length >= 1){
                    this.wifiDeviceConfigManager!.preSharedKey = strInput;
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
              Text($r('app.string.wifitest_text_i_6')).fontSize(ConfigData.VP_15).width(ConfigData.VP_110);
              TextInput({text: String(this.wifiDeviceConfigManager.isHiddenSsid), placeholder: "false"})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  //判断合法性
                  if (strInput.length >= 1){
                    this.wifiDeviceConfigManager!.isHiddenSsid = strInput === 'true';
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
                    this.wifiDeviceConfigManager!.securityType = index;
                  })
              }
              .width(ConfigData.WH_80_100)
              .borderRadius($r('app.float.wh_value_1'))
            }
            .backgroundColor($r("app.color.spring"))
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text($r('app.string.wifitest_text_c_3')).fontSize(ConfigData.VP_15).width(ConfigData.VP_100);
              TextInput({text: this.wifiDeviceConfigManager?.creatorUid?.toString() ?? "", placeholder: ConfigData.QV_MOCK_DOMAIN_1})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  //判断合法性
                  if (strInput.length >= 1){
                    this.wifiDeviceConfigManager!.creatorUid = Number(strInput);
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
              Text($r('app.string.wifitest_text_d_5')).fontSize(ConfigData.VP_15).width(ConfigData.VP_120);
              TextInput({text: this.wifiDeviceConfigManager?.disableReason?.toString() ?? "", placeholder: ConfigData.QV_MOCK_DOMAIN_0})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  //判断合法性
                  if (strInput.length >= 1){
                    this.wifiDeviceConfigManager!.disableReason = Number(strInput);
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
              Text($r('app.string.wifitest_text_n_2')).fontSize(ConfigData.VP_15).width(ConfigData.VP_60);
              TextInput({text: this.wifiDeviceConfigManager?.netId?.toString() ?? "", placeholder: ConfigData.QV_MOCK_DOMAIN_1})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  //判断合法性
                  if (strInput.length >= 1){
                    this.wifiDeviceConfigManager!.netId = Number(strInput);
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
              Text($r('app.string.wifitest_text_r_5')).fontSize(ConfigData.VP_15).width(ConfigData.VP_140);
              TextInput({text: this.wifiDeviceConfigManager?.randomMacType?.toString() ?? "", placeholder: ConfigData.QV_MOCK_DOMAIN_0})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  //判断合法性
                  if (strInput.length >= 1){
                    this.wifiDeviceConfigManager!.randomMacType = Number(strInput);
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
              Text($r('app.string.wifitest_text_r_3')).fontSize(ConfigData.VP_15).width(ConfigData.VP_140);
              TextInput({text: this.wifiDeviceConfigManager.randomMacAddr, placeholder: $r('app.string.wifitest_text_0fe13a')})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  //判断合法性
                  if (strInput.length >= 1){
                    this.wifiDeviceConfigManager!.randomMacAddr = strInput;
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
              Text($r('app.string.wifitest_text_i_2')).fontSize(ConfigData.VP_15).width(ConfigData.VP_60);
              TextInput({text: this.wifiDeviceConfigManager?.ipType?.toString() ?? '', placeholder: ConfigData.QV_MOCK_DOMAIN_1})//DHCP
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  //判断合法性
                  if (strInput.length >= 1){
                    this.wifiDeviceConfigManager!.ipType = Number(strInput);
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
              Text($r('app.string.wifitest_text_si_3')).fontSize(ConfigData.VP_15).width(ConfigData.VP_135);
              TextInput({
                text: this.wifiDeviceConfigManager?.staticIp?.ipAddress?.toString() ?? '',
                placeholder: $r('app.string.wifitest_text_3_2')
              })
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                  //判断合法性
                  if (strInput.length >= 1){
                    this.wifiDeviceConfigManager!.staticIp!.ipAddress = Number(strInput);
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius($r('app.float.wh_value_1'))
            }
            .backgroundColor($r("app.color.moon"))
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text($r('app.string.wifitest_text_sg_2')).fontSize(ConfigData.VP_15).width(ConfigData.VP_130);
              TextInput({
                text: this.wifiDeviceConfigManager?.staticIp?.gateway?.toString() ?? '',
                placeholder: $r('app.string.wifitest_text_3_1')
              })
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                  //判断合法性
                  if (strInput.length >= 1){
                    this.wifiDeviceConfigManager!.staticIp!.gateway = Number(strInput);
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius($r('app.float.wh_value_1'))
            }
            .backgroundColor($r("app.color.moon"))
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text($r('app.string.wifitest_text_sd_5')).fontSize(ConfigData.VP_15).width(ConfigData.VP_140);
              TextInput({
                text: this.wifiDeviceConfigManager?.staticIp?.dnsServers?.join(', ') ?? '',
                placeholder: $r('app.string.wifitest_text_3_3')
              })
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                  const dnsServersArray = strInput.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n));
                  //判断合法性
                  if (dnsServersArray.length){
                    this.wifiDeviceConfigManager!.staticIp!.dnsServers = dnsServersArray;
                  } else {
                    // 处理输入不包含有效数字的情况
                    hilog.error(0x1500, 'wifiTestApp', '%{public}s', 'Invalid input for DNS servers');
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius($r('app.float.wh_value_1'))
            }
            .backgroundColor($r("app.color.moon"))
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text($r('app.string.wifitest_text_sd_2')).fontSize(ConfigData.VP_15).width(ConfigData.VP_125);
              TextInput({
                text: this.wifiDeviceConfigManager?.staticIp?.domains?.join(', ') ?? '',// 将数组转换成以逗号分隔的字符串
                placeholder: $r('app.string.wifitest_text_012')
              })
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                  // 将输入的字符串按逗号分隔转换回数组
                  if (strInput.length >= 1){
                    this.wifiDeviceConfigManager!.staticIp!.domains = strInput.split(',').map(item => item.trim());
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius($r('app.float.wh_value_1'))
            }
            .backgroundColor($r("app.color.moon"))
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
struct WifiManagerInterfaceTest {
  @State showList: boolean = false;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State message: string = "";
  @State deviceId: string = '';
  @State currentClick: number = ConfigData.ITEM_CLICK_NONE;
  @StorageLink('isAllowed') isAllowed: number = 1;
  @StorageLink('pairedSsidM') pairedSsidM: string = "";
  @StorageLink('w_networkIdM') w_networkIdM: number = 0;
  @StorageLink('w_featureIdM') w_featureIdM: number = 1;
  @StorageLink('ipInfoManagerMessage') ipInfoManagerMessage: string = '';
  @StorageLink('linkedInfoManagerMessage') linkedInfoManagerMessage: string = '';
  @StorageLink('getDeviceConfigsManagerMessage') getDeviceConfigsManagerMessage: string = '';
  @StorageLink('getScanInfoManagerMessage') getScanInfoManagerMessage: string = '';
  @StorageLink('wifiDeviceConfigManager') wifiDeviceConfigManager: wifiManager.WifiDeviceConfig = {
    ssid: ConfigData.QV_MOCK_SSID,
    bssid: ConfigData.QV_MOCK_BSSID,
    preSharedKey: ConfigData.QV_MOCK_PRE_SHARED_KEY,
    isHiddenSsid: false,
    securityType: 3,
    creatorUid: 1,
    disableReason: 0,
    netId: 100,
    randomMacType: 0,
    randomMacAddr: ConfigData.QV_MOCK_RANDOM_MAC_ADDR,
    ipType: 1,
    staticIp: {
      ipAddress: ConfigData.QV_MOCK_STATIC_IP_ADDRESS,
      gateway: ConfigData.QV_MOCK_STATIC_GATEWAY,
      prefixLength: ConfigData.QV_MOCK_STATIC_PREFIX_LENGTH,
      dnsServers: [ConfigData.QV_MOCK_STATIC_DNS],
      domains: [ConfigData.QV_MOCK_DOMAIN_0, ConfigData.QV_MOCK_DOMAIN_1, ConfigData.QV_MOCK_DOMAIN_2],
    }
  }

  aboutToAppear() {

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
          Text($r('app.string.wifitest_text_yljdw'))
            .fontSize(ConfigData.VP_17)
            .height(ConfigData.VP_40)
            .width(ConfigData.WH_30_100)
            .align(Alignment.Start)

          TextInput({text: this.pairedSsidM, placeholder: $r('app.string.wifitest_text_qzycsrwdpz')})
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
        WifiManagerDeviceSetting()
      } else {
        Column() {
          Scroll() {
            Column() {
              Text() {
                Span($r('app.string.wifitest_text_quick_wlan_link'))
                Span(this.linkedInfoManagerMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_quick_ip'))
                Span(this.ipInfoManagerMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_quick_net_cfg'))
                Span(this.getDeviceConfigsManagerMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_quick_scan'))
                Span(this.getScanInfoManagerMessage)
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
          testItem: this.testItem, apiItems: initWifiManagerApiData()
        })
      }
    }
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r("app.color.lead"))
    .height(ConfigData.WH_100_100)
  }
}