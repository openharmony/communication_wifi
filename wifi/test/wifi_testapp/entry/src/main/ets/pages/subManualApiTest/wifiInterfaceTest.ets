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
import { initWifiApiData} from '../../entryability/model/testDataModels';
import { TestData} from '../../entryability/model/testData';
import wifi from '@ohos.wifi';

interface myParams extends Object {
  testItem: TestData
}

const TAG = "wifiTestApp [Wifi]"

/**
 * wifi Test Page Of Wifi test
 */

@Component
struct WifiDeviceSetting {
  @StorageLink('w_ssid') w_ssid: string = ConfigData.QV_MOCK_SSID;//TP-LINK_6365
  @StorageLink('w_bssid') w_bssid: string = ConfigData.QV_MOCK_BSSID;//6C:B1:58:75:63:65
  @StorageLink('w_preSharedKey') w_preSharedKey: string = ConfigData.QV_MOCK_PRE_SHARED_KEY;//kaihong123
  @StorageLink('w_isHiddenSsid') w_isHiddenSsid: boolean = false;
  @StorageLink('w_securityType') w_securityType: number = ConfigData.QV_MOCK_SECURITY_TYPE
  @StorageLink('w_creatorUid') w_creatorUid: number = ConfigData.QV_MOCK_CREATOR_UID;
  @StorageLink('w_disableReason') w_disableReason: number = ConfigData.QV_MOCK_DISABLE_REASON;
  @StorageLink('w_netId') w_netId: number = ConfigData.QV_MOCK_NET_ID;
  @StorageLink('w_randomMacType') w_randomMacType: number = ConfigData.QV_MOCK_RANDOM_MAC_TYPE;
  @StorageLink('w_randomMacAddr') w_randomMacAddr: string = ConfigData.QV_MOCK_RANDOM_MAC_ADDR
  @StorageLink('w_ipType') w_ipType: number = ConfigData.QV_MOCK_IP_TYPE;
  @StorageLink('w_staticIp_ipAddress') w_staticIp_ipAddress: number = ConfigData.QV_MOCK_STATIC_IP_ADDRESS;
  @StorageLink('w_staticIp_gateway') w_staticIp_gateway: number = ConfigData.QV_MOCK_STATIC_GATEWAY;
  @StorageLink('w_staticIp_dnsServers') w_staticIp_dnsServers: number[] = [ConfigData.QV_MOCK_STATIC_DNS];
  @StorageLink('w_staticIp_domains') w_staticIp_domains: Array<string> = [ConfigData.QV_MOCK_DOMAIN_0, ConfigData.QV_MOCK_DOMAIN_1, ConfigData.QV_MOCK_DOMAIN_2];
  @StorageLink('w_networkId') w_networkId: number = ConfigData.SCENARIO_WM_NET_ID;// id,netId,networkId是一个值嘛？
  @StorageLink('w_featureId') w_featureId: number = ConfigData.WIFI_DEMO_FEATURE_ID;

  aboutToAppear() {
    let w_staticIp: wifi.IpConfig = {
      ipAddress: this.w_staticIp_ipAddress,
      gateway: this.w_staticIp_gateway,
      dnsServers: this.w_staticIp_dnsServers,
      domains: this.w_staticIp_domains
    }
    let wifiDeviceConfig: wifi.WifiDeviceConfig = {
      ssid: this.w_ssid,
      bssid: this.w_bssid,
      preSharedKey: this.w_preSharedKey,
      isHiddenSsid: this.w_isHiddenSsid,
      securityType: this.w_securityType,
      creatorUid: this.w_creatorUid,
      disableReason: this.w_disableReason,
      netId: this.w_netId,
      randomMacType: this.w_randomMacType,
      randomMacAddr: this.w_randomMacAddr,
      ipType: this.w_ipType,
      staticIp: w_staticIp
    }
    AppStorage.setOrCreate("wifiDeviceConfig", wifiDeviceConfig)
  }

  build() {
    Column() {
      Row() {
        Text($r('app.string.wifitest_text_s_1')).fontSize(ConfigData.VP_17).width(ConfigData.VP_70)
        TextInput({text: this.w_ssid, placeholder: $r('app.string.wifitest_text_tl6')})//TP-LINK_6365
          .fontSize(ConfigData.VP_15)
          .onChange((strInput: string) => {
            this.w_ssid = strInput;
            AppStorage.setOrCreate('w_ssid', this.w_ssid);
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
              Text($r('app.string.wifitest_text_b_2')).fontSize(ConfigData.VP_15).width(ConfigData.VP_60);
              TextInput({text: this.w_bssid, placeholder: $r('app.string.wifitest_text_6b5766')})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  this.w_bssid = strInput;
                  AppStorage.setOrCreate('w_bssid', this.w_bssid);
                })
                .width(ConfigData.WH_80_100)
                .borderRadius($r('app.float.wh_value_1'))
            }
            .padding(ConfigData.VP_3)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))

            Row() {
              Text($r('app.string.wifitest_text_p_2')).fontSize(ConfigData.VP_15).width(ConfigData.VP_110);
              TextInput({text: this.w_preSharedKey, placeholder: $r('app.string.wifitest_text_1_3')})//kaihong123
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  this.w_preSharedKey = strInput;
                  AppStorage.setOrCreate('w_preSharedKey', this.w_preSharedKey);
                })
                .width(ConfigData.WH_80_100)
                .borderRadius($r('app.float.wh_value_1'))
            }
            .backgroundColor($r("app.color.spring"))
            .padding(ConfigData.VP_5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text($r('app.string.wifitest_text_i_4')).fontSize(ConfigData.VP_15).width(ConfigData.VP_110);
              TextInput({text: String(this.w_isHiddenSsid), placeholder: "false"})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  this.w_isHiddenSsid = strInput === 'true'
                  //判断合法性
                  if (strInput.length >= 1){
                    AppStorage.setOrCreate('w_isHiddenSsid', this.w_isHiddenSsid);
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
              Text($r('app.string.wifitest_text_s_5')).fontSize(ConfigData.VP_15).width(ConfigData.value_100);
              Column() {
                Select([
                  { value: 'WIFI_SEC_TYPE_INVALID'},
                  { value: 'WIFI_SEC_TYPE_OPEN'},
                  { value: 'WIFI_SEC_TYPE_WEP'},
                  { value: 'WIFI_SEC_TYPE_PSK'},
                  { value: 'WIFI_SEC_TYPE_SAE'}
])
                  .selected(0)
                  .value('WIFI_SEC_TYPE_PSK')
                  .font({size: ConfigData.VP_17})
                  .selectedOptionFont({size: ConfigData.VP_17})
                  .optionFont({size: ConfigData.VP_15})
                  .width(ConfigData.WH_80_100)
                  .onSelect((index: number) => {
                    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "Select:" + index)
                    this.w_securityType = index;
                    AppStorage.setOrCreate('w_securityType', this.w_securityType);
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
              Text($r('app.string.wifitest_text_c_1')).fontSize(ConfigData.VP_15).width(ConfigData.VP_100);
              TextInput({text: this.w_creatorUid.toString(), placeholder: ConfigData.QV_MOCK_DOMAIN_1})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  this.w_creatorUid = Number(strInput);
                  //判断合法性
                  if (strInput.length >= 1){
                    AppStorage.setOrCreate('w_creatorUid', this.w_creatorUid);
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
              Text($r('app.string.wifitest_text_d_2')).fontSize(ConfigData.VP_15).width(ConfigData.VP_120);
              TextInput({text: this.w_disableReason.toString(), placeholder: ConfigData.QV_MOCK_DOMAIN_0})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  this.w_disableReason = Number(strInput);
                  //判断合法性
                  if (strInput.length >= 1){
                    AppStorage.setOrCreate('w_disableReason', this.w_disableReason);
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
              Text($r('app.string.wifitest_text_n')).fontSize(ConfigData.VP_15).width(ConfigData.VP_60);
              TextInput({text: this.w_netId.toString(), placeholder: $r('app.string.wifitest_text_1')})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  this.w_netId = Number(strInput);
                  //判断合法性
                  if (strInput.length >= 1){
                    AppStorage.setOrCreate('w_netId', this.w_netId);
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
              Text($r('app.string.wifitest_text_r_1')).fontSize(ConfigData.VP_15).width(ConfigData.VP_140);
              TextInput({text: this.w_randomMacType.toString(), placeholder: ConfigData.QV_MOCK_DOMAIN_0})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  this.w_randomMacType = Number(strInput);
                  //判断合法性
                  if (strInput.length >= 1){
                    AppStorage.setOrCreate('w_randomMacType', this.w_randomMacType);
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
              Text($r('app.string.wifitest_text_r')).fontSize(ConfigData.VP_15).width(ConfigData.VP_140);
              TextInput({text: this.w_randomMacAddr, placeholder: $r('app.string.wifitest_text_0fe13a')})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  this.w_randomMacAddr = strInput;
                  //判断合法性
                  if (strInput.length >= 1){
                    AppStorage.setOrCreate('w_randomMacAddr', this.w_randomMacAddr);
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
              Text($r('app.string.wifitest_text_i')).fontSize(ConfigData.VP_15).width(ConfigData.VP_60);
              TextInput({text: this.w_ipType.toString(), placeholder: ConfigData.QV_MOCK_DOMAIN_1})//DHCP
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  this.w_ipType = Number(strInput);
                  if (strInput.length >= 1){
                    AppStorage.setOrCreate('w_ipType', this.w_ipType);
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
              Text($r('app.string.wifitest_text_si_1')).fontSize(ConfigData.VP_15).width(ConfigData.VP_135);
              TextInput({text: this.w_staticIp_ipAddress.toString(), placeholder: $r('app.string.wifitest_text_3_2')})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  this.w_staticIp_ipAddress = Number(strInput);
                  if (strInput.length >= 1){
                    AppStorage.setOrCreate('w_staticIp_ipAddress', this.w_staticIp_ipAddress);
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
              Text($r('app.string.wifitest_text_sg')).fontSize(ConfigData.VP_15).width(ConfigData.VP_130);
              TextInput({text: this.w_staticIp_gateway.toString(), placeholder: $r('app.string.wifitest_text_3_1')})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  this.w_staticIp_gateway = Number(strInput);
                  if (strInput.length >= 1){
                    AppStorage.setOrCreate('w_staticIp_gateway', this.w_staticIp_gateway);
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
              Text($r('app.string.wifitest_text_sd_3')).fontSize(ConfigData.VP_15).width(ConfigData.VP_140);
              TextInput({text: this.w_staticIp_dnsServers.join(', '), placeholder: $r('app.string.wifitest_text_3_3')})
                .fontSize(ConfigData.VP_15)
                .onChange((strInput: string) => {
                  //判断合法性
                  if (strInput.length >= 1){
                    const dnsServersArray = strInput.split(',')
                      .map(s => parseInt(s.trim(), 10))
                      .filter(n => !isNaN(n));
                    // 确保转换结果是一个数字数组
                    if (dnsServersArray.length){
                      this.w_staticIp_dnsServers = dnsServersArray;
                    } else {
                      // 处理输入不包含有效数字的情况
                      hilog.error(0x1500, 'wifiTestApp', '%{public}s', 'Invalid input for DNS servers');
                    }
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
              Text($r('app.string.wifitest_text_sd')).fontSize(ConfigData.VP_15).width(ConfigData.VP_125);
              TextInput({
                text: this.w_staticIp_domains.join(', '),// 将数组转换成以逗号分隔的字符串
                placeholder: $r('app.string.wifitest_text_012')
              })
              .fontSize(ConfigData.VP_15)
              .onChange((strInput: string) => {
                  // 将输入的字符串按逗号分隔转换回数组
                  this.w_staticIp_domains = strInput.split(',').map(item => item.trim());
                  if (strInput.length >= 1){
                    AppStorage.setOrCreate('w_staticIp_domains', this.w_staticIp_domains);
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
struct WifiInterfaceTest {
  @State showList: boolean = false;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State message: string = "";
  @State deviceId: string = '';
  @State currentClick: number = ConfigData.ITEM_CLICK_NONE;
  @StorageLink('pairedSsid') pairedSsid: string = "";
  @State w_ssid: string = ConfigData.QV_MOCK_SSID;//TP-LINK_6365
  @State w_bssid: string = ConfigData.QV_MOCK_BSSID;//6C:B1:58:75:63:65
  @State w_preSharedKey: string = ConfigData.QV_MOCK_PRE_SHARED_KEY;//kaihong123
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
  @StorageLink('linkedInfoMessage') linkedInfoMessage: string = '';
  @StorageLink('ipInfoMessage') ipInfoMessage: string = '';
  @StorageLink('getDeviceConfigsMessage') getDeviceConfigsMessage: string = '';
  @StorageLink('getScanInfoMessage') getScanInfoMessage: string = '';

  aboutToAppear() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, "this.testItem:" + JSON.stringify(this.testItem))
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

          TextInput({text: this.pairedSsid, placeholder: $r('app.string.wifitest_text_qzycsrwdpz')})
            .height(ConfigData.VP_40)
            .borderStyle(BorderStyle.Dashed)
            .backgroundColor($r("app.color.white"))
            .onChange((str) => {
              this.deviceId = str;
            })
            .width(ConfigData.WH_50_100)
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
        WifiDeviceSetting()
      } else {
        Column() {
          Scroll() {
            Column() {
              Text() {
                Span($r('app.string.wifitest_text_quick_wlan_link'))
                Span(this.linkedInfoMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_quick_ip'))
                Span(this.ipInfoMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_quick_net_cfg'))
                Span(this.getDeviceConfigsMessage)
              }
                .fontSize(ConfigData.VP_17)
                .margin({top: ConfigData.VP_5, left: ConfigData.VP_10})
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text() {
                Span($r('app.string.wifitest_text_quick_scan'))
                Span(this.getScanInfoMessage)
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
          testItem: this.testItem, apiItems: initWifiApiData()
        })
      }
    }
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r("app.color.lead"))
    .height(ConfigData.WH_100_100)
  }
}