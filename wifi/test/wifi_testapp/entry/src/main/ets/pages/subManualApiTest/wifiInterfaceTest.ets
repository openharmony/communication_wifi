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

// @ts-nocheck

/**
 * wifi Test Page Of Wifi test
 */
import { PageTitle } from '../../Component/pageTitle';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { ContentTable } from '../../Component/contentTable';
import Router from '@system.router';
import ConfigData from '../../Utils/ConfigData';
import LogUtil from '../../Utils/LogUtil';
import { initWiFiApiData } from '../../MainAbility/model/testDataModels'
import { TestData } from '../../MainAbility/model/testData'
const G_NAME = 'DaYu200'

@Component
struct WifiDeviceSetting {
  private ssid = "TP-LINK_6365";
  private bssid = "6C:B1:58:75:63:65";
  private preSharedKey = "kaihong123";
  private isHiddenSsid = "false";
  @State securityType: number = 3
  @State creatorUid: string = "1";
  @State disableReason: number = 0;
  @State netId: number = 0 ;
  @State randomMacType: number = 0 ;
  @State randomMacAddr: string ="08:fb:ea:1b:38:aa"
  @State ipType: number = 1 ;

  @State staticIp_ipAddress: number = 3232235880 ;
  @State staticIp_gateway: number = 3232235777 ;
  @State staticIp_dnsServers: number = 3716386629 ;
  @State staticIp_domains: Array<string> = ["0","1","2"] ;

  aboutToAppear() {
    AppStorage.SetOrCreate('ssid', this.ssid);
    AppStorage.SetOrCreate('bssid', this.bssid);
    AppStorage.SetOrCreate('preSharedKey', this.preSharedKey);
    AppStorage.SetOrCreate('isHiddenSsid', this.isHiddenSsid);
    AppStorage.SetOrCreate('securityType', this.securityType);
    AppStorage.SetOrCreate('creatorUid', this.creatorUid);
    AppStorage.SetOrCreate('disableReason', this.disableReason);
    AppStorage.SetOrCreate('netId', this.netId);
    AppStorage.SetOrCreate('randomMacType', this.randomMacType);
    AppStorage.SetOrCreate('randomMacAddr', this.randomMacAddr);
    AppStorage.SetOrCreate('ipType', this.ipType);
    AppStorage.SetOrCreate('staticIp_ipAddress', this.staticIp_ipAddress);
    AppStorage.SetOrCreate('staticIp_gateway', this.staticIp_gateway);
    AppStorage.SetOrCreate('staticIp_dnsServers', this.staticIp_dnsServers);
    AppStorage.SetOrCreate('staticIp_domains', this.staticIp_domains);
  }

  build() {
    Column() {
      Row() {
        Text("ssid:").fontSize("17vp").width(70)
        TextInput({ text: this.ssid, placeholder: "TP-LINK_6365" })
          .fontSize("15vp")
          .onChange((strInput) => {
            this.ssid = strInput;
            AppStorage.SetOrCreate('ssid', strInput);
          })
          .width("80%")
          .borderRadius(1)
      }
      .backgroundColor($r("app.color.moon"))
      .padding(5)
      .justifyContent(FlexAlign.Start)
      .alignItems(VerticalAlign.Center)

      Scroll() {
        Column() {
          Stack().height("0.25vp").backgroundColor("#000000");
          Column() {
            Row() {
              Text("bssid:").fontSize("15vp").width(60);
              TextInput({ text: this.bssid, placeholder: "6c:b1:58:75:63:67" })
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.bssid = strInput;
                  AppStorage.SetOrCreate('bssid', strInput);
                })
                .width("80%")
                .borderRadius(1)
            }
            .padding(3)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))

            Row() {
              Text("preSharedKey:").fontSize("15vp").width(110);
              TextInput({ text: this.preSharedKey, placeholder: "kaihong123" })
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.preSharedKey = strInput;
                  AppStorage.SetOrCreate('preSharedKey', strInput);
                })
                .width("80%")
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("isHiddenSsid:").fontSize(15).width(110);
              TextInput({ text: this.isHiddenSsid, placeholder: "false" })
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.isHiddenSsid = strInput;
                  //判断合法性
                  if (strInput.length >= 1) {
                    AppStorage.SetOrCreate('isHiddenSsid', strInput);
                  }
                })
                .width("80%")
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("securityType:").fontSize(15).width(100);
              Column() {
                Select([
                  {value:'WIFI_SEC_TYPE_INVALID'},
                  {value:'WIFI_SEC_TYPE_OPEN'},
                  {value:'WIFI_SEC_TYPE_WEP'},
                  {value:'WIFI_SEC_TYPE_PSK'},
                  {value:'WIFI_SEC_TYPE_SAE'}
                ])
                  .selected(3)
                  .value('WIFI_SEC_TYPE_PSK')
                  .font({size: 17})
                  .selectedOptionFont({size: 17})
                  .optionFont({size: 15})
                  .width("80%")
                  .onSelect((index:number)=>{
                    console.info("Select:" + index)
                    this.securityType = index;
                    AppStorage.SetOrCreate('securityType', index);
                  })
              }
              .width("80%")
              .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("creatorUid:").fontSize(15).width(100);
              TextInput({ text: this.creatorUid, placeholder: "1" })
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.creatorUid = strInput;
                  //判断合法性
                  if (strInput.length >= 1) {
                    AppStorage.SetOrCreate('creatorUid', strInput);
                  }
                })
                .width("80%")
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("disableReason:").fontSize(15).width(120);
              TextInput({ text: this.disableReason, placeholder: "0" })
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.disableReason = strInput;
                  //判断合法性
                  if (strInput.length >= 1) {
                    AppStorage.SetOrCreate('disableReason', strInput);
                  }
                })
                .width("80%")
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("netId:").fontSize(15).width(60);
              TextInput({ text: this.netId, placeholder: "0" })
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.netId = strInput;
                  //判断合法性
                  if (strInput.length >= 1) {
                    AppStorage.SetOrCreate('netId', strInput);
                  }
                })
                .width("80%")
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("randomMacType:").fontSize(15).width(140);
              TextInput({ text: this.randomMacType, placeholder: "0" })
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.randomMacType = strInput;
                  if (strInput.length >= 1) {
                    AppStorage.SetOrCreate('randomMacType', strInput);
                  }
                })
                .width("80%")
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("randomMacAddr:").fontSize(15).width(140);
              TextInput({ text: this.randomMacAddr, placeholder: "08:fb:ea:1b:38:aa" })
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.randomMacAddr = strInput;
                  if (strInput.length >= 1) {
                    AppStorage.SetOrCreate('randomMacAddr', strInput);
                  }
                })
                .width("80%")
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("ipType:").fontSize(15).width(60);
              TextInput({ text: this.descriptorUUID, placeholder: "1"  }) //DHCP
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.ipType = strInput;
                  if (strInput.length >= 1) {
                    AppStorage.SetOrCreate('ipType', strInput);
                  }
                })
                .width("80%")
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("staticIp_ipAddress:").fontSize(15).width(135);
              TextInput({ text: this.descriptorUUID, placeholder: "3232235880" })
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.staticIp_ipAddress = strInput;
                  if (strInput.length >= 1) {
                    AppStorage.SetOrCreate('staticIp_ipAddress', strInput);
                  }
                })
                .width("80%")
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.moon"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("staticIp_gateway:").fontSize(15).width(130);
              TextInput({ text: this.descriptorUUID, placeholder: "3232235777" })
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.staticIp_gateway = strInput;
                  if (strInput.length >= 1) {
                    AppStorage.SetOrCreate('staticIp_gateway', strInput);
                  }
                })
                .width("80%")
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.moon"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("staticIp_dnsServers:").fontSize(15).width(140);
              TextInput({ text: this.descriptorUUID, placeholder: "3716386629"})
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.staticIp_dnsServers = strInput;
                  if (strInput.length >= 1) {
                    AppStorage.SetOrCreate('staticIp_dnsServers', strInput);
                  }
                })
                .width("80%")
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.moon"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("staticIp_domains:").fontSize(15).width(125);
              TextInput({ text: this.descriptorUUID, placeholder: ["0","1","2"] })
                .fontSize("15vp")
                .onChange((strInput) => {
                  this.staticIp_domains = strInput;
                  if (strInput.length >= 1) {
                    AppStorage.SetOrCreate('staticIp_domains', strInput);
                  }
                })
                .width("80%")
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.moon"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
          }
          Stack().height("0.25vp").backgroundColor("#000000");
        }
      }
      .scrollBarWidth(10)
      .scrollBar(BarState.On)
    }
    .height("58%")
  }
}


@Entry
@Component
struct Index {
  @State showList: boolean = false;
  private testItem: TestData = Router.getParams().testId;
  @State message: string = "";
  @StorageLink('setLocalNameRet') setLocalNameRet: boolean = false;
  @StorageLink('setScanModeRet') setScanModeRet: boolean = false;
  @State deviceId: string = '';
  @State currentClick: number = -1;
  @StorageLink('pairedMac') pairedMac: string = "32:32:235:878";
  private ssid = "TP-LINK_6365";
  private bssid = "6C:B1:58:75:63:65";
  private preSharedKey = "kaihong123";
  private isHiddenSsid = false;
  @State securityType: number = 3
  @State creatorUid: number = 1;
  @State disableReason: number = 0;
  @State netId: number = 0 ;
  @State randomMacType: number = 0 ;
  @State randomMacAddr: string ="08:fb:ea:1b:38:aa"
  @State ipType: number = 1 ;
  @State staticIp_ipAddress: number = 3232235880 ;
  @State staticIp_gateway: number = 3232235777 ;
  @State staticIp_dnsServers: number = 3716386629 ;
  @State staticIp_domains: Array<string> =["0","1","2"] ;

  @StorageLink('linkedInfoMessage') linkedInfoMessage: string = '';
  @StorageLink('ipInfoMessage') ipInfoMessage: string = '';
  @StorageLink('getDeviceConfigsMessage') getDeviceConfigsMessage: string = '';
  @StorageLink('getScanInfoMessage') getScanInfoMessage: string = '';


  aboutToAppear() {
    AppStorage.SetOrCreate('ssid', this.ssid);
    AppStorage.SetOrCreate('bssid', this.bssid);
    AppStorage.SetOrCreate('preSharedKey', this.preSharedKey);
    AppStorage.SetOrCreate('isHiddenSsid', this.isHiddenSsid);
    AppStorage.SetOrCreate('securityType', this.securityType);
    AppStorage.SetOrCreate('creatorUid', this.creatorUid);
    AppStorage.SetOrCreate('disableReason', this.disableReason);
    AppStorage.SetOrCreate('netId', this.netId);
    AppStorage.SetOrCreate('randomMacType', this.randomMacType);
    AppStorage.SetOrCreate('randomMacAddr', this.randomMacAddr);
    AppStorage.SetOrCreate('ipType', this.ipType);
    AppStorage.SetOrCreate('staticIp_ipAddress', this.staticIp_ipAddress);
    AppStorage.SetOrCreate('staticIp_gateway', this.staticIp_gateway);
    AppStorage.SetOrCreate('staticIp_dnsServers', this.staticIp_dnsServers);
    AppStorage.SetOrCreate('staticIp_domains', this.staticIp_domains);
  }

  init() {
    console.log("init-----------")
  }

  build() {
    Column() {
      Stack({ alignContent: Alignment.TopStart }) {
        TestImageDisplay({ testItem: this.testItem })
        PageTitle({ testItem: this.testItem })
      }

      Stack().height("0.5vp").backgroundColor("#000000");
      Column() {
        Row() {
          Text("目标设备IP：")
            .fontSize("20vp")
            .height(40)
            .padding({ top: 5})
            .width("28%")
            .align(Alignment.Start)

          TextInput({ text: this.pairedMac, placeholder: "请输入即将连接的设备MAC" })
            .height(40)
            .borderStyle(BorderStyle.Dashed)
            .backgroundColor($r("app.color.white"))
            .onChange((str) => {
              this.deviceId = str;
            })
            .width("45%")
            .padding({ top: 5, left: 5 })
          Image($r('app.media.Switch'))
            .height(50)
            .padding({ top: 5, bottom: 5, left: 10 })
            .width('15%')
            .onClick(() => {
              this.showList = !this.showList;
            })
        }
      }
      .align(Alignment.Start)

      if (this.showList) {
        WifiDeviceSetting()
      } else {
        Column() {
          Scroll(){
            Column(){
//              Text("当前配置:")
//                .fontSize("17vp")
//                .margin({ top: "5vp", left: "10vp" })
//                .textAlign(TextAlign.Start)
//                .width("100%")
              Text("WLAN连接信息:" + this.linkedInfoMessage)
                .fontSize("17vp")
                .margin({ top: "5vp", left: "15vp" })
                .textAlign(TextAlign.Start)
                .width("90%")
              Text("IP信息:" + this.ipInfoMessage)
                .fontSize("17vp")
                .margin({ top: "5vp", left: "15vp" })
                .textAlign(TextAlign.Start)
                .width("90%")
              Text("获取网络配置:" + this.getDeviceConfigsMessage)
                .fontSize("17vp")
                .margin({ top: "5vp", left: "15vp"  })
                .textAlign(TextAlign.Start)
                .width("90%")
              Text("扫描结果:" + this.getScanInfoMessage)
                .fontSize("17vp")
                .margin({ top: "5vp", left: "15vp" })
                .textAlign(TextAlign.Start)
                .width("90%")
            }
            .width("100%")
          }
          .scrollBarWidth(10)
          .scrollBar(BarState.Auto)
        }
        .height(100)
        .width("95%")
        .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))

        ContentTable({ testItem: this.testItem, apiItems: initWiFiApiData() })
      }
    }
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r("app.color.lead"))
    .height("100%")
  }
}
