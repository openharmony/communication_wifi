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

import { PageTitle } from '../../Component/pageTitle';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { StressContentTable } from '../../Component/stressContentTable';
import router from '@ohos.router';
import ConfigData from '../../utils/ConfigData';
import { initWifiStressData } from '../../entryability/model/stressTestDataModels'
import { TestData } from '../../entryability/model/testData'
import wifi from '@ohos.wifi';
import { resolveIP } from '../../utils/Util'
import socket from '@ohos.net.socket';
import http from '@ohos.net.http'
import request from '@ohos.request'
import common from '@ohos.app.ability.common';
import abilityAccessCtrl , { Context , PermissionRequestResult } from '@ohos.abilityAccessCtrl';
import { BusinessError } from '@ohos.base';

const TAG = '[Stress]'

interface DownloadConfig {
  url: string,
  filePath: string
}

interface LocalAddr {
  address: string,
  family: number,
  port: number
}

interface OppositeAddr {
  address: string,
  family: number,
  port: number
}

interface myParams extends Object {
  testItem: TestData
}

let localAddr: LocalAddr = {
  address : resolveIP(wifi.getIpInfo().ipAddress) ,
  family : 1 ,
  port : 9090
}
let oppositeAddr: OppositeAddr = {
  address : '' ,
  family : 1 ,
  port : 0
}
let loginCount = 0

let udp = socket.constructUDPSocketInstance()

/**
 * wifi StressTest Page Of Wifi test
 */

@Entry
@Component
struct WifiStressTest {
  @State showList: boolean = false;
  @State showListItems: boolean = false;
  @State showListItem: boolean = false;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State message: string = "";
  @State deviceId: string = '';
  @State currentClick: number = - 1;
  @StorageLink('pairedMac') pairedMac: string = "";
  @State w_ssid: string = "TP-LINK_6365";
  @State w_bssid: string = "6C:B1:58:75:63:65";
  @State w_preSharedKey: string = "12345678";
  @State w_isHiddenSsid: boolean = false;
  @State w_securityType: number = 3
  @State w_creatorUid: number = 1;
  @State w_disableReason: number = 0;
  @State w_netId: number = 100;
  @State w_randomMacType: number = 0;
  @State w_randomMacAddr: string = "08:fb:ea:1b:38:aa"
  @State w_ipType: number = 1;
  @State w_staticIp_ipAddress: number = 3232235880;
  @State w_staticIp_gateway: number = 3232235777;
  @State w_staticIp_dnsServers: number = 3716386629;
  @State w_staticIp_domains: Array<string> = [ "0", "1", "2" ];
  @State w_networkId: number = 0; // id,netId,networkId是一个值嘛？
  @State w_featureId: number = 1;
  @StorageLink('stressNumber') stressNumber: number = 0;
  @StorageLink('stressTime') stressTime: number = 0;
  //  @StorageLink('getDeviceConfigsMessage') getDeviceConfigsMessage: string = '';
  //  @StorageLink('getScanInfoMessage') getScanInfoMessage: string = '';

  aboutToAppear() {
    AppStorage.setOrCreate('w_ssid' , this.w_ssid);
    AppStorage.setOrCreate('w_bssid' , this.w_bssid);
    AppStorage.setOrCreate('w_preSharedKey' , this.w_preSharedKey);
    AppStorage.setOrCreate('w_isHiddenSsid' , this.w_isHiddenSsid);
    AppStorage.setOrCreate('w_securityType' , this.w_securityType);
    AppStorage.setOrCreate('w_creatorUid' , this.w_creatorUid);
    AppStorage.setOrCreate('w_disableReason' , this.w_disableReason);
    AppStorage.setOrCreate('w_netId' , this.w_netId);
    AppStorage.setOrCreate('w_randomMacType' , this.w_randomMacType);
    AppStorage.setOrCreate('w_randomMacAddr' , this.w_randomMacAddr);
    AppStorage.setOrCreate('w_ipType' , this.w_ipType);
    AppStorage.setOrCreate('w_staticIp_ipAddress' , this.w_staticIp_ipAddress);
    AppStorage.setOrCreate('w_staticIp_gateway' , this.w_staticIp_gateway);
    AppStorage.setOrCreate('w_staticIp_dnsServers' , this.w_staticIp_dnsServers);
    AppStorage.setOrCreate('w_staticIp_domains' , this.w_staticIp_domains);
    AppStorage.setOrCreate('w_networkId' , this.w_networkId);
    AppStorage.setOrCreate('w_featureId' , this.w_featureId);
  }

  init() {
    console.log("init-----------")
  }

  build() {
    Column() {
      Stack({ alignContent : Alignment.TopStart }) {
        TestImageDisplay({ testItem : this.testItem })
        PageTitle({ testItem : this.testItem })
      }

      Stack().height("0.5vp").backgroundColor("#000000");
      Column() {
        Row() {
          Text("目标设备IP：")
            .fontSize("20vp")
            .height(40)
            .padding({ top : 5 })
            .width(ConfigData.WH_28_100)
            .align(Alignment.Start)

          TextInput({ text : this.pairedMac , placeholder : "请输入即将连接的设备MAC" })
            .height(40)
            .borderStyle(BorderStyle.Dashed)
            .backgroundColor($r("app.color.white"))
            .onChange((str) => {
              this.deviceId = str;
            })
            .width(ConfigData.WH_45_100)
            .padding({ top : 5 , left : 5 })
          Image($r('app.media.Switch'))
            .height(50)
            .padding({ top : 5 , bottom : 5 , left : 10 })
            .width(ConfigData.WH_15_100)
            .onClick(() => {
              this.showList = !this.showList;
            })
        }
      }
      .align(Alignment.Start)

      if ( this.showList ) {
        WifiDeviceSetting()
      } else {
        Column() {
          Scroll() {
            Column() {
              Text("stress测试：")
                .fontSize("17vp")
                .margin({ top : "5vp" , left : "15vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_100_100)
              Text("stress测试次数:" + this.stressNumber)
                .fontSize("17vp")
                .margin({ top : "5vp" , left : "15vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Text("stress测试时间：" + this.stressTime + "ms")
                .fontSize("17vp")
                .margin({ top : "5vp" , left : "15vp" })
                .textAlign(TextAlign.Start)
                .width(ConfigData.WH_90_100)
              Flex({ alignItems : ItemAlign.Center , justifyContent : FlexAlign.SpaceBetween }) {
                Button({ type : ButtonType.Normal , stateEffect : true }) {
                  Text('传输数据').fontSize("20vp").fontColor(0xffffff).margin({ left : 2 , right : 2 })
                }
                .borderRadius(8)
                .backgroundColor($r("app.color.blue"))
                .width(100)
                .height(60)
                .margin({ top : "5vp" , left : "10vp" , bottom : "5vp" })
                .align(Alignment.Start)
                .onClick(async(event: ClickEvent) => {
                  this.showListItems = true
                  this.showListItem = false
                })

                Button({ type : ButtonType.Normal , stateEffect : true }) {
                  Row() {
                    Text('上传下载').fontSize("20vp").fontColor(0xffffff).margin({ left : 2 , right : 2 })
                  }.alignItems(VerticalAlign.Center)
                }
                .borderRadius(8)
                .backgroundColor($r("app.color.blue"))
                .width(100)
                .height(60)
                .margin({ top : "5vp" , left : "10vp" , right : "10vp" , bottom : "5vp" })
                .align(Alignment.Center)
                .onClick(async(event: ClickEvent) => {
                  this.showListItem = true
                  this.showListItems = false
                })

                Button({ type : ButtonType.Normal , stateEffect : true }) {
                  Row() {
                    Text('返回接口').fontSize("20vp").fontColor(0xffffff).margin({ left : 2 , right : 2 })
                  }.alignItems(VerticalAlign.Bottom)
                }
                .borderRadius(8)
                .backgroundColor($r("app.color.blue"))
                .width(100)
                .height(60)
                .margin({ top : "5vp" , right : "10vp" , bottom : "5vp" })
                .align(Alignment.End)
                .onClick(async(event: ClickEvent) => {
                  this.showListItem = false
                  this.showListItems = false
                })
              }
              .backgroundColor($r("sys.color.ohos_id_color_sub_background"))
              .width(ConfigData.WH_100_100)
            }
            .width(ConfigData.WH_100_100)
          }
          .scrollBarWidth(10)
          .scrollBar(BarState.Auto)
        }
        .height(130)
        .width(ConfigData.WH_95_100)
        .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))

        if ( this.showListItems == true && this.showListItem == false ) {
          socketTest()
        } else if ( this.showListItems == false && this.showListItem == true ) {
          upDownLoad()
        } else {
          StressContentTable({
            testItem : this.testItem , apiItems : initWifiStressData()
          })
        }
      }
    }
    .alignItems(HorizontalAlign.Center)
    .backgroundColor($r("app.color.lead"))
    .height(ConfigData.WH_100_100)
  }
}

@Component
struct WifiDeviceSetting {
  @State w_ssid: string = "TP-LINK_6365"; //TP-LINK_6365
  @State w_bssid: string = "6C:B1:58:75:63:65"; //6C:B1:58:75:63:65
  @State w_preSharedKey: string = "12345678"; //kaihong123
  @State w_isHiddenSsid: boolean = false;
  @State w_securityType: number = 3
  @State w_creatorUid: number = 1;
  @State w_disableReason: number = 0;
  @State w_netId: number = 100;
  @State w_randomMacType: number = 0;
  @State w_randomMacAddr: string = "08:fb:ea:1b:38:aa"
  @State w_ipType: number = 1;
  @State w_staticIp_ipAddress: number = 3232235880;
  @State w_staticIp_gateway: number = 3232235777;
  @State w_staticIp_dnsServers: number = 3716386629;
  @State w_staticIp_domains: Array<string> = [ "0", "1", "2" ];
  @State w_networkId: number = 0; // id,netId,networkId是一个值嘛？
  @State w_featureId: number = 1;

  aboutToAppear() {
    AppStorage.setOrCreate('w_ssid' , this.w_ssid);
    AppStorage.setOrCreate('w_bssid' , this.w_bssid);
    AppStorage.setOrCreate('w_preSharedKey' , this.w_preSharedKey);
    AppStorage.setOrCreate('w_isHiddenSsid' , this.w_isHiddenSsid);
    AppStorage.setOrCreate('w_securityType' , this.w_securityType);
    AppStorage.setOrCreate('w_creatorUid' , this.w_creatorUid);
    AppStorage.setOrCreate('w_disableReason' , this.w_disableReason);
    AppStorage.setOrCreate('w_netId' , this.w_netId);
    AppStorage.setOrCreate('w_randomMacType' , this.w_randomMacType);
    AppStorage.setOrCreate('w_randomMacAddr' , this.w_randomMacAddr);
    AppStorage.setOrCreate('w_ipType' , this.w_ipType);
    AppStorage.setOrCreate('w_staticIp_ipAddress' , this.w_staticIp_ipAddress);
    AppStorage.setOrCreate('w_staticIp_gateway' , this.w_staticIp_gateway);
    AppStorage.setOrCreate('w_staticIp_dnsServers' , this.w_staticIp_dnsServers);
    AppStorage.setOrCreate('w_staticIp_domains' , this.w_staticIp_domains);
    AppStorage.setOrCreate('w_networkId' , this.w_networkId);
    AppStorage.setOrCreate('w_featureId' , this.w_featureId);
  }

  build() {
    Column() {
      Row() {
        Text("ssid:").fontSize("17vp").width(70)
        TextInput({ text : this.w_ssid , placeholder : "TP-LINK_6365" }) //TP-LINK_6365
          .fontSize("15vp")
          .onChange((strInput: string) => {
            this.w_ssid = strInput;
            AppStorage.setOrCreate('w_ssid' , this.w_ssid);
          })
          .width(ConfigData.WH_80_100)
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
              TextInput({ text : this.w_bssid , placeholder : "6c:b1:58:75:63:67" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.w_bssid = strInput;
                  AppStorage.setOrCreate('w_bssid' , this.w_bssid);
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .padding(3)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)
            .backgroundColor($r("app.color.spring"))

            Row() {
              Text("preSharedKey:").fontSize("15vp").width(110);
              TextInput({ text : this.w_preSharedKey , placeholder : "12345678" }) //kaihong123
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.w_preSharedKey = strInput;
                  AppStorage.setOrCreate('w_preSharedKey' , this.w_preSharedKey);
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("isHiddenSsid:").fontSize(15).width(110);
              TextInput({ text : String(this.w_isHiddenSsid) , placeholder : "false" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.w_isHiddenSsid = strInput === 'true';
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.setOrCreate('w_isHiddenSsid' , this.w_isHiddenSsid);
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("securityType:").fontSize(15).width(ConfigData.value_100);
              Column() {
                Select([
                  { value : 'WIFI_SEC_TYPE_INVALID' },
                  { value : 'WIFI_SEC_TYPE_OPEN' },
                  { value : 'WIFI_SEC_TYPE_WEP' },
                  { value : 'WIFI_SEC_TYPE_PSK' },
                  { value : 'WIFI_SEC_TYPE_SAE' }
                ])
                  .selected(3)
                  .value('WIFI_SEC_TYPE_PSK')
                  .font({ size : 17 })
                  .selectedOptionFont({ size : 17 })
                  .optionFont({ size : 15 })
                  .width(ConfigData.WH_80_100)
                  .onSelect((index: number) => {
                    console.log("Select:" + index)
                    this.w_securityType = index;
                    AppStorage.setOrCreate('w_securityType' , this.w_securityType);
                  })
              }
              .width(ConfigData.WH_80_100)
              .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("creatorUid:").fontSize(15).width(100);
              TextInput({ text : this.w_creatorUid.toString() , placeholder : "1" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.w_creatorUid = Number(strInput);
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.setOrCreate('w_creatorUid' , this.w_creatorUid);
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("disableReason:").fontSize(15).width(120);
              TextInput({ text : this.w_disableReason.toString() , placeholder : "0" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.w_disableReason = Number(strInput);
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.setOrCreate('w_disableReason' , this.w_disableReason);
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("netId:").fontSize(15).width(60);
              TextInput({ text : this.w_netId.toString() , placeholder : "100" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.w_netId = Number(strInput);
                  //判断合法性
                  if ( strInput.length >= 1 ) {
                    AppStorage.setOrCreate('w_netId' , this.w_netId);
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("randomMacType:").fontSize(15).width(140);
              TextInput({ text : this.w_randomMacType.toString() , placeholder : "0" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.w_randomMacType = Number(strInput);
                  if ( strInput.length >= 1 ) {
                    AppStorage.setOrCreate('w_randomMacType' , this.w_randomMacType);
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("randomMacAddr:").fontSize(15).width(140);
              TextInput({ text : this.w_randomMacAddr , placeholder : "08:fb:ea:1b:38:aa" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.w_randomMacAddr = strInput;
                  if ( strInput.length >= 1 ) {
                    AppStorage.setOrCreate('w_randomMacAddr' , this.w_randomMacAddr);
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("ipType:").fontSize(15).width(60);
              TextInput({ text : this.w_ipType.toString() , placeholder : "1" }) //DHCP
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.w_ipType = Number(strInput);
                  if ( strInput.length >= 1 ) {
                    AppStorage.setOrCreate('w_ipType' , this.w_ipType);
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.spring"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("staticIp_ipAddress:").fontSize(15).width(135);
              TextInput({ text : this.w_staticIp_ipAddress.toString() , placeholder : "3232235880" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.w_staticIp_ipAddress = Number(strInput);
                  if ( strInput.length >= 1 ) {
                    AppStorage.setOrCreate('w_staticIp_ipAddress' , this.w_staticIp_ipAddress);
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.moon"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("staticIp_gateway:").fontSize(15).width(130);
              TextInput({ text : this.w_staticIp_gateway.toString() , placeholder : "3232235777" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.w_staticIp_gateway = Number(strInput);
                  if ( strInput.length >= 1 ) {
                    AppStorage.setOrCreate('w_staticIp_gateway' , this.w_staticIp_gateway);
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.moon"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("staticIp_dnsServers:").fontSize(15).width(140);
              TextInput({ text : this.w_staticIp_dnsServers.toString() , placeholder : "3716386629" })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  this.w_staticIp_dnsServers = Number(strInput);
                  if ( strInput.length >= 1 ) {
                    AppStorage.setOrCreate('w_staticIp_dnsServers' , this.w_staticIp_dnsServers);
                  }
                })
                .width(ConfigData.WH_80_100)
                .borderRadius(1)
            }
            .backgroundColor($r("app.color.moon"))
            .padding(5)
            .justifyContent(FlexAlign.Start)
            .alignItems(VerticalAlign.Center)

            Row() {
              Text("staticIp_domains:").fontSize(15).width(125);
              TextInput({
                text : this.w_staticIp_domains.join(', ') , // 将数组转换成以逗号分隔的字符串
                placeholder : "0, 1, 2"
              })
                .fontSize("15vp")
                .onChange((strInput: string) => {
                  // 将输入的字符串按逗号分隔转换回数组
                  this.w_staticIp_domains = strInput.split(',').map(item => item.trim());
                  if ( strInput.length >= 1 ) {
                    AppStorage.setOrCreate('w_staticIp_domains' , this.w_staticIp_domains);
                  }
                })
                .width(ConfigData.WH_80_100)
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
    .height(ConfigData.WH_58_100)
  }
}

@Component
struct socketTest {
  @State login_feng: boolean = false
  @State login_wen: boolean = false
  @State user: string = ''
  @State roomDialog: boolean = false
  @State confirmDialog: boolean = false
  @State ipDialog: boolean = true
  @State txtDialog: boolean = true
  @State warnDialog: boolean = false
  @State warnText: string = ''
  @State roomNumber: string = ''
  @State bindMsg: string = "未绑定"
  @State receiveMsg: string = '待接收数据'

  bindOption() {
    let bindOption = udp.bind(localAddr);
    bindOption.then(() => {
      console.log(TAG , 'bind success')
      this.bindMsg = "绑定成功"
    }).catch((err: BusinessError) => {
      console.log(TAG , 'bind fail' + err)
      this.bindMsg = "绑定失败"
    })
    udp.on('message' , data => {
      console.log(TAG , `data:${ JSON.stringify(data) }`)
      let buffer = data.message
      let dataView = new DataView(buffer)
      console.log(TAG , `length = ${ dataView.byteLength }`)
      let str = ""
      for ( let i = 0 ;i < dataView.byteLength ; ++i ) {
        let c = String.fromCharCode(dataView.getUint8(i))
        if ( c != "\n" ) {
          str += c
        }
      }
      this.receiveMsg = str
      this.confirmDialog = true
    })
  }

  build() {
    Stack({ alignContent : Alignment.Center }) {
      Column() {
        if ( this.ipDialog ) {
          Column() {
            Text('本地IP：' + localAddr.address)
              .fontSize(25)
              .margin({ top : 10 })
            TextInput({ placeholder : '请输入对端ip' })
              .width(200)
              .fontSize(25)
              .margin({ top : 10 })
              .onChange((value: string) => {
                oppositeAddr.address = value
                oppositeAddr.port = 9090
              })

            if ( this.warnDialog ) {
              Text(this.warnText)
                .width(200)
                .fontSize(10)
                .fontColor(Color.Red).margin({ top : 5 })
            }
            Row() {
              Button($r('app.string.confirm'))
                .fontColor(Color.Black)
                .height(40)
                .width(130)
                .fontSize(25)
                .margin({ bottom : 10 })
                .onClick(() => {
                  if ( oppositeAddr.address === '' ) {
                    this.warnDialog = true
                    this.warnText = '请先输入对端IP'
                  } else {
                    this.bindOption()
                    this.txtDialog = true
                    console.log(TAG , `peer ip=${ oppositeAddr.address }`)
                    console.log(TAG , `peer port=${ oppositeAddr.port }`)
                    console.log(TAG , `peer port=${ localAddr.port }`)
                  }
                })
                .backgroundColor(0xffffff)

              Button($r('app.string.send_message'))
                .fontColor(Color.Black)
                .height(40)
                .width(130)
                .fontSize(25)
                .margin({ bottom : 10 })
                .onClick(() => {
                  {
                    //发送数据
                    udp.send({
                      data : 'online' ,
                      address : oppositeAddr
                    }).then(data => {
                      console.log(TAG , `send sucess : ${ data }`)
                    }).catch((error: BusinessError) => {
                      console.log(TAG , `TAG,send : ${ JSON.stringify(error) }`)
                    })

                    console.log(TAG , `send peer ip=${ oppositeAddr.address }`)
                    console.log(TAG , `send peer port=${ oppositeAddr.port }`)
                    console.log(TAG , `send peer port=${ localAddr.port }`)
                  }
                })
                .backgroundColor(0xffffff)
            }

            Text(this.bindMsg)
              .width(200)
              .fontSize(25)
              .fontColor(Color.Red).margin({ top : 3 })
          }
          .width(ConfigData.WH_80_100)
          .height(200)
          .margin({ top : ConfigData.WH_3_100 })
          .backgroundColor(Color.White)
          .border({ radius : 10 , width : 3 })
        }

        if ( this.txtDialog ) {
          Column() {
            Text('接收本地IP：' + localAddr.address)
              .fontSize(25)
              .margin({ top : 10 })

            Text(this.receiveMsg)
              .width(200)
              .fontSize(25)
              .fontColor(Color.Red).margin({ top : 5 })

          }
          .width(ConfigData.WH_80_100)
          .height(180)
          .margin({ top : ConfigData.WH_3_100 })
          .backgroundColor(Color.White)
          .border({ radius : 10 , width : 3 })
        }

      }.width(ConfigData.WH_100_100).height(ConfigData.WH_100_100)
    }
  }
}

@Component
struct upDownLoad {
  @State receivedSize: number = 0
  @State totalSize: number = 0
  @State message: string = ''
  @State files: Array<string> = []
  @State uploads: Array<string> = []
  private downloadConfig: DownloadConfig = {
    url : 'http://192.168.62.127:8000' ,
    filePath : ""
  }

  aboutToAppear() {
    console.log(TAG , `enter Index aboutToAppear`)
    let context: Context = getContext(this) as common.UIAbilityContext;
    let atManager: abilityAccessCtrl.AtManager = abilityAccessCtrl.createAtManager();
    // requestPermissionsFromUser会判断权限的授权状态来决定是否唤起弹窗
    atManager.requestPermissionsFromUser(context , [ 'ohos.permission.INTERNET' ])
      .then((data: PermissionRequestResult) => {
        console.log(TAG , `grantPermission,requestPermissionsFromUser,result.requestCode=${ data }`)
      })
    this.files.push("http://192.168.62.127:8000")
    let httpRequest = http.createHttp()
    httpRequest.request(
      'http://192.168.0.123/?tpl=list&folders-filter=&recursive' ,
      {
        method : http.RequestMethod.GET ,
        header : {
          'Content-Type' : 'text/plain'
        }
      } , (err , data) => {
      console.log(TAG , `error = ${ JSON.stringify(err) }`)
      if ( !err ) {
        console.log(TAG , `data = ${ JSON.stringify(data) }`)
        let result: string = data.result.toString()
        console.log(TAG , `Result = ${ result }`)

        let tempFiles = result.split('\r\n')
        for ( let i = 0 ; i < tempFiles.length ; i ++ ) {
          let splitFiles = tempFiles[ i ].split('//')[ 1 ].split('/')
          console.log(TAG , `splitFiles = ${ JSON.stringify(splitFiles) }`)
          if ( splitFiles.indexOf('upload') === - 1 ) {
            this.files.push(tempFiles[ i ])
          }
        }
        console.log(TAG , `files = ${ JSON.stringify(this.files) }`)
      } else {
        console.log(TAG , `error: ${ JSON.stringify(err) }`)
        httpRequest.destroy()
      }
    })
  }

  build() {
    Column() {
      Scroll() {
        Column() {
          Text($r('app.string.choice_download_file'))
            .fontSize(25)
            .alignSelf(ItemAlign.Start)
            .margin({ top : 20 , left : 10 })
          ForEach(this.files , (item: string , index) => {
            Divider()
              .margin({ top : 20 })
            Row() {
              Text(item)
                .fontSize(25)
                .constraintSize({ maxWidth : ConfigData.WH_75_100 })
                .fontWeight(FontWeight.Bold)
                .margin({ top : 20 , left : 10 })
              Blank()

              Button($r('app.string.click_download'))
                .margin({ top : 20 , right : 10 })
                .onClick(async() => {
                  let fileindex = 1;
                  setInterval(() => {
                    //                    let resourceManage = await resourceManager.getResourceManager()
                    //                    let downloadSuccess = await resourceManage.getString($r('app.string.download_success').id)
                    this.downloadConfig.url = item
                    console.log(TAG , `downloadConfig.url = ${ JSON.stringify(this.downloadConfig.url) }`)
                    this.downloadConfig.filePath = `/data/storage/el2/base/haps/entry/cache/ ${
                    item.split('//')[ 1 ].split('/')[ 1 ] + fileindex }`
                    //                    /data/storage/el2/base/haps/entry/cache/
                    fileindex += 1
                    console.log(TAG , `downloadConfig.filePath = ${ JSON.stringify(this.downloadConfig.filePath) }`)
                    request.downloadFile(getContext() , this.downloadConfig , (err , downloadTask) => {
                      console.log(TAG , `download enter`)
                      if ( err ) {
                        console.log(TAG , `download err = ${ JSON.stringify(err) }`)
                        return
                      }
                      console.log(TAG , `download data = ${ JSON.stringify(downloadTask) }`)

                      console.log(TAG , `download end`)
                    })
                  } , 1000)

                })
            }
            .width(ConfigData.WH_100_100)

            //            if (index === this.files.length - 1) {
            //              Divider().margin({ top: 20 })
            //            }
          } , (item: string) => item)
          Button($r('app.string.upload_page'))
            .fontSize(30)
            .width(180)
            .height(50)
            .margin({ top : 30 })
            .key('uploadBtn')
            .onClick(() => {
              router.pushUrl({
                url : 'pages/Upload' ,
                params : { uploads : this.uploads }
              })
            })

        }
        .width(ConfigData.WH_100_100)
      }
      .constraintSize({ maxHeight : ConfigData.WH_87_100 })

      if ( this.receivedSize !== 0 && this.totalSize !== 0 && this.files.length > 0 ) {
        Row() {
          Text($r('app.string.download_progress'))
            .fontSize(25)
            .fontWeight(FontWeight.Bold)
            .margin({ left : 10 })
          Progress({ value : this.receivedSize , total : this.totalSize , type : ProgressType.Capsule })
            .color(Color.Grey)
            .width(ConfigData.WH_40_100)
            .height(10)
            .margin({ left : 10 })
          Text(`${ JSON.stringify(Math.floor(this.receivedSize / this.totalSize * 100)) }%`)
            .margin({ left : 10 })
        }
        .margin({ top : 10 })
        .alignSelf(ItemAlign.Center)
      }
    }
  }
}

async function sleep(time: number): Promise<void> {
  return new Promise<void>((resolve , reject) => {
    setTimeout(() => {
      resolve();
    } , time * 1000);
  });
}