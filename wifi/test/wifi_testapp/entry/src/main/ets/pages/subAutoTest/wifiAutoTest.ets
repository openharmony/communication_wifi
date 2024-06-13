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

import ConfigData from '../../utils/ConfigData';
import router from '@ohos.router';
import { TestData } from '../../entryability/model/testData'
import { PageTitle } from '../../Component/pageTitle';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { WifiAutoTestCase , initWifiAutoData } from '../../entryability/model/autoTestDataModels'
import { AutoContentTable } from '../../Component/autoContentTable'
import prompt from '@system.prompt';

interface myParams extends Object {
  testItem: TestData
}

interface IWifiAutoArrayItem {
  name: string;
  para: string[]; // 替换any[]为实际参数类型
}
/**
 *  wifiAutoTest Page Of wifi test
 */

@Entry
@Component
struct WifiAutoTest {
  @State message: string = 'WifiAutoTest';
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State changeIndex: number = - 1
  //  @State autoTextMessage: string ="None";
  @StorageLink("wifiAutoTestMessage") wifiAutoTestMessage: string = ""
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
      Stack({ alignContent : Alignment.TopStart }) {
        TestImageDisplay({ testItem : this.testItem })
        PageTitle({ testItem : this.testItem })
      }

      Stack().height("1vp").backgroundColor("#000000");
      Column() {
        Scroll() {
          Column() {
            Text("API验证:")
              .fontSize("17vp")
              .margin({ top : "10vp" , bottom : "10vp" , left : "15vp" })
              .textAlign(TextAlign.Start)
              .width(ConfigData.WH_100_100)
            AutoContentTable({
              testItem : this.testItem ,
              autoItems : initWifiAutoData() ,
              //             testMessage: this.testMessage,  优化时修改
              changeIndex : this.changeIndex
            })
          }
          .width(ConfigData.WH_100_100)
          .height(280)
        }
        .scrollBarWidth(10)
        .scrollBar(BarState.Auto)

        Stack().height("1vp").backgroundColor("#000000");

        Scroll() {
          Column() {
            Text("Debug日志:")
              .fontSize("17vp")
              .margin({ top : "8vp" , bottom : "8vp" , left : "15vp" })
              .textAlign(TextAlign.Start)
              .width(ConfigData.WH_100_100)
            List() {
              ListItem() {
                Text(this.wifiAutoTestMessage)
                  //                Text("log:" + "\n"  + this.wifiAutoTestMessage)
                  .fontSize("17vp")
                  .margin({ top : "5vp" , left : "30vp" , right : "10vp" })
                  .textAlign(TextAlign.Start)
                  .width(ConfigData.WH_90_100)
              }
            }
            .height(ConfigData.WH_80_100)
            .width(ConfigData.WH_90_100)
            .backgroundColor($r("sys.color.ohos_id_color_foreground_contrary"))
          }
          .width(ConfigData.WH_100_100)
          .height(260)
        }
        .scrollBarWidth(10)
        .scrollBar(BarState.On)
      }
      .height(500)
      .width(ConfigData.WH_100_100)
      .backgroundColor($r("sys.color.ohos_id_color_sub_background"))


      Stack().height("1vp").backgroundColor("#000000");
      Column() {
        Button({ type : ButtonType.Normal , stateEffect : true }) {
          Row() {
            Text('自动测试').fontSize("24vp").fontColor(0xffffff).margin({ left : 5 , right : 5 })
          }.alignItems(VerticalAlign.Center)
        }
        .borderRadius(8)
        .backgroundColor($r("app.color.blue"))
        .width(180)
        .height(50)
        .margin({ top : "15vp" })
        .onClick(async(event: ClickEvent) => {
          console.log("wifiAutoTest start-------------")
          await this.forLoop()

          let msg = ""
          msg = "测试"
          console.log(msg)
          prompt.showToast({ message : msg })

          console.log("wifiAutoTest end-------------")
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
      let para: string[] = foundItem ? foundItem.para : [];
      return { name : i.api.name , para } as IWifiAutoArrayItem;
    })

    for ( let m = 0 ; m < Interface.length ; m ++ ) {
      wifiAutoTestMessage += await WifiAutoTestCase[ m ].api(... Interface[ m ].para) + "\n"
      this.changeIndex = m
      await sleep(2)
      AppStorage.setOrCreate("wifiAutoTestMessage" , wifiAutoTestMessage)
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