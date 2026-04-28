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
import router from '@ohos.router';
import { PageTitle} from '../../Component/pageTitle';
import { TestImageDisplay} from '../../Component/testImageDisplay';
import { TestData} from '../../entryability/model/testData';
import ConfigData from "../../Utils/ConfigData";
import wifi from '@ohos.wifi';
import { resolveIP} from '../../Utils/Util';
import socket from '@ohos.net.socket';
import http from '@ohos.net.http';
import request from '@ohos.request';
import common from '@ohos.app.ability.common';
import abilityAccessCtrl, { Context, PermissionRequestResult} from '@ohos.abilityAccessCtrl';
import { BusinessError} from '@ohos.base';

const TAG = 'wifiTestApp [Benchmark]'

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
  address: resolveIP(wifi.getIpInfo().ipAddress),
  family: ConfigData.SOCKET_AF_INET,
  port: ConfigData.DEMO_UDP_PORT
}
let oppositeAddr: OppositeAddr = {
  address: '',
  family: ConfigData.SOCKET_AF_INET,
  port: 0
}
let loginCount = 0

let udp = socket.constructUDPSocketInstance()

/**
 *  HotspotManager benchmark Test Page of wifi test
 */

@Entry
@Component
struct HotspotManagerBenchmarkTest {
  @State showList: boolean = false;
  @State message: string = ConfigData.PAGE_TAG_HS_M_BENCH;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State changeIndex: number = ConfigData.ITEM_CLICK_NONE
  @StorageLink("hotspotManagerBenchmarkTestMessage") hotspotManagerBenchmarkTestMessage: string = ""
  @State receivedSize: number = 0
  @State totalSize: number = 0
  @State files: Array<string> = []
  @State uploads: Array<string> = []
  @StorageLink('hotspotManagerBenchmarkTime') hotspotManagerBenchmarkTime: number = 0;
  @State h_ssid1: string = ConfigData.SCENARIO_HS_SSID;
  @State h_securityType1: number = ConfigData.QV_MOCK_SECURITY_TYPE;
  @State h_band1: number = ConfigData.SCENARIO_HS_BAND;
  @State h_preSharedKey1: string = ConfigData.QV_MOCK_PRE_SHARED_KEY;
  @State h_maxConn1: number = ConfigData.SCENARIO_HS_MAX_CONN;
  @State h_channel1: number = ConfigData.SCENARIO_HS_CHANNEL;

  aboutToAppear() {
    AppStorage.setOrCreate("h_ssid1", this.h_ssid1)
    AppStorage.setOrCreate("h_securityType1", this.h_securityType1)
    AppStorage.setOrCreate("h_band1", this.h_band1)
    AppStorage.setOrCreate("h_preSharedKey1", this.h_preSharedKey1)
    AppStorage.setOrCreate("h_maxConn1", this.h_maxConn1)
    AppStorage.setOrCreate("h_channel1", this.h_channel1)
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
            Text($r('app.string.wifitest_text_xncscshljsdsjsfxn'))
              .fontSize(ConfigData.VP_18)
              .margin({top: ConfigData.VP_5, bottom: ConfigData.VP_5, left: ConfigData.VP_5})
              .textAlign(TextAlign.Start)
              .width(ConfigData.WH_100_100)
          }
          .width(ConfigData.WH_100_100)
          .height(ConfigData.VP_60)

        }
        .scrollBarWidth(ConfigData.VP_10)
        .scrollBar(BarState.Auto)

        Stack().height(ConfigData.VP_1).backgroundColor($r("app.color.black"))

        Column() {
          Text() {
            Span($r('app.string.wifitest_text_bench_time'))
            Span('' + this.hotspotManagerBenchmarkTime)
            Span($r('app.string.wifitest_text_unit_ms'))
          }
            .fontSize(ConfigData.VP_20)
            .margin({top: ConfigData.VP_5, left: ConfigData.VP_10, bottom: ConfigData.VP_5})
            .textAlign(TextAlign.Start)
            .width(ConfigData.WH_90_100)
            .backgroundColor($r("sys.color.ohos_id_color_sub_background"))

          Flex({alignItems: ItemAlign.Center, justifyContent: FlexAlign.SpaceBetween}){
            Button({type: ButtonType.Normal, stateEffect: true}){
              Text($r('app.string.wifitest_text_cssj')).fontSize(ConfigData.VP_24).fontColor($r('app.color.white')).margin({left: ConfigData.VP_5, right: ConfigData.VP_5})
            }
            .borderRadius($r('app.float.wh_value_8'))
            .backgroundColor($r("app.color.blue"))
            .width(ConfigData.VP_120)
            .height(ConfigData.VP_60)
            .margin({top: ConfigData.VP_5, left: ConfigData.VP_50, bottom: ConfigData.VP_5})
            .align(Alignment.Start)
            .onClick(async(event: ClickEvent) => {
              this.showList = false
            })

            Button({type: ButtonType.Normal, stateEffect: true}){
              Row() {
                Text($r('app.string.wifitest_text_scxz')).fontSize(ConfigData.VP_24).fontColor($r('app.color.white')).margin({left: ConfigData.VP_5, right: ConfigData.VP_5})
              }.alignItems(VerticalAlign.Center)
            }
            .borderRadius($r('app.float.wh_value_8'))
            .backgroundColor($r("app.color.blue"))
            .width(ConfigData.VP_120)
            .height(ConfigData.VP_60)
            .margin({top: ConfigData.VP_5, right: ConfigData.VP_50, bottom: ConfigData.VP_5})
            .align(Alignment.Start)
            .onClick(async(event: ClickEvent) => {
              this.showList = true;
            })

          }
          .backgroundColor($r("sys.color.ohos_id_color_sub_background"))
          .width(ConfigData.WH_100_100)
        }
        .backgroundColor($r("sys.color.ohos_id_color_sub_background"))
        .width(ConfigData.WH_100_100)
        .height(ConfigData.VP_100)

        Stack().height(ConfigData.VP_1).backgroundColor($r("app.color.black"))

        Column() {
          if (!this.showList){
            socketTest()
          } else {
            upDownLoad()
          }
        }
        .backgroundColor($r("sys.color.ohos_id_color_sub_background"))
        .width(ConfigData.WH_100_100)
        .height(ConfigData.WH_100_100);
      }
    }
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
  @State bindMsg: string = ConfigData.SOCKET_STR_NOT_BOUND
  @State receiveMsg: string = ConfigData.SOCKET_STR_RX_PENDING

  bindOption() {
    let bindOption = udp.bind(localAddr)
    bindOption.then(() => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'bind success')
      this.bindMsg = ConfigData.SOCKET_STR_BIND_OK
    }).catch((err: BusinessError) => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'bind fail' + err)
      this.bindMsg = ConfigData.SOCKET_STR_BIND_FAIL
    })
    udp.on('message', data => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `data:${ JSON.stringify(data) }`)
      let buffer = data.message
      let dataView = new DataView(buffer)
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `length = ${ dataView.byteLength }`)
      let str = ""
      for(let i = 0 ;i<dataView.byteLength ; ++i){
        let c = String.fromCharCode(dataView.getUint8(i))
        if (c != "\n"){
          str += c
        }
      }
      this.receiveMsg = str
      this.confirmDialog = true
    })
  }

  build() {
    Stack({alignContent: Alignment.Center}){
      Column() {
        if (this.ipDialog){
          Column() {
            Text() {
              Span($r('app.string.wifitest_text_local_ip'))
              Span(localAddr.address)
            }
              .fontSize(ConfigData.VP_25)
              .margin({top: ConfigData.VP_10})
            TextInput({placeholder: $r('app.string.wifitest_text_qsrddi')})
              .width(ConfigData.VP_200)
              .fontSize(ConfigData.VP_25)
              .margin({top: ConfigData.VP_10})
              .onChange((value: string) => {
                oppositeAddr.address = value
                oppositeAddr.port = 9090
              })

            if (this.warnDialog){
              Text(this.warnText)
                .width(ConfigData.VP_200)
                .fontSize(ConfigData.VP_10)
                .fontColor($r('app.color.red')).margin({top: ConfigData.VP_5})
            }
            Row() {
              Button($r('app.string.confirm'))
                .fontColor($r('app.color.black'))
                .height(ConfigData.VP_40)
                .width(ConfigData.VP_130)
                .fontSize(ConfigData.VP_25)
                .margin({bottom: ConfigData.VP_10})
                .onClick(() => {
                  if (oppositeAddr.address === ''){
                    this.warnDialog = true
                    this.warnText = '请先输入对端IP'
                  } else {
                    this.bindOption()
                    this.txtDialog = true
                    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `peer ip=${ oppositeAddr.address }`)
                    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `peer port=${ oppositeAddr.port }`)
                    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `peer port=${ localAddr.port }`)
                  }
                })
                .backgroundColor($r('app.color.white'))

              Button($r('app.string.send_message'))
                .fontColor($r('app.color.black'))
                .height(ConfigData.VP_40)
                .width(ConfigData.VP_130)
                .fontSize(ConfigData.VP_25)
                .margin({bottom: ConfigData.VP_10})
                .onClick(() => {
                  {
                    //发送数据
                    udp.send({
                      data: 'online',
                      address: oppositeAddr
                  }).then(data => {
                      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `send sucess: ${ data }`)
                  }).catch((error: BusinessError) => {
                      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `TAG,send: ${ JSON.stringify(error) }`)
                    })
                    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `send peer ip=${ oppositeAddr.address }`)
                    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `send peer port=${ oppositeAddr.port }`)
                    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `send peer port=${ localAddr.port }`)
                  }
                })
                .backgroundColor($r('app.color.white'))
            }

            Text(this.bindMsg)
              .width(ConfigData.VP_200)
              .fontSize(ConfigData.VP_25)
              .fontColor($r('app.color.red')).margin({top: ConfigData.VP_3})
          }
          .width(ConfigData.WH_80_100)
          .height(ConfigData.VP_200)
          .margin({top: ConfigData.WH_3_100})
          .backgroundColor($r('app.color.white'))
          .border({radius: $r('app.float.wh_value_10'), width: ConfigData.VP_3})
        }

        if (this.txtDialog){
          Column() {
            Text() {
              Span($r('app.string.wifitest_text_rx_local_ip'))
              Span(localAddr.address)
            }
              .fontSize(ConfigData.VP_25)
              .margin({top: ConfigData.VP_10})

            Text(this.receiveMsg)
              .width(ConfigData.VP_200)
              .fontSize(ConfigData.VP_25)
              .fontColor($r('app.color.red')).margin({top: ConfigData.VP_5})

          }
          .width(ConfigData.WH_80_100)
          .height(ConfigData.VP_200)
          .margin({top: ConfigData.WH_3_100})
          .backgroundColor($r('app.color.white'))
          .border({radius: $r('app.float.wh_value_10'), width: ConfigData.VP_3})
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
    url: ConfigData.STRESS_DEMO_FILE_SERVER,
    filePath: ""
  }

  aboutToAppear() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `enter Index aboutToAppear`)
    let context: Context = getContext(this) as common.UIAbilityContext;
    let atManager: abilityAccessCtrl.AtManager = abilityAccessCtrl.createAtManager();
    // requestPermissionsFromUser会判断权限的授权状态来决定是否唤起弹窗
    atManager.requestPermissionsFromUser(context, ['ohos.permission.INTERNET'])
      .then((data: PermissionRequestResult) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `grantPermission,requestPermissionsFromUser,result.requestCode=${ data }`)
      })
    this.files.push(ConfigData.STRESS_DEMO_FILE_SERVER)
    let httpRequest = http.createHttp()
    httpRequest.request(
      ConfigData.STRESS_DEMO_FILE_LIST_URL,
      {
        method: http.RequestMethod.GET,
        header: {
          'Content - Type': 'text/plain'
        }
    }, (err, data) => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `error = ${ JSON.stringify(err) }`)
      if (!err){
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `data = ${ JSON.stringify(data) }`)
        let result: string = data.result.toString()
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Result = ${ result }`)

        let tempFiles = result.split('\r\n')
        for(let i = 0 ; i<tempFiles.length ; i++){
          let splitFiles = tempFiles[i].split('//')[1].split('/')
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `splitFiles = ${ JSON.stringify(splitFiles) }`)
          if (splitFiles.indexOf('upload') === - 1){
            this.files.push(tempFiles[i])
          }
        }
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `files = ${ JSON.stringify(this.files) }`)
      } else {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `error: ${ JSON.stringify(err) }`)
        httpRequest.destroy()
      }
    })
  }

  build() {
    Column() {
      Scroll() {
        Column() {
          Text($r('app.string.choice_download_file'))
            .fontSize(ConfigData.VP_25)
            .alignSelf(ItemAlign.Start)
            .margin({top: ConfigData.VP_20, left: ConfigData.VP_10})
          ForEach(this.files, (item: string, index) => {
            Divider()
              .margin({top: ConfigData.VP_20})
            Row() {
              Text(item)
                .fontSize(ConfigData.VP_25)
                .constraintSize({maxWidth: ConfigData.WH_75_100})
                .fontWeight(FontWeight.Bold)
                .margin({top: ConfigData.VP_20, left: ConfigData.VP_10})
              Blank()

              Button($r('app.string.click_download'))
                .margin({top: ConfigData.VP_20, right: ConfigData.VP_10})
                .onClick(async() => {
                  let fileindex = 1;
                  setInterval(() => {
                    this.downloadConfig.url = item
                    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `downloadConfig.url = ${ JSON.stringify(this.downloadConfig.url) }`)
                    this.downloadConfig.filePath = `/data/storage/el2/base/haps/entry/cache/ ${
                    item.split('//')[1].split('/')[1] + fileindex}`
            //   /data/storage/el2/base/haps/entry/cache/ 
		    fileindex += 1
                    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `downloadConfig.filePath = ${ JSON.stringify(this.downloadConfig.filePath) }`)
                    request.downloadFile(getContext(), this.downloadConfig, (err, downloadTask) => {
                      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `download enter`)
                      if (err){
                        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `download err = ${ JSON.stringify(err) }`)
                        return
                      }
                      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `download data = ${ JSON.stringify(downloadTask) }`)

                      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `download end`)
                    })
                }, 1000)

                })
            }
            .width(ConfigData.WH_100_100)
          }, (item: string) => item)
          Button($r('app.string.upload_page'))
            .fontSize(ConfigData.VP_30)
            .width(ConfigData.VP_180)
            .height(ConfigData.VP_50)
            .margin({top: ConfigData.VP_30})
            .key('uploadBtn')
            .onClick(() => {
              router.pushUrl({
                url: 'pages/Upload',
                params: { uploads: this.uploads}
              })
            })

        }
        .width(ConfigData.WH_100_100)
      }
      .constraintSize({maxHeight: ConfigData.WH_87_100})

      if (this.receivedSize !== 0 && this.totalSize !== 0 && this.files.length > 0){
        Row() {
          Text($r('app.string.download_progress'))
            .fontSize(ConfigData.VP_25)
            .fontWeight(FontWeight.Bold)
            .margin({left: ConfigData.VP_10})
          Progress({value: this.receivedSize, total: this.totalSize, type: ProgressType.Capsule})
            .color($r('app.color.color_999999_grey'))
            .width(ConfigData.WH_40_100)
            .height(ConfigData.VP_10)
            .margin({left: ConfigData.VP_10})
          Text(`${ JSON.stringify(Math.floor(this.receivedSize / this.totalSize * 100)) }%`)
            .margin({left: ConfigData.VP_10})
        }
        .margin({top: ConfigData.VP_10})
        .alignSelf(ItemAlign.Center)
      }
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