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
import { initP2pStressData } from '../../entryability/model/stressTestDataModels'
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
const G_NAME = 'DaYu200'

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
 * p2p StressTest of Wifi test
 */

@Entry
@Component
struct P2pStressTest {
  @State showList: boolean = false;
  @State showListItems: boolean = false;
  @State showListItem: boolean = false;
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State message: string = "";
  @State deviceId: string = '';
  @State currentClick: number = - 1;
  @State deviceAddress: string = '6c:96:d7:3d:87:6f';
  @State netId: number = - 2;
  @State passphrase: string = "12345678";
  @State groupName: string = "testGroup"
  @State goBand: number = 0;
  @State deviceName: string = "MyTestDevice"
  @StorageLink('stressNumber') stressNumber: number = 0;
  @StorageLink('stressTime') stressTime: number = 0;
  @StorageLink('pairedMac') pairedMac: string = "";

  aboutToAppear() {
    AppStorage.setOrCreate("deviceAddress" , this.deviceAddress)
    AppStorage.setOrCreate("netId" , this.netId)
    AppStorage.setOrCreate("passphrase" , this.passphrase)
    AppStorage.setOrCreate("groupName" , this.groupName)
    AppStorage.setOrCreate("goBand" , this.goBand)
    AppStorage.setOrCreate("deviceName" , this.deviceName)
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
        p2pSetting()
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
            testItem : this.testItem , apiItems : initP2pStressData()
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
struct p2pSetting {
  @State deviceAddress: string = '6c:96:d7:3d:87:6f';
  @State netId: number = - 2;
  @State passphrase: string = "12345678";
  @State groupName: string = "testGroup"
  @State goBand: number = 0;
  @State deviceName: string = "MyTestDevice"

  aboutToAppear() {
    AppStorage.setOrCreate("deviceAddress" , this.deviceAddress)
    AppStorage.setOrCreate("netId" , this.netId)
    AppStorage.setOrCreate("passphrase" , this.passphrase)
    AppStorage.setOrCreate("groupName" , this.groupName)
    AppStorage.setOrCreate("goBand" , this.goBand)
    AppStorage.setOrCreate("deviceName" , this.deviceName)
  }

  build() {
    Column() {
      Row() {
        Text("deviceAddress:").fontSize(16).width(120)
        TextInput({ text : this.deviceAddress , placeholder : "input peripheral deviceId." })
          .fontSize("15vp")
          .onChange((strInput: string) => {
            this.deviceAddress = strInput;
            //判断合法性
            if ( strInput.length >= 1 ) {
              AppStorage.setOrCreate('deviceAddress' , strInput);
            }
          })
          .width(ConfigData.WH_80_100)
          .borderRadius(1)
      }
      .backgroundColor($r("app.color.moon"))
      .padding(5)
      .justifyContent(FlexAlign.Start)
      .alignItems(VerticalAlign.Center)

      Column() {
        Stack().height("0.25vp").backgroundColor("#000000");
        Column() {
          Row() {
            Text("netId:").fontSize(15).width(60);
            TextInput({ text : this.netId.toString() , placeholder : "-2" })
              .fontSize("15vp")
              .onChange((strInput: string) => {
                this.netId = Number(strInput);
                //判断合法性
                if ( strInput.length >= 1 ) {
                  AppStorage.setOrCreate('netId' , strInput);
                }
              })
              .width(ConfigData.WH_80_100)
              .borderRadius(1)
          }
          .padding(5)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)
          .backgroundColor($r("app.color.spring"))

          Row() {
            Text("passphrase:").fontSize(15).width(100);
            TextInput({ text : this.passphrase , placeholder : "input passphrase" })
              .fontSize("15vp")
              .onChange((strInput: string) => {
                this.passphrase = strInput;
                if ( strInput.length >= 1 ) {
                  AppStorage.setOrCreate('passphrase' , strInput);
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
            Text("groupName:").fontSize(15).width(100);
            TextInput({ text : this.groupName , placeholder : "testGroup" })
              .fontSize("15vp")
              .onChange((strInput: string) => {
                this.groupName = strInput;
                if ( strInput.length >= 1 ) {
                  AppStorage.setOrCreate('groupName' , strInput);
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
            Text("goBand:").fontSize(15).width(80);
            TextInput({ text : this.goBand.toString() , placeholder : "0" })
              .fontSize("15vp")
              .onChange((strInput: string) => {
                this.goBand = Number(strInput);
                if ( strInput.length >= 1 ) {
                  AppStorage.setOrCreate('goBand' , strInput);
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
            Text("deviceName:").fontSize(15).width(100);
            TextInput({ text : this.deviceName , placeholder : "MyTestDevice" })
              .fontSize("15vp")
              .onChange((strInput: string) => {
                this.deviceName = strInput;
                if ( strInput.length >= 1 ) {
                  AppStorage.setOrCreate('deviceName' , strInput);
                }
              })
              .width(ConfigData.WH_80_100)
              .borderRadius(1)
          }
          .backgroundColor($r("app.color.spring"))
          .padding(5)
          .justifyContent(FlexAlign.Start)
          .alignItems(VerticalAlign.Center)
        }

        Stack().height("0.25vp").backgroundColor("#000000");
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
                      data : '1' , //online
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

