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
import wifi from '@ohos.wifi';
import router from '@ohos.router';
import { resolveIP} from '../../../Utils/Util';
import socket from '@ohos.net.socket';
import { BusinessError} from '@ohos.base';
import ConfigData from '../../../Utils/ConfigData';

const TAG = 'wifiTestApp [login]'

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
 * login Test Page Of Wifi test
 */
@Entry
@Component
struct Login {
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
  @State receiveMsg: string = ConfigData.SOCKET_STR_RX_PENDING

  bindOption() {
    let bindOption = udp.bind(localAddr);
    bindOption.then(() => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'bind success')
      this.receiveMsg = ConfigData.SOCKET_STR_BIND_OK
    }).catch((err: BusinessError) => {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'bind fail' + err)
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
      if (str == 'ok'){
        router.clear()
        loginCount += 1
        router.pushUrl({
          url: 'pages/index',
          params: { address: oppositeAddr.address, port: oppositeAddr.port, loginCount: loginCount}
        })
      } else {
        this.receiveMsg = str
        this.confirmDialog = true
      }
    })
  }

  build() {
    Stack({alignContent: Alignment.Center}){
      Column() {
        Text($r('app.string.MainAbility_label'))
          .width(ConfigData.WH_100_100)
          .height(ConfigData.VP_50)
          .backgroundColor($r("app.color.ohcc_hex_0d9ffb"))
          .textAlign(TextAlign.Start)
          .fontSize(ConfigData.VP_25)
          .padding({left: ConfigData.VP_10})
          .fontColor($r('app.color.white'))
          .fontWeight(FontWeight.Bold)
        if (!this.ipDialog){
          Column() {
            Image(this.login_feng ? $r('app.color.blue') : $r('app.color.moon'))
              .width(ConfigData.VP_100)
              .height(ConfigData.VP_100)
              .objectFit(ImageFit.Fill)
            Text() {
              Span($r('app.string.wifitest_text_user_name'))
              Span(this.user)
            }.fontSize(ConfigData.VP_25).margin({top: ConfigData.VP_50})

            Button() {
              Text($r('app.string.create_room')).fontSize(ConfigData.VP_25).fontColor($r('app.color.white'))
            }
            .width('150')
            .height(ConfigData.VP_50)
            .margin({top: ConfigData.VP_30})
            .type(ButtonType.Capsule)
            .onClick(() => {
              this.roomDialog = true
              this.bindOption()
            })
          }.width(ConfigData.WH_90_100).margin({top: ConfigData.VP_100})
        }

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
                oppositeAddr.port = ConfigData.DEMO_UDP_PORT
              })

            if (this.warnDialog){
              Text(this.warnText)
                .width(ConfigData.VP_200)
                .fontSize(ConfigData.VP_10)
                .fontColor($r('app.color.red')).margin({top: ConfigData.VP_5})
            }
            Button($r('app.string.confirm'))
              .fontColor($r('app.color.black'))
              .height(ConfigData.VP_50)
              .width(ConfigData.VP_100)
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
              .height(ConfigData.VP_50)
              .width(ConfigData.VP_100)
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
          .width(ConfigData.WH_80_100)
          .height(ConfigData.VP_200)
          .margin({top: ConfigData.WH_10_100})
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
          .margin({top: ConfigData.WH_10_100})
          .backgroundColor($r('app.color.white'))
          .border({radius: $r('app.float.wh_value_10'), width: ConfigData.VP_3})
        }
      }.width(ConfigData.WH_100_100).height(ConfigData.WH_100_100)
    }
  }
}