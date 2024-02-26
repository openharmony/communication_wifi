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

import wifi from '@ohos.wifi';
import router from '@ohos.router';
import { resolveIP } from '../../../utils/Util'
import socket from '@ohos.net.socket';
import { BusinessError } from '@ohos.base';
import ConfigData from '../../../Utils/ConfigData'

const TAG = '[login]'

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
  @State receiveMsg: string = '待接收数据'

  bindOption() {
    let bindOption = udp.bind(localAddr);
    bindOption.then(() => {
      console.log(TAG , 'bind success')
      this.receiveMsg = "绑定成功"
    }).catch((err: BusinessError) => {
      console.log(TAG , 'bind fail' + err)
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
      if ( str == 'ok' ) {
        router.clear()
        loginCount += 1
        router.pushUrl({
          url : 'pages/Index' ,
          params : { address : oppositeAddr.address , port : oppositeAddr.port , loginCount : loginCount }
        })
      }
      else {
        this.receiveMsg = str
        this.confirmDialog = true
      }
    })
  }

  build() {
    Stack({ alignContent : Alignment.Center }) {
      Column() {
        Text($r('app.string.MainAbility_label'))
          .width(ConfigData.WH_100_100)
          .height(50)
          .backgroundColor('#0D9FFB')
          .textAlign(TextAlign.Start)
          .fontSize(25)
          .padding({ left : 10 })
          .fontColor(Color.White)
          .fontWeight(FontWeight.Bold)
        if ( !this.ipDialog ) {
          Column() {
            Image(this.login_feng ? $r('app.color.blue') : $r('app.color.moon'))
              .width(100)
              .height(100)
              .objectFit(ImageFit.Fill)
            Text('用户名：' + this.user).fontSize(25).margin({ top : 50 })

            Button() {
              Text($r('app.string.create_room')).fontSize(25).fontColor(Color.White)
            }
            .width('150')
            .height(50)
            .margin({ top : 30 })
            .type(ButtonType.Capsule)
            .onClick(() => {
              this.roomDialog = true
              this.bindOption()
            })
          }.width(ConfigData.WH_90_100).margin({ top : 100 })
        }

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
            Button($r('app.string.confirm'))
              .fontColor(Color.Black)
              .height(50)
              .width(100)
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
              .height(50)
              .width(100)
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
          .width(ConfigData.WH_80_100)
          .height(200)
          .margin({ top : ConfigData.WH_10_100 })
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
          .height(200)
          .margin({ top : ConfigData.WH_10_100 })
          .backgroundColor(Color.White)
          .border({ radius : 10 , width : 3 })
        }
      }.width(ConfigData.WH_100_100).height(ConfigData.WH_100_100)
    }
  }
}