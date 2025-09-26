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

import socket from '@ohos.net.socket';
import { TitleBar } from '../../Component/titleBar';
import ConfigData from '../../utils/ConfigData';

export interface NetAddress {
  address: string;
  family?: number; 
  port?: number; 
}

const TAG = 'wifiTestApp [udpSocketTest]';

/**
 * UDP Socket Test Page Of Wifi test
 */
@Entry
@Component
struct UdpSocketTest {
  @State serverAddress: string = '192.168.1.100';
  @State serverPort: string = '8081';
  @State localPort: string = '9090';
  @State message: string = 'Hello UDP Server';
  @State responseData: string = '';
  @State isSocketBound: boolean = false;
  @State socketStatus: string = '未绑定';
  private udpSocket: socket.UDPSocket | null = null;

  aboutToAppear() {
    this.initSocket();
  }

  initSocket() {
    this.udpSocket = socket.constructUDPSocketInstance();
  }

  async bindSocket() {
    if (!this.udpSocket) {
      this.responseData = '错误: Socket未初始化';
      return;
    }

    try {
      this.socketStatus = '绑定中...';
      this.responseData = '';

      // 绑定本地端口
      const bindAddress: NetAddress = { 
        address: '0.0.0.0', 
        port: parseInt(this.localPort), 
        family: 1 
      };
      await this.udpSocket.bind(bindAddress);

      this.isSocketBound = true;
      this.socketStatus = '已绑定';
      this.responseData = `成功绑定到本地端口 ${this.localPort}`;

      // 设置消息接收回调
      this.udpSocket.on('message', (data) => {
        const receivedData = data.message.toString();
        const remoteInfo = data.remoteInfo;
        console.log(TAG, `收到数据: ${receivedData}, 来自: ${remoteInfo.address}:${remoteInfo.port}`);
        this.responseData += `\n收到: ${receivedData} (来自: ${remoteInfo.address}:${remoteInfo.port})`;
      });

      // 设置错误回调
      this.udpSocket.on('error', (err) => {
        console.error(TAG, `Socket错误: ${JSON.stringify(err)}`);
        this.responseData += `\n错误: ${JSON.stringify(err)}`;
        this.isSocketBound = false;
        this.socketStatus = 'Socket错误';
      });

      // 设置监听回调
      this.udpSocket.on('listening', () => {
        console.log(TAG, 'UDP Socket开始监听');
        this.responseData += '\nUDP Socket开始监听';
      });

      // 设置关闭回调
      this.udpSocket.on('close', () => {
        console.log(TAG, 'UDP Socket已关闭');
        this.responseData += '\nUDP Socket已关闭';
        this.isSocketBound = false;
        this.socketStatus = 'Socket已关闭';
      });

    } catch (error) {
      console.error(TAG, `绑定失败: ${JSON.stringify(error)}`);
      this.responseData = `绑定失败: ${JSON.stringify(error)}`;
      this.isSocketBound = false;
      this.socketStatus = '绑定失败';
    }
  }

  async sendMessage() {
    if (!this.udpSocket || !this.isSocketBound) {
      this.responseData += '\n错误: Socket未绑定';
      return;
    }

    try {
      const sendAddress: NetAddress = {
        address: this.serverAddress,
        port: parseInt(this.serverPort),
        family: 1
      };
      await this.udpSocket.send({
        data: this.message,
        address: sendAddress
      });
      this.responseData += `\n发送到 ${this.serverAddress}:${this.serverPort}: ${this.message}`;
      console.log(TAG, `发送消息到 ${this.serverAddress}:${this.serverPort}: ${this.message}`);
    } catch (error) {
      console.error(TAG, `发送失败: ${JSON.stringify(error)}`);
      this.responseData += `\n发送失败: ${JSON.stringify(error)}`;
    }
  }

  async closeSocket() {
    if (!this.udpSocket) {
      return;
    }

    try {
      await this.udpSocket.close();
      this.isSocketBound = false;
      this.socketStatus = '已关闭';
      this.responseData += '\n主动关闭Socket';
    } catch (error) {
      console.error(TAG, `关闭Socket失败: ${JSON.stringify(error)}`);
      this.responseData += `\n关闭Socket失败: ${JSON.stringify(error)}`;
    }
  }

  clearResponse() {
    this.responseData = '';
  }

  build() {
    Column() {
      Stack({ alignContent: Alignment.TopStart }) {
        TitleBar({ detail: "UDP Socket验证" })
      }

      Column() {
        // Socket配置区域
        Text('Socket配置')
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .width('100%')
          .margin({ top: 10, bottom: 10 })

        Row() {
          Text('本地端口: ')
            .fontSize(16)
            .width('30%')
          TextInput({ text: this.localPort })
            .width('70%')
            .borderRadius(5)
            .type(InputType.Number)
            .onChange((value: string) => {
              this.localPort = value;
            })
        }
        .width('100%')
        .margin({ bottom: 10 })

        Row() {
          Text('目标地址: ')
            .fontSize(16)
            .width('30%')
          TextInput({ text: this.serverAddress })
            .width('70%')
            .borderRadius(5)
            .onChange((value: string) => {
              this.serverAddress = value;
            })
        }
        .width('100%')
        .margin({ bottom: 10 })

        Row() {
          Text('目标端口: ')
            .fontSize(16)
            .width('30%')
          TextInput({ text: this.serverPort })
            .width('70%')
            .borderRadius(5)
            .type(InputType.Number)
            .onChange((value: string) => {
              this.serverPort = value;
            })
        }
        .width('100%')
        .margin({ bottom: 10 })

        // Socket状态
        Row() {
          Text('Socket状态: ')
            .fontSize(16)
            .width('30%')
          Text(this.socketStatus)
            .fontSize(16)
            .fontColor(this.isSocketBound ? Color.Green : Color.Red)
            .width('70%')
        }
        .width('100%')
        .margin({ bottom: 10 })

        // 操作按钮
        Row() {
          Button('绑定')
            .width('22%')
            .backgroundColor(this.isSocketBound ? Color.Gray : Color.Blue)
            .enabled(!this.isSocketBound)
            .onClick(() => {
              this.bindSocket();
            })

          Button('关闭')
            .width('22%')
            .backgroundColor(!this.isSocketBound ? Color.Gray : Color.Red)
            .enabled(this.isSocketBound)
            .onClick(() => {
              this.closeSocket();
            })

          Button('清空')
            .width('22%')
            .backgroundColor(Color.Orange)
            .onClick(() => {
              this.clearResponse();
            })

          Button('发送')
            .width('22%')
            .backgroundColor(!this.isSocketBound ? Color.Gray : Color.Green)
            .enabled(this.isSocketBound)
            .onClick(() => {
              this.sendMessage();
            })
        }
        .width('100%')
        .justifyContent(FlexAlign.SpaceBetween)
        .margin({ bottom: 15 })

        // 消息输入区域
        Text('发送消息')
          .fontSize(16)
          .fontWeight(FontWeight.Bold)
          .width('100%')
          .margin({ bottom: 5 })

        TextInput({ text: this.message })
          .width('100%')
          .borderRadius(5)
          .onChange((value: string) => {
            this.message = value;
          })
          .margin({ bottom: 15 })

        // 响应区域
        Text('响应数据')
          .fontSize(16)
          .fontWeight(FontWeight.Bold)
          .width('100%')
          .margin({ bottom: 5 })

        TextArea({ text: this.responseData })
          .width('100%')
          .height('40%')
          .borderRadius(5)
          .backgroundColor(Color.White)
      }
      .width('95%')
      .height('85%')
      .padding(10)
    }
    .size({ width: ConfigData.WH_100_100, height: ConfigData.WH_100_100 })
    .backgroundColor('#F5F5F5')
  }

  aboutToDisappear() {
    if (this.udpSocket) {
      this.udpSocket.close();
      this.udpSocket = null;
    }
  }
}
