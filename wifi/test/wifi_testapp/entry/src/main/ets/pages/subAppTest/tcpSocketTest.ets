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

export interface TCPConnectOptions {
  address: NetAddress;
  timeout?: number;
}

const TAG = 'wifiTestApp [tcpSocketTest]';

/**
 * TCP Socket Test Page Of Wifi test
 */
@Entry
@Component
struct TcpSocketTest {
  @State serverAddress: string = '192.168.1.100';
  @State serverPort: string = '8080';
  @State message: string = 'Hello TCP Server';
  @State responseData: string = '';
  @State isConnected: boolean = false;
  @State connectionStatus: string = '未连接';
  private tcpSocket: socket.TCPSocket | null = null;

  aboutToAppear() {
    this.initSocket();
  }

  initSocket() {
    this.tcpSocket = socket.constructTCPSocketInstance();
  }

  async connectToServer() {
    if (!this.tcpSocket) {
      this.responseData = '错误: Socket未初始化';
      return;
    }

    try {
      this.connectionStatus = '连接中...';
      this.responseData = '';

      // 绑定本地地址（可选）
      const bindAddress: NetAddress = { address: '0.0.0.0', port: 0, family: 1 };
      await this.tcpSocket.bind(bindAddress);

      // 连接到服务器
      const serverAddress: NetAddress = {
        address: this.serverAddress,
        port: parseInt(this.serverPort),
        family: 1
      };
      const connectOptions: TCPConnectOptions = {
        address: serverAddress,
        timeout: 60000
      };
      await this.tcpSocket.connect(connectOptions);

      this.isConnected = true;
      this.connectionStatus = '已连接';
      this.responseData = `成功连接到 ${this.serverAddress}:${this.serverPort}`;

      // 设置消息接收回调
      this.tcpSocket.on('message', (data) => {
        const receivedData = data.message.toString();
        console.log(TAG, `收到数据: ${receivedData}`);
        this.responseData += `\n收到: ${receivedData}`;
      });

      // 设置错误回调
      this.tcpSocket.on('error', (err) => {
        console.error(TAG, `Socket错误: ${JSON.stringify(err)}`);
        this.responseData += `\n错误: ${JSON.stringify(err)}`;
        this.isConnected = false;
        this.connectionStatus = '连接错误';
      });

      // 设置关闭回调
      this.tcpSocket.on('close', () => {
        console.log(TAG, 'Socket连接已关闭');
        this.responseData += '\n连接已关闭';
        this.isConnected = false;
        this.connectionStatus = '连接已关闭';
      });

    } catch (error) {
      console.error(TAG, `连接失败: ${JSON.stringify(error)}`);
      this.responseData = `连接失败: ${JSON.stringify(error)}`;
      this.isConnected = false;
      this.connectionStatus = '连接失败';
    }
  }

  async sendMessage() {
    if (!this.tcpSocket || !this.isConnected) {
      this.responseData += '\n错误: 未连接到服务器';
      return;
    }

    try {
      await this.tcpSocket.send({
        data: this.message,
        encoding: 'utf8'
      });
      this.responseData += `\n发送: ${this.message}`;
      console.log(TAG, `发送消息: ${this.message}`);
    } catch (error) {
      console.error(TAG, `发送失败: ${JSON.stringify(error)}`);
      this.responseData += `\n发送失败: ${JSON.stringify(error)}`;
    }
  }

  async disconnectFromServer() {
    if (!this.tcpSocket) {
      return;
    }

    try {
      await this.tcpSocket.close();
      this.isConnected = false;
      this.connectionStatus = '已断开';
      this.responseData += '\n主动断开连接';
    } catch (error) {
      console.error(TAG, `断开连接失败: ${JSON.stringify(error)}`);
      this.responseData += `\n断开连接失败: ${JSON.stringify(error)}`;
    }
  }

  clearResponse() {
    this.responseData = '';
  }

  build() {
    Column() {
      Stack({ alignContent: Alignment.TopStart }) {
        TitleBar({ detail: "TCP Socket验证" })
      }

      Column() {
        // 服务器配置区域
        Text('服务器配置')
          .fontSize(18)
          .fontWeight(FontWeight.Bold)
          .width('100%')
          .margin({ top: 10, bottom: 10 })

        Row() {
          Text('服务器地址: ')
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
          Text('端口: ')
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

        // 连接状态
        Row() {
          Text('连接状态: ')
            .fontSize(16)
            .width('30%')
          Text(this.connectionStatus)
            .fontSize(16)
            .fontColor(this.isConnected ? Color.Green : Color.Red)
            .width('70%')
        }
        .width('100%')
        .margin({ bottom: 10 })

        // 操作按钮
        Row() {
          Button('连接')
            .width('22%')
            .backgroundColor(this.isConnected ? Color.Gray : Color.Blue)
            .enabled(!this.isConnected)
            .onClick(() => {
              this.connectToServer();
            })

          Button('断开')
            .width('22%')
            .backgroundColor(!this.isConnected ? Color.Gray : Color.Red)
            .enabled(this.isConnected)
            .onClick(() => {
              this.disconnectFromServer();
            })

          Button('清空')
            .width('22%')
            .backgroundColor(Color.Orange)
            .onClick(() => {
              this.clearResponse();
            })

          Button('发送')
            .width('22%')
            .backgroundColor(!this.isConnected ? Color.Gray : Color.Green)
            .enabled(this.isConnected)
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
    if (this.tcpSocket) {
      this.tcpSocket.close();
      this.tcpSocket = null;
    }
  }
}
