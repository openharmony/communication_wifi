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
import connection from '@ohos.net.connection';
import ConfigData from '../../utils/ConfigData';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { PageTitle } from '../../Component/pageTitle';
import { TestData } from '../../entryability/model/testData'
import router from '@ohos.router';

interface myParams extends Object {
  testItem: TestData
}


export interface NetAddress {
  address: string;
  family?: number; 
  port?: number; 
}

export interface TCPConnectOptions {
  address: NetAddress;
  timeout?: number;
}

// 定义连接参数接口
interface ConnectParams {
  address: string;
  port: string;
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
  @State networkStatus: string = '检测中...';
  @State networkType: string = '未知';
  @State reconnectCount: number = 0;
  private tcpSocket: socket.TCPSocket | null = null;
  private shouldReconnect: boolean = false;
  private lastConnectParams: ConnectParams | null = null;
  private netConnection: connection.NetConnection | null = null;
  private testItem: TestData = (router.getParams() as myParams).testItem

  aboutToAppear() {
    this.initSocket();
    this.registerNetworkListener();
    this.checkCurrentNetwork();
  }

  initSocket() {
    this.tcpSocket = socket.constructTCPSocketInstance();
  }

  // 注册网络监听
  registerNetworkListener() {
    try {
      // 创建 NetConnection 对象
      this.netConnection = connection.createNetConnection();
      
      // 监听网络可用事件
      this.netConnection.on('netAvailable', (netHandle: connection.NetHandle) => {
        console.log(TAG, `网络可用: netId=${netHandle.netId}`);
        this.networkStatus = '网络可用';
        this.handleNetworkChange();
      });

      // 监听网络能力变化
      this.netConnection.on('netCapabilitiesChange', (netCapabilityInfo: connection.NetCapabilityInfo) => {
        console.log(TAG, `网络能力变化: ${JSON.stringify(netCapabilityInfo)}`);
        if (netCapabilityInfo.netCap) {
          this.updateNetworkType(netCapabilityInfo.netCap);
        }
        this.handleNetworkChange();
      });

      // 监听网络丢失
      this.netConnection.on('netLost', (netHandle: connection.NetHandle) => {
        console.log(TAG, `网络丢失: netId=${netHandle.netId}`);
        this.networkStatus = '网络断开';
        this.responseData += '\n[系统] 网络连接丢失';
      });

      // 注册监听
      this.netConnection.register((error: Error) => {
        if (error) {
          console.error(TAG, `注册网络监听失败: ${JSON.stringify(error)}`);
          this.networkStatus = '监听注册失败';
        } else {
          console.log(TAG, '网络监听已注册');
        }
      });
    } catch (error) {
      console.error(TAG, `创建网络监听失败: ${JSON.stringify(error)}`);
      this.networkStatus = '监听创建失败';
    }
  }

  // 检查当前网络状态
  async checkCurrentNetwork() {
    try {
      const netHandle = await connection.getDefaultNet();
      const netCapabilities = await connection.getNetCapabilities(netHandle);
      this.updateNetworkType(netCapabilities);
      this.networkStatus = '网络正常';
      console.log(TAG, `当前网络类型: ${this.networkType}`);
    } catch (error) {
      console.error(TAG, `获取网络状态失败: ${JSON.stringify(error)}`);
      this.networkStatus = '无网络';
      this.networkType = '未连接';
    }
  }

  // 更新网络类型显示
  updateNetworkType(netCapabilities: connection.NetCapabilities) {
    if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_WIFI)) {
      this.networkType = 'WiFi';
    } else if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_CELLULAR)) {
      this.networkType = '蜂窝网络';
    } else if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_ETHERNET)) {
      this.networkType = '以太网';
    } else {
      this.networkType = '其他';
    }
  }

  // 处理网络变化
  handleNetworkChange() {
    console.log(TAG, '检测到网络变化');
    this.responseData += `\n[系统] 检测到网络变化，当前网络: ${this.networkType}`;
    
    // 如果当前有连接，需要重连
    if (this.isConnected && this.lastConnectParams) {
      this.reconnectCount++;
      this.responseData += `\n[系统] 准备重连 (第${this.reconnectCount}次)...`;
      
      // 先关闭旧连接
      this.closeSocketForReconnect();
      
      // 延迟1秒后重连，等待新网络稳定
      setTimeout(() => {
        this.reconnectToServer();
      }, 1000);
    }
  }

  // 关闭Socket用于重连
  async closeSocketForReconnect() {
    if (this.tcpSocket) {
      try {
        await this.tcpSocket.close();
        console.log(TAG, '旧Socket已关闭，准备重连');
      } catch (error) {
        console.error(TAG, `关闭旧Socket失败: ${JSON.stringify(error)}`);
      }
      // 创建新的Socket实例
      this.tcpSocket = socket.constructTCPSocketInstance();
      this.isConnected = false;
    }
  }

  // 重新连接到服务器
  async reconnectToServer() {
    if (this.lastConnectParams) {
      console.log(TAG, `开始重连到 ${this.lastConnectParams.address}:${this.lastConnectParams.port}`);
      this.connectionStatus = '重连中...';
      // 恢复之前的连接参数
      this.serverAddress = this.lastConnectParams.address;
      this.serverPort = this.lastConnectParams.port;
      // 执行连接
      await this.connectToServer();
    }
  }

  async connectToServer() {
    if (!this.tcpSocket) {
      this.responseData = '错误: Socket未初始化';
      return;
    }

    try {
      this.connectionStatus = '连接中...';
      if (!this.responseData) {
        this.responseData = '';
      }

      // 保存连接参数，用于网络变化时重连
      const params: ConnectParams = {
        address: this.serverAddress,
        port: this.serverPort
      };
      this.lastConnectParams = params;

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
      this.responseData += `\n成功连接到 ${this.serverAddress}:${this.serverPort}`;

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
      Stack({ alignContent : Alignment.TopStart }) {
        TestImageDisplay({ testItem : this.testItem })
        PageTitle({ testItem : this.testItem })
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

        // 网络状态
        Row() {
          Text('网络状态: ')
            .fontSize(16)
            .width('30%')
          Text(`${this.networkStatus} (${this.networkType})`)
            .fontSize(16)
            .fontColor(this.networkStatus === '网络正常' || this.networkStatus === '网络可用' ? Color.Green : Color.Orange)
            .width('70%')
        }
        .width('100%')
        .margin({ bottom: 10 })

        // 重连次数
        if (this.reconnectCount > 0) {
          Row() {
            Text('重连次数: ')
              .fontSize(16)
              .width('30%')
            Text(`${this.reconnectCount}`)
              .fontSize(16)
              .fontColor(Color.Blue)
              .width('70%')
          }
          .width('100%')
          .margin({ bottom: 10 })
        }

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
    // 取消网络监听
    if (this.netConnection) {
      try {
        this.netConnection.unregister((error: Error) => {
          if (error) {
            console.error(TAG, `取消网络监听失败: ${JSON.stringify(error)}`);
          } else {
            console.log(TAG, '网络监听已取消');
          }
        });
      } catch (error) {
        console.error(TAG, `取消网络监听异常: ${JSON.stringify(error)}`);
      }
      this.netConnection = null;
    }

    // 关闭Socket
    if (this.tcpSocket) {
      this.tcpSocket.close();
      this.tcpSocket = null;
    }
    
    // 清空连接参数
    this.lastConnectParams = null;
  }
}
