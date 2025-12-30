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
import { TestImageDisplay } from '../../component/testImageDisplay';
import { PageTitle } from '../../component/pageTitle';
import { TestData } from '../../entryability/model/testData';
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
  @State mode: string = 'client'; // 'client' 或 'server'
  @State serverAddress: string = '192.168.1.100';
  @State serverPort: string = '8080';
  @State localPort: string = '8080'; // 服务端监听端口
  @State message: string = 'Hello TCP Server';
  @State responseData: string = '';
  @State isConnected: boolean = false;
  @State isServerRunning: boolean = false;
  @State connectionStatus: string = '未连接';
  @State networkStatus: string = '检测中...';
  @State networkType: string = '未知';
  @State reconnectCount: number = 0;
  @State clientCount: number = 0; // 已连接的客户端数量
  private tcpSocket: socket.TCPSocket | null = null;
  private serverSocket: socket.TCPSocket | null = null; // 服务端Socket
  private clientSockets: socket.TCPSocket[] = []; // 已连接的客户端Socket列表
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

  // 启动TCP服务端
  async startServer() {
    try {
      this.responseData = '';
      this.responseData += `[服务端] 正在启动服务...\n`;
      
      // 注意：HarmonyOS的标准socket API主要支持客户端功能
      // 这里使用bind来绑定本地端口，模拟服务端监听
      this.serverSocket = socket.constructTCPSocketInstance();
      
      const bindAddress: NetAddress = {
        address: '0.0.0.0',
        port: parseInt(this.localPort),
        family: 1
      };

      await this.serverSocket.bind(bindAddress);
      this.isServerRunning = true;
      
      this.responseData += `[服务端] 服务已启动，监听端口: ${this.localPort}\n`;
      this.responseData += `[服务端] 本地IP: 请在设置中查看WiFi信息获取本机IP地址\n`;
      this.responseData += `[提示] 其他设备可使用客户端模式连接到本机IP:${this.localPort}\n\n`;
      
      // 注意：标准TCPSocket API没有accept方法
      // 实际的服务端实现需要使用TCPSocketServer API（如果可用）
      // 或者使用其他方式如软总线、分布式能力等
      this.responseData += `[说明] HarmonyOS标准Socket API主要用于客户端连接\n`;
      this.responseData += `[说明] 完整的服务端功能可能需要使用：\n`;
      this.responseData += `  1. 软总线（Softbus）进行设备间通信\n`;
      this.responseData += `  2. 分布式数据管理\n`;
      this.responseData += `  3. 或等待后续API版本支持TCPSocketServer\n\n`;
      
      // 设置消息接收回调（如果有数据到达）
      this.serverSocket.on('message', (data) => {
        const receivedData = data.message.toString();
        const remoteInfo = data.remoteInfo;
        console.log(TAG, `[服务端] 收到数据: ${receivedData}, 来自: ${remoteInfo.address}:${remoteInfo.port}`);
        this.responseData += `[收到] ${receivedData} (来自: ${remoteInfo.address}:${remoteInfo.port})\n`;
        
        // 自动回复确认消息
        this.sendServerResponse(receivedData, remoteInfo);
      });

      // 设置错误回调
      this.serverSocket.on('error', (err) => {
        console.error(TAG, `[服务端] Socket错误: ${JSON.stringify(err)}`);
        this.responseData += `[错误] ${JSON.stringify(err)}\n`;
      });

      // 设置关闭回调
      this.serverSocket.on('close', () => {
        console.log(TAG, '[服务端] Socket已关闭');
        this.responseData += '[服务端] Socket已关闭\n';
        this.isServerRunning = false;
      });

    } catch (error) {
      console.error(TAG, `[服务端] 启动失败: ${JSON.stringify(error)}`);
      this.responseData += `[错误] 启动服务失败: ${JSON.stringify(error)}\n`;
      this.isServerRunning = false;
    }
  }

  // 停止TCP服务端
  async stopServer() {
    try {
      if (this.serverSocket) {
        await this.serverSocket.close();
        this.serverSocket = null;
      }
      
      // 关闭所有客户端连接
      for (const clientSocket of this.clientSockets) {
        try {
          await clientSocket.close();
        } catch (error) {
          console.error(TAG, `[服务端] 关闭客户端连接失败: ${JSON.stringify(error)}`);
        }
      }
      this.clientSockets = [];
      this.clientCount = 0;
      
      this.isServerRunning = false;
      this.responseData += '[服务端] 服务已停止\n';
      console.log(TAG, '[服务端] 服务已停止');
    } catch (error) {
      console.error(TAG, `[服务端] 停止服务失败: ${JSON.stringify(error)}`);
      this.responseData += `[错误] 停止服务失败: ${JSON.stringify(error)}\n`;
    }
  }

  // 发送服务端响应
  async sendServerResponse(receivedMessage: string, remoteInfo:socket.SocketRemoteInfo) {
    try {
      if (!this.serverSocket) {
        return;
      }

      const response = `服务端收到: ${receivedMessage}`;
      
      // 注意：标准TCPSocket的send方法用于已连接的socket
      // 对于服务端接收到的消息，需要向对应的客户端发送响应
      // 这里的实现取决于具体的API支持情况
      
      this.responseData += `[发送] 响应: ${response}\n`;
      console.log(TAG, `[服务端] 发送响应: ${response}`);
    } catch (error) {
      console.error(TAG, `[服务端] 发送响应失败: ${JSON.stringify(error)}`);
      this.responseData += `[错误] 发送响应失败: ${JSON.stringify(error)}\n`;
    }
  }

  // 广播消息到所有客户端
  async broadcastMessage() {
    if (!this.isServerRunning || this.clientCount === 0) {
      this.responseData += '[错误] 服务未运行或无客户端连接\n';
      return;
    }

    try {
      this.responseData += `[广播] 向${this.clientCount}个客户端发送: ${this.message}\n`;
      
      // 遍历所有已连接的客户端并发送消息
      let successCount = 0;
      for (const clientSocket of this.clientSockets) {
        try {
          await clientSocket.send({
            data: this.message,
            encoding: 'utf8'
          });
          successCount++;
        } catch (error) {
          console.error(TAG, `[服务端] 发送失败: ${JSON.stringify(error)}`);
        }
      }
      
      this.responseData += `[完成] 成功发送到${successCount}个客户端\n`;
      console.log(TAG, `[服务端] 广播完成，成功: ${successCount}/${this.clientCount}`);
    } catch (error) {
      console.error(TAG, `[服务端] 广播失败: ${JSON.stringify(error)}`);
      this.responseData += `[错误] 广播失败: ${JSON.stringify(error)}\n`;
    }
  }

  build() {
    Column() {
      Stack({ alignContent: Alignment.TopStart }) {
        TestImageDisplay({ testItem: this.testItem })
        PageTitle({ testItem: this.testItem })
      }

      Scroll() {
        Column() {
          // 模式选择
          Text('运行模式')
            .fontSize(18)
            .fontWeight(FontWeight.Bold)
            .width('100%')
            .margin({ top: 10, bottom: 10 })

          Row() {
            Button('客户端模式')
              .width('48%')
              .backgroundColor(this.mode === 'client' ? Color.Blue : Color.Gray)
              .onClick(() => {
                if (!this.isConnected && !this.isServerRunning) {
                  this.mode = 'client';
                  this.responseData = '';
                }
              })

            Button('服务端模式')
              .width('48%')
              .backgroundColor(this.mode === 'server' ? Color.Blue : Color.Gray)
              .onClick(() => {
                if (!this.isConnected && !this.isServerRunning) {
                  this.mode = 'server';
                  this.responseData = '';
                }
              })
          }
          .width('100%')
          .justifyContent(FlexAlign.SpaceBetween)
          .margin({ bottom: 15 })

          // 客户端模式配置
          if (this.mode === 'client') {
            Text('服务器配置')
              .fontSize(18)
              .fontWeight(FontWeight.Bold)
              .width('100%')
              .margin({ top: 5, bottom: 10 })

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
          }

          // 服务端模式配置
          if (this.mode === 'server') {
            Text('服务端配置')
              .fontSize(18)
              .fontWeight(FontWeight.Bold)
              .width('100%')
              .margin({ top: 5, bottom: 10 })

            Row() {
              Text('监听端口: ')
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
              Text('服务状态: ')
                .fontSize(16)
                .width('30%')
              Text(this.isServerRunning ? '运行中' : '未启动')
                .fontSize(16)
                .fontColor(this.isServerRunning ? Color.Green : Color.Gray)
                .width('70%')
            }
            .width('100%')
            .margin({ bottom: 10 })

            if (this.isServerRunning && this.clientCount > 0) {
              Row() {
                Text('连接数: ')
                  .fontSize(16)
                  .width('30%')
                Text(`${this.clientCount}`)
                  .fontSize(16)
                  .fontColor(Color.Blue)
                  .width('70%')
              }
              .width('100%')
              .margin({ bottom: 10 })
            }
          }

          // 连接状态（客户端模式）
          if (this.mode === 'client') {
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
          }

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

          // 重连次数（客户端模式）
          if (this.mode === 'client' && this.reconnectCount > 0) {
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

          // 操作按钮 - 客户端模式
          if (this.mode === 'client') {
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
          }

          // 操作按钮 - 服务端模式
          if (this.mode === 'server') {
            Row() {
              Button(this.isServerRunning ? '停止服务' : '启动服务')
                .width('30%')
                .backgroundColor(this.isServerRunning ? Color.Red : Color.Blue)
                .onClick(() => {
                  if (this.isServerRunning) {
                    this.stopServer();
                  } else {
                    this.startServer();
                  }
                })

              Button('清空日志')
                .width('30%')
                .backgroundColor(Color.Orange)
                .onClick(() => {
                  this.clearResponse();
                })

              Button('广播消息')
                .width('30%')
                .backgroundColor(!this.isServerRunning || this.clientCount === 0 ? Color.Gray : Color.Green)
                .enabled(this.isServerRunning && this.clientCount > 0)
                .onClick(() => {
                  this.broadcastMessage();
                })
            }
            .width('100%')
            .justifyContent(FlexAlign.SpaceBetween)
            .margin({ bottom: 15 })
          }

          // 消息输入区域
          Text(this.mode === 'client' ? '发送消息' : '广播消息')
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

          // 说明提示（服务端模式）
          if (this.mode === 'server') {
            Row() {
              Text('服务端模式: 监听本地端口，等待客户端连接。可以向所有已连接的客户端广播消息。')
                .fontSize(12)
                .fontColor(Color.Blue)
            }
            .width('100%')
            .padding(8)
            .backgroundColor('#E3F2FD')
            .borderRadius(5)
            .margin({ bottom: 10 })
          }

          // 响应/日志区域
          Text(this.mode === 'client' ? '响应数据' : '服务端日志')
            .fontSize(16)
            .fontWeight(FontWeight.Bold)
            .width('100%')
            .margin({ bottom: 5 })

          TextArea({ text: this.responseData })
            .width('100%')
            .height(300)
            .borderRadius(5)
            .backgroundColor(Color.White)
            .margin({ bottom: 20 })
        }
        .width('100%')
        .padding(10)
      }
      .width('95%')
      .height('85%')
      .scrollable(ScrollDirection.Vertical)
      .scrollBar(BarState.Auto)
      .edgeEffect(EdgeEffect.Spring)
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

    // 关闭客户端Socket
    if (this.tcpSocket) {
      this.tcpSocket.close();
      this.tcpSocket = null;
    }
    
    // 关闭服务端Socket
    if (this.serverSocket) {
      this.serverSocket.close();
      this.serverSocket = null;
    }
    
    // 关闭所有客户端连接
    for (const clientSocket of this.clientSockets) {
      try {
        clientSocket.close();
      } catch (error) {
        console.error(TAG, `关闭客户端连接失败: ${JSON.stringify(error)}`);
      }
    }
    this.clientSockets = [];
    
    // 清空连接参数
    this.lastConnectParams = null;
  }
}
