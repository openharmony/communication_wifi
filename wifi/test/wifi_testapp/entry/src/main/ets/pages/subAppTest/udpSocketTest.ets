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
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { PageTitle } from '../../Component/pageTitle';
import { TestData } from '../../entryability/model/testData'
import ConfigData from '../../utils/ConfigData';
import router from '@ohos.router';

interface myParams extends Object {
  testItem: TestData
}

export interface NetAddress {
  address: string;
  family?: number; 
  port?: number; 
}

// 定义绑定参数接口
interface BindParams {
  localPort: string;
}

const TAG = 'wifiTestApp [udpSocketTest]';

/**
 * UDP Socket Test Page Of Wifi test
 */
@Entry
@Component
struct UdpSocketTest {
  private testItem: TestData = (router.getParams() as myParams).testItem
  @State serverAddress: string = '192.168.1.100';
  @State serverPort: string = '8081';
  @State localPort: string = '9090';
  @State message: string = 'Hello UDP Server';
  @State responseData: string = '';
  @State isSocketBound: boolean = false;
  @State socketStatus: string = '未绑定';
  @State networkStatus: string = '检测中...';
  @State networkType: string = '未知';
  @State reconnectCount: number = 0;
  private udpSocket: socket.UDPSocket | null = null;
  private lastBindParams: BindParams | null = null;
  private netConnection: connection.NetConnection | null = null;

  aboutToAppear() {
    this.initSocket();
    this.registerNetworkListener();
    this.checkCurrentNetwork();
  }

  initSocket() {
    this.udpSocket = socket.constructUDPSocketInstance();
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
    
    // 如果当前Socket已绑定，需要重新绑定
    if (this.isSocketBound && this.lastBindParams) {
      this.reconnectCount++;
      this.responseData += `\n[系统] 准备重新绑定 (第${this.reconnectCount}次)...`;
      
      // 先关闭旧Socket
      this.closeSocketForRebind();
      
      // 延迟1秒后重新绑定，等待新网络稳定
      setTimeout(() => {
        this.rebindSocket();
      }, 1000);
    }
  }

  // 关闭Socket用于重新绑定
  async closeSocketForRebind() {
    if (this.udpSocket) {
      try {
        await this.udpSocket.close();
        console.log(TAG, '旧Socket已关闭，准备重新绑定');
      } catch (error) {
        console.error(TAG, `关闭旧Socket失败: ${JSON.stringify(error)}`);
      }
      // 创建新的Socket实例
      this.udpSocket = socket.constructUDPSocketInstance();
      this.isSocketBound = false;
    }
  }

  // 重新绑定Socket
  async rebindSocket() {
    if (this.lastBindParams) {
      console.log(TAG, `开始重新绑定到本地端口 ${this.lastBindParams.localPort}`);
      this.socketStatus = '重新绑定中...';
      // 恢复之前的绑定参数
      this.localPort = this.lastBindParams.localPort;
      // 执行绑定
      await this.bindSocket();
    }
  }

  async bindSocket() {
    if (!this.udpSocket) {
      this.responseData = '错误: Socket未初始化';
      return;
    }

    try {
      this.socketStatus = '绑定中...';
      if (!this.responseData) {
        this.responseData = '';
      }

      // 保存绑定参数，用于网络变化时重新绑定
      const params: BindParams = {
        localPort: this.localPort
      };
      this.lastBindParams = params;

      // 绑定本地端口
      const bindAddress: NetAddress = { 
        address: '0.0.0.0', 
        port: parseInt(this.localPort), 
        family: 1 
      };
      await this.udpSocket.bind(bindAddress);

      this.isSocketBound = true;
      this.socketStatus = '已绑定';
      this.responseData += `\n成功绑定到本地端口 ${this.localPort}`;

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
      Stack({ alignContent : Alignment.TopStart }) {
        TestImageDisplay({ testItem : this.testItem })
        PageTitle({ testItem : this.testItem })
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
    if (this.udpSocket) {
      this.udpSocket.close();
      this.udpSocket = null;
    }
    
    // 清空绑定参数
    this.lastBindParams = null;
  }
}
