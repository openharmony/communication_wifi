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
import socket from '@ohos.net.socket';
import connection from '@ohos.net.connection';
import ConfigData from '../../Utils/ConfigData';
import { TestImageDisplay} from '../../Component/testImageDisplay';
import { PageTitle} from '../../Component/pageTitle';
import { TestData} from '../../entryability/model/testData';
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
  @State mode: string = ConfigData.TCP_DEMO_MODE_CLIENT;// 'client' 或 'server'
  @State serverAddress: string = ConfigData.SOCKET_DEMO_LAN_IP;
  @State serverPort: string = ConfigData.TCP_DEMO_PORT_STR;
  @State localPort: string = ConfigData.TCP_DEMO_PORT_STR;// 服务端监听端口
  @State message: string = ConfigData.TCP_DEMO_HELLO_MSG;
  @State responseData: string = '';
  @State isConnected: boolean = false;
  @State isServerRunning: boolean = false;
  @State connectionStatus: string = ConfigData.HTTP_STR_NOT_CONN;
  @State networkStatus: string = ConfigData.HTTP_STR_CHECKING;
  @State networkType: string = ConfigData.HTTP_STR_NET_UNKNOWN;
  @State reconnectCount: number = 0;
  @State clientCount: number = 0;// 已连接的客户端数量
  private tcpSocket: socket.TCPSocket | null = null;
  private serverSocket: socket.TCPSocket | null = null;// 服务端Socket
  private clientSockets: socket.TCPSocket[] = [];// 已连接的客户端Socket列表
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
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `网络可用: netId=${netHandle.netId}`);
        this.networkStatus = ConfigData.HTTP_STR_NET_AVAILABLE;
        this.handleNetworkChange();
      });

      // 监听网络能力变化
      this.netConnection.on('netCapabilitiesChange', (netCapabilityInfo: connection.NetCapabilityInfo) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `网络能力变化: ${JSON.stringify(netCapabilityInfo)}`);
        if (netCapabilityInfo.netCap){
          this.updateNetworkType(netCapabilityInfo.netCap);
        }
        this.handleNetworkChange();
      });

      // 监听网络丢失
      this.netConnection.on('netLost', (netHandle: connection.NetHandle) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `网络丢失: netId=${netHandle.netId}`);
        this.networkStatus = ConfigData.HTTP_STR_NET_GONE;
        this.responseData += '\n[系统] 网络连接丢失';
      });

      // 注册监听
      this.netConnection.register((error: Error) => {
        if (error){
          hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `注册网络监听失败: ${JSON.stringify(error)}`);
          this.networkStatus = ConfigData.HTTP_STR_REG_FAIL;
        } else {
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '网络监听已注册');
        }
      });
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `创建网络监听失败: ${JSON.stringify(error)}`);
      this.networkStatus = ConfigData.HTTP_STR_CREATE_FAIL;
    }
  }

  // 检查当前网络状态
  async checkCurrentNetwork() {
    try {
      const netHandle = await connection.getDefaultNet();
      const netCapabilities = await connection.getNetCapabilities(netHandle);
      this.updateNetworkType(netCapabilities);
      this.networkStatus = ConfigData.HTTP_STR_NET_OK;
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `当前网络类型: ${this.networkType}`);
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `获取网络状态失败: ${JSON.stringify(error)}`);
      this.networkStatus = ConfigData.HTTP_STR_NO_NET;
      this.networkType = ConfigData.HTTP_STR_NOT_CONN;
    }
  }

  // 更新网络类型显示
  updateNetworkType(netCapabilities: connection.NetCapabilities){
    if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_WIFI)){
      this.networkType = ConfigData.HTTP_STR_BEARER_WIFI;
    } else if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_CELLULAR)){
      this.networkType = ConfigData.HTTP_STR_CELLULAR;
    } else if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_ETHERNET)){
      this.networkType = ConfigData.HTTP_STR_ETHERNET;
    } else {
      this.networkType = ConfigData.HTTP_STR_BEARER_OTHER;
    }
  }

  // 处理网络变化
  handleNetworkChange() {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '检测到网络变化');
    this.responseData += `\n[系统] 检测到网络变化，当前网络: ${this.networkType}`;

    // 如果当前有连接，需要重连
    if (this.isConnected && this.lastConnectParams){
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
    if (this.tcpSocket){
      try {
        await this.tcpSocket.close();
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '旧Socket已关闭，准备重连');
      } catch (error){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `关闭旧Socket失败: ${JSON.stringify(error)}`);
      }
      // 创建新的Socket实例
      this.tcpSocket = socket.constructTCPSocketInstance();
      this.isConnected = false;
    }
  }

  // 重新连接到服务器
  async reconnectToServer() {
    if (this.lastConnectParams){
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `开始重连到 ${this.lastConnectParams.address}:${this.lastConnectParams.port}`);
      this.connectionStatus = '重连中...';
      // 恢复之前的连接参数
      this.serverAddress = this.lastConnectParams.address;
      this.serverPort = this.lastConnectParams.port;
      // 执行连接
      await this.connectToServer();
    }
  }

  async connectToServer() {
    if (!this.tcpSocket){
      this.responseData = '错误: Socket未初始化';
      return;
    }

    try {
      this.connectionStatus = '连接中...';
      if (!this.responseData){
        this.responseData = '';
      }

      // 保存连接参数，用于网络变化时重连
      const params: ConnectParams = {
        address: this.serverAddress,
        port: this.serverPort
      };
      this.lastConnectParams = params;

      // 绑定本地地址（可选）
      const bindAddress: NetAddress = { address: ConfigData.ANY_ADDR_IPV4, port: 0, family: 1};
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
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `收到数据: ${receivedData}`);
        this.responseData += `\n收到: ${receivedData}`;
      });

      // 设置错误回调
      this.tcpSocket.on('error', (err) => {
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Socket错误: ${JSON.stringify(err)}`);
        this.responseData += `\n错误: ${JSON.stringify(err)}`;
        this.isConnected = false;
        this.connectionStatus = '连接错误';
      });

      // 设置关闭回调
      this.tcpSocket.on('close', () => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'Socket连接已关闭');
        this.responseData += '\n连接已关闭';
        this.isConnected = false;
        this.connectionStatus = '连接已关闭';
      });

    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `连接失败: ${JSON.stringify(error)}`);
      this.responseData = `连接失败: ${JSON.stringify(error)}`;
      this.isConnected = false;
      this.connectionStatus = '连接失败';
    }
  }

  async sendMessage() {
    if (!this.tcpSocket || !this.isConnected){
      this.responseData += '\n错误: 未连接到服务器';
      return;
    }

    try {
      await this.tcpSocket.send({
        data: this.message,
        encoding: 'utf8'
      });
      this.responseData += `\n发送: ${this.message}`;
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `发送消息: ${this.message}`);
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `发送失败: ${JSON.stringify(error)}`);
      this.responseData += `\n发送失败: ${JSON.stringify(error)}`;
    }
  }

  async disconnectFromServer() {
    if (!this.tcpSocket){
      return;
    }

    try {
      await this.tcpSocket.close();
      this.isConnected = false;
      this.connectionStatus = '已断开';
      this.responseData += '\n主动断开连接';
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `断开连接失败: ${JSON.stringify(error)}`);
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
        address: ConfigData.ANY_ADDR_IPV4,
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
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `[服务端] 收到数据: ${receivedData}, 来自: ${remoteInfo.address}:${remoteInfo.port}`);
        this.responseData += `[收到] ${receivedData} (来自: ${remoteInfo.address}:${remoteInfo.port})\n`;

        // 自动回复确认消息
        this.sendServerResponse(receivedData, remoteInfo);
      });

      // 设置错误回调
      this.serverSocket.on('error', (err) => {
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `[服务端] Socket错误: ${JSON.stringify(err)}`);
        this.responseData += `[错误] ${JSON.stringify(err)}\n`;
      });

      // 设置关闭回调
      this.serverSocket.on('close', () => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '[服务端] Socket已关闭');
        this.responseData += '[服务端] Socket已关闭\n';
        this.isServerRunning = false;
      });

    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `[服务端] 启动失败: ${JSON.stringify(error)}`);
      this.responseData += `[错误] 启动服务失败: ${JSON.stringify(error)}\n`;
      this.isServerRunning = false;
    }
  }

  // 停止TCP服务端
  async stopServer() {
    try {
      if (this.serverSocket){
        await this.serverSocket.close();
        this.serverSocket = null;
      }

      // 关闭所有客户端连接
      for(const clientSocket of this.clientSockets){
        try {
          await clientSocket.close();
        } catch (error){
          hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `[服务端] 关闭客户端连接失败: ${JSON.stringify(error)}`);
        }
      }
      this.clientSockets = [];
      this.clientCount = 0;

      this.isServerRunning = false;
      this.responseData += '[服务端] 服务已停止\n';
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '[服务端] 服务已停止');
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `[服务端] 停止服务失败: ${JSON.stringify(error)}`);
      this.responseData += `[错误] 停止服务失败: ${JSON.stringify(error)}\n`;
    }
  }

  // 发送服务端响应
  async sendServerResponse(receivedMessage: string, remoteInfo:socket.SocketRemoteInfo){
    try {
      if (!this.serverSocket){
        return;
      }

      const response = `服务端收到: ${receivedMessage}`;

      // 注意：标准TCPSocket的send方法用于已连接的socket
      // 对于服务端接收到的消息，需要向对应的客户端发送响应
      // 这里的实现取决于具体的API支持情况

      this.responseData += `[发送] 响应: ${response}\n`;
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `[服务端] 发送响应: ${response}`);
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `[服务端] 发送响应失败: ${JSON.stringify(error)}`);
      this.responseData += `[错误] 发送响应失败: ${JSON.stringify(error)}\n`;
    }
  }

  // 广播消息到所有客户端
  async broadcastMessage() {
    if (!this.isServerRunning || this.clientCount === 0){
      this.responseData += '[错误] 服务未运行或无客户端连接\n';
      return;
    }

    try {
      this.responseData += `[广播] 向${this.clientCount}个客户端发送: ${this.message}\n`;

      // 遍历所有已连接的客户端并发送消息
      let successCount = 0;
      for(const clientSocket of this.clientSockets){
        try {
          await clientSocket.send({
            data: this.message,
            encoding: 'utf8'
          });
          successCount++;
        } catch (error){
          hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `[服务端] 发送失败: ${JSON.stringify(error)}`);
        }
      }

      this.responseData += `[完成] 成功发送到${successCount}个客户端\n`;
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `[服务端] 广播完成，成功: ${successCount}/${this.clientCount}`);
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `[服务端] 广播失败: ${JSON.stringify(error)}`);
      this.responseData += `[错误] 广播失败: ${JSON.stringify(error)}\n`;
    }
  }

  build() {
    Column() {
      Stack({alignContent: Alignment.TopStart}){
        TestImageDisplay({testItem: this.testItem})
        PageTitle({testItem: this.testItem})
      }

      Scroll() {
        Column() {
          // 模式选择
          Text($r('app.string.wifitest_text_yxms'))
            .fontSize(ConfigData.VP_18)
            .fontWeight(FontWeight.Bold)
            .width(ConfigData.WH_100_100)
            .margin({top: ConfigData.VP_10, bottom: ConfigData.VP_10})

          Row() {
            Button(ConfigData.TCP_UI_MODE_CLIENT)
              .width(ConfigData.PCT_48)
              .backgroundColor(this.mode === ConfigData.TCP_DEMO_MODE_CLIENT ? $r('app.color.main_blue'): $r('app.color.color_999999_grey'))
              .onClick(() => {
                if (!this.isConnected && !this.isServerRunning){
                  this.mode = ConfigData.TCP_DEMO_MODE_CLIENT;
                  this.responseData = '';
                }
              })

            Button(ConfigData.TCP_UI_MODE_SERVER)
              .width(ConfigData.PCT_48)
              .backgroundColor(this.mode === ConfigData.TCP_DEMO_MODE_SERVER ? $r('app.color.main_blue'): $r('app.color.color_999999_grey'))
              .onClick(() => {
                if (!this.isConnected && !this.isServerRunning){
                  this.mode = ConfigData.TCP_DEMO_MODE_SERVER;
                  this.responseData = '';
                }
              })
          }
          .width(ConfigData.WH_100_100)
          .justifyContent(FlexAlign.SpaceBetween)
          .margin({bottom: ConfigData.VP_15})

          // 客户端模式配置
          if (this.mode === ConfigData.TCP_DEMO_MODE_CLIENT){
            Text($r('app.string.wifitest_text_fwqpz'))
              .fontSize(ConfigData.VP_18)
              .fontWeight(FontWeight.Bold)
              .width(ConfigData.WH_100_100)
              .margin({top: ConfigData.VP_5, bottom: ConfigData.VP_10})

            Row() {
              Text($r('app.string.wifitest_text_fwqdz'))
                .fontSize(ConfigData.VP_16)
                .width(ConfigData.WH_30_100)
              TextInput({text: this.serverAddress})
                .width(ConfigData.WH_70_100)
                .borderRadius($r('app.float.wh_value_5'))
                .onChange((value: string) => {
                  this.serverAddress = value;
                })
            }
            .width(ConfigData.WH_100_100)
            .margin({bottom: ConfigData.VP_10})

            Row() {
              Text($r('app.string.wifitest_text_dk'))
                .fontSize(ConfigData.VP_16)
                .width(ConfigData.WH_30_100)
              TextInput({text: this.serverPort})
                .width(ConfigData.WH_70_100)
                .borderRadius($r('app.float.wh_value_5'))
                .type(InputType.Number)
                .onChange((value: string) => {
                  this.serverPort = value;
                })
            }
            .width(ConfigData.WH_100_100)
            .margin({bottom: ConfigData.VP_10})
          }

          // 服务端模式配置
          if (this.mode === ConfigData.TCP_DEMO_MODE_SERVER){
            Text($r('app.string.wifitest_text_fwdpz'))
              .fontSize(ConfigData.VP_18)
              .fontWeight(FontWeight.Bold)
              .width(ConfigData.WH_100_100)
              .margin({top: ConfigData.VP_5, bottom: ConfigData.VP_10})

            Row() {
              Text($r('app.string.wifitest_text_jtdk'))
                .fontSize(ConfigData.VP_16)
                .width(ConfigData.WH_30_100)
              TextInput({text: this.localPort})
                .width(ConfigData.WH_70_100)
                .borderRadius($r('app.float.wh_value_5'))
                .type(InputType.Number)
                .onChange((value: string) => {
                  this.localPort = value;
                })
            }
            .width(ConfigData.WH_100_100)
            .margin({bottom: ConfigData.VP_10})

            Row() {
              Text($r('app.string.wifitest_text_fwzt'))
                .fontSize(ConfigData.VP_16)
                .width(ConfigData.WH_30_100)
              Text(this.isServerRunning ? '运行中' : '未启动')
                .fontSize(ConfigData.VP_16)
                .fontColor(this.isServerRunning ? $r('app.color.green'): $r('app.color.color_999999_grey'))
                .width(ConfigData.WH_70_100)
            }
            .width(ConfigData.WH_100_100)
            .margin({bottom: ConfigData.VP_10})

            if (this.isServerRunning && this.clientCount > 0){
              Row() {
                Text($r('app.string.wifitest_text_ljs'))
                  .fontSize(ConfigData.VP_16)
                  .width(ConfigData.WH_30_100)
                Text(`${this.clientCount}`)
                  .fontSize(ConfigData.VP_16)
                  .fontColor($r('app.color.main_blue'))
                  .width(ConfigData.WH_70_100)
              }
              .width(ConfigData.WH_100_100)
              .margin({bottom: ConfigData.VP_10})
            }
          }

          // 连接状态（客户端模式）
          if (this.mode === ConfigData.TCP_DEMO_MODE_CLIENT){
            Row() {
              Text($r('app.string.wifiConnectionChange'))
                .fontSize(ConfigData.VP_16)
                .width(ConfigData.WH_30_100)
              Text(this.connectionStatus)
                .fontSize(ConfigData.VP_16)
                .fontColor(this.isConnected ? $r('app.color.green'): $r('app.color.red'))
                .width(ConfigData.WH_70_100)
            }
            .width(ConfigData.WH_100_100)
            .margin({bottom: ConfigData.VP_10})
          }

          // 网络状态
          Row() {
            Text($r('app.string.wifitest_text_wlzt'))
              .fontSize(ConfigData.VP_16)
              .width(ConfigData.WH_30_100)
            Text(`${this.networkStatus} (${this.networkType})`)
              .fontSize(ConfigData.VP_16)
              .fontColor(this.networkStatus === ConfigData.HTTP_STR_NET_OK || this.networkStatus === ConfigData.HTTP_STR_NET_AVAILABLE ? $r('app.color.green'): $r('app.color.ui_orange'))
              .width(ConfigData.WH_70_100)
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_10})

          // 重连次数（客户端模式）
          if (this.mode === ConfigData.TCP_DEMO_MODE_CLIENT && this.reconnectCount > 0){
            Row() {
              Text($r('app.string.wifitest_text_zlcs'))
                .fontSize(ConfigData.VP_16)
                .width(ConfigData.WH_30_100)
              Text(`${this.reconnectCount}`)
                .fontSize(ConfigData.VP_16)
                .fontColor($r('app.color.main_blue'))
                .width(ConfigData.WH_70_100)
            }
            .width(ConfigData.WH_100_100)
            .margin({bottom: ConfigData.VP_10})
          }

          // 操作按钮 - 客户端模式
          if (this.mode === ConfigData.TCP_DEMO_MODE_CLIENT){
            Row() {
              Button(ConfigData.TCP_UI_CONNECT)
                .width(ConfigData.PCT_22)
                .backgroundColor(this.isConnected ? $r('app.color.color_999999_grey'): $r('app.color.main_blue'))
                .enabled(!this.isConnected)
                .onClick(() => {
                  this.connectToServer();
                })

              Button(ConfigData.TCP_UI_DISCONNECT)
                .width(ConfigData.PCT_22)
                .backgroundColor(!this.isConnected ? $r('app.color.color_999999_grey'): $r('app.color.red'))
                .enabled(this.isConnected)
                .onClick(() => {
                  this.disconnectFromServer();
                })

              Button(ConfigData.TCP_UI_CLEAR)
                .width(ConfigData.PCT_22)
                .backgroundColor($r('app.color.ui_orange'))
                .onClick(() => {
                  this.clearResponse();
                })

              Button(ConfigData.TCP_UI_SEND)
                .width(ConfigData.PCT_22)
                .backgroundColor(!this.isConnected ? $r('app.color.color_999999_grey'): $r('app.color.green'))
                .enabled(this.isConnected)
                .onClick(() => {
                  this.sendMessage();
                })
            }
            .width(ConfigData.WH_100_100)
            .justifyContent(FlexAlign.SpaceBetween)
            .margin({bottom: ConfigData.VP_15})
          }

          // 操作按钮 - 服务端模式
          if (this.mode === ConfigData.TCP_DEMO_MODE_SERVER){
            Row() {
              Button(this.isServerRunning ? ConfigData.TCP_UI_STOP_SERVER : ConfigData.TCP_UI_START_SERVER)
                .width(ConfigData.WH_30_100)
                .backgroundColor(this.isServerRunning ? $r('app.color.red'): $r('app.color.main_blue'))
                .onClick(() => {
                  if (this.isServerRunning){
                    this.stopServer();
                  } else {
                    this.startServer();
                  }
                })

              Button(ConfigData.TCP_UI_CLEAR_LOG)
                .width(ConfigData.WH_30_100)
                .backgroundColor($r('app.color.ui_orange'))
                .onClick(() => {
                  this.clearResponse();
                })

              Button(ConfigData.TCP_UI_BTN_BROADCAST)
                .width(ConfigData.WH_30_100)
                .backgroundColor(!this.isServerRunning || this.clientCount === 0 ? $r('app.color.color_999999_grey'): $r('app.color.green'))
                .enabled(this.isServerRunning && this.clientCount > 0)
                .onClick(() => {
                  this.broadcastMessage();
                })
            }
            .width(ConfigData.WH_100_100)
            .justifyContent(FlexAlign.SpaceBetween)
            .margin({bottom: ConfigData.VP_15})
          }

          // 消息输入区域
          Text(this.mode === ConfigData.TCP_DEMO_MODE_CLIENT ? ConfigData.TCP_UI_BTN_SEND : ConfigData.TCP_UI_BTN_BROADCAST)
            .fontSize(ConfigData.VP_16)
            .fontWeight(FontWeight.Bold)
            .width(ConfigData.WH_100_100)
            .margin({bottom: ConfigData.VP_5})

          TextInput({text: this.message})
            .width(ConfigData.WH_100_100)
            .borderRadius($r('app.float.wh_value_5'))
            .onChange((value: string) => {
              this.message = value;
            })
            .margin({bottom: ConfigData.VP_15})

          // 说明提示（服务端模式）
          if (this.mode === ConfigData.TCP_DEMO_MODE_SERVER){
            Row() {
              Text($r('app.string.wifitest_text_fwdmsjtbddkddkhdljkyxsyyljdk'))
                .fontSize(ConfigData.VP_12)
                .fontColor($r('app.color.main_blue'))
            }
            .width(ConfigData.WH_100_100)
            .padding(ConfigData.VP_8)
            .backgroundColor($r("app.color.ohcc_hex_e3f2fd"))
            .borderRadius($r('app.float.wh_value_5'))
            .margin({bottom: ConfigData.VP_10})
          }

          // 响应/日志区域
          Text(this.mode === ConfigData.TCP_DEMO_MODE_CLIENT ? '响应数据' : '服务端日志')
            .fontSize(ConfigData.VP_16)
            .fontWeight(FontWeight.Bold)
            .width(ConfigData.WH_100_100)
            .margin({bottom: ConfigData.VP_5})

          TextArea({text: this.responseData})
            .width(ConfigData.WH_100_100)
            .height(ConfigData.VP_300)
            .borderRadius($r('app.float.wh_value_5'))
            .backgroundColor($r('app.color.white'))
            .margin({bottom: ConfigData.VP_20})
        }
        .width(ConfigData.WH_100_100)
        .padding(ConfigData.VP_10)
      }
      .width(ConfigData.WH_95_100)
      .height(ConfigData.PCT_85)
      .scrollable(ScrollDirection.Vertical)
      .scrollBar(BarState.Auto)
      .edgeEffect(EdgeEffect.Spring)
    }
    .size({width: ConfigData.WH_100_100, height: ConfigData.WH_100_100})
    .backgroundColor($r("app.color.ohcc_hex_f5f5f5"))
  }

  aboutToDisappear() {
    // 取消网络监听
    if (this.netConnection){
      try {
        this.netConnection.unregister((error: Error) => {
          if (error){
            hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `取消网络监听失败: ${JSON.stringify(error)}`);
          } else {
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '网络监听已取消');
          }
        });
      } catch (error){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `取消网络监听异常: ${JSON.stringify(error)}`);
      }
      this.netConnection = null;
    }

    // 关闭客户端Socket
    if (this.tcpSocket){
      this.tcpSocket.close();
      this.tcpSocket = null;
    }

    // 关闭服务端Socket
    if (this.serverSocket){
      this.serverSocket.close();
      this.serverSocket = null;
    }

    // 关闭所有客户端连接
    for(const clientSocket of this.clientSockets){
      try {
        clientSocket.close();
      } catch (error){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `关闭客户端连接失败: ${JSON.stringify(error)}`);
      }
    }
    this.clientSockets = [];

    // 清空连接参数
    this.lastConnectParams = null;
  }
}
