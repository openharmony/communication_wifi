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
import { TestImageDisplay} from '../../Component/testImageDisplay';
import { PageTitle} from '../../Component/pageTitle';
import { TestData} from '../../entryability/model/testData';
import ConfigData from '../../Utils/ConfigData';
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
  @State serverAddress: string = ConfigData.SOCKET_DEMO_LAN_IP;
  @State serverPort: string = ConfigData.UDP_DEMO_PORT_STR;
  @State localPort: string = ConfigData.UDP_DEMO_LOCAL_PORT_STR;
  @State message: string = ConfigData.UDP_DEMO_HELLO_MSG;
  @State responseData: string = '';
  @State isSocketBound: boolean = false;
  @State socketStatus: string = ConfigData.SOCKET_STR_NOT_BOUND;
  @State networkStatus: string = ConfigData.HTTP_STR_CHECKING;
  @State networkType: string = ConfigData.HTTP_STR_NET_UNKNOWN;
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

    // 如果当前Socket已绑定，需要重新绑定
    if (this.isSocketBound && this.lastBindParams){
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
    if (this.udpSocket){
      try {
        await this.udpSocket.close();
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '旧Socket已关闭，准备重新绑定');
      } catch (error){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `关闭旧Socket失败: ${JSON.stringify(error)}`);
      }
      // 创建新的Socket实例
      this.udpSocket = socket.constructUDPSocketInstance();
      this.isSocketBound = false;
    }
  }

  // 重新绑定Socket
  async rebindSocket() {
    if (this.lastBindParams){
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `开始重新绑定到本地端口 ${this.lastBindParams.localPort}`);
      this.socketStatus = ConfigData.SOCKET_STR_REBINDING;
      // 恢复之前的绑定参数
      this.localPort = this.lastBindParams.localPort;
      // 执行绑定
      await this.bindSocket();
    }
  }

  async bindSocket() {
    if (!this.udpSocket){
      this.responseData = '错误: Socket未初始化';
      return;
    }

    try {
      this.socketStatus = ConfigData.SOCKET_STR_BINDING;
      if (!this.responseData){
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
      this.socketStatus = ConfigData.SOCKET_STR_BOUND;
      this.responseData += `\n成功绑定到本地端口 ${this.localPort}`;

      // 设置消息接收回调
      this.udpSocket.on('message', (data) => {
        const receivedData = data.message.toString();
        const remoteInfo = data.remoteInfo;
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `收到数据: ${receivedData}, 来自: ${remoteInfo.address}:${remoteInfo.port}`);
        this.responseData += `\n收到: ${receivedData} (来自: ${remoteInfo.address}:${remoteInfo.port})`;
      });

      // 设置错误回调
      this.udpSocket.on('error', (err) => {
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `Socket错误: ${JSON.stringify(err)}`);
        this.responseData += `\n错误: ${JSON.stringify(err)}`;
        this.isSocketBound = false;
        this.socketStatus = 'Socket错误';
      });

      // 设置监听回调
      this.udpSocket.on('listening', () => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'UDP Socket开始监听');
        this.responseData += '\nUDP Socket开始监听';
      });

      // 设置关闭回调
      this.udpSocket.on('close', () => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'UDP Socket已关闭');
        this.responseData += '\nUDP Socket已关闭';
        this.isSocketBound = false;
        this.socketStatus = 'Socket已关闭';
      });

    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `绑定失败: ${JSON.stringify(error)}`);
      this.responseData = `绑定失败: ${JSON.stringify(error)}`;
      this.isSocketBound = false;
      this.socketStatus = ConfigData.SOCKET_STR_BIND_FAIL;
    }
  }

  async sendMessage() {
    if (!this.udpSocket || !this.isSocketBound){
      this.responseData += '\n' + ConfigData.SOCKET_LOG_ERR_NOT_BOUND;
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
      hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `发送消息到 ${this.serverAddress}:${this.serverPort}: ${this.message}`);
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `发送失败: ${JSON.stringify(error)}`);
      this.responseData += `\n发送失败: ${JSON.stringify(error)}`;
    }
  }

  async closeSocket() {
    if (!this.udpSocket){
      return;
    }

    try {
      await this.udpSocket.close();
      this.isSocketBound = false;
      this.socketStatus = '已关闭';
      this.responseData += '\n主动关闭Socket';
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `关闭Socket失败: ${JSON.stringify(error)}`);
      this.responseData += `\n关闭Socket失败: ${JSON.stringify(error)}`;
    }
  }

  clearResponse() {
    this.responseData = '';
  }

  build() {
    Column() {
      Stack({alignContent: Alignment.TopStart}){
        TestImageDisplay({testItem: this.testItem})
        PageTitle({testItem: this.testItem})
      }

      Column() {
        // Socket配置区域
        Text($r('app.string.wifitest_text_spz'))
          .fontSize(ConfigData.VP_18)
          .fontWeight(FontWeight.Bold)
          .width(ConfigData.WH_100_100)
          .margin({top: ConfigData.VP_10, bottom: ConfigData.VP_10})

        Row() {
          Text($r('app.string.wifitest_text_bddk'))
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
          Text($r('app.string.wifitest_text_mbdz'))
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
          Text($r('app.string.wifitest_text_mbdk'))
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

        // Socket状态
        Row() {
          Text($r('app.string.wifitest_text_szt'))
            .fontSize(ConfigData.VP_16)
            .width(ConfigData.WH_30_100)
          Text(this.socketStatus)
            .fontSize(ConfigData.VP_16)
            .fontColor(this.isSocketBound ? $r('app.color.green'): $r('app.color.red'))
            .width(ConfigData.WH_70_100)
        }
        .width(ConfigData.WH_100_100)
        .margin({bottom: ConfigData.VP_10})

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

        // 重连次数
        if (this.reconnectCount > 0){
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

        // 操作按钮
        Row() {
          Button(ConfigData.SOCKET_UI_BTN_BIND)
            .width(ConfigData.PCT_22)
            .backgroundColor(this.isSocketBound ? $r('app.color.color_999999_grey'): $r('app.color.main_blue'))
            .enabled(!this.isSocketBound)
            .onClick(() => {
              this.bindSocket();
            })

          Button(ConfigData.HTTP_STR_SSL_OFF)
            .width(ConfigData.PCT_22)
            .backgroundColor(!this.isSocketBound ? $r('app.color.color_999999_grey'): $r('app.color.red'))
            .enabled(this.isSocketBound)
            .onClick(() => {
              this.closeSocket();
            })

          Button(ConfigData.TCP_UI_CLEAR)
            .width(ConfigData.PCT_22)
            .backgroundColor($r('app.color.ui_orange'))
            .onClick(() => {
              this.clearResponse();
            })

          Button(ConfigData.TCP_UI_SEND)
            .width(ConfigData.PCT_22)
            .backgroundColor(!this.isSocketBound ? $r('app.color.color_999999_grey'): $r('app.color.green'))
            .enabled(this.isSocketBound)
            .onClick(() => {
              this.sendMessage();
            })
        }
        .width(ConfigData.WH_100_100)
        .justifyContent(FlexAlign.SpaceBetween)
        .margin({bottom: ConfigData.VP_15})

        // 消息输入区域
        Text($r('app.string.wifitest_text_fsxx'))
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

        // 响应区域
        Text($r('app.string.wifitest_text_xysj'))
          .fontSize(ConfigData.VP_16)
          .fontWeight(FontWeight.Bold)
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_5})

        TextArea({text: this.responseData})
          .width(ConfigData.WH_100_100)
          .height(ConfigData.WH_40_100)
          .borderRadius($r('app.float.wh_value_5'))
          .backgroundColor($r('app.color.white'))
      }
      .width(ConfigData.WH_95_100)
      .height(ConfigData.PCT_85)
      .padding(ConfigData.VP_10)
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

    // 关闭Socket
    if (this.udpSocket){
      this.udpSocket.close();
      this.udpSocket = null;
    }

    // 清空绑定参数
    this.lastBindParams = null;
  }
}
