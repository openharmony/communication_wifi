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
import TextDecoder from '@ohos.util';
import { netHandover} from '@kit.NetworkBoostKit';
import connection from '@ohos.net.connection';
import ConfigData from '../../Utils/ConfigData';
import { TestImageDisplay} from '../../Component/testImageDisplay';
import { PageTitle} from '../../Component/pageTitle';
import { TestData} from '../../entryability/model/testData'
import router from '@ohos.router';
import { BusinessError} from '@ohos.base';

interface myParams extends Object {
  testItem: TestData
}

export interface NetAddress {
  address: string;
  family?: number;
  port?: number;
}

type PathType = 'wifi' | 'cellular';

const TAG = 'wifiTestApp [multipathSocketTest]';

/**
 * Multipath Socket Test Page Of Wifi test
 */
@Entry
@Component
struct MultipathSocketTest {
  private testItem: TestData = (router.getParams() as myParams).testItem
  // 模式选择
  @State wifiModeIndex: number = 0;
  @State wifiModeValue: string = ConfigData.MULTIPATH_DEMO_MODE;
  @State cellularModeIndex: number = 0;
  @State cellularModeValue: string = ConfigData.MULTIPATH_DEMO_MODE;
  @State modeList: Array<SelectOption> = [
    { value: ConfigData.MULTIPATH_DEMO_MODE},
    { value: ConfigData.MULTIPATH_DEMO_MODE_SERVER}
  ];
  // WiFi链路配置
  @State wifiRemoteAddress: string = ConfigData.SOCKET_DEMO_LAN_IP;
  @State wifiRemotePort: string = ConfigData.MULTIPATH_WIFI_REMOTE_PORT;
  @State wifiLocalPort: string = ConfigData.MULTIPATH_WIFI_LOCAL_PORT;
  // 蜂窝链路配置
  @State cellularRemoteAddress: string = ConfigData.SOCKET_DEMO_PUBLIC_DNS;
  @State cellularRemotePort: string = ConfigData.MULTIPATH_CELL_REMOTE_PORT;
  @State cellularLocalPort: string = ConfigData.MULTIPATH_CELL_LOCAL_PORT;
  @State cellularResponse: string = '';// 用于显示 DNS 响应
  // 通用状态
  @State message: string = ConfigData.MULTIPATH_HELLO_MSG;
  @State responseData: string = '';
  @State wifiNetworkStatus: string = ConfigData.HTTP_STR_CHECKING;
  @State cellularNetworkStatus: string = ConfigData.HTTP_STR_CHECKING;
  @State wifiStatus: string = ConfigData.SOCKET_STR_NOT_BOUND;
  @State cellularStatus: string = ConfigData.SOCKET_STR_NOT_BOUND;
  @State wifiHandleInfo: string = ConfigData.SOCKET_STR_HANDLE_PENDING;
  @State cellularHandleInfo: string = ConfigData.SOCKET_STR_HANDLE_PENDING;
  @State wifiBound: boolean = false;
  @State cellularBound: boolean = false;
  @State wifiReconnectCount: number = 0;
  @State cellularReconnectCount: number = 0;
  @State wifiSendCount: number = 0;
  @State cellularSendCount: number = 0;
  @State wifiReceiveCount: number = 0;
  @State cellularReceiveCount: number = 0;
  private wifiSocket: socket.UDPSocket | null = null;
  private cellularSocket: socket.TCPSocket | null = null;// ✅ 改为 TCP
  private wifiNetHandle: connection.NetHandle | null = null;
  private cellularNetHandle: connection.NetHandle | null = null;
  private netConnection: connection.NetConnection | null = null;
  private netConnectionCellular: connection.NetConnection | null = null;
  private wifiPacketSeq: number = 0;
  private cellularPacketSeq: number = 0;

  aboutToAppear() {
    this.requestMultiPath();
    this.registerNetworkListener();
    this.checkCurrentNetwork();
  }

  bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, ConfigData.QV_MOCK_DOMAIN_0))
      .join(' ');
  }

  // 将family字符串转换为数字（1 for IPv4, 2 for IPv6）
  convertFamilyToNumber(family: string | number | undefined): number {
    if (typeof family === 'number'){
      return family;
    }
    if (family === 'IPv6'){
      return 2;
    }
    return 1;// 默认为IPv4
  }

  requestMultiPath() {
    try {
      netHandover.requestMultiPath((data: netHandover.MultiPathRequestResult) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s', ` zly20000requestMultiPath result:` + JSON.stringify(data));
      });
    } catch (err){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s', 'zly20001errCode: ' + (err as BusinessError).code + ', errMessage: ' + (err as BusinessError).message);
    }
  }

  releaseMultiPath() {
    try {
      netHandover.releaseMultiPath();
    } catch (err){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s', 'zly20002errCode: ' + (err as BusinessError).code + ', errMessage: ' + (err as BusinessError).message);
    }
  }

  // 注册网络监听
  registerNetworkListener() {
    try {
      this.netConnection = connection.createNetConnection({
        netCapabilities: {
          bearerTypes: [connection.NetBearType.BEARER_WIFI]
        }
      });

      this.netConnection.register((error: Error) => {
        if (error){
          hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `注册WiFi网络监听失败: ${JSON.stringify(error)}`);
          this.wifiNetworkStatus = ConfigData.MULTIPATH_WIFI_REG_FAIL;
        } else {
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'WiFi网络监听已注册');
        }
      });

      this.netConnection.on('netAvailable', (netHandle: connection.NetHandle) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `WiFi网络可用: netId=${netHandle.netId}`);
        this.wifiNetworkStatus = ConfigData.MULTIPATH_WIFI_NET_OK;
        this.handleWifiNetworkChange();
      });

      this.netConnection.on('netCapabilitiesChange', (netCapabilityInfo: connection.NetCapabilityInfo) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `WiFi网络能力变化: ${JSON.stringify(netCapabilityInfo)}`);
        this.handleWifiNetworkChange();
      });

      this.netConnection.on('netLost', (netHandle: connection.NetHandle) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `WiFi网络丢失: netId=${netHandle.netId}`);
        this.wifiNetworkStatus = ConfigData.MULTIPATH_WIFI_NET_GONE;
        this.appendLog('[WiFi] 网络连接丢失');
      });

      // 关注蜂窝网络，需要传入相关网络特征，timeout参数未传入说明未使用超时时间，此时timeout为0
      this.netConnectionCellular = connection.createNetConnection({
        netCapabilities: {
          bearerTypes: [connection.NetBearType.BEARER_CELLULAR]
        }
      });

      // 先使用register接口注册订阅事件
      this.netConnectionCellular.register((error: BusinessError) => {
        if (error){
          hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `注册蜂窝网络监听失败: ${JSON.stringify(error)}`);
          this.cellularNetworkStatus = ConfigData.MULTIPATH_CELL_REG_FAIL;
        } else {
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '蜂窝网络监听已注册');
        }
      });

      // 订阅网络可用事件。调用register后，才能接收到此事件通知
      this.netConnectionCellular.on('netAvailable', (netHandle: connection.NetHandle) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `蜂窝网络可用: netId=${netHandle.netId}`);
        this.cellularNetworkStatus = ConfigData.MULTIPATH_CELL_NET_OK;
        this.handleCellularNetworkChange();
      });

      this.netConnectionCellular.on('netCapabilitiesChange', (netCapabilityInfo: connection.NetCapabilityInfo) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `蜂窝网络能力变化: ${JSON.stringify(netCapabilityInfo)}`);
        this.handleCellularNetworkChange();
      });

      this.netConnectionCellular.on('netLost', (netHandle: connection.NetHandle) => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `蜂窝网络丢失: netId=${netHandle.netId}`);
        this.cellularNetworkStatus = ConfigData.MULTIPATH_CELL_NET_GONE;
        this.appendLog('[蜂窝] 网络连接丢失');
      });

    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `创建网络监听失败: ${JSON.stringify(error)}`);
      this.wifiNetworkStatus = ConfigData.MULTIPATH_WIFI_REG_CREATE_FAIL;
      this.cellularNetworkStatus = ConfigData.MULTIPATH_CELL_REG_CREATE_FAIL;
    }
  }

  // 双路网络检测
  async checkCurrentNetwork() {
    this.wifiNetworkStatus = ConfigData.HTTP_STR_CHECKING;
    this.cellularNetworkStatus = ConfigData.HTTP_STR_CHECKING;
    this.wifiNetHandle = null;
    this.cellularNetHandle = null;
    this.wifiHandleInfo = ConfigData.SOCKET_STR_HANDLE_PENDING;
    this.cellularHandleInfo = ConfigData.SOCKET_STR_HANDLE_PENDING;

    try {
      // 优先使用同步API
      let handles: connection.NetHandle[] = [];
      try {
        handles = connection.getAllNetsSync();
      } catch (syncErr){
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'getAllNets同步API不可用，尝试异步');
        try {
          handles = await connection.getAllNets();
        } catch (asyncErr){
          hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, 'getAllNets异步API不可用，使用默认网络');
          const defaultNet = await connection.getDefaultNet();
          if (defaultNet && defaultNet.netId !== 0){
            handles = [defaultNet];
          }
        }
      }

      for(const handle of handles){
        // netId为0表示无有效网络，跳过
        if (!handle || handle.netId === 0){
          continue;
        }

        try {
          const netCapabilities = await connection.getNetCapabilities(handle);
          if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_WIFI) && !this.wifiNetHandle){
            this.wifiNetHandle = handle;
            this.wifiHandleInfo = `netId=${handle.netId}`;
            this.wifiNetworkStatus = ConfigData.MULTIPATH_WIFI_STATUS_OK;
          }
          if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_CELLULAR) && !this.cellularNetHandle){
            this.cellularNetHandle = handle;
            this.cellularHandleInfo = `netId=${handle.netId}`;
            this.cellularNetworkStatus = ConfigData.MULTIPATH_CELL_STATUS_OK;
          }
        } catch (capErr){
          hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `获取网络能力失败: ${JSON.stringify(capErr)}`);
        }
      }

      if (!this.wifiNetHandle){
        this.wifiNetworkStatus = ConfigData.MULTIPATH_WIFI_NO_NET;
      }
      if (!this.cellularNetHandle){
        this.cellularNetworkStatus = ConfigData.MULTIPATH_CELL_NO_NET;
      }

      if (!this.wifiNetHandle && !this.cellularNetHandle){
        this.appendLog('[系统] 未检测到WiFi或蜂窝网络');
        return;
      }

      this.appendLog(`[系统] 网络刷新完成 - WiFi:${this.wifiHandleInfo}(${this.wifiNetworkStatus}), 蜂窝:${this.cellularHandleInfo}(${this.cellularNetworkStatus})`);
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `获取网络状态失败: ${JSON.stringify(error)}`);
      this.wifiNetworkStatus = ConfigData.MULTIPATH_WIFI_FETCH_FAIL;
      this.cellularNetworkStatus = ConfigData.MULTIPATH_CELL_FETCH_FAIL;
      this.appendLog('[系统] 获取网络状态失败');
    }
  }

  // WiFi网络变化处理：重新检测并按需重绑
  handleWifiNetworkChange() {
    this.appendLog('[WiFi] 检测到WiFi网络变化，刷新链路中...');
    const wasWifiBound = this.wifiBound;

    this.checkCurrentNetwork().then(() => {
      // WiFi链路：如果之前已绑定且新netHandle有效，尝试重建
      if (wasWifiBound && this.wifiNetHandle && this.wifiNetHandle.netId !== 0){
        this.wifiReconnectCount++;
        this.appendLog(`[WiFi] 开始重建连接(第${this.wifiReconnectCount}次)`);
        this.rebindSocket('wifi');
      } else if (wasWifiBound && !this.wifiNetHandle){
        this.wifiBound = false;
        this.wifiStatus = ConfigData.MULTIPATH_WIFI_NET_LOST;
        this.appendLog('[WiFi] 网络丢失，已断开');
      }
    });
  }

  // 蜂窝网络变化处理：重新检测并按需重绑
  handleCellularNetworkChange() {
    this.appendLog('[蜂窝] 检测到蜂窝网络变化，刷新链路中...');
    const wasCellularBound = this.cellularBound;

    this.checkCurrentNetwork().then(() => {
      // 蜂窝链路：如果之前已绑定且新netHandle有效，尝试重建
      if (wasCellularBound && this.cellularNetHandle && this.cellularNetHandle.netId !== 0){
        this.cellularReconnectCount++;
        this.appendLog(`[蜂窝] 开始重建连接(第${this.cellularReconnectCount}次)`);
        this.rebindSocket('cellular');
      } else if (wasCellularBound && !this.cellularNetHandle){
        this.cellularBound = false;
        this.cellularStatus = ConfigData.MULTIPATH_CELL_NET_LOST;
        this.appendLog('[蜂窝] 网络丢失，已断开');
      }
    });
  }

  async rebindSocket(path: PathType){
    await this.closeSocket(path, false);
    setTimeout(() => {
      this.bindSocket(path);
    }, 500);// 延迟500ms等待网络稳定
  }

  async bindWifiSocket() {
    await this.bindSocket('wifi');
  }

  async bindCellularSocket() {
    await this.bindSocketCellular();
  }

  async bindSocket(path: PathType){
    const targetHandle = path === 'wifi' ? this.wifiNetHandle: this.cellularNetHandle;
    const targetPort = path === 'wifi' ? parseInt(this.wifiLocalPort) : parseInt(this.cellularLocalPort);
    const label = path === 'wifi' ? ConfigData.HTTP_STR_BEARER_WIFI: ConfigData.MULTIPATH_LABEL_CELLULAR;

    if (!targetHandle || targetHandle.netId === 0){
      this.appendLog(`[${label}] 未找到有效的netHandle(netId=${targetHandle?.netId})，请先刷新网络`);
      if (path === 'wifi'){
        this.wifiStatus = ConfigData.SOCKET_STR_NET_HANDLE_INVALID;
      } else {
        this.cellularStatus = ConfigData.SOCKET_STR_NET_HANDLE_INVALID;
      }
      return;
    }

    // 1. 关闭旧socket
    const existingSocket = path === 'wifi' ? this.wifiSocket: this.cellularSocket;
    if (existingSocket){
      try {
        await existingSocket.close();
      } catch (e){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `关闭旧${label} Socket失败: ${JSON.stringify(e)}`);
      }
    }

    // 2. 创建新socket
    const socketInstance = socket.constructUDPSocketInstance();
    if (path === 'wifi'){
      this.wifiSocket = socketInstance;
      this.wifiStatus = ConfigData.SOCKET_STR_BINDING;
    }

    try {
      // 3. 先bind本地端口（重要！必须在bindSocket之前）
      const bindAddress: NetAddress = {
        address: ConfigData.ANY_ADDR_IPV4,
        port: targetPort,
        family: 1
      };
      await socketInstance.bind(bindAddress);
      this.appendLog(`[${label}] 步骤1: 成功绑定本地端口 ${targetPort}`);

      // 4. 设置事件监听（在bindSocket之前）
      this.setupSocketEvents(socketInstance, label);
      this.appendLog(`[${label}] 步骤2: 已设置事件监听`);

      // 5. 最后绑定到指定netHandle
      const bindSuccess = await this.applyNetHandleToSocket(socketInstance, targetHandle, label);

      if (bindSuccess){
        if (path === 'wifi'){
          this.wifiBound = true;
          this.wifiStatus = `${ConfigData.SOCKET_STR_BOUND}(${this.wifiHandleInfo})`;
        } else {
          this.cellularBound = true;
          this.cellularStatus = `${ConfigData.SOCKET_STR_BOUND}(${this.cellularHandleInfo})`;
        }
        this.appendLog(`[${label}] ✓ 绑定流程完成`);
      } else {
        throw new Error(ConfigData.MULTIPATH_BIND_ERR);
      }
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `绑定${label} Socket失败: ${JSON.stringify(error)}`);
      this.appendLog(`[${label}] ✗ 绑定失败: ${JSON.stringify(error)}`);

      // 绑定失败，清理socket
      try {
        await socketInstance.close();
      } catch (e){
      // ignore
      }

      if (path === 'wifi'){
        this.wifiSocket = null;
        this.wifiBound = false;
        this.wifiStatus = ConfigData.SOCKET_STR_BIND_FAIL;
      } else {
        this.cellularSocket = null;
        this.cellularBound = false;
        this.cellularStatus = ConfigData.SOCKET_STR_BIND_FAIL;
      }
    }
  }

  async bindSocketCellular() {
    const label = ConfigData.MULTIPATH_LABEL_CELLULAR;

    // 关闭旧 socket（如果存在）
    if (this.cellularSocket){
      try {
        await this.cellularSocket.close();
      } catch (e){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `关闭旧${label} Socket失败: ${JSON.stringify(e)}`);
      }
    }

    // 创建新的 TCP Socket
    const socketInstance = socket.constructTCPSocketInstance();
    this.cellularSocket = socketInstance;
    this.cellularStatus = ConfigData.SOCKET_STR_CELLULAR_INIT;

    try {
      // 设置 TCP 选项（参考你提供的大纲）
      socketInstance.setExtraOptions({
        receiveBufferSize: 8192,
        sendBufferSize: 8192,
        reuseAddress: true,
        socketTimeout: 60000
      });

      this.cellularBound = true;
      this.cellularStatus = ConfigData.SOCKET_STR_CELLULAR_TCP_READY;
      this.appendLog('[蜂窝] ✓ TCP Socket 初始化完成，等待连接百度');
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `初始化蜂窝 TCP Socket失败: ${JSON.stringify(error)}`);
      this.appendLog('[蜂窝] ✗ 初始化失败: ' + JSON.stringify(error));
      this.cellularSocket = null;
      this.cellularBound = false;
      this.cellularStatus = ConfigData.SOCKET_STR_INIT_FAILED;
    }
  }

  async applyNetHandleToSocket(socketInstance: socket.UDPSocket, netHandle: connection.NetHandle, label: string): Promise<boolean> {
    // 直接使用 netHandle.bindSocket（参考官方示例）
    try {
      await new Promise<void>((resolve, reject) => {
        netHandle.bindSocket(socketInstance, (error: BusinessError) => {
          if (error){
            reject(error);
            hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `${label} 通过netHandle.bindSocket绑定失败,error: ${JSON.stringify(error)}`);
          } else {
            resolve();
          }
        });
      });
      this.appendLog(`[${label}] 步骤3: 已绑定到netId=${netHandle.netId} (netHandle.bindSocket)`);
      return true;
    } catch (err){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `${label} 通过netHandle.bindSocket绑定失败,err: ${JSON.stringify(err)}`);
      return false;
    }
  }

  setupSocketEvents(socketInstance: socket.UDPSocket, label: string){
    socketInstance.on('message', (data) => {
      const receivedData = data.message ? data.message.toString() : '';
      const remoteInfo = data.remoteInfo;
      const isWifi = label === ConfigData.HTTP_STR_BEARER_WIFI;
      const currentMode = isWifi ? this.wifiModeValue: this.cellularModeValue;

      // 更新接收计数
      if (isWifi){
        this.wifiReceiveCount++;
      } else {
        this.cellularReceiveCount++;
      }

      const receiveCount = isWifi ? this.wifiReceiveCount: this.cellularReceiveCount;
      this.appendLog(`[${label}][${currentMode}] 收到 #${receiveCount}: ${receivedData} (来自: ${remoteInfo.address}:${remoteInfo.port})`);

      // Server模式：自动回复
      if (currentMode === ConfigData.MULTIPATH_DEMO_MODE_SERVER){
        const replyMsg = `[${label}][Server] Echo: ${receivedData}`;
        const replyAddress: NetAddress = {
          address: remoteInfo.address,
          port: remoteInfo.port,
          family: this.convertFamilyToNumber(remoteInfo.family)
        };

        socketInstance.send({
          data: replyMsg,
          address: replyAddress
        }).then(() => {
          this.appendLog(`[${label}][Server] 回复到 ${remoteInfo.address}:${remoteInfo.port}`);
        }).catch((err:BusinessError) => {
          hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `${label} Server回复失败: ${JSON.stringify(err)}`);
          this.appendLog(`[${label}][Server] ✗ 回复失败: ${JSON.stringify(err)}`);
        });
      }
    });

    socketInstance.on('error', (err) => {
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `${label} Socket错误: ${JSON.stringify(err)}`);
      this.appendLog(`[${label}] ✗ Socket错误: ${JSON.stringify(err)}`);
    });

    socketInstance.on('listening', () => {
      this.appendLog(`[${label}] UDP Socket开始监听`);
    });

    socketInstance.on('close', () => {
      this.appendLog(`[${label}] UDP Socket已关闭`);
      // 清理状态
      if (label === ConfigData.HTTP_STR_BEARER_WIFI){
        this.wifiBound = false;
      } else {
        this.cellularBound = false;
      }
    });
  }

  async sendOnWifi() {
    await this.sendMessage('wifi');
  }

  async sendOnCellular() {
    await this.sendMessageCellular();
  }

  async sendBoth() {
    await this.sendOnWifi();
    await this.sendOnCellular();
  }

  async sendMessage(path: PathType){
    const socketInstance = path === 'wifi' ? this.wifiSocket: this.cellularSocket;
    const bound = path === 'wifi' ? this.wifiBound: this.cellularBound;
    const label = path === 'wifi' ? ConfigData.HTTP_STR_BEARER_WIFI: ConfigData.MULTIPATH_LABEL_CELLULAR;
    const targetAddress = path === 'wifi' ? this.wifiRemoteAddress: this.cellularRemoteAddress;
    const targetPort = path === 'wifi' ? parseInt(this.wifiRemotePort) : parseInt(this.cellularRemotePort);

    if (!socketInstance || !bound){
      this.appendLog(`[${label}] ✗ ${ConfigData.SOCKET_LOG_ERR_NOT_BOUND}`);
      return;
    }

    try {
      // 生成序列号
      const seq = path === 'wifi' ? ++this.wifiPacketSeq: ++this.cellularPacketSeq;
      const timestamp = new Date().toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3});

      // 根据路径区分发送方式
      if (path === 'wifi'){
        // ✅ WiFi 是 UDP，需要 address
        const udpSocket = socketInstance as socket.UDPSocket;// ✅ 类型断言为 UDPSocket
        const sendAddress: NetAddress = {
          address: targetAddress,
          port: targetPort,
          family: 1
        };

        const dataToSend = `[${label}] [SEQ:${seq}] [TIME:${timestamp}] ${this.message}`;

        await udpSocket.send({
          data: dataToSend,
          address: sendAddress
        });

        this.appendLog(`[${label}] 发送 #${seq} 到 ${targetAddress}:${targetPort}`);
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `${label} 发送数据包 #${seq}: ${dataToSend}`);

        this.wifiSendCount++;// 只有 WiFi 才递增
      } else {
        // ✅ 蜂窝是 TCP，不需要 address
        const tcpSocket = socketInstance as socket.TCPSocket;// ✅ 类型断言为 TCPSocket
        const dataToSend = `[${label}] [SEQ:${seq}] [TIME:${timestamp}] ${this.message}`;

        await tcpSocket.send({
          data: dataToSend
        });

        this.appendLog(`[${label}] 发送数据包 #${seq} (TCP)`);
        hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `${label} 发送 TCP 数据: ${dataToSend}`);

        this.cellularSendCount++;// 只有蜂窝才递增
      }

    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `${label} 发送失败: ${JSON.stringify(error)}`);
      this.appendLog(`[${label}] ✗ 发送失败: ${JSON.stringify(error)}`);
    }
  }

  async sendMessageCellular() {
    if (!this.cellularSocket || !this.cellularBound){
      this.appendLog('[蜂窝] ✗ TCP Socket未初始化，请先点击“绑定蜂窝”');
      this.cellularStatus = ConfigData.MULTIPATH_CELL_STATUS_NOT_INIT;
      return;
    }

    this.cellularStatus = ConfigData.MULTIPATH_CELL_STATUS_CONNECTING;
    this.cellularResponse = '';
    this.appendLog('[蜂窝] 正在连接百度服务器...');

    const host = ConfigData.WEB_DEMO_ADDR_BAIDU;
    const port = ConfigData.HTTP_PORT_WELL_KNOWN;

    let response = '';
    let hasReceivedData = false;
    let isClosed = false;

    try {
      const tcpSocket = this.cellularSocket as socket.TCPSocket;

      // ✅ 连接
      await tcpSocket.connect({
        address: {
          address: host,
          port: port
        },
        timeout: 10000
      });
      this.appendLog('[蜂窝] ✅ 连接成功！');

      // ✅ 发送 HTTP GET 请求
      const httpRequest = `GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`;
      await tcpSocket.send({
        data: httpRequest
      });
      this.appendLog('[蜂窝] ✅ HTTP 请求已发送');

      // ✅ 使用事件监听接收数据（✅ 替代 while(true) + recv）
      tcpSocket.on('message', (info: socket.SocketMessageInfo) => {
        if (isClosed) return;

        const message = info.message;
        if (!message || message.byteLength === 0) return;

        // ✅ 正确使用 info.message
        const uint8Array = new Uint8Array(message);
        let dataStr = '';
        for(let i = 0; i<uint8Array.length; i++){
          dataStr += String.fromCharCode(uint8Array[i]);
        }

        response += dataStr;
        hasReceivedData = true;

        this.appendLog(`[蜂窝] 接收到 ${message.byteLength} 字节数据`);

        if (info.remoteInfo){
          hilog.info(0x1500, 'wifiTestApp', '%{public}s', `[蜂窝] 来自 ${info.remoteInfo.address}:${info.remoteInfo.port}`);
        }
      });

      // ✅ 监听连接关闭
      tcpSocket.on('close', () => {
        isClosed = true;
        this.appendLog('[蜂窝] ✅ 连接已关闭');
      });

      // ✅ 监听错误
      tcpSocket.on('error', (err: Error) => {
        if (!isClosed){
          this.appendLog(`[蜂窝] ❌ 收到错误: ${err.message}`);
        }
      });

      // ✅ 等待连接关闭（通过事件触发）
      await new Promise<void>((resolve) => {
        const checkClosed = () => {
          if (isClosed){
            resolve();
          } else {
            setTimeout(checkClosed, 50);// 每50ms检查一次
          }
        };
        checkClosed();
      });

      // ✅ 检查是否收到数据
      if (!hasReceivedData){
        throw new Error(ConfigData.MULTIPATH_ERR_NO_HTTP_RESPONSE);
      }

      this.appendLog(`[蜂窝] ✅ 收到完整响应（总长度: ${response.length} 字节）`);
      this.cellularSendCount++;

      // 提取 HTML 内容
      const bodyStart = response.indexOf('\r\n\r\n');
      if (bodyStart !== -1){
        const htmlContent = response.substring(bodyStart + 4);
        this.cellularResponse = htmlContent.length > 500 ? htmlContent.substring(0, 500) + '...' : htmlContent;
      } else {
        this.cellularResponse = response.length > 500 ? response.substring(0, 500) + '...' : response;
      }

      this.cellularStatus = ConfigData.MULTIPATH_HTTP_RESULT_OK;
      this.appendLog('[蜂窝] ✅ 响应内容已显示');

    } catch (error){
      const errorMsg = error instanceof Error ? error.message: JSON.stringify(error);
      this.cellularResponse = `❌ 连接失败: ${errorMsg}`;
      this.appendLog(`[蜂窝] ❌ ${this.cellularResponse}`);
      this.cellularStatus = ConfigData.MULTIPATH_HTTP_RESULT_FAIL;
    } finally {
      try {
        const tcpSocket = this.cellularSocket as socket.TCPSocket;
        if (tcpSocket){
          await tcpSocket.close();
        }
        this.appendLog('[蜂窝] 连接已关闭');
      } catch (e){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s %{public}s', TAG, '关闭蜂窝 TCP Socket失败:', JSON.stringify(e));
      }
      this.cellularSocket = null;
      this.cellularBound = false;
      this.cellularStatus = ConfigData.MULTIPATH_STATUS_DISCONNECTED;
    }
  }



  setupCellularSocketEvents(socketInstance: socket.UDPSocket, label: string){
    socketInstance.on('message', (data) => {
      // 蜂窝模式下，只关心收到的 DNS 响应
      const receivedData = data.message ? data.message.toString() : '';
      const remoteInfo = data.remoteInfo;
      this.appendLog(`[${label}] 收到响应来自 ${remoteInfo.address}:${remoteInfo.port}（长度: ${data.message.byteLength} 字节）`);
    });

    socketInstance.on('error', (err) => {
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `${label} Socket错误: ${JSON.stringify(err)}`);
      this.appendLog(`[${label}] ✗ Socket错误: ${JSON.stringify(err)}`);
    });

    socketInstance.on('close', () => {
      this.appendLog(`[${label}] UDP Socket已关闭`);
      this.cellularBound = false;
    });
  }

  async closeWifiSocket() {
    await this.closeSocket('wifi');
  }

  async closeCellularSocket() {
    await this.closeSocketCellular();
  }

  async closeSocket(path: PathType, log: boolean = true){
    const socketInstance = path === 'wifi' ? this.wifiSocket: this.cellularSocket;
    const label = path === 'wifi' ? ConfigData.HTTP_STR_BEARER_WIFI: ConfigData.MULTIPATH_LABEL_CELLULAR;
    if (!socketInstance){
      return;
    }

    try {
      await socketInstance.close();
      if (log){
        this.appendLog(`[${label}] 主动关闭Socket`);
      }
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `${label} 关闭Socket失败: ${JSON.stringify(error)}`);
      if (log){
        this.appendLog(`[${label}] 关闭Socket失败: ${JSON.stringify(error)}`);
      }
    }

    if (path === 'wifi'){
      this.wifiBound = false;
      this.wifiStatus = ConfigData.MULTIPATH_SOCKET_CLOSED;
    } else {
      this.cellularBound = false;
      this.cellularStatus = ConfigData.MULTIPATH_SOCKET_CLOSED;
    }
  }

  async closeSocketCellular() {
    const label = ConfigData.MULTIPATH_LABEL_CELLULAR;
    if (!this.cellularSocket) return;

    try {
      await this.cellularSocket.close();
      this.appendLog(`[${label}] 主动关闭Socket`);
    } catch (error){
      hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `${label} 关闭Socket失败: ${JSON.stringify(error)}`);
      this.appendLog(`[${label}] 关闭Socket失败: ${JSON.stringify(error)}`);
    }

    this.cellularBound = false;
    this.cellularStatus = ConfigData.MULTIPATH_SOCKET_CLOSED;
    this.cellularSocket = null;
  }

  clearResponse() {
    this.responseData = '';
  }

  appendLog(msg: string){
    if (!this.responseData){
      this.responseData = msg;
    } else {
      this.responseData += `\n${msg}`;
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
          // 网络信息
          Text($r('app.string.wifitest_text_wlyllzt'))
            .fontSize(ConfigData.VP_18)
            .fontWeight(FontWeight.Bold)
            .width(ConfigData.WH_100_100)
            .margin({top: ConfigData.VP_10, bottom: ConfigData.VP_10})

          Row() {
            Text($r('app.string.wifitest_text_wzt'))
              .fontSize(ConfigData.VP_16)
              .width(ConfigData.WH_30_100)
            Text(this.wifiNetworkStatus)
              .fontSize(ConfigData.VP_16)
              .fontColor(this.wifiNetworkStatus.indexOf('正常') >= 0 || this.wifiNetworkStatus.indexOf('可用') >= 0 ?
                $r('app.color.green'): $r('app.color.ui_orange'))
              .width(ConfigData.WH_70_100)
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_8})

          Row() {
            Text($r('app.string.wifitest_text_fwzt_1'))
              .fontSize(ConfigData.VP_16)
              .width(ConfigData.WH_30_100)
            Text(this.cellularNetworkStatus)
              .fontSize(ConfigData.VP_16)
              .fontColor(this.cellularNetworkStatus.indexOf('正常') >= 0 ||
                this.cellularNetworkStatus.indexOf('可用') >= 0 ? $r('app.color.green'): $r('app.color.ui_orange'))
              .width(ConfigData.WH_70_100)
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_10})

          Row() {
            Text($r('app.string.wifitest_text_wjb'))
              .fontSize(ConfigData.VP_16)
              .width(ConfigData.WH_30_100)
            Text(this.wifiHandleInfo)
              .fontSize(ConfigData.VP_16)
              .fontColor(this.wifiNetHandle ? $r('app.color.green'): $r('app.color.red'))
              .width(ConfigData.WH_70_100)
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_8})

          Row() {
            Text($r('app.string.wifitest_text_fwjb'))
              .fontSize(ConfigData.VP_16)
              .width(ConfigData.WH_30_100)
            Text(this.cellularHandleInfo)
              .fontSize(ConfigData.VP_16)
              .fontColor(this.cellularNetHandle ? $r('app.color.green'): $r('app.color.red'))
              .width(ConfigData.WH_70_100)
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_10})

          Button('刷新网络')
            .width(ConfigData.WH_100_100)
            .backgroundColor($r('app.color.main_blue'))
            .onClick(() => {
              this.checkCurrentNetwork();
            })
            .margin({bottom: ConfigData.VP_12})

          // WiFi 链路
          Text($r('app.string.wifitest_text_wllsywn'))
            .fontSize(ConfigData.VP_18)
            .fontWeight(FontWeight.Bold)
            .width(ConfigData.WH_100_100)
            .margin({top: ConfigData.VP_10, bottom: ConfigData.VP_8})

          // WiFi 模式选择
          Row() {
            Text($r('app.string.wifitest_text_yxms_1'))
              .fontSize(ConfigData.VP_16)
              .width(ConfigData.WH_30_100)
            Select(this.modeList)
              .selected(this.wifiModeIndex)
              .value(this.wifiModeValue)
              .font({size: ConfigData.VP_14, weight: ConfigData.FONT_W_400})
              .fontColor($r("app.color.font_color_182431"))
              .selectedOptionFont({size: ConfigData.VP_16, weight: ConfigData.FONT_W_400})
              .optionFont({size: ConfigData.VP_16, weight: ConfigData.FONT_W_400})
              .borderRadius($r('app.float.wh_value_5'))
              .width(ConfigData.WH_70_100)
              .enabled(!this.wifiBound)
              .onSelect((index: number, text?: string) => {
                hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `WiFi模式选择: ${index}`);
                this.wifiModeIndex = index;
                if (text){
                  this.wifiModeValue = text;
                  // 切换模式时调整默认配置
                  if (text === ConfigData.MULTIPATH_DEMO_MODE_SERVER){
                    this.wifiLocalPort = ConfigData.UDP_DEMO_PORT_STR;
                  } else {
                    this.wifiLocalPort = ConfigData.MULTIPATH_WIFI_LOCAL_PORT;
                    this.wifiRemoteAddress = ConfigData.SOCKET_DEMO_LAN_IP;
                    this.wifiRemotePort = ConfigData.MULTIPATH_WIFI_REMOTE_PORT;
                  }
                }
              })
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_8})

          Row() {
            Text($r('app.string.wifitest_text_bddk'))
              .fontSize(ConfigData.VP_16)
              .width(ConfigData.WH_30_100)
            TextInput({text: this.wifiLocalPort})
              .width(ConfigData.WH_70_100)
              .borderRadius($r('app.float.wh_value_5'))
              .type(InputType.Number)
              .onChange((value: string) => {
                this.wifiLocalPort = value;
              })
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_8})

          // Client模式才需要配置目标地址和端口
          if (this.wifiModeValue === ConfigData.MULTIPATH_DEMO_MODE){
            Row() {
              Text($r('app.string.wifitest_text_mbdz'))
                .fontSize(ConfigData.VP_16)
                .width(ConfigData.WH_30_100)
              TextInput({placeholder: $r('app.string.wifitest_text_wjywi'), text: this.wifiRemoteAddress})
                .width(ConfigData.WH_70_100)
                .borderRadius($r('app.float.wh_value_5'))
                .onChange((value: string) => {
                  this.wifiRemoteAddress = value;
                })
            }
            .width(ConfigData.WH_100_100)
            .margin({bottom: ConfigData.VP_8})

            Row() {
              Text($r('app.string.wifitest_text_mbdk'))
                .fontSize(ConfigData.VP_16)
                .width(ConfigData.WH_30_100)
              TextInput({text: this.wifiRemotePort})
                .width(ConfigData.WH_70_100)
                .borderRadius($r('app.float.wh_value_5'))
                .type(InputType.Number)
                .onChange((value: string) => {
                  this.wifiRemotePort = value;
                })
            }
            .width(ConfigData.WH_100_100)
            .margin({bottom: ConfigData.VP_8})
          }

          Row() {
            Text($r('app.string.wifitest_text_llzt'))
              .fontSize(ConfigData.VP_16)
              .width(ConfigData.WH_30_100)
            Text(`[${this.wifiModeValue}] ${this.wifiStatus}`)
              .fontSize(ConfigData.VP_16)
              .fontColor(this.wifiBound ? $r('app.color.green'): $r('app.color.red'))
              .width(ConfigData.WH_70_100)
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_8})

          Row() {
            Text($r('app.string.wifitest_text_fsjs'))
              .fontSize(ConfigData.VP_14)
              .width(ConfigData.WH_30_100)
            Text(`${this.wifiSendCount} / ${this.wifiReceiveCount}`)
              .fontSize(ConfigData.VP_14)
              .fontColor($r('app.color.main_blue'))
              .width(ConfigData.WH_70_100)
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_8})

          if (this.wifiReconnectCount > 0){
            Row() {
              Text($r('app.string.wifitest_text_zlcs'))
                .fontSize(ConfigData.VP_14)
                .width(ConfigData.WH_30_100)
              Text(`${this.wifiReconnectCount}`)
                .fontSize(ConfigData.VP_14)
                .fontColor($r('app.color.ui_orange'))
                .width(ConfigData.WH_70_100)
            }
            .width(ConfigData.WH_100_100)
            .margin({bottom: ConfigData.VP_8})
          }

          // 根据模式显示不同的按钮组合
          if (this.wifiModeValue === ConfigData.MULTIPATH_DEMO_MODE){
            Row() {
              Button('绑定WiFi')
                .width(ConfigData.PCT_32)
                .backgroundColor(this.wifiBound ? $r('app.color.color_999999_grey'): $r('app.color.main_blue'))
                .enabled(!this.wifiBound)
                .onClick(() => {
                  this.bindWifiSocket();
                })

              Button('发送WiFi')
                .width(ConfigData.PCT_32)
                .backgroundColor(this.wifiBound ? $r('app.color.green'): $r('app.color.color_999999_grey'))
                .enabled(this.wifiBound)
                .onClick(() => {
                  this.sendOnWifi();
                })

              Button('关闭WiFi')
                .width(ConfigData.PCT_32)
                .backgroundColor(this.wifiBound ? $r('app.color.red'): $r('app.color.color_999999_grey'))
                .enabled(this.wifiBound)
                .onClick(() => {
                  this.closeWifiSocket();
                })
            }
            .width(ConfigData.WH_100_100)
            .justifyContent(FlexAlign.SpaceBetween)
            .margin({bottom: ConfigData.VP_16})
          } else {
            // Server模式：启动/关闭
            Row() {
              Button('启动Server')
                .width(ConfigData.PCT_48)
                .backgroundColor(this.wifiBound ? $r('app.color.color_999999_grey'): $r('app.color.main_blue'))
                .enabled(!this.wifiBound)
                .onClick(() => {
                  this.bindWifiSocket();
                })

              Button('关闭Server')
                .width(ConfigData.PCT_48)
                .backgroundColor(this.wifiBound ? $r('app.color.red'): $r('app.color.color_999999_grey'))
                .enabled(this.wifiBound)
                .onClick(() => {
                  this.closeWifiSocket();
                })
            }
            .width(ConfigData.WH_100_100)
            .justifyContent(FlexAlign.SpaceBetween)
            .margin({bottom: ConfigData.VP_16})
          }

          // 蜂窝链路
          Text($r('app.string.wifitest_text_fwllzjfwgwd'))
            .fontSize(ConfigData.VP_18)
            .fontWeight(FontWeight.Bold)
            .width(ConfigData.WH_100_100)
            .margin({top: ConfigData.VP_5, bottom: ConfigData.VP_8})

          // 蜂窝本地端口（可配置）
          Row() {
            Text($r('app.string.wifitest_text_bddk'))
              .fontSize(ConfigData.VP_16)
              .width(ConfigData.WH_30_100)
            TextInput({text: this.cellularLocalPort})
              .width(ConfigData.WH_70_100)
              .borderRadius($r('app.float.wh_value_5'))
              .type(InputType.Number)
              .onChange((value: string) => {
                this.cellularLocalPort = value;
              })
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_8})

          // 链路状态（无 Client/Server 选项）
          Row() {
            Text($r('app.string.wifitest_text_llzt'))
              .fontSize(ConfigData.VP_16)
              .width(ConfigData.WH_30_100)
            Text(this.cellularStatus)
              .fontSize(ConfigData.VP_16)
              .fontColor(this.cellularBound ? $r('app.color.green'): $r('app.color.red'))
              .width(ConfigData.WH_70_100)
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_8})

          Row() {
            Text($r('app.string.wifitest_text_fscs'))
              .fontSize(ConfigData.VP_14)
              .width(ConfigData.WH_30_100)
            Text(`${this.cellularSendCount}`)
              .fontSize(ConfigData.VP_14)
              .fontColor($r('app.color.main_blue'))
              .width(ConfigData.WH_70_100)
          }
          .width(ConfigData.WH_100_100)
          .margin({bottom: ConfigData.VP_8})

          // 三个按钮：绑定 / 发送 / 关闭
          Row() {
            Button('绑定蜂窝')
              .width(ConfigData.PCT_32)
              .backgroundColor(this.cellularBound ? $r('app.color.color_999999_grey'): $r('app.color.main_blue'))
              .enabled(!this.cellularBound)
              .onClick(() => {
                this.bindSocketCellular();
              })

            Button('发送到百度')
              .width(ConfigData.PCT_32)
              .backgroundColor(this.cellularBound ? $r('app.color.green'): $r('app.color.color_999999_grey'))
              .enabled(this.cellularBound)
              .onClick(() => {
                this.sendMessageCellular();
              })

            Button('关闭蜂窝')
              .width(ConfigData.PCT_32)
              .backgroundColor(this.cellularBound ? $r('app.color.red'): $r('app.color.color_999999_grey'))
              .enabled(this.cellularBound)
              .onClick(() => {
                this.closeCellularSocket();
              })
          }
          .width(ConfigData.WH_100_100)
          .justifyContent(FlexAlign.SpaceBetween)
          .margin({bottom: ConfigData.VP_16})

          // 显示 DNS 响应（Hex）
          if (this.cellularResponse){
            Text($r('app.string.wifitest_text_dxyh'))
              .fontSize(ConfigData.VP_16)
              .fontWeight(FontWeight.Bold)
              .width(ConfigData.WH_100_100)
              .margin({bottom: ConfigData.VP_5})

            TextArea({text: this.cellularResponse})
              .width(ConfigData.WH_100_100)
              .height(ConfigData.WH_15_100)
              .borderRadius($r('app.float.wh_value_5'))
              .backgroundColor($r('app.color.white'))
              .margin({bottom: ConfigData.VP_15})
          }

          // 公共操作
          Row() {
            // 只有双Client模式才显示双路发送按钮
            if (this.wifiModeValue === ConfigData.MULTIPATH_DEMO_MODE && this.cellularModeValue === ConfigData.MULTIPATH_DEMO_MODE){
              Button('双路发送')
                .width(ConfigData.PCT_48)
                .backgroundColor((this.wifiBound || this.cellularBound) ? $r('app.color.green'): $r('app.color.color_999999_grey'))
                .enabled(this.wifiBound || this.cellularBound)
                .onClick(() => {
                  this.sendBoth();
                })
            }

            Button('清空日志')
              .width(this.wifiModeValue === ConfigData.MULTIPATH_DEMO_MODE && this.cellularModeValue === ConfigData.MULTIPATH_DEMO_MODE ? ConfigData.PCT_48: ConfigData.WH_100_100)
              .backgroundColor($r('app.color.ui_orange'))
              .onClick(() => {
                this.clearResponse();
              })
          }
          .width(ConfigData.WH_100_100)
          .justifyContent(FlexAlign.SpaceBetween)
          .margin({bottom: ConfigData.VP_12})

          // 消息输入区域（Client模式才需要）
          if (this.wifiModeValue === ConfigData.MULTIPATH_DEMO_MODE || this.cellularModeValue === ConfigData.MULTIPATH_DEMO_MODE){
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
          }

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
    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '页面即将销毁，清理资源...');

    // 1. 取消网络监听
    if (this.netConnection){
      try {
        this.netConnection.unregister((error: Error) => {
          if (error){
            hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `取消网络注册订阅事件失败: ${JSON.stringify(error)}`);
          } else {
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '网络注册订阅事件已取消');
          }
        });
      } catch (error){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `取消网络注册订阅事件异常: ${JSON.stringify(error)}`);
      }
      this.netConnection = null;
    }

    if (this.netConnectionCellular){
      try {
        this.netConnectionCellular.unregister((error: Error) => {
          if (error){
            hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `取消蜂窝网络注册订阅事件失败: ${JSON.stringify(error)}`);
          } else {
            hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '蜂窝网络注册订阅事件已取消');
          }
        });
      } catch (error){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `取消蜂窝网络注册订阅事件异常: ${JSON.stringify(error)}`);
      }
      this.netConnectionCellular = null;
    }

    // 2. 关闭并清理WiFi Socket
    if (this.wifiSocket){
      try {
        this.wifiSocket.close();
      } catch (e){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `关闭WiFi Socket异常: ${JSON.stringify(e)}`);
      }
      this.wifiSocket = null;
      this.wifiBound = false;
    }

    // 3. 关闭并清理蜂窝Socket
    if (this.cellularSocket){
      try {
        this.cellularSocket.close();
      } catch (e){
        hilog.error(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, `关闭蜂窝Socket异常: ${JSON.stringify(e)}`);
      }
      this.cellularSocket = null;
      this.cellularBound = false;
    }

    // 4. 清理netHandle引用
    this.wifiNetHandle = null;
    this.cellularNetHandle = null;

    hilog.info(0x1500, 'wifiTestApp', '%{public}s %{public}s', TAG, '资源清理完成');

    //5.关闭多网请求
    this.releaseMultiPath();
  }
}

