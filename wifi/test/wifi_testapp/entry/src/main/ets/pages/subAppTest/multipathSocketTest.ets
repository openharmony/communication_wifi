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
import TextDecoder from '@ohos.util';
import { netHandover } from '@kit.NetworkBoostKit';
import connection from '@ohos.net.connection';
import ConfigData from '../../utils/ConfigData';
import { TestImageDisplay } from '../../Component/testImageDisplay';
import { PageTitle } from '../../Component/pageTitle';
import { TestData } from '../../entryability/model/testData'
import router from '@ohos.router';
import { BusinessError } from '@ohos.base';

interface myParams extends Object {
  testItem: TestData
}

export interface NetAddress {
  address: string;
  family?: number;
  port?: number;
}

type PathType = 'wifi' | 'cellular';
type ModeType = 'Client' | 'Server';

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
  @State wifiModeValue: string = 'Client';
  @State cellularModeIndex: number = 0;
  @State cellularModeValue: string = 'Client';
  @State modeList: Array<SelectOption> = [
    { value: 'Client' },
    { value: 'Server' }
  ];
  // WiFi链路配置
  @State wifiRemoteAddress: string = '192.168.1.100';
  @State wifiRemotePort: string = '8081';
  @State wifiLocalPort: string = '12000';
  // 蜂窝链路配置
  @State cellularRemoteAddress: string = '8.8.8.8';
  @State cellularRemotePort: string = '8082';
  @State cellularLocalPort: string = '12001';
  @State cellularResponse: string = ''; // 用于显示 DNS 响应
  // 通用状态
  @State message: string = 'Hello Multipath';
  @State responseData: string = '';
  @State wifiNetworkStatus: string = '检测中...';
  @State cellularNetworkStatus: string = '检测中...';
  @State wifiStatus: string = '未绑定';
  @State cellularStatus: string = '未绑定';
  @State wifiHandleInfo: string = '未获取';
  @State cellularHandleInfo: string = '未获取';
  @State wifiBound: boolean = false;
  @State cellularBound: boolean = false;
  @State wifiReconnectCount: number = 0;
  @State cellularReconnectCount: number = 0;
  @State wifiSendCount: number = 0;
  @State cellularSendCount: number = 0;
  @State wifiReceiveCount: number = 0;
  @State cellularReceiveCount: number = 0;
  private wifiSocket: socket.UDPSocket | null = null;
  private cellularSocket: socket.TCPSocket | null = null; // ✅ 改为 TCP
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
      .map(b => b.toString(16).padStart(2, '0'))
      .join(' ');
  }

  // 将family字符串转换为数字（1 for IPv4, 2 for IPv6）
  convertFamilyToNumber(family: string | number | undefined): number {
    if (typeof family === 'number') {
      return family;
    }
    if (family === 'IPv6') {
      return 2;
    }
    return 1; // 默认为IPv4
  }

  requestMultiPath() {
    try {
      netHandover.requestMultiPath((data: netHandover.MultiPathRequestResult) => {
        console.info(` zly20000requestMultiPath result:` + JSON.stringify(data));
      });
    } catch (err) {
      console.error('zly20001errCode: ' + (err as BusinessError).code + ', errMessage: ' + (err as BusinessError).message);
    }
  }

  releaseMultiPath() {
    try {
      netHandover.releaseMultiPath();
    } catch (err) {
      console.error('zly20002errCode: ' + (err as BusinessError).code + ', errMessage: ' + (err as BusinessError).message);
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
        if (error) {
          console.error(TAG, `注册WiFi网络监听失败: ${JSON.stringify(error)}`);
          this.wifiNetworkStatus = 'WiFi监听注册失败';
        } else {
          console.log(TAG, 'WiFi网络监听已注册');
        }
      });

      this.netConnection.on('netAvailable', (netHandle: connection.NetHandle) => {
        console.log(TAG, `WiFi网络可用: netId=${netHandle.netId}`);
        this.wifiNetworkStatus = 'WiFi网络可用';
        this.handleWifiNetworkChange();
      });

      this.netConnection.on('netCapabilitiesChange', (netCapabilityInfo: connection.NetCapabilityInfo) => {
        console.log(TAG, `WiFi网络能力变化: ${JSON.stringify(netCapabilityInfo)}`);
        this.handleWifiNetworkChange();
      });

      this.netConnection.on('netLost', (netHandle: connection.NetHandle) => {
        console.log(TAG, `WiFi网络丢失: netId=${netHandle.netId}`);
        this.wifiNetworkStatus = 'WiFi网络断开';
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
        if (error) {
          console.error(TAG, `注册蜂窝网络监听失败: ${JSON.stringify(error)}`);
          this.cellularNetworkStatus = '蜂窝监听注册失败';
        } else {
          console.log(TAG, '蜂窝网络监听已注册');
        }
      });

      // 订阅网络可用事件。调用register后，才能接收到此事件通知
      this.netConnectionCellular.on('netAvailable', (netHandle: connection.NetHandle) => {
        console.log(TAG, `蜂窝网络可用: netId=${netHandle.netId}`);
        this.cellularNetworkStatus = '蜂窝网络可用';
        this.handleCellularNetworkChange();
      });

      this.netConnectionCellular.on('netCapabilitiesChange', (netCapabilityInfo: connection.NetCapabilityInfo) => {
        console.log(TAG, `蜂窝网络能力变化: ${JSON.stringify(netCapabilityInfo)}`);
        this.handleCellularNetworkChange();
      });

      this.netConnectionCellular.on('netLost', (netHandle: connection.NetHandle) => {
        console.log(TAG, `蜂窝网络丢失: netId=${netHandle.netId}`);
        this.cellularNetworkStatus = '蜂窝网络断开';
        this.appendLog('[蜂窝] 网络连接丢失');
      });

    } catch (error) {
      console.error(TAG, `创建网络监听失败: ${JSON.stringify(error)}`);
      this.wifiNetworkStatus = 'WiFi监听创建失败';
      this.cellularNetworkStatus = '蜂窝监听创建失败';
    }
  }

  // 双路网络检测
  async checkCurrentNetwork() {
    this.wifiNetworkStatus = '检测中...';
    this.cellularNetworkStatus = '检测中...';
    this.wifiNetHandle = null;
    this.cellularNetHandle = null;
    this.wifiHandleInfo = '未获取';
    this.cellularHandleInfo = '未获取';

    try {
      // 优先使用同步API
      let handles: connection.NetHandle[] = [];
      try {
        handles = connection.getAllNetsSync();
      } catch (syncErr) {
        console.log(TAG, 'getAllNets同步API不可用，尝试异步');
        try {
          handles = await connection.getAllNets();
        } catch (asyncErr) {
          console.log(TAG, 'getAllNets异步API不可用，使用默认网络');
          const defaultNet = await connection.getDefaultNet();
          if (defaultNet && defaultNet.netId !== 0) {
            handles = [defaultNet];
          }
        }
      }

      for (const handle of handles) {
        // netId为0表示无有效网络，跳过
        if (!handle || handle.netId === 0) {
          continue;
        }

        try {
          const netCapabilities = await connection.getNetCapabilities(handle);
          if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_WIFI) && !this.wifiNetHandle) {
            this.wifiNetHandle = handle;
            this.wifiHandleInfo = `netId=${handle.netId}`;
            this.wifiNetworkStatus = 'WiFi网络正常';
          }
          if (netCapabilities.bearerTypes.includes(connection.NetBearType.BEARER_CELLULAR) && !this.cellularNetHandle) {
            this.cellularNetHandle = handle;
            this.cellularHandleInfo = `netId=${handle.netId}`;
            this.cellularNetworkStatus = '蜂窝网络正常';
          }
        } catch (capErr) {
          console.error(TAG, `获取网络能力失败: ${JSON.stringify(capErr)}`);
        }
      }

      if (!this.wifiNetHandle) {
        this.wifiNetworkStatus = 'WiFi无可用网络';
      }
      if (!this.cellularNetHandle) {
        this.cellularNetworkStatus = '蜂窝无可用网络';
      }

      if (!this.wifiNetHandle && !this.cellularNetHandle) {
        this.appendLog('[系统] 未检测到WiFi或蜂窝网络');
        return;
      }

      this.appendLog(`[系统] 网络刷新完成 - WiFi:${this.wifiHandleInfo}(${this.wifiNetworkStatus}), 蜂窝:${this.cellularHandleInfo}(${this.cellularNetworkStatus})`);
    } catch (error) {
      console.error(TAG, `获取网络状态失败: ${JSON.stringify(error)}`);
      this.wifiNetworkStatus = 'WiFi获取失败';
      this.cellularNetworkStatus = '蜂窝获取失败';
      this.appendLog('[系统] 获取网络状态失败');
    }
  }

  // WiFi网络变化处理：重新检测并按需重绑
  handleWifiNetworkChange() {
    this.appendLog('[WiFi] 检测到WiFi网络变化，刷新链路中...');
    const wasWifiBound = this.wifiBound;

    this.checkCurrentNetwork().then(() => {
      // WiFi链路：如果之前已绑定且新netHandle有效，尝试重建
      if (wasWifiBound && this.wifiNetHandle && this.wifiNetHandle.netId !== 0) {
        this.wifiReconnectCount++;
        this.appendLog(`[WiFi] 开始重建连接(第${this.wifiReconnectCount}次)`);
        this.rebindSocket('wifi');
      } else if (wasWifiBound && !this.wifiNetHandle) {
        this.wifiBound = false;
        this.wifiStatus = 'WiFi网络丢失';
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
      if (wasCellularBound && this.cellularNetHandle && this.cellularNetHandle.netId !== 0) {
        this.cellularReconnectCount++;
        this.appendLog(`[蜂窝] 开始重建连接(第${this.cellularReconnectCount}次)`);
        this.rebindSocket('cellular');
      } else if (wasCellularBound && !this.cellularNetHandle) {
        this.cellularBound = false;
        this.cellularStatus = '蜂窝网络丢失';
        this.appendLog('[蜂窝] 网络丢失，已断开');
      }
    });
  }

  async rebindSocket(path: PathType) {
    await this.closeSocket(path, false);
    setTimeout(() => {
      this.bindSocket(path);
    }, 500); // 延迟500ms等待网络稳定
  }

  async bindWifiSocket() {
    await this.bindSocket('wifi');
  }

  async bindCellularSocket() {
    await this.bindSocketCellular();
  }

  async bindSocket(path: PathType) {
    const targetHandle = path === 'wifi' ? this.wifiNetHandle : this.cellularNetHandle;
    const targetPort = path === 'wifi' ? parseInt(this.wifiLocalPort) : parseInt(this.cellularLocalPort);
    const label = path === 'wifi' ? 'WiFi' : '蜂窝';

    if (!targetHandle || targetHandle.netId === 0) {
      this.appendLog(`[${label}] 未找到有效的netHandle(netId=${targetHandle?.netId})，请先刷新网络`);
      if (path === 'wifi') {
        this.wifiStatus = 'netHandle无效';
      } else {
        this.cellularStatus = 'netHandle无效';
      }
      return;
    }

    // 1. 关闭旧socket
    const existingSocket = path === 'wifi' ? this.wifiSocket : this.cellularSocket;
    if (existingSocket) {
      try {
        await existingSocket.close();
      } catch (e) {
        console.error(TAG, `关闭旧${label} Socket失败: ${JSON.stringify(e)}`);
      }
    }

    // 2. 创建新socket
    const socketInstance = socket.constructUDPSocketInstance();
    if (path === 'wifi') {
      this.wifiSocket = socketInstance;
      this.wifiStatus = '绑定中...';
    }

    try {
      // 3. 先bind本地端口（重要！必须在bindSocket之前）
      const bindAddress: NetAddress = {
        address: '0.0.0.0',
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

      if (bindSuccess) {
        if (path === 'wifi') {
          this.wifiBound = true;
          this.wifiStatus = `已绑定(${this.wifiHandleInfo})`;
        } else {
          this.cellularBound = true;
          this.cellularStatus = `已绑定(${this.cellularHandleInfo})`;
        }
        this.appendLog(`[${label}] ✓ 绑定流程完成`);
      } else {
        throw new Error('bindSocket失败');
      }
    } catch (error) {
      console.error(TAG, `绑定${label} Socket失败: ${JSON.stringify(error)}`);
      this.appendLog(`[${label}] ✗ 绑定失败: ${JSON.stringify(error)}`);

      // 绑定失败，清理socket
      try {
        await socketInstance.close();
      } catch (e) {
        // ignore
      }

      if (path === 'wifi') {
        this.wifiSocket = null;
        this.wifiBound = false;
        this.wifiStatus = '绑定失败';
      } else {
        this.cellularSocket = null;
        this.cellularBound = false;
        this.cellularStatus = '绑定失败';
      }
    }
  }

  async bindSocketCellular() {
    const label = '蜂窝';

    // 关闭旧 socket（如果存在）
    if (this.cellularSocket) {
      try {
        await this.cellularSocket.close();
      } catch (e) {
        console.error(TAG, `关闭旧${label} Socket失败: ${JSON.stringify(e)}`);
      }
    }

    // 创建新的 TCP Socket
    const socketInstance = socket.constructTCPSocketInstance();
    this.cellularSocket = socketInstance;
    this.cellularStatus = '初始化中...';

    try {
      // 设置 TCP 选项（参考你提供的大纲）
      socketInstance.setExtraOptions({
        receiveBufferSize: 8192,
        sendBufferSize: 8192,
        reuseAddress: true,
        socketTimeout: 60000
      });

      this.cellularBound = true;
      this.cellularStatus = '已准备（TCP Socket就绪）';
      this.appendLog('[蜂窝] ✓ TCP Socket 初始化完成，等待连接百度');
    } catch (error) {
      console.error(TAG, `初始化蜂窝 TCP Socket失败: ${JSON.stringify(error)}`);
      this.appendLog('[蜂窝] ✗ 初始化失败: ' + JSON.stringify(error));
      this.cellularSocket = null;
      this.cellularBound = false;
      this.cellularStatus = '初始化失败';
    }
  }

  async applyNetHandleToSocket(socketInstance: socket.UDPSocket, netHandle: connection.NetHandle, label: string): Promise<boolean> {
    // 直接使用 netHandle.bindSocket（参考官方示例）
    try {
      await new Promise<void>((resolve, reject) => {
        netHandle.bindSocket(socketInstance, (error: BusinessError) => {
          if (error) {
            reject(error);
            console.error(TAG, `${label} 通过netHandle.bindSocket绑定失败,error: ${JSON.stringify(error)}`);
          } else {
            resolve();
          }
        });
      });
      this.appendLog(`[${label}] 步骤3: 已绑定到netId=${netHandle.netId} (netHandle.bindSocket)`);
      return true;
    } catch (err) {
      console.error(TAG, `${label} 通过netHandle.bindSocket绑定失败,err: ${JSON.stringify(err)}`);
      return false;
    }
  }

  setupSocketEvents(socketInstance: socket.UDPSocket, label: string) {
    socketInstance.on('message', (data) => {
      const receivedData = data.message ? data.message.toString() : '';
      const remoteInfo = data.remoteInfo;
      const isWifi = label === 'WiFi';
      const currentMode = isWifi ? this.wifiModeValue : this.cellularModeValue;

      // 更新接收计数
      if (isWifi) {
        this.wifiReceiveCount++;
      } else {
        this.cellularReceiveCount++;
      }

      const receiveCount = isWifi ? this.wifiReceiveCount : this.cellularReceiveCount;
      this.appendLog(`[${label}][${currentMode}] 收到 #${receiveCount}: ${receivedData} (来自: ${remoteInfo.address}:${remoteInfo.port})`);

      // Server模式：自动回复
      if (currentMode === 'Server') {
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
          console.error(TAG, `${label} Server回复失败: ${JSON.stringify(err)}`);
          this.appendLog(`[${label}][Server] ✗ 回复失败: ${JSON.stringify(err)}`);
        });
      }
    });

    socketInstance.on('error', (err) => {
      console.error(TAG, `${label} Socket错误: ${JSON.stringify(err)}`);
      this.appendLog(`[${label}] ✗ Socket错误: ${JSON.stringify(err)}`);
    });

    socketInstance.on('listening', () => {
      this.appendLog(`[${label}] UDP Socket开始监听`);
    });

    socketInstance.on('close', () => {
      this.appendLog(`[${label}] UDP Socket已关闭`);
      // 清理状态
      if (label === 'WiFi') {
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

  async sendMessage(path: PathType) {
    const socketInstance = path === 'wifi' ? this.wifiSocket : this.cellularSocket;
    const bound = path === 'wifi' ? this.wifiBound : this.cellularBound;
    const label = path === 'wifi' ? 'WiFi' : '蜂窝';
    const targetAddress = path === 'wifi' ? this.wifiRemoteAddress : this.cellularRemoteAddress;
    const targetPort = path === 'wifi' ? parseInt(this.wifiRemotePort) : parseInt(this.cellularRemotePort);

    if (!socketInstance || !bound) {
      this.appendLog(`[${label}] ✗ 错误: Socket未绑定`);
      return;
    }

    try {
      // 生成序列号
      const seq = path === 'wifi' ? ++this.wifiPacketSeq : ++this.cellularPacketSeq;
      const timestamp = new Date().toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 });

      // 根据路径区分发送方式
      if (path === 'wifi') {
        // ✅ WiFi 是 UDP，需要 address
        const udpSocket = socketInstance as socket.UDPSocket; // ✅ 类型断言为 UDPSocket
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
        console.log(TAG, `${label} 发送数据包 #${seq}: ${dataToSend}`);

        this.wifiSendCount++; // 只有 WiFi 才递增
      } else {
        // ✅ 蜂窝是 TCP，不需要 address
        const tcpSocket = socketInstance as socket.TCPSocket; // ✅ 类型断言为 TCPSocket
        const dataToSend = `[${label}] [SEQ:${seq}] [TIME:${timestamp}] ${this.message}`;

        await tcpSocket.send({
          data: dataToSend
        });

        this.appendLog(`[${label}] 发送数据包 #${seq} (TCP)`);
        console.log(TAG, `${label} 发送 TCP 数据: ${dataToSend}`);

        this.cellularSendCount++; // 只有蜂窝才递增
      }

    } catch (error) {
      console.error(TAG, `${label} 发送失败: ${JSON.stringify(error)}`);
      this.appendLog(`[${label}] ✗ 发送失败: ${JSON.stringify(error)}`);
    }
  }

  async sendMessageCellular() {
    if (!this.cellularSocket || !this.cellularBound) {
      this.appendLog('[蜂窝] ✗ TCP Socket未初始化，请先点击“绑定蜂窝”');
      this.cellularStatus = '未初始化';
      return;
    }

    this.cellularStatus = '连接中...';
    this.cellularResponse = '';
    this.appendLog('[蜂窝] 正在连接百度服务器...');

    const host = 'www.baidu.com';
    const port = 80;

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
        for (let i = 0; i < uint8Array.length; i++) {
          dataStr += String.fromCharCode(uint8Array[i]);
        }

        response += dataStr;
        hasReceivedData = true;

        this.appendLog(`[蜂窝] 接收到 ${message.byteLength} 字节数据`);

        if (info.remoteInfo) {
          console.log(`[蜂窝] 来自 ${info.remoteInfo.address}:${info.remoteInfo.port}`);
        }
      });

      // ✅ 监听连接关闭
      tcpSocket.on('close', () => {
        isClosed = true;
        this.appendLog('[蜂窝] ✅ 连接已关闭');
      });

      // ✅ 监听错误
      tcpSocket.on('error', (err: Error) => {
        if (!isClosed) {
          this.appendLog(`[蜂窝] ❌ 收到错误: ${err.message}`);
        }
      });

      // ✅ 等待连接关闭（通过事件触发）
      await new Promise<void>((resolve) => {
        const checkClosed = () => {
          if (isClosed) {
            resolve();
          } else {
            setTimeout(checkClosed, 50); // 每50ms检查一次
          }
        };
        checkClosed();
      });

      // ✅ 检查是否收到数据
      if (!hasReceivedData) {
        throw new Error('未收到任何响应数据');
      }

      this.appendLog(`[蜂窝] ✅ 收到完整响应（总长度: ${response.length} 字节）`);
      this.cellularSendCount++;

      // 提取 HTML 内容
      const bodyStart = response.indexOf('\r\n\r\n');
      if (bodyStart !== -1) {
        const htmlContent = response.substring(bodyStart + 4);
        this.cellularResponse = htmlContent.length > 500 ? htmlContent.substring(0, 500) + '...' : htmlContent;
      } else {
        this.cellularResponse = response.length > 500 ? response.substring(0, 500) + '...' : response;
      }

      this.cellularStatus = '访问成功';
      this.appendLog('[蜂窝] ✅ 响应内容已显示');

    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : JSON.stringify(error);
      this.cellularResponse = `❌ 连接失败: ${errorMsg}`;
      this.appendLog(`[蜂窝] ❌ ${this.cellularResponse}`);
      this.cellularStatus = '访问失败';
    } finally {
      try {
        const tcpSocket = this.cellularSocket as socket.TCPSocket;
        if (tcpSocket) {
          await tcpSocket.close();
        }
        this.appendLog('[蜂窝] 连接已关闭');
      } catch (e) {
        console.error(TAG, '关闭蜂窝 TCP Socket失败:', JSON.stringify(e));
      }
      this.cellularSocket = null;
      this.cellularBound = false;
      this.cellularStatus = '已断开';
    }
  }



  setupCellularSocketEvents(socketInstance: socket.UDPSocket, label: string) {
    socketInstance.on('message', (data) => {
      // 蜂窝模式下，只关心收到的 DNS 响应
      const receivedData = data.message ? data.message.toString() : '';
      const remoteInfo = data.remoteInfo;
      this.appendLog(`[${label}] 收到响应来自 ${remoteInfo.address}:${remoteInfo.port}（长度: ${data.message.byteLength} 字节）`);
    });

    socketInstance.on('error', (err) => {
      console.error(TAG, `${label} Socket错误: ${JSON.stringify(err)}`);
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

  async closeSocket(path: PathType, log: boolean = true) {
    const socketInstance = path === 'wifi' ? this.wifiSocket : this.cellularSocket;
    const label = path === 'wifi' ? 'WiFi' : '蜂窝';
    if (!socketInstance) {
      return;
    }

    try {
      await socketInstance.close();
      if (log) {
        this.appendLog(`[${label}] 主动关闭Socket`);
      }
    } catch (error) {
      console.error(TAG, `${label} 关闭Socket失败: ${JSON.stringify(error)}`);
      if (log) {
        this.appendLog(`[${label}] 关闭Socket失败: ${JSON.stringify(error)}`);
      }
    }

    if (path === 'wifi') {
      this.wifiBound = false;
      this.wifiStatus = '已关闭';
    } else {
      this.cellularBound = false;
      this.cellularStatus = '已关闭';
    }
  }

  async closeSocketCellular() {
    const label = '蜂窝';
    if (!this.cellularSocket) return;

    try {
      await this.cellularSocket.close();
      this.appendLog(`[${label}] 主动关闭Socket`);
    } catch (error) {
      console.error(TAG, `${label} 关闭Socket失败: ${JSON.stringify(error)}`);
      this.appendLog(`[${label}] 关闭Socket失败: ${JSON.stringify(error)}`);
    }

    this.cellularBound = false;
    this.cellularStatus = '已关闭';
    this.cellularSocket = null;
  }

  clearResponse() {
    this.responseData = '';
  }

  appendLog(msg: string) {
    if (!this.responseData) {
      this.responseData = msg;
    } else {
      this.responseData += `\n${msg}`;
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
          // 网络信息
          Text('网络与链路状态')
            .fontSize(18)
            .fontWeight(FontWeight.Bold)
            .width('100%')
            .margin({ top: 10, bottom: 10 })

          Row() {
            Text('WiFi状态: ')
              .fontSize(16)
              .width('30%')
            Text(this.wifiNetworkStatus)
              .fontSize(16)
              .fontColor(this.wifiNetworkStatus.indexOf('正常') >= 0 || this.wifiNetworkStatus.indexOf('可用') >= 0 ?
                Color.Green : Color.Orange)
              .width('70%')
          }
          .width('100%')
          .margin({ bottom: 8 })

          Row() {
            Text('蜂窝状态: ')
              .fontSize(16)
              .width('30%')
            Text(this.cellularNetworkStatus)
              .fontSize(16)
              .fontColor(this.cellularNetworkStatus.indexOf('正常') >= 0 ||
                this.cellularNetworkStatus.indexOf('可用') >= 0 ? Color.Green : Color.Orange)
              .width('70%')
          }
          .width('100%')
          .margin({ bottom: 10 })

          Row() {
            Text('WiFi句柄: ')
              .fontSize(16)
              .width('30%')
            Text(this.wifiHandleInfo)
              .fontSize(16)
              .fontColor(this.wifiNetHandle ? Color.Green : Color.Red)
              .width('70%')
          }
          .width('100%')
          .margin({ bottom: 8 })

          Row() {
            Text('蜂窝句柄: ')
              .fontSize(16)
              .width('30%')
            Text(this.cellularHandleInfo)
              .fontSize(16)
              .fontColor(this.cellularNetHandle ? Color.Green : Color.Red)
              .width('70%')
          }
          .width('100%')
          .margin({ bottom: 10 })

          Button('刷新网络')
            .width('100%')
            .backgroundColor(Color.Blue)
            .onClick(() => {
              this.checkCurrentNetwork();
            })
            .margin({ bottom: 12 })

          // WiFi 链路
          Text('WiFi链路(使用WiFi netHandle)')
            .fontSize(18)
            .fontWeight(FontWeight.Bold)
            .width('100%')
            .margin({ top: 10, bottom: 8 })

          // WiFi 模式选择
          Row() {
            Text('运行模式: ')
              .fontSize(16)
              .width('30%')
            Select(this.modeList)
              .selected(this.wifiModeIndex)
              .value(this.wifiModeValue)
              .font({ size: 14, weight: 400 })
              .fontColor('#182431')
              .selectedOptionFont({ size: 16, weight: 400 })
              .optionFont({ size: 16, weight: 400 })
              .borderRadius(5)
              .width('70%')
              .enabled(!this.wifiBound)
              .onSelect((index: number, text?: string) => {
                console.log(TAG, `WiFi模式选择: ${index}`);
                this.wifiModeIndex = index;
                if (text) {
                  this.wifiModeValue = text;
                  // 切换模式时调整默认配置
                  if (text === 'Server') {
                    this.wifiLocalPort = '8081';
                  } else {
                    this.wifiLocalPort = '12000';
                    this.wifiRemoteAddress = '192.168.1.100';
                    this.wifiRemotePort = '8081';
                  }
                }
              })
          }
          .width('100%')
          .margin({ bottom: 8 })

          Row() {
            Text('本地端口: ')
              .fontSize(16)
              .width('30%')
            TextInput({ text: this.wifiLocalPort })
              .width('70%')
              .borderRadius(5)
              .type(InputType.Number)
              .onChange((value: string) => {
                this.wifiLocalPort = value;
              })
          }
          .width('100%')
          .margin({ bottom: 8 })

          // Client模式才需要配置目标地址和端口
          if (this.wifiModeValue === 'Client') {
            Row() {
              Text('目标地址: ')
                .fontSize(16)
                .width('30%')
              TextInput({ placeholder: 'WiFi局域网IP', text: this.wifiRemoteAddress })
                .width('70%')
                .borderRadius(5)
                .onChange((value: string) => {
                  this.wifiRemoteAddress = value;
                })
            }
            .width('100%')
            .margin({ bottom: 8 })

            Row() {
              Text('目标端口: ')
                .fontSize(16)
                .width('30%')
              TextInput({ text: this.wifiRemotePort })
                .width('70%')
                .borderRadius(5)
                .type(InputType.Number)
                .onChange((value: string) => {
                  this.wifiRemotePort = value;
                })
            }
            .width('100%')
            .margin({ bottom: 8 })
          }

          Row() {
            Text('链路状态: ')
              .fontSize(16)
              .width('30%')
            Text(`[${this.wifiModeValue}] ${this.wifiStatus}`)
              .fontSize(16)
              .fontColor(this.wifiBound ? Color.Green : Color.Red)
              .width('70%')
          }
          .width('100%')
          .margin({ bottom: 8 })

          Row() {
            Text('发送/接收: ')
              .fontSize(14)
              .width('30%')
            Text(`${this.wifiSendCount} / ${this.wifiReceiveCount}`)
              .fontSize(14)
              .fontColor(Color.Blue)
              .width('70%')
          }
          .width('100%')
          .margin({ bottom: 8 })

          if (this.wifiReconnectCount > 0) {
            Row() {
              Text('重连次数: ')
                .fontSize(14)
                .width('30%')
              Text(`${this.wifiReconnectCount}`)
                .fontSize(14)
                .fontColor(Color.Orange)
                .width('70%')
            }
            .width('100%')
            .margin({ bottom: 8 })
          }

          // 根据模式显示不同的按钮组合
          if (this.wifiModeValue === 'Client') {
            Row() {
              Button('绑定WiFi')
                .width('32%')
                .backgroundColor(this.wifiBound ? Color.Gray : Color.Blue)
                .enabled(!this.wifiBound)
                .onClick(() => {
                  this.bindWifiSocket();
                })

              Button('发送WiFi')
                .width('32%')
                .backgroundColor(this.wifiBound ? Color.Green : Color.Gray)
                .enabled(this.wifiBound)
                .onClick(() => {
                  this.sendOnWifi();
                })

              Button('关闭WiFi')
                .width('32%')
                .backgroundColor(this.wifiBound ? Color.Red : Color.Gray)
                .enabled(this.wifiBound)
                .onClick(() => {
                  this.closeWifiSocket();
                })
            }
            .width('100%')
            .justifyContent(FlexAlign.SpaceBetween)
            .margin({ bottom: 16 })
          } else {
            // Server模式：启动/关闭
            Row() {
              Button('启动Server')
                .width('48%')
                .backgroundColor(this.wifiBound ? Color.Gray : Color.Blue)
                .enabled(!this.wifiBound)
                .onClick(() => {
                  this.bindWifiSocket();
                })

              Button('关闭Server')
                .width('48%')
                .backgroundColor(this.wifiBound ? Color.Red : Color.Gray)
                .enabled(this.wifiBound)
                .onClick(() => {
                  this.closeWifiSocket();
                })
            }
            .width('100%')
            .justifyContent(FlexAlign.SpaceBetween)
            .margin({ bottom: 16 })
          }

          // 蜂窝链路
          Text('蜂窝链路（直接访问公网 DNS）')
            .fontSize(18)
            .fontWeight(FontWeight.Bold)
            .width('100%')
            .margin({ top: 5, bottom: 8 })

          // 蜂窝本地端口（可配置）
          Row() {
            Text('本地端口: ')
              .fontSize(16)
              .width('30%')
            TextInput({ text: this.cellularLocalPort })
              .width('70%')
              .borderRadius(5)
              .type(InputType.Number)
              .onChange((value: string) => {
                this.cellularLocalPort = value;
              })
          }
          .width('100%')
          .margin({ bottom: 8 })

          // 链路状态（无 Client/Server 选项）
          Row() {
            Text('链路状态: ')
              .fontSize(16)
              .width('30%')
            Text(this.cellularStatus)
              .fontSize(16)
              .fontColor(this.cellularBound ? Color.Green : Color.Red)
              .width('70%')
          }
          .width('100%')
          .margin({ bottom: 8 })

          Row() {
            Text('发送次数: ')
              .fontSize(14)
              .width('30%')
            Text(`${this.cellularSendCount}`)
              .fontSize(14)
              .fontColor(Color.Blue)
              .width('70%')
          }
          .width('100%')
          .margin({ bottom: 8 })

          // 三个按钮：绑定 / 发送 / 关闭
          Row() {
            Button('绑定蜂窝')
              .width('32%')
              .backgroundColor(this.cellularBound ? Color.Gray : Color.Blue)
              .enabled(!this.cellularBound)
              .onClick(() => {
                this.bindSocketCellular();
              })

            Button('发送到百度')
              .width('32%')
              .backgroundColor(this.cellularBound ? Color.Green : Color.Gray)
              .enabled(this.cellularBound)
              .onClick(() => {
                this.sendMessageCellular();
              })

            Button('关闭蜂窝')
              .width('32%')
              .backgroundColor(this.cellularBound ? Color.Red : Color.Gray)
              .enabled(this.cellularBound)
              .onClick(() => {
                this.closeCellularSocket();
              })
          }
          .width('100%')
          .justifyContent(FlexAlign.SpaceBetween)
          .margin({ bottom: 16 })

          // 显示 DNS 响应（Hex）
          if (this.cellularResponse) {
            Text('DNS响应（Hex）')
              .fontSize(16)
              .fontWeight(FontWeight.Bold)
              .width('100%')
              .margin({ bottom: 5 })

            TextArea({ text: this.cellularResponse })
              .width('100%')
              .height('15%')
              .borderRadius(5)
              .backgroundColor(Color.White)
              .margin({ bottom: 15 })
          }

          // 公共操作
          Row() {
            // 只有双Client模式才显示双路发送按钮
            if (this.wifiModeValue === 'Client' && this.cellularModeValue === 'Client') {
              Button('双路发送')
                .width('48%')
                .backgroundColor((this.wifiBound || this.cellularBound) ? Color.Green : Color.Gray)
                .enabled(this.wifiBound || this.cellularBound)
                .onClick(() => {
                  this.sendBoth();
                })
            }

            Button('清空日志')
              .width(this.wifiModeValue === 'Client' && this.cellularModeValue === 'Client' ? '48%' : '100%')
              .backgroundColor(Color.Orange)
              .onClick(() => {
                this.clearResponse();
              })
          }
          .width('100%')
          .justifyContent(FlexAlign.SpaceBetween)
          .margin({ bottom: 12 })

          // 消息输入区域（Client模式才需要）
          if (this.wifiModeValue === 'Client' || this.cellularModeValue === 'Client') {
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
          }

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
    console.log(TAG, '页面即将销毁，清理资源...');

    // 1. 取消网络监听
    if (this.netConnection) {
      try {
        this.netConnection.unregister((error: Error) => {
          if (error) {
            console.error(TAG, `取消网络注册订阅事件失败: ${JSON.stringify(error)}`);
          } else {
            console.log(TAG, '网络注册订阅事件已取消');
          }
        });
      } catch (error) {
        console.error(TAG, `取消网络注册订阅事件异常: ${JSON.stringify(error)}`);
      }
      this.netConnection = null;
    }

    if (this.netConnectionCellular) {
      try {
        this.netConnectionCellular.unregister((error: Error) => {
          if (error) {
            console.error(TAG, `取消蜂窝网络注册订阅事件失败: ${JSON.stringify(error)}`);
          } else {
            console.log(TAG, '蜂窝网络注册订阅事件已取消');
          }
        });
      } catch (error) {
        console.error(TAG, `取消蜂窝网络注册订阅事件异常: ${JSON.stringify(error)}`);
      }
      this.netConnectionCellular = null;
    }

    // 2. 关闭并清理WiFi Socket
    if (this.wifiSocket) {
      try {
        this.wifiSocket.close();
      } catch (e) {
        console.error(TAG, `关闭WiFi Socket异常: ${JSON.stringify(e)}`);
      }
      this.wifiSocket = null;
      this.wifiBound = false;
    }

    // 3. 关闭并清理蜂窝Socket
    if (this.cellularSocket) {
      try {
        this.cellularSocket.close();
      } catch (e) {
        console.error(TAG, `关闭蜂窝Socket异常: ${JSON.stringify(e)}`);
      }
      this.cellularSocket = null;
      this.cellularBound = false;
    }

    // 4. 清理netHandle引用
    this.wifiNetHandle = null;
    this.cellularNetHandle = null;

    console.log(TAG, '资源清理完成');

    //5.关闭多网请求
    this.releaseMultiPath();
  }
}

