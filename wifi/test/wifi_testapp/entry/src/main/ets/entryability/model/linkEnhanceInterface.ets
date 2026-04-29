/**
 * Copyright (c) 2025 Shenzhen Kaihong Digital Industry Development Co., Ltd.
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
import linkEnhance from '@ohos.distributedsched.linkEnhance';
import { BusinessError} from '@ohos.base';
import util from '@ohos.util';
import promptAction from '@ohos.promptAction';
import ConfigData from '../../Utils/ConfigData';

const TAG = '[LinkEnhanceTest]';

let testServer: linkEnhance.Server | null = null;
let testConnection: linkEnhance.Connection | null = null;
let testServerName = ConfigData.LE_MODEL_DEFAULT_SERVER;
let testDeviceId = ConfigData.LE_MODEL_DEFAULT_DEVICE_ID;

// 监听状态标志
let serverConnectionAcceptedListening = false;
let serverStoppedListening = false;
let connectionConnectResultListening = false;
let connectionDisconnectedListening = false;
let connectionDataReceivedListening = false;

export function testCreateServer(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testCreateServer start');
    testServer = linkEnhance.createServer(testServerName);
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'createServer success');
    return 'createServer success';
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'createServer failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'createServer failed: ' + error.message;
  }
}

export function testServerStart(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testServerStart start');
    if (!testServer){
      return 'Server not created, please create server first';
    }
    testServer.start();
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'server start success');
    return 'server start success';
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'server start failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'server start failed: ' + error.message;
  }
}

export function testServerStop(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testServerStop start');
    if (!testServer){
      return 'Server not created, please create server first';
    }
    testServer.stop();
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'server stop success');
    return 'server stop success';
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'server stop failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'server stop failed: ' + error.message;
  }
}

export function testServerClose(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testServerClose start');
    if (!testServer){
      return 'Server not created, please create server first';
    }
    testServer.close();
    testServer = null;
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'server close success');
    return 'server close success';
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'server close failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'server close failed: ' + error.message;
  }
}

export function testServerOnConnectionAccepted(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testServerOnConnectionAccepted start');
    if (!testServer){
      return 'Server not created, please create server first';
    }

    let message = '';
    if (serverConnectionAcceptedListening){
      // 关闭监听
      testServer.off('connectionAccepted', () => {
        promptAction.showToast({message: '已关闭connectionAccepted监听'});
      });
      message = '已关闭connectionAccepted监听';
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + message);
    } else {
      // 开启监听
      testServer.on('connectionAccepted', (connection: linkEnhance.Connection): void => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'connectionAccepted callback triggered');
        hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'peer device id: ' + connection.getPeerDeviceId());
        testConnection = connection;
        let connectMessage = '接受到新连接，设备ID: ' + connection.getPeerDeviceId();
        promptAction.showToast({message: connectMessage});
        AppStorage.setOrCreate('le_connectionAccepted', connectMessage);

        connection.on('disconnected', (reason: number) => {
          hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'connection disconnected, reason: ' + reason);
        });

        connection.on('dataReceived', (data: ArrayBuffer) => {
          hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'data received, length: ' + data.byteLength);
        });
      });
      message = '已开启connectionAccepted监听';
      promptAction.showToast({message: message});
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + message);
    }

    serverConnectionAcceptedListening = !serverConnectionAcceptedListening;
    return message;
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'server on connectionAccepted failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'server on connectionAccepted failed: ' + error.message;
  }
}

export function testServerOnServerStopped(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testServerOnServerStopped start');
    if (!testServer){
      return 'Server not created, please create server first';
    }

    let message = '';
    if (serverStoppedListening){
      // 关闭监听
      testServer.off('serverStopped', () => {
        promptAction.showToast({message: '已关闭serverStopped监听'});
      });
      message = '已关闭serverStopped监听';
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + message);
    } else {
      // 开启监听
      testServer.on('serverStopped', (reason: number): void => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'serverStopped callback triggered, reason: ' + reason);
        let stopMessage = '服务器已停止，原因: ' + reason;
        promptAction.showToast({message: stopMessage});
        AppStorage.setOrCreate('le_serverStopped', stopMessage);
      });
      message = '已开启serverStopped监听';
      promptAction.showToast({message: message});
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + message);
    }

    serverStoppedListening = !serverStoppedListening;
    return message;
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'server on serverStopped failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'server on serverStopped failed: ' + error.message;
  }
}

export function testCreateConnection(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testCreateConnection start');
    testConnection = linkEnhance.createConnection(testDeviceId, testServerName);
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'createConnection success');
    return 'createConnection success';
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'createConnection failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'createConnection failed: ' + error.message;
  }
}

export function testConnectionConnect(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testConnectionConnect start');
    if (!testConnection){
      return 'Connection not created, please create connection first';
    }
    testConnection.connect();
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'connection connect success');
    return 'connection connect success';
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'connection connect failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'connection connect failed: ' + error.message;
  }
}

export function testConnectionDisconnect(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testConnectionDisconnect start');
    if (!testConnection){
      return 'Connection not created, please create connection first';
    }
    testConnection.disconnect();
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'connection disconnect success');
    return 'connection disconnect success';
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'connection disconnect failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'connection disconnect failed: ' + error.message;
  }
}

export function testConnectionClose(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testConnectionClose start');
    if (!testConnection){
      return 'Connection not created, please create connection first';
    }
    testConnection.close();
    testConnection = null;
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'connection close success');
    return 'connection close success';
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'connection close failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'connection close failed: ' + error.message;
  }
}

export function testConnectionGetPeerDeviceId(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testConnectionGetPeerDeviceId start');
    if (!testConnection){
      return 'Connection not created, please create connection first';
    }
    let peerDeviceId = testConnection.getPeerDeviceId();
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'getPeerDeviceId success, deviceId: ' + peerDeviceId);
    return 'getPeerDeviceId success, deviceId: ' + peerDeviceId;
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'getPeerDeviceId failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'getPeerDeviceId failed: ' + error.message;
  }
}


export function testConnectionSendData(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testConnectionSendData start');
    if (!testConnection){
      return 'Connection not created, please create connection first';
    }

    let testData = ConfigData.LE_DEMO_TEST_MESSAGE;
    let textEncoder = new util.TextEncoder();
    let uint8Array = textEncoder.encodeInto(testData);
    let arrayBuffer = uint8Array.buffer;

    testConnection.sendData(arrayBuffer);
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'sendData success, data length: ' + arrayBuffer.byteLength);
    return 'sendData success, data: ' + testData;
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'sendData failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'sendData failed: ' + error.message;
  }
}

export function testConnectionOnConnectResult(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testConnectionOnConnectResult start');
    if (!testConnection){
      return 'Connection not created, please create connection first';
    }

    let message = '';
    if (connectionConnectResultListening){
      // 关闭监听
      testConnection.off('connectResult', () => {
        promptAction.showToast({message: '已关闭connectResult监听'});
      });
      message = '已关闭connectResult监听';
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + message);
    } else {
      // 开启监听
      testConnection.on('connectResult', (result: linkEnhance.ConnectResult): void => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'connectResult callback triggered');
        hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'deviceId: ' + result.deviceId);
        hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'success: ' + result.success);
        hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'reason: ' + result.reason);

        let resultMessage = '连接结果：' + (result.success ? '成功' : '失败') + '，设备ID: ' + result.deviceId + '，原因: ' + result.reason;
        promptAction.showToast({message: resultMessage});
        AppStorage.setOrCreate('le_connectResult', resultMessage);
      });
      message = '已开启connectResult监听';
      promptAction.showToast({message: message});
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + message);
    }

    connectionConnectResultListening = !connectionConnectResultListening;
    return message;
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'connection on connectResult failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'connection on connectResult failed: ' + error.message;
  }
}

export function testConnectionOnDisconnected(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testConnectionOnDisconnected start');
    if (!testConnection){
      return 'Connection not created, please create connection first';
    }

    let message = '';
    if (connectionDisconnectedListening){
      // 关闭监听
      testConnection.off('disconnected', () => {
        promptAction.showToast({message: '已关闭disconnected监听'});
      });
      message = '已关闭disconnected监听';
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + message);
    } else {
      // 开启监听
      testConnection.on('disconnected', (reason: number): void => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'disconnected callback triggered, reason: ' + reason);
        let disconnectMessage = '连接已断开，原因: ' + reason;
        promptAction.showToast({message: disconnectMessage});
        AppStorage.setOrCreate('le_disconnected', disconnectMessage);
      });
      message = '已开启disconnected监听';
      promptAction.showToast({message: message});
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + message);
    }

    connectionDisconnectedListening = !connectionDisconnectedListening;
    return message;
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'connection on disconnected failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'connection on disconnected failed: ' + error.message;
  }
}

export function testConnectionOnDataReceived(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'testConnectionOnDataReceived start');
    if (!testConnection){
      return 'Connection not created, please create connection first';
    }

    let message = '';
    if (connectionDataReceivedListening){
      // 关闭监听
      testConnection.off('dataReceived', () => {
        promptAction.showToast({message: '已关闭dataReceived监听'});
      });
      message = '已关闭dataReceived监听';
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + message);
    } else {
      // 开启监听
      testConnection.on('dataReceived', (data: ArrayBuffer): void => {
        hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'dataReceived callback triggered, data length: ' + data.byteLength);

        // 将接收到的数据转换为字符串
        let textDecoder = new util.TextDecoder('utf-8');
        let uint8Array = new Uint8Array(data);
        let receivedText = textDecoder.decodeWithStream(uint8Array, { stream: false});
        hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'received data: ' + receivedText);

        let dataMessage = '收到数据: ' + receivedText + ' (长度: ' + data.byteLength + '字节)';
        promptAction.showToast({message: dataMessage});
        AppStorage.setOrCreate('le_dataReceived', dataMessage);
      });
      message = '已开启dataReceived监听';
      promptAction.showToast({message: message});
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + message);
    }

    connectionDataReceivedListening = !connectionDataReceivedListening;
    return message;
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'connection on dataReceived failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'connection on dataReceived failed: ' + error.message;
  }
}

export function setTestDeviceId(deviceId: string): void {
  testDeviceId = deviceId;
  hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'set test device id: ' + deviceId);
}


export function setTestServerName(serverName: string): void {
  testServerName = serverName;
  hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'set test server name: ' + serverName);
}


export function getCurrentServer(): linkEnhance.Server | null {
  return testServer;
}

export function getCurrentConnection(): linkEnhance.Connection | null {
  return testConnection;
}

export function cleanupTestResources(): string {
  try {
    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'cleanupTestResources start');

    if (testConnection){
      testConnection.close();
      testConnection = null;
    }

    if (testServer){
      testServer.close();
      testServer = null;
    }

    hilog.info(0x1500, 'wifiTestApp', '%{public}s', TAG + 'cleanup test resources success');
    return 'cleanup test resources success';
  } catch (err){
    let error = err as BusinessError;
    hilog.error(0x1500, 'wifiTestApp', '%{public}s', TAG + 'cleanup test resources failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'cleanup test resources failed: ' + error.message;
  }
}
