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

import linkEnhance from '@ohos.distributedsched.linkEnhance';
import { BusinessError } from '@ohos.base';
import util from '@ohos.util';
import promptAction from '@ohos.promptAction';

const TAG = '[LinkEnhanceTest]';

let testServer: linkEnhance.Server | null = null;
let testConnection: linkEnhance.Connection | null = null;
let testServerName = 'TestServer';
let testDeviceId = 'test_device_id';

// 监听状态标志
let serverConnectionAcceptedListening = false;
let serverStoppedListening = false;
let connectionConnectResultListening = false;
let connectionDisconnectedListening = false;
let connectionDataReceivedListening = false;

export function testCreateServer(): string {
  try {
    console.info(TAG + 'testCreateServer start');
    testServer = linkEnhance.createServer(testServerName);
    console.info(TAG + 'createServer success');
    return 'createServer success';
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'createServer failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'createServer failed: ' + error.message;
  }
}

export function testServerStart(): string {
  try {
    console.info(TAG + 'testServerStart start');
    if (!testServer) {
      return 'Server not created, please create server first';
    }
    testServer.start();
    console.info(TAG + 'server start success');
    return 'server start success';
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'server start failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'server start failed: ' + error.message;
  }
}

export function testServerStop(): string {
  try {
    console.info(TAG + 'testServerStop start');
    if (!testServer) {
      return 'Server not created, please create server first';
    }
    testServer.stop();
    console.info(TAG + 'server stop success');
    return 'server stop success';
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'server stop failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'server stop failed: ' + error.message;
  }
}

export function testServerClose(): string {
  try {
    console.info(TAG + 'testServerClose start');
    if (!testServer) {
      return 'Server not created, please create server first';
    }
    testServer.close();
    testServer = null;
    console.info(TAG + 'server close success');
    return 'server close success';
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'server close failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'server close failed: ' + error.message;
  }
}

export function testServerOnConnectionAccepted(): string {
  try {
    console.info(TAG + 'testServerOnConnectionAccepted start');
    if (!testServer) {
      return 'Server not created, please create server first';
    }
    
    let message = '';
    if (serverConnectionAcceptedListening) {
      // 关闭监听
      testServer.off('connectionAccepted', () => {
        promptAction.showToast({ message: '已关闭connectionAccepted监听' });
      });
      message = '已关闭connectionAccepted监听';
      console.info(TAG + message);
    } else {
      // 开启监听
      testServer.on('connectionAccepted', (connection: linkEnhance.Connection): void => {
        console.info(TAG + 'connectionAccepted callback triggered');
        console.info(TAG + 'peer device id: ' + connection.getPeerDeviceId());
        testConnection = connection;
        let connectMessage = '接受到新连接，设备ID: ' + connection.getPeerDeviceId();
        promptAction.showToast({ message: connectMessage });
        AppStorage.setOrCreate('le_connectionAccepted', connectMessage);

        connection.on('disconnected', (reason: number) => {
          console.info(TAG + 'connection disconnected, reason: ' + reason);
        });
        
        connection.on('dataReceived', (data: ArrayBuffer) => {
          console.info(TAG + 'data received, length: ' + data.byteLength);
        });
      });
      message = '已开启connectionAccepted监听';
      promptAction.showToast({ message: message });
      console.info(TAG + message);
    }
    
    serverConnectionAcceptedListening = !serverConnectionAcceptedListening;
    return message;
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'server on connectionAccepted failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'server on connectionAccepted failed: ' + error.message;
  }
}

export function testServerOnServerStopped(): string {
  try {
    console.info(TAG + 'testServerOnServerStopped start');
    if (!testServer) {
      return 'Server not created, please create server first';
    }
    
    let message = '';
    if (serverStoppedListening) {
      // 关闭监听
      testServer.off('serverStopped', () => {
        promptAction.showToast({ message: '已关闭serverStopped监听' });
      });
      message = '已关闭serverStopped监听';
      console.info(TAG + message);
    } else {
      // 开启监听
      testServer.on('serverStopped', (reason: number): void => {
        console.info(TAG + 'serverStopped callback triggered, reason: ' + reason);
        let stopMessage = '服务器已停止，原因: ' + reason;
        promptAction.showToast({ message: stopMessage });
        AppStorage.setOrCreate('le_serverStopped', stopMessage);
      });
      message = '已开启serverStopped监听';
      promptAction.showToast({ message: message });
      console.info(TAG + message);
    }
    
    serverStoppedListening = !serverStoppedListening;
    return message;
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'server on serverStopped failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'server on serverStopped failed: ' + error.message;
  }
}

export function testCreateConnection(): string {
  try {
    console.info(TAG + 'testCreateConnection start');
    testConnection = linkEnhance.createConnection(testDeviceId, testServerName);
    console.info(TAG + 'createConnection success');
    return 'createConnection success';
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'createConnection failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'createConnection failed: ' + error.message;
  }
}

export function testConnectionConnect(): string {
  try {
    console.info(TAG + 'testConnectionConnect start');
    if (!testConnection) {
      return 'Connection not created, please create connection first';
    }
    testConnection.connect();
    console.info(TAG + 'connection connect success');
    return 'connection connect success';
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'connection connect failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'connection connect failed: ' + error.message;
  }
}

export function testConnectionDisconnect(): string {
  try {
    console.info(TAG + 'testConnectionDisconnect start');
    if (!testConnection) {
      return 'Connection not created, please create connection first';
    }
    testConnection.disconnect();
    console.info(TAG + 'connection disconnect success');
    return 'connection disconnect success';
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'connection disconnect failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'connection disconnect failed: ' + error.message;
  }
}

export function testConnectionClose(): string {
  try {
    console.info(TAG + 'testConnectionClose start');
    if (!testConnection) {
      return 'Connection not created, please create connection first';
    }
    testConnection.close();
    testConnection = null;
    console.info(TAG + 'connection close success');
    return 'connection close success';
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'connection close failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'connection close failed: ' + error.message;
  }
}

export function testConnectionGetPeerDeviceId(): string {
  try {
    console.info(TAG + 'testConnectionGetPeerDeviceId start');
    if (!testConnection) {
      return 'Connection not created, please create connection first';
    }
    let peerDeviceId = testConnection.getPeerDeviceId();
    console.info(TAG + 'getPeerDeviceId success, deviceId: ' + peerDeviceId);
    return 'getPeerDeviceId success, deviceId: ' + peerDeviceId;
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'getPeerDeviceId failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'getPeerDeviceId failed: ' + error.message;
  }
}


export function testConnectionSendData(): string {
  try {
    console.info(TAG + 'testConnectionSendData start');
    if (!testConnection) {
      return 'Connection not created, please create connection first';
    }

    let testData = 'Hello LinkEnhance!';
    let textEncoder = new util.TextEncoder();
    let uint8Array = textEncoder.encodeInto(testData);
    let arrayBuffer = uint8Array.buffer;
    
    testConnection.sendData(arrayBuffer);
    console.info(TAG + 'sendData success, data length: ' + arrayBuffer.byteLength);
    return 'sendData success, data: ' + testData;
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'sendData failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'sendData failed: ' + error.message;
  }
}

export function testConnectionOnConnectResult(): string {
  try {
    console.info(TAG + 'testConnectionOnConnectResult start');
    if (!testConnection) {
      return 'Connection not created, please create connection first';
    }
    
    let message = '';
    if (connectionConnectResultListening) {
      // 关闭监听
      testConnection.off('connectResult', () => {
        promptAction.showToast({ message: '已关闭connectResult监听' });
      });
      message = '已关闭connectResult监听';
      console.info(TAG + message);
    } else {
      // 开启监听
      testConnection.on('connectResult', (result: linkEnhance.ConnectResult): void => {
        console.info(TAG + 'connectResult callback triggered');
        console.info(TAG + 'deviceId: ' + result.deviceId);
        console.info(TAG + 'success: ' + result.success);
        console.info(TAG + 'reason: ' + result.reason);
        
        let resultMessage = '连接结果：' + (result.success ? '成功' : '失败') + '，设备ID: ' + result.deviceId + '，原因: ' + result.reason;
        promptAction.showToast({ message: resultMessage });
        AppStorage.setOrCreate('le_connectResult', resultMessage);
      });
      message = '已开启connectResult监听';
      promptAction.showToast({ message: message });
      console.info(TAG + message);
    }
    
    connectionConnectResultListening = !connectionConnectResultListening;
    return message;
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'connection on connectResult failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'connection on connectResult failed: ' + error.message;
  }
}

export function testConnectionOnDisconnected(): string {
  try {
    console.info(TAG + 'testConnectionOnDisconnected start');
    if (!testConnection) {
      return 'Connection not created, please create connection first';
    }
    
    let message = '';
    if (connectionDisconnectedListening) {
      // 关闭监听
      testConnection.off('disconnected', () => {
        promptAction.showToast({ message: '已关闭disconnected监听' });
      });
      message = '已关闭disconnected监听';
      console.info(TAG + message);
    } else {
      // 开启监听
      testConnection.on('disconnected', (reason: number): void => {
        console.info(TAG + 'disconnected callback triggered, reason: ' + reason);
        let disconnectMessage = '连接已断开，原因: ' + reason;
        promptAction.showToast({ message: disconnectMessage });
        AppStorage.setOrCreate('le_disconnected', disconnectMessage);
      });
      message = '已开启disconnected监听';
      promptAction.showToast({ message: message });
      console.info(TAG + message);
    }
    
    connectionDisconnectedListening = !connectionDisconnectedListening;
    return message;
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'connection on disconnected failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'connection on disconnected failed: ' + error.message;
  }
}

export function testConnectionOnDataReceived(): string {
  try {
    console.info(TAG + 'testConnectionOnDataReceived start');
    if (!testConnection) {
      return 'Connection not created, please create connection first';
    }
    
    let message = '';
    if (connectionDataReceivedListening) {
      // 关闭监听
      testConnection.off('dataReceived', () => {
        promptAction.showToast({ message: '已关闭dataReceived监听' });
      });
      message = '已关闭dataReceived监听';
      console.info(TAG + message);
    } else {
      // 开启监听
      testConnection.on('dataReceived', (data: ArrayBuffer): void => {
        console.info(TAG + 'dataReceived callback triggered, data length: ' + data.byteLength);
        
        // 将接收到的数据转换为字符串
        let textDecoder = new util.TextDecoder('utf-8');
        let uint8Array = new Uint8Array(data);
        let receivedText = textDecoder.decodeWithStream(uint8Array, { stream: false });
        console.info(TAG + 'received data: ' + receivedText);
        
        let dataMessage = '收到数据: ' + receivedText + ' (长度: ' + data.byteLength + '字节)';
        promptAction.showToast({ message: dataMessage });
        AppStorage.setOrCreate('le_dataReceived', dataMessage);
      });
      message = '已开启dataReceived监听';
      promptAction.showToast({ message: message });
      console.info(TAG + message);
    }
    
    connectionDataReceivedListening = !connectionDataReceivedListening;
    return message;
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'connection on dataReceived failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'connection on dataReceived failed: ' + error.message;
  }
}

export function setTestDeviceId(deviceId: string): void {
  testDeviceId = deviceId;
  console.info(TAG + 'set test device id: ' + deviceId);
}


export function setTestServerName(serverName: string): void {
  testServerName = serverName;
  console.info(TAG + 'set test server name: ' + serverName);
}


export function getCurrentServer(): linkEnhance.Server | null {
  return testServer;
}

export function getCurrentConnection(): linkEnhance.Connection | null {
  return testConnection;
}

export function cleanupTestResources(): string {
  try {
    console.info(TAG + 'cleanupTestResources start');
    
    if (testConnection) {
      testConnection.close();
      testConnection = null;
    }
    
    if (testServer) {
      testServer.close();
      testServer = null;
    }
    
    console.info(TAG + 'cleanup test resources success');
    return 'cleanup test resources success';
  } catch (err) {
    let error = err as BusinessError;
    console.error(TAG + 'cleanup test resources failed, errCode: ' + error.code + ', errMessage: ' + error.message);
    return 'cleanup test resources failed: ' + error.message;
  }
}
