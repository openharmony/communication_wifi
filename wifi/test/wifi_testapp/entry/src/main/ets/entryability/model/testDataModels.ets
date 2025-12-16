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

/**
 * test Data model of wifi test
 */

import { TestData , TestApi , Category , CaseCategory } from './testData'

import {
  testGetP2pLinkedInfoManagerPromise ,
  testGetP2pLinkedInfoManagerCallback ,
  testGetCurrentP2pGroupManagerPromise ,
  testGetCurrentP2pGroupManagerCallback ,
  testGetP2pPeerDevicesManagerPromise ,
  testGetP2pPeerDevicesManagerCallback ,
  testGetP2pLocalDeviceManagerPromise ,
  testGetP2pLocalDeviceManagerCallback ,
  testCreateP2pGroupManager ,
  testRemoveP2pGroupManager ,
  testP2pConnectManager ,
  testP2pCancelConnectManager ,
  testStartDiscoverP2pDevicesManager ,
  testStopDiscoverP2pDevicesManager ,
  testOnP2pStateChangeManager ,
  testOnP2pConnectionChangeManager ,
  testOnP2pDeviceChangeManager ,
  testOnP2pPeerDeviceChangeManager ,
  testOnP2pPersistentGroupChangeManager ,
  testOnP2pDiscoveryChangeManager
} from './p2pManagerInterface'

import {
  testCreateServer,
  testServerStart,
  testServerStop,
  testServerClose,
  testServerOnConnectionAccepted,
  testServerOnServerStopped,
  testCreateConnection,
  testConnectionConnect,
  testConnectionDisconnect,
  testConnectionClose,
  testConnectionGetPeerDeviceId,
  testConnectionSendData,
  testConnectionOnConnectResult,
  testConnectionOnDisconnected,
  testConnectionOnDataReceived
} from './linkEnhanceInterface'

interface WifiTest {
  name: string;
  detail: string;
  method: string;
  api: Function;
  result: string;
  category: CaseCategory;
}

interface WifiTestComposition {
  name: string;
  detail: string;
  url: string;
  image: Resource;
  category: Category;
}

const p2pManagerTestCase: WifiTest[] = [
  {
    'name' : '注册P2P开关状态改变事件' ,
    'detail' : '注册P2P开关状态改变事件' ,
    'method' : 'on.P2pStateChange' ,
    'api' : testOnP2pStateChangeManager ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '注册P2P连接状态改变事件' ,
    'detail' : '注册P2P连接状态改变事件' ,
    'method' : 'on.P2pConnectionChange' ,
    'api' : testOnP2pConnectionChangeManager ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '注册P2P设备状态改变事件' ,
    'detail' : '注册P2P设备状态改变事件' ,
    'method' : 'on.p2pDeviceChange' ,
    'api' : testOnP2pDeviceChangeManager ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '注册P2P对端设备状态改变事件' ,
    'detail' : '注册P2P对端设备状态改变事件' ,
    'method' : 'on.p2pPeerDeviceChange' ,
    'api' : testOnP2pPeerDeviceChangeManager ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '注册P2P永久组状态改变事件' ,
    'detail' : '注册P2P永久组状态改变事件' ,
    'method' : 'on.p2pPersistentGroupChange' ,
    'api' : testOnP2pPersistentGroupChangeManager ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '注册发现设备状态改变事件' ,
    'detail' : '注册发现设备状态改变事件' ,
    'method' : 'on.p2pDiscoveryChange' ,
    'api' : testOnP2pDiscoveryChangeManager ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '创建群组' ,
    'detail' : '创建群组' ,
    'method' : 'createGroup' ,
    'api' : testCreateP2pGroupManager ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '开始发现设备' ,
    'detail' : '开始发现设备' ,
    'method' : 'startDiscoverDevices' ,
    'api' : testStartDiscoverP2pDevicesManager ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '停止发现设备' ,
    'detail' : '停止发现设备' ,
    'method' : 'stopDiscoverDevices' ,
    'api' : testStopDiscoverP2pDevicesManager ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '执行P2P连接' ,
    'detail' : '执行P2P连接' ,
    'method' : 'p2pConnect' ,
    'api' : testP2pConnectManager ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '获取P2P连接信息Promise' ,
    'detail' : '获取P2P连接信息Promise' ,
    'method' : 'getP2pLinkedInfo' ,
    'api' : testGetP2pLinkedInfoManagerPromise ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '获取P2P连接信息Callback' ,
    'detail' : '获取P2P连接信息Callback' ,
    'method' : 'getP2pLinkedInfo' ,
    'api' : testGetP2pLinkedInfoManagerCallback ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '获取P2P当前组信息Promise' ,
    'detail' : '获取P2P当前组信息Promise' ,
    'method' : 'getCurrentGroup' ,
    'api' : testGetCurrentP2pGroupManagerPromise ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '获取P2P当前组信息Callback' ,
    'detail' : '获取P2P当前组信息Callback' ,
    'method' : 'getCurrentGroup' ,
    'api' : testGetCurrentP2pGroupManagerCallback ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '获取P2P对端设备列表信息Promise' ,
    'detail' : '获取P2P对端设备列表信息Promise' ,
    'method' : 'getP2pPeerDevices' ,
    'api' : testGetP2pPeerDevicesManagerPromise ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '获取P2P对端设备列表信息Callback' ,
    'detail' : '获取P2P对端设备列表信息Callback' ,
    'method' : 'getP2pPeerDevices' ,
    'api' : testGetP2pPeerDevicesManagerCallback ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '获取P2P本端设备信息Promise' ,
    'detail' : '获取P2P本端设备信息Promise' ,
    'method' : 'getP2pLocalDevice' ,
    'api' : testGetP2pLocalDeviceManagerPromise ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '获取P2P本端设备信息Callback' ,
    'detail' : '获取P2P本端设备信息Callback' ,
    'method' : 'getP2pLocalDevice' ,
    'api' : testGetP2pLocalDeviceManagerCallback ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '取消P2P连接' ,
    'detail' : '取消P2P连接' ,
    'method' : 'p2pCancelConnect' ,
    'api' : testP2pCancelConnectManager ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
  {
    'name' : '移除群组' ,
    'detail' : '移除群组' ,
    'method' : 'removeGroup' ,
    'api' : testRemoveP2pGroupManager ,
    'result' : 'None' ,
    'category' : CaseCategory.P2pManager
  },
]

export const LinkEnhanceTestCase: WifiTest[] = [
// Server相关接口测试
  {
    'name': '创建服务器',
    'detail': '创建linkEnhance服务器实例',
    'method': 'createServer',
    'api': testCreateServer,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  },
  {
    'name': '启动服务器',
    'detail': '启动linkEnhance服务器',
    'method': 'server.start',
    'api': testServerStart,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  },
  {
    'name': '停止服务器',
    'detail': '停止linkEnhance服务器',
    'method': 'server.stop',
    'api': testServerStop,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  },
  {
    'name': '关闭服务器',
    'detail': '关闭linkEnhance服务器并清理资源',
    'method': 'server.close',
    'api': testServerClose,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  },
  {
    'name': '监听连接接受事件(开/关)',
    'detail': '注册/注销服务器连接接受事件监听',
    'method': 'server.on/off.connectionAccepted',
    'api': testServerOnConnectionAccepted,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  },
  {
    'name': '监听服务器停止事件(开/关)',
    'detail': '注册/注销服务器停止事件监听',
    'method': 'server.on/off.serverStopped',
    'api': testServerOnServerStopped,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  },

  // Connection相关接口测试
  {
    'name': '创建连接',
    'detail': '创建linkEnhance连接实例',
    'method': 'createConnection',
    'api': testCreateConnection,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  },
  {
    'name': '建立连接',
    'detail': '连接到对端设备',
    'method': 'connection.connect',
    'api': testConnectionConnect,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  },
  {
    'name': '断开连接',
    'detail': '断开与对端设备的连接',
    'method': 'connection.disconnect',
    'api': testConnectionDisconnect,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  },
  {
    'name': '关闭连接',
    'detail': '关闭连接并清理资源',
    'method': 'connection.close',
    'api': testConnectionClose,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  },
  {
    'name': '获取对端设备ID',
    'detail': '获取连接的对端设备ID',
    'method': 'connection.getPeerDeviceId',
    'api': testConnectionGetPeerDeviceId,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  },
  {
    'name': '发送数据',
    'detail': '向对端设备发送数据',
    'method': 'connection.sendData',
    'api': testConnectionSendData,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  },
  {
    'name': '监听连接结果事件(开/关)',
    'detail': '注册/注销连接结果事件监听',
    'method': 'connection.on/off.connectResult',
    'api': testConnectionOnConnectResult,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  },
  {
    'name': '监听断开连接事件(开/关)',
    'detail': '注册/注销断开连接事件监听',
    'method': 'connection.on/off.disconnected',
    'api': testConnectionOnDisconnected,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  },
  {
    'name': '监听数据接收事件(开/关)',
    'detail': '注册/注销数据接收事件监听',
    'method': 'connection.on/off.dataReceived',
    'api': testConnectionOnDataReceived,
    'result': 'None',
    'category': CaseCategory.LinkEnhance
  }
]

const TestComposition: WifiTestComposition[] = [
  {
    'name': '快速验证测试',
    'detail': '快速验证WiFi相关功能',
    'url': 'pages/newApi/QuickVerifyTest',
    'image': $r('app.media.wifi'),
    'category': Category.NewApi
  },
  {
    'name' : 'WIFI' ,
    'detail' : 'wifi发现' ,
    'url' : 'pages/subAppTest/wifiScanTest' ,
    'image' : $r('app.media.wifi') ,
    'category' : Category.App
  },
  {
    'name' : 'WIFI候选网络' ,
    'detail' : 'wifi候选网络' ,
    'url' : 'pages/subAppTest/wifiCandidateTest' ,
    'image' : $r('app.media.wifi') ,
    'category' : Category.App
  },
  {
    'name' : 'p2p扫描' ,
    'detail' : 'p2p扫描结果' ,
    'url' : 'pages/subAppTest/p2pDiscoveryTest' ,
    'image' : $r('app.media.WLAN') ,
    'category' : Category.App
  },
  {
    'name' : 'TCP Socket验证' ,
    'detail' : 'TCP连接测试' ,
    'url' : 'pages/subAppTest/tcpSocketTest' ,
    'image' : $r('app.media.wifi') ,
    'category' : Category.App
  },
  {
    'name' : 'UDP Socket验证' ,
    'detail' : 'UDP连接测试' ,
    'url' : 'pages/subAppTest/udpSocketTest' ,
    'image' : $r('app.media.wifi') ,
    'category' : Category.App
  },
  {
    'name' : 'Multipath Socket验证' ,
    'detail' : '蜂窝+WiFi双路Socket验证' ,
    'url' : 'pages/subAppTest/multipathSocketTest' ,
    'image' : $r('app.media.wifi') ,
    'category' : Category.App
  },
  {
    'name' : 'HTTP验证' ,
    'detail' : 'HTTP请求测试' ,
    'url' : 'pages/subAppTest/httpSocketTest' ,
    'image' : $r('app.media.wifi') ,
    'category' : Category.App
  },
  {
    'name' : 'HTTPS验证' ,
    'detail' : 'HTTPS请求测试' ,
    'url' : 'pages/subAppTest/httpsSocketTest' ,
    'image' : $r('app.media.wifi') ,
    'category' : Category.App
  },
  {
    'name' : 'RCP HTTP验证' ,
    'detail' : 'RCP协议HTTP请求测试' ,
    'url' : 'pages/subAppTest/rcpHttpTest' ,
    'image' : $r('app.media.wifi') ,
    'category' : Category.App
  },
  {
    'name' : 'TCPDUMP' ,
    'detail' : 'TCPDUMP 开关' ,
    'url' : 'pages/subAppTest/tcpdump' ,
    'image' : $r('app.media.wifi') ,
    'category' : Category.App
  },

  {
    'name' : 'P2pManager' ,
    'detail' : 'p2pManager测试' ,
    'url' : 'pages/subManualApiTest/p2pManagerInterfaceTest' ,
    'image' : $r('app.media.WLAN') ,
    'category' : Category.API
  },
  {
    'name' : 'LinkEnhance' ,
    'detail' : '软总线增强连接测试' ,
    'url' : 'pages/subManualApiTest/linkEnhanceInterfaceTest' ,
    'image' : $r('app.media.WLAN') ,
    'category' : Category.API
  },
  {
    'name' : 'WiFiSwitchStabilityTest' ,
    'detail' : 'WiFi开关稳定性测试' ,
    'url' : 'pages/subStabilityTest/wifiSwitchStabilityTest' ,
    'image' : $r('app.media.ScenarioTest') ,
    'category' : Category.Stability
  },
  {
    'name' : 'WiFiScanStabilityTest' ,
    'detail' : 'WiFi搜索稳定性测试' ,
    'url' : 'pages/subStabilityTest/wifiScanStabilityTest' ,
    'image' : $r('app.media.ScenarioTest') ,
    'category' : Category.Stability
  },
  {
    'name' : 'WiFiConnectStabilityTest' ,
    'detail' : 'WiFi连接稳定性测试' ,
    'url' : 'pages/subStabilityTest/wifiConnectStabilityTest' ,
    'image' : $r('app.media.ScenarioTest') ,
    'category' : Category.Stability
  },
  {
    'name' : 'HotspotStabilityTest' ,
    'detail' : '热点稳定性测试' ,
    'url' : 'pages/subStabilityTest/hotspotStabilityTest' ,
    'image' : $r('app.media.ScenarioTest') ,
    'category' : Category.Stability
  },
  {
    'name' : 'WifiConnectScenarioTest' ,
    'detail' : 'Wifi连接场景测试' ,
    'url' : 'pages/subScenarioTest/wifiConnectScenarioTest' ,
    'image' : $r('app.media.ScenarioTest') ,
    'category' : Category.Scenario
  },
  {
    'name' : 'WifiManagerScanScenarioTest' ,
    'detail' : 'WifiManager扫描场景测试' ,
    'url' : 'pages/subScenarioTest/wifiManagerConnectScenarioTest' ,
    'image' : $r('app.media.ScenarioTest') ,
    'category' : Category.Scenario
  },
  {
    'name' : 'HotspotCreateScenarioTest' ,
    'detail' : '热点创建场景测试' ,
    'url' : 'pages/subScenarioTest/hotspotCreateScenarioTest' ,
    'image' : $r('app.media.ScenarioTest') ,
    'category' : Category.Scenario
  },
  {
    'name' : 'HotspotManagerCreateScenarioTest' ,
    'detail' : '热点Manager创建场景测试' ,
    'url' : 'pages/subScenarioTest/hotspotManagerCreateScenarioTest' ,
    'image' : $r('app.media.ScenarioTest') ,
    'category' : Category.Scenario
  },
  {
    'name' : 'P2pConnectScenarioTest' ,
    'detail' : 'P2p连接场景测试' ,
    'url' : 'pages/subScenarioTest/p2pConnectScenarioTest' ,
    'image' : $r('app.media.ScenarioTest') ,
    'category' : Category.Scenario
  },
  {
    'name' : 'P2pManagerConnectScenarioTest' ,
    'detail' : 'P2p连接场景测试' ,
    'url' : 'pages/subScenarioTest/p2pManagerConnectScenarioTest' ,
    'image' : $r('app.media.ScenarioTest') ,
    'category' : Category.Scenario
  },
  {
    'name' : 'WifiBenchmarkTest' ,
    'detail' : 'Wifi性能测试' ,
    'url' : 'pages/subBenchmarkTest/wifiBenchmarkTest' ,
    'image' : $r('app.media.Benchmark') ,
    'category' : Category.BenchMark
  },
  {
    'name' : 'WifiManagerBenchmarkTest' ,
    'detail' : 'WifiManager性能测试' ,
    'url' : 'pages/subBenchmarkTest/wifiManagerBenchmarkTest' ,
    'image' : $r('app.media.Benchmark') ,
    'category' : Category.BenchMark
  },
  {
    'name' : 'HotspotBenchmarkTest' ,
    'detail' : '热点性能测试' ,
    'url' : 'pages/subBenchmarkTest/hotspotBenchmarkTest' ,
    'image' : $r('app.media.Benchmark') ,
    'category' : Category.BenchMark
  },
  {
    'name' : 'HotspotManagerBenchmarkTest' ,
    'detail' : '热点Manager性能测试' ,
    'url' : 'pages/subBenchmarkTest/hotspotManagerBenchmarkTest' ,
    'image' : $r('app.media.Benchmark') ,
    'category' : Category.BenchMark
  },
  {
    'name' : 'P2pBenchmarkTest' ,
    'detail' : 'p2p性能测试' ,
    'url' : 'pages/subBenchmarkTest/p2pBenchmarkTest' ,
    'image' : $r('app.media.Benchmark') ,
    'category' : Category.BenchMark
  },
  {
    'name' : 'P2pManagerBenchmarkTest' ,
    'detail' : 'p2pManager性能测试' ,
    'url' : 'pages/subBenchmarkTest/p2pManagerBenchmarkTest' ,
    'image' : $r('app.media.Benchmark') ,
    'category' : Category.BenchMark
  },
  {
    'name' : 'WifiStressTest' ,
    'detail' : 'Wifi压力测试' ,
    'url' : 'pages/subStressTest/wifiStressTest' ,
    'image' : $r('app.media.StressTest') ,
    'category' : Category.Stress
  },
  {
    'name' : 'WifiManagerStressTest' ,
    'detail' : 'WifiManager压力测试' ,
    'url' : 'pages/subStressTest/wifiManagerStressTest' ,
    'image' : $r('app.media.StressTest') ,
    'category' : Category.Stress
  },
  {
    'name' : 'HotspotStressTest' ,
    'detail' : '热点压力测试' ,
    'url' : 'pages/subStressTest/hotspotStressTest' ,
    'image' : $r('app.media.StressTest') ,
    'category' : Category.Stress
  },
  {
    'name' : 'HotspotManagerStressTest' ,
    'detail' : '热点Manager压力测试' ,
    'url' : 'pages/subStressTest/hotspotManagerStressTest' ,
    'image' : $r('app.media.StressTest') ,
    'category' : Category.Stress
  },
  {
    'name' : 'P2pStressTest' ,
    'detail' : 'p2p压力测试' ,
    'url' : 'pages/subStressTest/p2pStressTest' ,
    'image' : $r('app.media.StressTest') ,
    'category' : Category.Stress
  },
  {
    'name' : 'P2pManagerStressTest' ,
    'detail' : 'p2pManager压力测试' ,
    'url' : 'pages/subStressTest/p2pManagerStressTest' ,
    'image' : $r('app.media.StressTest') ,
    'category' : Category.Stress
  }
]

export function initTestData(): Array<TestData> {
  let TestDataArray: Array<TestData> = []
  TestComposition.forEach(item => {
    TestDataArray.push(new TestData(item.name , item.detail , item.url , item.image , item.category));
  })
  return TestDataArray;
}

export function initP2pManagerApIData(): Array<TestApi> {
  let TestApiArray: Array<TestApi> = []
  p2pManagerTestCase.forEach(item => {
    TestApiArray.push(new TestApi(item.name , item.detail , item.method , item.api , item.result , item.category));
  })
  return TestApiArray;
}

export function initLinkEnhanceApiData(): Array<TestApi> {
  let linkEnhanceApiArray: Array<TestApi> = []
  LinkEnhanceTestCase.forEach(item => {
    linkEnhanceApiArray.push(new TestApi(item.name, item.detail, item.method, item.api, item.result, item.category))
  })
  return linkEnhanceApiArray
}