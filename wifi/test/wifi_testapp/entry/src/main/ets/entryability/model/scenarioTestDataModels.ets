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
 * scenario DataModel of wifi test
 */

import { TestScenario , ScenarioCategory } from './testData'

import {
  testEnableWifi ,
  testDisableWifi ,
  testIsWifiActive ,
  testScan ,
  testGetScanInfosPromise ,
  testGetScanInfosCallback ,
  testAddDeviceConfigPromise ,
  testAddDeviceConfigCallback ,
  testAddUntrustedConfigPromise ,
  testAddUntrustedConfigCallback ,
  testRemoveUntrustedConfigPromise ,
  testRemoveUntrustedConfigCallback ,
  testConnectToNetwork ,
  testConnectToDevice ,
  testDisconnect ,
  testGetSignalLevel ,
  testGetLinkedInfoPromise ,
  testGetLinkedInfoCallback ,
  testIsConnected ,
  testGetSupportedFeatures ,
  testIsFeatureSupported ,
  testGetDeviceMacAddress ,
  testGetIpInfo ,
  testGetCountryCode ,
  testReassociate ,
  testReConnect ,
  testGetDeviceConfigs ,
  testUpdateNetwork ,
  testDisableNetwork ,
  testRemoveAllNetwork ,
  testRemoveDevice ,
  testOnWifiStateChange ,
  testOnWifiConnectionChange ,
  testOnWifiScanStateChange ,
  testOnWifiRssiChange
} from './wifiInterface'

import {
  testEnableWifiManager ,
  testDisableWifiManager ,
  testIsWifiActiveManager ,
  testScanManager ,
  testGetScanInfoListManager ,
/*testGetScanResultsManagerPromise,
  testGetScanResultsManagerCallback,
  testGetScanResultsSyncManager,*/
  testAddDeviceConfigManagerPromise ,
  testAddDeviceConfigManagerCallback ,
  testAddCandidateConfigManagerPromise ,
  testAddCandidateConfigManagerCallback ,
  testRemoveCandidateConfigManagerPromise ,
  testRemoveCandidateConfigManagerCallback ,
  testGetCandidateConfigsManager ,
  testConnectToCandidateConfigManager ,
  testConnectToNetworkManager ,
  testConnectToDeviceManager ,
  testDisconnectManager ,
  testGetSignalLevelManager ,
  testGetLinkedInfoManagerPromise ,
  testGetLinkedInfoManagerCallback ,
  testIsConnectedManager ,
  testGetSupportedFeaturesManager ,
  testIsFeatureSupportedManager ,
  testGetDeviceMacAddressManager ,
  testGetIpInfoManager ,
  testGetCountryCodeManager ,
  testReassociateManager ,
  testReconnectManager ,
  testGetDeviceConfigsManager ,
  testUpdateDeviceConfigManager ,
  testDisableDeviceConfigManager ,
  testRemoveAllDeviceConfigsManager ,
  testRemoveDeviceConfigManager ,
  testOnWifiStateChangeManager ,
  testOnWifiConnectionChangeManager ,
  testOnWifiScanStateChangeManager ,
  testOnWifiRssiChangeManager ,
  testOnStreamChangeManager ,
  testOnDeviceConfigChangeManager
} from './wifiManagerInterface'

import {
  testEnableHotspot ,
  testDisableHotspot ,
  testIsHotspotDualBandSupported ,
  testIsHostActive ,
  testSetHotspotConfig ,
  testGetHotspotConfig ,
  testGetStations ,
  testOnHotspotStateChange
} from './hotspotInterface'

import {
  testEnableHotspotManager ,
  testDisableHotspotManager ,
  testIsHotspotDualBandSupportedManager ,
  testIsHostActiveManager ,
  testSetHotspotConfigManager ,
  testGetHotspotConfigManager ,
  testGetHotspotStationsManager ,
  testOnHotspotStateChangeManager ,
  testOnHotspotStaJoinManager ,
  testOnHotspotStaLeaveManager
} from "./hotspotManagerInterface"

import {
  testGetP2pLinkedInfoPromise ,
  testGetP2pLinkedInfoCallback ,
  testGetCurrentGroupPromise ,
  testGetCurrentGroupCallback ,
  testGetP2pPeerDevicesPromise ,
  testGetP2pPeerDevicesCallback ,
  testCreateGroup ,
  testRemoveGroup ,
  testP2pConnect ,
  testP2pCancelConnect ,
  testStartDiscoverDevices ,
  testStopDiscoverDevices ,
  testDeletePersistentGroup ,
  testSetDeviceName ,
  testOnP2pStateChange ,
  testOnP2pConnectionChange ,
  testOnP2pDeviceChange ,
  testOnP2pPeerDeviceChange ,
  testOnP2pPersistentGroupChange ,
  testOnP2pDiscoveryChange
} from './p2pInterface'

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
  testDeletePersistentP2pGroupManager ,
  testGetP2pGroupsManagerPromise ,
  testGetP2pGroupsManagerCallback ,
  testSetP2pDeviceNameManager ,
  testOnP2pStateChangeManager ,
  testOnP2pConnectionChangeManager ,
  testOnP2pDeviceChangeManager ,
  testOnP2pPeerDeviceChangeManager ,
  testOnP2pPersistentGroupChangeManager ,
  testOnP2pDiscoveryChangeManager
} from './p2pManagerInterface'

import wifi from '@ohos.wifi';

interface ScenarioTest {
  name: string;
  detail: string;
  method: string;
  api: Function;
  result: string;
  category: ScenarioCategory;
}

export const WifiConnectScenarioTestCase: ScenarioTest[] = [
  {
    'name' : '注册WLAN状态改变事件' ,
    'detail' : '1' ,
    'method' : 'on.WifiStateChange' ,
    'api' : testOnWifiStateChange ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '是否已使能' ,
    'detail' : '2' ,
    'method' : 'isWifiActive' ,
    'api' : testIsWifiActive ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '开Wifi' ,
    'detail' : '3' ,
    'method' : 'enableWifi' ,
    'api' : testEnableWifi ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '注册WLAN连接状态改变事件' ,
    'detail' : '4' ,
    'method' : 'on.WifiConnectionChange' ,
    'api' : testOnWifiConnectionChange ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '注册扫描状态改变事件' ,
    'detail' : '5' ,
    'method' : 'on.WifiScanStateChange' ,
    'api' : testOnWifiScanStateChange ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '注册RSSI状态改变事件' ,
    'detail' : '6' ,
    'method' : 'on.WifiRssiChange' ,
    'api' : testOnWifiRssiChange ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '启动WLAN扫描' ,
    'detail' : '7' ,
    'method' : 'scan' ,
    'api' : testScan ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '获取扫描结果Callback' ,
    'detail' : '8' ,
    'method' : 'getScanInfos' ,
    'api' : testGetScanInfosCallback ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '添加网络配置Callback' ,
    'detail' : '9' ,
    'method' : 'addDeviceConfig' ,
    'api' : testAddDeviceConfigCallback ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '连接到指定网络' ,
    'detail' : '10' ,
    'method' : 'connectToDevice' ,
    'api' : testConnectToDevice ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '是否已连接' ,
    'detail' : '11' ,
    'method' : 'isConnected' ,
    'api' : testIsConnected ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '获取WLAN连接信息Callback' ,
    'detail' : '12' ,
    'method' : 'GetLinkedInfo' ,
    'api' : testGetLinkedInfoCallback ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '获取设备的MAC地址' ,
    'detail' : '13' ,
    'method' : 'getDeviceMacAddress' ,
    'api' : testGetDeviceMacAddress ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '获取IP信息' ,
    'detail' : '14' ,
    'method' : 'getIpInfo' ,
    'api' : testGetIpInfo ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '获取国家码信息' ,
    'detail' : '15' ,
    'method' : 'getCountryCode' ,
    'api' : testGetCountryCode ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '查询WLAN信号强度' ,
    'detail' : '16' ,
    'method' : 'getSignalLevel' ,
    'api' : testGetSignalLevel ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  },
  {
    'name' : '获取网络配置' ,
    'detail' : '17' ,
    'method' : 'getDeviceConfigs' ,
    'api' : testGetDeviceConfigs ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiScanScenario
  }
]

export const WifiManagerConnectScenarioTestCase: ScenarioTest[] = [
  {
    'name' : '注册WLAN状态改变事件' ,
    'detail' : '1' ,
    'method' : 'on.wifiStateChange' ,
    'api' : testOnWifiStateChangeManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '是否已使能' ,
    'detail' : '2' ,
    'method' : 'isWifiActive' ,
    'api' : testIsWifiActiveManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '开Wifi' ,
    'detail' : '3' ,
    'method' : 'enableWifi' ,
    'api' : testEnableWifiManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '注册WLAN连接状态改变事件' ,
    'detail' : '4' ,
    'method' : 'on.wifiConnectionChange' ,
    'api' : testOnWifiConnectionChangeManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '注册扫描状态改变事件' ,
    'detail' : '5' ,
    'method' : 'on.wifiScanStateChange' ,
    'api' : testOnWifiScanStateChangeManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '注册RSSI状态改变事件' ,
    'detail' : '6' ,
    'method' : 'on.wifiRssiChange' ,
    'api' : testOnWifiRssiChangeManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '启动WLAN扫描' ,
    'detail' : '7' ,
    'method' : 'scan' ,
    'api' : testScanManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '添加网络配置Callback' ,
    'detail' : '9' ,
    'method' : 'addDeviceConfig' ,
    'api' : testAddDeviceConfigManagerCallback ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '连接到指定网络' ,
    'detail' : '10' ,
    'method' : 'connectToDevice' ,
    'api' : testConnectToDeviceManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '是否已连接' ,
    'detail' : '11' ,
    'method' : 'isConnected' ,
    'api' : testIsConnectedManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '获取WLAN连接信息Callback' ,
    'detail' : '12' ,
    'method' : 'GetLinkedInfo' ,
    'api' : testGetLinkedInfoManagerCallback ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '获取设备的MAC地址' ,
    'detail' : '13' ,
    'method' : 'getDeviceMacAddress' ,
    'api' : testGetDeviceMacAddressManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '获取IP信息' ,
    'detail' : '14' ,
    'method' : 'getIpInfo' ,
    'api' : testGetIpInfoManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '获取国家码信息' ,
    'detail' : '15' ,
    'method' : 'getCountryCode' ,
    'api' : testGetCountryCodeManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '查询WLAN信号强度' ,
    'detail' : '16' ,
    'method' : 'getSignalLevel' ,
    'api' : testGetSignalLevelManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
  {
    'name' : '获取网络配置' ,
    'detail' : '17' ,
    'method' : 'getDeviceConfigs' ,
    'api' : testGetDeviceConfigsManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.WifiManagerScanScenario
  },
]

export const HotspotCreateScenarioTestCase: ScenarioTest[] = [
  {
    'name' : '注册热点状态改变事件' ,
    'detail' : '1' ,
    'method' : 'on.hotspotStateChange' ,
    'api' : testOnHotspotStateChange ,
    'result' : 'None' ,
    'category' : ScenarioCategory.HotspotCreateScenario
  },
  {
    'name' : '热点是否已使能' ,
    'detail' : '2' ,
    'method' : 'isHostActive' ,
    'api' : testIsHostActive ,
    'result' : 'None' ,
    'category' : ScenarioCategory.HotspotCreateScenario
  },
  {
    'name' : '使能热点' ,
    'detail' : '3' ,
    'method' : 'enableHotspot' ,
    'api' : testEnableHotspot ,
    'result' : 'None' ,
    'category' : ScenarioCategory.HotspotCreateScenario
  },
  {
    'name' : '热点是否支持双频' ,
    'detail' : '4' ,
    'method' : 'isHotspotDualBandSupported' ,
    'api' : testIsHotspotDualBandSupported ,
    'result' : 'None' ,
    'category' : ScenarioCategory.HotspotCreateScenario
  },
  {
    'name' : '设置热点配置信息' ,
    'detail' : '5' ,
    'method' : 'setHotspotConfig' ,
    'api' : testSetHotspotConfig ,
    'result' : 'None' ,
    'category' : ScenarioCategory.HotspotCreateScenario
  },
  {
    'name' : '获取热点配置信息' ,
    'detail' : '6' ,
    'method' : 'getHotspotConfig' ,
    'api' : testGetHotspotConfig ,
    'result' : 'None' ,
    'category' : ScenarioCategory.HotspotCreateScenario
  }
]

export const HotspotManagerCreateScenarioTestCase: ScenarioTest[] = [
  {
    'name' : '注册热点状态改变事件' ,
    'detail' : '1' ,
    'method' : 'on.hotspotStateChange' ,
    'api' : testOnHotspotStateChangeManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.HotspotManagerCreateScenario
  },
  {
    'name' : '热点是否已使能' ,
    'detail' : '2' ,
    'method' : 'isHostActive' ,
    'api' : testIsHostActiveManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.HotspotManagerCreateScenario
  },
  {
    'name' : '使能热点' ,
    'detail' : '3' ,
    'method' : 'enableHotspot' ,
    'api' : testEnableHotspotManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.HotspotManagerCreateScenario
  },
  {
    'name' : '热点是否支持双频' ,
    'detail' : '4' ,
    'method' : 'isHotspotDualBandSupported' ,
    'api' : testIsHotspotDualBandSupportedManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.HotspotManagerCreateScenario
  },
  {
    'name' : '设置热点配置信息' ,
    'detail' : '5' ,
    'method' : 'setHotspotConfig' ,
    'api' : testSetHotspotConfigManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.HotspotManagerCreateScenario
  },
  {
    'name' : '获取热点配置信息' ,
    'detail' : '6' ,
    'method' : 'getHotspotConfig' ,
    'api' : testGetHotspotConfigManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.HotspotManagerCreateScenario
  }
]

export const P2pConnectScenarioTestCase: ScenarioTest[] = [
  {
    'name' : '注册P2P开关状态改变事件' ,
    'detail' : '1' ,
    'method' : 'On.P2pStateChange' ,
    'api' : testOnP2pStateChange ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pConnectScenario
  },
  {
    'name' : '注册P2P连接状态改变事件' ,
    'detail' : '2' ,
    'method' : 'On.P2pConnectionChange' ,
    'api' : testOnP2pConnectionChange ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pConnectScenario
  },
  {
    'name' : '注册P2P设备状态改变事件' ,
    'detail' : '3' ,
    'method' : 'On.p2pDeviceChange' ,
    'api' : testOnP2pDeviceChange ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pConnectScenario
  },
  {
    'name' : '注册P2P对端设备状态改变事件' ,
    'detail' : '4' ,
    'method' : 'On.p2pPeerDeviceChange' ,
    'api' : testOnP2pPeerDeviceChange ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pConnectScenario
  },
  {
    'name' : '注册P2P永久组状态改变事件' ,
    'detail' : '5' ,
    'method' : 'On.p2pPersistentGroupChange' ,
    'api' : testOnP2pPersistentGroupChange ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pConnectScenario
  },
  {
    'name' : '注册发现设备状态改变事件' ,
    'detail' : '6' ,
    'method' : 'On.p2pDiscoveryChange' ,
    'api' : testOnP2pDiscoveryChange ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pConnectScenario
  },
  {
    'name' : '设置设备名称' ,
    'detail' : '7' ,
    'method' : 'setDeviceName' ,
    'api' : testSetDeviceName ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pConnectScenario
  },
  {
    'name' : '创建群组' ,
    'detail' : '8' ,
    'method' : 'createGroup' ,
    'api' : testCreateGroup ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pConnectScenario
  },
  {
    'name' : '开始发现设备' ,
    'detail' : '9' ,
    'method' : 'startDiscoverDevices' ,
    'api' : testStartDiscoverDevices ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pConnectScenario
  },
  {
    'name' : '执行P2P连接' ,
    'detail' : '10' ,
    'method' : 'p2pConnect' ,
    'api' : testP2pConnect ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pConnectScenario
  },
  {
    'name' : '获取P2P连接信息Callback' ,
    'detail' : '11' ,
    'method' : 'getP2pLinkedInfo' ,
    'api' : testGetP2pLinkedInfoCallback ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pConnectScenario
  },
  {
    'name' : '获取P2P当前组信息Callback' ,
    'detail' : '12' ,
    'method' : 'getCurrentGroup' ,
    'api' : testGetCurrentGroupCallback ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pConnectScenario
  },
  {
    'name' : '获取P2P对端设备列表信息Callback' ,
    'detail' : '13' ,
    'method' : 'getP2pPeerDevices' ,
    'api' : testGetP2pPeerDevicesCallback ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pConnectScenario
  },
]

export const P2pManagerConnectScenarioTestCase: ScenarioTest[] = [
  {
    'name' : '注册P2P开关状态改变事件' ,
    'detail' : '1' ,
    'method' : 'On.P2pStateChange' ,
    'api' : testOnP2pStateChangeManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
  {
    'name' : '注册P2P连接状态改变事件' ,
    'detail' : '2' ,
    'method' : 'On.P2pConnectionChange' ,
    'api' : testOnP2pConnectionChangeManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
  {
    'name' : '注册P2P设备状态改变事件' ,
    'detail' : '3' ,
    'method' : 'On.p2pDeviceChange' ,
    'api' : testOnP2pDeviceChangeManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
  {
    'name' : '注册P2P对端设备状态改变事件' ,
    'detail' : '4' ,
    'method' : 'On.p2pPeerDeviceChange' ,
    'api' : testOnP2pPeerDeviceChangeManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
  {
    'name' : '注册P2P永久组状态改变事件' ,
    'detail' : '5' ,
    'method' : 'On.p2pPersistentGroupChange' ,
    'api' : testOnP2pPersistentGroupChangeManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
  {
    'name' : '注册发现设备状态改变事件' ,
    'detail' : '6' ,
    'method' : 'On.p2pDiscoveryChange' ,
    'api' : testOnP2pDiscoveryChangeManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
  {
    'name' : '设置设备名称' ,
    'detail' : '7' ,
    'method' : 'SetP2pDeviceName' ,
    'api' : testSetP2pDeviceNameManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
  {
    'name' : '创建群组' ,
    'detail' : '8' ,
    'method' : 'createGroup' ,
    'api' : testCreateP2pGroupManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
  {
    'name' : '开始发现设备' ,
    'detail' : '9' ,
    'method' : 'startDiscoverDevices' ,
    'api' : testStartDiscoverP2pDevicesManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
  {
    'name' : '执行P2P连接' ,
    'detail' : '10' ,
    'method' : 'p2pConnect' ,
    'api' : testP2pConnectManager ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
  {
    'name' : '获取P2P连接信息Callback' ,
    'detail' : '11' ,
    'method' : 'getP2pLinkedInfo' ,
    'api' : testGetP2pLinkedInfoManagerCallback ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
  {
    'name' : '获取P2P当前组信息Callback' ,
    'detail' : '12' ,
    'method' : 'getCurrentGroup' ,
    'api' : testGetCurrentP2pGroupManagerCallback ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
  {
    'name' : '获取P2P对端设备列表信息Callback' ,
    'detail' : '13' ,
    'method' : 'getP2pPeerDevices' ,
    'api' : testGetP2pPeerDevicesManagerCallback ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
  {
    'name' : '获取P2P本地设备列表信息Callback' ,
    'detail' : '14' ,
    'method' : 'getP2pPeerDevices' ,
    'api' : testGetP2pLocalDeviceManagerCallback ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
  {
    'name' : '获取创建的所有P2P群组信息Callback' ,
    'detail' : '15' ,
    'method' : 'GetP2pGroupsManagerCallback' ,
    'api' : testGetP2pGroupsManagerCallback ,
    'result' : 'None' ,
    'category' : ScenarioCategory.P2pManagerConnectScenario
  },
]

export function initWifiConnectScenarioData(): Array<TestScenario> {
  let TestScenarioArray: Array<TestScenario> = []
  WifiConnectScenarioTestCase.forEach(item => {
    TestScenarioArray.push(new TestScenario(item.name , item.detail , item.method , item.api , item.result , item.category));
  })
  return TestScenarioArray;
}

export function initWifiManagerConnectScenarioData(): Array<TestScenario> {
  let TestScenarioArray: Array<TestScenario> = []
  WifiManagerConnectScenarioTestCase.forEach(item => {
    TestScenarioArray.push(new TestScenario(item.name , item.detail , item.method , item.api , item.result , item.category));
  })
  return TestScenarioArray;
}

export function initHotspotCreateScenarioData(): Array<TestScenario> {
  let TestScenarioArray: Array<TestScenario> = []
  HotspotCreateScenarioTestCase.forEach(item => {
    TestScenarioArray.push(new TestScenario(item.name , item.detail , item.method , item.api , item.result , item.category));
  })
  return TestScenarioArray;
}

export function initHotspotManagerCreateScenarioData(): Array<TestScenario> {
  let TestScenarioArray: Array<TestScenario> = []
  HotspotManagerCreateScenarioTestCase.forEach(item => {
    TestScenarioArray.push(new TestScenario(item.name , item.detail , item.method , item.api , item.result , item.category));
  })
  return TestScenarioArray;
}

export function initP2pConnectScenarioData(): Array<TestScenario> {
  let TestScenarioArray: Array<TestScenario> = []
  P2pConnectScenarioTestCase.forEach(item => {
    TestScenarioArray.push(new TestScenario(item.name , item.detail , item.method , item.api , item.result , item.category));
  })
  return TestScenarioArray;
}

export function initP2pManagerConnectScenarioData(): Array<TestScenario> {
  let TestScenarioArray: Array<TestScenario> = []
  P2pManagerConnectScenarioTestCase.forEach(item => {
    TestScenarioArray.push(new TestScenario(item.name , item.detail , item.method , item.api , item.result , item.category));
  })
  return TestScenarioArray;
}