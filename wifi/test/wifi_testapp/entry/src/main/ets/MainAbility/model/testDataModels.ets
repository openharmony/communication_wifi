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

import { TestData, TestApi, Category, CaseCategory } from './testData'

import { testEnableWifi, testDisableWifi, testIsWifiActive,testScan,testGetScanInfosPromise,testGetScanInfosCallback,
  testAddDeviceConfigPromise,testAddDeviceConfigCallback,testAddUntrustedConfigPromise, testAddUntrustedConfigCallback,testRemoveUntrustedConfigPromise ,
  testRemoveUntrustedConfigCallback,testConnectToNetwork,testConnectToDevice,testDisconnect,testGetSignalLevel,
  testGetLinkedInfoPromise,testGetLinkedInfoCallback,testIsConnected,testGetSupportedFeatures,testIsFeatureSupported,testGetDeviceMacAddress,
  testGetIpInfo,testGetCountryCode,testReassociate,testReConnect,testGetDeviceConfigs,testUpdateNetwork,testDisableNetwork,testRemoveAllNetwork,
  testRemoveDevice,testOnWifiStateChange,testOnWifiConnectionChange,testOnWifiScanStateChange,testOnWifiRssiChange} from './wifiInterface'

import { testEnableWifiManager,testDisableWifiManager, testIsWifiActiveManager,testScanManager,testGetScanInfoListManager,/*testGetScanResultsManagerPromise,
  testGetScanResultsManagerCallback,testGetScanResultsSyncManager,*/testAddDeviceConfigManagerPromise,testAddDeviceConfigManagerCallback,testAddCandidateConfigManagerPromise,
  testAddCandidateConfigManagerCallback,testRemoveCandidateConfigManagerPromise,testRemoveCandidateConfigManagerCallback,testGetCandidateConfigsManager,
  testConnectToCandidateConfigManager,testConnectToNetworkManager,testConnectToDeviceManager,testDisconnectManager,testGetSignalLevelManager,
  testGetLinkedInfoManagerPromise,testGetLinkedInfoManagerCallback,testIsConnectedManager,testGetSupportedFeaturesManager,testIsFeatureSupportedManager,
  testGetDeviceMacAddressManager,testGetIpInfoManager,testGetCountryCodeManager,testReassociateManager,testReconnectManager,testGetDeviceConfigsManager,
  testUpdateDeviceConfigManager,testDisableDeviceConfigManager,testRemoveAllDeviceConfigsManager,testRemoveDeviceConfigManager,testOnWifiStateChangeManager,
  testOnWifiConnectionChangeManager,testOnWifiScanStateChangeManager,testOnWifiRssiChangeManager,testOnStreamChangeManager,testOnDeviceConfigChangeManager
} from './wifiManagerInterface'

import { testEnableHotspot, testDisableHotspot, testIsHotspotDualBandSupported, testIsHostActive,testSetHotspotConfig,testGetHotspotConfig,testGetStations,testOnHotspotStateChange
} from './hotspotInterface'

import {testEnableHotspotManager,testDisableHotspotManager,testIsHotspotDualBandSupportedManager,testIsHostActiveManager,
  testSetHotspotConfigManager,testGetHotspotConfigManager,testGetHotspotStationsManager,testOnHotspotStateChangeManager,
  testOnHotspotStaJoinManager,testOnHotspotStaLeaveManager
} from "./hotspotManagerInterface"

import {testGetP2pLinkedInfoPromise, testGetP2pLinkedInfoCallback, testGetCurrentGroupPromise, testGetCurrentGroupCallback, testGetP2pPeerDevicesPromise, testGetP2pPeerDevicesCallback,
  testCreateGroup, testRemoveGroup,testP2pConnect,testP2pCancelConnect,testStartDiscoverDevices, testStopDiscoverDevices, testDeletePersistentGroup,  testSetDeviceName,testOnP2pStateChange,
  testOnP2pConnectionChange, testOnP2pDeviceChange,testOnP2pPeerDeviceChange, testOnP2pPersistentGroupChange,testOnP2pDiscoveryChange } from './p2pInterface'


import wifi from '@ohos.wifi';
const WiFiTestCase: any[]= [
  { 'name': '注册WLAN状态改变事件', 'detail': '注册WLAN状态改变事件', 'method': 'on.WifiStateChange', 'api': testOnWifiStateChange, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '是否已使能', 'detail': '是否已使能', 'method': 'isWifiActive', 'api': testIsWifiActive, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '开WiFi', 'detail': '使能WiFi', 'method': 'enableWiFi', 'api': testEnableWifi, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '关wifi', 'detail': '去使能wifi', 'method': 'disableWiFi', 'api': testDisableWifi, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '注册WLAN连接状态改变事件', 'detail': '注册WLAN连接状态改变事件', 'method': 'on.WifiConnectionChange', 'api': testOnWifiConnectionChange, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '注册扫描状态改变事件', 'detail': '注册扫描状态改变事件', 'method': 'on.WifiScanStateChange', 'api': testOnWifiScanStateChange, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '注册RSSI状态改变事件', 'detail': '注册RSSI状态改变事件', 'method': 'on.WifiRssiChange', 'api': testOnWifiRssiChange, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '启动WLAN扫描', 'detail': '启动WLAN扫描', 'method': 'scan', 'api': testScan, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '获取扫描结果Promise', 'detail': '获取扫描结果Promise', 'method': 'getScanInfos', 'api': testGetScanInfosPromise, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '获取扫描结果Callback', 'detail': '获取扫描结果Callback', 'method': 'getScanInfos', 'api': testGetScanInfosCallback, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '添加网络配置Promise', 'detail': '添加网络配置Promise', 'method': 'addDeviceConfig', 'api': testAddDeviceConfigPromise, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '添加网络配置Callback', 'detail': '添加网络配置Callback', 'method': 'addDeviceConfig', 'api': testAddDeviceConfigCallback, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '添加不可信网络配置Promise', 'detail': '添加不可信网络配置Promise', 'method': 'addUntrustedConfig', 'api': testAddUntrustedConfigPromise, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '添加不可信网络配置Callback', 'detail': '添加不可信网络配置Callback', 'method': 'addUntrustedConfig', 'api': testAddUntrustedConfigCallback, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '移除不可信网络配置Promise', 'detail': '移除不可信网络配置Promise', 'method': 'removeUntrustedConfig', 'api': testRemoveUntrustedConfigPromise, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '移除不可信网络配置Callback', 'detail': '移除不可信网络配置Callback', 'method': 'removeUntrustedConfig', 'api': testRemoveUntrustedConfigCallback, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '连接到指定网络', 'detail': '连接到指定网络', 'method': 'connectToNetwork', 'api': testConnectToNetwork, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '连接到指定网络', 'detail': '连接到指定网络', 'method': 'connectToDevice', 'api': testConnectToDevice, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '断开连接的网络', 'detail': '断开连接的网络', 'method': 'disconnect', 'api': testDisconnect, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '是否已连接', 'detail': '查询WLAN是否已连接', 'method': 'isConnected', 'api': testIsConnected, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '获取WLAN连接信息Promise', 'detail': '获取WLAN连接信息Promise', 'method': 'GetLinkedInfo', 'api': testGetLinkedInfoPromise, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '获取WLAN连接信息Callback', 'detail': '获取WLAN连接信息Callback', 'method': 'GetLinkedInfo', 'api': testGetLinkedInfoCallback, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '获取设备的MAC地址', 'detail': '获取设备的MAC地址', 'method': 'getDeviceMacAddress', 'api': testGetDeviceMacAddress, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '获取IP信息', 'detail': '获取IP信息', 'method': 'getIpInfo', 'api': testGetIpInfo, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '获取国家码信息', 'detail': '获取国家码信息', 'method': 'getCountryCode', 'api': testGetCountryCode, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '查询WLAN信号强度', 'detail': '查询WLAN信号强度', 'method': 'getSignalLevel', 'api': testGetSignalLevel, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '查询设备支持的特性', 'detail': '查询设备支持的特性', 'method': 'getSupportedFeatures', 'api': testGetSupportedFeatures, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '是否支持相关WLAN特性', 'detail': '判断设备是否支持相关WLAN特性', 'method': 'isFeatureSupported', 'api': testIsFeatureSupported, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '重新关联网络', 'detail': '重新关联网络', 'method': 'reassociate', 'api': testReassociate, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '重新连接网络', 'detail': '重新连接网络', 'method': 'reConnect', 'api': testReConnect, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '获取网络配置', 'detail': '获取网络配置', 'method': 'getDeviceConfigs', 'api': testGetDeviceConfigs, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '更新网络配置', 'detail': '更新网络配置', 'method': 'updateNetwork', 'api': testUpdateNetwork, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '去使能网络配置', 'detail': '去使能网络配置', 'method': 'disableNetwork', 'api': testDisableNetwork, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '移除指定的网络配置', 'detail': '移除指定的网络配置', 'method': 'removeDevice', 'api': testRemoveDevice, 'result': 'None', 'category': CaseCategory.Wifi },
  { 'name': '移除所有网络配置', 'detail': '移除所有网络配置', 'method': 'removeAllNetwork', 'api': testRemoveAllNetwork, 'result': 'None', 'category': CaseCategory.Wifi }
]

const WiFiManagerTestCase: any[] =[
  { 'name': '注册WLAN状态改变事件', 'detail': '注册WLAN状态改变事件', 'method': 'on.wifiStateChange', 'api': testOnWifiStateChangeManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '是否已使能', 'detail': '是否已使能', 'method': 'isWifiActive', 'api': testIsWifiActiveManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '开WiFi', 'detail': '使能WiFi', 'method': 'enableWiFi', 'api': testEnableWifiManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '关wifi', 'detail': '去使能wifi', 'method': 'disableWiFi', 'api': testDisableWifiManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '注册WLAN连接状态改变事件', 'detail': '注册WLAN连接状态改变事件', 'method': 'on.wifiConnectionChange', 'api': testOnWifiConnectionChangeManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '注册扫描状态改变事件', 'detail': '注册扫描状态改变事件', 'method': 'on.wifiScanStateChange', 'api': testOnWifiScanStateChangeManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '注册RSSI状态改变事件', 'detail': '注册RSSI状态改变事件', 'method': 'on.wifiRssiChange', 'api': testOnWifiRssiChangeManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '启动WLAN扫描', 'detail': '启动WLAN扫描', 'method': 'scan', 'api': testScanManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '获取扫描信息列表', 'detail': '获取扫描信息列表', 'method': 'getScanInfoList', 'api': testGetScanInfoListManager, 'result': 'None', 'category': CaseCategory.WifiManger },

//  { 'name': '获取扫描结果sync', 'detail': '获取扫描结果sync', 'method': 'getScanResultsSync', 'api': testGetScanResultsSyncManager, 'result': 'None', 'category': CaseCategory.WifiManger },
//  { 'name': '获取扫描结果Promise', 'detail': '获取扫描结果Promise', 'method': 'getScanResults', 'api': testGetScanResultsManagerPromise, 'result': 'None', 'category': CaseCategory.WifiManger },
//  { 'name': '获取扫描结果Callback', 'detail': '获取扫描结果Callback', 'method': 'getScanResults', 'api': testGetScanResultsManagerCallback, 'result': 'None', 'category': CaseCategory.WifiManger },

  { 'name': '添加网络配置Promise', 'detail': '添加网络配置Promise', 'method': 'addDeviceConfig', 'api': testAddDeviceConfigManagerPromise, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '添加网络配置Callback', 'detail': '添加网络配置Callback', 'method': 'addDeviceConfig', 'api': testAddDeviceConfigManagerCallback, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '添加候选网络配置Promise', 'detail': '添加候选网络配置Promise', 'method': 'addCandidateConfig', 'api': testAddCandidateConfigManagerPromise, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '添加候选网络配置Callback', 'detail': '添加候选网络配置Callback', 'method': 'addCandidateConfig', 'api': testAddCandidateConfigManagerCallback, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '移除候选网络配置Promise', 'detail': '移除候选网络配置Promise', 'method': 'removeCandidateConfig', 'api': testRemoveCandidateConfigManagerPromise, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '移除候选网络配置Callback', 'detail': '移除候选网络配置Callback', 'method': 'removeCandidateConfig', 'api': testRemoveCandidateConfigManagerCallback, 'result': 'None', 'category': CaseCategory.WifiManger },

  { 'name': '获取候选网络配置', 'detail': '获取候选网络配置', 'method': 'getCandidateConfigs', 'api': testGetCandidateConfigsManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '连接到候选网络', 'detail': '连接到候选网络', 'method': 'connectToCandidateConfig', 'api': testConnectToCandidateConfigManager, 'result': 'None', 'category': CaseCategory.WifiManger },

  { 'name': '连接到指定网络', 'detail': '连接到指定网络', 'method': 'connectToNetwork', 'api': testConnectToNetworkManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '连接到指定网络', 'detail': '连接到指定网络', 'method': 'connectToDevice', 'api': testConnectToDeviceManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '断开连接的网络', 'detail': '断开连接的网络', 'method': 'disconnect', 'api': testDisconnectManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '是否已连接', 'detail': '查询WLAN是否已连接', 'method': 'isConnected', 'api': testIsConnectedManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '获取WLAN连接信息Promise', 'detail': '获取WLAN连接信息Promise', 'method': 'GetLinkedInfo', 'api': testGetLinkedInfoManagerPromise, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '获取WLAN连接信息Callback', 'detail': '获取WLAN连接信息Callback', 'method': 'GetLinkedInfo', 'api': testGetLinkedInfoManagerCallback, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '获取设备的MAC地址', 'detail': '获取设备的MAC地址', 'method': 'getDeviceMacAddress', 'api': testGetDeviceMacAddressManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '获取IP信息', 'detail': '获取IP信息', 'method': 'getIpInfo', 'api': testGetIpInfoManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '获取国家码信息', 'detail': '获取国家码信息', 'method': 'getCountryCode', 'api': testGetCountryCodeManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '查询WLAN信号强度', 'detail': '查询WLAN信号强度', 'method': 'getSignalLevel', 'api': testGetSignalLevelManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '查询设备支持的特性', 'detail': '查询设备支持的特性', 'method': 'getSupportedFeatures', 'api': testGetSupportedFeaturesManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '是否支持相关WLAN特性', 'detail': '判断设备是否支持相关WLAN特性', 'method': 'isFeatureSupported', 'api': testIsFeatureSupportedManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '重新关联网络', 'detail': '重新关联网络', 'method': 'reassociate', 'api': testReassociateManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '重新连接网络', 'detail': '重新连接网络', 'method': 'reConnect', 'api': testReconnectManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '获取网络配置', 'detail': '获取网络配置', 'method': 'getDeviceConfigs', 'api': testGetDeviceConfigsManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '更新网络配置', 'detail': '更新网络配置', 'method': 'updateDeviceConfig', 'api': testUpdateDeviceConfigManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '去使能网络配置', 'detail': '去使能网络配置', 'method': 'disableDeviceConfig', 'api': testDisableDeviceConfigManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '移除指定的网络配置', 'detail': '移除指定的网络配置', 'method': 'removeDeviceConfig', 'api': testRemoveDeviceConfigManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '移除所有网络配置', 'detail': '移除所有网络配置', 'method': 'removeAllDeviceConfigs', 'api': testRemoveAllDeviceConfigsManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '注册流改变事件', 'detail': '注册扫描状态改变事件', 'method': 'on.streamChange', 'api': testOnStreamChangeManager, 'result': 'None', 'category': CaseCategory.WifiManger },
  { 'name': '注册设备配置改变事件', 'detail': '注册RSSI状态改变事件', 'method': 'on.deviceConfigChange', 'api': testOnDeviceConfigChangeManager, 'result': 'None', 'category': CaseCategory.WifiManger },
]

const HotspotTestCase: any[]  = [
  { 'name': '使能热点', 'detail': '使能热点', 'method': 'enableHotspot', 'api': testEnableHotspot, 'result': 'None', 'category': CaseCategory.Hotspot },
  { 'name': '去使能热点', 'detail': '去使能热点', 'method': 'disableHotspot', 'api': testDisableHotspot, 'result': 'None', 'category': CaseCategory.Hotspot },
  { 'name': '热点是否支持双频', 'detail': '热点是否支持双频', 'method': 'isHotspotDualBandSupported', 'api': testIsHotspotDualBandSupported, 'result': 'None', 'category': CaseCategory.Hotspot },
  { 'name': '热点是否已使能', 'detail': '热点是否已使能', 'method': 'isHostActive', 'api': testIsHostActive, 'result': 'None', 'category': CaseCategory.Hotspot },
  { 'name': '设置热点配置信息', 'detail': '设置热点配置信息', 'method': 'setHotspotConfig', 'api': testSetHotspotConfig, 'result': 'None', 'category': CaseCategory.Hotspot },
  { 'name': '获取热点配置信息', 'detail': '获取热点配置信息', 'method': 'getHotspotConfig', 'api': testGetHotspotConfig, 'result': 'None', 'category': CaseCategory.Hotspot },
  { 'name': '获取连接的设备', 'detail': '获取连接的设备', 'method': 'getStations', 'api': testGetStations, 'result': 'None', 'category': CaseCategory.Hotspot },
  { 'name': '注册热点状态改变事件', 'detail': '注册热点状态改变事件', 'method': 'on.hotspotStateChange', 'api': testOnHotspotStateChange, 'result': 'None', 'category': CaseCategory.Hotspot }
]

const HotspotManagerTestCase: any[] =[
  { 'name': '使能热点', 'detail': '使能热点', 'method': 'enableHotspot', 'api': testEnableHotspotManager, 'result': 'None', 'category': CaseCategory.HotspotManager },
  { 'name': '去使能热点', 'detail': '去使能热点', 'method': 'disableHotspot', 'api': testDisableHotspotManager, 'result': 'None', 'category': CaseCategory.HotspotManager },
  { 'name': '热点是否支持双频', 'detail': '热点是否支持双频', 'method': 'isHotspotDualBandSupported', 'api': testIsHotspotDualBandSupportedManager, 'result': 'None', 'category': CaseCategory.HotspotManager },
  { 'name': '热点是否已使能', 'detail': '热点是否已使能', 'method': 'isHostActive', 'api': testIsHostActiveManager, 'result': 'None', 'category': CaseCategory.HotspotManager },
  { 'name': '设置热点配置信息', 'detail': '设置热点配置信息', 'method': 'setHotspotConfig', 'api': testSetHotspotConfigManager, 'result': 'None', 'category': CaseCategory.HotspotManager },
  { 'name': '获取热点配置信息', 'detail': '获取热点配置信息', 'method': 'getHotspotConfig', 'api': testGetHotspotConfigManager, 'result': 'None', 'category': CaseCategory.HotspotManager },
  { 'name': '获取连接的设备', 'detail': '获取连接的设备', 'method': 'getStations', 'api': testGetHotspotStationsManager, 'result': 'None', 'category': CaseCategory.HotspotManager },
  { 'name': '注册热点状态改变事件', 'detail': '注册热点状态改变事件', 'method': 'on.hotspotStateChange', 'api': testOnHotspotStateChangeManager, 'result': 'None', 'category': CaseCategory.HotspotManager },
  { 'name': '注册加入改变事件', 'detail': '注册热点状态改变事件', 'method': 'on.hotspotStateChange', 'api': testOnHotspotStaJoinManager, 'result': 'None', 'category': CaseCategory.HotspotManager },
  { 'name': '注册离开改变事件', 'detail': '注册热点状态改变事件', 'method': 'on.hotspotStateChange', 'api': testOnHotspotStaLeaveManager, 'result': 'None', 'category': CaseCategory.HotspotManager }
]

const p2pTestCase: any[] =[
  { 'name': '获取P2P连接信息Promise', 'detail': '获取P2P连接信息Promise', 'method': 'getP2pLinkedInfo', 'api': testGetP2pLinkedInfoPromise, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '获取P2P连接信息Callback', 'detail': '获取P2P连接信息Callback', 'method': 'getP2pLinkedInfo', 'api': testGetP2pLinkedInfoCallback, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '获取P2P当前组信息Promise', 'detail': '获取P2P当前组信息Promise', 'method': 'getCurrentGroup', 'api': testGetCurrentGroupPromise, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '获取P2P当前组信息Callback', 'detail': '获取P2P当前组信息Callback', 'method': 'getCurrentGroup', 'api': testGetCurrentGroupCallback, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '获取P2P对端设备列表信息Promise', 'detail': '获取P2P对端设备列表信息Promise', 'method': 'getP2pPeerDevices', 'api': testGetP2pPeerDevicesPromise, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '获取P2P对端设备列表信息Callback', 'detail': '获取P2P对端设备列表信息Callback', 'method': 'getP2pPeerDevices', 'api': testGetP2pPeerDevicesCallback, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '开始发现设备', 'detail': '创建群组', 'method': 'createGroup', 'api': testCreateGroup, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '停止发现设备', 'detail': '移除群组', 'method': 'removeGroup', 'api': testRemoveGroup, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '设置设备名称', 'detail': '执行P2P连接', 'method': 'p2pConnect', 'api': testP2pConnect, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '取消P2P连接', 'detail': '取消P2P连接', 'method': 'p2pCancelConnect', 'api': testP2pCancelConnect, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '开始发现设备', 'detail': '开始发现设备', 'method': 'startDiscoverDevices', 'api': testStartDiscoverDevices, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '停止发现设备', 'detail': '停止发现设备', 'method': 'stopDiscoverDevices', 'api': testStopDiscoverDevices, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '删除永久组', 'detail': '删除永久组', 'method': 'deletePersistentGroup', 'api': testDeletePersistentGroup, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '设置设备名称', 'detail': '设置设备名称', 'method': 'setDeviceName', 'api': testSetDeviceName, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '注册P2P开关状态改变事件', 'detail': '注册P2P开关状态改变事件', 'method': 'On.P2pStateChange', 'api': testOnP2pStateChange, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '注册P2P连接状态改变事件', 'detail': '注册P2P连接状态改变事件', 'method': 'On.P2pConnectionChange', 'api': testOnP2pConnectionChange, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '注册P2P设备状态改变事件', 'detail': '注册P2P设备状态改变事件', 'method': 'On.p2pDeviceChange', 'api': testOnP2pDeviceChange, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '注册P2P对端设备状态改变事件', 'detail': '注册P2P对端设备状态改变事件', 'method': 'On.p2pPeerDeviceChange', 'api': testOnP2pPeerDeviceChange, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '注册P2P永久组状态改变事件', 'detail': '注册P2P永久组状态改变事件', 'method': 'On.p2pPersistentGroupChange', 'api': testOnP2pPersistentGroupChange, 'result': 'None', 'category': CaseCategory.P2p },
  { 'name': '注册发现设备状态改变事件', 'detail': '注册发现设备状态改变事件', 'method': 'On.p2pDiscoveryChange', 'api': testOnP2pDiscoveryChange, 'result': 'None', 'category': CaseCategory.P2p },
]

const p2pManagerTestCase: any[] = [

]

const TestComposition: any[] = [
  { 'name': 'WIFI', 'detail': 'wifi测试', 'url': 'pages/subManualApiTest/wifiInterfaceTest', 'image': $r('app.media.wifi'), 'category': Category.API},
  { 'name': 'WIFIManager', 'detail': 'wifiManager测试', 'url': 'pages/subManualApiTest/wifiManagerInterfaceTest', 'image': $r('app.media.wifi'), 'category': Category.API},
  { 'name': 'HotSpot', 'detail': '热点测试', 'url': 'pages/subManualApiTest/hotspotInterfaceTest', 'image': $r('app.media.hotspot'), 'category': Category.API},
  { 'name': 'HotSpotManager', 'detail': '热点Manager测试', 'url': 'pages/subManualApiTest/hotspotManagerInterfaceTest', 'image': $r('app.media.hotspot'), 'category': Category.API},
  { 'name': 'p2p', 'detail': 'p2p测试', 'url': 'pages/subManualApiTest/p2pInterfaceTest', 'image': $r('app.media.WLAN'), 'category': Category.API},
  { 'name': 'p2pManager', 'detail': 'p2pManager测试', 'url': 'pages/subManualApiTest/p2pManagerInterfaceTest', 'image': $r('app.media.WLAN'), 'category': Category.API},
]

export function initTestData(): Array<TestData> {
  let TestDataArray: Array<TestData> = []
  TestComposition.forEach(item => {
    TestDataArray.push(new TestData(item.name, item.detail, item.url, item.image, item.category));
  })
  return TestDataArray;
}

export function initWiFiApiData(): Array<TestApi> {
  let TestApiArray: Array<TestApi> = []
  WiFiTestCase.forEach(item => {
    TestApiArray.push(new TestApi(item.name, item.detail, item.method, item.api, item.result, item.category));
  })
  return TestApiArray;
}

export function initHotspotApIData(): Array<TestApi> {
  let TestApiArray: Array<TestApi> = []
  HotspotTestCase.forEach(item => {
    TestApiArray.push(new TestApi(item.name, item.detail, item.method, item.api, item.result, item.category));
  })
  return TestApiArray;
}

export function initP2pApiData(): Array<TestApi> {
  let TestApiArray: Array<TestApi> = []
  p2pTestCase.forEach(item => {
    TestApiArray.push(new TestApi(item.name, item.detail, item.method, item.api, item.result, item.category));
  })
  return TestApiArray;
}

export function initWiFiManagerApiData(): Array<TestApi> {
  let TestApiArray: Array<TestApi> = []
  WiFiManagerTestCase.forEach(item => {
    TestApiArray.push(new TestApi(item.name, item.detail, item.method, item.api, item.result, item.category));
  })
  return TestApiArray;
}

export function initHotspotManagerApIData(): Array<TestApi> {
  let TestApiArray: Array<TestApi> = []
  HotspotManagerTestCase.forEach(item => {
    TestApiArray.push(new TestApi(item.name, item.detail, item.method, item.api, item.result, item.category));
  })
  return TestApiArray;
}

export function initP2pManagerApIData(): Array<TestApi> {
  let TestApiArray: Array<TestApi> = []
  p2pManagerTestCase.forEach(item => {
    TestApiArray.push(new TestApi(item.name, item.detail, item.method, item.api, item.result, item.category));
  })
  return TestApiArray;
}