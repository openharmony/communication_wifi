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
 * stress DataModel of wifi test
 */

import { TestStress , StressCategory } from './testData'

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

interface StressTest {
  name: string;
  detail: string;
  method: string;
  api: Function;
  result: string;
  category: StressCategory;
}

export const WifiStressTestCase: StressTest[] = [
  {
    'name' : '注册WLAN状态改变事件' ,
    'detail' : '1' ,
    'method' : 'on.WifiStateChange' ,
    'api' : testOnWifiStateChange ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '是否已使能' ,
    'detail' : '2' ,
    'method' : 'isWifiActive' ,
    'api' : testIsWifiActive ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '开Wifi' ,
    'detail' : '3' ,
    'method' : 'enableWifi' ,
    'api' : testEnableWifi ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '注册WLAN连接状态改变事件' ,
    'detail' : '5' ,
    'method' : 'on.WifiConnectionChange' ,
    'api' : testOnWifiConnectionChange ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '注册扫描状态改变事件' ,
    'detail' : '6' ,
    'method' : 'on.WifiScanStateChange' ,
    'api' : testOnWifiScanStateChange ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '注册RSSI状态改变事件' ,
    'detail' : '7' ,
    'method' : 'on.WifiRssiChange' ,
    'api' : testOnWifiRssiChange ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '启动WLAN扫描' ,
    'detail' : '8' ,
    'method' : 'scan' ,
    'api' : testScan ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '获取扫描结果Promise' ,
    'detail' : '9' ,
    'method' : 'getScanInfos' ,
    'api' : testGetScanInfosPromise ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '获取扫描结果Callback' ,
    'detail' : '10' ,
    'method' : 'getScanInfos' ,
    'api' : testGetScanInfosCallback ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '添加网络配置Promise' ,
    'detail' : '11' ,
    'method' : 'addDeviceConfig' ,
    'api' : testAddDeviceConfigPromise ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '添加网络配置Callback' ,
    'detail' : '12' ,
    'method' : 'addDeviceConfig' ,
    'api' : testAddDeviceConfigCallback ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '添加不可信网络配置Promise' ,
    'detail' : '13' ,
    'method' : 'addUntrustedConfig' ,
    'api' : testAddUntrustedConfigPromise ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '添加不可信网络配置Callback' ,
    'detail' : '14' ,
    'method' : 'addUntrustedConfig' ,
    'api' : testAddUntrustedConfigCallback ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '移除不可信网络配置Promise' ,
    'detail' : '15' ,
    'method' : 'removeUntrustedConfig' ,
    'api' : testRemoveUntrustedConfigPromise ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '移除不可信网络配置Callback' ,
    'detail' : '16' ,
    'method' : 'removeUntrustedConfig' ,
    'api' : testRemoveUntrustedConfigCallback ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '连接到指定网络' ,
    'detail' : '17' ,
    'method' : 'connectToNetwork' ,
    'api' : testConnectToNetwork ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '连接到指定网络' ,
    'detail' : '18' ,
    'method' : 'connectToDevice' ,
    'api' : testConnectToDevice ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '断开连接的网络' ,
    'detail' : '19' ,
    'method' : 'disconnect' ,
    'api' : testDisconnect ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '是否已连接' ,
    'detail' : '20' ,
    'method' : 'isConnected' ,
    'api' : testIsConnected ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '获取WLAN连接信息Promise' ,
    'detail' : '21' ,
    'method' : 'GetLinkedInfo' ,
    'api' : testGetLinkedInfoPromise ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '获取WLAN连接信息Callback' ,
    'detail' : '22' ,
    'method' : 'GetLinkedInfo' ,
    'api' : testGetLinkedInfoCallback ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '获取设备的MAC地址' ,
    'detail' : '23' ,
    'method' : 'getDeviceMacAddress' ,
    'api' : testGetDeviceMacAddress ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '获取IP信息' ,
    'detail' : '24' ,
    'method' : 'getIpInfo' ,
    'api' : testGetIpInfo ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '获取国家码信息' ,
    'detail' : '25' ,
    'method' : 'getCountryCode' ,
    'api' : testGetCountryCode ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '查询WLAN信号强度' ,
    'detail' : '26' ,
    'method' : 'getSignalLevel' ,
    'api' : testGetSignalLevel ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '查询设备支持的特性' ,
    'detail' : '27' ,
    'method' : 'getSupportedFeatures' ,
    'api' : testGetSupportedFeatures ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '是否支持相关WLAN特性' ,
    'detail' : '28' ,
    'method' : 'isFeatureSupported' ,
    'api' : testIsFeatureSupported ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '重新关联网络' ,
    'detail' : '29' ,
    'method' : 'reassociate' ,
    'api' : testReassociate ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '重新连接网络' ,
    'detail' : '30' ,
    'method' : 'reConnect' ,
    'api' : testReConnect ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '获取网络配置' ,
    'detail' : '31' ,
    'method' : 'getDeviceConfigs' ,
    'api' : testGetDeviceConfigs ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '更新网络配置' ,
    'detail' : '32' ,
    'method' : 'updateNetwork' ,
    'api' : testUpdateNetwork ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '去使能网络配置' ,
    'detail' : '33' ,
    'method' : 'disableNetwork' ,
    'api' : testDisableNetwork ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '移除指定的网络配置' ,
    'detail' : '34' ,
    'method' : 'removeDevice' ,
    'api' : testRemoveDevice ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '移除所有网络配置' ,
    'detail' : '35' ,
    'method' : 'removeAllNetwork' ,
    'api' : testRemoveAllNetwork ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  },
  {
    'name' : '关wifi' ,
    'detail' : '4' ,
    'method' : 'disableWifi' ,
    'api' : testDisableWifi ,
    'result' : 'None' ,
    'category' : StressCategory.WifiStress
  }
]

export const WifiManagerStressTestCase: StressTest[] = [
  {
    'name' : '注册WLAN状态改变事件' ,
    'detail' : '1' ,
    'method' : 'on.wifiStateChange' ,
    'api' : testOnWifiStateChangeManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '是否已使能' ,
    'detail' : '2' ,
    'method' : 'isWifiActive' ,
    'api' : testIsWifiActiveManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '开Wifi' ,
    'detail' : '3' ,
    'method' : 'enableWifi' ,
    'api' : testEnableWifiManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '注册WLAN连接状态改变事件' ,
    'detail' : '4' ,
    'method' : 'on.wifiConnectionChange' ,
    'api' : testOnWifiConnectionChangeManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '注册扫描状态改变事件' ,
    'detail' : '5' ,
    'method' : 'on.wifiScanStateChange' ,
    'api' : testOnWifiScanStateChangeManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '注册RSSI状态改变事件' ,
    'detail' : '6' ,
    'method' : 'on.wifiRssiChange' ,
    'api' : testOnWifiRssiChangeManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '启动WLAN扫描' ,
    'detail' : '7' ,
    'method' : 'scan' ,
    'api' : testScanManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '获取扫描信息列表' ,
    'detail' : '8' ,
    'method' : 'getScanInfoList' ,
    'api' : testGetScanInfoListManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },

  {
    'name' : '添加网络配置Promise' ,
    'detail' : '9' ,
    'method' : 'addDeviceConfig' ,
    'api' : testAddDeviceConfigManagerPromise ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '添加网络配置Callback' ,
    'detail' : '10' ,
    'method' : 'addDeviceConfig' ,
    'api' : testAddDeviceConfigManagerCallback ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '添加候选网络配置Promise' ,
    'detail' : '11' ,
    'method' : 'addCandidateConfig' ,
    'api' : testAddCandidateConfigManagerPromise ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '添加候选网络配置Callback' ,
    'detail' : '12' ,
    'method' : 'addCandidateConfig' ,
    'api' : testAddCandidateConfigManagerCallback ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '移除候选网络配置Promise' ,
    'detail' : '13' ,
    'method' : 'removeCandidateConfig' ,
    'api' : testRemoveCandidateConfigManagerPromise ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '移除候选网络配置Callback' ,
    'detail' : '14' ,
    'method' : 'removeCandidateConfig' ,
    'api' : testRemoveCandidateConfigManagerCallback ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },

  {
    'name' : '获取候选网络配置' ,
    'detail' : '15' ,
    'method' : 'getCandidateConfigs' ,
    'api' : testGetCandidateConfigsManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '连接到候选网络' ,
    'detail' : '16' ,
    'method' : 'connectToCandidateConfig' ,
    'api' : testConnectToCandidateConfigManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },

  {
    'name' : '连接到指定网络' ,
    'detail' : '17' ,
    'method' : 'connectToNetwork' ,
    'api' : testConnectToNetworkManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '连接到指定网络' ,
    'detail' : '18' ,
    'method' : 'connectToDevice' ,
    'api' : testConnectToDeviceManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '断开连接的网络' ,
    'detail' : '19' ,
    'method' : 'disconnect' ,
    'api' : testDisconnectManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '是否已连接' ,
    'detail' : '20' ,
    'method' : 'isConnected' ,
    'api' : testIsConnectedManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '获取WLAN连接信息Promise' ,
    'detail' : '21' ,
    'method' : 'GetLinkedInfo' ,
    'api' : testGetLinkedInfoManagerPromise ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '获取WLAN连接信息Callback' ,
    'detail' : '22' ,
    'method' : 'GetLinkedInfo' ,
    'api' : testGetLinkedInfoManagerCallback ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '获取设备的MAC地址' ,
    'detail' : '23' ,
    'method' : 'getDeviceMacAddress' ,
    'api' : testGetDeviceMacAddressManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '获取IP信息' ,
    'detail' : '24' ,
    'method' : 'getIpInfo' ,
    'api' : testGetIpInfoManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '获取国家码信息' ,
    'detail' : '25' ,
    'method' : 'getCountryCode' ,
    'api' : testGetCountryCodeManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '查询WLAN信号强度' ,
    'detail' : '26' ,
    'method' : 'getSignalLevel' ,
    'api' : testGetSignalLevelManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '查询设备支持的特性' ,
    'detail' : '27' ,
    'method' : 'getSupportedFeatures' ,
    'api' : testGetSupportedFeaturesManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '是否支持相关WLAN特性' ,
    'detail' : '28' ,
    'method' : 'isFeatureSupported' ,
    'api' : testIsFeatureSupportedManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '重新关联网络' ,
    'detail' : '29' ,
    'method' : 'reassociate' ,
    'api' : testReassociateManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '重新连接网络' ,
    'detail' : '30' ,
    'method' : 'reConnect' ,
    'api' : testReconnectManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '获取网络配置' ,
    'detail' : '31' ,
    'method' : 'getDeviceConfigs' ,
    'api' : testGetDeviceConfigsManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '更新网络配置' ,
    'detail' : '32' ,
    'method' : 'updateDeviceConfig' ,
    'api' : testUpdateDeviceConfigManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '去使能网络配置' ,
    'detail' : '33' ,
    'method' : 'disableDeviceConfig' ,
    'api' : testDisableDeviceConfigManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '移除指定的网络配置' ,
    'detail' : '34' ,
    'method' : 'removeDeviceConfig' ,
    'api' : testRemoveDeviceConfigManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '移除所有网络配置' ,
    'detail' : '35' ,
    'method' : 'removeAllDeviceConfigs' ,
    'api' : testRemoveAllDeviceConfigsManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '注册流改变事件' ,
    'detail' : '36' ,
    'method' : 'on.streamChange' ,
    'api' : testOnStreamChangeManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '注册设备配置改变事件' ,
    'detail' : '37' ,
    'method' : 'on.deviceConfigChange' ,
    'api' : testOnDeviceConfigChangeManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  },
  {
    'name' : '关wifi' ,
    'detail' : '38' ,
    'method' : 'disableWifi' ,
    'api' : testDisableWifiManager ,
    'result' : 'None' ,
    'category' : StressCategory.WifiManagerStress
  }
]

export const HotspotStressTestCase: StressTest[] = [
  {
    'name' : '使能热点' ,
    'detail' : '1' ,
    'method' : 'enableHotspot' ,
    'api' : testEnableHotspot ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotStress
  },
  {
    'name' : '去使能热点' ,
    'detail' : '2' ,
    'method' : 'disableHotspot' ,
    'api' : testDisableHotspot ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotStress
  },
  {
    'name' : '热点是否支持双频' ,
    'detail' : '3' ,
    'method' : 'isHotspotDualBandSupported' ,
    'api' : testIsHotspotDualBandSupported ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotStress
  },
  {
    'name' : '热点是否已使能' ,
    'detail' : '4' ,
    'method' : 'isHostActive' ,
    'api' : testIsHostActive ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotStress
  },
  {
    'name' : '设置热点配置信息' ,
    'detail' : '5' ,
    'method' : 'setHotspotConfig' ,
    'api' : testSetHotspotConfig ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotStress
  },
  {
    'name' : '获取热点配置信息' ,
    'detail' : '6' ,
    'method' : 'getHotspotConfig' ,
    'api' : testGetHotspotConfig ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotStress
  },
  {
    'name' : '获取连接的设备' ,
    'detail' : '7' ,
    'method' : 'getStations' ,
    'api' : testGetStations ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotStress
  },
  {
    'name' : '注册热点状态改变事件' ,
    'detail' : '8' ,
    'method' : 'on.hotspotStateChange' ,
    'api' : testOnHotspotStateChange ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotStress
  }
]

export const HotspotManagerStressTestCase: StressTest[] = [
  {
    'name' : '使能热点' ,
    'detail' : '1' ,
    'method' : 'enableHotspot' ,
    'api' : testEnableHotspotManager ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotManagerStress
  },
  {
    'name' : '去使能热点' ,
    'detail' : '2' ,
    'method' : 'disableHotspot' ,
    'api' : testDisableHotspotManager ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotManagerStress
  },
  {
    'name' : '热点是否支持双频' ,
    'detail' : '3' ,
    'method' : 'isHotspotDualBandSupported' ,
    'api' : testIsHotspotDualBandSupportedManager ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotManagerStress
  },
  {
    'name' : '热点是否已使能' ,
    'detail' : '4' ,
    'method' : 'isHostActive' ,
    'api' : testIsHostActiveManager ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotManagerStress
  },
  {
    'name' : '设置热点配置信息' ,
    'detail' : '5' ,
    'method' : 'setHotspotConfig' ,
    'api' : testSetHotspotConfigManager ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotManagerStress
  },
  {
    'name' : '获取热点配置信息' ,
    'detail' : '6' ,
    'method' : 'getHotspotConfig' ,
    'api' : testGetHotspotConfigManager ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotManagerStress
  },
  {
    'name' : '获取连接的设备' ,
    'detail' : '7' ,
    'method' : 'getStations' ,
    'api' : testGetHotspotStationsManager ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotManagerStress
  },
  {
    'name' : '注册热点状态改变事件' ,
    'detail' : '8' ,
    'method' : 'on.hotspotStateChange' ,
    'api' : testOnHotspotStateChangeManager ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotManagerStress
  },
  {
    'name' : '注册加入改变事件' ,
    'detail' : '9' ,
    'method' : 'on.hotspotStateChange' ,
    'api' : testOnHotspotStaJoinManager ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotManagerStress
  },
  {
    'name' : '注册离开改变事件' ,
    'detail' : '10' ,
    'method' : 'on.hotspotStateChange' ,
    'api' : testOnHotspotStaLeaveManager ,
    'result' : 'None' ,
    'category' : StressCategory.HotspotManagerStress
  }
]

export const P2pStressTestCase: StressTest[] = [
  {
    'name' : '获取P2P连接信息Promise' ,
    'detail' : '获取P2P连接信息Promise' ,
    'method' : 'getP2pLinkedInfo' ,
    'api' : testGetP2pLinkedInfoPromise ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '获取P2P连接信息Callback' ,
    'detail' : '获取P2P连接信息Callback' ,
    'method' : 'getP2pLinkedInfo' ,
    'api' : testGetP2pLinkedInfoCallback ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '获取P2P当前组信息Promise' ,
    'detail' : '获取P2P当前组信息Promise' ,
    'method' : 'getCurrentGroup' ,
    'api' : testGetCurrentGroupPromise ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '获取P2P当前组信息Callback' ,
    'detail' : '获取P2P当前组信息Callback' ,
    'method' : 'getCurrentGroup' ,
    'api' : testGetCurrentGroupCallback ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '获取P2P对端设备列表信息Promise' ,
    'detail' : '获取P2P对端设备列表信息Promise' ,
    'method' : 'getP2pPeerDevices' ,
    'api' : testGetP2pPeerDevicesPromise ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '获取P2P对端设备列表信息Callback' ,
    'detail' : '获取P2P对端设备列表信息Callback' ,
    'method' : 'getP2pPeerDevices' ,
    'api' : testGetP2pPeerDevicesCallback ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '开始发现设备' ,
    'detail' : '创建群组' ,
    'method' : 'createGroup' ,
    'api' : testCreateGroup ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '停止发现设备' ,
    'detail' : '移除群组' ,
    'method' : 'removeGroup' ,
    'api' : testRemoveGroup ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '设置设备名称' ,
    'detail' : '执行P2P连接' ,
    'method' : 'p2pConnect' ,
    'api' : testP2pConnect ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '取消P2P连接' ,
    'detail' : '取消P2P连接' ,
    'method' : 'p2pCancelConnect' ,
    'api' : testP2pCancelConnect ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '开始发现设备' ,
    'detail' : '开始发现设备' ,
    'method' : 'startDiscoverDevices' ,
    'api' : testStartDiscoverDevices ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '停止发现设备' ,
    'detail' : '停止发现设备' ,
    'method' : 'stopDiscoverDevices' ,
    'api' : testStopDiscoverDevices ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '删除永久组' ,
    'detail' : '删除永久组' ,
    'method' : 'deletePersistentGroup' ,
    'api' : testDeletePersistentGroup ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '设置设备名称' ,
    'detail' : '设置设备名称' ,
    'method' : 'setDeviceName' ,
    'api' : testSetDeviceName ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '注册P2P开关状态改变事件' ,
    'detail' : '注册P2P开关状态改变事件' ,
    'method' : 'On.P2pStateChange' ,
    'api' : testOnP2pStateChange ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '注册P2P连接状态改变事件' ,
    'detail' : '注册P2P连接状态改变事件' ,
    'method' : 'On.P2pConnectionChange' ,
    'api' : testOnP2pConnectionChange ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '注册P2P设备状态改变事件' ,
    'detail' : '注册P2P设备状态改变事件' ,
    'method' : 'On.p2pDeviceChange' ,
    'api' : testOnP2pDeviceChange ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '注册P2P对端设备状态改变事件' ,
    'detail' : '注册P2P对端设备状态改变事件' ,
    'method' : 'On.p2pPeerDeviceChange' ,
    'api' : testOnP2pPeerDeviceChange ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '注册P2P永久组状态改变事件' ,
    'detail' : '注册P2P永久组状态改变事件' ,
    'method' : 'On.p2pPersistentGroupChange' ,
    'api' : testOnP2pPersistentGroupChange ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
  {
    'name' : '注册发现设备状态改变事件' ,
    'detail' : '注册发现设备状态改变事件' ,
    'method' : 'On.p2pDiscoveryChange' ,
    'api' : testOnP2pDiscoveryChange ,
    'result' : 'None' ,
    'category' : StressCategory.P2pStress
  },
]

export const P2pManagerStressTestCase: StressTest[] = [
  {
    'name' : '获取P2P连接信息Promise' ,
    'detail' : '获取P2P连接信息Promise' ,
    'method' : 'getP2pLinkedInfo' ,
    'api' : testGetP2pLinkedInfoManagerPromise ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '获取P2P连接信息Callback' ,
    'detail' : '获取P2P连接信息Callback' ,
    'method' : 'getP2pLinkedInfo' ,
    'api' : testGetP2pLinkedInfoManagerCallback ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '获取P2P当前组信息Promise' ,
    'detail' : '获取P2P当前组信息Promise' ,
    'method' : 'getCurrentGroup' ,
    'api' : testGetCurrentP2pGroupManagerPromise ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '获取P2P当前组信息Callback' ,
    'detail' : '获取P2P当前组信息Callback' ,
    'method' : 'getCurrentGroup' ,
    'api' : testGetCurrentP2pGroupManagerCallback ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '获取P2P对端设备列表信息Promise' ,
    'detail' : '获取P2P对端设备列表信息Promise' ,
    'method' : 'getP2pPeerDevices' ,
    'api' : testGetP2pPeerDevicesManagerPromise ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '获取P2P对端设备列表信息Callback' ,
    'detail' : '获取P2P对端设备列表信息Callback' ,
    'method' : 'getP2pPeerDevices' ,
    'api' : testGetP2pPeerDevicesManagerCallback ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '获取P2P对端设备列表信息Promise' ,
    'detail' : '获取P2P对端设备列表信息Promise' ,
    'method' : 'getP2pPeerDevices' ,
    'api' : testGetP2pLocalDeviceManagerPromise ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '获取P2P对端设备列表信息Callback' ,
    'detail' : '获取P2P对端设备列表信息Callback' ,
    'method' : 'getP2pPeerDevices' ,
    'api' : testGetP2pLocalDeviceManagerCallback ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },

  {
    'name' : '开始发现设备' ,
    'detail' : '创建群组' ,
    'method' : 'createGroup' ,
    'api' : testCreateP2pGroupManager ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '停止发现设备' ,
    'detail' : '移除群组' ,
    'method' : 'removeGroup' ,
    'api' : testRemoveP2pGroupManager ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '设置设备名称' ,
    'detail' : '执行P2P连接' ,
    'method' : 'p2pConnect' ,
    'api' : testP2pConnectManager ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '取消P2P连接' ,
    'detail' : '取消P2P连接' ,
    'method' : 'p2pCancelConnect' ,
    'api' : testP2pCancelConnectManager ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '开始发现设备' ,
    'detail' : '开始发现设备' ,
    'method' : 'startDiscoverDevices' ,
    'api' : testStartDiscoverP2pDevicesManager ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '停止发现设备' ,
    'detail' : '停止发现设备' ,
    'method' : 'stopDiscoverDevices' ,
    'api' : testStopDiscoverP2pDevicesManager ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '删除永久组' ,
    'detail' : '删除永久组' ,
    'method' : 'deletePersistentGroup' ,
    'api' : testDeletePersistentP2pGroupManager ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '删除永久组' ,
    'detail' : '删除永久组' ,
    'method' : 'deletePersistentGroup' ,
    'api' : testGetP2pGroupsManagerPromise ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '删除永久组' ,
    'detail' : '删除永久组' ,
    'method' : 'deletePersistentGroup' ,
    'api' : testGetP2pGroupsManagerCallback ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '删除永久组' ,
    'detail' : '删除永久组' ,
    'method' : 'deletePersistentGroup' ,
    'api' : testSetP2pDeviceNameManager ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '注册P2P开关状态改变事件' ,
    'detail' : '注册P2P开关状态改变事件' ,
    'method' : 'On.P2pStateChange' ,
    'api' : testOnP2pStateChangeManager ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '注册P2P连接状态改变事件' ,
    'detail' : '注册P2P连接状态改变事件' ,
    'method' : 'On.P2pConnectionChange' ,
    'api' : testOnP2pConnectionChangeManager ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '注册P2P设备状态改变事件' ,
    'detail' : '注册P2P设备状态改变事件' ,
    'method' : 'On.p2pDeviceChange' ,
    'api' : testOnP2pDeviceChangeManager ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '注册P2P对端设备状态改变事件' ,
    'detail' : '注册P2P对端设备状态改变事件' ,
    'method' : 'On.p2pPeerDeviceChange' ,
    'api' : testOnP2pPeerDeviceChangeManager ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '注册P2P永久组状态改变事件' ,
    'detail' : '注册P2P永久组状态改变事件' ,
    'method' : 'On.p2pPersistentGroupChange' ,
    'api' : testOnP2pPersistentGroupChangeManager ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
  {
    'name' : '注册发现设备状态改变事件' ,
    'detail' : '注册发现设备状态改变事件' ,
    'method' : 'On.p2pDiscoveryChange' ,
    'api' : testOnP2pDiscoveryChangeManager ,
    'result' : 'None' ,
    'category' : StressCategory.P2pManagerStress
  },
]

export function initWifiStressData(): Array<TestStress> {
  let TestStressArray: Array<TestStress> = []
  WifiStressTestCase.forEach(item => {
    TestStressArray.push(new TestStress(item.name , item.detail , item.method , item.api , item.result , item.category));
  })
  return TestStressArray;
}

export function initWifiManagerStressData(): Array<TestStress> {
  let TestStressArray: Array<TestStress> = []
  WifiManagerStressTestCase.forEach(item => {
    TestStressArray.push(new TestStress(item.name , item.detail , item.method , item.api , item.result , item.category));
  })
  return TestStressArray;
}

export function initHotspotStressData(): Array<TestStress> {
  let TestStressArray: Array<TestStress> = []
  HotspotStressTestCase.forEach(item => {
    TestStressArray.push(new TestStress(item.name , item.detail , item.method , item.api , item.result , item.category));
  })
  return TestStressArray;
}

export function initHotspotManagerStressData(): Array<TestStress> {
  let TestStressArray: Array<TestStress> = []
  HotspotManagerStressTestCase.forEach(item => {
    TestStressArray.push(new TestStress(item.name , item.detail , item.method , item.api , item.result , item.category));
  })
  return TestStressArray;
}

export function initP2pStressData(): Array<TestStress> {
  let TestStressArray: Array<TestStress> = []
  P2pStressTestCase.forEach(item => {
    TestStressArray.push(new TestStress(item.name , item.detail , item.method , item.api , item.result , item.category));
  })
  return TestStressArray;
}

export function initP2pManagerStressData(): Array<TestStress> {
  let TestStressArray: Array<TestStress> = []
  P2pManagerStressTestCase.forEach(item => {
    TestStressArray.push(new TestStress(item.name , item.detail , item.method , item.api , item.result , item.category));
  })
  return TestStressArray;
}