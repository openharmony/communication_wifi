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
import { TestData, TestApi, Category, CaseCategory} from './testData';
import {
  testEnableWifi,
  testDisableWifi,
  testIsWifiActive,
  testScan,
  testGetScanInfosPromise,
  testGetScanInfosCallback,
  testAddDeviceConfigPromise,
  testAddDeviceConfigCallback,
  testAddUntrustedConfigPromise,
  testAddUntrustedConfigCallback,
  testRemoveUntrustedConfigPromise,
  testRemoveUntrustedConfigCallback,
  testConnectToNetwork,
  testConnectToDevice,
  testDisconnect,
  testGetSignalLevel,
  testGetLinkedInfoPromise,
  testGetLinkedInfoCallback,
  testIsConnected,
  testGetSupportedFeatures,
  testIsFeatureSupported,
  testGetDeviceMacAddress,
  testGetIpInfo,
  testGetCountryCode,
  testReassociate,
  testReConnect,
  testGetDeviceConfigs,
  testUpdateNetwork,
  testDisableNetwork,
  testRemoveAllNetwork,
  testRemoveDevice,
  testOnWifiStateChange,
  testOnWifiConnectionChange,
  testOnWifiScanStateChange,
  testOnWifiRssiChange,
  testOnStreamChange
} from './wifiInterface'
import {
  testEnableWifiManager,
  testDisableWifiManager,
  testEnableSemiWifiManager,
  testIsWifiActiveManager,
  testScanManager,
  testStartScanManager,
  testGetScanInfoListManager,
  testGetScanResultsPromise,
  testGetScanResultsCallback,
  testGetScanResultsSync,
  testGetWifiDetailState,
  testSetScanAlwaysAllowed,
  testGetScanAlwaysAllowed,
  testGetLinkedInfoSyncManager,
  testAddDeviceConfigManagerPromise,
  testAddDeviceConfigManagerCallback,
  testAddCandidateConfigManagerPromise,
  testAddCandidateConfigManagerCallback,
  testRemoveCandidateConfigManagerPromise,
  testRemoveCandidateConfigManagerCallback,
  testGetCandidateConfigsManager,
  testConnectToCandidateConfigManager,
  testConnectToNetworkManager,
  testConnectToDeviceManager,
  testDisconnectManager,
  testGetSignalLevelManager,
  testGetLinkedInfoManagerPromise,
  testGetLinkedInfoManagerCallback,
  testIsConnectedManager,
  testGetSupportedFeaturesManager,
  testIsFeatureSupportedManager,
  testGetDeviceMacAddressManager,
  testGetIpInfoManager,
  testGetIpv6Info,
  testGetCountryCodeManager,
  testReassociateManager,
  testReconnectManager,
  testGetDeviceConfigsManager,
  testUpdateDeviceConfigManager,
  testDisableDeviceConfigManager,
  testRemoveAllDeviceConfigsManager,
  testRemoveDeviceConfigManager,
  testIsBandTypeSupported,
  testGet5GChannelList,
  testGetDisconnectedReason,
  testStartPortalCertification,
  testStartWifiDetection,
  testOnWifiStateChangeManager,
  testOnWifiConnectionChangeManager,
  testOnWifiScanStateChangeManager,
  testOnWifiRssiChangeManager,
  testOnStreamChangeManager,
  testOnDeviceConfigChangeManager
} from './wifiManagerInterface'
import {
  testEnableHotspot,
  testDisableHotspot,
  testIsHotspotDualBandSupported,
  testIsHostActive,
  testSetHotspotConfig,
  testGetHotspotConfig,
  testGetStations,
  testOnHotspotStateChange,
  testOnHotspotStaJoin,
  testOnHotspotStaLeave
} from './hotspotInterface'
import {
  testEnableHotspotManager,
  testDisableHotspotManager,
  testIsHotspotDualBandSupportedManager,
  testIsHostActiveManager,
  testSetHotspotConfigManager,
  testGetHotspotConfigManager,
  testGetHotspotStationsManager,
  testOnHotspotStateChangeManager,
  testOnHotspotStaJoinManager,
  testOnHotspotStaLeaveManager,
  testIsMeteredHotspot,
  testAddHotspotBlockList,
  testDelHotspotBlockList,
  testGetHotspotBlockList
} from "./hotspotManagerInterface"
import {
  testGetP2pLinkedInfoPromise,
  testGetP2pLinkedInfoCallback,
  testGetCurrentGroupPromise,
  testGetCurrentGroupCallback,
  testGetP2pPeerDevicesPromise,
  testGetP2pPeerDevicesCallback,
  testCreateGroup,
  testRemoveGroup,
  testP2pConnect,
  testP2pCancelConnect,
  testStartDiscoverDevices,
  testStopDiscoverDevices,
  testDeletePersistentGroup,
  testSetDeviceName,
  testOnP2pStateChange,
  testOnP2pConnectionChange,
  testOnP2pDeviceChange,
  testOnP2pPeerDeviceChange,
  testOnP2pPersistentGroupChange,
  testOnP2pDiscoveryChange
} from './p2pInterface'
import {
  testGetP2pLinkedInfoManagerPromise,
  testGetP2pLinkedInfoManagerCallback,
  testGetCurrentP2pGroupManagerPromise,
  testGetCurrentP2pGroupManagerCallback,
  testGetP2pPeerDevicesManagerPromise,
  testGetP2pPeerDevicesManagerCallback,
  testGetP2pLocalDeviceManagerPromise,
  testGetP2pLocalDeviceManagerCallback,
  testCreateP2pGroupManager,
  testRemoveP2pGroupManager,
  testP2pConnectManager,
  testP2pCancelConnectManager,
  testStartDiscoverP2pDevicesManager,
  testStopDiscoverP2pDevicesManager,
  testDeletePersistentP2pGroupManager,
  testGetP2pGroupsManagerPromise,
  testGetP2pGroupsManagerCallback,
  testSetP2pDeviceNameManager,
  testOnP2pStateChangeManager,
  testOnP2pConnectionChangeManager,
  testOnP2pDeviceChangeManager,
  testOnP2pPeerDeviceChangeManager,
  testOnP2pPersistentGroupChangeManager,
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
const WifiTestCase: WifiTest[] = [
  {
    'name': '注册WLAN状态改变事件',
    'detail': '注册WLAN状态改变事件',
    'method': 'on.wifiStateChange',
    'api': testOnWifiStateChange,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '是否已使能',
    'detail': '是否已使能',
    'method': 'isWifiActive',
    'api': testIsWifiActive,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '开Wifi',
    'detail': '使能Wifi',
    'method': 'enableWifi',
    'api': testEnableWifi,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '关wifi',
    'detail': '去使能wifi',
    'method': 'disableWifi',
    'api': testDisableWifi,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '注册WLAN连接状态改变事件',
    'detail': '注册WLAN连接状态改变事件',
    'method': 'on.wifiConnectionChange',
    'api': testOnWifiConnectionChange,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '注册扫描状态改变事件',
    'detail': '注册扫描状态改变事件',
    'method': 'on.wifiScanStateChange',
    'api': testOnWifiScanStateChange,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '注册RSSI状态改变事件',
    'detail': '注册RSSI状态改变事件',
    'method': 'on.wifiRssiChange',
    'api': testOnWifiRssiChange,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '启动WLAN扫描',
    'detail': '启动WLAN扫描',
    'method': 'scan',
    'api': testScan,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '获取扫描结果Promise',
    'detail': '获取扫描结果Promise',
    'method': 'getScanInfos',
    'api': testGetScanInfosPromise,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '获取扫描结果Callback',
    'detail': '获取扫描结果Callback',
    'method': 'getScanInfos',
    'api': testGetScanInfosCallback,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '添加网络配置Promise',
    'detail': '添加网络配置Promise',
    'method': 'addDeviceConfig',
    'api': testAddDeviceConfigPromise,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '添加网络配置Callback',
    'detail': '添加网络配置Callback',
    'method': 'addDeviceConfig',
    'api': testAddDeviceConfigCallback,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '添加不可信网络配置Promise',
    'detail': '添加不可信网络配置Promise',
    'method': 'addUntrustedConfig',
    'api': testAddUntrustedConfigPromise,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '添加不可信网络配置Callback',
    'detail': '添加不可信网络配置Callback',
    'method': 'addUntrustedConfig',
    'api': testAddUntrustedConfigCallback,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '移除不可信网络配置Promise',
    'detail': '移除不可信网络配置Promise',
    'method': 'removeUntrustedConfig',
    'api': testRemoveUntrustedConfigPromise,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '移除不可信网络配置Callback',
    'detail': '移除不可信网络配置Callback',
    'method': 'removeUntrustedConfig',
    'api': testRemoveUntrustedConfigCallback,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '连接到指定网络',
    'detail': '连接到指定网络',
    'method': 'connectToNetwork',
    'api': testConnectToNetwork,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '连接到指定网络',
    'detail': '连接到指定网络',
    'method': 'connectToDevice',
    'api': testConnectToDevice,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '断开连接的网络',
    'detail': '断开连接的网络',
    'method': 'disconnect',
    'api': testDisconnect,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '是否已连接',
    'detail': '查询WLAN是否已连接',
    'method': 'isConnected',
    'api': testIsConnected,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '获取WLAN连接信息Promise',
    'detail': '获取WLAN连接信息Promise',
    'method': 'GetLinkedInfo',
    'api': testGetLinkedInfoPromise,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '获取WLAN连接信息Callback',
    'detail': '获取WLAN连接信息Callback',
    'method': 'GetLinkedInfo',
    'api': testGetLinkedInfoCallback,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '获取设备的MAC地址',
    'detail': '获取设备的MAC地址',
    'method': 'getDeviceMacAddress',
    'api': testGetDeviceMacAddress,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '获取IP信息',
    'detail': '获取IP信息',
    'method': 'getIpInfo',
    'api': testGetIpInfo,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '获取国家码信息',
    'detail': '获取国家码信息',
    'method': 'getCountryCode',
    'api': testGetCountryCode,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '查询WLAN信号强度',
    'detail': '查询WLAN信号强度',
    'method': 'getSignalLevel',
    'api': testGetSignalLevel,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '查询设备支持的特性',
    'detail': '查询设备支持的特性',
    'method': 'getSupportedFeatures',
    'api': testGetSupportedFeatures,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '是否支持相关WLAN特性',
    'detail': '判断设备是否支持相关WLAN特性',
    'method': 'isFeatureSupported',
    'api': testIsFeatureSupported,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '重新关联网络',
    'detail': '重新关联网络',
    'method': 'reassociate',
    'api': testReassociate,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '重新连接网络',
    'detail': '重新连接网络',
    'method': 'reConnect',
    'api': testReConnect,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '获取网络配置',
    'detail': '获取网络配置',
    'method': 'getDeviceConfigs',
    'api': testGetDeviceConfigs,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '更新网络配置',
    'detail': '更新网络配置',
    'method': 'updateNetwork',
    'api': testUpdateNetwork,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '去使能网络配置',
    'detail': '去使能网络配置',
    'method': 'disableNetwork',
    'api': testDisableNetwork,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '移除指定的网络配置',
    'detail': '移除指定的网络配置',
    'method': 'removeDevice',
    'api': testRemoveDevice,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '启动网络探测',
    'detail': '启动网络探测',
    'method': 'StartWifiDetection',
    'api': testStartWifiDetection,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '移除所有网络配置',
    'detail': '移除所有网络配置',
    'method': 'removeAllNetwork',
    'api': testRemoveAllNetwork,
    'result': 'None',
    'category': CaseCategory.Wifi
},
  {
    'name': '注册流改变事件',
    'detail': '注册流改变事件',
    'method': 'on.streamChange',
    'api': testOnStreamChange,
    'result': 'None',
    'category': CaseCategory.Wifi
},
]
const WifiManagerTestCase: WifiTest[] = [
  {
    'name': '注册WLAN状态改变事件',
    'detail': '注册WLAN状态改变事件',
    'method': 'on.wifiStateChange',
    'api': testOnWifiStateChangeManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '是否已使能',
    'detail': '是否已使能',
    'method': 'isWifiActive',
    'api': testIsWifiActiveManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '开Wifi',
    'detail': '使能Wifi',
    'method': 'enableWifi',
    'api': testEnableWifiManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '关wifi',
    'detail': '去使能wifi',
    'method': 'disableWifi',
    'api': testDisableWifiManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '开SemiWifi',
    'detail': '使能SemiWifi',
    'method': 'enableSemiWifi',
    'api': testEnableSemiWifiManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '注册WLAN连接状态改变事件',
    'detail': '注册WLAN连接状态改变事件',
    'method': 'on.wifiConnectionChange',
    'api': testOnWifiConnectionChangeManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '注册扫描状态改变事件',
    'detail': '注册扫描状态改变事件',
    'method': 'on.wifiScanStateChange',
    'api': testOnWifiScanStateChangeManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '注册RSSI状态改变事件',
    'detail': '注册RSSI状态改变事件',
    'method': 'on.wifiRssiChange',
    'api': testOnWifiRssiChangeManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '启动WLAN扫描',
    'detail': '启动WLAN扫描',
    'method': 'scan',
    'api': testScanManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '开始启动WLAN扫描',
    'detail': '开始启动WLAN扫描',
    'method': 'StartScan',
    'api': testStartScanManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取扫描信息列表',
    'detail': '获取扫描信息列表',
    'method': 'getScanInfoList',
    'api': testGetScanInfoListManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取扫描结果列表',
    'detail': '获取扫描结果列表',
    'method': 'getScanResultsSync',
    'api': testGetScanResultsSync,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取wifi详细状态',
    'detail': '获取wifi详细状态',
    'method': 'getWifiDetailState',
    'api': testGetWifiDetailState,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '设置始终允许标志',
    'detail': '设置wifi详细状态',
    'method': 'setScanAlwaysAllowed',
    'api': testSetScanAlwaysAllowed,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取扫描始终允许标志',
    'detail': '获取扫描始终允许标志',
    'method': 'getScanAlwaysAllowed',
    'api': testGetScanAlwaysAllowed,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '同步获取连接信息',
    'detail': '同步获取连接信息',
    'method': 'getLinkedInfoSync',
    'api': testGetLinkedInfoSyncManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取扫描结果列表Promise',
    'detail': '获取扫描结果列表Promise',
    'method': 'getScanResultsPromise',
    'api': testGetScanResultsPromise,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取扫描结果列表Callback',
    'detail': '获取扫描结果列表Callback',
    'method': 'getScanResultsCallback',
    'api': testGetScanResultsCallback,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '添加网络配置Promise',
    'detail': '添加网络配置Promise',
    'method': 'addDeviceConfig',
    'api': testAddDeviceConfigManagerPromise,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '添加网络配置Callback',
    'detail': '添加网络配置Callback',
    'method': 'addDeviceConfig',
    'api': testAddDeviceConfigManagerCallback,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '添加候选网络配置Promise',
    'detail': '添加候选网络配置Promise',
    'method': 'addCandidateConfig',
    'api': testAddCandidateConfigManagerPromise,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '添加候选网络配置Callback',
    'detail': '添加候选网络配置Callback',
    'method': 'addCandidateConfig',
    'api': testAddCandidateConfigManagerCallback,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '移除候选网络配置Promise',
    'detail': '移除候选网络配置Promise',
    'method': 'removeCandidateConfig',
    'api': testRemoveCandidateConfigManagerPromise,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '移除候选网络配置Callback',
    'detail': '移除候选网络配置Callback',
    'method': 'removeCandidateConfig',
    'api': testRemoveCandidateConfigManagerCallback,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取候选网络配置',
    'detail': '获取候选网络配置',
    'method': 'getCandidateConfigs',
    'api': testGetCandidateConfigsManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '连接到候选网络',
    'detail': '连接到候选网络',
    'method': 'connectToCandidateConfig',
    'api': testConnectToCandidateConfigManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},

  {
    'name': '连接到指定网络',
    'detail': '连接到指定网络',
    'method': 'connectToNetwork',
    'api': testConnectToNetworkManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '连接到指定网络',
    'detail': '连接到指定网络',
    'method': 'connectToDevice',
    'api': testConnectToDeviceManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '断开连接的网络',
    'detail': '断开连接的网络',
    'method': 'disconnect',
    'api': testDisconnectManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '是否已连接',
    'detail': '查询WLAN是否已连接',
    'method': 'isConnected',
    'api': testIsConnectedManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取WLAN连接信息Promise',
    'detail': '获取WLAN连接信息Promise',
    'method': 'GetLinkedInfo',
    'api': testGetLinkedInfoManagerPromise,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取WLAN连接信息Callback',
    'detail': '获取WLAN连接信息Callback',
    'method': 'GetLinkedInfo',
    'api': testGetLinkedInfoManagerCallback,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取设备的MAC地址',
    'detail': '获取设备的MAC地址',
    'method': 'getDeviceMacAddress',
    'api': testGetDeviceMacAddressManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取IP信息',
    'detail': '获取IP信息',
    'method': 'getIpInfo',
    'api': testGetIpInfoManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取IPv6信息',
    'detail': '获取IPv6信息',
    'method': 'getIpv6Info',
    'api': testGetIpv6Info,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取国家码信息',
    'detail': '获取国家码信息',
    'method': 'getCountryCode',
    'api': testGetCountryCodeManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '查询WLAN信号强度',
    'detail': '查询WLAN信号强度',
    'method': 'getSignalLevel',
    'api': testGetSignalLevelManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '查询设备支持的特性',
    'detail': '查询设备支持的特性',
    'method': 'getSupportedFeatures',
    'api': testGetSupportedFeaturesManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '是否支持相关WLAN特性',
    'detail': '判断设备是否支持相关WLAN特性',
    'method': 'isFeatureSupported',
    'api': testIsFeatureSupportedManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '重新关联网络',
    'detail': '重新关联网络',
    'method': 'reassociate',
    'api': testReassociateManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '重新连接网络',
    'detail': '重新连接网络',
    'method': 'reConnect',
    'api': testReconnectManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取网络配置',
    'detail': '获取网络配置',
    'method': 'getDeviceConfigs',
    'api': testGetDeviceConfigsManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '更新网络配置',
    'detail': '更新网络配置',
    'method': 'updateDeviceConfig',
    'api': testUpdateDeviceConfigManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '去使能网络配置',
    'detail': '去使能网络配置',
    'method': 'disableDeviceConfig',
    'api': testDisableDeviceConfigManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '移除指定的网络配置',
    'detail': '移除指定的网络配置',
    'method': 'removeDeviceConfig',
    'api': testRemoveDeviceConfigManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '移除指定的网络配置',
    'detail': '移除指定的网络配置',
    'method': 'isBandTypeSupported',
    'api': testIsBandTypeSupported,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取5G频道列表',
    'detail': '获取5G频道列表',
    'method': 'get5GChannelList',
    'api': testGet5GChannelList,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '获取未连接的原因',
    'detail': '获取未连接的原因',
    'method': 'getDisconnectedReason',
    'api': testGetDisconnectedReason,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '启动门户认证',
    'detail': '启动门户认证',
    'method': 'startPortalCertification',
    'api': testStartPortalCertification,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '移除所有网络配置',
    'detail': '移除所有网络配置',
    'method': 'removeAllDeviceConfigs',
    'api': testRemoveAllDeviceConfigsManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '注册流改变事件',
    'detail': '注册流改变事件',
    'method': 'on.streamChange',
    'api': testOnStreamChangeManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
  {
    'name': '注册设备配置改变事件',
    'detail': '注册设备配置改变事件',
    'method': 'on.deviceConfigChange',
    'api': testOnDeviceConfigChangeManager,
    'result': 'None',
    'category': CaseCategory.WifiManager
},
]
const HotspotTestCase: WifiTest[] = [
  {
    'name': '注册热点状态改变事件',
    'detail': '注册热点状态改变事件',
    'method': 'on.hotspotStateChange',
    'api': testOnHotspotStateChange,
    'result': 'None',
    'category': CaseCategory.Hotspot
},
  {
    'name': '热点是否已使能',
    'detail': '热点是否已使能',
    'method': 'isHostActive',
    'api': testIsHostActive,
    'result': 'None',
    'category': CaseCategory.Hotspot
},
  {
    'name': '使能热点',
    'detail': '使能热点',
    'method': 'enableHotspot',
    'api': testEnableHotspot,
    'result': 'None',
    'category': CaseCategory.Hotspot
},
  {
    'name': '去使能热点',
    'detail': '去使能热点',
    'method': 'disableHotspot',
    'api': testDisableHotspot,
    'result': 'None',
    'category': CaseCategory.Hotspot
},
  {
    'name': '热点是否支持双频',
    'detail': '热点是否支持双频',
    'method': 'isHotspotDualBandSupported',
    'api': testIsHotspotDualBandSupported,
    'result': 'None',
    'category': CaseCategory.Hotspot
},
  {
    'name': '设置热点配置信息',
    'detail': '设置热点配置信息',
    'method': 'setHotspotConfig',
    'api': testSetHotspotConfig,
    'result': 'None',
    'category': CaseCategory.Hotspot
},
  {
    'name': '获取热点配置信息',
    'detail': '获取热点配置信息',
    'method': 'getHotspotConfig',
    'api': testGetHotspotConfig,
    'result': 'None',
    'category': CaseCategory.Hotspot
},
  {
    'name': '获取连接的设备',
    'detail': '获取连接的设备',
    'method': 'getStations',
    'api': testGetStations,
    'result': 'None',
    'category': CaseCategory.Hotspot
},
  {
    'name': '注册加入改变事件',
    'detail': '注册加入改变事件',
    'method': 'on.hotspotStaJoinChange',
    'api': testOnHotspotStaJoin,
    'result': 'None',
    'category': CaseCategory.Hotspot
},
  {
    'name': '注册离开改变事件',
    'detail': '注册离开改变事件',
    'method': 'on.hotspotStaLeaveChange',
    'api': testOnHotspotStaLeave,
    'result': 'None',
    'category': CaseCategory.Hotspot
  }
]
const HotspotManagerTestCase: WifiTest[] = [
  {
    'name': '注册热点状态改变事件',
    'detail': '注册热点状态改变事件',
    'method': 'on.hotspotStateChange',
    'api': testOnHotspotStateChangeManager,
    'result': 'None',
    'category': CaseCategory.HotspotManager
},
  {
    'name': '热点是否已使能',
    'detail': '热点是否已使能',
    'method': 'isHostActive',
    'api': testIsHostActiveManager,
    'result': 'None',
    'category': CaseCategory.HotspotManager
},
  {
    'name': '使能热点',
    'detail': '使能热点',
    'method': 'enableHotspot',
    'api': testEnableHotspotManager,
    'result': 'None',
    'category': CaseCategory.HotspotManager
},
  {
    'name': '去使能热点',
    'detail': '去使能热点',
    'method': 'disableHotspot',
    'api': testDisableHotspotManager,
    'result': 'None',
    'category': CaseCategory.HotspotManager
},
  {
    'name': '热点是否支持双频',
    'detail': '热点是否支持双频',
    'method': 'isHotspotDualBandSupported',
    'api': testIsHotspotDualBandSupportedManager,
    'result': 'None',
    'category': CaseCategory.HotspotManager
},
  {
    'name': '设置热点配置信息',
    'detail': '设置热点配置信息',
    'method': 'setHotspotConfig',
    'api': testSetHotspotConfigManager,
    'result': 'None',
    'category': CaseCategory.HotspotManager
},
  {
    'name': '获取热点配置信息',
    'detail': '获取热点配置信息',
    'method': 'getHotspotConfig',
    'api': testGetHotspotConfigManager,
    'result': 'None',
    'category': CaseCategory.HotspotManager
},
  {
    'name': '获取连接的设备',
    'detail': '获取连接的设备',
    'method': 'getStations',
    'api': testGetHotspotStationsManager,
    'result': 'None',
    'category': CaseCategory.HotspotManager
},
  {
    'name': '注册加入改变事件',
    'detail': '注册加入改变事件',
    'method': 'on.hotspotStateChange',
    'api': testOnHotspotStaJoinManager,
    'result': 'None',
    'category': CaseCategory.HotspotManager
},
  {
    'name': '注册离开改变事件',
    'detail': '注册离开改变事件',
    'method': 'on.hotspotStateChange',
    'api': testOnHotspotStaLeaveManager,
    'result': 'None',
    'category': CaseCategory.HotspotManager
},
  {
    'name': '是否为计量热点',
    'detail': '是否为计量热点',
    'method': 'isMeteredHotspot',
    'api': testIsMeteredHotspot,
    'result': 'None',
    'category': CaseCategory.HotspotManager
},
  {
    'name': '添加热点黑名单',
    'detail': '添加热点黑名单',
    'method': 'addHotspotBlockList',
    'api': testAddHotspotBlockList,
    'result': 'None',
    'category': CaseCategory.HotspotManager