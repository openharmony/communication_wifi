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

export class MessageDataManager {
  TAG = 'WIFI_Manager_Test '
  //wifi
  testEnableWifi = "enableWifi test";
  testIsActive = "Wifi已经使能"
  testWifiEnableResult = "Wifi使能执行结果："
  testEnableResult = "使能结果："
  testWifiEnableMaybe = "Wifi已打开或打开失败,请确认"
  testDisableWifi = "testDisableWifi"
  testIsInactive = "WIFI还未使能"
  testWifiDisableResult = "Wifi去使能执行结果："
  testDisableResult = "去使能结果："
  testWifiDisableMaybe = "Wifi已关闭或关闭失败,请确认"
  testIsWifiActive = "testIsWifiActive"
  testIsActiveResult = "wifi使能结果为："
  testScan = "scan test"
  testScanResult = "scan: "
  testForcibleScan = "ForcibleScan test"
  testForcibleScanResult = "ForcibleScan: "
  testGetScanInfoList = "getScanInfoList test"
  testGetScanInfosPromise = "getScanInfosPromise test"
  testGetScanInfo = "WifiScanInfo: "
  testGetScanInfosCallback = "getScanInfosCallback test"
  testAddDeviceConfigPromise = "addDeviceConfigPromise test"
  testAddDeviceConfig = "addDeviceConfig: "
  testAddDeviceConfigCallback = "addDeviceConfigCallback test"
  testAddCandidateConfigPromise = "addCandidateConfigPromise test"
  testAddCandidateConfig = "addCandidateConfig: "
  testAddCandidateConfigCallback = "addCandidateConfigCallback test"
  testRemoveCandidateConfigPromise = "removeCandidateConfigPromise test"
  testRemoveCandidateConfig = "removeCandidateConfig: "
  testRemoveCandidateConfigCallback = "removeCandidateConfigCallback test"
  testGetCandidateConfigs = "GetCandidateConfigs test"

  testConnectToCandidateConfig = "ConnectToCandidateConfig test"






  testConnectToNetwork = "connectToNetwork test"
  testConnectToDevice = "connectToDevice test"
  testDisconnect = "disconnect test"
  testGetSignalLevel = "getSignalLevel test"
  testGetLinkedInfoPromise = "getLinkedInfoPromise test"
  testGetLinkedInfoCallback = "getLinkedInfoCallback test"
  testIsConnected = "isConnected test"
  testGetSupportedFeatures = "getSupportedFeatures test"
  testIsFeatureSupported = "isFeatureSupported test"
  testGetDeviceMacAddress = "getDeviceMacAddress test"
  testGetIpInfo = "getIpInfo test"
  testGetCountryCode = "getCountryCode test"
  testReassociate = "reAssociate test"
  testReConnect = "reConnect test"
  testGetDeviceConfigs = "getDeviceConfigs test"
  testUpdateNetwork = "updateNetwork test"
  testDisableNetwork = "disableNetWork test"
  testRemoveAllNetwork = "removeAllNetwork test"
  testRemoveDevice = "removeDevice test"
  testOnWifiStateChange = "onWifiStateChange test"
  offWifiStateChange = "on.WifiStateChange监听已关闭"
  offWifiStateChangeTest = "关闭注册WLAN状态改变事件"
  onWifiStateChange = "on.WifiStateChange监听已打开"
  onWifiStateChangeTest = "打开注册WLAN状态变化"
  wifiStateChange = "wifi状态: "
  testOnWifiConnectionChange = "onWifiConnectionChange test"
  offWifiConnectionChange = "on.wifiConnectionChange监听已关闭"
  offWifiConnectionChangeTest = "关闭WLAN连接状态改变事件"
  onWifiConnectionChangeTest = "打开注册WLAN连接状态变化"
  testOnWifiScanStateChange = "onWifiScanStateChange test"
  offWifiScanStateChange = "on.wifiScanStateChange监听已关闭"
  offWifiScanStateChangeTest = "关闭扫描状态改变事件"
  onWifiScanStateChangeTest = "打开注册扫描状态变化"
  testOnWifiRssiChange = "onWifiRssiChange test"
  offWifiRssiChange = "on.wifiRssiChange监听已关闭"
  offWifiRssiChangeTest = "关闭RSSI状态变化事件"
  onWifiRssiChangeTest = "打开注册RSSI状态变化"
  testOnStreamChange = "onStreamChange test"
  offStreamChange = "on.streamChange监听已关闭"
  offStreamChangeTest = "关闭注册流改变事件"
  onStreamChangeTest = "打开注册流变化"
  //hotspot
  testEnableHotspot = "enableHotspot test"
  testDisableHotspot = "disableHotspot test"
  hotspot_enable = "热点已经使能"
  hotspot_disEnable = "热点还未使能"
  testIsHotspotDualBandSupported = "isHotspotDualBandSupported test"
  testIsHotspotActive = "isHotspotActive test"
  testSetHotspotConfig = "SetHotspotConfig test"
  testGetHotspotConfig = "getHotspotConfig test"
  testGetStations = "GetStations test"
  testOnHotspotStateChange = "onHotspotStateChange test"
  offHotspotStateChange = "on.hotspotStateChange监听已关闭"
  offHotspotStateChangeTest = "关闭注册热点状态改变事件"
  onHotspotStateChangeTest = "打开注册热点状态变化"
  testOnHotspotStaJoin = "onHotspotStaJoin test"
  offHotspotStaJoin = "on.hotspotStaJoin监听已关闭"
  offHotspotStaJoinTest = "关闭注册Wi-Fi 热点 sta加入变化事件"
  onHotspotStaJoinTest = "打开注册Wi-Fi 热点 sta加入变化"
  testOnHotspotStaLeave = "onHotspotStaLeave test"
  offHotspotStaLeave = "on.hotspotStaLeave监听已关闭"
  offHotspotStaLeaveTest = "关闭注册Wi-Fi 热点 sta离开变化事件"
  onHotspotStaLeaveTest = "打开注册Wi-Fi 热点 sta离开变化"
  //p2p
  testGetP2pLinkedInfoPromise = "getP2pLinkedInfoPromise test"
  testGetP2pLinkedInfoCallback = "getP2pLinkedInfoCallback test"
  testGetCurrentGroupPromise = "getCurrentGroupPromise test"
  testGetCurrentGroupCallback = "getCurrentGroupCallback test"
  testGetP2pPeerDevicesPromise = "getP2pPeerDevicesPromise test"
  testGetP2pPeerDevicesCallback = "getP2pPeerDevicesCallback test"
  testCreateGroup = "createGroup test"
  testRemoveGroup = "removeGroup test"
  testP2pConnect = "P2pConnect test"
  testP2pCancelConnect = "p2pCancelConnect test"
  testStartDiscoverDevices = "startDiscoverDevices test"
  testStopDiscoverDevices = "stopDiscoverDevices test"
  testDeletePersistentGroup = "deletePersistentGroup test"
  testSetDeviceName = "setDeviceName test"
  testOnP2pStateChange = "OnP2pStateChange test"
  offP2pStateChange = "on.p2pStateChange监听已关闭"
  onP2pStateChangeTest = "打开注册P2P开关状态变化"
  offP2pStateChangeTest = "关闭注册P2P开关状态改变事件"
  testOnP2pConnectionChange = "OnP2pConnectionChange test"
  offP2pConnectionChange = "on.P2pConnectionChange监听已关闭"
  offP2pConnectionChangeTest = "关闭P2P连接状态改变事件"
  onP2pConnectionChangeTest = "打开注册p2p连接状态变化"
  testOnP2pDeviceChange = "OnP2pDeviceChange test"
  offP2pDeviceChange = "on.P2pDeviceChange监听已关闭"
  offP2pDeviceChangeTest = "关闭P2P设备状态改变事件"
  onP2pDeviceChangeTest = "打开注册p2p设备连接状态变化"
  testOnP2pPeerDeviceChange = "OnP2pPeerDeviceChange test"
  offP2pPeerDeviceChange = "on.p2pPeerDeviceChange监听已关闭"
  offP2pPeerDeviceChangeTest = "关闭P2P对端设备状态改变事件"
  onP2pPeerDeviceChangeTest = "打开P2P对端设备状态变化"
  testOnP2pPersistentGroupChange = "OnP2pPersistentGroupChange test"
  offP2pPersistentGroupChange = "on.p2pPersistentGroupChange监听已关闭"
  offP2pPersistentGroupChangeTest = "关闭P2P设备状态改变事件"
  onP2pPersistentGroupChangeTest = "打开P2P永久组状态变化"
  testOnP2pDiscoveryChange = "OnP2pDiscoveryChange test"
  offP2pDiscoveryChange = "on.P2pDiscoveryChange监听已关闭"
  offP2pDiscoveryChangeTest = "关闭发现设备状态改变事件"
  onP2pDiscoveryChangeTest = "打开发现设备状态变化"
}

let messageDataManager = new MessageDataManager();

export default messageDataManager as MessageDataManager;