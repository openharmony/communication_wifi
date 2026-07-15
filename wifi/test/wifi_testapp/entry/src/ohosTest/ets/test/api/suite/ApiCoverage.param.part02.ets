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
/** 自动生成，请勿手改 */
import { it } from '@ohos/hypium';
import { executeApiTestCaseById } from '../ApiTestRunner';

/** 注册 Api_Parameter_Coverage 分片 part02（须在 describe 内调用） */
export function register_param_part02(): void {
    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00101
     * @tc.name WM_P_00101_wifiManager_factoryReset
     * @tc.desc wifiManager.factoryReset param#0 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00101_wifiManager_factoryReset', 0, async () => {
      await executeApiTestCaseById('WM_P_00101');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00102
     * @tc.name WM_P_00102_wifiManager_isOpenSoftApAllowed
     * @tc.desc wifiManager.isOpenSoftApAllowed param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00102_wifiManager_isOpenSoftApAllowed', 0, async () => {
      await executeApiTestCaseById('WM_P_00102');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00103
     * @tc.name WM_P_00103_wifiManager_isOpenSoftApAllowed
     * @tc.desc wifiManager.isOpenSoftApAllowed param#0 precond=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00103_wifiManager_isOpenSoftApAllowed', 0, async () => {
      await executeApiTestCaseById('WM_P_00103');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00104
     * @tc.name WM_P_00104_wifiManager_enableHotspot
     * @tc.desc wifiManager.enableHotspot param#0 precond=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00104_wifiManager_enableHotspot', 0, async () => {
      await executeApiTestCaseById('WM_P_00104');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00105
     * @tc.name WM_P_00105_wifiManager_enableHotspot
     * @tc.desc wifiManager.enableHotspot param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00105_wifiManager_enableHotspot', 0, async () => {
      await executeApiTestCaseById('WM_P_00105');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00106
     * @tc.name WM_P_00106_wifiManager_disableHotspot
     * @tc.desc wifiManager.disableHotspot param#0 precond=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00106_wifiManager_disableHotspot', 0, async () => {
      await executeApiTestCaseById('WM_P_00106');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00107
     * @tc.name WM_P_00107_wifiManager_disableHotspot
     * @tc.desc wifiManager.disableHotspot param#0 precond=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00107_wifiManager_disableHotspot', 0, async () => {
      await executeApiTestCaseById('WM_P_00107');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00108
     * @tc.name WM_P_00108_wifiManager_isHotspotDualBandSupported
     * @tc.desc wifiManager.isHotspotDualBandSupported param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00108_wifiManager_isHotspotDualBandSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00108');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00109
     * @tc.name WM_P_00109_wifiManager_isHotspotActive
     * @tc.desc wifiManager.isHotspotActive param#0 precond=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00109_wifiManager_isHotspotActive', 0, async () => {
      await executeApiTestCaseById('WM_P_00109');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00110
     * @tc.name WM_P_00110_wifiManager_isHotspotActive
     * @tc.desc wifiManager.isHotspotActive param#0 precond=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00110_wifiManager_isHotspotActive', 0, async () => {
      await executeApiTestCaseById('WM_P_00110');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00111
     * @tc.name WM_P_00111_wifiManager_getHotspotConfig
     * @tc.desc wifiManager.getHotspotConfig param#0 precond=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00111_wifiManager_getHotspotConfig', 0, async () => {
      await executeApiTestCaseById('WM_P_00111');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00112
     * @tc.name WM_P_00112_wifiManager_getHotspotConfig
     * @tc.desc wifiManager.getHotspotConfig param#0 precond=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00112_wifiManager_getHotspotConfig', 0, async () => {
      await executeApiTestCaseById('WM_P_00112');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00113
     * @tc.name WM_P_00113_wifiManager_getStations
     * @tc.desc wifiManager.getStations param#0 precond=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00113_wifiManager_getStations', 0, async () => {
      await executeApiTestCaseById('WM_P_00113');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00114
     * @tc.name WM_P_00114_wifiManager_getHotspotBlockList
     * @tc.desc wifiManager.getHotspotBlockList param#0 precond=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00114_wifiManager_getHotspotBlockList', 0, async () => {
      await executeApiTestCaseById('WM_P_00114');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00115
     * @tc.name WM_P_00115_wifiManager_getHotspotBlockList
     * @tc.desc wifiManager.getHotspotBlockList param#0 precond=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00115_wifiManager_getHotspotBlockList', 0, async () => {
      await executeApiTestCaseById('WM_P_00115');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00116
     * @tc.name WM_P_00116_wifiManager_getP2pLinkedInfo
     * @tc.desc wifiManager.getP2pLinkedInfo param#0 precond=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00116_wifiManager_getP2pLinkedInfo', 0, async () => {
      await executeApiTestCaseById('WM_P_00116');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00117
     * @tc.name WM_P_00117_wifiManager_getP2pLinkedInfo
     * @tc.desc wifiManager.getP2pLinkedInfo param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00117_wifiManager_getP2pLinkedInfo', 0, async () => {
      await executeApiTestCaseById('WM_P_00117');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00118
     * @tc.name WM_P_00118_wifiManager_getCurrentGroup
     * @tc.desc wifiManager.getCurrentGroup param#0 precond=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00118_wifiManager_getCurrentGroup', 0, async () => {
      await executeApiTestCaseById('WM_P_00118');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00119
     * @tc.name WM_P_00119_wifiManager_getCurrentGroup
     * @tc.desc wifiManager.getCurrentGroup param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00119_wifiManager_getCurrentGroup', 0, async () => {
      await executeApiTestCaseById('WM_P_00119');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00120
     * @tc.name WM_P_00120_wifiManager_getP2pPeerDevices
     * @tc.desc wifiManager.getP2pPeerDevices param#0 precond=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00120_wifiManager_getP2pPeerDevices', 0, async () => {
      await executeApiTestCaseById('WM_P_00120');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00121
     * @tc.name WM_P_00121_wifiManager_getP2pPeerDevices
     * @tc.desc wifiManager.getP2pPeerDevices param#0 precond=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00121_wifiManager_getP2pPeerDevices', 0, async () => {
      await executeApiTestCaseById('WM_P_00121');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00122
     * @tc.name WM_P_00122_wifiManager_getP2pLocalDevice
     * @tc.desc wifiManager.getP2pLocalDevice param#0 precond=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00122_wifiManager_getP2pLocalDevice', 0, async () => {
      await executeApiTestCaseById('WM_P_00122');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00123
     * @tc.name WM_P_00123_wifiManager_getP2pLocalDevice
     * @tc.desc wifiManager.getP2pLocalDevice param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00123_wifiManager_getP2pLocalDevice', 0, async () => {
      await executeApiTestCaseById('WM_P_00123');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00124
     * @tc.name WM_P_00124_wifiManager_getP2pGroups
     * @tc.desc wifiManager.getP2pGroups param#0 precond=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00124_wifiManager_getP2pGroups', 0, async () => {
      await executeApiTestCaseById('WM_P_00124');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00125
     * @tc.name WM_P_00125_wifiManager_getP2pGroups
     * @tc.desc wifiManager.getP2pGroups param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00125_wifiManager_getP2pGroups', 0, async () => {
      await executeApiTestCaseById('WM_P_00125');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00126
     * @tc.name WM_P_00126_wifiManager_removeGroup
     * @tc.desc wifiManager.removeGroup param#0 precond=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00126_wifiManager_removeGroup', 0, async () => {
      await executeApiTestCaseById('WM_P_00126');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00127
     * @tc.name WM_P_00127_wifiManager_p2pCancelConnect
     * @tc.desc wifiManager.p2pCancelConnect param#0 precond=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00127_wifiManager_p2pCancelConnect', 0, async () => {
      await executeApiTestCaseById('WM_P_00127');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00128
     * @tc.name WM_P_00128_wifiManager_stopDiscoverDevices
     * @tc.desc wifiManager.stopDiscoverDevices param#0 precond=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00128_wifiManager_stopDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WM_P_00128');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00129
     * @tc.name WM_P_00129_wifiManager_stopDiscoverDevices
     * @tc.desc wifiManager.stopDiscoverDevices param#0 precond=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00129_wifiManager_stopDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WM_P_00129');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00130
     * @tc.name WM_P_00130_wifiManager_deletePersistentGroup
     * @tc.desc wifiManager.deletePersistentGroup param#0 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00130_wifiManager_deletePersistentGroup', 0, async () => {
      await executeApiTestCaseById('WM_P_00130');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00131
     * @tc.name WM_P_00131_wifiManager_deletePersistentGroup
     * @tc.desc wifiManager.deletePersistentGroup param#1 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00131_wifiManager_deletePersistentGroup', 0, async () => {
      await executeApiTestCaseById('WM_P_00131');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00132
     * @tc.name WM_P_00132_wifiManager_setDeviceName
     * @tc.desc wifiManager.setDeviceName param#0 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00132_wifiManager_setDeviceName', 0, async () => {
      await executeApiTestCaseById('WM_P_00132');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00133
     * @tc.name WM_P_00133_wifiManager_setDeviceName
     * @tc.desc wifiManager.setDeviceName param#1 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00133_wifiManager_setDeviceName', 0, async () => {
      await executeApiTestCaseById('WM_P_00133');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00134
     * @tc.name WM_P_00134_wifiManager_setDeviceName
     * @tc.desc wifiManager.setDeviceName param#2 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00134_wifiManager_setDeviceName', 0, async () => {
      await executeApiTestCaseById('WM_P_00134');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00135
     * @tc.name WM_P_00135_wifiManager_setDeviceName
     * @tc.desc wifiManager.setDeviceName param#3 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00135_wifiManager_setDeviceName', 0, async () => {
      await executeApiTestCaseById('WM_P_00135');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00136
     * @tc.name WM_P_00136_wifiManager_startDiscoverDevices
     * @tc.desc wifiManager.startDiscoverDevices param#0 precond=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00136_wifiManager_startDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WM_P_00136');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00137
     * @tc.name WM_P_00137_wifiManager_startDiscoverDevices
     * @tc.desc wifiManager.startDiscoverDevices param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00137_wifiManager_startDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WM_P_00137');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00976
     * @tc.name WM_DC_00976_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=0 ip=0 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00976_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00976');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00977
     * @tc.name WM_DC_00977_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=0 ip=0 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00977_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00977');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00978
     * @tc.name WM_DC_00978_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=0 ip=1 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00978_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00978');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00979
     * @tc.name WM_DC_00979_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=0 ip=1 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00979_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00979');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00980
     * @tc.name WM_DC_00980_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=0 ip=2 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00980_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00980');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00981
     * @tc.name WM_DC_00981_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=0 ip=2 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00981_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00981');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00982
     * @tc.name WM_DC_00982_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=1 ip=0 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00982_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00982');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00983
     * @tc.name WM_DC_00983_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=1 ip=0 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00983_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00983');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00984
     * @tc.name WM_DC_00984_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=1 ip=1 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00984_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00984');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00985
     * @tc.name WM_DC_00985_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=1 ip=1 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00985_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00985');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00986
     * @tc.name WM_DC_00986_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=1 ip=2 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00986_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00986');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00987
     * @tc.name WM_DC_00987_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=1 ip=2 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00987_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00987');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00988
     * @tc.name WM_DC_00988_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=2 ip=0 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00988_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00988');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00989
     * @tc.name WM_DC_00989_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=2 ip=0 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00989_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00989');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00990
     * @tc.name WM_DC_00990_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=2 ip=1 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00990_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00990');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00991
     * @tc.name WM_DC_00991_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=2 ip=1 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00991_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00991');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00992
     * @tc.name WM_DC_00992_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=2 ip=2 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00992_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00992');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00993
     * @tc.name WM_DC_00993_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=2 ip=2 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00993_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00993');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00994
     * @tc.name WM_DC_00994_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=3 ip=0 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00994_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00994');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00995
     * @tc.name WM_DC_00995_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=3 ip=0 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00995_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00995');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00996
     * @tc.name WM_DC_00996_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=3 ip=1 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00996_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00996');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00997
     * @tc.name WM_DC_00997_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=3 ip=1 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00997_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00997');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00998
     * @tc.name WM_DC_00998_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=3 ip=2 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00998_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00998');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_00999
     * @tc.name WM_DC_00999_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=3 ip=2 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_00999_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_00999');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01000
     * @tc.name WM_DC_01000_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=4 ip=0 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01000_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01000');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01001
     * @tc.name WM_DC_01001_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=4 ip=0 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01001_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01001');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01002
     * @tc.name WM_DC_01002_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=4 ip=1 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01002_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01002');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01003
     * @tc.name WM_DC_01003_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=4 ip=1 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01003_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01003');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01004
     * @tc.name WM_DC_01004_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=4 ip=2 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01004_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01004');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01005
     * @tc.name WM_DC_01005_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=4 ip=2 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01005_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01005');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01006
     * @tc.name WM_DC_01006_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=5 ip=0 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01006_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01006');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01007
     * @tc.name WM_DC_01007_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=5 ip=0 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01007_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01007');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01008
     * @tc.name WM_DC_01008_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=5 ip=1 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01008_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01008');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01009
     * @tc.name WM_DC_01009_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=5 ip=1 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01009_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01009');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01010
     * @tc.name WM_DC_01010_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=5 ip=2 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01010_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01010');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01011
     * @tc.name WM_DC_01011_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=5 ip=2 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01011_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01011');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01012
     * @tc.name WM_DC_01012_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=6 ip=0 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01012_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01012');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01013
     * @tc.name WM_DC_01013_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=6 ip=0 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01013_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01013');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01014
     * @tc.name WM_DC_01014_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=6 ip=1 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01014_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01014');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01015
     * @tc.name WM_DC_01015_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=6 ip=1 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01015_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01015');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01016
     * @tc.name WM_DC_01016_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=6 ip=2 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01016_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01016');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01017
     * @tc.name WM_DC_01017_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=6 ip=2 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01017_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01017');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01018
     * @tc.name WM_DC_01018_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=7 ip=0 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01018_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01018');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01019
     * @tc.name WM_DC_01019_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=7 ip=0 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01019_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01019');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01020
     * @tc.name WM_DC_01020_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=7 ip=1 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01020_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01020');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01021
     * @tc.name WM_DC_01021_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=7 ip=1 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01021_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01021');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01022
     * @tc.name WM_DC_01022_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=7 ip=2 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01022_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01022');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01023
     * @tc.name WM_DC_01023_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=7 ip=2 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01023_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01023');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01024
     * @tc.name WM_DC_01024_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=8 ip=0 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01024_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01024');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01025
     * @tc.name WM_DC_01025_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=8 ip=0 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01025_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01025');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01026
     * @tc.name WM_DC_01026_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=8 ip=1 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01026_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01026');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01027
     * @tc.name WM_DC_01027_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=8 ip=1 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01027_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01027');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01028
     * @tc.name WM_DC_01028_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=8 ip=2 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01028_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01028');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01029
     * @tc.name WM_DC_01029_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=8 ip=2 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01029_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01029');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01030
     * @tc.name WM_DC_01030_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=9 ip=0 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01030_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01030');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01031
     * @tc.name WM_DC_01031_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=9 ip=0 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01031_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01031');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01032
     * @tc.name WM_DC_01032_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=9 ip=1 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01032_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01032');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01033
     * @tc.name WM_DC_01033_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=9 ip=1 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01033_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01033');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01034
     * @tc.name WM_DC_01034_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=9 ip=2 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01034_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01034');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01035
     * @tc.name WM_DC_01035_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=0 sec=9 ip=2 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01035_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01035');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01036
     * @tc.name WM_DC_01036_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=1 sec=0 ip=0 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01036_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01036');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01037
     * @tc.name WM_DC_01037_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=1 sec=0 ip=0 hidden=False
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01037_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01037');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_DC_01038
     * @tc.name WM_DC_01038_wifiManager_addDeviceConfig
     * @tc.desc addDeviceConfig ssid=1 sec=0 ip=1 hidden=True
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_DC_01038_wifiManager_addDeviceConfig', 0, async () => {
      await executeApiTestCaseById('WM_DC_01038');
    });

}
