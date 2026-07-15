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

/** 注册 Api_Parameter_Coverage 分片 part01（须在 describe 内调用） */
export function register_param_part01(): void {
    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00001
     * @tc.name WM_P_00001_wifiManager_enableWifi
     * @tc.desc wifiManager.enableWifi param#0 precond=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00001_wifiManager_enableWifi', 0, async () => {
      await executeApiTestCaseById('WM_P_00001');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00002
     * @tc.name WM_P_00002_wifiManager_enableWifi
     * @tc.desc wifiManager.enableWifi param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00002_wifiManager_enableWifi', 0, async () => {
      await executeApiTestCaseById('WM_P_00002');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00003
     * @tc.name WM_P_00003_wifiManager_disableWifi
     * @tc.desc wifiManager.disableWifi param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00003_wifiManager_disableWifi', 0, async () => {
      await executeApiTestCaseById('WM_P_00003');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00004
     * @tc.name WM_P_00004_wifiManager_disableWifi
     * @tc.desc wifiManager.disableWifi param#0 precond=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00004_wifiManager_disableWifi', 0, async () => {
      await executeApiTestCaseById('WM_P_00004');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00005
     * @tc.name WM_P_00005_wifiManager_enableSemiWifi
     * @tc.desc wifiManager.enableSemiWifi param#0 precond=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00005_wifiManager_enableSemiWifi', 0, async () => {
      await executeApiTestCaseById('WM_P_00005');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00006
     * @tc.name WM_P_00006_wifiManager_enableSemiWifi
     * @tc.desc wifiManager.enableSemiWifi param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00006_wifiManager_enableSemiWifi', 0, async () => {
      await executeApiTestCaseById('WM_P_00006');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00007
     * @tc.name WM_P_00007_wifiManager_isWifiActive
     * @tc.desc wifiManager.isWifiActive param#0 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00007_wifiManager_isWifiActive', 0, async () => {
      await executeApiTestCaseById('WM_P_00007');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00008
     * @tc.name WM_P_00008_wifiManager_isWifiActive
     * @tc.desc wifiManager.isWifiActive param#0 precond=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00008_wifiManager_isWifiActive', 0, async () => {
      await executeApiTestCaseById('WM_P_00008');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00009
     * @tc.name WM_P_00009_wifiManager_isWifiActive
     * @tc.desc wifiManager.isWifiActive param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00009_wifiManager_isWifiActive', 0, async () => {
      await executeApiTestCaseById('WM_P_00009');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00010
     * @tc.name WM_P_00010_wifiManager_scan
     * @tc.desc wifiManager.scan param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00010_wifiManager_scan', 0, async () => {
      await executeApiTestCaseById('WM_P_00010');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00011
     * @tc.name WM_P_00011_wifiManager_startScan
     * @tc.desc wifiManager.startScan param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00011_wifiManager_startScan', 0, async () => {
      await executeApiTestCaseById('WM_P_00011');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00012
     * @tc.name WM_P_00012_wifiManager_getScanInfoList
     * @tc.desc wifiManager.getScanInfoList param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00012_wifiManager_getScanInfoList', 0, async () => {
      await executeApiTestCaseById('WM_P_00012');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00013
     * @tc.name WM_P_00013_wifiManager_getScanInfoList
     * @tc.desc wifiManager.getScanInfoList param#0 precond=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00013_wifiManager_getScanInfoList', 0, async () => {
      await executeApiTestCaseById('WM_P_00013');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00014
     * @tc.name WM_P_00014_wifiManager_getScanResultsSync
     * @tc.desc wifiManager.getScanResultsSync param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00014_wifiManager_getScanResultsSync', 0, async () => {
      await executeApiTestCaseById('WM_P_00014');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00015
     * @tc.name WM_P_00015_wifiManager_getScanResultsSync
     * @tc.desc wifiManager.getScanResultsSync param#0 precond=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00015_wifiManager_getScanResultsSync', 0, async () => {
      await executeApiTestCaseById('WM_P_00015');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00016
     * @tc.name WM_P_00016_wifiManager_getWifiDetailState
     * @tc.desc wifiManager.getWifiDetailState param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00016_wifiManager_getWifiDetailState', 0, async () => {
      await executeApiTestCaseById('WM_P_00016');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00017
     * @tc.name WM_P_00017_wifiManager_getWifiDetailState
     * @tc.desc wifiManager.getWifiDetailState param#0 precond=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00017_wifiManager_getWifiDetailState', 0, async () => {
      await executeApiTestCaseById('WM_P_00017');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00018
     * @tc.name WM_P_00018_wifiManager_setScanAlwaysAllowed
     * @tc.desc wifiManager.setScanAlwaysAllowed param#0 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00018_wifiManager_setScanAlwaysAllowed', 0, async () => {
      await executeApiTestCaseById('WM_P_00018');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00019
     * @tc.name WM_P_00019_wifiManager_setScanAlwaysAllowed
     * @tc.desc wifiManager.setScanAlwaysAllowed param#1 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00019_wifiManager_setScanAlwaysAllowed', 0, async () => {
      await executeApiTestCaseById('WM_P_00019');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00020
     * @tc.name WM_P_00020_wifiManager_getScanAlwaysAllowed
     * @tc.desc wifiManager.getScanAlwaysAllowed param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00020_wifiManager_getScanAlwaysAllowed', 0, async () => {
      await executeApiTestCaseById('WM_P_00020');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00021
     * @tc.name WM_P_00021_wifiManager_getCandidateConfigs
     * @tc.desc wifiManager.getCandidateConfigs param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00021_wifiManager_getCandidateConfigs', 0, async () => {
      await executeApiTestCaseById('WM_P_00021');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00022
     * @tc.name WM_P_00022_wifiManager_connectToNetwork
     * @tc.desc wifiManager.connectToNetwork param#0 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00022_wifiManager_connectToNetwork', 0, async () => {
      await executeApiTestCaseById('WM_P_00022');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00023
     * @tc.name WM_P_00023_wifiManager_connectToNetwork
     * @tc.desc wifiManager.connectToNetwork param#1 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00023_wifiManager_connectToNetwork', 0, async () => {
      await executeApiTestCaseById('WM_P_00023');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00024
     * @tc.name WM_P_00024_wifiManager_connectToNetwork
     * @tc.desc wifiManager.connectToNetwork param#2 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00024_wifiManager_connectToNetwork', 0, async () => {
      await executeApiTestCaseById('WM_P_00024');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00025
     * @tc.name WM_P_00025_wifiManager_disconnect
     * @tc.desc wifiManager.disconnect param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00025_wifiManager_disconnect', 0, async () => {
      await executeApiTestCaseById('WM_P_00025');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00026
     * @tc.name WM_P_00026_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#0 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00026_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00026');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00027
     * @tc.name WM_P_00027_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#1 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00027_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00027');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00028
     * @tc.name WM_P_00028_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#2 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00028_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00028');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00029
     * @tc.name WM_P_00029_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#3 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00029_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00029');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00030
     * @tc.name WM_P_00030_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#4 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00030_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00030');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00031
     * @tc.name WM_P_00031_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#5 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00031_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00031');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00032
     * @tc.name WM_P_00032_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#6 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00032_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00032');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00033
     * @tc.name WM_P_00033_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#7 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00033_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00033');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00034
     * @tc.name WM_P_00034_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#8 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00034_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00034');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00035
     * @tc.name WM_P_00035_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#9 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00035_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00035');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00036
     * @tc.name WM_P_00036_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#10 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00036_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00036');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00037
     * @tc.name WM_P_00037_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#11 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00037_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00037');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00038
     * @tc.name WM_P_00038_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#12 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00038_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00038');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00039
     * @tc.name WM_P_00039_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#13 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00039_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00039');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00040
     * @tc.name WM_P_00040_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#14 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00040_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00040');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00041
     * @tc.name WM_P_00041_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#15 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00041_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00041');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00042
     * @tc.name WM_P_00042_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#16 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00042_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00042');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00043
     * @tc.name WM_P_00043_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#17 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00043_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00043');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00044
     * @tc.name WM_P_00044_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#18 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00044_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00044');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00045
     * @tc.name WM_P_00045_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#19 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00045_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00045');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00046
     * @tc.name WM_P_00046_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel param#20 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00046_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_P_00046');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00047
     * @tc.name WM_P_00047_wifiManager_getLinkedInfoSync
     * @tc.desc wifiManager.getLinkedInfoSync param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00047_wifiManager_getLinkedInfoSync', 0, async () => {
      await executeApiTestCaseById('WM_P_00047');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00048
     * @tc.name WM_P_00048_wifiManager_getMultiLinkedInfo
     * @tc.desc wifiManager.getMultiLinkedInfo param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00048_wifiManager_getMultiLinkedInfo', 0, async () => {
      await executeApiTestCaseById('WM_P_00048');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00049
     * @tc.name WM_P_00049_wifiManager_isConnected
     * @tc.desc wifiManager.isConnected param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00049_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_P_00049');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00050
     * @tc.name WM_P_00050_wifiManager_isConnected
     * @tc.desc wifiManager.isConnected param#0 precond=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00050_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_P_00050');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00051
     * @tc.name WM_P_00051_wifiManager_getSupportedFeatures
     * @tc.desc wifiManager.getSupportedFeatures param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00051_wifiManager_getSupportedFeatures', 0, async () => {
      await executeApiTestCaseById('WM_P_00051');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00052
     * @tc.name WM_P_00052_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#0 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00052_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00052');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00053
     * @tc.name WM_P_00053_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#1 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00053_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00053');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00054
     * @tc.name WM_P_00054_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#2 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00054_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00054');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00055
     * @tc.name WM_P_00055_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#3 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00055_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00055');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00056
     * @tc.name WM_P_00056_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#4 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00056_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00056');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00057
     * @tc.name WM_P_00057_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#5 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00057_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00057');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00058
     * @tc.name WM_P_00058_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#6 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00058_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00058');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00059
     * @tc.name WM_P_00059_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#7 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00059_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00059');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00060
     * @tc.name WM_P_00060_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#8 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00060_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00060');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00061
     * @tc.name WM_P_00061_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#9 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00061_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00061');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00062
     * @tc.name WM_P_00062_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#10 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00062_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00062');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00063
     * @tc.name WM_P_00063_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#11 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00063_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00063');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00064
     * @tc.name WM_P_00064_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#12 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00064_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00064');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00065
     * @tc.name WM_P_00065_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#13 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00065_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00065');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00066
     * @tc.name WM_P_00066_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#14 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00066_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00066');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00067
     * @tc.name WM_P_00067_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported param#15 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00067_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00067');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00068
     * @tc.name WM_P_00068_wifiManager_getDeviceMacAddress
     * @tc.desc wifiManager.getDeviceMacAddress param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00068_wifiManager_getDeviceMacAddress', 0, async () => {
      await executeApiTestCaseById('WM_P_00068');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00069
     * @tc.name WM_P_00069_wifiManager_getIpInfo
     * @tc.desc wifiManager.getIpInfo param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00069_wifiManager_getIpInfo', 0, async () => {
      await executeApiTestCaseById('WM_P_00069');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00070
     * @tc.name WM_P_00070_wifiManager_getIpv6Info
     * @tc.desc wifiManager.getIpv6Info param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00070_wifiManager_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WM_P_00070');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00071
     * @tc.name WM_P_00071_wifiManager_getCountryCode
     * @tc.desc wifiManager.getCountryCode param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00071_wifiManager_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WM_P_00071');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00072
     * @tc.name WM_P_00072_wifiManager_reassociate
     * @tc.desc wifiManager.reassociate param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00072_wifiManager_reassociate', 0, async () => {
      await executeApiTestCaseById('WM_P_00072');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00073
     * @tc.name WM_P_00073_wifiManager_reconnect
     * @tc.desc wifiManager.reconnect param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00073_wifiManager_reconnect', 0, async () => {
      await executeApiTestCaseById('WM_P_00073');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00074
     * @tc.name WM_P_00074_wifiManager_getDeviceConfigs
     * @tc.desc wifiManager.getDeviceConfigs param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00074_wifiManager_getDeviceConfigs', 0, async () => {
      await executeApiTestCaseById('WM_P_00074');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00075
     * @tc.name WM_P_00075_wifiManager_allowAutoConnect
     * @tc.desc wifiManager.allowAutoConnect param#0 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00075_wifiManager_allowAutoConnect', 0, async () => {
      await executeApiTestCaseById('WM_P_00075');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00076
     * @tc.name WM_P_00076_wifiManager_allowAutoConnect
     * @tc.desc wifiManager.allowAutoConnect param#1 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00076_wifiManager_allowAutoConnect', 0, async () => {
      await executeApiTestCaseById('WM_P_00076');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00077
     * @tc.name WM_P_00077_wifiManager_allowAutoConnect
     * @tc.desc wifiManager.allowAutoConnect param#2 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00077_wifiManager_allowAutoConnect', 0, async () => {
      await executeApiTestCaseById('WM_P_00077');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00078
     * @tc.name WM_P_00078_wifiManager_disableNetwork
     * @tc.desc wifiManager.disableNetwork param#0 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00078_wifiManager_disableNetwork', 0, async () => {
      await executeApiTestCaseById('WM_P_00078');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00079
     * @tc.name WM_P_00079_wifiManager_disableNetwork
     * @tc.desc wifiManager.disableNetwork param#1 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00079_wifiManager_disableNetwork', 0, async () => {
      await executeApiTestCaseById('WM_P_00079');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00080
     * @tc.name WM_P_00080_wifiManager_disableNetwork
     * @tc.desc wifiManager.disableNetwork param#2 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00080_wifiManager_disableNetwork', 0, async () => {
      await executeApiTestCaseById('WM_P_00080');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00081
     * @tc.name WM_P_00081_wifiManager_disableNetwork
     * @tc.desc wifiManager.disableNetwork param#3 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00081_wifiManager_disableNetwork', 0, async () => {
      await executeApiTestCaseById('WM_P_00081');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00082
     * @tc.name WM_P_00082_wifiManager_disableNetwork
     * @tc.desc wifiManager.disableNetwork param#4 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00082_wifiManager_disableNetwork', 0, async () => {
      await executeApiTestCaseById('WM_P_00082');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00083
     * @tc.name WM_P_00083_wifiManager_removeAllNetwork
     * @tc.desc wifiManager.removeAllNetwork param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00083_wifiManager_removeAllNetwork', 0, async () => {
      await executeApiTestCaseById('WM_P_00083');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00084
     * @tc.name WM_P_00084_wifiManager_removeDevice
     * @tc.desc wifiManager.removeDevice param#0 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00084_wifiManager_removeDevice', 0, async () => {
      await executeApiTestCaseById('WM_P_00084');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00085
     * @tc.name WM_P_00085_wifiManager_removeDevice
     * @tc.desc wifiManager.removeDevice param#1 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00085_wifiManager_removeDevice', 0, async () => {
      await executeApiTestCaseById('WM_P_00085');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00086
     * @tc.name WM_P_00086_wifiManager_removeDevice
     * @tc.desc wifiManager.removeDevice param#2 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00086_wifiManager_removeDevice', 0, async () => {
      await executeApiTestCaseById('WM_P_00086');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00087
     * @tc.name WM_P_00087_wifiManager_isBandTypeSupported
     * @tc.desc wifiManager.isBandTypeSupported param#0 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00087_wifiManager_isBandTypeSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00087');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00088
     * @tc.name WM_P_00088_wifiManager_isBandTypeSupported
     * @tc.desc wifiManager.isBandTypeSupported param#1 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00088_wifiManager_isBandTypeSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00088');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00089
     * @tc.name WM_P_00089_wifiManager_isBandTypeSupported
     * @tc.desc wifiManager.isBandTypeSupported param#2 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00089_wifiManager_isBandTypeSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00089');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00090
     * @tc.name WM_P_00090_wifiManager_isBandTypeSupported
     * @tc.desc wifiManager.isBandTypeSupported param#3 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00090_wifiManager_isBandTypeSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00090');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00091
     * @tc.name WM_P_00091_wifiManager_isBandTypeSupported
     * @tc.desc wifiManager.isBandTypeSupported param#4 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00091_wifiManager_isBandTypeSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00091');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00092
     * @tc.name WM_P_00092_wifiManager_isBandTypeSupported
     * @tc.desc wifiManager.isBandTypeSupported param#5 precond=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00092_wifiManager_isBandTypeSupported', 0, async () => {
      await executeApiTestCaseById('WM_P_00092');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00093
     * @tc.name WM_P_00093_wifiManager_get5GChannelList
     * @tc.desc wifiManager.get5GChannelList param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00093_wifiManager_get5GChannelList', 0, async () => {
      await executeApiTestCaseById('WM_P_00093');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00094
     * @tc.name WM_P_00094_wifiManager_getDisconnectedReason
     * @tc.desc wifiManager.getDisconnectedReason param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00094_wifiManager_getDisconnectedReason', 0, async () => {
      await executeApiTestCaseById('WM_P_00094');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00095
     * @tc.name WM_P_00095_wifiManager_getDisconnectedReason
     * @tc.desc wifiManager.getDisconnectedReason param#0 precond=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00095_wifiManager_getDisconnectedReason', 0, async () => {
      await executeApiTestCaseById('WM_P_00095');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00096
     * @tc.name WM_P_00096_wifiManager_startPortalCertification
     * @tc.desc wifiManager.startPortalCertification param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00096_wifiManager_startPortalCertification', 0, async () => {
      await executeApiTestCaseById('WM_P_00096');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00097
     * @tc.name WM_P_00097_wifiManager_startWifiDetection
     * @tc.desc wifiManager.startWifiDetection param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00097_wifiManager_startWifiDetection', 0, async () => {
      await executeApiTestCaseById('WM_P_00097');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00098
     * @tc.name WM_P_00098_wifiManager_isRandomMacDisabled
     * @tc.desc wifiManager.isRandomMacDisabled param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00098_wifiManager_isRandomMacDisabled', 0, async () => {
      await executeApiTestCaseById('WM_P_00098');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00099
     * @tc.name WM_P_00099_wifiManager_isMeteredHotspot
     * @tc.desc wifiManager.isMeteredHotspot param#0 precond=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00099_wifiManager_isMeteredHotspot', 0, async () => {
      await executeApiTestCaseById('WM_P_00099');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_P_00100
     * @tc.name WM_P_00100_wifiManager_isMeteredHotspot
     * @tc.desc wifiManager.isMeteredHotspot param#0 precond=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('WM_P_00100_wifiManager_isMeteredHotspot', 0, async () => {
      await executeApiTestCaseById('WM_P_00100');
    });

}
