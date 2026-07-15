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

/** 注册 Api_Combination_Coverage 分片 part03（须在 describe 内调用） */
export function register_combo_part03(): void {
    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_X_01532
     * @tc.name WM_X_01532_wifiManager_getDeviceMacAddress
     * @tc.desc triple_combo isWifiActive->getIpInfo->getDeviceMacAddress
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WM_X_01532_wifiManager_getDeviceMacAddress', 0, async () => {
      await executeApiTestCaseById('WM_X_01532');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_X_01533
     * @tc.name WM_X_01533_wifiManager_isConnected
     * @tc.desc triple_combo isWifiActive->getIpInfo->isConnected
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WM_X_01533_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_X_01533');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_X_01534
     * @tc.name WM_X_01534_wifiManager_isConnected
     * @tc.desc triple_combo isWifiActive->getDeviceMacAddress->isConnected
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WM_X_01534_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_X_01534');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_X_01535
     * @tc.name WM_X_01535_wifiManager_getDeviceMacAddress
     * @tc.desc triple_combo getCountryCode->getIpInfo->getDeviceMacAddress
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WM_X_01535_wifiManager_getDeviceMacAddress', 0, async () => {
      await executeApiTestCaseById('WM_X_01535');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_X_01536
     * @tc.name WM_X_01536_wifiManager_isConnected
     * @tc.desc triple_combo getCountryCode->getIpInfo->isConnected
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WM_X_01536_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_X_01536');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_X_01537
     * @tc.name WM_X_01537_wifiManager_isConnected
     * @tc.desc triple_combo getCountryCode->getDeviceMacAddress->isConnected
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WM_X_01537_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_X_01537');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_X_01538
     * @tc.name WM_X_01538_wifiManager_isConnected
     * @tc.desc triple_combo getIpInfo->getDeviceMacAddress->isConnected
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WM_X_01538_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_X_01538');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01794
     * @tc.name WF_CB_01794_wifi_getScanInfoList
     * @tc.desc combo flow#0 var#0 -> getScanInfoList
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01794_wifi_getScanInfoList', 0, async () => {
      await executeApiTestCaseById('WF_CB_01794');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01795
     * @tc.name WF_CB_01795_wifi_getScanInfoList
     * @tc.desc combo flow#0 var#1 -> getScanInfoList
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01795_wifi_getScanInfoList', 0, async () => {
      await executeApiTestCaseById('WF_CB_01795');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01796
     * @tc.name WF_CB_01796_wifi_getScanInfoList
     * @tc.desc combo flow#0 var#2 -> getScanInfoList
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01796_wifi_getScanInfoList', 0, async () => {
      await executeApiTestCaseById('WF_CB_01796');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01797
     * @tc.name WF_CB_01797_wifi_getScanInfoList
     * @tc.desc combo flow#0 var#3 -> getScanInfoList
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01797_wifi_getScanInfoList', 0, async () => {
      await executeApiTestCaseById('WF_CB_01797');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01798
     * @tc.name WF_CB_01798_wifi_getScanInfoList
     * @tc.desc combo flow#0 var#4 -> getScanInfoList
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01798_wifi_getScanInfoList', 0, async () => {
      await executeApiTestCaseById('WF_CB_01798');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01799
     * @tc.name WF_CB_01799_wifi_getScanInfoList
     * @tc.desc combo flow#0 var#5 -> getScanInfoList
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01799_wifi_getScanInfoList', 0, async () => {
      await executeApiTestCaseById('WF_CB_01799');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01800
     * @tc.name WF_CB_01800_wifi_getScanInfoList
     * @tc.desc combo flow#0 var#6 -> getScanInfoList
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01800_wifi_getScanInfoList', 0, async () => {
      await executeApiTestCaseById('WF_CB_01800');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01801
     * @tc.name WF_CB_01801_wifi_getScanInfoList
     * @tc.desc combo flow#0 var#7 -> getScanInfoList
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01801_wifi_getScanInfoList', 0, async () => {
      await executeApiTestCaseById('WF_CB_01801');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01802
     * @tc.name WF_CB_01802_wifi_getWifiDetailState
     * @tc.desc combo flow#1 var#0 -> getWifiDetailState
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01802_wifi_getWifiDetailState', 0, async () => {
      await executeApiTestCaseById('WF_CB_01802');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01803
     * @tc.name WF_CB_01803_wifi_getWifiDetailState
     * @tc.desc combo flow#1 var#1 -> getWifiDetailState
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01803_wifi_getWifiDetailState', 0, async () => {
      await executeApiTestCaseById('WF_CB_01803');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01804
     * @tc.name WF_CB_01804_wifi_getWifiDetailState
     * @tc.desc combo flow#1 var#2 -> getWifiDetailState
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01804_wifi_getWifiDetailState', 0, async () => {
      await executeApiTestCaseById('WF_CB_01804');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01805
     * @tc.name WF_CB_01805_wifi_getWifiDetailState
     * @tc.desc combo flow#1 var#3 -> getWifiDetailState
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01805_wifi_getWifiDetailState', 0, async () => {
      await executeApiTestCaseById('WF_CB_01805');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01806
     * @tc.name WF_CB_01806_wifi_getWifiDetailState
     * @tc.desc combo flow#1 var#4 -> getWifiDetailState
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01806_wifi_getWifiDetailState', 0, async () => {
      await executeApiTestCaseById('WF_CB_01806');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01807
     * @tc.name WF_CB_01807_wifi_getWifiDetailState
     * @tc.desc combo flow#1 var#5 -> getWifiDetailState
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01807_wifi_getWifiDetailState', 0, async () => {
      await executeApiTestCaseById('WF_CB_01807');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01808
     * @tc.name WF_CB_01808_wifi_getWifiDetailState
     * @tc.desc combo flow#1 var#6 -> getWifiDetailState
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01808_wifi_getWifiDetailState', 0, async () => {
      await executeApiTestCaseById('WF_CB_01808');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01809
     * @tc.name WF_CB_01809_wifi_getWifiDetailState
     * @tc.desc combo flow#1 var#7 -> getWifiDetailState
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01809_wifi_getWifiDetailState', 0, async () => {
      await executeApiTestCaseById('WF_CB_01809');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01810
     * @tc.name WF_CB_01810_wifi_getCountryCode
     * @tc.desc combo flow#2 var#0 -> getCountryCode
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01810_wifi_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WF_CB_01810');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01811
     * @tc.name WF_CB_01811_wifi_getCountryCode
     * @tc.desc combo flow#2 var#1 -> getCountryCode
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01811_wifi_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WF_CB_01811');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01812
     * @tc.name WF_CB_01812_wifi_getCountryCode
     * @tc.desc combo flow#2 var#2 -> getCountryCode
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01812_wifi_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WF_CB_01812');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01813
     * @tc.name WF_CB_01813_wifi_getCountryCode
     * @tc.desc combo flow#2 var#3 -> getCountryCode
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01813_wifi_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WF_CB_01813');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01814
     * @tc.name WF_CB_01814_wifi_getCountryCode
     * @tc.desc combo flow#2 var#4 -> getCountryCode
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01814_wifi_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WF_CB_01814');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01815
     * @tc.name WF_CB_01815_wifi_getCountryCode
     * @tc.desc combo flow#2 var#5 -> getCountryCode
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01815_wifi_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WF_CB_01815');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01816
     * @tc.name WF_CB_01816_wifi_getCountryCode
     * @tc.desc combo flow#2 var#6 -> getCountryCode
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01816_wifi_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WF_CB_01816');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01817
     * @tc.name WF_CB_01817_wifi_getCountryCode
     * @tc.desc combo flow#2 var#7 -> getCountryCode
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01817_wifi_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WF_CB_01817');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01818
     * @tc.name WF_CB_01818_wifi_getIpv6Info
     * @tc.desc combo flow#3 var#0 -> getIpv6Info
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01818_wifi_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WF_CB_01818');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01819
     * @tc.name WF_CB_01819_wifi_getIpv6Info
     * @tc.desc combo flow#3 var#1 -> getIpv6Info
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01819_wifi_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WF_CB_01819');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01820
     * @tc.name WF_CB_01820_wifi_getIpv6Info
     * @tc.desc combo flow#3 var#2 -> getIpv6Info
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01820_wifi_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WF_CB_01820');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01821
     * @tc.name WF_CB_01821_wifi_getIpv6Info
     * @tc.desc combo flow#3 var#3 -> getIpv6Info
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01821_wifi_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WF_CB_01821');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01822
     * @tc.name WF_CB_01822_wifi_getIpv6Info
     * @tc.desc combo flow#3 var#4 -> getIpv6Info
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01822_wifi_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WF_CB_01822');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01823
     * @tc.name WF_CB_01823_wifi_getIpv6Info
     * @tc.desc combo flow#3 var#5 -> getIpv6Info
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01823_wifi_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WF_CB_01823');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01824
     * @tc.name WF_CB_01824_wifi_getIpv6Info
     * @tc.desc combo flow#3 var#6 -> getIpv6Info
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01824_wifi_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WF_CB_01824');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01825
     * @tc.name WF_CB_01825_wifi_getIpv6Info
     * @tc.desc combo flow#3 var#7 -> getIpv6Info
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01825_wifi_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WF_CB_01825');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01826
     * @tc.name WF_CB_01826_wifi_getDisconnectedReason
     * @tc.desc combo flow#4 var#0 -> getDisconnectedReason
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01826_wifi_getDisconnectedReason', 0, async () => {
      await executeApiTestCaseById('WF_CB_01826');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01827
     * @tc.name WF_CB_01827_wifi_getDisconnectedReason
     * @tc.desc combo flow#4 var#1 -> getDisconnectedReason
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01827_wifi_getDisconnectedReason', 0, async () => {
      await executeApiTestCaseById('WF_CB_01827');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01828
     * @tc.name WF_CB_01828_wifi_getDisconnectedReason
     * @tc.desc combo flow#4 var#2 -> getDisconnectedReason
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01828_wifi_getDisconnectedReason', 0, async () => {
      await executeApiTestCaseById('WF_CB_01828');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01829
     * @tc.name WF_CB_01829_wifi_getDisconnectedReason
     * @tc.desc combo flow#4 var#3 -> getDisconnectedReason
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01829_wifi_getDisconnectedReason', 0, async () => {
      await executeApiTestCaseById('WF_CB_01829');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01830
     * @tc.name WF_CB_01830_wifi_getDisconnectedReason
     * @tc.desc combo flow#4 var#4 -> getDisconnectedReason
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01830_wifi_getDisconnectedReason', 0, async () => {
      await executeApiTestCaseById('WF_CB_01830');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01831
     * @tc.name WF_CB_01831_wifi_getDisconnectedReason
     * @tc.desc combo flow#4 var#5 -> getDisconnectedReason
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01831_wifi_getDisconnectedReason', 0, async () => {
      await executeApiTestCaseById('WF_CB_01831');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01832
     * @tc.name WF_CB_01832_wifi_getDisconnectedReason
     * @tc.desc combo flow#4 var#6 -> getDisconnectedReason
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01832_wifi_getDisconnectedReason', 0, async () => {
      await executeApiTestCaseById('WF_CB_01832');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01833
     * @tc.name WF_CB_01833_wifi_getDisconnectedReason
     * @tc.desc combo flow#4 var#7 -> getDisconnectedReason
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01833_wifi_getDisconnectedReason', 0, async () => {
      await executeApiTestCaseById('WF_CB_01833');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01834
     * @tc.name WF_CB_01834_wifi_getScanAlwaysAllowed
     * @tc.desc combo flow#5 var#0 -> getScanAlwaysAllowed
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01834_wifi_getScanAlwaysAllowed', 0, async () => {
      await executeApiTestCaseById('WF_CB_01834');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01835
     * @tc.name WF_CB_01835_wifi_getScanAlwaysAllowed
     * @tc.desc combo flow#5 var#1 -> getScanAlwaysAllowed
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01835_wifi_getScanAlwaysAllowed', 0, async () => {
      await executeApiTestCaseById('WF_CB_01835');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01836
     * @tc.name WF_CB_01836_wifi_getScanAlwaysAllowed
     * @tc.desc combo flow#5 var#2 -> getScanAlwaysAllowed
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01836_wifi_getScanAlwaysAllowed', 0, async () => {
      await executeApiTestCaseById('WF_CB_01836');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01837
     * @tc.name WF_CB_01837_wifi_getScanAlwaysAllowed
     * @tc.desc combo flow#5 var#3 -> getScanAlwaysAllowed
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01837_wifi_getScanAlwaysAllowed', 0, async () => {
      await executeApiTestCaseById('WF_CB_01837');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01838
     * @tc.name WF_CB_01838_wifi_getScanAlwaysAllowed
     * @tc.desc combo flow#5 var#4 -> getScanAlwaysAllowed
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01838_wifi_getScanAlwaysAllowed', 0, async () => {
      await executeApiTestCaseById('WF_CB_01838');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01839
     * @tc.name WF_CB_01839_wifi_getScanAlwaysAllowed
     * @tc.desc combo flow#5 var#5 -> getScanAlwaysAllowed
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01839_wifi_getScanAlwaysAllowed', 0, async () => {
      await executeApiTestCaseById('WF_CB_01839');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01840
     * @tc.name WF_CB_01840_wifi_getScanAlwaysAllowed
     * @tc.desc combo flow#5 var#6 -> getScanAlwaysAllowed
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01840_wifi_getScanAlwaysAllowed', 0, async () => {
      await executeApiTestCaseById('WF_CB_01840');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01841
     * @tc.name WF_CB_01841_wifi_getScanAlwaysAllowed
     * @tc.desc combo flow#5 var#7 -> getScanAlwaysAllowed
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01841_wifi_getScanAlwaysAllowed', 0, async () => {
      await executeApiTestCaseById('WF_CB_01841');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01842
     * @tc.name WF_CB_01842_wifi_startScan
     * @tc.desc combo flow#6 var#0 -> startScan
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01842_wifi_startScan', 0, async () => {
      await executeApiTestCaseById('WF_CB_01842');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01843
     * @tc.name WF_CB_01843_wifi_startScan
     * @tc.desc combo flow#6 var#1 -> startScan
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01843_wifi_startScan', 0, async () => {
      await executeApiTestCaseById('WF_CB_01843');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01844
     * @tc.name WF_CB_01844_wifi_startScan
     * @tc.desc combo flow#6 var#2 -> startScan
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01844_wifi_startScan', 0, async () => {
      await executeApiTestCaseById('WF_CB_01844');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01845
     * @tc.name WF_CB_01845_wifi_startScan
     * @tc.desc combo flow#6 var#3 -> startScan
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01845_wifi_startScan', 0, async () => {
      await executeApiTestCaseById('WF_CB_01845');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01846
     * @tc.name WF_CB_01846_wifi_startScan
     * @tc.desc combo flow#6 var#4 -> startScan
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01846_wifi_startScan', 0, async () => {
      await executeApiTestCaseById('WF_CB_01846');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01847
     * @tc.name WF_CB_01847_wifi_startScan
     * @tc.desc combo flow#6 var#5 -> startScan
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01847_wifi_startScan', 0, async () => {
      await executeApiTestCaseById('WF_CB_01847');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01848
     * @tc.name WF_CB_01848_wifi_startScan
     * @tc.desc combo flow#6 var#6 -> startScan
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01848_wifi_startScan', 0, async () => {
      await executeApiTestCaseById('WF_CB_01848');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01849
     * @tc.name WF_CB_01849_wifi_startScan
     * @tc.desc combo flow#6 var#7 -> startScan
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01849_wifi_startScan', 0, async () => {
      await executeApiTestCaseById('WF_CB_01849');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01850
     * @tc.name WF_CB_01850_wifi_getSignalLevel
     * @tc.desc combo flow#7 var#0 -> getSignalLevel
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01850_wifi_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WF_CB_01850');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01851
     * @tc.name WF_CB_01851_wifi_getSignalLevel
     * @tc.desc combo flow#7 var#1 -> getSignalLevel
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01851_wifi_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WF_CB_01851');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01852
     * @tc.name WF_CB_01852_wifi_getSignalLevel
     * @tc.desc combo flow#7 var#2 -> getSignalLevel
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01852_wifi_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WF_CB_01852');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01853
     * @tc.name WF_CB_01853_wifi_getSignalLevel
     * @tc.desc combo flow#7 var#3 -> getSignalLevel
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01853_wifi_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WF_CB_01853');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01854
     * @tc.name WF_CB_01854_wifi_getSignalLevel
     * @tc.desc combo flow#7 var#4 -> getSignalLevel
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01854_wifi_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WF_CB_01854');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01855
     * @tc.name WF_CB_01855_wifi_getSignalLevel
     * @tc.desc combo flow#7 var#5 -> getSignalLevel
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01855_wifi_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WF_CB_01855');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01856
     * @tc.name WF_CB_01856_wifi_getSignalLevel
     * @tc.desc combo flow#7 var#6 -> getSignalLevel
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01856_wifi_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WF_CB_01856');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01857
     * @tc.name WF_CB_01857_wifi_getSignalLevel
     * @tc.desc combo flow#7 var#7 -> getSignalLevel
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01857_wifi_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WF_CB_01857');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01858
     * @tc.name WF_CB_01858_wifi_isBandTypeSupported
     * @tc.desc combo flow#8 var#0 -> isBandTypeSupported
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01858_wifi_isBandTypeSupported', 0, async () => {
      await executeApiTestCaseById('WF_CB_01858');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01859
     * @tc.name WF_CB_01859_wifi_isBandTypeSupported
     * @tc.desc combo flow#8 var#1 -> isBandTypeSupported
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01859_wifi_isBandTypeSupported', 0, async () => {
      await executeApiTestCaseById('WF_CB_01859');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01860
     * @tc.name WF_CB_01860_wifi_isBandTypeSupported
     * @tc.desc combo flow#8 var#2 -> isBandTypeSupported
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01860_wifi_isBandTypeSupported', 0, async () => {
      await executeApiTestCaseById('WF_CB_01860');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01861
     * @tc.name WF_CB_01861_wifi_isBandTypeSupported
     * @tc.desc combo flow#8 var#3 -> isBandTypeSupported
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01861_wifi_isBandTypeSupported', 0, async () => {
      await executeApiTestCaseById('WF_CB_01861');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01862
     * @tc.name WF_CB_01862_wifi_isBandTypeSupported
     * @tc.desc combo flow#8 var#4 -> isBandTypeSupported
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01862_wifi_isBandTypeSupported', 0, async () => {
      await executeApiTestCaseById('WF_CB_01862');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01863
     * @tc.name WF_CB_01863_wifi_isBandTypeSupported
     * @tc.desc combo flow#8 var#5 -> isBandTypeSupported
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01863_wifi_isBandTypeSupported', 0, async () => {
      await executeApiTestCaseById('WF_CB_01863');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01864
     * @tc.name WF_CB_01864_wifi_isBandTypeSupported
     * @tc.desc combo flow#8 var#6 -> isBandTypeSupported
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01864_wifi_isBandTypeSupported', 0, async () => {
      await executeApiTestCaseById('WF_CB_01864');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01865
     * @tc.name WF_CB_01865_wifi_isBandTypeSupported
     * @tc.desc combo flow#8 var#7 -> isBandTypeSupported
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01865_wifi_isBandTypeSupported', 0, async () => {
      await executeApiTestCaseById('WF_CB_01865');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01866
     * @tc.name WF_CB_01866_wifi_isWifiActive
     * @tc.desc combo flow#9 var#0 -> isWifiActive
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01866_wifi_isWifiActive', 0, async () => {
      await executeApiTestCaseById('WF_CB_01866');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01867
     * @tc.name WF_CB_01867_wifi_isWifiActive
     * @tc.desc combo flow#9 var#1 -> isWifiActive
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01867_wifi_isWifiActive', 0, async () => {
      await executeApiTestCaseById('WF_CB_01867');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01868
     * @tc.name WF_CB_01868_wifi_isWifiActive
     * @tc.desc combo flow#9 var#2 -> isWifiActive
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01868_wifi_isWifiActive', 0, async () => {
      await executeApiTestCaseById('WF_CB_01868');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01869
     * @tc.name WF_CB_01869_wifi_isWifiActive
     * @tc.desc combo flow#9 var#3 -> isWifiActive
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01869_wifi_isWifiActive', 0, async () => {
      await executeApiTestCaseById('WF_CB_01869');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01870
     * @tc.name WF_CB_01870_wifi_isWifiActive
     * @tc.desc combo flow#9 var#4 -> isWifiActive
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01870_wifi_isWifiActive', 0, async () => {
      await executeApiTestCaseById('WF_CB_01870');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01871
     * @tc.name WF_CB_01871_wifi_isWifiActive
     * @tc.desc combo flow#9 var#5 -> isWifiActive
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01871_wifi_isWifiActive', 0, async () => {
      await executeApiTestCaseById('WF_CB_01871');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01872
     * @tc.name WF_CB_01872_wifi_isWifiActive
     * @tc.desc combo flow#9 var#6 -> isWifiActive
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01872_wifi_isWifiActive', 0, async () => {
      await executeApiTestCaseById('WF_CB_01872');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01873
     * @tc.name WF_CB_01873_wifi_isWifiActive
     * @tc.desc combo flow#9 var#7 -> isWifiActive
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01873_wifi_isWifiActive', 0, async () => {
      await executeApiTestCaseById('WF_CB_01873');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01874
     * @tc.name WF_CB_01874_wifi_getHotspotConfig
     * @tc.desc combo flow#10 var#0 -> getHotspotConfig
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01874_wifi_getHotspotConfig', 0, async () => {
      await executeApiTestCaseById('WF_CB_01874');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01875
     * @tc.name WF_CB_01875_wifi_getHotspotConfig
     * @tc.desc combo flow#10 var#1 -> getHotspotConfig
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01875_wifi_getHotspotConfig', 0, async () => {
      await executeApiTestCaseById('WF_CB_01875');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01876
     * @tc.name WF_CB_01876_wifi_getHotspotConfig
     * @tc.desc combo flow#10 var#2 -> getHotspotConfig
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01876_wifi_getHotspotConfig', 0, async () => {
      await executeApiTestCaseById('WF_CB_01876');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01877
     * @tc.name WF_CB_01877_wifi_getHotspotConfig
     * @tc.desc combo flow#10 var#3 -> getHotspotConfig
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01877_wifi_getHotspotConfig', 0, async () => {
      await executeApiTestCaseById('WF_CB_01877');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01878
     * @tc.name WF_CB_01878_wifi_getHotspotConfig
     * @tc.desc combo flow#10 var#4 -> getHotspotConfig
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01878_wifi_getHotspotConfig', 0, async () => {
      await executeApiTestCaseById('WF_CB_01878');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01879
     * @tc.name WF_CB_01879_wifi_getHotspotConfig
     * @tc.desc combo flow#10 var#5 -> getHotspotConfig
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01879_wifi_getHotspotConfig', 0, async () => {
      await executeApiTestCaseById('WF_CB_01879');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01880
     * @tc.name WF_CB_01880_wifi_getHotspotConfig
     * @tc.desc combo flow#10 var#6 -> getHotspotConfig
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01880_wifi_getHotspotConfig', 0, async () => {
      await executeApiTestCaseById('WF_CB_01880');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01881
     * @tc.name WF_CB_01881_wifi_getHotspotConfig
     * @tc.desc combo flow#10 var#7 -> getHotspotConfig
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01881_wifi_getHotspotConfig', 0, async () => {
      await executeApiTestCaseById('WF_CB_01881');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01882
     * @tc.name WF_CB_01882_wifi_disableHotspot
     * @tc.desc combo flow#11 var#0 -> disableHotspot
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01882_wifi_disableHotspot', 0, async () => {
      await executeApiTestCaseById('WF_CB_01882');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01883
     * @tc.name WF_CB_01883_wifi_disableHotspot
     * @tc.desc combo flow#11 var#1 -> disableHotspot
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01883_wifi_disableHotspot', 0, async () => {
      await executeApiTestCaseById('WF_CB_01883');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01884
     * @tc.name WF_CB_01884_wifi_disableHotspot
     * @tc.desc combo flow#11 var#2 -> disableHotspot
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01884_wifi_disableHotspot', 0, async () => {
      await executeApiTestCaseById('WF_CB_01884');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01885
     * @tc.name WF_CB_01885_wifi_disableHotspot
     * @tc.desc combo flow#11 var#3 -> disableHotspot
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01885_wifi_disableHotspot', 0, async () => {
      await executeApiTestCaseById('WF_CB_01885');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_CB_01886
     * @tc.name WF_CB_01886_wifi_disableHotspot
     * @tc.desc combo flow#11 var#4 -> disableHotspot
     * @tc.size LargeTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('WF_CB_01886_wifi_disableHotspot', 0, async () => {
      await executeApiTestCaseById('WF_CB_01886');
    });

}
