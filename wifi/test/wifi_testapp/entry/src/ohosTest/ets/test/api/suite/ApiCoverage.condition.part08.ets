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

/** 注册 Api_Condition_Coverage 分片 part08（须在 describe 内调用） */
export function register_condition_part08(): void {
    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01774
     * @tc.name WF_C_01774_wifi_getP2pPeerDevices
     * @tc.desc wifi.getP2pPeerDevices condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01774_wifi_getP2pPeerDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01774');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01775
     * @tc.name WF_C_01775_wifi_getP2pPeerDevices
     * @tc.desc wifi.getP2pPeerDevices condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01775_wifi_getP2pPeerDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01775');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01776
     * @tc.name WF_C_01776_wifi_getP2pPeerDevices
     * @tc.desc wifi.getP2pPeerDevices condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01776_wifi_getP2pPeerDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01776');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01777
     * @tc.name WF_C_01777_wifi_getP2pPeerDevices
     * @tc.desc wifi.getP2pPeerDevices condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01777_wifi_getP2pPeerDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01777');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01778
     * @tc.name WF_C_01778_wifi_startDiscoverDevices
     * @tc.desc wifi.startDiscoverDevices condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01778_wifi_startDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01778');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01779
     * @tc.name WF_C_01779_wifi_startDiscoverDevices
     * @tc.desc wifi.startDiscoverDevices condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01779_wifi_startDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01779');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01780
     * @tc.name WF_C_01780_wifi_startDiscoverDevices
     * @tc.desc wifi.startDiscoverDevices condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01780_wifi_startDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01780');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01781
     * @tc.name WF_C_01781_wifi_startDiscoverDevices
     * @tc.desc wifi.startDiscoverDevices condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01781_wifi_startDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01781');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01782
     * @tc.name WF_C_01782_wifi_startDiscoverDevices
     * @tc.desc wifi.startDiscoverDevices condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01782_wifi_startDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01782');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01783
     * @tc.name WF_C_01783_wifi_startDiscoverDevices
     * @tc.desc wifi.startDiscoverDevices condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01783_wifi_startDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01783');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01784
     * @tc.name WF_C_01784_wifi_startDiscoverDevices
     * @tc.desc wifi.startDiscoverDevices condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01784_wifi_startDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01784');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01785
     * @tc.name WF_C_01785_wifi_startDiscoverDevices
     * @tc.desc wifi.startDiscoverDevices condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01785_wifi_startDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01785');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01786
     * @tc.name WF_C_01786_wifi_stopDiscoverDevices
     * @tc.desc wifi.stopDiscoverDevices condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01786_wifi_stopDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01786');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01787
     * @tc.name WF_C_01787_wifi_stopDiscoverDevices
     * @tc.desc wifi.stopDiscoverDevices condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01787_wifi_stopDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01787');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01788
     * @tc.name WF_C_01788_wifi_stopDiscoverDevices
     * @tc.desc wifi.stopDiscoverDevices condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01788_wifi_stopDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01788');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01789
     * @tc.name WF_C_01789_wifi_stopDiscoverDevices
     * @tc.desc wifi.stopDiscoverDevices condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01789_wifi_stopDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01789');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01790
     * @tc.name WF_C_01790_wifi_stopDiscoverDevices
     * @tc.desc wifi.stopDiscoverDevices condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01790_wifi_stopDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01790');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01791
     * @tc.name WF_C_01791_wifi_stopDiscoverDevices
     * @tc.desc wifi.stopDiscoverDevices condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01791_wifi_stopDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01791');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01792
     * @tc.name WF_C_01792_wifi_stopDiscoverDevices
     * @tc.desc wifi.stopDiscoverDevices condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01792_wifi_stopDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01792');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WF_C_01793
     * @tc.name WF_C_01793_wifi_stopDiscoverDevices
     * @tc.desc wifi.stopDiscoverDevices condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WF_C_01793_wifi_stopDiscoverDevices', 0, async () => {
      await executeApiTestCaseById('WF_C_01793');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_01991
     * @tc.name LE_C_01991_linkEnhance_createServer
     * @tc.desc linkEnhance.createServer condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_01991_linkEnhance_createServer', 0, async () => {
      await executeApiTestCaseById('LE_C_01991');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_01992
     * @tc.name LE_C_01992_linkEnhance_createServer
     * @tc.desc linkEnhance.createServer condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_01992_linkEnhance_createServer', 0, async () => {
      await executeApiTestCaseById('LE_C_01992');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_01993
     * @tc.name LE_C_01993_linkEnhance_createServer
     * @tc.desc linkEnhance.createServer condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_01993_linkEnhance_createServer', 0, async () => {
      await executeApiTestCaseById('LE_C_01993');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_01994
     * @tc.name LE_C_01994_linkEnhance_createServer
     * @tc.desc linkEnhance.createServer condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_01994_linkEnhance_createServer', 0, async () => {
      await executeApiTestCaseById('LE_C_01994');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_01995
     * @tc.name LE_C_01995_linkEnhance_createServer
     * @tc.desc linkEnhance.createServer condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_01995_linkEnhance_createServer', 0, async () => {
      await executeApiTestCaseById('LE_C_01995');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_01996
     * @tc.name LE_C_01996_linkEnhance_createServer
     * @tc.desc linkEnhance.createServer condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_01996_linkEnhance_createServer', 0, async () => {
      await executeApiTestCaseById('LE_C_01996');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_01997
     * @tc.name LE_C_01997_linkEnhance_createServer
     * @tc.desc linkEnhance.createServer condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_01997_linkEnhance_createServer', 0, async () => {
      await executeApiTestCaseById('LE_C_01997');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_01998
     * @tc.name LE_C_01998_linkEnhance_createServer
     * @tc.desc linkEnhance.createServer condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_01998_linkEnhance_createServer', 0, async () => {
      await executeApiTestCaseById('LE_C_01998');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_01999
     * @tc.name LE_C_01999_linkEnhance_createConnection
     * @tc.desc linkEnhance.createConnection condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_01999_linkEnhance_createConnection', 0, async () => {
      await executeApiTestCaseById('LE_C_01999');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_02000
     * @tc.name LE_C_02000_linkEnhance_createConnection
     * @tc.desc linkEnhance.createConnection condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_02000_linkEnhance_createConnection', 0, async () => {
      await executeApiTestCaseById('LE_C_02000');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_02001
     * @tc.name LE_C_02001_linkEnhance_createConnection
     * @tc.desc linkEnhance.createConnection condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_02001_linkEnhance_createConnection', 0, async () => {
      await executeApiTestCaseById('LE_C_02001');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_02002
     * @tc.name LE_C_02002_linkEnhance_createConnection
     * @tc.desc linkEnhance.createConnection condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_02002_linkEnhance_createConnection', 0, async () => {
      await executeApiTestCaseById('LE_C_02002');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_02003
     * @tc.name LE_C_02003_linkEnhance_createConnection
     * @tc.desc linkEnhance.createConnection condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_02003_linkEnhance_createConnection', 0, async () => {
      await executeApiTestCaseById('LE_C_02003');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_02004
     * @tc.name LE_C_02004_linkEnhance_createConnection
     * @tc.desc linkEnhance.createConnection condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_02004_linkEnhance_createConnection', 0, async () => {
      await executeApiTestCaseById('LE_C_02004');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_02005
     * @tc.name LE_C_02005_linkEnhance_createConnection
     * @tc.desc linkEnhance.createConnection condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_02005_linkEnhance_createConnection', 0, async () => {
      await executeApiTestCaseById('LE_C_02005');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_LE_C_02006
     * @tc.name LE_C_02006_linkEnhance_createConnection
     * @tc.desc linkEnhance.createConnection condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('LE_C_02006_linkEnhance_createConnection', 0, async () => {
      await executeApiTestCaseById('LE_C_02006');
    });

}
