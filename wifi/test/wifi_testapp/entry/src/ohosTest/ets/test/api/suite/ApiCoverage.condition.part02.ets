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

/** 注册 Api_Condition_Coverage 分片 part02（须在 describe 内调用） */
export function register_condition_part02(): void {
    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00436
     * @tc.name WM_C_00436_wifiManager_connectToNetwork
     * @tc.desc wifiManager.connectToNetwork condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00436_wifiManager_connectToNetwork', 0, async () => {
      await executeApiTestCaseById('WM_C_00436');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00437
     * @tc.name WM_C_00437_wifiManager_connectToNetwork
     * @tc.desc wifiManager.connectToNetwork condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00437_wifiManager_connectToNetwork', 0, async () => {
      await executeApiTestCaseById('WM_C_00437');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00438
     * @tc.name WM_C_00438_wifiManager_connectToNetwork
     * @tc.desc wifiManager.connectToNetwork condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00438_wifiManager_connectToNetwork', 0, async () => {
      await executeApiTestCaseById('WM_C_00438');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00439
     * @tc.name WM_C_00439_wifiManager_connectToNetwork
     * @tc.desc wifiManager.connectToNetwork condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00439_wifiManager_connectToNetwork', 0, async () => {
      await executeApiTestCaseById('WM_C_00439');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00440
     * @tc.name WM_C_00440_wifiManager_disconnect
     * @tc.desc wifiManager.disconnect condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00440_wifiManager_disconnect', 0, async () => {
      await executeApiTestCaseById('WM_C_00440');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00441
     * @tc.name WM_C_00441_wifiManager_disconnect
     * @tc.desc wifiManager.disconnect condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00441_wifiManager_disconnect', 0, async () => {
      await executeApiTestCaseById('WM_C_00441');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00442
     * @tc.name WM_C_00442_wifiManager_disconnect
     * @tc.desc wifiManager.disconnect condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00442_wifiManager_disconnect', 0, async () => {
      await executeApiTestCaseById('WM_C_00442');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00443
     * @tc.name WM_C_00443_wifiManager_disconnect
     * @tc.desc wifiManager.disconnect condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00443_wifiManager_disconnect', 0, async () => {
      await executeApiTestCaseById('WM_C_00443');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00444
     * @tc.name WM_C_00444_wifiManager_disconnect
     * @tc.desc wifiManager.disconnect condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00444_wifiManager_disconnect', 0, async () => {
      await executeApiTestCaseById('WM_C_00444');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00445
     * @tc.name WM_C_00445_wifiManager_disconnect
     * @tc.desc wifiManager.disconnect condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00445_wifiManager_disconnect', 0, async () => {
      await executeApiTestCaseById('WM_C_00445');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00446
     * @tc.name WM_C_00446_wifiManager_disconnect
     * @tc.desc wifiManager.disconnect condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00446_wifiManager_disconnect', 0, async () => {
      await executeApiTestCaseById('WM_C_00446');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00447
     * @tc.name WM_C_00447_wifiManager_disconnect
     * @tc.desc wifiManager.disconnect condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00447_wifiManager_disconnect', 0, async () => {
      await executeApiTestCaseById('WM_C_00447');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00448
     * @tc.name WM_C_00448_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00448_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_C_00448');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00449
     * @tc.name WM_C_00449_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00449_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_C_00449');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00450
     * @tc.name WM_C_00450_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00450_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_C_00450');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00451
     * @tc.name WM_C_00451_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00451_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_C_00451');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00452
     * @tc.name WM_C_00452_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00452_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_C_00452');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00453
     * @tc.name WM_C_00453_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00453_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_C_00453');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00454
     * @tc.name WM_C_00454_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00454_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_C_00454');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00455
     * @tc.name WM_C_00455_wifiManager_getSignalLevel
     * @tc.desc wifiManager.getSignalLevel condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00455_wifiManager_getSignalLevel', 0, async () => {
      await executeApiTestCaseById('WM_C_00455');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00456
     * @tc.name WM_C_00456_wifiManager_getLinkedInfoSync
     * @tc.desc wifiManager.getLinkedInfoSync condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00456_wifiManager_getLinkedInfoSync', 0, async () => {
      await executeApiTestCaseById('WM_C_00456');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00457
     * @tc.name WM_C_00457_wifiManager_getLinkedInfoSync
     * @tc.desc wifiManager.getLinkedInfoSync condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00457_wifiManager_getLinkedInfoSync', 0, async () => {
      await executeApiTestCaseById('WM_C_00457');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00458
     * @tc.name WM_C_00458_wifiManager_getLinkedInfoSync
     * @tc.desc wifiManager.getLinkedInfoSync condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00458_wifiManager_getLinkedInfoSync', 0, async () => {
      await executeApiTestCaseById('WM_C_00458');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00459
     * @tc.name WM_C_00459_wifiManager_getLinkedInfoSync
     * @tc.desc wifiManager.getLinkedInfoSync condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00459_wifiManager_getLinkedInfoSync', 0, async () => {
      await executeApiTestCaseById('WM_C_00459');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00460
     * @tc.name WM_C_00460_wifiManager_getLinkedInfoSync
     * @tc.desc wifiManager.getLinkedInfoSync condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00460_wifiManager_getLinkedInfoSync', 0, async () => {
      await executeApiTestCaseById('WM_C_00460');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00461
     * @tc.name WM_C_00461_wifiManager_getLinkedInfoSync
     * @tc.desc wifiManager.getLinkedInfoSync condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00461_wifiManager_getLinkedInfoSync', 0, async () => {
      await executeApiTestCaseById('WM_C_00461');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00462
     * @tc.name WM_C_00462_wifiManager_getLinkedInfoSync
     * @tc.desc wifiManager.getLinkedInfoSync condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00462_wifiManager_getLinkedInfoSync', 0, async () => {
      await executeApiTestCaseById('WM_C_00462');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00463
     * @tc.name WM_C_00463_wifiManager_getLinkedInfoSync
     * @tc.desc wifiManager.getLinkedInfoSync condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00463_wifiManager_getLinkedInfoSync', 0, async () => {
      await executeApiTestCaseById('WM_C_00463');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00464
     * @tc.name WM_C_00464_wifiManager_getMultiLinkedInfo
     * @tc.desc wifiManager.getMultiLinkedInfo condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00464_wifiManager_getMultiLinkedInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00464');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00465
     * @tc.name WM_C_00465_wifiManager_getMultiLinkedInfo
     * @tc.desc wifiManager.getMultiLinkedInfo condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00465_wifiManager_getMultiLinkedInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00465');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00466
     * @tc.name WM_C_00466_wifiManager_getMultiLinkedInfo
     * @tc.desc wifiManager.getMultiLinkedInfo condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00466_wifiManager_getMultiLinkedInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00466');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00467
     * @tc.name WM_C_00467_wifiManager_getMultiLinkedInfo
     * @tc.desc wifiManager.getMultiLinkedInfo condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00467_wifiManager_getMultiLinkedInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00467');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00468
     * @tc.name WM_C_00468_wifiManager_getMultiLinkedInfo
     * @tc.desc wifiManager.getMultiLinkedInfo condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00468_wifiManager_getMultiLinkedInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00468');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00469
     * @tc.name WM_C_00469_wifiManager_getMultiLinkedInfo
     * @tc.desc wifiManager.getMultiLinkedInfo condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00469_wifiManager_getMultiLinkedInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00469');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00470
     * @tc.name WM_C_00470_wifiManager_getMultiLinkedInfo
     * @tc.desc wifiManager.getMultiLinkedInfo condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00470_wifiManager_getMultiLinkedInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00470');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00471
     * @tc.name WM_C_00471_wifiManager_getMultiLinkedInfo
     * @tc.desc wifiManager.getMultiLinkedInfo condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00471_wifiManager_getMultiLinkedInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00471');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00472
     * @tc.name WM_C_00472_wifiManager_isConnected
     * @tc.desc wifiManager.isConnected condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00472_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_C_00472');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00473
     * @tc.name WM_C_00473_wifiManager_isConnected
     * @tc.desc wifiManager.isConnected condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00473_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_C_00473');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00474
     * @tc.name WM_C_00474_wifiManager_isConnected
     * @tc.desc wifiManager.isConnected condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00474_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_C_00474');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00475
     * @tc.name WM_C_00475_wifiManager_isConnected
     * @tc.desc wifiManager.isConnected condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00475_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_C_00475');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00476
     * @tc.name WM_C_00476_wifiManager_isConnected
     * @tc.desc wifiManager.isConnected condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00476_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_C_00476');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00477
     * @tc.name WM_C_00477_wifiManager_isConnected
     * @tc.desc wifiManager.isConnected condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00477_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_C_00477');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00478
     * @tc.name WM_C_00478_wifiManager_isConnected
     * @tc.desc wifiManager.isConnected condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00478_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_C_00478');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00479
     * @tc.name WM_C_00479_wifiManager_isConnected
     * @tc.desc wifiManager.isConnected condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00479_wifiManager_isConnected', 0, async () => {
      await executeApiTestCaseById('WM_C_00479');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00480
     * @tc.name WM_C_00480_wifiManager_getSupportedFeatures
     * @tc.desc wifiManager.getSupportedFeatures condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00480_wifiManager_getSupportedFeatures', 0, async () => {
      await executeApiTestCaseById('WM_C_00480');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00481
     * @tc.name WM_C_00481_wifiManager_getSupportedFeatures
     * @tc.desc wifiManager.getSupportedFeatures condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00481_wifiManager_getSupportedFeatures', 0, async () => {
      await executeApiTestCaseById('WM_C_00481');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00482
     * @tc.name WM_C_00482_wifiManager_getSupportedFeatures
     * @tc.desc wifiManager.getSupportedFeatures condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00482_wifiManager_getSupportedFeatures', 0, async () => {
      await executeApiTestCaseById('WM_C_00482');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00483
     * @tc.name WM_C_00483_wifiManager_getSupportedFeatures
     * @tc.desc wifiManager.getSupportedFeatures condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00483_wifiManager_getSupportedFeatures', 0, async () => {
      await executeApiTestCaseById('WM_C_00483');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00484
     * @tc.name WM_C_00484_wifiManager_getSupportedFeatures
     * @tc.desc wifiManager.getSupportedFeatures condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00484_wifiManager_getSupportedFeatures', 0, async () => {
      await executeApiTestCaseById('WM_C_00484');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00485
     * @tc.name WM_C_00485_wifiManager_getSupportedFeatures
     * @tc.desc wifiManager.getSupportedFeatures condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00485_wifiManager_getSupportedFeatures', 0, async () => {
      await executeApiTestCaseById('WM_C_00485');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00486
     * @tc.name WM_C_00486_wifiManager_getSupportedFeatures
     * @tc.desc wifiManager.getSupportedFeatures condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00486_wifiManager_getSupportedFeatures', 0, async () => {
      await executeApiTestCaseById('WM_C_00486');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00487
     * @tc.name WM_C_00487_wifiManager_getSupportedFeatures
     * @tc.desc wifiManager.getSupportedFeatures condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00487_wifiManager_getSupportedFeatures', 0, async () => {
      await executeApiTestCaseById('WM_C_00487');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00488
     * @tc.name WM_C_00488_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00488_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_C_00488');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00489
     * @tc.name WM_C_00489_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00489_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_C_00489');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00490
     * @tc.name WM_C_00490_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00490_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_C_00490');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00491
     * @tc.name WM_C_00491_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00491_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_C_00491');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00492
     * @tc.name WM_C_00492_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00492_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_C_00492');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00493
     * @tc.name WM_C_00493_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00493_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_C_00493');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00494
     * @tc.name WM_C_00494_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00494_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_C_00494');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00495
     * @tc.name WM_C_00495_wifiManager_isFeatureSupported
     * @tc.desc wifiManager.isFeatureSupported condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00495_wifiManager_isFeatureSupported', 0, async () => {
      await executeApiTestCaseById('WM_C_00495');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00496
     * @tc.name WM_C_00496_wifiManager_getDeviceMacAddress
     * @tc.desc wifiManager.getDeviceMacAddress condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00496_wifiManager_getDeviceMacAddress', 0, async () => {
      await executeApiTestCaseById('WM_C_00496');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00497
     * @tc.name WM_C_00497_wifiManager_getDeviceMacAddress
     * @tc.desc wifiManager.getDeviceMacAddress condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00497_wifiManager_getDeviceMacAddress', 0, async () => {
      await executeApiTestCaseById('WM_C_00497');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00498
     * @tc.name WM_C_00498_wifiManager_getDeviceMacAddress
     * @tc.desc wifiManager.getDeviceMacAddress condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00498_wifiManager_getDeviceMacAddress', 0, async () => {
      await executeApiTestCaseById('WM_C_00498');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00499
     * @tc.name WM_C_00499_wifiManager_getDeviceMacAddress
     * @tc.desc wifiManager.getDeviceMacAddress condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00499_wifiManager_getDeviceMacAddress', 0, async () => {
      await executeApiTestCaseById('WM_C_00499');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00500
     * @tc.name WM_C_00500_wifiManager_getDeviceMacAddress
     * @tc.desc wifiManager.getDeviceMacAddress condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00500_wifiManager_getDeviceMacAddress', 0, async () => {
      await executeApiTestCaseById('WM_C_00500');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00501
     * @tc.name WM_C_00501_wifiManager_getDeviceMacAddress
     * @tc.desc wifiManager.getDeviceMacAddress condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00501_wifiManager_getDeviceMacAddress', 0, async () => {
      await executeApiTestCaseById('WM_C_00501');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00502
     * @tc.name WM_C_00502_wifiManager_getDeviceMacAddress
     * @tc.desc wifiManager.getDeviceMacAddress condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00502_wifiManager_getDeviceMacAddress', 0, async () => {
      await executeApiTestCaseById('WM_C_00502');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00503
     * @tc.name WM_C_00503_wifiManager_getDeviceMacAddress
     * @tc.desc wifiManager.getDeviceMacAddress condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00503_wifiManager_getDeviceMacAddress', 0, async () => {
      await executeApiTestCaseById('WM_C_00503');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00504
     * @tc.name WM_C_00504_wifiManager_getIpInfo
     * @tc.desc wifiManager.getIpInfo condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00504_wifiManager_getIpInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00504');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00505
     * @tc.name WM_C_00505_wifiManager_getIpInfo
     * @tc.desc wifiManager.getIpInfo condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00505_wifiManager_getIpInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00505');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00506
     * @tc.name WM_C_00506_wifiManager_getIpInfo
     * @tc.desc wifiManager.getIpInfo condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00506_wifiManager_getIpInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00506');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00507
     * @tc.name WM_C_00507_wifiManager_getIpInfo
     * @tc.desc wifiManager.getIpInfo condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00507_wifiManager_getIpInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00507');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00508
     * @tc.name WM_C_00508_wifiManager_getIpInfo
     * @tc.desc wifiManager.getIpInfo condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00508_wifiManager_getIpInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00508');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00509
     * @tc.name WM_C_00509_wifiManager_getIpInfo
     * @tc.desc wifiManager.getIpInfo condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00509_wifiManager_getIpInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00509');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00510
     * @tc.name WM_C_00510_wifiManager_getIpInfo
     * @tc.desc wifiManager.getIpInfo condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00510_wifiManager_getIpInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00510');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00511
     * @tc.name WM_C_00511_wifiManager_getIpInfo
     * @tc.desc wifiManager.getIpInfo condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00511_wifiManager_getIpInfo', 0, async () => {
      await executeApiTestCaseById('WM_C_00511');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00512
     * @tc.name WM_C_00512_wifiManager_getIpv6Info
     * @tc.desc wifiManager.getIpv6Info condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00512_wifiManager_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WM_C_00512');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00513
     * @tc.name WM_C_00513_wifiManager_getIpv6Info
     * @tc.desc wifiManager.getIpv6Info condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00513_wifiManager_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WM_C_00513');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00514
     * @tc.name WM_C_00514_wifiManager_getIpv6Info
     * @tc.desc wifiManager.getIpv6Info condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00514_wifiManager_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WM_C_00514');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00515
     * @tc.name WM_C_00515_wifiManager_getIpv6Info
     * @tc.desc wifiManager.getIpv6Info condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00515_wifiManager_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WM_C_00515');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00516
     * @tc.name WM_C_00516_wifiManager_getIpv6Info
     * @tc.desc wifiManager.getIpv6Info condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00516_wifiManager_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WM_C_00516');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00517
     * @tc.name WM_C_00517_wifiManager_getIpv6Info
     * @tc.desc wifiManager.getIpv6Info condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00517_wifiManager_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WM_C_00517');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00518
     * @tc.name WM_C_00518_wifiManager_getIpv6Info
     * @tc.desc wifiManager.getIpv6Info condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00518_wifiManager_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WM_C_00518');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00519
     * @tc.name WM_C_00519_wifiManager_getIpv6Info
     * @tc.desc wifiManager.getIpv6Info condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00519_wifiManager_getIpv6Info', 0, async () => {
      await executeApiTestCaseById('WM_C_00519');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00520
     * @tc.name WM_C_00520_wifiManager_getCountryCode
     * @tc.desc wifiManager.getCountryCode condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00520_wifiManager_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WM_C_00520');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00521
     * @tc.name WM_C_00521_wifiManager_getCountryCode
     * @tc.desc wifiManager.getCountryCode condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00521_wifiManager_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WM_C_00521');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00522
     * @tc.name WM_C_00522_wifiManager_getCountryCode
     * @tc.desc wifiManager.getCountryCode condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00522_wifiManager_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WM_C_00522');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00523
     * @tc.name WM_C_00523_wifiManager_getCountryCode
     * @tc.desc wifiManager.getCountryCode condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00523_wifiManager_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WM_C_00523');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00524
     * @tc.name WM_C_00524_wifiManager_getCountryCode
     * @tc.desc wifiManager.getCountryCode condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00524_wifiManager_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WM_C_00524');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00525
     * @tc.name WM_C_00525_wifiManager_getCountryCode
     * @tc.desc wifiManager.getCountryCode condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00525_wifiManager_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WM_C_00525');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00526
     * @tc.name WM_C_00526_wifiManager_getCountryCode
     * @tc.desc wifiManager.getCountryCode condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00526_wifiManager_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WM_C_00526');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00527
     * @tc.name WM_C_00527_wifiManager_getCountryCode
     * @tc.desc wifiManager.getCountryCode condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00527_wifiManager_getCountryCode', 0, async () => {
      await executeApiTestCaseById('WM_C_00527');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00528
     * @tc.name WM_C_00528_wifiManager_reassociate
     * @tc.desc wifiManager.reassociate condition=ANY
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00528_wifiManager_reassociate', 0, async () => {
      await executeApiTestCaseById('WM_C_00528');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00529
     * @tc.name WM_C_00529_wifiManager_reassociate
     * @tc.desc wifiManager.reassociate condition=WIFI_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00529_wifiManager_reassociate', 0, async () => {
      await executeApiTestCaseById('WM_C_00529');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00530
     * @tc.name WM_C_00530_wifiManager_reassociate
     * @tc.desc wifiManager.reassociate condition=WIFI_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00530_wifiManager_reassociate', 0, async () => {
      await executeApiTestCaseById('WM_C_00530');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00531
     * @tc.name WM_C_00531_wifiManager_reassociate
     * @tc.desc wifiManager.reassociate condition=WIFI_ON_SCAN
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00531_wifiManager_reassociate', 0, async () => {
      await executeApiTestCaseById('WM_C_00531');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00532
     * @tc.name WM_C_00532_wifiManager_reassociate
     * @tc.desc wifiManager.reassociate condition=HOTSPOT_OFF
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00532_wifiManager_reassociate', 0, async () => {
      await executeApiTestCaseById('WM_C_00532');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00533
     * @tc.name WM_C_00533_wifiManager_reassociate
     * @tc.desc wifiManager.reassociate condition=HOTSPOT_ON
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00533_wifiManager_reassociate', 0, async () => {
      await executeApiTestCaseById('WM_C_00533');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00534
     * @tc.name WM_C_00534_wifiManager_reassociate
     * @tc.desc wifiManager.reassociate condition=P2P_IDLE
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00534_wifiManager_reassociate', 0, async () => {
      await executeApiTestCaseById('WM_C_00534');
    });

    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_WM_C_00535
     * @tc.name WM_C_00535_wifiManager_reassociate
     * @tc.desc wifiManager.reassociate condition=P2P_DISCOVERING
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('WM_C_00535_wifiManager_reassociate', 0, async () => {
      await executeApiTestCaseById('WM_C_00535');
    });

}
