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
import { ApiTestCase } from '../ApiTestTypes';
import {
  makeApiTestCase,
  buildParams
} from '../ApiTestCaseFactory';

export const APITESTCATALOG_PART05: ApiTestCase[] = [
  makeApiTestCase(
    "WM_C_00401",
    "wifiManager",
    "getWifiDetailState",
    "condition",
    buildParams([]),
    [],
    "WIFI_OFF",
    "number",
    "non_negative",
    true,
    "wifiManager.getWifiDetailState condition=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_C_00402",
    "wifiManager",
    "getWifiDetailState",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON",
    "number",
    "non_negative",
    true,
    "wifiManager.getWifiDetailState condition=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_C_00403",
    "wifiManager",
    "getWifiDetailState",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON_SCAN",
    "number",
    "non_negative",
    true,
    "wifiManager.getWifiDetailState condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_C_00404",
    "wifiManager",
    "getWifiDetailState",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_OFF",
    "number",
    "non_negative",
    true,
    "wifiManager.getWifiDetailState condition=HOTSPOT_OFF"
  ),
  makeApiTestCase(
    "WM_C_00405",
    "wifiManager",
    "getWifiDetailState",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_ON",
    "number",
    "non_negative",
    true,
    "wifiManager.getWifiDetailState condition=HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_C_00406",
    "wifiManager",
    "getWifiDetailState",
    "condition",
    buildParams([]),
    [],
    "P2P_IDLE",
    "number",
    "non_negative",
    true,
    "wifiManager.getWifiDetailState condition=P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_C_00407",
    "wifiManager",
    "getWifiDetailState",
    "condition",
    buildParams([]),
    [],
    "P2P_DISCOVERING",
    "number",
    "non_negative",
    true,
    "wifiManager.getWifiDetailState condition=P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_C_00408",
    "wifiManager",
    "setScanAlwaysAllowed",
    "condition",
    buildParams([
      ["allowed", true]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.setScanAlwaysAllowed condition=ANY"
  ),
  makeApiTestCase(
    "WM_C_00409",
    "wifiManager",
    "setScanAlwaysAllowed",
    "condition",
    buildParams([
      ["allowed", true]
    ]),
    [],
    "WIFI_OFF",
    "void",
    "none",
    true,
    "wifiManager.setScanAlwaysAllowed condition=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_C_00410",
    "wifiManager",
    "setScanAlwaysAllowed",
    "condition",
    buildParams([
      ["allowed", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "wifiManager.setScanAlwaysAllowed condition=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_C_00411",
    "wifiManager",
    "setScanAlwaysAllowed",
    "condition",
    buildParams([
      ["allowed", true]
    ]),
    [],
    "WIFI_ON_SCAN",
    "void",
    "none",
    true,
    "wifiManager.setScanAlwaysAllowed condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_C_00412",
    "wifiManager",
    "setScanAlwaysAllowed",
    "condition",
    buildParams([
      ["allowed", true]
    ]),
    [],
    "HOTSPOT_OFF",
    "void",
    "none",
    true,
    "wifiManager.setScanAlwaysAllowed condition=HOTSPOT_OFF"
  ),
  makeApiTestCase(
    "WM_C_00413",
    "wifiManager",
    "setScanAlwaysAllowed",
    "condition",
    buildParams([
      ["allowed", true]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "wifiManager.setScanAlwaysAllowed condition=HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_C_00414",
    "wifiManager",
    "setScanAlwaysAllowed",
    "condition",
    buildParams([
      ["allowed", true]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "wifiManager.setScanAlwaysAllowed condition=P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_C_00415",
    "wifiManager",
    "setScanAlwaysAllowed",
    "condition",
    buildParams([
      ["allowed", true]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "wifiManager.setScanAlwaysAllowed condition=P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_C_00416",
    "wifiManager",
    "getScanAlwaysAllowed",
    "condition",
    buildParams([]),
    [],
    "ANY",
    "boolean",
    "none",
    true,
    "wifiManager.getScanAlwaysAllowed condition=ANY"
  ),
  makeApiTestCase(
    "WM_C_00417",
    "wifiManager",
    "getScanAlwaysAllowed",
    "condition",
    buildParams([]),
    [],
    "WIFI_OFF",
    "boolean",
    "none",
    true,
    "wifiManager.getScanAlwaysAllowed condition=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_C_00418",
    "wifiManager",
    "getScanAlwaysAllowed",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON",
    "boolean",
    "none",
    true,
    "wifiManager.getScanAlwaysAllowed condition=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_C_00419",
    "wifiManager",
    "getScanAlwaysAllowed",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON_SCAN",
    "boolean",
    "none",
    true,
    "wifiManager.getScanAlwaysAllowed condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_C_00420",
    "wifiManager",
    "getScanAlwaysAllowed",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_OFF",
    "boolean",
    "none",
    true,
    "wifiManager.getScanAlwaysAllowed condition=HOTSPOT_OFF"
  ),
  makeApiTestCase(
    "WM_C_00421",
    "wifiManager",
    "getScanAlwaysAllowed",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_ON",
    "boolean",
    "none",
    true,
    "wifiManager.getScanAlwaysAllowed condition=HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_C_00422",
    "wifiManager",
    "getScanAlwaysAllowed",
    "condition",
    buildParams([]),
    [],
    "P2P_IDLE",
    "boolean",
    "none",
    true,
    "wifiManager.getScanAlwaysAllowed condition=P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_C_00423",
    "wifiManager",
    "getScanAlwaysAllowed",
    "condition",
    buildParams([]),
    [],
    "P2P_DISCOVERING",
    "boolean",
    "none",
    true,
    "wifiManager.getScanAlwaysAllowed condition=P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_C_00424",
    "wifiManager",
    "getCandidateConfigs",
    "condition",
    buildParams([]),
    [],
    "ANY",
    "array",
    "none",
    true,
    "wifiManager.getCandidateConfigs condition=ANY"
  ),
  makeApiTestCase(
    "WM_C_00425",
    "wifiManager",
    "getCandidateConfigs",
    "condition",
    buildParams([]),
    [],
    "WIFI_OFF",
    "array",
    "none",
    true,
    "wifiManager.getCandidateConfigs condition=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_C_00426",
    "wifiManager",
    "getCandidateConfigs",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON",
    "array",
    "none",
    true,
    "wifiManager.getCandidateConfigs condition=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_C_00427",
    "wifiManager",
    "getCandidateConfigs",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON_SCAN",
    "array",
    "none",
    true,
    "wifiManager.getCandidateConfigs condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_C_00428",
    "wifiManager",
    "getCandidateConfigs",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_OFF",
    "array",
    "none",
    true,
    "wifiManager.getCandidateConfigs condition=HOTSPOT_OFF"
  ),
  makeApiTestCase(
    "WM_C_00429",
    "wifiManager",
    "getCandidateConfigs",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_ON",
    "array",
    "none",
    true,
    "wifiManager.getCandidateConfigs condition=HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_C_00430",
    "wifiManager",
    "getCandidateConfigs",
    "condition",
    buildParams([]),
    [],
    "P2P_IDLE",
    "array",
    "none",
    true,
    "wifiManager.getCandidateConfigs condition=P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_C_00431",
    "wifiManager",
    "getCandidateConfigs",
    "condition",
    buildParams([]),
    [],
    "P2P_DISCOVERING",
    "array",
    "none",
    true,
    "wifiManager.getCandidateConfigs condition=P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_C_00432",
    "wifiManager",
    "connectToNetwork",
    "condition",
    buildParams([
      ["netId", 0]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.connectToNetwork condition=ANY"
  ),
  makeApiTestCase(
    "WM_C_00433",
    "wifiManager",
    "connectToNetwork",
    "condition",
    buildParams([
      ["netId", 0]
    ]),
    [],
    "WIFI_OFF",
    "void",
    "none",
    true,
    "wifiManager.connectToNetwork condition=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_C_00434",
    "wifiManager",
    "connectToNetwork",
    "condition",
    buildParams([
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "wifiManager.connectToNetwork condition=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_C_00435",
    "wifiManager",
    "connectToNetwork",
    "condition",
    buildParams([
      ["netId", 0]
    ]),
    [],
    "WIFI_ON_SCAN",
    "void",
    "none",
    true,
    "wifiManager.connectToNetwork condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_C_00436",
    "wifiManager",
    "connectToNetwork",
    "condition",
    buildParams([
      ["netId", 0]
    ]),
    [],
    "HOTSPOT_OFF",
    "void",
    "none",
    true,
    "wifiManager.connectToNetwork condition=HOTSPOT_OFF"
  ),
  makeApiTestCase(
    "WM_C_00437",
    "wifiManager",
    "connectToNetwork",
    "condition",
    buildParams([
      ["netId", 0]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "wifiManager.connectToNetwork condition=HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_C_00438",
    "wifiManager",
    "connectToNetwork",
    "condition",
    buildParams([
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "wifiManager.connectToNetwork condition=P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_C_00439",
    "wifiManager",
    "connectToNetwork",
    "condition",
    buildParams([
      ["netId", 0]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "wifiManager.connectToNetwork condition=P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_C_00440",
    "wifiManager",
    "disconnect",
    "condition",
    buildParams([]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.disconnect condition=ANY"
  ),
  makeApiTestCase(
    "WM_C_00441",
    "wifiManager",
    "disconnect",
    "condition",
    buildParams([]),
    [],
    "WIFI_OFF",
    "void",
    "none",
    true,
    "wifiManager.disconnect condition=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_C_00442",
    "wifiManager",
    "disconnect",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "wifiManager.disconnect condition=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_C_00443",
    "wifiManager",
    "disconnect",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON_SCAN",
    "void",
    "none",
    true,
    "wifiManager.disconnect condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_C_00444",
    "wifiManager",
    "disconnect",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_OFF",
    "void",
    "none",
    true,
    "wifiManager.disconnect condition=HOTSPOT_OFF"
  ),
  makeApiTestCase(
    "WM_C_00445",
    "wifiManager",
    "disconnect",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "wifiManager.disconnect condition=HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_C_00446",
    "wifiManager",
    "disconnect",
    "condition",
    buildParams([]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "wifiManager.disconnect condition=P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_C_00447",
    "wifiManager",
    "disconnect",
    "condition",
    buildParams([]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "wifiManager.disconnect condition=P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_C_00448",
    "wifiManager",
    "getSignalLevel",
    "condition",
    buildParams([
      ["rssi", -100],
      ["band", 1]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    true,
    "wifiManager.getSignalLevel condition=ANY"
  ),
  makeApiTestCase(
    "WM_C_00449",
    "wifiManager",
    "getSignalLevel",
    "condition",
    buildParams([
      ["rssi", -100],
      ["band", 1]
    ]),
    [],
    "WIFI_OFF",
    "number",
    "range_0_4",
    true,
    "wifiManager.getSignalLevel condition=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_C_00450",
    "wifiManager",
    "getSignalLevel",
    "condition",
    buildParams([
      ["rssi", -100],
      ["band", 1]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "wifiManager.getSignalLevel condition=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_C_00451",
    "wifiManager",
    "getSignalLevel",
    "condition",
    buildParams([
      ["rssi", -100],
      ["band", 1]
    ]),
    [],
    "WIFI_ON_SCAN",
    "number",
    "range_0_4",
    true,
    "wifiManager.getSignalLevel condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_C_00452",
    "wifiManager",
    "getSignalLevel",
    "condition",
    buildParams([
      ["rssi", -100],
      ["band", 1]
    ]),
    [],
    "HOTSPOT_OFF",
    "number",
    "range_0_4",
    true,
    "wifiManager.getSignalLevel condition=HOTSPOT_OFF"
  ),
  makeApiTestCase(
    "WM_C_00453",
    "wifiManager",
    "getSignalLevel",
    "condition",
    buildParams([
      ["rssi", -100],
      ["band", 1]
    ]),
    [],
    "HOTSPOT_ON",
    "number",
    "range_0_4",
    true,
    "wifiManager.getSignalLevel condition=HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_C_00454",
    "wifiManager",
    "getSignalLevel",
    "condition",
    buildParams([
      ["rssi", -100],
      ["band", 1]
    ]),
    [],
    "P2P_IDLE",
    "number",
    "range_0_4",
    true,
    "wifiManager.getSignalLevel condition=P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_C_00455",
    "wifiManager",
    "getSignalLevel",
    "condition",
    buildParams([
      ["rssi", -100],
      ["band", 1]
    ]),
    [],
    "P2P_DISCOVERING",
    "number",
    "range_0_4",
    true,
    "wifiManager.getSignalLevel condition=P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_C_00456",
    "wifiManager",
    "getLinkedInfoSync",
    "condition",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "wifiManager.getLinkedInfoSync condition=ANY"
  ),
  makeApiTestCase(
    "WM_C_00457",
    "wifiManager",
    "getLinkedInfoSync",
    "condition",
    buildParams([]),
    [],
    "WIFI_OFF",
    "object",
    "none",
    true,
    "wifiManager.getLinkedInfoSync condition=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_C_00458",
    "wifiManager",
    "getLinkedInfoSync",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON",
    "object",
    "none",
    true,
    "wifiManager.getLinkedInfoSync condition=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_C_00459",
    "wifiManager",
    "getLinkedInfoSync",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON_SCAN",
    "object",
    "none",
    true,
    "wifiManager.getLinkedInfoSync condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_C_00460",
    "wifiManager",
    "getLinkedInfoSync",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_OFF",
    "object",
    "none",
    true,
    "wifiManager.getLinkedInfoSync condition=HOTSPOT_OFF"
  ),
  makeApiTestCase(
    "WM_C_00461",
    "wifiManager",
    "getLinkedInfoSync",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_ON",
    "object",
    "none",
    true,
    "wifiManager.getLinkedInfoSync condition=HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_C_00462",
    "wifiManager",
    "getLinkedInfoSync",
    "condition",
    buildParams([]),
    [],
    "P2P_IDLE",
    "object",
    "none",
    true,
    "wifiManager.getLinkedInfoSync condition=P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_C_00463",
    "wifiManager",
    "getLinkedInfoSync",
    "condition",
    buildParams([]),
    [],
    "P2P_DISCOVERING",
    "object",
    "none",
    true,
    "wifiManager.getLinkedInfoSync condition=P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_C_00464",
    "wifiManager",
    "getMultiLinkedInfo",
    "condition",
    buildParams([]),
    [],
    "ANY",
    "array",
    "none",
    true,
    "wifiManager.getMultiLinkedInfo condition=ANY"
  ),
  makeApiTestCase(
    "WM_C_00465",
    "wifiManager",
    "getMultiLinkedInfo",
    "condition",
    buildParams([]),
    [],
    "WIFI_OFF",
    "array",
    "none",
    true,
    "wifiManager.getMultiLinkedInfo condition=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_C_00466",
    "wifiManager",
    "getMultiLinkedInfo",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON",
    "array",
    "none",
    true,
    "wifiManager.getMultiLinkedInfo condition=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_C_00467",
    "wifiManager",
    "getMultiLinkedInfo",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON_SCAN",
    "array",
    "none",
    true,
    "wifiManager.getMultiLinkedInfo condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_C_00468",
    "wifiManager",
    "getMultiLinkedInfo",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_OFF",
    "array",
    "none",
    true,
    "wifiManager.getMultiLinkedInfo condition=HOTSPOT_OFF"
  ),
  makeApiTestCase(
    "WM_C_00469",
    "wifiManager",
    "getMultiLinkedInfo",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_ON",
    "array",
    "none",
    true,
    "wifiManager.getMultiLinkedInfo condition=HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_C_00470",
    "wifiManager",
    "getMultiLinkedInfo",
    "condition",
    buildParams([]),
    [],
    "P2P_IDLE",
    "array",
    "none",
    true,
    "wifiManager.getMultiLinkedInfo condition=P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_C_00471",
    "wifiManager",
    "getMultiLinkedInfo",
    "condition",
    buildParams([]),
    [],
    "P2P_DISCOVERING",
    "array",
    "none",
    true,
    "wifiManager.getMultiLinkedInfo condition=P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_C_00472",
    "wifiManager",
    "isConnected",
    "condition",
    buildParams([]),
    [],
    "ANY",
    "boolean",
    "none",
    true,
    "wifiManager.isConnected condition=ANY"
  ),
  makeApiTestCase(
    "WM_C_00473",
    "wifiManager",
    "isConnected",
    "condition",
    buildParams([]),
    [],
    "WIFI_OFF",
    "boolean",
    "none",
    true,
    "wifiManager.isConnected condition=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_C_00474",
    "wifiManager",
    "isConnected",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON",
    "boolean",
    "none",
    true,
    "wifiManager.isConnected condition=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_C_00475",
    "wifiManager",
    "isConnected",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON_SCAN",
    "boolean",
    "none",
    true,
    "wifiManager.isConnected condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_C_00476",
    "wifiManager",
    "isConnected",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_OFF",
    "boolean",
    "none",
    true,
    "wifiManager.isConnected condition=HOTSPOT_OFF"
  ),
  makeApiTestCase(
    "WM_C_00477",
    "wifiManager",
    "isConnected",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_ON",
    "boolean",
    "none",
    true,
    "wifiManager.isConnected condition=HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_C_00478",
    "wifiManager",
    "isConnected",
    "condition",
    buildParams([]),
    [],
    "P2P_IDLE",
    "boolean",
    "none",
    true,
    "wifiManager.isConnected condition=P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_C_00479",
    "wifiManager",
    "isConnected",
    "condition",
    buildParams([]),
    [],
    "P2P_DISCOVERING",
    "boolean",
    "none",
    true,
    "wifiManager.isConnected condition=P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_C_00480",
    "wifiManager",
    "getSupportedFeatures",
    "condition",
    buildParams([]),
    [],
    "ANY",
    "number",
    "non_negative",
    true,
    "wifiManager.getSupportedFeatures condition=ANY"
  ),
  makeApiTestCase(
    "WM_C_00481",
    "wifiManager",
    "getSupportedFeatures",
    "condition",
    buildParams([]),
    [],
    "WIFI_OFF",
    "number",
    "non_negative",
    true,
    "wifiManager.getSupportedFeatures condition=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_C_00482",
    "wifiManager",
    "getSupportedFeatures",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON",
    "number",
    "non_negative",
    true,
    "wifiManager.getSupportedFeatures condition=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_C_00483",
    "wifiManager",
    "getSupportedFeatures",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON_SCAN",
    "number",
    "non_negative",
    true,
    "wifiManager.getSupportedFeatures condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_C_00484",
    "wifiManager",
    "getSupportedFeatures",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_OFF",
    "number",
    "non_negative",
    true,
    "wifiManager.getSupportedFeatures condition=HOTSPOT_OFF"
  ),
  makeApiTestCase(
    "WM_C_00485",
    "wifiManager",
    "getSupportedFeatures",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_ON",
    "number",
    "non_negative",
    true,
    "wifiManager.getSupportedFeatures condition=HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_C_00486",
    "wifiManager",
    "getSupportedFeatures",
    "condition",
    buildParams([]),
    [],
    "P2P_IDLE",
    "number",
    "non_negative",
    true,
    "wifiManager.getSupportedFeatures condition=P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_C_00487",
    "wifiManager",
    "getSupportedFeatures",
    "condition",
    buildParams([]),
    [],
    "P2P_DISCOVERING",
    "number",
    "non_negative",
    true,
    "wifiManager.getSupportedFeatures condition=P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_C_00488",
    "wifiManager",
    "isFeatureSupported",
    "condition",
    buildParams([
      ["featureId", 0]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    true,
    "wifiManager.isFeatureSupported condition=ANY"
  ),
  makeApiTestCase(
    "WM_C_00489",
    "wifiManager",
    "isFeatureSupported",
    "condition",
    buildParams([
      ["featureId", 0]
    ]),
    [],
    "WIFI_OFF",
    "boolean",
    "none",
    true,
    "wifiManager.isFeatureSupported condition=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_C_00490",
    "wifiManager",
    "isFeatureSupported",
    "condition",
    buildParams([
      ["featureId", 0]
    ]),
    [],
    "WIFI_ON",
    "boolean",
    "none",
    true,
    "wifiManager.isFeatureSupported condition=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_C_00491",
    "wifiManager",
    "isFeatureSupported",
    "condition",
    buildParams([
      ["featureId", 0]
    ]),
    [],
    "WIFI_ON_SCAN",
    "boolean",
    "none",
    true,
    "wifiManager.isFeatureSupported condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_C_00492",
    "wifiManager",
    "isFeatureSupported",
    "condition",
    buildParams([
      ["featureId", 0]
    ]),
    [],
    "HOTSPOT_OFF",
    "boolean",
    "none",
    true,
    "wifiManager.isFeatureSupported condition=HOTSPOT_OFF"
  ),
  makeApiTestCase(
    "WM_C_00493",
    "wifiManager",
    "isFeatureSupported",
    "condition",
    buildParams([
      ["featureId", 0]
    ]),
    [],
    "HOTSPOT_ON",
    "boolean",
    "none",
    true,
    "wifiManager.isFeatureSupported condition=HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_C_00494",
    "wifiManager",
    "isFeatureSupported",
    "condition",
    buildParams([
      ["featureId", 0]
    ]),
    [],
    "P2P_IDLE",
    "boolean",
    "none",
    true,
    "wifiManager.isFeatureSupported condition=P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_C_00495",
    "wifiManager",
    "isFeatureSupported",
    "condition",
    buildParams([
      ["featureId", 0]
    ]),
    [],
    "P2P_DISCOVERING",
    "boolean",
    "none",
    true,
    "wifiManager.isFeatureSupported condition=P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_C_00496",
    "wifiManager",
    "getDeviceMacAddress",
    "condition",
    buildParams([]),
    [],
    "ANY",
    "array",
    "none",
    true,
    "wifiManager.getDeviceMacAddress condition=ANY"
  ),
  makeApiTestCase(
    "WM_C_00497",
    "wifiManager",
    "getDeviceMacAddress",
    "condition",
    buildParams([]),
    [],
    "WIFI_OFF",
    "array",
    "none",
    true,
    "wifiManager.getDeviceMacAddress condition=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_C_00498",
    "wifiManager",
    "getDeviceMacAddress",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON",
    "array",
    "none",
    true,
    "wifiManager.getDeviceMacAddress condition=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_C_00499",
    "wifiManager",
    "getDeviceMacAddress",
    "condition",
    buildParams([]),
    [],
    "WIFI_ON_SCAN",
    "array",
    "none",
    true,
    "wifiManager.getDeviceMacAddress condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_C_00500",
    "wifiManager",
    "getDeviceMacAddress",
    "condition",
    buildParams([]),
    [],
    "HOTSPOT_OFF",
    "array",
    "none",
    true,
    "wifiManager.getDeviceMacAddress condition=HOTSPOT_OFF"
  ),
];
