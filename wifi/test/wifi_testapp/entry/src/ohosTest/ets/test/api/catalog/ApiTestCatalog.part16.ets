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

export const APITESTCATALOG_PART16: ApiTestCase[] = [
  makeApiTestCase(
    "WM_X_01501",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_e"],
      ["securityType", 3],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_e sec=3"
  ),
  makeApiTestCase(
    "WM_X_01502",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_e"],
      ["securityType", 4],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_e sec=4"
  ),
  makeApiTestCase(
    "WM_X_01503",
    "wifiManager",
    "connectToCandidateConfig",
    "param",
    buildParams([
      ["netId", -1]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToCandidateConfig netId=-1"
  ),
  makeApiTestCase(
    "WM_X_01504",
    "wifiManager",
    "connectToCandidateConfig",
    "param",
    buildParams([
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToCandidateConfig netId=0"
  ),
  makeApiTestCase(
    "WM_X_01505",
    "wifiManager",
    "connectToCandidateConfig",
    "param",
    buildParams([
      ["netId", 1]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToCandidateConfig netId=1"
  ),
  makeApiTestCase(
    "WM_X_01506",
    "wifiManager",
    "connectToCandidateConfig",
    "param",
    buildParams([
      ["netId", 2]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToCandidateConfig netId=2"
  ),
  makeApiTestCase(
    "WM_X_01507",
    "wifiManager",
    "connectToCandidateConfig",
    "param",
    buildParams([
      ["netId", 3]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToCandidateConfig netId=3"
  ),
  makeApiTestCase(
    "WM_X_01508",
    "wifiManager",
    "getCountryCode",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isWifiActive",
      "getCountryCode"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo isWifiActive->getCountryCode"
  ),
  makeApiTestCase(
    "WM_X_01509",
    "wifiManager",
    "getIpInfo",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isWifiActive",
      "getIpInfo"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo isWifiActive->getIpInfo"
  ),
  makeApiTestCase(
    "WM_X_01510",
    "wifiManager",
    "getDeviceMacAddress",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isWifiActive",
      "getDeviceMacAddress"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo isWifiActive->getDeviceMacAddress"
  ),
  makeApiTestCase(
    "WM_X_01511",
    "wifiManager",
    "getSupportedFeatures",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isWifiActive",
      "getSupportedFeatures"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo isWifiActive->getSupportedFeatures"
  ),
  makeApiTestCase(
    "WM_X_01512",
    "wifiManager",
    "isConnected",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isWifiActive",
      "isConnected"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo isWifiActive->isConnected"
  ),
  makeApiTestCase(
    "WM_X_01513",
    "wifiManager",
    "getWifiDetailState",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isWifiActive",
      "getWifiDetailState"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo isWifiActive->getWifiDetailState"
  ),
  makeApiTestCase(
    "WM_X_01514",
    "wifiManager",
    "getIpInfo",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getCountryCode",
      "getIpInfo"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo getCountryCode->getIpInfo"
  ),
  makeApiTestCase(
    "WM_X_01515",
    "wifiManager",
    "getDeviceMacAddress",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getCountryCode",
      "getDeviceMacAddress"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo getCountryCode->getDeviceMacAddress"
  ),
  makeApiTestCase(
    "WM_X_01516",
    "wifiManager",
    "getSupportedFeatures",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getCountryCode",
      "getSupportedFeatures"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo getCountryCode->getSupportedFeatures"
  ),
  makeApiTestCase(
    "WM_X_01517",
    "wifiManager",
    "isConnected",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getCountryCode",
      "isConnected"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo getCountryCode->isConnected"
  ),
  makeApiTestCase(
    "WM_X_01518",
    "wifiManager",
    "getWifiDetailState",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getCountryCode",
      "getWifiDetailState"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo getCountryCode->getWifiDetailState"
  ),
  makeApiTestCase(
    "WM_X_01519",
    "wifiManager",
    "getDeviceMacAddress",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getIpInfo",
      "getDeviceMacAddress"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo getIpInfo->getDeviceMacAddress"
  ),
  makeApiTestCase(
    "WM_X_01520",
    "wifiManager",
    "getSupportedFeatures",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getIpInfo",
      "getSupportedFeatures"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo getIpInfo->getSupportedFeatures"
  ),
  makeApiTestCase(
    "WM_X_01521",
    "wifiManager",
    "isConnected",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getIpInfo",
      "isConnected"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo getIpInfo->isConnected"
  ),
  makeApiTestCase(
    "WM_X_01522",
    "wifiManager",
    "getWifiDetailState",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getIpInfo",
      "getWifiDetailState"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo getIpInfo->getWifiDetailState"
  ),
  makeApiTestCase(
    "WM_X_01523",
    "wifiManager",
    "getSupportedFeatures",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getDeviceMacAddress",
      "getSupportedFeatures"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo getDeviceMacAddress->getSupportedFeatures"
  ),
  makeApiTestCase(
    "WM_X_01524",
    "wifiManager",
    "isConnected",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getDeviceMacAddress",
      "isConnected"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo getDeviceMacAddress->isConnected"
  ),
  makeApiTestCase(
    "WM_X_01525",
    "wifiManager",
    "getWifiDetailState",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getDeviceMacAddress",
      "getWifiDetailState"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo getDeviceMacAddress->getWifiDetailState"
  ),
  makeApiTestCase(
    "WM_X_01526",
    "wifiManager",
    "isConnected",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getSupportedFeatures",
      "isConnected"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo getSupportedFeatures->isConnected"
  ),
  makeApiTestCase(
    "WM_X_01527",
    "wifiManager",
    "getWifiDetailState",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getSupportedFeatures",
      "getWifiDetailState"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo getSupportedFeatures->getWifiDetailState"
  ),
  makeApiTestCase(
    "WM_X_01528",
    "wifiManager",
    "getWifiDetailState",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isConnected",
      "getWifiDetailState"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "short_combo isConnected->getWifiDetailState"
  ),
  makeApiTestCase(
    "WM_X_01529",
    "wifiManager",
    "getIpInfo",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isWifiActive",
      "getCountryCode",
      "getIpInfo"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "triple_combo isWifiActive->getCountryCode->getIpInfo"
  ),
  makeApiTestCase(
    "WM_X_01530",
    "wifiManager",
    "getDeviceMacAddress",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isWifiActive",
      "getCountryCode",
      "getDeviceMacAddress"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "triple_combo isWifiActive->getCountryCode->getDeviceMacAddress"
  ),
  makeApiTestCase(
    "WM_X_01531",
    "wifiManager",
    "isConnected",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isWifiActive",
      "getCountryCode",
      "isConnected"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "triple_combo isWifiActive->getCountryCode->isConnected"
  ),
  makeApiTestCase(
    "WM_X_01532",
    "wifiManager",
    "getDeviceMacAddress",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isWifiActive",
      "getIpInfo",
      "getDeviceMacAddress"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "triple_combo isWifiActive->getIpInfo->getDeviceMacAddress"
  ),
  makeApiTestCase(
    "WM_X_01533",
    "wifiManager",
    "isConnected",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isWifiActive",
      "getIpInfo",
      "isConnected"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "triple_combo isWifiActive->getIpInfo->isConnected"
  ),
  makeApiTestCase(
    "WM_X_01534",
    "wifiManager",
    "isConnected",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isWifiActive",
      "getDeviceMacAddress",
      "isConnected"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "triple_combo isWifiActive->getDeviceMacAddress->isConnected"
  ),
  makeApiTestCase(
    "WM_X_01535",
    "wifiManager",
    "getDeviceMacAddress",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getCountryCode",
      "getIpInfo",
      "getDeviceMacAddress"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "triple_combo getCountryCode->getIpInfo->getDeviceMacAddress"
  ),
  makeApiTestCase(
    "WM_X_01536",
    "wifiManager",
    "isConnected",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getCountryCode",
      "getIpInfo",
      "isConnected"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "triple_combo getCountryCode->getIpInfo->isConnected"
  ),
  makeApiTestCase(
    "WM_X_01537",
    "wifiManager",
    "isConnected",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getCountryCode",
      "getDeviceMacAddress",
      "isConnected"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "triple_combo getCountryCode->getDeviceMacAddress->isConnected"
  ),
  makeApiTestCase(
    "WM_X_01538",
    "wifiManager",
    "isConnected",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getIpInfo",
      "getDeviceMacAddress",
      "isConnected"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "triple_combo getIpInfo->getDeviceMacAddress->isConnected"
  ),
  makeApiTestCase(
    "WM_X_01539",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -100],
      ["band", 1]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=0"
  ),
  makeApiTestCase(
    "WM_X_01540",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -95],
      ["band", 2]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=1"
  ),
  makeApiTestCase(
    "WM_X_01541",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -90],
      ["band", 3]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=2"
  ),
  makeApiTestCase(
    "WM_X_01542",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -85],
      ["band", 1]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=3"
  ),
  makeApiTestCase(
    "WM_X_01543",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -80],
      ["band", 2]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=4"
  ),
  makeApiTestCase(
    "WM_X_01544",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -75],
      ["band", 3]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=5"
  ),
  makeApiTestCase(
    "WM_X_01545",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -70],
      ["band", 1]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=6"
  ),
  makeApiTestCase(
    "WM_X_01546",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -65],
      ["band", 2]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=7"
  ),
  makeApiTestCase(
    "WM_X_01547",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -60],
      ["band", 3]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=8"
  ),
  makeApiTestCase(
    "WM_X_01548",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -55],
      ["band", 1]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=9"
  ),
  makeApiTestCase(
    "WM_X_01549",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -50],
      ["band", 2]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=10"
  ),
  makeApiTestCase(
    "WM_X_01550",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -45],
      ["band", 3]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=11"
  ),
  makeApiTestCase(
    "WM_X_01551",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -40],
      ["band", 1]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=12"
  ),
  makeApiTestCase(
    "WM_X_01552",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -35],
      ["band", 2]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=13"
  ),
  makeApiTestCase(
    "WM_X_01553",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -30],
      ["band", 3]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=14"
  ),
  makeApiTestCase(
    "WM_X_01554",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -25],
      ["band", 1]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=15"
  ),
  makeApiTestCase(
    "WM_X_01555",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -20],
      ["band", 2]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=16"
  ),
  makeApiTestCase(
    "WM_X_01556",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -15],
      ["band", 3]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=17"
  ),
  makeApiTestCase(
    "WM_X_01557",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -10],
      ["band", 1]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=18"
  ),
  makeApiTestCase(
    "WM_X_01558",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -5],
      ["band", 2]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=19"
  ),
  makeApiTestCase(
    "WM_X_01559",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 0],
      ["band", 3]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=20"
  ),
  makeApiTestCase(
    "WM_X_01560",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 5],
      ["band", 1]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=21"
  ),
  makeApiTestCase(
    "WM_X_01561",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 10],
      ["band", 2]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=22"
  ),
  makeApiTestCase(
    "WM_X_01562",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 15],
      ["band", 3]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=23"
  ),
  makeApiTestCase(
    "WM_X_01563",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 20],
      ["band", 1]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=24"
  ),
  makeApiTestCase(
    "WM_X_01564",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 25],
      ["band", 2]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=25"
  ),
  makeApiTestCase(
    "WM_X_01565",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 30],
      ["band", 3]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=26"
  ),
  makeApiTestCase(
    "WM_X_01566",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 35],
      ["band", 1]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=27"
  ),
  makeApiTestCase(
    "WM_X_01567",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 40],
      ["band", 2]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=28"
  ),
  makeApiTestCase(
    "WM_X_01568",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 45],
      ["band", 3]
    ]),
    [],
    "WIFI_ON",
    "number",
    "range_0_4",
    true,
    "getSignalLevel sweep i=29"
  ),
  makeApiTestCase(
    "WF_P_01569",
    "wifi",
    "enableWifi",
    "param",
    buildParams([]),
    [],
    "ANY",
    "void",
    "none",
    false,
    "wifi.enableWifi param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01570",
    "wifi",
    "disableWifi",
    "param",
    buildParams([]),
    [],
    "ANY",
    "void",
    "none",
    false,
    "wifi.disableWifi param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01571",
    "wifi",
    "isWifiActive",
    "param",
    buildParams([]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifi.isWifiActive param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01572",
    "wifi",
    "scan",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "void",
    "none",
    false,
    "wifi.scan param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WF_P_01573",
    "wifi",
    "isConnected",
    "param",
    buildParams([]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifi.isConnected param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01574",
    "wifi",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -90],
      ["band", 1]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifi.getSignalLevel param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01575",
    "wifi",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -90],
      ["band", 2]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifi.getSignalLevel param#1 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01576",
    "wifi",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifi.getSignalLevel param#2 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01577",
    "wifi",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -50],
      ["band", 2]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifi.getSignalLevel param#3 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01578",
    "wifi",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -10],
      ["band", 1]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifi.getSignalLevel param#4 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01579",
    "wifi",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -10],
      ["band", 2]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifi.getSignalLevel param#5 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01580",
    "wifi",
    "getIpInfo",
    "param",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    false,
    "wifi.getIpInfo param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01581",
    "wifi",
    "getCountryCode",
    "param",
    buildParams([]),
    [],
    "ANY",
    "string",
    "none",
    false,
    "wifi.getCountryCode param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01582",
    "wifi",
    "getSupportedFeatures",
    "param",
    buildParams([]),
    [],
    "ANY",
    "number",
    "none",
    false,
    "wifi.getSupportedFeatures param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01583",
    "wifi",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 0]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifi.isFeatureSupported param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01584",
    "wifi",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 1]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifi.isFeatureSupported param#1 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01585",
    "wifi",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 2]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifi.isFeatureSupported param#2 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01586",
    "wifi",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 3]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifi.isFeatureSupported param#3 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01587",
    "wifi",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 4]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifi.isFeatureSupported param#4 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01588",
    "wifi",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 5]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifi.isFeatureSupported param#5 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01589",
    "wifi",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 6]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifi.isFeatureSupported param#6 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01590",
    "wifi",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 7]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifi.isFeatureSupported param#7 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01591",
    "wifi",
    "enableHotspot",
    "param",
    buildParams([]),
    [],
    "ANY",
    "void",
    "none",
    false,
    "wifi.enableHotspot param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01592",
    "wifi",
    "disableHotspot",
    "param",
    buildParams([]),
    [],
    "ANY",
    "void",
    "none",
    false,
    "wifi.disableHotspot param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01593",
    "wifi",
    "isHotspotActive",
    "param",
    buildParams([]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifi.isHotspotActive param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01594",
    "wifi",
    "getHotspotConfig",
    "param",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    false,
    "wifi.getHotspotConfig param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01595",
    "wifi",
    "getP2pPeerDevices",
    "param",
    buildParams([]),
    [],
    "ANY",
    "array",
    "none",
    true,
    "wifi.getP2pPeerDevices param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01596",
    "wifi",
    "startDiscoverDevices",
    "param",
    buildParams([]),
    [],
    "ANY",
    "void",
    "none",
    false,
    "wifi.startDiscoverDevices param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_P_01597",
    "wifi",
    "stopDiscoverDevices",
    "param",
    buildParams([]),
    [],
    "ANY",
    "void",
    "none",
    false,
    "wifi.stopDiscoverDevices param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WF_R_01598",
    "wifi",
    "isWifiActive",
    "return",
    buildParams([]),
    [],
    "WIFI_ON",
    "boolean",
    "none",
    true,
    "wifi.isWifiActive return_type_check variant=0 expect=boolean"
  ),
  makeApiTestCase(
    "WF_R_01599",
    "wifi",
    "isWifiActive",
    "return",
    buildParams([]),
    [],
    "WIFI_ON",
    "boolean",
    "none",
    true,
    "wifi.isWifiActive return_type_check variant=1 expect=boolean"
  ),
  makeApiTestCase(
    "WF_R_01600",
    "wifi",
    "isWifiActive",
    "return",
    buildParams([]),
    [],
    "WIFI_ON",
    "boolean",
    "none",
    true,
    "wifi.isWifiActive return_type_check variant=2 expect=boolean"
  ),
];
