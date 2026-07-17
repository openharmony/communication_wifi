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

export const APITESTCATALOG_PART01: ApiTestCase[] = [
  makeApiTestCase(
    "WM_P_00001",
    "wifiManager",
    "enableWifi",
    "param",
    buildParams([]),
    [],
    "WIFI_OFF",
    "void",
    "none",
    false,
    "wifiManager.enableWifi param#0 precond=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_P_00002",
    "wifiManager",
    "enableWifi",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "void",
    "none",
    false,
    "wifiManager.enableWifi param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00003",
    "wifiManager",
    "disableWifi",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "void",
    "none",
    false,
    "wifiManager.disableWifi param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00004",
    "wifiManager",
    "disableWifi",
    "param",
    buildParams([]),
    [],
    "WIFI_OFF",
    "void",
    "none",
    false,
    "wifiManager.disableWifi param#0 precond=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_P_00005",
    "wifiManager",
    "enableSemiWifi",
    "param",
    buildParams([]),
    [],
    "WIFI_OFF",
    "void",
    "none",
    false,
    "wifiManager.enableSemiWifi param#0 precond=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_P_00006",
    "wifiManager",
    "enableSemiWifi",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "void",
    "none",
    false,
    "wifiManager.enableSemiWifi param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00007",
    "wifiManager",
    "isWifiActive",
    "param",
    buildParams([]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifiManager.isWifiActive param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00008",
    "wifiManager",
    "isWifiActive",
    "param",
    buildParams([]),
    [],
    "WIFI_OFF",
    "boolean",
    "none",
    false,
    "wifiManager.isWifiActive param#0 precond=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_P_00009",
    "wifiManager",
    "isWifiActive",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "boolean",
    "none",
    false,
    "wifiManager.isWifiActive param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00010",
    "wifiManager",
    "scan",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "wifiManager.scan param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00011",
    "wifiManager",
    "startScan",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "wifiManager.startScan param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00012",
    "wifiManager",
    "getScanInfoList",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "array",
    "not_empty",
    false,
    "wifiManager.getScanInfoList param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00013",
    "wifiManager",
    "getScanInfoList",
    "param",
    buildParams([]),
    [],
    "WIFI_ON_SCAN",
    "array",
    "not_empty",
    false,
    "wifiManager.getScanInfoList param#0 precond=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_P_00014",
    "wifiManager",
    "getScanResultsSync",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "array",
    "not_empty",
    false,
    "wifiManager.getScanResultsSync param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00015",
    "wifiManager",
    "getScanResultsSync",
    "param",
    buildParams([]),
    [],
    "WIFI_ON_SCAN",
    "array",
    "not_empty",
    false,
    "wifiManager.getScanResultsSync param#0 precond=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "WM_P_00016",
    "wifiManager",
    "getWifiDetailState",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "number",
    "non_negative",
    false,
    "wifiManager.getWifiDetailState param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00017",
    "wifiManager",
    "getWifiDetailState",
    "param",
    buildParams([]),
    [],
    "WIFI_OFF",
    "number",
    "non_negative",
    false,
    "wifiManager.getWifiDetailState param#0 precond=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_P_00018",
    "wifiManager",
    "setScanAlwaysAllowed",
    "param",
    buildParams([
      ["allowed", true]
    ]),
    [],
    "ANY",
    "void",
    "none",
    false,
    "wifiManager.setScanAlwaysAllowed param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00019",
    "wifiManager",
    "setScanAlwaysAllowed",
    "param",
    buildParams([
      ["allowed", false]
    ]),
    [],
    "ANY",
    "void",
    "none",
    false,
    "wifiManager.setScanAlwaysAllowed param#1 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00020",
    "wifiManager",
    "getScanAlwaysAllowed",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "boolean",
    "none",
    false,
    "wifiManager.getScanAlwaysAllowed param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00021",
    "wifiManager",
    "getCandidateConfigs",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "array",
    "none",
    false,
    "wifiManager.getCandidateConfigs param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00022",
    "wifiManager",
    "connectToNetwork",
    "param",
    buildParams([
      ["netId", 0]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.connectToNetwork param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00023",
    "wifiManager",
    "connectToNetwork",
    "param",
    buildParams([
      ["netId", -1]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.connectToNetwork param#1 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00024",
    "wifiManager",
    "connectToNetwork",
    "param",
    buildParams([
      ["netId", 99999]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.connectToNetwork param#2 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00025",
    "wifiManager",
    "disconnect",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "wifiManager.disconnect param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00026",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -100],
      ["band", 1]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00027",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -100],
      ["band", 2]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#1 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00028",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -100],
      ["band", 3]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#2 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00029",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -80],
      ["band", 1]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#3 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00030",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -80],
      ["band", 2]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#4 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00031",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -80],
      ["band", 3]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#5 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00032",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -60],
      ["band", 1]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#6 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00033",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -60],
      ["band", 2]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#7 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00034",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -60],
      ["band", 3]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#8 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00035",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -40],
      ["band", 1]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#9 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00036",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -40],
      ["band", 2]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#10 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00037",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -40],
      ["band", 3]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#11 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00038",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -20],
      ["band", 1]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#12 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00039",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -20],
      ["band", 2]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#13 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00040",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", -20],
      ["band", 3]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#14 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00041",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 0],
      ["band", 1]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#15 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00042",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 0],
      ["band", 2]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#16 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00043",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 0],
      ["band", 3]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#17 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00044",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 20],
      ["band", 1]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#18 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00045",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 20],
      ["band", 2]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#19 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00046",
    "wifiManager",
    "getSignalLevel",
    "param",
    buildParams([
      ["rssi", 20],
      ["band", 3]
    ]),
    [],
    "ANY",
    "number",
    "range_0_4",
    false,
    "wifiManager.getSignalLevel param#20 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00047",
    "wifiManager",
    "getLinkedInfoSync",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "object",
    "none",
    false,
    "wifiManager.getLinkedInfoSync param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00048",
    "wifiManager",
    "getMultiLinkedInfo",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "array",
    "none",
    true,
    "wifiManager.getMultiLinkedInfo param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00049",
    "wifiManager",
    "isConnected",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "boolean",
    "none",
    false,
    "wifiManager.isConnected param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00050",
    "wifiManager",
    "isConnected",
    "param",
    buildParams([]),
    [],
    "WIFI_OFF",
    "boolean",
    "none",
    false,
    "wifiManager.isConnected param#0 precond=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_P_00051",
    "wifiManager",
    "getSupportedFeatures",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "number",
    "non_negative",
    false,
    "wifiManager.getSupportedFeatures param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00052",
    "wifiManager",
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
    "wifiManager.isFeatureSupported param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00053",
    "wifiManager",
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
    "wifiManager.isFeatureSupported param#1 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00054",
    "wifiManager",
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
    "wifiManager.isFeatureSupported param#2 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00055",
    "wifiManager",
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
    "wifiManager.isFeatureSupported param#3 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00056",
    "wifiManager",
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
    "wifiManager.isFeatureSupported param#4 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00057",
    "wifiManager",
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
    "wifiManager.isFeatureSupported param#5 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00058",
    "wifiManager",
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
    "wifiManager.isFeatureSupported param#6 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00059",
    "wifiManager",
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
    "wifiManager.isFeatureSupported param#7 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00060",
    "wifiManager",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 8]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifiManager.isFeatureSupported param#8 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00061",
    "wifiManager",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 9]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifiManager.isFeatureSupported param#9 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00062",
    "wifiManager",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 10]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifiManager.isFeatureSupported param#10 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00063",
    "wifiManager",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 11]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifiManager.isFeatureSupported param#11 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00064",
    "wifiManager",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 12]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifiManager.isFeatureSupported param#12 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00065",
    "wifiManager",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 13]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifiManager.isFeatureSupported param#13 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00066",
    "wifiManager",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 14]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifiManager.isFeatureSupported param#14 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00067",
    "wifiManager",
    "isFeatureSupported",
    "param",
    buildParams([
      ["featureId", 15]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    false,
    "wifiManager.isFeatureSupported param#15 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00068",
    "wifiManager",
    "getDeviceMacAddress",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "array",
    "none",
    true,
    "wifiManager.getDeviceMacAddress param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00069",
    "wifiManager",
    "getIpInfo",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "object",
    "none",
    false,
    "wifiManager.getIpInfo param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00070",
    "wifiManager",
    "getIpv6Info",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "object",
    "none",
    false,
    "wifiManager.getIpv6Info param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00071",
    "wifiManager",
    "getCountryCode",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "string",
    "not_empty_string",
    false,
    "wifiManager.getCountryCode param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00072",
    "wifiManager",
    "reassociate",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "wifiManager.reassociate param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00073",
    "wifiManager",
    "reconnect",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "wifiManager.reconnect param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00074",
    "wifiManager",
    "getDeviceConfigs",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "array",
    "none",
    false,
    "wifiManager.getDeviceConfigs param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00075",
    "wifiManager",
    "allowAutoConnect",
    "param",
    buildParams([
      ["netId", 0],
      ["isAllowed", true]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.allowAutoConnect param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00076",
    "wifiManager",
    "allowAutoConnect",
    "param",
    buildParams([
      ["netId", 0],
      ["isAllowed", false]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.allowAutoConnect param#1 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00077",
    "wifiManager",
    "allowAutoConnect",
    "param",
    buildParams([
      ["netId", -1],
      ["isAllowed", false]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.allowAutoConnect param#2 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00078",
    "wifiManager",
    "disableNetwork",
    "param",
    buildParams([
      ["netId", 0]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.disableNetwork param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00079",
    "wifiManager",
    "disableNetwork",
    "param",
    buildParams([
      ["netId", -1]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.disableNetwork param#1 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00080",
    "wifiManager",
    "disableNetwork",
    "param",
    buildParams([
      ["netId", 0],
      ["blockDuration", 0]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.disableNetwork param#2 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00081",
    "wifiManager",
    "disableNetwork",
    "param",
    buildParams([
      ["netId", 0],
      ["blockDuration", 3600]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.disableNetwork param#3 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00082",
    "wifiManager",
    "disableNetwork",
    "param",
    buildParams([
      ["netId", 0],
      ["blockDuration", -1]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.disableNetwork param#4 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00083",
    "wifiManager",
    "removeAllNetwork",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "wifiManager.removeAllNetwork param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00084",
    "wifiManager",
    "removeDevice",
    "param",
    buildParams([
      ["id", 0]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.removeDevice param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00085",
    "wifiManager",
    "removeDevice",
    "param",
    buildParams([
      ["id", -1]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.removeDevice param#1 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00086",
    "wifiManager",
    "removeDevice",
    "param",
    buildParams([
      ["id", 99999]
    ]),
    [],
    "ANY",
    "void",
    "none",
    true,
    "wifiManager.removeDevice param#2 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00087",
    "wifiManager",
    "isBandTypeSupported",
    "param",
    buildParams([
      ["bandType", 0]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    true,
    "wifiManager.isBandTypeSupported param#0 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00088",
    "wifiManager",
    "isBandTypeSupported",
    "param",
    buildParams([
      ["bandType", 1]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    true,
    "wifiManager.isBandTypeSupported param#1 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00089",
    "wifiManager",
    "isBandTypeSupported",
    "param",
    buildParams([
      ["bandType", 2]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    true,
    "wifiManager.isBandTypeSupported param#2 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00090",
    "wifiManager",
    "isBandTypeSupported",
    "param",
    buildParams([
      ["bandType", 3]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    true,
    "wifiManager.isBandTypeSupported param#3 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00091",
    "wifiManager",
    "isBandTypeSupported",
    "param",
    buildParams([
      ["bandType", 4]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    true,
    "wifiManager.isBandTypeSupported param#4 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00092",
    "wifiManager",
    "isBandTypeSupported",
    "param",
    buildParams([
      ["bandType", 5]
    ]),
    [],
    "ANY",
    "boolean",
    "none",
    true,
    "wifiManager.isBandTypeSupported param#5 precond=ANY"
  ),
  makeApiTestCase(
    "WM_P_00093",
    "wifiManager",
    "get5GChannelList",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "array",
    "none",
    true,
    "wifiManager.get5GChannelList param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00094",
    "wifiManager",
    "getDisconnectedReason",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "wifiManager.getDisconnectedReason param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00095",
    "wifiManager",
    "getDisconnectedReason",
    "param",
    buildParams([]),
    [],
    "WIFI_OFF",
    "number",
    "none",
    true,
    "wifiManager.getDisconnectedReason param#0 precond=WIFI_OFF"
  ),
  makeApiTestCase(
    "WM_P_00096",
    "wifiManager",
    "startPortalCertification",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "wifiManager.startPortalCertification param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00097",
    "wifiManager",
    "startWifiDetection",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "wifiManager.startWifiDetection param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00098",
    "wifiManager",
    "isRandomMacDisabled",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "boolean",
    "none",
    false,
    "wifiManager.isRandomMacDisabled param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00099",
    "wifiManager",
    "isMeteredHotspot",
    "param",
    buildParams([]),
    [],
    "WIFI_ON",
    "boolean",
    "none",
    true,
    "wifiManager.isMeteredHotspot param#0 precond=WIFI_ON"
  ),
  makeApiTestCase(
    "WM_P_00100",
    "wifiManager",
    "isMeteredHotspot",
    "param",
    buildParams([]),
    [],
    "HOTSPOT_ON",
    "boolean",
    "none",
    true,
    "wifiManager.isMeteredHotspot param#0 precond=HOTSPOT_ON"
  ),
];
