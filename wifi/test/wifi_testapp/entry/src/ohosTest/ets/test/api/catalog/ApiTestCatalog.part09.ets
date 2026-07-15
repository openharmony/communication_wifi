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

export const APITESTCATALOG_PART09: ApiTestCase[] = [
  makeApiTestCase(
    "WM_CB_00801",
    "wifiManager",
    "getScanInfoList",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "isWifiActive",
      "scan",
      "getScanInfoList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#0 var#1 -> getScanInfoList"
  ),
  makeApiTestCase(
    "WM_CB_00802",
    "wifiManager",
    "getScanInfoList",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "isWifiActive",
      "scan",
      "getScanInfoList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#0 var#2 -> getScanInfoList"
  ),
  makeApiTestCase(
    "WM_CB_00803",
    "wifiManager",
    "getScanInfoList",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "isWifiActive",
      "scan",
      "getScanInfoList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#0 var#3 -> getScanInfoList"
  ),
  makeApiTestCase(
    "WM_CB_00804",
    "wifiManager",
    "getScanInfoList",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "isWifiActive",
      "scan",
      "getScanInfoList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#0 var#4 -> getScanInfoList"
  ),
  makeApiTestCase(
    "WM_CB_00805",
    "wifiManager",
    "getScanInfoList",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "isWifiActive",
      "scan",
      "getScanInfoList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#0 var#5 -> getScanInfoList"
  ),
  makeApiTestCase(
    "WM_CB_00806",
    "wifiManager",
    "getScanInfoList",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "isWifiActive",
      "scan",
      "getScanInfoList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#0 var#6 -> getScanInfoList"
  ),
  makeApiTestCase(
    "WM_CB_00807",
    "wifiManager",
    "getScanInfoList",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "isWifiActive",
      "scan",
      "getScanInfoList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#0 var#7 -> getScanInfoList"
  ),
  makeApiTestCase(
    "WM_CB_00808",
    "wifiManager",
    "getWifiDetailState",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "startScan",
      "getScanResultsSync",
      "getWifiDetailState"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#1 var#0 -> getWifiDetailState"
  ),
  makeApiTestCase(
    "WM_CB_00809",
    "wifiManager",
    "getWifiDetailState",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "startScan",
      "getScanResultsSync",
      "getWifiDetailState"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#1 var#1 -> getWifiDetailState"
  ),
  makeApiTestCase(
    "WM_CB_00810",
    "wifiManager",
    "getWifiDetailState",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "startScan",
      "getScanResultsSync",
      "getWifiDetailState"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#1 var#2 -> getWifiDetailState"
  ),
  makeApiTestCase(
    "WM_CB_00811",
    "wifiManager",
    "getWifiDetailState",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "startScan",
      "getScanResultsSync",
      "getWifiDetailState"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#1 var#3 -> getWifiDetailState"
  ),
  makeApiTestCase(
    "WM_CB_00812",
    "wifiManager",
    "getWifiDetailState",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "startScan",
      "getScanResultsSync",
      "getWifiDetailState"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#1 var#4 -> getWifiDetailState"
  ),
  makeApiTestCase(
    "WM_CB_00813",
    "wifiManager",
    "getWifiDetailState",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "startScan",
      "getScanResultsSync",
      "getWifiDetailState"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#1 var#5 -> getWifiDetailState"
  ),
  makeApiTestCase(
    "WM_CB_00814",
    "wifiManager",
    "getWifiDetailState",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "startScan",
      "getScanResultsSync",
      "getWifiDetailState"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#1 var#6 -> getWifiDetailState"
  ),
  makeApiTestCase(
    "WM_CB_00815",
    "wifiManager",
    "getWifiDetailState",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "startScan",
      "getScanResultsSync",
      "getWifiDetailState"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#1 var#7 -> getWifiDetailState"
  ),
  makeApiTestCase(
    "WM_CB_00816",
    "wifiManager",
    "getCountryCode",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getSupportedFeatures",
      "isFeatureSupported",
      "getCountryCode"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#2 var#0 -> getCountryCode"
  ),
  makeApiTestCase(
    "WM_CB_00817",
    "wifiManager",
    "getCountryCode",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "getSupportedFeatures",
      "isFeatureSupported",
      "getCountryCode"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#2 var#1 -> getCountryCode"
  ),
  makeApiTestCase(
    "WM_CB_00818",
    "wifiManager",
    "getCountryCode",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "getSupportedFeatures",
      "isFeatureSupported",
      "getCountryCode"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#2 var#2 -> getCountryCode"
  ),
  makeApiTestCase(
    "WM_CB_00819",
    "wifiManager",
    "getCountryCode",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "getSupportedFeatures",
      "isFeatureSupported",
      "getCountryCode"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#2 var#3 -> getCountryCode"
  ),
  makeApiTestCase(
    "WM_CB_00820",
    "wifiManager",
    "getCountryCode",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "getSupportedFeatures",
      "isFeatureSupported",
      "getCountryCode"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#2 var#4 -> getCountryCode"
  ),
  makeApiTestCase(
    "WM_CB_00821",
    "wifiManager",
    "getCountryCode",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "getSupportedFeatures",
      "isFeatureSupported",
      "getCountryCode"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#2 var#5 -> getCountryCode"
  ),
  makeApiTestCase(
    "WM_CB_00822",
    "wifiManager",
    "getCountryCode",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "getSupportedFeatures",
      "isFeatureSupported",
      "getCountryCode"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#2 var#6 -> getCountryCode"
  ),
  makeApiTestCase(
    "WM_CB_00823",
    "wifiManager",
    "getCountryCode",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "getSupportedFeatures",
      "isFeatureSupported",
      "getCountryCode"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#2 var#7 -> getCountryCode"
  ),
  makeApiTestCase(
    "WM_CB_00824",
    "wifiManager",
    "getIpv6Info",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getDeviceMacAddress",
      "getIpInfo",
      "getIpv6Info"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#3 var#0 -> getIpv6Info"
  ),
  makeApiTestCase(
    "WM_CB_00825",
    "wifiManager",
    "getIpv6Info",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "getDeviceMacAddress",
      "getIpInfo",
      "getIpv6Info"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#3 var#1 -> getIpv6Info"
  ),
  makeApiTestCase(
    "WM_CB_00826",
    "wifiManager",
    "getIpv6Info",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "getDeviceMacAddress",
      "getIpInfo",
      "getIpv6Info"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#3 var#2 -> getIpv6Info"
  ),
  makeApiTestCase(
    "WM_CB_00827",
    "wifiManager",
    "getIpv6Info",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "getDeviceMacAddress",
      "getIpInfo",
      "getIpv6Info"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#3 var#3 -> getIpv6Info"
  ),
  makeApiTestCase(
    "WM_CB_00828",
    "wifiManager",
    "getIpv6Info",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "getDeviceMacAddress",
      "getIpInfo",
      "getIpv6Info"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#3 var#4 -> getIpv6Info"
  ),
  makeApiTestCase(
    "WM_CB_00829",
    "wifiManager",
    "getIpv6Info",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "getDeviceMacAddress",
      "getIpInfo",
      "getIpv6Info"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#3 var#5 -> getIpv6Info"
  ),
  makeApiTestCase(
    "WM_CB_00830",
    "wifiManager",
    "getIpv6Info",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "getDeviceMacAddress",
      "getIpInfo",
      "getIpv6Info"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#3 var#6 -> getIpv6Info"
  ),
  makeApiTestCase(
    "WM_CB_00831",
    "wifiManager",
    "getIpv6Info",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "getDeviceMacAddress",
      "getIpInfo",
      "getIpv6Info"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#3 var#7 -> getIpv6Info"
  ),
  makeApiTestCase(
    "WM_CB_00832",
    "wifiManager",
    "getDisconnectedReason",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getLinkedInfoSync",
      "isConnected",
      "getDisconnectedReason"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#4 var#0 -> getDisconnectedReason"
  ),
  makeApiTestCase(
    "WM_CB_00833",
    "wifiManager",
    "getDisconnectedReason",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "getLinkedInfoSync",
      "isConnected",
      "getDisconnectedReason"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#4 var#1 -> getDisconnectedReason"
  ),
  makeApiTestCase(
    "WM_CB_00834",
    "wifiManager",
    "getDisconnectedReason",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "getLinkedInfoSync",
      "isConnected",
      "getDisconnectedReason"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#4 var#2 -> getDisconnectedReason"
  ),
  makeApiTestCase(
    "WM_CB_00835",
    "wifiManager",
    "getDisconnectedReason",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "getLinkedInfoSync",
      "isConnected",
      "getDisconnectedReason"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#4 var#3 -> getDisconnectedReason"
  ),
  makeApiTestCase(
    "WM_CB_00836",
    "wifiManager",
    "getDisconnectedReason",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "getLinkedInfoSync",
      "isConnected",
      "getDisconnectedReason"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#4 var#4 -> getDisconnectedReason"
  ),
  makeApiTestCase(
    "WM_CB_00837",
    "wifiManager",
    "getDisconnectedReason",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "getLinkedInfoSync",
      "isConnected",
      "getDisconnectedReason"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#4 var#5 -> getDisconnectedReason"
  ),
  makeApiTestCase(
    "WM_CB_00838",
    "wifiManager",
    "getDisconnectedReason",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "getLinkedInfoSync",
      "isConnected",
      "getDisconnectedReason"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#4 var#6 -> getDisconnectedReason"
  ),
  makeApiTestCase(
    "WM_CB_00839",
    "wifiManager",
    "getDisconnectedReason",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "getLinkedInfoSync",
      "isConnected",
      "getDisconnectedReason"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#4 var#7 -> getDisconnectedReason"
  ),
  makeApiTestCase(
    "WM_CB_00840",
    "wifiManager",
    "getScanAlwaysAllowed",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getCandidateConfigs",
      "getDeviceConfigs",
      "getScanAlwaysAllowed"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#5 var#0 -> getScanAlwaysAllowed"
  ),
  makeApiTestCase(
    "WM_CB_00841",
    "wifiManager",
    "getScanAlwaysAllowed",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "getCandidateConfigs",
      "getDeviceConfigs",
      "getScanAlwaysAllowed"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#5 var#1 -> getScanAlwaysAllowed"
  ),
  makeApiTestCase(
    "WM_CB_00842",
    "wifiManager",
    "getScanAlwaysAllowed",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "getCandidateConfigs",
      "getDeviceConfigs",
      "getScanAlwaysAllowed"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#5 var#2 -> getScanAlwaysAllowed"
  ),
  makeApiTestCase(
    "WM_CB_00843",
    "wifiManager",
    "getScanAlwaysAllowed",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "getCandidateConfigs",
      "getDeviceConfigs",
      "getScanAlwaysAllowed"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#5 var#3 -> getScanAlwaysAllowed"
  ),
  makeApiTestCase(
    "WM_CB_00844",
    "wifiManager",
    "getScanAlwaysAllowed",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "getCandidateConfigs",
      "getDeviceConfigs",
      "getScanAlwaysAllowed"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#5 var#4 -> getScanAlwaysAllowed"
  ),
  makeApiTestCase(
    "WM_CB_00845",
    "wifiManager",
    "getScanAlwaysAllowed",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "getCandidateConfigs",
      "getDeviceConfigs",
      "getScanAlwaysAllowed"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#5 var#5 -> getScanAlwaysAllowed"
  ),
  makeApiTestCase(
    "WM_CB_00846",
    "wifiManager",
    "getScanAlwaysAllowed",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "getCandidateConfigs",
      "getDeviceConfigs",
      "getScanAlwaysAllowed"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#5 var#6 -> getScanAlwaysAllowed"
  ),
  makeApiTestCase(
    "WM_CB_00847",
    "wifiManager",
    "getScanAlwaysAllowed",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "getCandidateConfigs",
      "getDeviceConfigs",
      "getScanAlwaysAllowed"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#5 var#7 -> getScanAlwaysAllowed"
  ),
  makeApiTestCase(
    "WM_CB_00848",
    "wifiManager",
    "startScan",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "setScanAlwaysAllowed",
      "getScanAlwaysAllowed",
      "startScan"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#6 var#0 -> startScan"
  ),
  makeApiTestCase(
    "WM_CB_00849",
    "wifiManager",
    "startScan",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "setScanAlwaysAllowed",
      "getScanAlwaysAllowed",
      "startScan"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#6 var#1 -> startScan"
  ),
  makeApiTestCase(
    "WM_CB_00850",
    "wifiManager",
    "startScan",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "setScanAlwaysAllowed",
      "getScanAlwaysAllowed",
      "startScan"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#6 var#2 -> startScan"
  ),
  makeApiTestCase(
    "WM_CB_00851",
    "wifiManager",
    "startScan",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "setScanAlwaysAllowed",
      "getScanAlwaysAllowed",
      "startScan"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#6 var#3 -> startScan"
  ),
  makeApiTestCase(
    "WM_CB_00852",
    "wifiManager",
    "startScan",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "setScanAlwaysAllowed",
      "getScanAlwaysAllowed",
      "startScan"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#6 var#4 -> startScan"
  ),
  makeApiTestCase(
    "WM_CB_00853",
    "wifiManager",
    "startScan",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "setScanAlwaysAllowed",
      "getScanAlwaysAllowed",
      "startScan"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#6 var#5 -> startScan"
  ),
  makeApiTestCase(
    "WM_CB_00854",
    "wifiManager",
    "startScan",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "setScanAlwaysAllowed",
      "getScanAlwaysAllowed",
      "startScan"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#6 var#6 -> startScan"
  ),
  makeApiTestCase(
    "WM_CB_00855",
    "wifiManager",
    "startScan",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "setScanAlwaysAllowed",
      "getScanAlwaysAllowed",
      "startScan"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#6 var#7 -> startScan"
  ),
  makeApiTestCase(
    "WM_CB_00856",
    "wifiManager",
    "getSignalLevel",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getMultiLinkedInfo",
      "getLinkedInfoSync",
      "getSignalLevel"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#7 var#0 -> getSignalLevel"
  ),
  makeApiTestCase(
    "WM_CB_00857",
    "wifiManager",
    "getSignalLevel",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "getMultiLinkedInfo",
      "getLinkedInfoSync",
      "getSignalLevel"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#7 var#1 -> getSignalLevel"
  ),
  makeApiTestCase(
    "WM_CB_00858",
    "wifiManager",
    "getSignalLevel",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "getMultiLinkedInfo",
      "getLinkedInfoSync",
      "getSignalLevel"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#7 var#2 -> getSignalLevel"
  ),
  makeApiTestCase(
    "WM_CB_00859",
    "wifiManager",
    "getSignalLevel",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "getMultiLinkedInfo",
      "getLinkedInfoSync",
      "getSignalLevel"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#7 var#3 -> getSignalLevel"
  ),
  makeApiTestCase(
    "WM_CB_00860",
    "wifiManager",
    "getSignalLevel",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "getMultiLinkedInfo",
      "getLinkedInfoSync",
      "getSignalLevel"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#7 var#4 -> getSignalLevel"
  ),
  makeApiTestCase(
    "WM_CB_00861",
    "wifiManager",
    "getSignalLevel",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "getMultiLinkedInfo",
      "getLinkedInfoSync",
      "getSignalLevel"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#7 var#5 -> getSignalLevel"
  ),
  makeApiTestCase(
    "WM_CB_00862",
    "wifiManager",
    "getSignalLevel",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "getMultiLinkedInfo",
      "getLinkedInfoSync",
      "getSignalLevel"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#7 var#6 -> getSignalLevel"
  ),
  makeApiTestCase(
    "WM_CB_00863",
    "wifiManager",
    "getSignalLevel",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "getMultiLinkedInfo",
      "getLinkedInfoSync",
      "getSignalLevel"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#7 var#7 -> getSignalLevel"
  ),
  makeApiTestCase(
    "WM_CB_00864",
    "wifiManager",
    "isBandTypeSupported",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isRandomMacDisabled",
      "get5GChannelList",
      "isBandTypeSupported"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#8 var#0 -> isBandTypeSupported"
  ),
  makeApiTestCase(
    "WM_CB_00865",
    "wifiManager",
    "isBandTypeSupported",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "isRandomMacDisabled",
      "get5GChannelList",
      "isBandTypeSupported"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#8 var#1 -> isBandTypeSupported"
  ),
  makeApiTestCase(
    "WM_CB_00866",
    "wifiManager",
    "isBandTypeSupported",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "isRandomMacDisabled",
      "get5GChannelList",
      "isBandTypeSupported"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#8 var#2 -> isBandTypeSupported"
  ),
  makeApiTestCase(
    "WM_CB_00867",
    "wifiManager",
    "isBandTypeSupported",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "isRandomMacDisabled",
      "get5GChannelList",
      "isBandTypeSupported"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#8 var#3 -> isBandTypeSupported"
  ),
  makeApiTestCase(
    "WM_CB_00868",
    "wifiManager",
    "isBandTypeSupported",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "isRandomMacDisabled",
      "get5GChannelList",
      "isBandTypeSupported"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#8 var#4 -> isBandTypeSupported"
  ),
  makeApiTestCase(
    "WM_CB_00869",
    "wifiManager",
    "isBandTypeSupported",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "isRandomMacDisabled",
      "get5GChannelList",
      "isBandTypeSupported"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#8 var#5 -> isBandTypeSupported"
  ),
  makeApiTestCase(
    "WM_CB_00870",
    "wifiManager",
    "isBandTypeSupported",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "isRandomMacDisabled",
      "get5GChannelList",
      "isBandTypeSupported"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#8 var#6 -> isBandTypeSupported"
  ),
  makeApiTestCase(
    "WM_CB_00871",
    "wifiManager",
    "isBandTypeSupported",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "isRandomMacDisabled",
      "get5GChannelList",
      "isBandTypeSupported"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#8 var#7 -> isBandTypeSupported"
  ),
  makeApiTestCase(
    "WM_CB_00872",
    "wifiManager",
    "isWifiActive",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "startWifiDetection",
      "getWifiDetailState",
      "isWifiActive"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#9 var#0 -> isWifiActive"
  ),
  makeApiTestCase(
    "WM_CB_00873",
    "wifiManager",
    "isWifiActive",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "startWifiDetection",
      "getWifiDetailState",
      "isWifiActive"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#9 var#1 -> isWifiActive"
  ),
  makeApiTestCase(
    "WM_CB_00874",
    "wifiManager",
    "isWifiActive",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "startWifiDetection",
      "getWifiDetailState",
      "isWifiActive"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#9 var#2 -> isWifiActive"
  ),
  makeApiTestCase(
    "WM_CB_00875",
    "wifiManager",
    "isWifiActive",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "startWifiDetection",
      "getWifiDetailState",
      "isWifiActive"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#9 var#3 -> isWifiActive"
  ),
  makeApiTestCase(
    "WM_CB_00876",
    "wifiManager",
    "isWifiActive",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "startWifiDetection",
      "getWifiDetailState",
      "isWifiActive"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#9 var#4 -> isWifiActive"
  ),
  makeApiTestCase(
    "WM_CB_00877",
    "wifiManager",
    "isWifiActive",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "startWifiDetection",
      "getWifiDetailState",
      "isWifiActive"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#9 var#5 -> isWifiActive"
  ),
  makeApiTestCase(
    "WM_CB_00878",
    "wifiManager",
    "isWifiActive",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "startWifiDetection",
      "getWifiDetailState",
      "isWifiActive"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#9 var#6 -> isWifiActive"
  ),
  makeApiTestCase(
    "WM_CB_00879",
    "wifiManager",
    "isWifiActive",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "startWifiDetection",
      "getWifiDetailState",
      "isWifiActive"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#9 var#7 -> isWifiActive"
  ),
  makeApiTestCase(
    "WM_CB_00880",
    "wifiManager",
    "getHotspotConfig",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "enableHotspot",
      "isHotspotActive",
      "getHotspotConfig"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#10 var#0 -> getHotspotConfig"
  ),
  makeApiTestCase(
    "WM_CB_00881",
    "wifiManager",
    "getHotspotConfig",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "enableHotspot",
      "isHotspotActive",
      "getHotspotConfig"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#10 var#1 -> getHotspotConfig"
  ),
  makeApiTestCase(
    "WM_CB_00882",
    "wifiManager",
    "getHotspotConfig",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "enableHotspot",
      "isHotspotActive",
      "getHotspotConfig"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#10 var#2 -> getHotspotConfig"
  ),
  makeApiTestCase(
    "WM_CB_00883",
    "wifiManager",
    "getHotspotConfig",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "enableHotspot",
      "isHotspotActive",
      "getHotspotConfig"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#10 var#3 -> getHotspotConfig"
  ),
  makeApiTestCase(
    "WM_CB_00884",
    "wifiManager",
    "getHotspotConfig",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "enableHotspot",
      "isHotspotActive",
      "getHotspotConfig"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#10 var#4 -> getHotspotConfig"
  ),
  makeApiTestCase(
    "WM_CB_00885",
    "wifiManager",
    "getHotspotConfig",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "enableHotspot",
      "isHotspotActive",
      "getHotspotConfig"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#10 var#5 -> getHotspotConfig"
  ),
  makeApiTestCase(
    "WM_CB_00886",
    "wifiManager",
    "getHotspotConfig",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "enableHotspot",
      "isHotspotActive",
      "getHotspotConfig"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#10 var#6 -> getHotspotConfig"
  ),
  makeApiTestCase(
    "WM_CB_00887",
    "wifiManager",
    "getHotspotConfig",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "enableHotspot",
      "isHotspotActive",
      "getHotspotConfig"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#10 var#7 -> getHotspotConfig"
  ),
  makeApiTestCase(
    "WM_CB_00888",
    "wifiManager",
    "disableHotspot",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "enableHotspot",
      "getStations",
      "disableHotspot"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#11 var#0 -> disableHotspot"
  ),
  makeApiTestCase(
    "WM_CB_00889",
    "wifiManager",
    "disableHotspot",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "enableHotspot",
      "getStations",
      "disableHotspot"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#11 var#1 -> disableHotspot"
  ),
  makeApiTestCase(
    "WM_CB_00890",
    "wifiManager",
    "disableHotspot",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "enableHotspot",
      "getStations",
      "disableHotspot"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#11 var#2 -> disableHotspot"
  ),
  makeApiTestCase(
    "WM_CB_00891",
    "wifiManager",
    "disableHotspot",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "enableHotspot",
      "getStations",
      "disableHotspot"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#11 var#3 -> disableHotspot"
  ),
  makeApiTestCase(
    "WM_CB_00892",
    "wifiManager",
    "disableHotspot",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "enableHotspot",
      "getStations",
      "disableHotspot"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#11 var#4 -> disableHotspot"
  ),
  makeApiTestCase(
    "WM_CB_00893",
    "wifiManager",
    "disableHotspot",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "enableHotspot",
      "getStations",
      "disableHotspot"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#11 var#5 -> disableHotspot"
  ),
  makeApiTestCase(
    "WM_CB_00894",
    "wifiManager",
    "disableHotspot",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "enableHotspot",
      "getStations",
      "disableHotspot"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#11 var#6 -> disableHotspot"
  ),
  makeApiTestCase(
    "WM_CB_00895",
    "wifiManager",
    "disableHotspot",
    "combo",
    buildParams([
