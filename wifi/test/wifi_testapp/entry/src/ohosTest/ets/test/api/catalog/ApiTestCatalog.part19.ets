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

export const APITESTCATALOG_PART19: ApiTestCase[] = [
  makeApiTestCase(
    "WF_CB_01801",
    "wifi",
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
    "WF_CB_01802",
    "wifi",
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
    "WF_CB_01803",
    "wifi",
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
    "WF_CB_01804",
    "wifi",
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
    "WF_CB_01805",
    "wifi",
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
    "WF_CB_01806",
    "wifi",
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
    "WF_CB_01807",
    "wifi",
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
    "WF_CB_01808",
    "wifi",
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
    "WF_CB_01809",
    "wifi",
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
    "WF_CB_01810",
    "wifi",
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
    "WF_CB_01811",
    "wifi",
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
    "WF_CB_01812",
    "wifi",
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
    "WF_CB_01813",
    "wifi",
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
    "WF_CB_01814",
    "wifi",
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
    "WF_CB_01815",
    "wifi",
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
    "WF_CB_01816",
    "wifi",
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
    "WF_CB_01817",
    "wifi",
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
    "WF_CB_01818",
    "wifi",
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
    "WF_CB_01819",
    "wifi",
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
    "WF_CB_01820",
    "wifi",
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
    "WF_CB_01821",
    "wifi",
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
    "WF_CB_01822",
    "wifi",
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
    "WF_CB_01823",
    "wifi",
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
    "WF_CB_01824",
    "wifi",
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
    "WF_CB_01825",
    "wifi",
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
    "WF_CB_01826",
    "wifi",
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
    "WF_CB_01827",
    "wifi",
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
    "WF_CB_01828",
    "wifi",
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
    "WF_CB_01829",
    "wifi",
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
    "WF_CB_01830",
    "wifi",
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
    "WF_CB_01831",
    "wifi",
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
    "WF_CB_01832",
    "wifi",
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
    "WF_CB_01833",
    "wifi",
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
    "WF_CB_01834",
    "wifi",
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
    "WF_CB_01835",
    "wifi",
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
    "WF_CB_01836",
    "wifi",
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
    "WF_CB_01837",
    "wifi",
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
    "WF_CB_01838",
    "wifi",
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
    "WF_CB_01839",
    "wifi",
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
    "WF_CB_01840",
    "wifi",
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
    "WF_CB_01841",
    "wifi",
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
    "WF_CB_01842",
    "wifi",
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
    "WF_CB_01843",
    "wifi",
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
    "WF_CB_01844",
    "wifi",
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
    "WF_CB_01845",
    "wifi",
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
    "WF_CB_01846",
    "wifi",
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
    "WF_CB_01847",
    "wifi",
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
    "WF_CB_01848",
    "wifi",
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
    "WF_CB_01849",
    "wifi",
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
    "WF_CB_01850",
    "wifi",
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
    "WF_CB_01851",
    "wifi",
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
    "WF_CB_01852",
    "wifi",
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
    "WF_CB_01853",
    "wifi",
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
    "WF_CB_01854",
    "wifi",
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
    "WF_CB_01855",
    "wifi",
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
    "WF_CB_01856",
    "wifi",
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
    "WF_CB_01857",
    "wifi",
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
    "WF_CB_01858",
    "wifi",
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
    "WF_CB_01859",
    "wifi",
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
    "WF_CB_01860",
    "wifi",
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
    "WF_CB_01861",
    "wifi",
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
    "WF_CB_01862",
    "wifi",
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
    "WF_CB_01863",
    "wifi",
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
    "WF_CB_01864",
    "wifi",
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
    "WF_CB_01865",
    "wifi",
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
    "WF_CB_01866",
    "wifi",
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
    "WF_CB_01867",
    "wifi",
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
    "WF_CB_01868",
    "wifi",
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
    "WF_CB_01869",
    "wifi",
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
    "WF_CB_01870",
    "wifi",
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
    "WF_CB_01871",
    "wifi",
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
    "WF_CB_01872",
    "wifi",
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
    "WF_CB_01873",
    "wifi",
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
    "WF_CB_01874",
    "wifi",
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
    "WF_CB_01875",
    "wifi",
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
    "WF_CB_01876",
    "wifi",
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
    "WF_CB_01877",
    "wifi",
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
    "WF_CB_01878",
    "wifi",
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
    "WF_CB_01879",
    "wifi",
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
    "WF_CB_01880",
    "wifi",
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
    "WF_CB_01881",
    "wifi",
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
    "WF_CB_01882",
    "wifi",
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
    "WF_CB_01883",
    "wifi",
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
    "WF_CB_01884",
    "wifi",
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
    "WF_CB_01885",
    "wifi",
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
    "WF_CB_01886",
    "wifi",
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
    "WF_CB_01887",
    "wifi",
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
    "WF_CB_01888",
    "wifi",
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
    "WF_CB_01889",
    "wifi",
    "disableHotspot",
    "combo",
    buildParams([
      ["blockDuration", 60]
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
    "combo flow#11 var#7 -> disableHotspot"
  ),
  makeApiTestCase(
    "WF_CB_01890",
    "wifi",
    "getHotspotBlockList",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isOpenSoftApAllowed",
      "isHotspotDualBandSupported",
      "getHotspotBlockList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#12 var#0 -> getHotspotBlockList"
  ),
  makeApiTestCase(
    "WF_CB_01891",
    "wifi",
    "getHotspotBlockList",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "isOpenSoftApAllowed",
      "isHotspotDualBandSupported",
      "getHotspotBlockList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#12 var#1 -> getHotspotBlockList"
  ),
  makeApiTestCase(
    "WF_CB_01892",
    "wifi",
    "getHotspotBlockList",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "isOpenSoftApAllowed",
      "isHotspotDualBandSupported",
      "getHotspotBlockList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#12 var#2 -> getHotspotBlockList"
  ),
  makeApiTestCase(
    "WF_CB_01893",
    "wifi",
    "getHotspotBlockList",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "isOpenSoftApAllowed",
      "isHotspotDualBandSupported",
      "getHotspotBlockList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#12 var#3 -> getHotspotBlockList"
  ),
  makeApiTestCase(
    "WF_CB_01894",
    "wifi",
    "getHotspotBlockList",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "isOpenSoftApAllowed",
      "isHotspotDualBandSupported",
      "getHotspotBlockList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#12 var#4 -> getHotspotBlockList"
  ),
  makeApiTestCase(
    "WF_CB_01895",
    "wifi",
    "getHotspotBlockList",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "isOpenSoftApAllowed",
      "isHotspotDualBandSupported",
      "getHotspotBlockList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#12 var#5 -> getHotspotBlockList"
  ),
  makeApiTestCase(
    "WF_CB_01896",
    "wifi",
    "getHotspotBlockList",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "isOpenSoftApAllowed",
      "isHotspotDualBandSupported",
      "getHotspotBlockList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#12 var#6 -> getHotspotBlockList"
  ),
  makeApiTestCase(
    "WF_CB_01897",
    "wifi",
    "getHotspotBlockList",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "isOpenSoftApAllowed",
      "isHotspotDualBandSupported",
      "getHotspotBlockList"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#12 var#7 -> getHotspotBlockList"
  ),
  makeApiTestCase(
    "WF_CB_01898",
    "wifi",
    "isHotspotActive",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "isMeteredHotspot",
      "getHotspotConfig",
      "isHotspotActive"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#13 var#0 -> isHotspotActive"
  ),
  makeApiTestCase(
    "WF_CB_01899",
    "wifi",
    "isHotspotActive",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "isMeteredHotspot",
      "getHotspotConfig",
      "isHotspotActive"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#13 var#1 -> isHotspotActive"
  ),
  makeApiTestCase(
    "WF_CB_01900",
    "wifi",
    "isHotspotActive",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "isMeteredHotspot",
      "getHotspotConfig",
      "isHotspotActive"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#13 var#2 -> isHotspotActive"
  ),
];
