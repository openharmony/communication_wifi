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

export const APITESTCATALOG_PART15: ApiTestCase[] = [
  makeApiTestCase(
    "WM_PC_01401",
    "wifiManager",
    "addCandidateConfig",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "addCandidateConfig invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01402",
    "wifiManager",
    "addCandidateConfig",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "addCandidateConfig invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01403",
    "wifiManager",
    "addCandidateConfig",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "addCandidateConfig invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01404",
    "wifiManager",
    "addCandidateConfig",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "addCandidateConfig invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01405",
    "wifiManager",
    "addCandidateConfig",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "addCandidateConfig invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01406",
    "wifiManager",
    "removeCandidateConfig",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "removeCandidateConfig invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01407",
    "wifiManager",
    "removeCandidateConfig",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "removeCandidateConfig invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01408",
    "wifiManager",
    "removeCandidateConfig",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "removeCandidateConfig invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01409",
    "wifiManager",
    "removeCandidateConfig",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "removeCandidateConfig invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01410",
    "wifiManager",
    "removeCandidateConfig",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "removeCandidateConfig invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01411",
    "wifiManager",
    "removeCandidateConfig",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "removeCandidateConfig invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01412",
    "wifiManager",
    "getP2pLinkedInfo",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getP2pLinkedInfo invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01413",
    "wifiManager",
    "getP2pLinkedInfo",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getP2pLinkedInfo invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01414",
    "wifiManager",
    "getP2pLinkedInfo",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getP2pLinkedInfo invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01415",
    "wifiManager",
    "getP2pLinkedInfo",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getP2pLinkedInfo invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01416",
    "wifiManager",
    "getP2pLinkedInfo",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getP2pLinkedInfo invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01417",
    "wifiManager",
    "getP2pLinkedInfo",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getP2pLinkedInfo invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01418",
    "wifiManager",
    "getCurrentGroup",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getCurrentGroup invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01419",
    "wifiManager",
    "getCurrentGroup",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getCurrentGroup invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01420",
    "wifiManager",
    "getCurrentGroup",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getCurrentGroup invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01421",
    "wifiManager",
    "getCurrentGroup",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getCurrentGroup invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01422",
    "wifiManager",
    "getCurrentGroup",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getCurrentGroup invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01423",
    "wifiManager",
    "getCurrentGroup",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getCurrentGroup invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01424",
    "wifiManager",
    "getP2pPeerDevices",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getP2pPeerDevices invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01425",
    "wifiManager",
    "getP2pPeerDevices",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getP2pPeerDevices invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01426",
    "wifiManager",
    "getP2pPeerDevices",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getP2pPeerDevices invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01427",
    "wifiManager",
    "getP2pPeerDevices",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getP2pPeerDevices invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01428",
    "wifiManager",
    "getP2pPeerDevices",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getP2pPeerDevices invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01429",
    "wifiManager",
    "getP2pPeerDevices",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getP2pPeerDevices invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01430",
    "wifiManager",
    "getP2pLocalDevice",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getP2pLocalDevice invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01431",
    "wifiManager",
    "getP2pLocalDevice",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getP2pLocalDevice invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01432",
    "wifiManager",
    "getP2pLocalDevice",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getP2pLocalDevice invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01433",
    "wifiManager",
    "getP2pLocalDevice",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getP2pLocalDevice invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01434",
    "wifiManager",
    "getP2pLocalDevice",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getP2pLocalDevice invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01435",
    "wifiManager",
    "getP2pLocalDevice",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getP2pLocalDevice invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01436",
    "wifiManager",
    "getP2pGroups",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getP2pGroups invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01437",
    "wifiManager",
    "getP2pGroups",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getP2pGroups invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01438",
    "wifiManager",
    "getP2pGroups",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getP2pGroups invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01439",
    "wifiManager",
    "getP2pGroups",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getP2pGroups invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01440",
    "wifiManager",
    "getP2pGroups",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "getP2pGroups invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01441",
    "wifiManager",
    "getP2pGroups",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "getP2pGroups invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01442",
    "wifiManager",
    "connectToCandidateConfigWithUserAction",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "connectToCandidateConfigWithUserAction invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01443",
    "wifiManager",
    "connectToCandidateConfigWithUserAction",
    "param",
    buildParams([
      ["invokeMode", "promise"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "connectToCandidateConfigWithUserAction invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01444",
    "wifiManager",
    "connectToCandidateConfigWithUserAction",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "connectToCandidateConfigWithUserAction invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01445",
    "wifiManager",
    "connectToCandidateConfigWithUserAction",
    "param",
    buildParams([
      ["invokeMode", "callback"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "connectToCandidateConfigWithUserAction invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01446",
    "wifiManager",
    "connectToCandidateConfigWithUserAction",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "WIFI_ON",
    "any",
    "none",
    true,
    "connectToCandidateConfigWithUserAction invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01447",
    "wifiManager",
    "connectToCandidateConfigWithUserAction",
    "param",
    buildParams([
      ["invokeMode", "sync"],
      ["netId", 0]
    ]),
    [],
    "P2P_IDLE",
    "any",
    "none",
    true,
    "connectToCandidateConfigWithUserAction invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_X_01448",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 0],
      ["ipType", 0],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=0 ip=0"
  ),
  makeApiTestCase(
    "WM_X_01449",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 0],
      ["ipType", 1],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=0 ip=1"
  ),
  makeApiTestCase(
    "WM_X_01450",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 0],
      ["ipType", 2],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=0 ip=2"
  ),
  makeApiTestCase(
    "WM_X_01451",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 1],
      ["ipType", 0],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=1 ip=0"
  ),
  makeApiTestCase(
    "WM_X_01452",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 1],
      ["ipType", 1],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=1 ip=1"
  ),
  makeApiTestCase(
    "WM_X_01453",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 1],
      ["ipType", 2],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=1 ip=2"
  ),
  makeApiTestCase(
    "WM_X_01454",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 2],
      ["ipType", 0],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=2 ip=0"
  ),
  makeApiTestCase(
    "WM_X_01455",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 2],
      ["ipType", 1],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=2 ip=1"
  ),
  makeApiTestCase(
    "WM_X_01456",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 2],
      ["ipType", 2],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=2 ip=2"
  ),
  makeApiTestCase(
    "WM_X_01457",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 3],
      ["ipType", 0],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=3 ip=0"
  ),
  makeApiTestCase(
    "WM_X_01458",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 3],
      ["ipType", 1],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=3 ip=1"
  ),
  makeApiTestCase(
    "WM_X_01459",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 3],
      ["ipType", 2],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=3 ip=2"
  ),
  makeApiTestCase(
    "WM_X_01460",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 4],
      ["ipType", 0],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=4 ip=0"
  ),
  makeApiTestCase(
    "WM_X_01461",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 4],
      ["ipType", 1],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=4 ip=1"
  ),
  makeApiTestCase(
    "WM_X_01462",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 4],
      ["ipType", 2],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=4 ip=2"
  ),
  makeApiTestCase(
    "WM_X_01463",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 5],
      ["ipType", 0],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=5 ip=0"
  ),
  makeApiTestCase(
    "WM_X_01464",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 5],
      ["ipType", 1],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=5 ip=1"
  ),
  makeApiTestCase(
    "WM_X_01465",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 5],
      ["ipType", 2],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=5 ip=2"
  ),
  makeApiTestCase(
    "WM_X_01466",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 6],
      ["ipType", 0],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=6 ip=0"
  ),
  makeApiTestCase(
    "WM_X_01467",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 6],
      ["ipType", 1],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=6 ip=1"
  ),
  makeApiTestCase(
    "WM_X_01468",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 6],
      ["ipType", 2],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=6 ip=2"
  ),
  makeApiTestCase(
    "WM_X_01469",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 7],
      ["ipType", 0],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=7 ip=0"
  ),
  makeApiTestCase(
    "WM_X_01470",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 7],
      ["ipType", 1],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=7 ip=1"
  ),
  makeApiTestCase(
    "WM_X_01471",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 7],
      ["ipType", 2],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=7 ip=2"
  ),
  makeApiTestCase(
    "WM_X_01472",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 8],
      ["ipType", 0],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=8 ip=0"
  ),
  makeApiTestCase(
    "WM_X_01473",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 8],
      ["ipType", 1],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=8 ip=1"
  ),
  makeApiTestCase(
    "WM_X_01474",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 8],
      ["ipType", 2],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=8 ip=2"
  ),
  makeApiTestCase(
    "WM_X_01475",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 9],
      ["ipType", 0],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=9 ip=0"
  ),
  makeApiTestCase(
    "WM_X_01476",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 9],
      ["ipType", 1],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=9 ip=1"
  ),
  makeApiTestCase(
    "WM_X_01477",
    "wifiManager",
    "updateNetwork",
    "param",
    buildParams([
      ["securityType", 9],
      ["ipType", 2],
      ["ssid", "ut_update"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "updateNetwork sec=9 ip=2"
  ),
  makeApiTestCase(
    "WM_X_01478",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_a"],
      ["securityType", 0],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_a sec=0"
  ),
  makeApiTestCase(
    "WM_X_01479",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_a"],
      ["securityType", 1],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_a sec=1"
  ),
  makeApiTestCase(
    "WM_X_01480",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_a"],
      ["securityType", 2],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_a sec=2"
  ),
  makeApiTestCase(
    "WM_X_01481",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_a"],
      ["securityType", 3],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_a sec=3"
  ),
  makeApiTestCase(
    "WM_X_01482",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_a"],
      ["securityType", 4],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_a sec=4"
  ),
  makeApiTestCase(
    "WM_X_01483",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_b"],
      ["securityType", 0],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_b sec=0"
  ),
  makeApiTestCase(
    "WM_X_01484",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_b"],
      ["securityType", 1],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_b sec=1"
  ),
  makeApiTestCase(
    "WM_X_01485",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_b"],
      ["securityType", 2],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_b sec=2"
  ),
  makeApiTestCase(
    "WM_X_01486",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_b"],
      ["securityType", 3],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_b sec=3"
  ),
  makeApiTestCase(
    "WM_X_01487",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_b"],
      ["securityType", 4],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_b sec=4"
  ),
  makeApiTestCase(
    "WM_X_01488",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_c"],
      ["securityType", 0],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_c sec=0"
  ),
  makeApiTestCase(
    "WM_X_01489",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_c"],
      ["securityType", 1],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_c sec=1"
  ),
  makeApiTestCase(
    "WM_X_01490",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_c"],
      ["securityType", 2],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_c sec=2"
  ),
  makeApiTestCase(
    "WM_X_01491",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_c"],
      ["securityType", 3],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_c sec=3"
  ),
  makeApiTestCase(
    "WM_X_01492",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_c"],
      ["securityType", 4],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_c sec=4"
  ),
  makeApiTestCase(
    "WM_X_01493",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_d"],
      ["securityType", 0],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_d sec=0"
  ),
  makeApiTestCase(
    "WM_X_01494",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_d"],
      ["securityType", 1],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_d sec=1"
  ),
  makeApiTestCase(
    "WM_X_01495",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_d"],
      ["securityType", 2],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_d sec=2"
  ),
  makeApiTestCase(
    "WM_X_01496",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_d"],
      ["securityType", 3],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_d sec=3"
  ),
  makeApiTestCase(
    "WM_X_01497",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_d"],
      ["securityType", 4],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_d sec=4"
  ),
  makeApiTestCase(
    "WM_X_01498",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_e"],
      ["securityType", 0],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_e sec=0"
  ),
  makeApiTestCase(
    "WM_X_01499",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_e"],
      ["securityType", 1],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_e sec=1"
  ),
  makeApiTestCase(
    "WM_X_01500",
    "wifiManager",
    "connectToDevice",
    "param",
    buildParams([
      ["ssid", "ut_conn_e"],
      ["securityType", 2],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "connectToDevice ssid=ut_conn_e sec=2"
  ),
];
