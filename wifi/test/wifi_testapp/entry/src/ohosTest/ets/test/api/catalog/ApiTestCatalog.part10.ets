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

export const APITESTCATALOG_PART10: ApiTestCase[] = [
  makeApiTestCase(
    "WM_CB_00901",
    "wifiManager",
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
    "WM_CB_00902",
    "wifiManager",
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
    "WM_CB_00903",
    "wifiManager",
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
    "WM_CB_00904",
    "wifiManager",
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
    "WM_CB_00905",
    "wifiManager",
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
    "WM_CB_00906",
    "wifiManager",
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
  makeApiTestCase(
    "WM_CB_00907",
    "wifiManager",
    "isHotspotActive",
    "combo",
    buildParams([
      ["featureId", 1]
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
    "combo flow#13 var#3 -> isHotspotActive"
  ),
  makeApiTestCase(
    "WM_CB_00908",
    "wifiManager",
    "isHotspotActive",
    "combo",
    buildParams([
      ["allowed", true]
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
    "combo flow#13 var#4 -> isHotspotActive"
  ),
  makeApiTestCase(
    "WM_CB_00909",
    "wifiManager",
    "isHotspotActive",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
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
    "combo flow#13 var#5 -> isHotspotActive"
  ),
  makeApiTestCase(
    "WM_CB_00910",
    "wifiManager",
    "isHotspotActive",
    "combo",
    buildParams([
      ["id", 0]
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
    "combo flow#13 var#6 -> isHotspotActive"
  ),
  makeApiTestCase(
    "WM_CB_00911",
    "wifiManager",
    "isHotspotActive",
    "combo",
    buildParams([
      ["blockDuration", 60]
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
    "combo flow#13 var#7 -> isHotspotActive"
  ),
  makeApiTestCase(
    "WM_CB_00912",
    "wifiManager",
    "stopDiscoverDevices",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "startDiscoverDevices",
      "getP2pPeerDevices",
      "stopDiscoverDevices"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#14 var#0 -> stopDiscoverDevices"
  ),
  makeApiTestCase(
    "WM_CB_00913",
    "wifiManager",
    "stopDiscoverDevices",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "startDiscoverDevices",
      "getP2pPeerDevices",
      "stopDiscoverDevices"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#14 var#1 -> stopDiscoverDevices"
  ),
  makeApiTestCase(
    "WM_CB_00914",
    "wifiManager",
    "stopDiscoverDevices",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "startDiscoverDevices",
      "getP2pPeerDevices",
      "stopDiscoverDevices"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#14 var#2 -> stopDiscoverDevices"
  ),
  makeApiTestCase(
    "WM_CB_00915",
    "wifiManager",
    "stopDiscoverDevices",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "startDiscoverDevices",
      "getP2pPeerDevices",
      "stopDiscoverDevices"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#14 var#3 -> stopDiscoverDevices"
  ),
  makeApiTestCase(
    "WM_CB_00916",
    "wifiManager",
    "stopDiscoverDevices",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "startDiscoverDevices",
      "getP2pPeerDevices",
      "stopDiscoverDevices"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#14 var#4 -> stopDiscoverDevices"
  ),
  makeApiTestCase(
    "WM_CB_00917",
    "wifiManager",
    "stopDiscoverDevices",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "startDiscoverDevices",
      "getP2pPeerDevices",
      "stopDiscoverDevices"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#14 var#5 -> stopDiscoverDevices"
  ),
  makeApiTestCase(
    "WM_CB_00918",
    "wifiManager",
    "stopDiscoverDevices",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "startDiscoverDevices",
      "getP2pPeerDevices",
      "stopDiscoverDevices"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#14 var#6 -> stopDiscoverDevices"
  ),
  makeApiTestCase(
    "WM_CB_00919",
    "wifiManager",
    "stopDiscoverDevices",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "startDiscoverDevices",
      "getP2pPeerDevices",
      "stopDiscoverDevices"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#14 var#7 -> stopDiscoverDevices"
  ),
  makeApiTestCase(
    "WM_CB_00920",
    "wifiManager",
    "getP2pLinkedInfo",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "getP2pLocalDevice",
      "getP2pGroups",
      "getP2pLinkedInfo"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#15 var#0 -> getP2pLinkedInfo"
  ),
  makeApiTestCase(
    "WM_CB_00921",
    "wifiManager",
    "getP2pLinkedInfo",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "getP2pLocalDevice",
      "getP2pGroups",
      "getP2pLinkedInfo"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#15 var#1 -> getP2pLinkedInfo"
  ),
  makeApiTestCase(
    "WM_CB_00922",
    "wifiManager",
    "getP2pLinkedInfo",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "getP2pLocalDevice",
      "getP2pGroups",
      "getP2pLinkedInfo"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#15 var#2 -> getP2pLinkedInfo"
  ),
  makeApiTestCase(
    "WM_CB_00923",
    "wifiManager",
    "getP2pLinkedInfo",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "getP2pLocalDevice",
      "getP2pGroups",
      "getP2pLinkedInfo"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#15 var#3 -> getP2pLinkedInfo"
  ),
  makeApiTestCase(
    "WM_CB_00924",
    "wifiManager",
    "getP2pLinkedInfo",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "getP2pLocalDevice",
      "getP2pGroups",
      "getP2pLinkedInfo"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#15 var#4 -> getP2pLinkedInfo"
  ),
  makeApiTestCase(
    "WM_CB_00925",
    "wifiManager",
    "getP2pLinkedInfo",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "getP2pLocalDevice",
      "getP2pGroups",
      "getP2pLinkedInfo"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#15 var#5 -> getP2pLinkedInfo"
  ),
  makeApiTestCase(
    "WM_CB_00926",
    "wifiManager",
    "getP2pLinkedInfo",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "getP2pLocalDevice",
      "getP2pGroups",
      "getP2pLinkedInfo"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#15 var#6 -> getP2pLinkedInfo"
  ),
  makeApiTestCase(
    "WM_CB_00927",
    "wifiManager",
    "getP2pLinkedInfo",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "getP2pLocalDevice",
      "getP2pGroups",
      "getP2pLinkedInfo"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#15 var#7 -> getP2pLinkedInfo"
  ),
  makeApiTestCase(
    "WM_CB_00928",
    "wifiManager",
    "getCurrentGroup",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "setDeviceName",
      "getP2pLocalDevice",
      "getCurrentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#16 var#0 -> getCurrentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00929",
    "wifiManager",
    "getCurrentGroup",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "setDeviceName",
      "getP2pLocalDevice",
      "getCurrentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#16 var#1 -> getCurrentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00930",
    "wifiManager",
    "getCurrentGroup",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "setDeviceName",
      "getP2pLocalDevice",
      "getCurrentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#16 var#2 -> getCurrentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00931",
    "wifiManager",
    "getCurrentGroup",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "setDeviceName",
      "getP2pLocalDevice",
      "getCurrentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#16 var#3 -> getCurrentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00932",
    "wifiManager",
    "getCurrentGroup",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "setDeviceName",
      "getP2pLocalDevice",
      "getCurrentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#16 var#4 -> getCurrentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00933",
    "wifiManager",
    "getCurrentGroup",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "setDeviceName",
      "getP2pLocalDevice",
      "getCurrentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#16 var#5 -> getCurrentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00934",
    "wifiManager",
    "getCurrentGroup",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "setDeviceName",
      "getP2pLocalDevice",
      "getCurrentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#16 var#6 -> getCurrentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00935",
    "wifiManager",
    "getCurrentGroup",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "setDeviceName",
      "getP2pLocalDevice",
      "getCurrentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#16 var#7 -> getCurrentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00936",
    "wifiManager",
    "deletePersistentGroup",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "p2pCancelConnect",
      "removeGroup",
      "deletePersistentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#17 var#0 -> deletePersistentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00937",
    "wifiManager",
    "deletePersistentGroup",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "p2pCancelConnect",
      "removeGroup",
      "deletePersistentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#17 var#1 -> deletePersistentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00938",
    "wifiManager",
    "deletePersistentGroup",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "p2pCancelConnect",
      "removeGroup",
      "deletePersistentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#17 var#2 -> deletePersistentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00939",
    "wifiManager",
    "deletePersistentGroup",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "p2pCancelConnect",
      "removeGroup",
      "deletePersistentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#17 var#3 -> deletePersistentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00940",
    "wifiManager",
    "deletePersistentGroup",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "p2pCancelConnect",
      "removeGroup",
      "deletePersistentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#17 var#4 -> deletePersistentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00941",
    "wifiManager",
    "deletePersistentGroup",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "p2pCancelConnect",
      "removeGroup",
      "deletePersistentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#17 var#5 -> deletePersistentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00942",
    "wifiManager",
    "deletePersistentGroup",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "p2pCancelConnect",
      "removeGroup",
      "deletePersistentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#17 var#6 -> deletePersistentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00943",
    "wifiManager",
    "deletePersistentGroup",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "p2pCancelConnect",
      "removeGroup",
      "deletePersistentGroup"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#17 var#7 -> deletePersistentGroup"
  ),
  makeApiTestCase(
    "WM_CB_00944",
    "wifiManager",
    "disableWifi",
    "combo",
    buildParams([]),
    [
      "disableWifi",
      "enableWifi",
      "scan",
      "disableWifi"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#18 var#0 -> disableWifi"
  ),
  makeApiTestCase(
    "WM_CB_00945",
    "wifiManager",
    "disableWifi",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "disableWifi",
      "enableWifi",
      "scan",
      "disableWifi"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#18 var#1 -> disableWifi"
  ),
  makeApiTestCase(
    "WM_CB_00946",
    "wifiManager",
    "disableWifi",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "disableWifi",
      "enableWifi",
      "scan",
      "disableWifi"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#18 var#2 -> disableWifi"
  ),
  makeApiTestCase(
    "WM_CB_00947",
    "wifiManager",
    "disableWifi",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "disableWifi",
      "enableWifi",
      "scan",
      "disableWifi"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#18 var#3 -> disableWifi"
  ),
  makeApiTestCase(
    "WM_CB_00948",
    "wifiManager",
    "disableWifi",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "disableWifi",
      "enableWifi",
      "scan",
      "disableWifi"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#18 var#4 -> disableWifi"
  ),
  makeApiTestCase(
    "WM_CB_00949",
    "wifiManager",
    "disableWifi",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "disableWifi",
      "enableWifi",
      "scan",
      "disableWifi"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#18 var#5 -> disableWifi"
  ),
  makeApiTestCase(
    "WM_CB_00950",
    "wifiManager",
    "disableWifi",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "disableWifi",
      "enableWifi",
      "scan",
      "disableWifi"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#18 var#6 -> disableWifi"
  ),
  makeApiTestCase(
    "WM_CB_00951",
    "wifiManager",
    "disableWifi",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "disableWifi",
      "enableWifi",
      "scan",
      "disableWifi"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#18 var#7 -> disableWifi"
  ),
  makeApiTestCase(
    "WM_CB_00952",
    "wifiManager",
    "reassociate",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "disconnect",
      "reconnect",
      "reassociate"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#19 var#0 -> reassociate"
  ),
  makeApiTestCase(
    "WM_CB_00953",
    "wifiManager",
    "reassociate",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "disconnect",
      "reconnect",
      "reassociate"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#19 var#1 -> reassociate"
  ),
  makeApiTestCase(
    "WM_CB_00954",
    "wifiManager",
    "reassociate",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "disconnect",
      "reconnect",
      "reassociate"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#19 var#2 -> reassociate"
  ),
  makeApiTestCase(
    "WM_CB_00955",
    "wifiManager",
    "reassociate",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "disconnect",
      "reconnect",
      "reassociate"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#19 var#3 -> reassociate"
  ),
  makeApiTestCase(
    "WM_CB_00956",
    "wifiManager",
    "reassociate",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "disconnect",
      "reconnect",
      "reassociate"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#19 var#4 -> reassociate"
  ),
  makeApiTestCase(
    "WM_CB_00957",
    "wifiManager",
    "reassociate",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "disconnect",
      "reconnect",
      "reassociate"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#19 var#5 -> reassociate"
  ),
  makeApiTestCase(
    "WM_CB_00958",
    "wifiManager",
    "reassociate",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "disconnect",
      "reconnect",
      "reassociate"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#19 var#6 -> reassociate"
  ),
  makeApiTestCase(
    "WM_CB_00959",
    "wifiManager",
    "reassociate",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "disconnect",
      "reconnect",
      "reassociate"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#19 var#7 -> reassociate"
  ),
  makeApiTestCase(
    "WM_CB_00960",
    "wifiManager",
    "removeDevice",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "allowAutoConnect",
      "disableNetwork",
      "removeDevice"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#20 var#0 -> removeDevice"
  ),
  makeApiTestCase(
    "WM_CB_00961",
    "wifiManager",
    "removeDevice",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "allowAutoConnect",
      "disableNetwork",
      "removeDevice"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#20 var#1 -> removeDevice"
  ),
  makeApiTestCase(
    "WM_CB_00962",
    "wifiManager",
    "removeDevice",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "allowAutoConnect",
      "disableNetwork",
      "removeDevice"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#20 var#2 -> removeDevice"
  ),
  makeApiTestCase(
    "WM_CB_00963",
    "wifiManager",
    "removeDevice",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "allowAutoConnect",
      "disableNetwork",
      "removeDevice"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#20 var#3 -> removeDevice"
  ),
  makeApiTestCase(
    "WM_CB_00964",
    "wifiManager",
    "removeDevice",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "allowAutoConnect",
      "disableNetwork",
      "removeDevice"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#20 var#4 -> removeDevice"
  ),
  makeApiTestCase(
    "WM_CB_00965",
    "wifiManager",
    "removeDevice",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "allowAutoConnect",
      "disableNetwork",
      "removeDevice"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#20 var#5 -> removeDevice"
  ),
  makeApiTestCase(
    "WM_CB_00966",
    "wifiManager",
    "removeDevice",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "allowAutoConnect",
      "disableNetwork",
      "removeDevice"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#20 var#6 -> removeDevice"
  ),
  makeApiTestCase(
    "WM_CB_00967",
    "wifiManager",
    "removeDevice",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "allowAutoConnect",
      "disableNetwork",
      "removeDevice"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#20 var#7 -> removeDevice"
  ),
  makeApiTestCase(
    "WM_CB_00968",
    "wifiManager",
    "removeAllNetwork",
    "combo",
    buildParams([]),
    [
      "enableWifi",
      "connectToNetwork",
      "disconnect",
      "removeAllNetwork"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#21 var#0 -> removeAllNetwork"
  ),
  makeApiTestCase(
    "WM_CB_00969",
    "wifiManager",
    "removeAllNetwork",
    "combo",
    buildParams([
      ["netId", 0]
    ]),
    [
      "enableWifi",
      "connectToNetwork",
      "disconnect",
      "removeAllNetwork"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#21 var#1 -> removeAllNetwork"
  ),
  makeApiTestCase(
    "WM_CB_00970",
    "wifiManager",
    "removeAllNetwork",
    "combo",
    buildParams([
      ["rssi", -50],
      ["band", 1]
    ]),
    [
      "enableWifi",
      "connectToNetwork",
      "disconnect",
      "removeAllNetwork"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#21 var#2 -> removeAllNetwork"
  ),
  makeApiTestCase(
    "WM_CB_00971",
    "wifiManager",
    "removeAllNetwork",
    "combo",
    buildParams([
      ["featureId", 1]
    ]),
    [
      "enableWifi",
      "connectToNetwork",
      "disconnect",
      "removeAllNetwork"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#21 var#3 -> removeAllNetwork"
  ),
  makeApiTestCase(
    "WM_CB_00972",
    "wifiManager",
    "removeAllNetwork",
    "combo",
    buildParams([
      ["allowed", true]
    ]),
    [
      "enableWifi",
      "connectToNetwork",
      "disconnect",
      "removeAllNetwork"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#21 var#4 -> removeAllNetwork"
  ),
  makeApiTestCase(
    "WM_CB_00973",
    "wifiManager",
    "removeAllNetwork",
    "combo",
    buildParams([
      ["devName", "ComboTest"]
    ]),
    [
      "enableWifi",
      "connectToNetwork",
      "disconnect",
      "removeAllNetwork"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#21 var#5 -> removeAllNetwork"
  ),
  makeApiTestCase(
    "WM_CB_00974",
    "wifiManager",
    "removeAllNetwork",
    "combo",
    buildParams([
      ["id", 0]
    ]),
    [
      "enableWifi",
      "connectToNetwork",
      "disconnect",
      "removeAllNetwork"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#21 var#6 -> removeAllNetwork"
  ),
  makeApiTestCase(
    "WM_CB_00975",
    "wifiManager",
    "removeAllNetwork",
    "combo",
    buildParams([
      ["blockDuration", 60]
    ]),
    [
      "enableWifi",
      "connectToNetwork",
      "disconnect",
      "removeAllNetwork"
    ],
    "WIFI_ON",
    "any",
    "none",
    true,
    "combo flow#21 var#7 -> removeAllNetwork"
  ),
  makeApiTestCase(
    "WM_DC_00976",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 0],
      ["ipType", 0],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=0 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_00977",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 0],
      ["ipType", 0],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=0 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_00978",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 0],
      ["ipType", 1],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=0 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_00979",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 0],
      ["ipType", 1],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=0 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_00980",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 0],
      ["ipType", 2],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=0 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_00981",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 0],
      ["ipType", 2],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=0 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_00982",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 1],
      ["ipType", 0],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=1 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_00983",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 1],
      ["ipType", 0],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=1 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_00984",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 1],
      ["ipType", 1],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=1 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_00985",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 1],
      ["ipType", 1],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=1 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_00986",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 1],
      ["ipType", 2],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=1 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_00987",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 1],
      ["ipType", 2],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=1 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_00988",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 2],
      ["ipType", 0],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=2 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_00989",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 2],
      ["ipType", 0],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=2 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_00990",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 2],
      ["ipType", 1],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=2 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_00991",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 2],
      ["ipType", 1],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=2 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_00992",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 2],
      ["ipType", 2],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=2 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_00993",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 2],
      ["ipType", 2],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=2 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_00994",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 3],
      ["ipType", 0],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=3 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_00995",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 3],
      ["ipType", 0],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=3 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_00996",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 3],
      ["ipType", 1],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=3 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_00997",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 3],
      ["ipType", 1],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=3 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_00998",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 3],
      ["ipType", 2],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=3 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_00999",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 3],
      ["ipType", 2],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=3 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01000",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
      ["securityType", 4],
      ["ipType", 0],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=0 sec=4 ip=0 hidden=True"
  ),
];
