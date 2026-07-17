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

export const APITESTCATALOG_PART20: ApiTestCase[] = [
  makeApiTestCase(
    "WF_CB_01901",
    "wifi",
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
    "WF_CB_01902",
    "wifi",
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
    "WF_CB_01903",
    "wifi",
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
    "WF_CB_01904",
    "wifi",
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
    "WF_CB_01905",
    "wifi",
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
    "WF_CB_01906",
    "wifi",
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
    "WF_CB_01907",
    "wifi",
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
    "WF_CB_01908",
    "wifi",
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
    "WF_CB_01909",
    "wifi",
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
    "WF_CB_01910",
    "wifi",
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
    "WF_CB_01911",
    "wifi",
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
    "WF_CB_01912",
    "wifi",
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
    "WF_CB_01913",
    "wifi",
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
    "WF_CB_01914",
    "wifi",
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
    "WF_CB_01915",
    "wifi",
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
    "WF_CB_01916",
    "wifi",
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
    "WF_CB_01917",
    "wifi",
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
    "WF_CB_01918",
    "wifi",
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
    "WF_CB_01919",
    "wifi",
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
    "WF_CB_01920",
    "wifi",
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
    "WF_CB_01921",
    "wifi",
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
    "WF_CB_01922",
    "wifi",
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
    "WF_CB_01923",
    "wifi",
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
    "WF_CB_01924",
    "wifi",
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
    "WF_CB_01925",
    "wifi",
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
    "WF_CB_01926",
    "wifi",
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
    "WF_CB_01927",
    "wifi",
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
    "WF_CB_01928",
    "wifi",
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
    "WF_CB_01929",
    "wifi",
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
    "WF_CB_01930",
    "wifi",
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
    "WF_CB_01931",
    "wifi",
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
    "WF_CB_01932",
    "wifi",
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
    "WF_CB_01933",
    "wifi",
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
    "WF_CB_01934",
    "wifi",
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
    "WF_CB_01935",
    "wifi",
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
    "WF_CB_01936",
    "wifi",
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
    "WF_CB_01937",
    "wifi",
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
    "WF_CB_01938",
    "wifi",
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
    "WF_CB_01939",
    "wifi",
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
    "WF_CB_01940",
    "wifi",
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
    "WF_CB_01941",
    "wifi",
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
    "WF_CB_01942",
    "wifi",
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
    "WF_CB_01943",
    "wifi",
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
    "WF_CB_01944",
    "wifi",
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
    "WF_CB_01945",
    "wifi",
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
    "WF_CB_01946",
    "wifi",
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
    "WF_CB_01947",
    "wifi",
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
    "WF_CB_01948",
    "wifi",
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
    "WF_CB_01949",
    "wifi",
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
    "WF_CB_01950",
    "wifi",
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
    "WF_CB_01951",
    "wifi",
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
    "WF_CB_01952",
    "wifi",
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
    "WF_CB_01953",
    "wifi",
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
    "WF_CB_01954",
    "wifi",
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
    "WF_CB_01955",
    "wifi",
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
    "WF_CB_01956",
    "wifi",
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
    "WF_CB_01957",
    "wifi",
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
    "WF_CB_01958",
    "wifi",
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
    "WF_CB_01959",
    "wifi",
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
    "WF_CB_01960",
    "wifi",
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
    "WF_CB_01961",
    "wifi",
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
    "WF_CB_01962",
    "wifi",
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
    "WF_CB_01963",
    "wifi",
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
    "WF_CB_01964",
    "wifi",
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
    "WF_CB_01965",
    "wifi",
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
    "WF_CB_01966",
    "wifi",
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
    "WF_CB_01967",
    "wifi",
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
    "WF_CB_01968",
    "wifi",
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
    "WF_CB_01969",
    "wifi",
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
    "LE_P_01970",
    "linkEnhance",
    "createServer",
    "param",
    buildParams([
      ["name", "ut_srv_1"]
    ]),
    [],
    "ANY",
    "object",
    "none",
    false,
    "linkEnhance.createServer param#0 precond=ANY"
  ),
  makeApiTestCase(
    "LE_P_01971",
    "linkEnhance",
    "createServer",
    "param",
    buildParams([
      ["name", "ut_srv_2"]
    ]),
    [],
    "ANY",
    "object",
    "none",
    false,
    "linkEnhance.createServer param#1 precond=ANY"
  ),
  makeApiTestCase(
    "LE_P_01972",
    "linkEnhance",
    "createServer",
    "param",
    buildParams([
      ["name", "ut_srv_3"]
    ]),
    [],
    "ANY",
    "object",
    "none",
    false,
    "linkEnhance.createServer param#2 precond=ANY"
  ),
  makeApiTestCase(
    "LE_P_01973",
    "linkEnhance",
    "createConnection",
    "param",
    buildParams([
      ["deviceId", ""],
      ["name", "ut_conn"]
    ]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createConnection param#0 precond=ANY"
  ),
  makeApiTestCase(
    "LE_P_01974",
    "linkEnhance",
    "createConnection",
    "param",
    buildParams([
      ["deviceId", ""],
      ["name", "ut_link"]
    ]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createConnection param#1 precond=ANY"
  ),
  makeApiTestCase(
    "LE_P_01975",
    "linkEnhance",
    "createConnection",
    "param",
    buildParams([
      ["deviceId", "local"],
      ["name", "ut_conn"]
    ]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createConnection param#2 precond=ANY"
  ),
  makeApiTestCase(
    "LE_P_01976",
    "linkEnhance",
    "createConnection",
    "param",
    buildParams([
      ["deviceId", "local"],
      ["name", "ut_link"]
    ]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createConnection param#3 precond=ANY"
  ),
  makeApiTestCase(
    "LE_P_01977",
    "linkEnhance",
    "createConnection",
    "param",
    buildParams([
      ["deviceId", "peer0"],
      ["name", "ut_conn"]
    ]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createConnection param#4 precond=ANY"
  ),
  makeApiTestCase(
    "LE_P_01978",
    "linkEnhance",
    "createConnection",
    "param",
    buildParams([
      ["deviceId", "peer0"],
      ["name", "ut_link"]
    ]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createConnection param#5 precond=ANY"
  ),
  makeApiTestCase(
    "LE_R_01979",
    "linkEnhance",
    "createServer",
    "return",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createServer return_type_check variant=0 expect=object"
  ),
  makeApiTestCase(
    "LE_R_01980",
    "linkEnhance",
    "createServer",
    "return",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createServer return_type_check variant=1 expect=object"
  ),
  makeApiTestCase(
    "LE_R_01981",
    "linkEnhance",
    "createServer",
    "return",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createServer return_type_check variant=2 expect=object"
  ),
  makeApiTestCase(
    "LE_R_01982",
    "linkEnhance",
    "createServer",
    "return",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createServer return_type_check variant=3 expect=object"
  ),
  makeApiTestCase(
    "LE_R_01983",
    "linkEnhance",
    "createServer",
    "return",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createServer return_type_check variant=4 expect=object"
  ),
  makeApiTestCase(
    "LE_R_01984",
    "linkEnhance",
    "createServer",
    "return",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createServer return_type_check variant=5 expect=object"
  ),
  makeApiTestCase(
    "LE_R_01985",
    "linkEnhance",
    "createConnection",
    "return",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createConnection return_type_check variant=0 expect=object"
  ),
  makeApiTestCase(
    "LE_R_01986",
    "linkEnhance",
    "createConnection",
    "return",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createConnection return_type_check variant=1 expect=object"
  ),
  makeApiTestCase(
    "LE_R_01987",
    "linkEnhance",
    "createConnection",
    "return",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createConnection return_type_check variant=2 expect=object"
  ),
  makeApiTestCase(
    "LE_R_01988",
    "linkEnhance",
    "createConnection",
    "return",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createConnection return_type_check variant=3 expect=object"
  ),
  makeApiTestCase(
    "LE_R_01989",
    "linkEnhance",
    "createConnection",
    "return",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createConnection return_type_check variant=4 expect=object"
  ),
  makeApiTestCase(
    "LE_R_01990",
    "linkEnhance",
    "createConnection",
    "return",
    buildParams([]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createConnection return_type_check variant=5 expect=object"
  ),
  makeApiTestCase(
    "LE_C_01991",
    "linkEnhance",
    "createServer",
    "condition",
    buildParams([
      ["name", "ut_srv_1"]
    ]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createServer condition=ANY"
  ),
  makeApiTestCase(
    "LE_C_01992",
    "linkEnhance",
    "createServer",
    "condition",
    buildParams([
      ["name", "ut_srv_1"]
    ]),
    [],
    "WIFI_OFF",
    "object",
    "none",
    true,
    "linkEnhance.createServer condition=WIFI_OFF"
  ),
  makeApiTestCase(
    "LE_C_01993",
    "linkEnhance",
    "createServer",
    "condition",
    buildParams([
      ["name", "ut_srv_1"]
    ]),
    [],
    "WIFI_ON",
    "object",
    "none",
    true,
    "linkEnhance.createServer condition=WIFI_ON"
  ),
  makeApiTestCase(
    "LE_C_01994",
    "linkEnhance",
    "createServer",
    "condition",
    buildParams([
      ["name", "ut_srv_1"]
    ]),
    [],
    "WIFI_ON_SCAN",
    "object",
    "none",
    true,
    "linkEnhance.createServer condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "LE_C_01995",
    "linkEnhance",
    "createServer",
    "condition",
    buildParams([
      ["name", "ut_srv_1"]
    ]),
    [],
    "HOTSPOT_OFF",
    "object",
    "none",
    true,
    "linkEnhance.createServer condition=HOTSPOT_OFF"
  ),
  makeApiTestCase(
    "LE_C_01996",
    "linkEnhance",
    "createServer",
    "condition",
    buildParams([
      ["name", "ut_srv_1"]
    ]),
    [],
    "HOTSPOT_ON",
    "object",
    "none",
    true,
    "linkEnhance.createServer condition=HOTSPOT_ON"
  ),
  makeApiTestCase(
    "LE_C_01997",
    "linkEnhance",
    "createServer",
    "condition",
    buildParams([
      ["name", "ut_srv_1"]
    ]),
    [],
    "P2P_IDLE",
    "object",
    "none",
    true,
    "linkEnhance.createServer condition=P2P_IDLE"
  ),
  makeApiTestCase(
    "LE_C_01998",
    "linkEnhance",
    "createServer",
    "condition",
    buildParams([
      ["name", "ut_srv_1"]
    ]),
    [],
    "P2P_DISCOVERING",
    "object",
    "none",
    true,
    "linkEnhance.createServer condition=P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "LE_C_01999",
    "linkEnhance",
    "createConnection",
    "condition",
    buildParams([
      ["deviceId", ""],
      ["name", "ut_conn"]
    ]),
    [],
    "ANY",
    "object",
    "none",
    true,
    "linkEnhance.createConnection condition=ANY"
  ),
  makeApiTestCase(
    "LE_C_02000",
    "linkEnhance",
    "createConnection",
    "condition",
    buildParams([
      ["deviceId", ""],
      ["name", "ut_conn"]
    ]),
    [],
    "WIFI_OFF",
    "object",
    "none",
    true,
    "linkEnhance.createConnection condition=WIFI_OFF"
  ),
];
