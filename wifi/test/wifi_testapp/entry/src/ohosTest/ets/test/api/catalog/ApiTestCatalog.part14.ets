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

export const APITESTCATALOG_PART14: ApiTestCase[] = [
  makeApiTestCase(
    "WM_E_01301",
    "wifiManager",
    "on_streamChange",
    "condition",
    buildParams([
      ["event", "streamChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event streamChange unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01302",
    "wifiManager",
    "on_deviceConfigChange",
    "condition",
    buildParams([
      ["event", "deviceConfigChange"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event deviceConfigChange register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01303",
    "wifiManager",
    "on_deviceConfigChange",
    "condition",
    buildParams([
      ["event", "deviceConfigChange"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event deviceConfigChange register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01304",
    "wifiManager",
    "on_deviceConfigChange",
    "condition",
    buildParams([
      ["event", "deviceConfigChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event deviceConfigChange register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01305",
    "wifiManager",
    "on_deviceConfigChange",
    "condition",
    buildParams([
      ["event", "deviceConfigChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event deviceConfigChange register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01306",
    "wifiManager",
    "on_deviceConfigChange",
    "condition",
    buildParams([
      ["event", "deviceConfigChange"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event deviceConfigChange unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01307",
    "wifiManager",
    "on_deviceConfigChange",
    "condition",
    buildParams([
      ["event", "deviceConfigChange"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event deviceConfigChange unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01308",
    "wifiManager",
    "on_deviceConfigChange",
    "condition",
    buildParams([
      ["event", "deviceConfigChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event deviceConfigChange unregister under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01309",
    "wifiManager",
    "on_deviceConfigChange",
    "condition",
    buildParams([
      ["event", "deviceConfigChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event deviceConfigChange unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01310",
    "wifiManager",
    "on_hotspotStateChange",
    "condition",
    buildParams([
      ["event", "hotspotStateChange"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event hotspotStateChange register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01311",
    "wifiManager",
    "on_hotspotStateChange",
    "condition",
    buildParams([
      ["event", "hotspotStateChange"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event hotspotStateChange register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01312",
    "wifiManager",
    "on_hotspotStateChange",
    "condition",
    buildParams([
      ["event", "hotspotStateChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event hotspotStateChange register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01313",
    "wifiManager",
    "on_hotspotStateChange",
    "condition",
    buildParams([
      ["event", "hotspotStateChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event hotspotStateChange register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01314",
    "wifiManager",
    "on_hotspotStateChange",
    "condition",
    buildParams([
      ["event", "hotspotStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event hotspotStateChange unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01315",
    "wifiManager",
    "on_hotspotStateChange",
    "condition",
    buildParams([
      ["event", "hotspotStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event hotspotStateChange unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01316",
    "wifiManager",
    "on_hotspotStateChange",
    "condition",
    buildParams([
      ["event", "hotspotStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event hotspotStateChange unregister under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01317",
    "wifiManager",
    "on_hotspotStateChange",
    "condition",
    buildParams([
      ["event", "hotspotStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event hotspotStateChange unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01318",
    "wifiManager",
    "on_hotspotStaJoin",
    "condition",
    buildParams([
      ["event", "hotspotStaJoin"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event hotspotStaJoin register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01319",
    "wifiManager",
    "on_hotspotStaJoin",
    "condition",
    buildParams([
      ["event", "hotspotStaJoin"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event hotspotStaJoin register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01320",
    "wifiManager",
    "on_hotspotStaJoin",
    "condition",
    buildParams([
      ["event", "hotspotStaJoin"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event hotspotStaJoin register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01321",
    "wifiManager",
    "on_hotspotStaJoin",
    "condition",
    buildParams([
      ["event", "hotspotStaJoin"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event hotspotStaJoin register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01322",
    "wifiManager",
    "on_hotspotStaJoin",
    "condition",
    buildParams([
      ["event", "hotspotStaJoin"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event hotspotStaJoin unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01323",
    "wifiManager",
    "on_hotspotStaJoin",
    "condition",
    buildParams([
      ["event", "hotspotStaJoin"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event hotspotStaJoin unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01324",
    "wifiManager",
    "on_hotspotStaJoin",
    "condition",
    buildParams([
      ["event", "hotspotStaJoin"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event hotspotStaJoin unregister under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01325",
    "wifiManager",
    "on_hotspotStaJoin",
    "condition",
    buildParams([
      ["event", "hotspotStaJoin"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event hotspotStaJoin unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01326",
    "wifiManager",
    "on_hotspotStaLeave",
    "condition",
    buildParams([
      ["event", "hotspotStaLeave"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event hotspotStaLeave register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01327",
    "wifiManager",
    "on_hotspotStaLeave",
    "condition",
    buildParams([
      ["event", "hotspotStaLeave"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event hotspotStaLeave register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01328",
    "wifiManager",
    "on_hotspotStaLeave",
    "condition",
    buildParams([
      ["event", "hotspotStaLeave"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event hotspotStaLeave register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01329",
    "wifiManager",
    "on_hotspotStaLeave",
    "condition",
    buildParams([
      ["event", "hotspotStaLeave"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event hotspotStaLeave register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01330",
    "wifiManager",
    "on_hotspotStaLeave",
    "condition",
    buildParams([
      ["event", "hotspotStaLeave"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event hotspotStaLeave unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01331",
    "wifiManager",
    "on_hotspotStaLeave",
    "condition",
    buildParams([
      ["event", "hotspotStaLeave"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event hotspotStaLeave unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01332",
    "wifiManager",
    "on_hotspotStaLeave",
    "condition",
    buildParams([
      ["event", "hotspotStaLeave"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event hotspotStaLeave unregister under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01333",
    "wifiManager",
    "on_hotspotStaLeave",
    "condition",
    buildParams([
      ["event", "hotspotStaLeave"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event hotspotStaLeave unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01334",
    "wifiManager",
    "on_p2pStateChange",
    "condition",
    buildParams([
      ["event", "p2pStateChange"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event p2pStateChange register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01335",
    "wifiManager",
    "on_p2pStateChange",
    "condition",
    buildParams([
      ["event", "p2pStateChange"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event p2pStateChange register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01336",
    "wifiManager",
    "on_p2pStateChange",
    "condition",
    buildParams([
      ["event", "p2pStateChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event p2pStateChange register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01337",
    "wifiManager",
    "on_p2pStateChange",
    "condition",
    buildParams([
      ["event", "p2pStateChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event p2pStateChange register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01338",
    "wifiManager",
    "on_p2pStateChange",
    "condition",
    buildParams([
      ["event", "p2pStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event p2pStateChange unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01339",
    "wifiManager",
    "on_p2pStateChange",
    "condition",
    buildParams([
      ["event", "p2pStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event p2pStateChange unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01340",
    "wifiManager",
    "on_p2pStateChange",
    "condition",
    buildParams([
      ["event", "p2pStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event p2pStateChange unregister under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01341",
    "wifiManager",
    "on_p2pStateChange",
    "condition",
    buildParams([
      ["event", "p2pStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event p2pStateChange unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01342",
    "wifiManager",
    "on_p2pConnectionChange",
    "condition",
    buildParams([
      ["event", "p2pConnectionChange"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event p2pConnectionChange register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01343",
    "wifiManager",
    "on_p2pConnectionChange",
    "condition",
    buildParams([
      ["event", "p2pConnectionChange"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event p2pConnectionChange register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01344",
    "wifiManager",
    "on_p2pConnectionChange",
    "condition",
    buildParams([
      ["event", "p2pConnectionChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event p2pConnectionChange register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01345",
    "wifiManager",
    "on_p2pConnectionChange",
    "condition",
    buildParams([
      ["event", "p2pConnectionChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event p2pConnectionChange register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01346",
    "wifiManager",
    "on_p2pConnectionChange",
    "condition",
    buildParams([
      ["event", "p2pConnectionChange"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event p2pConnectionChange unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01347",
    "wifiManager",
    "on_p2pConnectionChange",
    "condition",
    buildParams([
      ["event", "p2pConnectionChange"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event p2pConnectionChange unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01348",
    "wifiManager",
    "on_p2pConnectionChange",
    "condition",
    buildParams([
      ["event", "p2pConnectionChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event p2pConnectionChange unregister under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01349",
    "wifiManager",
    "on_p2pConnectionChange",
    "condition",
    buildParams([
      ["event", "p2pConnectionChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event p2pConnectionChange unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01350",
    "wifiManager",
    "on_p2pDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pDeviceChange"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event p2pDeviceChange register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01351",
    "wifiManager",
    "on_p2pDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pDeviceChange"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event p2pDeviceChange register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01352",
    "wifiManager",
    "on_p2pDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pDeviceChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event p2pDeviceChange register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01353",
    "wifiManager",
    "on_p2pDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pDeviceChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event p2pDeviceChange register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01354",
    "wifiManager",
    "on_p2pDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pDeviceChange"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event p2pDeviceChange unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01355",
    "wifiManager",
    "on_p2pDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pDeviceChange"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event p2pDeviceChange unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01356",
    "wifiManager",
    "on_p2pDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pDeviceChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event p2pDeviceChange unregister under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01357",
    "wifiManager",
    "on_p2pDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pDeviceChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event p2pDeviceChange unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01358",
    "wifiManager",
    "on_p2pPeerDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pPeerDeviceChange"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event p2pPeerDeviceChange register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01359",
    "wifiManager",
    "on_p2pPeerDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pPeerDeviceChange"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event p2pPeerDeviceChange register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01360",
    "wifiManager",
    "on_p2pPeerDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pPeerDeviceChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event p2pPeerDeviceChange register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01361",
    "wifiManager",
    "on_p2pPeerDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pPeerDeviceChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event p2pPeerDeviceChange register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01362",
    "wifiManager",
    "on_p2pPeerDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pPeerDeviceChange"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event p2pPeerDeviceChange unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01363",
    "wifiManager",
    "on_p2pPeerDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pPeerDeviceChange"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event p2pPeerDeviceChange unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01364",
    "wifiManager",
    "on_p2pPeerDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pPeerDeviceChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event p2pPeerDeviceChange unregister under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01365",
    "wifiManager",
    "on_p2pPeerDeviceChange",
    "condition",
    buildParams([
      ["event", "p2pPeerDeviceChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event p2pPeerDeviceChange unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01366",
    "wifiManager",
    "on_p2pPersistentGroupChange",
    "condition",
    buildParams([
      ["event", "p2pPersistentGroupChange"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event p2pPersistentGroupChange register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01367",
    "wifiManager",
    "on_p2pPersistentGroupChange",
    "condition",
    buildParams([
      ["event", "p2pPersistentGroupChange"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event p2pPersistentGroupChange register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01368",
    "wifiManager",
    "on_p2pPersistentGroupChange",
    "condition",
    buildParams([
      ["event", "p2pPersistentGroupChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event p2pPersistentGroupChange register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01369",
    "wifiManager",
    "on_p2pPersistentGroupChange",
    "condition",
    buildParams([
      ["event", "p2pPersistentGroupChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event p2pPersistentGroupChange register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01370",
    "wifiManager",
    "on_p2pPersistentGroupChange",
    "condition",
    buildParams([
      ["event", "p2pPersistentGroupChange"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event p2pPersistentGroupChange unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01371",
    "wifiManager",
    "on_p2pPersistentGroupChange",
    "condition",
    buildParams([
      ["event", "p2pPersistentGroupChange"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event p2pPersistentGroupChange unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01372",
    "wifiManager",
    "on_p2pPersistentGroupChange",
    "condition",
    buildParams([
      ["event", "p2pPersistentGroupChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event p2pPersistentGroupChange unregister under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01373",
    "wifiManager",
    "on_p2pPersistentGroupChange",
    "condition",
    buildParams([
      ["event", "p2pPersistentGroupChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event p2pPersistentGroupChange unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01374",
    "wifiManager",
    "on_p2pDiscoveryChange",
    "condition",
    buildParams([
      ["event", "p2pDiscoveryChange"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event p2pDiscoveryChange register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01375",
    "wifiManager",
    "on_p2pDiscoveryChange",
    "condition",
    buildParams([
      ["event", "p2pDiscoveryChange"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event p2pDiscoveryChange register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01376",
    "wifiManager",
    "on_p2pDiscoveryChange",
    "condition",
    buildParams([
      ["event", "p2pDiscoveryChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event p2pDiscoveryChange register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01377",
    "wifiManager",
    "on_p2pDiscoveryChange",
    "condition",
    buildParams([
      ["event", "p2pDiscoveryChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event p2pDiscoveryChange register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01378",
    "wifiManager",
    "on_p2pDiscoveryChange",
    "condition",
    buildParams([
      ["event", "p2pDiscoveryChange"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event p2pDiscoveryChange unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01379",
    "wifiManager",
    "on_p2pDiscoveryChange",
    "condition",
    buildParams([
      ["event", "p2pDiscoveryChange"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event p2pDiscoveryChange unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01380",
    "wifiManager",
    "on_p2pDiscoveryChange",
    "condition",
    buildParams([
      ["event", "p2pDiscoveryChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event p2pDiscoveryChange unregister under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01381",
    "wifiManager",
    "on_p2pDiscoveryChange",
    "condition",
    buildParams([
      ["event", "p2pDiscoveryChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event p2pDiscoveryChange unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_PC_01382",
    "wifiManager",
    "getScanResults",
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
    "getScanResults invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01383",
    "wifiManager",
    "getScanResults",
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
    "getScanResults invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01384",
    "wifiManager",
    "getScanResults",
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
    "getScanResults invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01385",
    "wifiManager",
    "getScanResults",
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
    "getScanResults invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01386",
    "wifiManager",
    "getScanResults",
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
    "getScanResults invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01387",
    "wifiManager",
    "getScanResults",
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
    "getScanResults invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01388",
    "wifiManager",
    "getLinkedInfo",
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
    "getLinkedInfo invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01389",
    "wifiManager",
    "getLinkedInfo",
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
    "getLinkedInfo invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01390",
    "wifiManager",
    "getLinkedInfo",
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
    "getLinkedInfo invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01391",
    "wifiManager",
    "getLinkedInfo",
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
    "getLinkedInfo invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01392",
    "wifiManager",
    "getLinkedInfo",
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
    "getLinkedInfo invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01393",
    "wifiManager",
    "getLinkedInfo",
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
    "getLinkedInfo invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01394",
    "wifiManager",
    "addDeviceConfig",
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
    "addDeviceConfig invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01395",
    "wifiManager",
    "addDeviceConfig",
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
    "addDeviceConfig invokeMode=promise"
  ),
  makeApiTestCase(
    "WM_PC_01396",
    "wifiManager",
    "addDeviceConfig",
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
    "addDeviceConfig invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01397",
    "wifiManager",
    "addDeviceConfig",
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
    "addDeviceConfig invokeMode=callback"
  ),
  makeApiTestCase(
    "WM_PC_01398",
    "wifiManager",
    "addDeviceConfig",
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
    "addDeviceConfig invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01399",
    "wifiManager",
    "addDeviceConfig",
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
    "addDeviceConfig invokeMode=sync"
  ),
  makeApiTestCase(
    "WM_PC_01400",
    "wifiManager",
    "addCandidateConfig",
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
    "addCandidateConfig invokeMode=promise"
  ),
];
