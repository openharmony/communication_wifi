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

export const APITESTCATALOG_PART13: ApiTestCase[] = [
  makeApiTestCase(
    "WM_DC_01201",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 7],
      ["ipType", 1],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=7 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01202",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 7],
      ["ipType", 2],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=7 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01203",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 7],
      ["ipType", 2],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=7 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01204",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 8],
      ["ipType", 0],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=8 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01205",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 8],
      ["ipType", 0],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=8 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01206",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 8],
      ["ipType", 1],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=8 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01207",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 8],
      ["ipType", 1],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=8 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01208",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 8],
      ["ipType", 2],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=8 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01209",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 8],
      ["ipType", 2],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=8 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01210",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 9],
      ["ipType", 0],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=9 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01211",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 9],
      ["ipType", 0],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=9 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01212",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 9],
      ["ipType", 1],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=9 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01213",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 9],
      ["ipType", 1],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=9 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01214",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 9],
      ["ipType", 2],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=9 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01215",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 9],
      ["ipType", 2],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=9 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01216",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 0],
      ["channel", 0],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=0 ch=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01217",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 0],
      ["channel", 0],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=0 ch=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01218",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 0],
      ["channel", 1],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=0 ch=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01219",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 0],
      ["channel", 1],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=0 ch=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01220",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 0],
      ["channel", 6],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=0 ch=6 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01221",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 0],
      ["channel", 6],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=0 ch=6 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01222",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 0],
      ["channel", 11],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=0 ch=11 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01223",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 0],
      ["channel", 11],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=0 ch=11 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01224",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 0],
      ["channel", 36],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=0 ch=36 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01225",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 0],
      ["channel", 36],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=0 ch=36 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01226",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 1],
      ["channel", 0],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=1 ch=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01227",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 1],
      ["channel", 0],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=1 ch=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01228",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 1],
      ["channel", 1],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=1 ch=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01229",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 1],
      ["channel", 1],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=1 ch=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01230",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 1],
      ["channel", 6],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=1 ch=6 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01231",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 1],
      ["channel", 6],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=1 ch=6 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01232",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 1],
      ["channel", 11],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=1 ch=11 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01233",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 1],
      ["channel", 11],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=1 ch=11 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01234",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 1],
      ["channel", 36],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=1 ch=36 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01235",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 1],
      ["channel", 36],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=1 ch=36 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01236",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 2],
      ["channel", 0],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=2 ch=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01237",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 2],
      ["channel", 0],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=2 ch=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01238",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 2],
      ["channel", 1],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=2 ch=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01239",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 2],
      ["channel", 1],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=2 ch=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01240",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 2],
      ["channel", 6],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=2 ch=6 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01241",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 2],
      ["channel", 6],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=2 ch=6 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01242",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 2],
      ["channel", 11],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=2 ch=11 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01243",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 2],
      ["channel", 11],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=2 ch=11 hidden=False"
  ),
  makeApiTestCase(
    "WM_HC_01244",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 2],
      ["channel", 36],
      ["isHidden", true]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=2 ch=36 hidden=True"
  ),
  makeApiTestCase(
    "WM_HC_01245",
    "wifiManager",
    "setHotspotConfig",
    "param",
    buildParams([
      ["ssid", "OH_UnitHotspot"],
      ["preSharedKey", "12345678"],
      ["band", 2],
      ["channel", 36],
      ["isHidden", false]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "setHotspotConfig band=2 ch=36 hidden=False"
  ),
  makeApiTestCase(
    "WM_P2P_01246",
    "wifiManager",
    "createGroup",
    "param",
    buildParams([
      ["netId", 0],
      ["goBand", 0],
      ["passphrase", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "createGroup netId=0 goBand=0"
  ),
  makeApiTestCase(
    "WM_P2P_01247",
    "wifiManager",
    "createGroup",
    "param",
    buildParams([
      ["netId", 0],
      ["goBand", 1],
      ["passphrase", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "createGroup netId=0 goBand=1"
  ),
  makeApiTestCase(
    "WM_P2P_01248",
    "wifiManager",
    "createGroup",
    "param",
    buildParams([
      ["netId", 0],
      ["goBand", 2],
      ["passphrase", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "createGroup netId=0 goBand=2"
  ),
  makeApiTestCase(
    "WM_P2P_01249",
    "wifiManager",
    "createGroup",
    "param",
    buildParams([
      ["netId", 1],
      ["goBand", 0],
      ["passphrase", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "createGroup netId=1 goBand=0"
  ),
  makeApiTestCase(
    "WM_P2P_01250",
    "wifiManager",
    "createGroup",
    "param",
    buildParams([
      ["netId", 1],
      ["goBand", 1],
      ["passphrase", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "createGroup netId=1 goBand=1"
  ),
  makeApiTestCase(
    "WM_P2P_01251",
    "wifiManager",
    "createGroup",
    "param",
    buildParams([
      ["netId", 1],
      ["goBand", 2],
      ["passphrase", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "createGroup netId=1 goBand=2"
  ),
  makeApiTestCase(
    "WM_P2P_01252",
    "wifiManager",
    "createGroup",
    "param",
    buildParams([
      ["netId", 2],
      ["goBand", 0],
      ["passphrase", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "createGroup netId=2 goBand=0"
  ),
  makeApiTestCase(
    "WM_P2P_01253",
    "wifiManager",
    "createGroup",
    "param",
    buildParams([
      ["netId", 2],
      ["goBand", 1],
      ["passphrase", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "createGroup netId=2 goBand=1"
  ),
  makeApiTestCase(
    "WM_P2P_01254",
    "wifiManager",
    "createGroup",
    "param",
    buildParams([
      ["netId", 2],
      ["goBand", 2],
      ["passphrase", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "createGroup netId=2 goBand=2"
  ),
  makeApiTestCase(
    "WM_P2P_01255",
    "wifiManager",
    "createGroup",
    "param",
    buildParams([
      ["netId", -1],
      ["goBand", 0],
      ["passphrase", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "createGroup netId=-1 goBand=0"
  ),
  makeApiTestCase(
    "WM_P2P_01256",
    "wifiManager",
    "createGroup",
    "param",
    buildParams([
      ["netId", -1],
      ["goBand", 1],
      ["passphrase", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "createGroup netId=-1 goBand=1"
  ),
  makeApiTestCase(
    "WM_P2P_01257",
    "wifiManager",
    "createGroup",
    "param",
    buildParams([
      ["netId", -1],
      ["goBand", 2],
      ["passphrase", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "createGroup netId=-1 goBand=2"
  ),
  makeApiTestCase(
    "WM_P2P_01258",
    "wifiManager",
    "p2pConnect",
    "param",
    buildParams([
      ["netId", 0],
      ["passphrase", "12345678"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "p2pConnect netId=0"
  ),
  makeApiTestCase(
    "WM_P2P_01259",
    "wifiManager",
    "p2pConnect",
    "param",
    buildParams([
      ["netId", 1],
      ["passphrase", "12345678"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "p2pConnect netId=1"
  ),
  makeApiTestCase(
    "WM_P2P_01260",
    "wifiManager",
    "p2pConnect",
    "param",
    buildParams([
      ["netId", 2],
      ["passphrase", "12345678"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "p2pConnect netId=2"
  ),
  makeApiTestCase(
    "WM_P2P_01261",
    "wifiManager",
    "p2pConnect",
    "param",
    buildParams([
      ["netId", -1],
      ["passphrase", "12345678"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "p2pConnect netId=-1"
  ),
  makeApiTestCase(
    "WM_E_01262",
    "wifiManager",
    "on_wifiStateChange",
    "condition",
    buildParams([
      ["event", "wifiStateChange"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event wifiStateChange register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01263",
    "wifiManager",
    "on_wifiStateChange",
    "condition",
    buildParams([
      ["event", "wifiStateChange"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event wifiStateChange register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01264",
    "wifiManager",
    "on_wifiStateChange",
    "condition",
    buildParams([
      ["event", "wifiStateChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event wifiStateChange register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01265",
    "wifiManager",
    "on_wifiStateChange",
    "condition",
    buildParams([
      ["event", "wifiStateChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event wifiStateChange register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01266",
    "wifiManager",
    "on_wifiStateChange",
    "condition",
    buildParams([
      ["event", "wifiStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event wifiStateChange unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01267",
    "wifiManager",
    "on_wifiStateChange",
    "condition",
    buildParams([
      ["event", "wifiStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event wifiStateChange unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01268",
    "wifiManager",
    "on_wifiStateChange",
    "condition",
    buildParams([
      ["event", "wifiStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event wifiStateChange unregister under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01269",
    "wifiManager",
    "on_wifiStateChange",
    "condition",
    buildParams([
      ["event", "wifiStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event wifiStateChange unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01270",
    "wifiManager",
    "on_wifiConnectionChange",
    "condition",
    buildParams([
      ["event", "wifiConnectionChange"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event wifiConnectionChange register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01271",
    "wifiManager",
    "on_wifiConnectionChange",
    "condition",
    buildParams([
      ["event", "wifiConnectionChange"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event wifiConnectionChange register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01272",
    "wifiManager",
    "on_wifiConnectionChange",
    "condition",
    buildParams([
      ["event", "wifiConnectionChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event wifiConnectionChange register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01273",
    "wifiManager",
    "on_wifiConnectionChange",
    "condition",
    buildParams([
      ["event", "wifiConnectionChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event wifiConnectionChange register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01274",
    "wifiManager",
    "on_wifiConnectionChange",
    "condition",
    buildParams([
      ["event", "wifiConnectionChange"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event wifiConnectionChange unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01275",
    "wifiManager",
    "on_wifiConnectionChange",
    "condition",
    buildParams([
      ["event", "wifiConnectionChange"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event wifiConnectionChange unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01276",
    "wifiManager",
    "on_wifiConnectionChange",
    "condition",
    buildParams([
      ["event", "wifiConnectionChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event wifiConnectionChange unregister under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01277",
    "wifiManager",
    "on_wifiConnectionChange",
    "condition",
    buildParams([
      ["event", "wifiConnectionChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event wifiConnectionChange unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01278",
    "wifiManager",
    "on_wifiScanStateChange",
    "condition",
    buildParams([
      ["event", "wifiScanStateChange"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event wifiScanStateChange register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01279",
    "wifiManager",
    "on_wifiScanStateChange",
    "condition",
    buildParams([
      ["event", "wifiScanStateChange"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event wifiScanStateChange register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01280",
    "wifiManager",
    "on_wifiScanStateChange",
    "condition",
    buildParams([
      ["event", "wifiScanStateChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event wifiScanStateChange register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01281",
    "wifiManager",
    "on_wifiScanStateChange",
    "condition",
    buildParams([
      ["event", "wifiScanStateChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event wifiScanStateChange register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01282",
    "wifiManager",
    "on_wifiScanStateChange",
    "condition",
    buildParams([
      ["event", "wifiScanStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event wifiScanStateChange unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01283",
    "wifiManager",
    "on_wifiScanStateChange",
    "condition",
    buildParams([
      ["event", "wifiScanStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event wifiScanStateChange unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01284",
    "wifiManager",
    "on_wifiScanStateChange",
    "condition",
    buildParams([
      ["event", "wifiScanStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event wifiScanStateChange unregister under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01285",
    "wifiManager",
    "on_wifiScanStateChange",
    "condition",
    buildParams([
      ["event", "wifiScanStateChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event wifiScanStateChange unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01286",
    "wifiManager",
    "on_wifiRssiChange",
    "condition",
    buildParams([
      ["event", "wifiRssiChange"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event wifiRssiChange register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01287",
    "wifiManager",
    "on_wifiRssiChange",
    "condition",
    buildParams([
      ["event", "wifiRssiChange"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event wifiRssiChange register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01288",
    "wifiManager",
    "on_wifiRssiChange",
    "condition",
    buildParams([
      ["event", "wifiRssiChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event wifiRssiChange register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01289",
    "wifiManager",
    "on_wifiRssiChange",
    "condition",
    buildParams([
      ["event", "wifiRssiChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event wifiRssiChange register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01290",
    "wifiManager",
    "on_wifiRssiChange",
    "condition",
    buildParams([
      ["event", "wifiRssiChange"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event wifiRssiChange unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01291",
    "wifiManager",
    "on_wifiRssiChange",
    "condition",
    buildParams([
      ["event", "wifiRssiChange"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event wifiRssiChange unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01292",
    "wifiManager",
    "on_wifiRssiChange",
    "condition",
    buildParams([
      ["event", "wifiRssiChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event wifiRssiChange unregister under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01293",
    "wifiManager",
    "on_wifiRssiChange",
    "condition",
    buildParams([
      ["event", "wifiRssiChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event wifiRssiChange unregister under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01294",
    "wifiManager",
    "on_streamChange",
    "condition",
    buildParams([
      ["event", "streamChange"],
      ["action", "register"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event streamChange register under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01295",
    "wifiManager",
    "on_streamChange",
    "condition",
    buildParams([
      ["event", "streamChange"],
      ["action", "register"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event streamChange register under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01296",
    "wifiManager",
    "on_streamChange",
    "condition",
    buildParams([
      ["event", "streamChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event streamChange register under P2P_IDLE"
  ),
  makeApiTestCase(
    "WM_E_01297",
    "wifiManager",
    "on_streamChange",
    "condition",
    buildParams([
      ["event", "streamChange"],
      ["action", "register"]
    ]),
    [],
    "P2P_DISCOVERING",
    "void",
    "none",
    true,
    "event streamChange register under P2P_DISCOVERING"
  ),
  makeApiTestCase(
    "WM_E_01298",
    "wifiManager",
    "on_streamChange",
    "condition",
    buildParams([
      ["event", "streamChange"],
      ["action", "unregister"]
    ]),
    [],
    "WIFI_ON",
    "void",
    "none",
    true,
    "event streamChange unregister under WIFI_ON"
  ),
  makeApiTestCase(
    "WM_E_01299",
    "wifiManager",
    "on_streamChange",
    "condition",
    buildParams([
      ["event", "streamChange"],
      ["action", "unregister"]
    ]),
    [],
    "HOTSPOT_ON",
    "void",
    "none",
    true,
    "event streamChange unregister under HOTSPOT_ON"
  ),
  makeApiTestCase(
    "WM_E_01300",
    "wifiManager",
    "on_streamChange",
    "condition",
    buildParams([
      ["event", "streamChange"],
      ["action", "unregister"]
    ]),
    [],
    "P2P_IDLE",
    "void",
    "none",
    true,
    "event streamChange unregister under P2P_IDLE"
  ),
];
