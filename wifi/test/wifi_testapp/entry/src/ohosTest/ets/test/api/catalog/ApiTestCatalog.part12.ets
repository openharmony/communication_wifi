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

export const APITESTCATALOG_PART12: ApiTestCase[] = [
  makeApiTestCase(
    "WM_DC_01101",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=0 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01102",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=1 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01103",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=1 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01104",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=1 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01105",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=1 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01106",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=1 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01107",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=1 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01108",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=2 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01109",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=2 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01110",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=2 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01111",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=2 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01112",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=2 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01113",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=2 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01114",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=3 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01115",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=3 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01116",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=3 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01117",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=3 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01118",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=3 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01119",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=3 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01120",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=4 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01121",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 4],
      ["ipType", 0],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=4 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01122",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 4],
      ["ipType", 1],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=4 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01123",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 4],
      ["ipType", 1],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=4 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01124",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 4],
      ["ipType", 2],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=4 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01125",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 4],
      ["ipType", 2],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=4 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01126",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 5],
      ["ipType", 0],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=5 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01127",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 5],
      ["ipType", 0],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=5 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01128",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 5],
      ["ipType", 1],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=5 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01129",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 5],
      ["ipType", 1],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=5 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01130",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 5],
      ["ipType", 2],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=5 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01131",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 5],
      ["ipType", 2],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=5 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01132",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 6],
      ["ipType", 0],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=6 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01133",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 6],
      ["ipType", 0],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=6 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01134",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 6],
      ["ipType", 1],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=6 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01135",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 6],
      ["ipType", 1],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=6 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01136",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 6],
      ["ipType", 2],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=6 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01137",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 6],
      ["ipType", 2],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=6 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01138",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 7],
      ["ipType", 0],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=7 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01139",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 7],
      ["ipType", 0],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=7 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01140",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
      ["securityType", 7],
      ["ipType", 1],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=2 sec=7 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01141",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=7 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01142",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=7 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01143",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=7 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01144",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=8 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01145",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=8 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01146",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=8 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01147",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=8 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01148",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=8 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01149",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=8 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01150",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=9 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01151",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=9 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01152",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=9 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01153",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=9 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01154",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=9 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01155",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=9 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01156",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=0 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01157",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=0 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01158",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=0 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01159",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=0 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01160",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=0 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01161",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=0 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01162",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=1 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01163",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=1 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01164",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=1 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01165",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=1 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01166",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=1 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01167",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=1 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01168",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=2 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01169",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=2 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01170",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=2 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01171",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=2 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01172",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=2 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01173",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=2 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01174",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=3 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01175",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=3 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01176",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=3 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01177",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=3 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01178",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=3 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01179",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=3 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01180",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
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
    "addDeviceConfig ssid=3 sec=4 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01181",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 4],
      ["ipType", 0],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=4 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01182",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 4],
      ["ipType", 1],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=4 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01183",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 4],
      ["ipType", 1],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=4 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01184",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 4],
      ["ipType", 2],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=4 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01185",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 4],
      ["ipType", 2],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=4 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01186",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 5],
      ["ipType", 0],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=5 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01187",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 5],
      ["ipType", 0],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=5 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01188",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 5],
      ["ipType", 1],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=5 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01189",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 5],
      ["ipType", 1],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=5 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01190",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 5],
      ["ipType", 2],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=5 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01191",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 5],
      ["ipType", 2],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=5 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01192",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 6],
      ["ipType", 0],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=6 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01193",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 6],
      ["ipType", 0],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=6 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01194",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 6],
      ["ipType", 1],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=6 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01195",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 6],
      ["ipType", 1],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=6 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01196",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 6],
      ["ipType", 2],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=6 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01197",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 6],
      ["ipType", 2],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=6 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01198",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 7],
      ["ipType", 0],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=7 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01199",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 7],
      ["ipType", 0],
      ["isHiddenSsid", false],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=7 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01200",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", ""],
      ["securityType", 7],
      ["ipType", 1],
      ["isHiddenSsid", true],
      ["preSharedKey", "12345678"]
    ]),
    [],
    "WIFI_ON",
    "number",
    "none",
    true,
    "addDeviceConfig ssid=3 sec=7 ip=1 hidden=True"
  ),
];
