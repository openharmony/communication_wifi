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

export const APITESTCATALOG_PART11: ApiTestCase[] = [
  makeApiTestCase(
    "WM_DC_01001",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=4 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01002",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=4 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01003",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=4 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01004",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=4 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01005",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=4 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01006",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=5 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01007",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=5 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01008",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=5 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01009",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=5 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01010",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=5 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01011",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=5 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01012",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=6 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01013",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=6 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01014",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=6 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01015",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=6 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01016",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=6 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01017",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=6 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01018",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=7 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01019",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=7 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01020",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=7 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01021",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=7 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01022",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=7 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01023",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=7 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01024",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=8 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01025",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=8 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01026",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=8 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01027",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=8 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01028",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=8 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01029",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=8 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01030",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=9 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01031",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=9 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01032",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=9 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01033",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=9 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01034",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=9 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01035",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_open"],
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
    "addDeviceConfig ssid=0 sec=9 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01036",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=0 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01037",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=0 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01038",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=0 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01039",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=0 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01040",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=0 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01041",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=0 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01042",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=1 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01043",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=1 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01044",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=1 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01045",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=1 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01046",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=1 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01047",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=1 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01048",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=2 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01049",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=2 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01050",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=2 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01051",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=2 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01052",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=2 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01053",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=2 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01054",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=3 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01055",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=3 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01056",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=3 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01057",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=3 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01058",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=3 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01059",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=3 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01060",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=4 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01061",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=4 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01062",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=4 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01063",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=4 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01064",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=4 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01065",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=4 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01066",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=5 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01067",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=5 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01068",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=5 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01069",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=5 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01070",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=5 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01071",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=5 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01072",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=6 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01073",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=6 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01074",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=6 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01075",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=6 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01076",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=6 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01077",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=6 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01078",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=7 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01079",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=7 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01080",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=7 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01081",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=7 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01082",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=7 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01083",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=7 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01084",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=8 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01085",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=8 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01086",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=8 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01087",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=8 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01088",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=8 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01089",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=8 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01090",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=9 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01091",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=9 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01092",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=9 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01093",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=9 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01094",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=9 ip=2 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01095",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_ssid_wpa2"],
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
    "addDeviceConfig ssid=1 sec=9 ip=2 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01096",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=0 ip=0 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01097",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=0 ip=0 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01098",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=0 ip=1 hidden=True"
  ),
  makeApiTestCase(
    "WM_DC_01099",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=0 ip=1 hidden=False"
  ),
  makeApiTestCase(
    "WM_DC_01100",
    "wifiManager",
    "addDeviceConfig",
    "param",
    buildParams([
      ["ssid", "ut_hidden"],
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
    "addDeviceConfig ssid=2 sec=0 ip=2 hidden=True"
  ),
];
