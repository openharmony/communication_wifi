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

export const APITESTCATALOG_PART21: ApiTestCase[] = [
  makeApiTestCase(
    "LE_C_02001",
    "linkEnhance",
    "createConnection",
    "condition",
    buildParams([
      ["deviceId", ""],
      ["name", "ut_conn"]
    ]),
    [],
    "WIFI_ON",
    "object",
    "none",
    true,
    "linkEnhance.createConnection condition=WIFI_ON"
  ),
  makeApiTestCase(
    "LE_C_02002",
    "linkEnhance",
    "createConnection",
    "condition",
    buildParams([
      ["deviceId", ""],
      ["name", "ut_conn"]
    ]),
    [],
    "WIFI_ON_SCAN",
    "object",
    "none",
    true,
    "linkEnhance.createConnection condition=WIFI_ON_SCAN"
  ),
  makeApiTestCase(
    "LE_C_02003",
    "linkEnhance",
    "createConnection",
    "condition",
    buildParams([
      ["deviceId", ""],
      ["name", "ut_conn"]
    ]),
    [],
    "HOTSPOT_OFF",
    "object",
    "none",
    true,
    "linkEnhance.createConnection condition=HOTSPOT_OFF"
  ),
  makeApiTestCase(
    "LE_C_02004",
    "linkEnhance",
    "createConnection",
    "condition",
    buildParams([
      ["deviceId", ""],
      ["name", "ut_conn"]
    ]),
    [],
    "HOTSPOT_ON",
    "object",
    "none",
    true,
    "linkEnhance.createConnection condition=HOTSPOT_ON"
  ),
  makeApiTestCase(
    "LE_C_02005",
    "linkEnhance",
    "createConnection",
    "condition",
    buildParams([
      ["deviceId", ""],
      ["name", "ut_conn"]
    ]),
    [],
    "P2P_IDLE",
    "object",
    "none",
    true,
    "linkEnhance.createConnection condition=P2P_IDLE"
  ),
  makeApiTestCase(
    "LE_C_02006",
    "linkEnhance",
    "createConnection",
    "condition",
    buildParams([
      ["deviceId", ""],
      ["name", "ut_conn"]
    ]),
    [],
    "P2P_DISCOVERING",
    "object",
    "none",
    true,
    "linkEnhance.createConnection condition=P2P_DISCOVERING"
  ),
];
