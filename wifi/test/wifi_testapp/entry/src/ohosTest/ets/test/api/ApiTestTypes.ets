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

/** 用例分类：参数 / 返回值 / 组合 / 条件 */
export type ApiTestCategory = 'param' | 'return' | 'combo' | 'condition';

/** 前置条件标签 */
export type ApiPrecondition =
  | 'ANY'
  | 'WIFI_OFF'
  | 'WIFI_ON'
  | 'WIFI_ON_SCAN'
  | 'HOTSPOT_OFF'
  | 'HOTSPOT_ON'
  | 'P2P_IDLE'
  | 'P2P_DISCOVERING';

/** 单条 API 单元测试用例定义 */
export interface ApiTestCase {
  id: string;
  module: string;
  api: string;
  category: ApiTestCategory;
  params: Record<string, Object>;
  comboSteps: string[];
  precond: ApiPrecondition;
  expectType: string;
  expectAssert: string;
  allowError: boolean;
  desc: string;
}

/** API 调用结果 */
export interface ApiInvokeResult {
  ok: boolean;
  valueType: string;
  value: Object | undefined;
  errorCode: number;
  errorMessage: string;
}
