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

import { ApiPrecondition, ApiTestCase, ApiTestCategory } from './ApiTestTypes';

/** 构造类型安全的 API 测试用例（供生成器调用） */
export function makeApiTestCase(
  id: string,
  module: string,
  api: string,
  category: ApiTestCategory,
  params: Record<string, Object>,
  comboSteps: string[],
  precond: ApiPrecondition,
  expectType: string,
  expectAssert: string,
  allowError: boolean,
  desc: string
): ApiTestCase {
  return {
    id: id,
    module: module,
    api: api,
    category: category,
    params: params,
    comboSteps: comboSteps,
    precond: precond,
    expectType: expectType,
    expectAssert: expectAssert,
    allowError: allowError,
    desc: desc,
  };
}

type ParamValue = string | number | boolean;

/** 构造类型安全的 params 字典（供生成器调用） */
export function buildParams(items: Array<[string, ParamValue]>): Record<string, Object> {
  const result: Record<string, Object> = {};
  for (let i = 0; i < items.length; i++) {
    const key = items[i][0];
    const val = items[i][1];
    result[key] = val;
  }
  return result;
}
