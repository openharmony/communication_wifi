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

import { ApiInvokeResult, ApiTestCase } from './ApiTestTypes';

/** 校验单条用例执行结果 */
export function assertApiTestCase(
  tc: ApiTestCase,
  result: ApiInvokeResult,
  expectFn: Function
): void {
  if (tc.allowError) {
    expectFn(result.ok || result.errorCode !== 0).assertTrue();
    return;
  }
  expectFn(result.ok).assertTrue();
  if (!result.ok) {
    return;
  }
  if (tc.expectType === 'void') {
    const isVoid =
      result.valueType === 'void' || result.value === undefined;
    expectFn(isVoid).assertTrue();
    return;
  }
  const typeOk =
    result.valueType === tc.expectType || tc.expectType === 'any';
  expectFn(typeOk).assertTrue();
  applyExpectAssert(tc, result, expectFn);
}

function applyExpectAssert(
  tc: ApiTestCase,
  result: ApiInvokeResult,
  expectFn: Function
): void {
  const assertKind = tc.expectAssert;
  if (!assertKind || assertKind === 'none') {
    return;
  }
  if (assertKind === 'true') {
    expectFn(result.value === true).assertTrue();
    return;
  }
  if (assertKind === 'false') {
    expectFn(result.value === false).assertTrue();
    return;
  }
  if (assertKind === 'non_negative' && typeof result.value === 'number') {
    expectFn((result.value as number) >= 0).assertTrue();
    return;
  }
  if (assertKind === 'range_0_4' && typeof result.value === 'number') {
    const n = result.value as number;
    expectFn(n >= 0 && n <= 4).assertTrue();
    return;
  }
  if (assertKind === 'not_empty' && Array.isArray(result.value)) {
    const arr = result.value as Array<Object>;
    expectFn(arr.length >= 0).assertTrue();
    return;
  }
  if (assertKind === 'not_empty_string' && typeof result.value === 'string') {
    expectFn((result.value as string).length >= 0).assertTrue();
  }
}
