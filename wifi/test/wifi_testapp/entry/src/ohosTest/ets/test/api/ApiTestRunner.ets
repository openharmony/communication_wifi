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

import hilog from '@ohos.hilog';
import { expect } from '@ohos/hypium';
import { API_TEST_CASES } from './ApiTestCatalog';
import { ApiTestCase } from './ApiTestTypes';
import { assertApiTestCase } from './ApiTestAssertions';
import { applyApiPrecondition } from './ApiTestPrecond';
import { invokeApiTestCase } from './ApiTestExecutor.generated';

const TAG = 'wifiTestApp [ApiCoverageSuite]';

async function runComboSteps(tc: ApiTestCase): Promise<void> {
  if (tc.comboSteps.length === 0) {
    return;
  }
  for (let i = 0; i < tc.comboSteps.length; i++) {
    const stepApi = tc.comboSteps[i];
    const stepCase: ApiTestCase = {
      id: `${tc.id}_step${i}`,
      module: tc.module,
      api: stepApi,
      category: 'combo',
      params: {},
      comboSteps: [],
      precond: 'ANY',
      expectType: 'any',
      expectAssert: 'none',
      allowError: true,
      desc: `combo step ${stepApi}`,
    };
    await invokeApiTestCase(stepCase);
  }
}

/** 按用例 id 查找目录项 */
export function findApiTestCaseById(id: string): ApiTestCase | undefined {
  return API_TEST_CASES.find((c: ApiTestCase) => c.id === id);
}

/** 执行单条 API 覆盖用例（供生成 suite 中的 it 调用） */
export async function executeApiTestCaseById(id: string): Promise<void> {
  const tc = findApiTestCaseById(id);
  expect(tc !== undefined).assertTrue();
  if (tc === undefined) {
    return;
  }
  await applyApiPrecondition(tc.precond);
  await runComboSteps(tc);
  const result = await invokeApiTestCase(tc);
  assertApiTestCase(tc, result, expect);
  hilog.info(0x1500, TAG, '%{public}s done %{public}s', tc.id, tc.desc);
}
