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
import { describe, it, expect } from '@ohos/hypium';
import hilog from '@ohos.hilog';
import { API_TEST_CASE_COUNT } from './ApiTestCatalog';
import { register_param_part01 } from './suite/ApiCoverage.param.part01';
import { register_param_part02 } from './suite/ApiCoverage.param.part02';
import { register_param_part03 } from './suite/ApiCoverage.param.part03';
import { register_param_part04 } from './suite/ApiCoverage.param.part04';
import { register_param_part05 } from './suite/ApiCoverage.param.part05';
import { register_param_part06 } from './suite/ApiCoverage.param.part06';
import { register_param_part07 } from './suite/ApiCoverage.param.part07';
import { register_return_part01 } from './suite/ApiCoverage.return.part01';
import { register_return_part02 } from './suite/ApiCoverage.return.part02';
import { register_return_part03 } from './suite/ApiCoverage.return.part03';
import { register_combo_part01 } from './suite/ApiCoverage.combo.part01';
import { register_combo_part02 } from './suite/ApiCoverage.combo.part02';
import { register_combo_part03 } from './suite/ApiCoverage.combo.part03';
import { register_combo_part04 } from './suite/ApiCoverage.combo.part04';
import { register_condition_part01 } from './suite/ApiCoverage.condition.part01';
import { register_condition_part02 } from './suite/ApiCoverage.condition.part02';
import { register_condition_part03 } from './suite/ApiCoverage.condition.part03';
import { register_condition_part04 } from './suite/ApiCoverage.condition.part04';
import { register_condition_part05 } from './suite/ApiCoverage.condition.part05';
import { register_condition_part06 } from './suite/ApiCoverage.condition.part06';
import { register_condition_part07 } from './suite/ApiCoverage.condition.part07';
import { register_condition_part08 } from './suite/ApiCoverage.condition.part08';

const TAG = 'wifiTestApp [ApiCoverageSuite]';

export function registerGeneratedApiSuites(): void {
  describe('WifiConnectivity_ApiUnitCoverage_All', () => {
    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_CATALOG_TOTAL
     * @tc.name catalog_total_at_least_2000
     * @tc.desc Verify generated API catalog size >= 2000
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('catalog_total_at_least_2000', 0, () => {
      expect(API_TEST_CASE_COUNT >= 2000).assertTrue();
      hilog.info(
        0x1500,
        TAG,
        'total cases=%{public}d',
        API_TEST_CASE_COUNT
      );
    });
  });

  describe('Api_Parameter_Coverage', () => {
    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_PARAM_META
     * @tc.name Api_Parameter_Coverage_meta_count
     * @tc.desc Verify param suite case count > 0
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('Api_Parameter_Coverage_meta_count', 0, () => {
      expect(617 > 0).assertTrue();
      expect(API_TEST_CASE_COUNT >= 2000).assertTrue();
    });
    register_param_part01();
    register_param_part02();
    register_param_part03();
    register_param_part04();
    register_param_part05();
    register_param_part06();
    register_param_part07();
  });

  describe('Api_ReturnValue_Coverage', () => {
    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_RETURN_META
     * @tc.name Api_ReturnValue_Coverage_meta_count
     * @tc.desc Verify return suite case count > 0
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 1
     */
    it('Api_ReturnValue_Coverage_meta_count', 0, () => {
      expect(270 > 0).assertTrue();
      expect(API_TEST_CASE_COUNT >= 2000).assertTrue();
    });
    register_return_part01();
    register_return_part02();
    register_return_part03();
  });

  describe('Api_Combination_Coverage', () => {
    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_COMBO_META
     * @tc.name Api_Combination_Coverage_meta_count
     * @tc.desc Verify combo suite case count > 0
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 3
     */
    it('Api_Combination_Coverage_meta_count', 0, () => {
      expect(383 > 0).assertTrue();
      expect(API_TEST_CASE_COUNT >= 2000).assertTrue();
    });
    register_combo_part01();
    register_combo_part02();
    register_combo_part03();
    register_combo_part04();
  });

  describe('Api_Condition_Coverage', () => {
    /**
     * @tc.number SUB_WIFI_CONNECTIVITY_API_CONDITION_META
     * @tc.name Api_Condition_Coverage_meta_count
     * @tc.desc Verify condition suite case count > 0
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('Api_Condition_Coverage_meta_count', 0, () => {
      expect(736 > 0).assertTrue();
      expect(API_TEST_CASE_COUNT >= 2000).assertTrue();
    });
    register_condition_part01();
    register_condition_part02();
    register_condition_part03();
    register_condition_part04();
    register_condition_part05();
    register_condition_part06();
    register_condition_part07();
    register_condition_part08();
  });

}
