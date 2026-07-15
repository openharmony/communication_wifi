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
import { Hypium } from '@ohos/hypium';
import testsuite from '../test/List.test';
import window from '@ohos.window';
import UIAbility from '@ohos.app.ability.UIAbility';
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import Want from '@ohos.app.ability.Want';
import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import abilityAccessCtrl, { Permissions } from '@ohos.abilityAccessCtrl';

/** 用户授权类权限：跑用例前尽量补齐（可配合 atm perm grant） */
const USER_GRANT_PERMISSIONS: Array<Permissions> = [
  'ohos.permission.LOCATION',
  'ohos.permission.APPROXIMATELY_LOCATION',
  'ohos.permission.LOCATION_IN_BACKGROUND',
  'ohos.permission.DISTRIBUTED_DATASYNC',
];

export default class TestAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam) {
    hilog.info(0x0000, 'testTag', '%{public}s', 'TestAbility onCreate');
    hilog.info(
      0x0000,
      'testTag',
      '%{public}s',
      'want param:' + JSON.stringify(want) ?? ''
    );
    hilog.info(
      0x0000,
      'testTag',
      '%{public}s',
      'launchParam:' + JSON.stringify(launchParam) ?? ''
    );
    this.requestPermissionsThenRunTests();
  }

  private async requestPermissionsThenRunTests(): Promise<void> {
    try {
      const atManager = abilityAccessCtrl.createAtManager();
      const result = await atManager.requestPermissionsFromUser(
        this.context,
        USER_GRANT_PERMISSIONS
      );
      hilog.info(
        0x0000,
        'testTag',
        'permission grant result=%{public}s',
        JSON.stringify(result) ?? ''
      );
    } catch (err) {
      hilog.error(
        0x0000,
        'testTag',
        'requestPermissionsFromUser failed: %{public}s',
        JSON.stringify(err) ?? ''
      );
    }
    const abilityDelegator =
      AbilityDelegatorRegistry.getAbilityDelegator();
    const abilityDelegatorArguments =
      AbilityDelegatorRegistry.getArguments();
    hilog.info(0x0000, 'testTag', '%{public}s', 'start run testcase!!!');
    Hypium.hypiumTest(
      abilityDelegator,
      abilityDelegatorArguments,
      testsuite
    );
  }

  onDestroy() {
    hilog.info(0x0000, 'testTag', '%{public}s', 'TestAbility onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage) {
    hilog.info(
      0x0000,
      'testTag',
      '%{public}s',
      'TestAbility onWindowStageCreate'
    );
    windowStage.loadContent('TestAbility/pages/index', (err, data) => {
      if (err.code) {
        hilog.error(
          0x0000,
          'testTag',
          'Failed to load content: %{public}s',
          JSON.stringify(err) ?? ''
        );
        return;
      }
      hilog.info(
        0x0000,
        'testTag',
        'load content ok: %{public}s',
        JSON.stringify(data) ?? ''
      );
    });
  }

  onWindowStageDestroy() {
    hilog.info(
      0x0000,
      'testTag',
      '%{public}s',
      'TestAbility onWindowStageDestroy'
    );
  }

  onForeground() {
    hilog.info(0x0000, 'testTag', '%{public}s', 'TestAbility onForeground');
  }

  onBackground() {
    hilog.info(0x0000, 'testTag', '%{public}s', 'TestAbility onBackground');
  }
}
