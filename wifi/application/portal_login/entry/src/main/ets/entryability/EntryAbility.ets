/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
import { AbilityConstant, ConfigurationConstant, UIAbility, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { window } from '@kit.ArkUI';
import { wifiManager } from '@kit.ConnectivityKit';
import { setUrl, setNetId, setShouldShowBrowseItem, setIsInOOBE, getIsInOOBE, loadUAWhiteList } from '../common/utils';
import { updateOnNewWant, updateOnBackground } from '../common/chr';
import { emitter } from '@kit.BasicServicesKit';
import { BusinessError } from '@kit.BasicServicesKit';
import { deviceInfo, systemDateTime, systemTimer } from '@kit.BasicServicesKit';
import settings from '@ohos.settings';

const DOMAIN = 0x01560;
const TAG = 'Entry';
const KEEP_SCREEN_ON_TIMEOUT = 30 * 1000; // 30 seconds

export default class EntryAbility extends UIAbility {
  private keepScreenOnTimer: number = -1;

  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    try {
      wifiManager.on("wifiStateChange", this.wifiStateCallback);
      hilog.info(DOMAIN, TAG, '%{public}s', 'Register wifiStateChange success');
    } catch (error) {
      hilog.error(DOMAIN, TAG, 'Register wifiStateChange failed. code: %{public}s', `${error.code}`);
    }
    this.context.getApplicationContext().setColorMode(ConfigurationConstant.ColorMode.COLOR_MODE_NOT_SET);
    hilog.info(DOMAIN, TAG, '%{public}s', 'Ability onCreate');
    setUrl(want);
    setNetId(want);
    setShouldShowBrowseItem(want);
    if (settings.getValueSync(this.context, 'user_setup_complete', '0', settings.domainName.DEVICE_SHARED) === '0') {
      hilog.info(DOMAIN, TAG, '%{public}s', 'in oobe.');
      setIsInOOBE(true);
    }
    loadUAWhiteList(this.context.getApplicationContext());
  }

  onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    hilog.info(DOMAIN, TAG, '%{public}s', 'Ability onNewWant');
    updateOnNewWant();
    setUrl(want);
    setNetId(want);
    setShouldShowBrowseItem(want);
    emitter.emit('WANT_UPDATE');
  }

  onDestroy(): void {
    try {
      wifiManager.off("wifiStateChange", this.wifiStateCallback);
    } catch (error) {
      hilog.error(DOMAIN, TAG, 'Unregister wifiStateChange failed. code: %{public}s', `${error.code}`);
    }
    this.stopKeepScreenOnTimer();
    hilog.info(DOMAIN, TAG, '%{public}s', 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    // Main window is created, set main page for this ability
    hilog.info(DOMAIN, TAG, '%{public}s', 'Ability onWindowStageCreate');
    let windowClass: window.Window = windowStage.getMainWindowSync();
    if (deviceInfo.deviceType === 'wearable') {
      try {
        windowClass.setWindowKeepScreenOn(true);
        hilog.info(DOMAIN, TAG, '%{public}s', 'wearable device, keep screen on');
        this.startKeepScreenOnTimer(windowClass);
      } catch (exception) {
        hilog.error(DOMAIN, TAG, 'Failed to set window keep screen on. code: %{public}s', `${exception.code}`);
      }
    }
    if (getIsInOOBE()) {
      windowClass.maximize(window.MaximizePresentation.ENTER_IMMERSIVE);
    }
    let isLayoutFullScreen: boolean = true;
    windowClass.setWindowLayoutFullScreen(isLayoutFullScreen).then(() => {
      console.info('Succeeded in setting the window layout to full-screen mode.');
    }).catch((err: BusinessError) => {
      console.error('Failed to set the window layout to full-screen mode. Cause:' + JSON.stringify(err));
    });
    let type = window.AvoidAreaType.TYPE_SYSTEM;
    let avoidArea = windowClass.getWindowAvoidArea(type);
    let topRectHeight = avoidArea.topRect.height;
    AppStorage.setOrCreate('topRectHeight', topRectHeight);
    try {
      windowClass.on('avoidAreaChange', (data) => {
        if (data.type === window.AvoidAreaType.TYPE_SYSTEM) {
          let topRectHeight = data.area.topRect.height;
          AppStorage.setOrCreate('topRectHeight', topRectHeight);
        }
      });
    } catch (exception) {
      console.error(`Failed to enable the listener for system avoid area changes. code: ${exception.code}`);
    }
    windowStage.loadContent('pages/Index', (err) => {
      if (err.code) {
        hilog.error(DOMAIN, TAG, 'Failed to load the content. Cause: %{public}s', JSON.stringify(err));
        return;
      }
      hilog.info(DOMAIN, TAG, 'Succeeded in loading the content.');
    });
  }

  onWindowStageDestroy(): void {
    // Main window is destroyed, release UI related resources
    hilog.info(DOMAIN, TAG, '%{public}s', 'Ability onWindowStageDestroy');
  }

  onForeground(): void {
    // Ability has brought to foreground
    hilog.info(DOMAIN, TAG, '%{public}s', 'Ability onForeground');
  }

  onBackground(): void {
    // Ability has back to background
    updateOnBackground();
    hilog.info(DOMAIN, TAG, '%{public}s', 'Ability onBackground');
    try {
      wifiManager.startWifiDetection();
      hilog.info(DOMAIN, TAG, '%{public}s', 'onBackground startWifiDetection');
    } catch (error) {
      hilog.error(DOMAIN, TAG, '%{public}s',
        `onBackground startWifiDetection. Code:${error.code}, message:${error.message}`);
    }
  }

  private startKeepScreenOnTimer(windowClass: window.Window): void {
    const options: systemTimer.TimerOptions = {
      type: systemTimer.TIMER_TYPE_WAKEUP | systemTimer.TIMER_TYPE_EXACT | systemTimer.TIMER_TYPE_REALTIME,
      repeat: false,
      callback: () => {
        hilog.info(DOMAIN, TAG, '%{public}s', 'keep screen on timeout, turning off and exiting');
        try {
          windowClass.setWindowKeepScreenOn(false);
        } catch (exception) {
          hilog.error(DOMAIN, TAG, 'Failed to set window keep screen off. code: %{public}s', `${exception.code}`);
        }
      }
    };
    try {
      systemTimer.createTimer(options).then((timerId: number) => {
        this.keepScreenOnTimer = timerId;
        const triggerTime = systemDateTime.getUptime(systemDateTime.TimeType.STARTUP) + KEEP_SCREEN_ON_TIMEOUT;
        systemTimer.startTimer(timerId, triggerTime).then(() => {
          hilog.info(DOMAIN, TAG, 'keep screen on timer started, id: %{public}d', timerId);
        }).catch((err: BusinessError) => {
          hilog.error(DOMAIN, TAG, 'Failed to start timer. code: %{public}s', `${err.code}`);
        });
      }).catch((err: BusinessError) => {
        hilog.error(DOMAIN, TAG, 'Failed to create timer. code: %{public}s', `${err.code}`);
      });
    } catch (exception) {
      hilog.error(DOMAIN, TAG, 'Failed to create timer. code: %{public}s', `${exception.code}`);
    }
  }

  private stopKeepScreenOnTimer(): void {
    if (this.keepScreenOnTimer === -1) {
      return;
    }
    try {
      systemTimer.stopTimer(this.keepScreenOnTimer).then(() => {
        return systemTimer.destroyTimer(this.keepScreenOnTimer);
      }).then(() => {
        hilog.info(DOMAIN, TAG, 'keep screen on timer stopped and destroyed');
      }).catch((err: BusinessError) => {
        hilog.error(DOMAIN, TAG, 'Failed to stop or destroy timer. code: %{public}s', `${err.code}`);
      });
    } catch (exception) {
      hilog.error(DOMAIN, TAG, 'Failed to stop timer. code: %{public}s', `${exception.code}`);
    }
    this.keepScreenOnTimer = -1;
  }

  private wifiStateCallback: (state: number) => void = (state: number) => {
    switch (state) {
      case 0:
        if (deviceInfo.deviceType === 'wearable') {
          this.context.terminateSelf();
        }
        break;
      default:
        break;
    }
  }
}