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

import wifiManager from '@ohos.wifiManager';
import { ApiPrecondition } from './ApiTestTypes';

const SETTLE_MS = 300;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function safeEnableWifi(): Promise<void> {
  try {
    if (!wifiManager.isWifiActive()) {
      wifiManager.enableWifi();
      await sleep(SETTLE_MS);
    }
  } catch (_e) {
    // 前置条件尽力满足，失败由用例 allowError 兜底
  }
}

async function safeDisableWifi(): Promise<void> {
  try {
    if (wifiManager.isWifiActive()) {
      wifiManager.disableWifi();
      await sleep(SETTLE_MS);
    }
  } catch (_e) {
  }
}

async function safeEnableHotspot(): Promise<void> {
  await safeEnableWifi();
  try {
    if (!wifiManager.isHotspotActive()) {
      wifiManager.enableHotspot();
      await sleep(SETTLE_MS);
    }
  } catch (_e) {
  }
}

async function safeDisableHotspot(): Promise<void> {
  try {
    if (wifiManager.isHotspotActive()) {
      wifiManager.disableHotspot();
      await sleep(SETTLE_MS);
    }
  } catch (_e) {
  }
}

/** 按用例标签建立测试前置状态（条件覆盖） */
export async function applyApiPrecondition(precond: ApiPrecondition): Promise<void> {
  switch (precond) {
    case 'ANY':
      return;
    case 'WIFI_OFF':
      await safeDisableWifi();
      return;
    case 'WIFI_ON':
    case 'WIFI_ON_SCAN':
      await safeEnableWifi();
      if (precond === 'WIFI_ON_SCAN') {
        try {
          wifiManager.startScan();
          await sleep(SETTLE_MS);
        } catch (_e) {
        }
      }
      return;
    case 'HOTSPOT_OFF':
      await safeDisableHotspot();
      return;
    case 'HOTSPOT_ON':
      await safeEnableHotspot();
      return;
    case 'P2P_IDLE':
      await safeEnableWifi();
      try {
        wifiManager.stopDiscoverDevices();
      } catch (_e) {
      }
      return;
    case 'P2P_DISCOVERING':
      await safeEnableWifi();
      try {
        wifiManager.startDiscoverDevices();
        await sleep(SETTLE_MS);
      } catch (_e) {
      }
      return;
    default:
      return;
  }
}
