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
 
import { Want, common } from '@kit.AbilityKit'
import { connection } from '@kit.NetworkKit'
import { BusinessError } from '@kit.BasicServicesKit'
import { hilog } from '@kit.PerformanceAnalysisKit'
import { url } from '@kit.ArkTS'

const DOMAIN = 0x01560
const TAG = 'Utils';
const MAX_URL_LENGTH = 2048;

let url_: string = '';
let netId_: number = -1;
let shouldShowBrowseItem_: boolean = true;

export function setShouldShowBrowseItem(want: Want): void {
  if (want.parameters) {
    shouldShowBrowseItem_ = want.parameters?.shouldShowBrowseItem as boolean;
    hilog.info(DOMAIN, TAG, '%{public}s', 'Succeeded set shouldShowBrowseItem:' + shouldShowBrowseItem_);
  } else {
    hilog.error(DOMAIN, TAG, '%{public}s', 'Failed set shouldShowBrowseItem');
  }
}

export function shouldShowBrowseItem(): boolean {
  return shouldShowBrowseItem_;
}

export function validateURL(urlString: string): boolean {
  if (urlString.length > MAX_URL_LENGTH) {
    hilog.error(DOMAIN, TAG, '%{public}s', 'Invalid URL: url length exceed 2048.');
    return false;
  }
  try {
    const urlObject = url.URL.parseURL(urlString);
    if (urlObject && urlObject.hostname) {
      hilog.info(DOMAIN, TAG, '%{public}s', 'validateURL:' + urlObject.hostname);
      return true;
    }
  } catch (error) {
    hilog.error(DOMAIN, TAG, '%{public}s', 'Invalid URL:' + error);
  }
  return false;
}

export function setUrl(want: Want): void {
  if (want.parameters && want.parameters.url && validateURL(want.parameters.url as string)) {
    url_ = want.parameters.url as string;
    hilog.info(DOMAIN, TAG, '%{public}s', 'Succeeded set url:' + extractDomain(url_));
  } else {
    hilog.error(DOMAIN, TAG, '%{public}s', 'Failed set url:' + extractDomain(url_));
  }
}

export function getUrl(): string {
  hilog.info(DOMAIN, TAG, '%{public}s', 'get url:' + extractDomain(url_));
  if (extractDomain(url_) === 'Invalid URL') {
    return 'Invalid URL';
  }
  return url_;
}

function validateNetId(netId: number): boolean {
  if (netId >= 100) {
    return true;
  }
  hilog.error(DOMAIN, TAG, '%{public}s', 'Invalid net id:' + netId);
  return false;
}

export function setNetId(want: Want): void {
  if (want.parameters && want.parameters.netId && validateNetId(want.parameters.netId as number)) {
    netId_ = want.parameters.netId as number;
    hilog.info(DOMAIN, TAG, '%{public}s', 'Succeeded set net id:' + netId_);
  } else {
    hilog.error(DOMAIN, TAG, '%{public}s', 'Failed set net id:' + netId_);
  }
}

export async function bindToNetById(context: common.UIAbilityContext) {
  try {
    const netHandleArray: connection.NetHandle[] = await new Promise((resolve, reject) => {
      connection.getAllNets((error: BusinessError, nets: connection.NetHandle[]) => {
        if (error) {
          hilog.error(DOMAIN, TAG, '%{public}s', `Failed to get all nets. Code:${error.code}, message:${error.message}`);
          reject(error);
        } else {
          hilog.info(DOMAIN, TAG, '%{public}s', 'Succeeded get all nets.' + JSON.stringify(nets));
          resolve(nets);
        }
      });
    });
    const targetNetHandle = netHandleArray.find((netHandle) => netHandle.netId === netId_);
    if (targetNetHandle) {
      await new Promise<void>((resolve, reject) => {
        connection.setAppNet(targetNetHandle, (error: BusinessError, data: void) => {
          if (error) {
            hilog.error(DOMAIN, TAG, '%{public}s', `Failed bind net. Code:${error.code}, message:${error.message}, netId:` + netId_);
            reject(error);
          } else {
            hilog.info(DOMAIN, TAG, '%{public}s', 'Succeeded bind net. netId:' + netId_);
            resolve();
          }
        });
      });
    } else {
      hilog.error(DOMAIN, TAG, '%{public}s', 'Not find matched NetHandle.');
      exitApp(context);
    }
  } catch (error) {
    hilog.error(DOMAIN, TAG, '%{public}s', `bindToNetById process failed: ${error.message}`);
    exitApp(context);
  }
}

export function exitApp(context: common.UIAbilityContext): void {
  try {
    context.terminateSelf()
      .then(() => {
        hilog.info(DOMAIN, TAG, '%{public}s', 'exit app success.')
      })
      .catch((err: BusinessError) => {
        hilog.error(DOMAIN, TAG, '%{public}s', `exit app fail.Code:${err.code}, message:${err.message}`)
      })
  } catch (error) {
    hilog.error(DOMAIN, TAG, '%{public}s', 'exit app abnormal.' + (error as BusinessError).message)
  }
}

export function handleNetworkChange(data: connection.NetHandle, context: common.UIAbilityContext): void {
  if (data.netId === netId_) {
    hilog.info(DOMAIN, TAG, '%{public}s', 'exit app beacuse netlost.')
    exitApp(context);
  }
}

export function extractDomain(urlString: string): string {
  try {
    const urlObject = url.URL.parseURL(urlString);
    return urlObject.hostname;
  } catch (error) {
    hilog.error(DOMAIN, TAG, '%{public}s', 'Invalid URL:' + error)
  }
  return 'Invalid URL';
}

export enum UserAgentSet {
  harmonyUA = '',
  mobileUA = 'Mozilla/5.0 (Linux; Android 12; BRA-AL00) AppleWebKit/537.36 (KHTML, like Gecko)' + 
  'Chrome/100.0.4896.75 Mobile Safari/537.36',
  desktopUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' +
    'Chrome/114.0.0.0 Safari/537.36'
}