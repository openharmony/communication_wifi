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
import BaseModel from './BaseModel';

const LOG_DOMAIN = 0x1500;
const LOG_TAG = 'wifiTestApp';

function msgStr(msg: unknown): string {
  if (typeof msg === 'string') {
    return msg;
  }
  try {
    return JSON.stringify(msg);
  } catch (_e) {
    return String(msg);
  }
}

let LogLevel = {
  /**
   * debug
   */
  DEBUG: 3,

  /**
   * info
   */
  INFO: 4,

  /**
   * warn
   */
  WARN: 5,

  /**
   * error
   */
  ERROR: 6,

  /**
   * fatal
   */
  FATAL: 7,
};

const LOG_LEVEL = LogLevel.INFO;

/**
 *  log package tool class
 */
export class LogUtil extends BaseModel {
  debug(msg: unknown): void {
    if (LogLevel.DEBUG >= LOG_LEVEL) {
      hilog.debug(LOG_DOMAIN, LOG_TAG, '%{public}s', msgStr(msg));
    }
  }

  log(msg: unknown): void {
    if (LogLevel.INFO >= LOG_LEVEL) {
      hilog.info(LOG_DOMAIN, LOG_TAG, '%{public}s', msgStr(msg));
    }
  }

  info(msg: unknown): void {
    if (LogLevel.INFO >= LOG_LEVEL) {
      hilog.info(LOG_DOMAIN, LOG_TAG, '%{public}s', msgStr(msg));
    }
  }

  warn(msg: unknown): void {
    if (LogLevel.WARN >= LOG_LEVEL) {
      hilog.warn(LOG_DOMAIN, LOG_TAG, '%{public}s', msgStr(msg));
    }
  }

  error(msg: unknown): void {
    if (LogLevel.ERROR >= LOG_LEVEL) {
      hilog.error(LOG_DOMAIN, LOG_TAG, '%{public}s', msgStr(msg));
    }
  }
}

let mLogUtil = new LogUtil();

export default mLogUtil as LogUtil;
