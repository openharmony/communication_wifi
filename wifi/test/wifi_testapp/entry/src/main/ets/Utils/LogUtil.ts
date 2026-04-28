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
  debug(msg): void {
    if (LogLevel.DEBUG >= LOG_LEVEL) {
      hilog.debug(0x1500, 'wifiTestApp', '%{public}s', String(msg));
    }
  }

  log(msg): void {
    if (LogLevel.INFO >= LOG_LEVEL) {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', String(msg));
    }
  }

  info(msg): void {
    if (LogLevel.INFO >= LOG_LEVEL) {
      hilog.info(0x1500, 'wifiTestApp', '%{public}s', String(msg));
    }
  }

  warn(msg): void {
    if (LogLevel.WARN >= LOG_LEVEL) {
      hilog.warn(0x1500, 'wifiTestApp', '%{public}s', String(msg));
    }
  }

  error(msg): void {
    if (LogLevel.ERROR >= LOG_LEVEL) {
      hilog.error(0x1500, 'wifiTestApp', '%{public}s', String(msg));
    }
  }
}

let mLogUtil = new LogUtil();

export default mLogUtil as LogUtil;