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

import { hiSysEvent, hilog } from '@kit.PerformanceAnalysisKit';
import { BusinessError } from '@kit.BasicServicesKit';

const DOMAIN = 0x01560
const TAG = 'CHR';
 
let isOnNewWant_ = 0;
let bindNetDuration_ = 0;
let isBindNetSuccess_ = 0;
let initUrl_ = '';
let finalUrl_ = '';
let httpErrorCode_ = 0;
let errorCode_ = 0;
let sslErrorCode_ = 0;
let isUpload_ = false;
let isPortalSuccess_ = 0;


export function updateOnNewWant() {
  isOnNewWant_ = 1;
  bindNetDuration_ = 0;
  isBindNetSuccess_ = 0;
  initUrl_ = '';
  finalUrl_ = '';
  httpErrorCode_ = 0;
  errorCode_ = 0;
  sslErrorCode_ = 0;
  isUpload_ = false;
}
 
export function updateBindNetTime(duration: number) {
  bindNetDuration_ = duration;
}
 
export function updateBindNetSuccess() {
  isBindNetSuccess_ = 1;
}
 
export function safeAnonymize(str: string): string {
  if (typeof str !== 'string' || str.length === 0) {
    return str;
  }
  const chars = str.split('');
  for (let i = 1; i < chars.length; i += 2) {
    chars[i] = '*';
  }
  return chars.join('');
}
 
export function updateInitUrl(url: string) {
  if (initUrl_ === ''){
    initUrl_ = safeAnonymize(url);
  }
}
 
export function updateFinalUrl(url: string) {
  finalUrl_ = safeAnonymize(url);
}
 
export function updateOnHttpErrorReceive(code: number) {
  httpErrorCode_ = code;
}
 
export function updateOnErrorReceive(code: number) {
  errorCode_ = code;
}
 
export function updateOnSslErrorEvent(code: number) {
  sslErrorCode_ = code;
}
 
function portalHiSysEvent() {
  hilog.info(DOMAIN, TAG, '%{public}s', 'Enter portalHiSysEvent');
  if (httpErrorCode_ == 0 && errorCode_ == 0 &&  sslErrorCode_ == 0) {
    isPortalSuccess_ = 1;
  }
  hiSysEvent.write({
    domain: 'COMMUNICATION',
    name:'PORTAL_LOGIN_LOAD_INFO',
    eventType: hiSysEvent.EventType.STATISTIC,
    params:{
      'IS_ON_NEW_WANT': isOnNewWant_,
      'BIND_NET_DURATION': bindNetDuration_,
      'IS_BIND_NET_SUCCESS': isBindNetSuccess_,
      'INIT_URL': initUrl_,
      'FINAL_URL': finalUrl_,
      'HTTP_ERROR_CODE': httpErrorCode_,
      'ERROR_CODE': errorCode_,
      'SSL_ERROR_CODE': sslErrorCode_,
      'IS_PORTAL_SUCCESS': isPortalSuccess_,
    },
  }, (err:BusinessError) => {
    if(err){
      hilog.error(DOMAIN, TAG, `code: ${err.code}, message: ${err.message}`);
      return;
    }
    hilog.info(DOMAIN, TAG, `success to write event`);
  });
}
 
export function updateOnBackground() {
  if ((httpErrorCode_ != 0 || errorCode_ != 0 || sslErrorCode_ != 0) && !isUpload_) {
    portalHiSysEvent();
    isUpload_ = true;
  }
}
 
export function updateAboutToDisappear() {
  if (!isUpload_){
    portalHiSysEvent();
  }
}