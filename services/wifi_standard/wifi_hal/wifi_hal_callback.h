/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_HAL_CALLBACK_H
#define OHOS_WIFI_HAL_CALLBACK_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @Description Wi-Fi Hal callback notification indicating that the scanning is complete.
 *
 * @param status
 */
void WifiHalCbNotifyScanEnd(int status);
/**
 * @Description Wi-Fi Hal callback notification of the connection change.
 *
 * @param status
 * @param networkId
 * @param pos
 */
void WifiHalCbNotifyConnectChanged(int status, int networkId, const char *pos);
/**
 * @Description The Wi-Fi Hal module notifies the WPA module of the status change.
 *
 * @param status
 */
void WifiHalCbNotifyWpaStateChange(int status);
/**
 * @Description Wi-Fi Hal callback notification error key.
 *
 * @param status
 */
void WifiHalCbNotifyWrongKey(int status);
/**
 * @Description Wi-Fi Hal callback notification WPS overlaps.
 *
 * @param event
 */
void WifiHalCbNotifyWpsOverlap(int event);
/**
 * @Description Wi-Fi Hal callback notification WPS times out.
 *
 * @param event
 */
void WifiHalCbNotifyWpsTimeOut(int event);
/**
 * @Description Wi-Fi Hal calls back the STA to join the AP.
 *
 * @param content
 */
void WifiHalCbSTAJoin(const char *content);
/**
 * @Description Wi-Fi Hal callback AP status.
 *
 * @param content
 */
void WifiHalCbAPState(const char *content);

#ifdef __cplusplus
}
#endif
#endif