/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef SOFTAPHDI_WIFI_HDI_WPA_AP_IMPL_H
#define SOFTAPHDI_WIFI_HDI_WPA_AP_IMPL_H
#ifdef HDI_WPA_INTERFACE_SUPPORT

#include "wifi_hdi_wpa_proxy.h"
#include "i_wifi_struct.h"
#include "wifi_hdi_define.h"

#ifdef __cplusplus
extern "C" {
#endif

WifiErrorNo HdiStartAp(const char *ifaceName, int id);
WifiErrorNo HdiStopAp(int id);
WifiErrorNo HdiRegisterApEventCallback(struct IHostapdCallback *callback);
WifiErrorNo HdiReloadApConfigInfo(int id);
WifiErrorNo HdiEnableAp(int id);
WifiErrorNo HdiDisableAp(int id);
WifiErrorNo HdiSetApPasswd(const char *pass, int id);
WifiErrorNo HdiSetApName(const char *name, int id);
WifiErrorNo HdiSetApWpaValue(int securityType, int id);
WifiErrorNo HdiSetApBand(int band, int id);
WifiErrorNo HdiSetAp80211n(int value, int id);
WifiErrorNo HdiSetApWmm(int value, int id);
WifiErrorNo HdiSetApChannel(int channel, int id);
WifiErrorNo HdiSetApMaxConn(int maxConn, int id);
WifiErrorNo HdiSetMacFilter(const char *mac, int id);
WifiErrorNo HdiDelMacFilter(const char *mac, int id);
WifiErrorNo HdiGetStaInfos(char *buf, int size, int id);
WifiErrorNo HdiDisassociateSta(const char *mac, int id);

#ifdef __cplusplus
}
#endif
#endif // HDI_WPA_INTERFACE_SUPPORT
#endif // SOFTAPHDI_WIFI_HDI_WPA_AP_IMPL_H
