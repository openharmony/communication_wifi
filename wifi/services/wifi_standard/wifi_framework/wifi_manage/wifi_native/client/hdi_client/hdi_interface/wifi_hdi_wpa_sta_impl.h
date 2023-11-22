/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifdef HDI_WPA_INTERFACE_SUPPORT
#ifndef OHOS_WIFI_HDI_WPA_STA_IMPL_H
#define OHOS_WIFI_HDI_WPA_STA_IMPL_H

#include "wifi_hdi_wpa_proxy.h"
#include "i_wifi_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

WifiErrorNo HdiStart();

WifiErrorNo HdiStop();

WifiErrorNo HdiConnect(int networkId);

WifiErrorNo HdiReconnect();

WifiErrorNo HdiDisconnect();

WifiErrorNo HdiGetDeviceMacAddress(char *macAddr, int macAddrLen);

WifiErrorNo HdiScan();

ScanInfo *HdiGetScanInfos(int *size);

WifiErrorNo HdiRemoveNetwork(int networkId);

WifiErrorNo HdiAddNetwork(int *networkId);

WifiErrorNo HdiEnableNetwork(int networkId);

WifiErrorNo HdiDisableNetwork(int networkId);

WifiErrorNo HdiSetNetwork(int networkId, SetNetworkConfig *confs, int size);

WifiErrorNo HdiSaveConfig();

WifiErrorNo RegisterHdiWpaStaEventCallback(struct IWpaCallback *callback);

WifiErrorNo HdiStartWpsPbcMode(WifiWpsParam *config);

WifiErrorNo HdiStartWpsPinMode(WifiWpsParam *config, int *pinCode);

WifiErrorNo HdiStopWps();

WifiErrorNo HdiWpaAutoConnect(int enable);

WifiErrorNo HdiWpaBlocklistClear();

WifiErrorNo HdiSetPowerSave(int enable);

WifiErrorNo HdiWpaSetCountryCode(const char *countryCode);

WifiErrorNo HdiWpaSetSuspendMode(int mode);

#ifdef __cplusplus
}
#endif
#endif
#endif