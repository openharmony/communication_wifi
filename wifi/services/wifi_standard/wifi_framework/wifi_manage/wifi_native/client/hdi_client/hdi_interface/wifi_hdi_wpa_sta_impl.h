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
#include "wifi_hdi_wpa_callback.h"

#ifdef __cplusplus
extern "C" {
#endif

WifiErrorNo Start();

WifiErrorNo Stop();

WifiErrorNo Connect(int networkId);

WifiErrorNo Reconnect();

WifiErrorNo Reassociate();

WifiErrorNo Disconnect();

WifiErrorNo GetCapabilities(int *capabilities);

WifiErrorNo GetDeviceMacAddress(char *macAddr, int macAddrLen);

WifiErrorNo GetFrequencies(int band, int *values, int *size);

WifiErrorNo SetAssocMacAddr(char *mac, int len);

WifiErrorNo Scan(WifiScanParam *scanParam);

WifiErrorNo GetScanInfos(InterScanInfo *scanInfos, int *size);

WifiErrorNo StartPnoScan(WifiPnoScanParam *scanParam);

WifiErrorNo StopPnoScan();

WifiErrorNo RemoveNetwork(int networkId);

WifiErrorNo AddNetwork(int *networkId);

WifiErrorNo EnableNetwork(int networkId);

WifiErrorNo DisableNetwork(int networkId);

WifiErrorNo SetNetwork(int networkId, const char *name, const char *value);

WifiErrorNo SaveConfig();

WifiErrorNo RegisterHdiWpaStaEventCallback(IWifiHdiWpaCallback *callback);

WifiErrorNo StartWpsPbcMode(WifiIdlWpsConfig *config);

WifiErrorNo StartWpsPinMode(WifiIdlWpsConfig *config, int *pinCode);

WifiErrorNo StopWps();

WifiErrorNo GetRoamingCapabilities(WifiIdlRoamCapability *capability);

WifiErrorNo SetRoamConfig(WifiIdlRoamConfig *config);

WifiErrorNo GetConnectSignalInfo(const char *endBssid, WifiWpaSignalInfo *info);

WifiErrorNo WpaAutoConnect(int enable);

WifiErrorNo WpaBlocklistClear();

WifiErrorNo SetPowerSave(int enable);

WifiErrorNo WpaSetCountryCode(const char *countryCode);

WifiErrorNo WpaSetSuspendMode(int mode);

#ifdef __cplusplus
}
#endif
#endif
#endif