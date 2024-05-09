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

WifiErrorNo HdiWpaStaStart(const char *ifaceName);

WifiErrorNo HdiWpaStaStop();

WifiErrorNo HdiWpaStaConnect(int networkId);

WifiErrorNo HdiWpaStaReconnect();

WifiErrorNo HdiWpaStaReassociate();

WifiErrorNo HdiWpaStaDisconnect();

WifiErrorNo HdiWpaStaGetDeviceMacAddress(char *macAddr, int macAddrLen);

WifiErrorNo HdiWpaStaScan();

ScanInfo *HdiWpaStaGetScanInfos(int *size);

WifiErrorNo HdiWpaStaRemoveNetwork(int networkId);

WifiErrorNo HdiWpaStaAddNetwork(int *networkId);

WifiErrorNo HdiWpaStaEnableNetwork(int networkId);

WifiErrorNo HdiWpaStaDisableNetwork(int networkId);

WifiErrorNo HdiWpaStaSetNetwork(int networkId, SetNetworkConfig *confs, int size);

WifiErrorNo HdiWpaStaSaveConfig();

WifiErrorNo RegisterHdiWpaStaEventCallback(struct IWpaCallback *callback);

WifiErrorNo HdiWpaStaStartWpsPbcMode(WifiWpsParam *config);

WifiErrorNo HdiWpaStaStartWpsPinMode(WifiWpsParam *config, int *pinCode);

WifiErrorNo HdiStopWpsSta();

WifiErrorNo HdiWpaStaAutoConnect(int enable);

WifiErrorNo HdiWpaStaBlocklistClear();

WifiErrorNo HdiWpaStaSetPowerSave(int enable);

WifiErrorNo HdiWpaStaSetCountryCode(const char *countryCode);

WifiErrorNo HdiWpaStaSetSuspendMode(int mode);

WifiErrorNo HdiWpaStaGetCountryCode(char *countryCode, uint32_t size);

WifiErrorNo HdiWpaListNetworks(struct HdiWifiWpaNetworkInfo *networkList, uint32_t *size);

WifiErrorNo HdiWpaGetNetwork(int32_t networkId, const char* param, char* value, uint32_t valueLen);

WifiErrorNo HdiWpaStaSetShellCmd(const char *ifName, const char *cmd);

WifiErrorNo HdiWpaStaGetPskPassphrase(const char *ifName, char *psk, uint32_t pskLen);

int ConvertMacToStr(char *mac, int macSize, char *macStr, int strLen);

#ifdef __cplusplus
}
#endif
#endif
#endif