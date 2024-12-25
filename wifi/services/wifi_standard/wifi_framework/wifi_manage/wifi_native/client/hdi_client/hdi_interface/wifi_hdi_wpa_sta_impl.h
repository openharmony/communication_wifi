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

WifiErrorNo HdiWpaStaStart(const char *ifaceName, int instId);

WifiErrorNo HdiWpaStaStop(int instId);

WifiErrorNo HdiWpaStaConnect(int networkId, const char *ifaceName);

WifiErrorNo HdiWpaStaReconnect(const char *ifaceName);

WifiErrorNo HdiWpaStaReassociate(const char *ifaceName);

WifiErrorNo HdiWpaStaDisconnect(const char *ifaceName);

WifiErrorNo HdiWpaStaGetDeviceMacAddress(char *macAddr, int macAddrLen, const char *ifaceName);

WifiErrorNo HdiWpaStaScan();

ScanInfo *HdiWpaStaGetScanInfos(int *size, const char *ifaceName);

WifiErrorNo HdiWpaStaRemoveNetwork(int networkId, const char *ifaceName);

WifiErrorNo HdiWpaStaAddNetwork(int *networkId, const char *ifaceName);

WifiErrorNo HdiWpaStaEnableNetwork(int networkId, const char *ifaceName);

WifiErrorNo HdiWpaStaDisableNetwork(int networkId, const char *ifaceName);

WifiErrorNo HdiWpaStaSetNetwork(int networkId, SetNetworkConfig *confs, int size, const char *ifaceName);

WifiErrorNo HdiWpaStaSaveConfig(const char *ifaceName);

WifiErrorNo RegisterHdiWpaStaEventCallback(struct IWpaCallback *callback, const char *ifaceName, int instId);

WifiErrorNo HdiWpaStaStartWpsPbcMode(WifiWpsParam *config, const char *ifaceName);

WifiErrorNo HdiWpaStaStartWpsPinMode(WifiWpsParam *config, int *pinCode, const char *ifaceName);

WifiErrorNo HdiStopWpsSta(const char *ifaceName);

WifiErrorNo HdiWpaStaAutoConnect(int enable, const char *ifaceName);

WifiErrorNo HdiWpaStaBlocklistClear(const char *ifaceName);

WifiErrorNo HdiWpaStaSetPowerSave(int enable, const char *ifaceName);

WifiErrorNo HdiWpaStaSetCountryCode(const char *countryCode, const char *ifaceName);

WifiErrorNo HdiWpaStaSetSuspendMode(int mode, const char *ifaceName);

WifiErrorNo HdiWpaStaGetCountryCode(char *countryCode, uint32_t size, const char *ifaceName);

WifiErrorNo HdiWpaListNetworks(struct HdiWifiWpaNetworkInfo *networkList, uint32_t *size, const char *ifaceName);

WifiErrorNo HdiWpaGetNetwork(
    int32_t networkId, const char* param, char* value, uint32_t valueLen, const char *ifaceName);

WifiErrorNo HdiWpaStaSetShellCmd(const char *ifName, const char *cmd);

WifiErrorNo HdiWpaStaGetPskPassphrase(const char *ifName, char *psk, uint32_t pskLen);

int ConvertMacToStr(char *mac, int macSize, char *macStr, int strLen);

WifiErrorNo HdiSetNativeProcessCallback(void (*callback)(int));

WifiErrorNo HdiWpaGetMloLinkedInfo(const char *ifName, const char *staParam, char *staData,
    uint32_t staDataLen);
#ifdef __cplusplus
}
#endif
#endif
#endif