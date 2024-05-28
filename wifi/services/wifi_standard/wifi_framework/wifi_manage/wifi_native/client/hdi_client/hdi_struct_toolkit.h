/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef HDI_STRUCT_TOOLKIT_H
#define HDI_STRUCT_TOOLKIT_H
#ifdef HDI_WPA_INTERFACE_SUPPORT
#include "wifi_hdi_wpa_client.h"
#include "wifi_hdi_wpa_sta_impl.h"
#include "wifi_hdi_wpa_callback.h"
#include "wifi_hdi_wpa_ap_impl.h"
#include "wifi_hdi_wpa_p2p_impl.h"
#include "wifi_hdi_util.h"
#include "wifi_common_util.h"
#include "hdi_struct_toolkit.h"
#include <securec.h>
#include <unistd.h>

static void FreeHdiWifiWpaNetworkInfo(HdiWifiWpaNetworkInfo *hdiWifiWpaNetworkInfo)
{
    free(hdiWifiWpaNetworkInfo->ssid);
    free(hdiWifiWpaNetworkInfo->bssid);
    free(hdiWifiWpaNetworkInfo->flags);
    hdiWifiWpaNetworkInfo->ssid = nullptr;
    hdiWifiWpaNetworkInfo->bssid = nullptr;
    hdiWifiWpaNetworkInfo->flags = nullptr;
    hdiWifiWpaNetworkInfo = nullptr;
}

static void FreeHdiP2pNetworkInfo(HdiP2pNetworkInfo *hdiP2pNetworkInfo)
{
    free(hdiP2pNetworkInfo->ssid);
    free(hdiP2pNetworkInfo->bssid);
    free(hdiP2pNetworkInfo->flags);
    hdiP2pNetworkInfo->ssid = nullptr;
    hdiP2pNetworkInfo->bssid = nullptr;
    hdiP2pNetworkInfo->flags = nullptr;
}

static void FreeHdiP2pNetworkList(HdiP2pNetworkList *hdiP2pNetworkList)
{
    for (int i = 0; i < hdiP2pNetworkList->infoNum; i++) {
        FreeHdiP2pNetworkInfo(&hdiP2pNetworkList->infos[i]);
    }
    free(hdiP2pNetworkList->infos);
    hdiP2pNetworkList->infos = nullptr;
    hdiP2pNetworkList = nullptr;
}

static void FreeHdiP2pDeviceInfo(HdiP2pDeviceInfo *hdiP2pDeviceInfo) {
    free(hdiP2pDeviceInfo->srcAddress);
    free(hdiP2pDeviceInfo->p2pDeviceAddress);
    free(hdiP2pDeviceInfo->primaryDeviceType);
    free(hdiP2pDeviceInfo->deviceName);
    free(hdiP2pDeviceInfo->wfdDeviceInfo);
    free(hdiP2pDeviceInfo->operSsid);
    hdiP2pDeviceInfo->srcAddress = nullptr;
    hdiP2pDeviceInfo->p2pDeviceAddress = nullptr;
    hdiP2pDeviceInfo->primaryDeviceType = nullptr;
    hdiP2pDeviceInfo->deviceName = nullptr;
    hdiP2pDeviceInfo->wfdDeviceInfo = nullptr;
    hdiP2pDeviceInfo->operSsid = nullptr;
    hdiP2pDeviceInfo = nullptr;
}
#endif
#endif