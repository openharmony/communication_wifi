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

#ifdef HDI_WPA_INTERFACE_SUPPORT
#include "wifi_hdi_wpa_callback.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_supplicant_hal_interface.h"
#include "wifi_hdi_util.h"

constexpr int WIFI_HDI_STR_MAC_LENGTH = 17;
#undef LOG_TAG
#define LOG_TAG "WifiHdiWpaCallback"

int32_t OnEventDisconnected(struct IWpaCallback *self,
    const struct HdiWpaDisconnectParam *disconectParam, const char* ifName)
{
    LOGI("OnEventDisconnected: callback enter!");
    if (disconectParam == NULL) {
        LOGE("OnEventDisconnected: invalid parameter!");
        return 1;
    }
    uint32_t bssidLen = disconectParam->bssidLen;
    std::string strBssid = OHOS::Wifi::ConvertArrayToHex(disconectParam->bssid, bssidLen);
    char szBssid[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
    ConvertMacToStr(strBssid.c_str(), strBssid.length(), szBssid, sizeof(szBssid));
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onConnectChanged) {
        cbk.onConnectChanged(WPA_CB_DISCONNECTED, disconectParam->reasonCode, szBssid);
    }
    LOGI("%{public}s callback out ,bssid = %{public}s", __func__, szBssid);
    return 0;
}

int32_t OnEventConnected(struct IWpaCallback *self,
    const struct HdiWpaConnectParam *connectParam, const char* ifName)
{
    LOGI("OnEventConnected: callback enter!");
    if (connectParam == NULL) {
        LOGE("OnEventConnected: invalid parameter!");
        return 1;
    }
    uint32_t bssidLen = connectParam->bssidLen;
    std::string strBssid = OHOS::Wifi::ConvertArrayToHex(connectParam->bssid, bssidLen);
    char szBssid[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
    ConvertMacToStr(strBssid.c_str(), strBssid.length(), szBssid, sizeof(szBssid));
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onConnectChanged) {
        cbk.onConnectChanged(WPA_CB_CONNECTED, connectParam->networkId, (const char *)connectParam->bssid);
    }
    LOGI("%{public}s callback out ,bssid = %{public}s", __func__, szBssid);
    return 0;
}

int32_t OnEventBssidChanged(struct IWpaCallback *self,
    const struct HdiWpaBssidChangedParam *bssidChangedParam, const char* ifName)
{
    LOGI("OnEventBssidChanged: callback enter!");
    if (bssidChangedParam == NULL) {
        LOGE("OnEventBssidChanged: invalid parameter!");
        return 1;
    }
    uint32_t bssidLen = bssidChangedParam->bssidLen;
    std::string strBssid = OHOS::Wifi::ConvertArrayToHex(bssidChangedParam->bssid, bssidLen);
    char szBssid[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
    ConvertMacToStr(strBssid.c_str(), strBssid.length(), szBssid, sizeof(szBssid));
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onBssidChanged) {
        cbk.onBssidChanged((const char *)bssidChangedParam->reason, szBssid);
    }
    LOGI("%{public}s callback out ,bssid = %{public}s", __func__, szBssid);
    return 0;
}

int32_t OnEventStateChanged(struct IWpaCallback *self,
    const struct HdiWpaStateChangedParam *statechangedParam, const char* ifName)
{
    LOGI("OnEventStateChanged: callback enter!");
    if (statechangedParam == NULL) {
        LOGE("OnEventStateChanged: invalid parameter!");
        return 1;
    }

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpaStateChanged) {
        cbk.onWpaStateChanged(statechangedParam->status);
    }
    return 0;
}

int32_t OnEventTempDisabled(struct IWpaCallback *self,
    const struct HdiWpaTempDisabledParam *tempDisabledParam, const char *ifName)
{
    LOGI("OnEventTempDisabled: callback enter!");
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpaSsidWrongKey) {
        cbk.onWpaSsidWrongKey(1);
    }
    return 0;
}

int32_t OnEventAssociateReject(struct IWpaCallback *self,
    const struct HdiWpaAssociateRejectParam *associateRejectParam, const char *ifName)
{
    LOGI("OnEventAssociateReject: callback enter!");
    if (associateRejectParam == NULL) {
        LOGE("OnEventAssociateReject: invalid parameter!");
        return 1;
    }

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpaConnectionReject) {
        cbk.onWpaConnectionReject(associateRejectParam->statusCode);
    }
    return 0;
}

int32_t OnEventWpsOverlap(struct IWpaCallback *self, const char *ifName)
{
    LOGI("OnEventWpsOverlap: callback enter!");
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpsOverlap) {
        cbk.onWpsOverlap(1);
    }
    return 0;
}

int32_t OnEventWpsTimeout(struct IWpaCallback *self, const char *ifName)
{
    LOGI("OnEventWpsTimeout: callback enter!");
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpsTimeOut) {
        cbk.onWpsTimeOut(1);
    }
    return 0;
}

int32_t OnEventScanResult(struct IWpaCallback *self,
    const struct HdiWpaRecvScanResultParam *recvScanResultParam, const char* ifName)
{
    LOGI("OnEventScanResult: callback enter!");
    if (recvScanResultParam == NULL) {
        LOGE("OnEventScanResult: invalid parameter!");
        return 1;
    }

    const OHOS::Wifi::SupplicantEventCallback &cbk =
        OHOS::Wifi::WifiSupplicantHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onScanNotify) {
        cbk.onScanNotify(SINGLE_SCAN_OVER_OK);
    }
    return 0;
}
#endif