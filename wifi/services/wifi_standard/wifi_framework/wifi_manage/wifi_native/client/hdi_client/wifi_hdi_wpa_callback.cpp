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
#include "wifi_ap_hal_interface.h"

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
    char szBssid[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
    ConvertMacArr2String(disconectParam->bssid, bssidLen, szBssid, sizeof(szBssid));
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
    char szBssid[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
    ConvertMacArr2String(connectParam->bssid, bssidLen, szBssid, sizeof(szBssid));
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onConnectChanged) {
        cbk.onConnectChanged(WPA_CB_CONNECTED, connectParam->networkId, szBssid);
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
    char szBssid[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
    ConvertMacArr2String(bssidChangedParam->bssid, bssidLen, szBssid, sizeof(szBssid));
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
    LOGI("OnEventStateChanged:callback out status = %{public}d", statechangedParam->status);
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

int32_t onEventStaJoin(struct IHostapdCallback *self, const struct HdiApCbParm *apCbParm, const char* ifName)
{
    LOGI("onEvenStaJoin: callback enter!");
    if (apCbParm == nullptr || apCbParm->content == NULL) {
        LOGE("onEvenStaJoin: invalid parameter!");
        return 1;
    }
    WifiIdlEvent event;
    uint8_t len = 0;
    char tmpBuf[WIFI_BSSID_LENGTH] = {0};
    if (strncmp(apCbParm->content, "AP-STA-CONNECTED", strlen("AP-STA-CONNECTED")) == 0) {
        event = WIFI_IDL_CBK_CMD_STA_JOIN;
        len = strlen("AP-STA-CONNECTED");
    } else if (strncmp(apCbParm->content, "AP-STA-DISCONNECTED", strlen("AP-STA-DISCONNECTED")) == 0) {
        event = WIFI_IDL_CBK_CMD_STA_LEAVE;
        len = strlen("AP-STA-DISCONNECTED");
    } else {
        LOGE("onEvenStaJoin: unknown content!");
        return 1;
    }

    if (strcpy_s(tmpBuf, sizeof(tmpBuf), apCbParm->content + len + 1) != 0) {
        LOGE("onEvenStaJoin: strcpy_s failed!");
    }

    const OHOS::Wifi::IWifiApMonitorEventCallback &cbk =
            OHOS::Wifi::WifiApHalInterface::GetInstance().GetApCallbackInst(apCbParm->id);
    if (cbk.onStaJoinOrLeave) {
        OHOS::Wifi::WifiApConnectionNofify cbInfo;
        cbInfo.type = static_cast<int>(event);
        cbInfo.mac = tmpBuf;
        cbk.onStaJoinOrLeave(cbInfo);
    }
    return 0;
}

int32_t onEventApState(struct IHostapdCallback *self, const struct HdiApCbParm *apCbParm, const char* ifName)
{
    LOGI("onEvenApState: callback enter!");
    if (apCbParm == nullptr || apCbParm->content == NULL) {
        LOGE("onEvenApState: invalid parameter!");
        return 1;
    }
    WifiIdlEvent event;
    if (strncmp(apCbParm->content, "AP-ENABLED", strlen("AP-ENABLED")) == 0) {
        event = WIFI_IDL_CBK_CMD_AP_ENABLE;
    } else if (strncmp(apCbParm->content, "CRTL-EVENT-TERMINATING", strlen("CRTL-EVENT-TERMINATING")) == 0) {
        event = WIFI_IDL_CBK_CMD_AP_DISABLE;
    } else if (strncmp(apCbParm->content, "AP-STA-POSSIBLE-PSK-MISMATCH ", strlen("AP-STA-POSSIBLE-PSK-MISMATCH ")) == 0) {
        event = WIFI_IDL_CBK_CMD_AP_STA_PSK_MISMATCH_EVENT;
    } else {
        return 1;
    }

    const OHOS::Wifi::IWifiApMonitorEventCallback &cbk =
            OHOS::Wifi::WifiApHalInterface::GetInstance().GetApCallbackInst(apCbParm->id);
    if (cbk.onApEnableOrDisable) {
        cbk.onApEnableOrDisable(static_cast<int>(event));
    }
    return 0;
}
#endif