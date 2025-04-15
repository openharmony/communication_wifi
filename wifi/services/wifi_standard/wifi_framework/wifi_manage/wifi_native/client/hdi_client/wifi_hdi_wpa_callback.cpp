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
#include "wifi_p2p_hal_interface.h"
#include "wifi_hdi_common.h"
#include "wifi_common_util.h"
#include "wifi_native_define.h"
#include "wifi_msg.h"
#include "wifi_config_center.h"
#include "wifi_log.h"
#include "wifi_hisysevent.h"
#ifdef UT_TEST
#define static
#endif

constexpr int WIFI_HDI_STR_MAC_LENGTH = 17;
constexpr int WIFI_HDI_REASON_LENGTH = 32;
constexpr int PD_STATUS_CODE_SHOW_PIN = 0;
constexpr int PD_STATUS_CODE_ENTER_PIN = 1;
constexpr int PD_STATUS_CODE_PBC_REQ = 2;
constexpr int PD_STATUS_CODE_PBC_RSP = 3;
constexpr int PD_STATUS_CODE_FAIL = 4;
constexpr int WEP_WRONG_PASSWORD_STATUS_CODE = 5202;
int g_currentWpaStatus = static_cast<int>(OHOS::Wifi::SupplicantState::UNKNOWN);
#undef LOG_TAG
#define LOG_TAG "WifiHdiWpaCallback"

int32_t OnEventDisconnected(struct IWpaCallback *self,
    const struct HdiWpaDisconnectParam *disconectParam, const char* ifName)
{
    if (ifName == nullptr) {
        LOGE("OnEventDisconnected: invalid ifName!");
        return 1;
    }
    LOGI("OnEventDisconnected: callback enter! ifName = %{public}s", ifName);
    if (disconectParam == NULL || disconectParam->bssidLen <= 0) {
        LOGE("OnEventDisconnected: invalid parameter!");
        return 1;
    }
    uint32_t bssidLen = disconectParam->bssidLen;
    char szBssid[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
    if (ConvertMacArr2String(disconectParam->bssid, bssidLen, szBssid, sizeof(szBssid)) != 0) {
        LOGE("%{public}s: failed to convert mac!", __func__);
        return 1;
    }
    int reasonCode = disconectParam->reasonCode;
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst(ifName);
    if (cbk.onReportDisConnectReason) {
        cbk.onReportDisConnectReason(reasonCode, std::string(szBssid));
    }
    bool isPsk = false;
    std::vector<OHOS::Wifi::WifiScanInfo> scanResults;
    OHOS::Wifi::WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanResults);
    for (OHOS::Wifi::WifiScanInfo &item : scanResults) {
        if (strcasecmp(item.bssid.c_str(), szBssid) == 0 &&
            (item.capabilities.find("PSK") != std::string::npos ||
            item.capabilities.find("WAPI-PSK") != std::string::npos)) {
                isPsk = true;
                break;
        }
    }
    int locallyGenerated = disconectParam->locallyGenerated;
    if (cbk.onWpaSsidWrongKey && isPsk &&
        g_currentWpaStatus == static_cast<int>(OHOS::Wifi::SupplicantState::FOUR_WAY_HANDSHAKE) &&
        (reasonCode != Wifi80211ReasonCode::WLAN_REASON_IE_IN_4WAY_DIFFERS || !locallyGenerated)) {
        LOGI("OnEventDisconnected, wrong password");
        cbk.onWpaSsidWrongKey();
        OHOS::Wifi::WriteAuthFailHiSysEvent("WRONG_PSWD", reasonCode);
    }
    if (cbk.onConnectChanged) {
        cbk.onConnectChanged(HAL_WPA_CB_DISCONNECTED, reasonCode, std::string(szBssid), locallyGenerated);
    }
    LOGI("%{public}s callback out, bssid:%{public}s ifName = %{public}s",
        __func__,
        OHOS::Wifi::MacAnonymize(szBssid).c_str(),
        ifName);
    return 0;
}

int32_t OnEventConnected(struct IWpaCallback *self,
    const struct HdiWpaConnectParam *connectParam, const char* ifName)
{
    if (ifName == nullptr) {
        LOGE("OnEventConnected: invalid ifName!");
        return 1;
    }
    LOGI("OnEventConnected: callback enter! ifName = %{public}s", ifName);
    if (connectParam == NULL || connectParam->bssidLen <= 0) {
        LOGE("OnEventConnected: invalid parameter!");
        return 1;
    }
    uint32_t bssidLen = connectParam->bssidLen;
    char szBssid[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
    if (ConvertMacArr2String(connectParam->bssid, bssidLen, szBssid, sizeof(szBssid)) != 0) {
        LOGE("%{public}s: failed to convert mac!", __func__);
        return 1;
    }
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst(ifName);
    if (cbk.onConnectChanged) {
        cbk.onConnectChanged(HAL_WPA_CB_CONNECTED, connectParam->networkId, szBssid, 0);
    }
    LOGI("%{public}s callback out ,bssid = %{public}s", __func__, OHOS::Wifi::MacAnonymize(szBssid).c_str());
    return 0;
}

int32_t OnEventBssidChanged(struct IWpaCallback *self,
    const struct HdiWpaBssidChangedParam *bssidChangedParam, const char* ifName)
{
    if (ifName == nullptr) {
        LOGE("OnEventBssidChanged: invalid ifName!");
        return 1;
    }
    LOGI("OnEventBssidChanged: callback enter! ifName = %{public}s", ifName);
    if (bssidChangedParam == nullptr || bssidChangedParam->reason == nullptr) {
        LOGE("OnEventBssidChanged: invalid parameter!");
        return 1;
    }

    std::string reason = "";
    if (bssidChangedParam->reasonLen > 0 && bssidChangedParam->reasonLen < WIFI_HDI_REASON_LENGTH) {
        reason = std::string(bssidChangedParam->reason, bssidChangedParam->reason + bssidChangedParam->reasonLen);
    } else {
        LOGE("OnEventBssidChanged: invalid reasonLen:%{public}u", bssidChangedParam->reasonLen);
    }
    char szBssid[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
    if (ConvertMacArr2String(bssidChangedParam->bssid, bssidChangedParam->bssidLen, szBssid, sizeof(szBssid)) != 0) {
        LOGE("OnEventBssidChanged: failed to convert mac!");
        return 1;
    }

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst(ifName);
    if (cbk.onBssidChanged) {
        cbk.onBssidChanged(reason, szBssid);
    }
    LOGI("%{public}s callback out, bssid:%{public}s reason:%{public}s reasonLen:%{public}u",
        __func__, OHOS::Wifi::MacAnonymize(szBssid).c_str(), reason.c_str(), bssidChangedParam->reasonLen);
    return 0;
}

int32_t OnEventStateChanged(struct IWpaCallback *self,
    const struct HdiWpaStateChangedParam *statechangedParam, const char* ifName)
{
    if (ifName == nullptr) {
        LOGE("OnEventStateChanged: invalid ifName!");
        return 1;
    }
    LOGD("OnEventStateChanged: callback enter! ifName = %{public}s", ifName);
    if (statechangedParam == NULL) {
        LOGE("OnEventStateChanged: invalid parameter!");
        return 1;
    }

    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst(ifName);
    g_currentWpaStatus = statechangedParam->status;
    std::string ssid = std::string(statechangedParam->ssid, statechangedParam->ssid + statechangedParam->ssidLen);
    if (cbk.onWpaStateChanged) {
        cbk.onWpaStateChanged(g_currentWpaStatus, ssid);
    }
    LOGI("OnEventStateChanged:callback out status = %{public}d, ifName = %{public}s", g_currentWpaStatus, ifName);
    return 0;
}

int32_t OnEventTempDisabled(struct IWpaCallback *self,
    const struct HdiWpaTempDisabledParam *tempDisabledParam, const char *ifName)
{
    if (ifName == nullptr) {
        LOGE("OnEventTempDisabled: invalid ifName!");
        return 1;
    }
    LOGI("OnEventTempDisabled: callback enter! ifName = %{public}s", ifName);
    
    if (tempDisabledParam == NULL) {
        LOGE("OnEventTempDisabled tempDisabledParam is NULL");
        return 1;
    }
    std::string ssid = "";
    if (tempDisabledParam->ssid != NULL && tempDisabledParam->ssidLen > 0) {
        ssid = std::string(tempDisabledParam->ssid, tempDisabledParam->ssid + tempDisabledParam->ssidLen);
    }
    std::string reason = "";
    if (tempDisabledParam->reason != NULL && tempDisabledParam->reasonLen > 0) {
        reason = std::string(tempDisabledParam->reason, tempDisabledParam->reason + tempDisabledParam->reasonLen);
    }
    LOGI("OnEventTempDisabled ssid:%{public}s reason:%{public}s, ifName = %{public}s",
        OHOS::Wifi::SsidAnonymize(ssid).c_str(),
        reason.c_str(),
        ifName);
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst(ifName);
    if (cbk.onWpaSsidWrongKey && reason == "AUTH_FAILED") {
        cbk.onWpaSsidWrongKey();
    }
    return 0;
}

int32_t OnEventAssociateReject(struct IWpaCallback *self,
    const struct HdiWpaAssociateRejectParam *associateRejectParam, const char *ifName)
{
    if (ifName == nullptr) {
        LOGE("OnEventAssociateReject: invalid ifName!");
        return 1;
    }
    LOGI("OnEventAssociateReject: callback enter! ifName = %{public}s", ifName);
    if (associateRejectParam == NULL) {
        LOGE("OnEventAssociateReject: invalid parameter!");
        return 1;
    }
    char bssid[WIFI_HDI_STR_MAC_LENGTH + 1] = {0};
    ConvertMacArr2String(associateRejectParam->bssid, associateRejectParam->bssidLen, bssid, sizeof(bssid));
    int statusCode = associateRejectParam->statusCode;
 
    /* Special handling for WPA3-Personal networks. If the password is
       incorrect, the AP will send association rejection, with status code 1
       (unspecified failure). In SAE networks, the password authentication
       is not related to the 4-way handshake. In this case, we will send an
       authentication failure event up. */
    bool isWrongPwd = false;
    std::string failReason = "";
    std::vector<OHOS::Wifi::WifiScanInfo> scanResults;
    OHOS::Wifi::WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanResults);
    for (OHOS::Wifi::WifiScanInfo &item : scanResults) {
        if (strcasecmp(item.bssid.c_str(), bssid) == 0) {
            if (statusCode == Wifi80211StatusCode::WLAN_STATUS_UNSPECIFIED_FAILURE &&
                (item.capabilities.find("SAE") != std::string::npos)) {
                isWrongPwd = true;
                failReason = "WPA3_WRONG_PSWD";
                break;
            } else if (statusCode == WEP_WRONG_PASSWORD_STATUS_CODE &&
                item.capabilities.find("WEP") != std::string::npos) {
                isWrongPwd = true;
                failReason = "WEP_WRONG_PSWD";
                break;
            }
        }
    }
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst(ifName);
    if (isWrongPwd && cbk.onWpaSsidWrongKey) {
        LOGI("onWpaConnectionRejectCallBack, wrong password");
        cbk.onWpaSsidWrongKey();
        OHOS::Wifi::WriteAuthFailHiSysEvent(failReason, statusCode);
        return 0;
    }
    if ((statusCode == Wifi80211StatusCode::WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA ||
        statusCode == Wifi80211StatusCode::WLAN_STATUS_ASSOC_REJECTED_TEMPORARILY ||
        statusCode == Wifi80211StatusCode::WLAN_STATUS_DENIED_INSUFFICIENT_BANDWIDTH) &&
        cbk.onWpaConnectionFull) {
        LOGI("onWpaConnectionRejectCallBack, connect full");
        cbk.onWpaConnectionFull(statusCode);
        OHOS::Wifi::WriteAssocFailHiSysEvent("CONNECT_FULL", statusCode);
        return 0;
    }
    if (cbk.onWpaConnectionReject) {
        LOGI("onWpaConnectionRejectCallBack");
        OHOS::Wifi::AssocRejectInfo assocRejectInfo;
        assocRejectInfo.bssid = std::string(bssid);
        assocRejectInfo.statusCode = statusCode;
        assocRejectInfo.timeOut = associateRejectParam->timeOut;
        cbk.onWpaConnectionReject(assocRejectInfo);
        OHOS::Wifi::WriteAssocFailHiSysEvent("CONNECT_REJECT", statusCode);
    }
    return 0;
}

int32_t OnEventStaNotify(struct IWpaCallback *self, const char* notifyParam, const char *ifName)
{
    if (ifName == nullptr) {
        LOGE("OnEventStaNotify: invalid ifName!");
        return 1;
    }
    LOGI("OnEventStaNotify: callback enter! ifName = %{public}s", ifName);
    if (notifyParam == NULL) {
        LOGE("OnEventStaNotify: invalid parameter!");
        return 1;
    }

    if (strcmp(ifName, "wlan0") == 0 || strcmp(ifName, "wlan1") == 0) {
        const OHOS::Wifi::WifiEventCallback &cbk =
            OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst(ifName);
        if (cbk.onEventStaNotify) {
            cbk.onEventStaNotify(notifyParam);
        }
    } else if (strncmp(ifName, "p2p", strlen("p2p")) == 0) {
        const OHOS::Wifi::P2pHalCallback &p2pCbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
        if (p2pCbk.onEventStaNotify) {
            p2pCbk.onEventStaNotify(notifyParam);
        }
    }
    return 0;
}

int32_t OnEventWpsOverlap(struct IWpaCallback *self, const char *ifName)
{
    if (ifName == nullptr) {
        LOGE("OnEventWpsOverlap: invalid ifName!");
        return 1;
    }
    LOGI("OnEventWpsOverlap: callback enter! ifName = %{public}s", ifName);
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst(ifName);
    if (cbk.onWpsOverlap) {
        cbk.onWpsOverlap(1);
    }
    return 0;
}

int32_t OnEventWpsTimeout(struct IWpaCallback *self, const char *ifName)
{
    if (ifName == nullptr) {
        LOGE("OnEventWpsOverlap: invalid ifName!");
        return 1;
    }
    LOGI("OnEventWpsTimeout: callback enter! ifName = %{public}s", ifName);
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst(ifName);
    if (cbk.onWpsTimeOut) {
        cbk.onWpsTimeOut(1);
    }
    return 0;
}

int32_t OnEventAuthTimeout(struct IWpaCallback *self, const char *ifName)
{
    if (ifName == nullptr) {
        LOGE("OnEventWpsOverlap: invalid ifName!");
        return 1;
    }
    LOGI("OnEventAuthTimeout: callback enter! ifName = %{public}s", ifName);
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst(ifName);
    if (g_currentWpaStatus == static_cast<int>(OHOS::Wifi::SupplicantState::FOUR_WAY_HANDSHAKE) &&
        cbk.onWpaSsidWrongKey) {
        LOGI("OnEventAuthTimeout, wrong password");
        cbk.onWpaSsidWrongKey();
        OHOS::Wifi::WriteAuthFailHiSysEvent("WRONG_PSWD");
        return 0;
    }
    if (cbk.onWpaAuthTimeout) {
        cbk.onWpaAuthTimeout();
        OHOS::Wifi::WriteAuthFailHiSysEvent("AUTH_TIMEOUT");
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
        cbk.onScanNotify(HAL_SINGLE_SCAN_OVER_OK);
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
    HalCallbackEvent event;
    uint8_t len = 0;
    char tmpBuf[WIFI_BSSID_LENGTH] = {0};
    if (strncmp(apCbParm->content, "AP-STA-CONNECTED", strlen("AP-STA-CONNECTED")) == 0) {
        event = HAL_CBK_CMD_STA_JOIN;
        len = strlen("AP-STA-CONNECTED");
    } else if (strncmp(apCbParm->content, "AP-STA-DISCONNECTED", strlen("AP-STA-DISCONNECTED")) == 0) {
        event = HAL_CBK_CMD_STA_LEAVE;
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
        OHOS::Wifi::WifiHalApConnectionNofify cbInfo;
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
    HalCallbackEvent event;
    if (strncmp(apCbParm->content, "AP-ENABLED", strlen("AP-ENABLED")) == 0) {
        event = HAL_CBK_CMD_AP_ENABLE;
    } else if (strncmp(apCbParm->content, "AP-DISABLED", strlen("AP-DISABLED")) == 0) {
        event = HAL_CBK_CMD_AP_DISABLE;
        if (GetExecDisable() == EXEC_DISABLE) {
            SetExecDisable(0);
            return 0;
        }
    } else if (strncmp(apCbParm->content, "CTRL-EVENT-TERMINATING", strlen("CTRL-EVENT-TERMINATING")) == 0) {
        event = HAL_CBK_CMD_AP_DISABLE;
    } else if (strncmp(apCbParm->content, "AP-STA-POSSIBLE-PSK-MISMATCH ",
        strlen("AP-STA-POSSIBLE-PSK-MISMATCH ")) == 0) {
        event = HAL_CBK_CMD_AP_STA_PSK_MISMATCH_EVENT;
    } else if (strncmp(apCbParm->content, "AP-CSA-FINISHED ", strlen("AP-CSA-FINISHED ")) == 0) {
        const OHOS::Wifi::IWifiApMonitorEventCallback &cbk =
            OHOS::Wifi::WifiApHalInterface::GetInstance().GetApCallbackInst(apCbParm->id);
        const std::string str(apCbParm->content);
        if (cbk.onEventHostApdNotify) {
            cbk.onEventHostApdNotify(str);
        }
        return 0;
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

int32_t OnEventP2pStateChanged(int status)
{
    LOGI("OnEventP2pStateChanged %{public}d", status);
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onConnectSupplicant) {
        cbk.onConnectSupplicant(status);
    }
    return 0;
}

int32_t OnEventDeviceFound(struct IWpaCallback *self,
    const struct HdiP2pDeviceInfoParam *deviceInfoParam, const char* ifName)
{
    LOGI("OnEventDeviceFound");
    if (deviceInfoParam == nullptr) {
        return 1;
    }
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onDeviceFound) {
        OHOS::Wifi::HalP2pDeviceFound cbInfo;
        uint32_t srcAddressLen = deviceInfoParam->srcAddressLen;
        char srcAddress[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        ConvertMacArr2String(deviceInfoParam->srcAddress, srcAddressLen, srcAddress, sizeof(srcAddress));
        cbInfo.srcAddress = srcAddress;

        uint32_t p2pDeviceAddressLen = deviceInfoParam->p2pDeviceAddressLen;
        char p2pDeviceAddress[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        ConvertMacArr2String(deviceInfoParam->p2pDeviceAddress, p2pDeviceAddressLen,
            p2pDeviceAddress, sizeof(p2pDeviceAddress));
        cbInfo.p2pDeviceAddress = p2pDeviceAddress;

        cbInfo.primaryDeviceType = (char *)(deviceInfoParam->primaryDeviceType);
        cbInfo.deviceName = (char *)(deviceInfoParam->deviceName);
        cbInfo.configMethods = deviceInfoParam->configMethods;
        cbInfo.deviceCapabilities = deviceInfoParam->deviceCapabilities;
        cbInfo.groupCapabilities = deviceInfoParam->groupCapabilities;
        cbInfo.wfdDeviceInfo.insert(cbInfo.wfdDeviceInfo.begin(), deviceInfoParam->wfdDeviceInfo,
            deviceInfoParam->wfdDeviceInfo + deviceInfoParam->wfdLength);
        cbk.onDeviceFound(cbInfo);
        LOGI("OnEventDeviceFound p2pDeviceAddress=%{private}s deviceName=%{private}s",
            p2pDeviceAddress, deviceInfoParam->deviceName);
    }
    return 0;
}

int32_t OnEventDeviceLost(struct IWpaCallback *self,
    const struct HdiP2pDeviceLostParam *deviceLostParam, const char* ifName)
{
    LOGI("OnEventDeviceLost");
    if (deviceLostParam == nullptr) {
        return 1;
    }
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onDeviceLost) {
        uint32_t p2pDeviceAddressLen = deviceLostParam->p2pDeviceAddressLen;
        char p2pDeviceAddress[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        ConvertMacArr2String(deviceLostParam->p2pDeviceAddress, p2pDeviceAddressLen,
            p2pDeviceAddress, sizeof(p2pDeviceAddress));
        cbk.onDeviceLost(p2pDeviceAddress);
        LOGI("OnEventDeviceLost p2pDeviceAddress=%{private}s", p2pDeviceAddress);
    }
    return 0;
}

int32_t OnEventGoNegotiationRequest(struct IWpaCallback *self,
    const struct HdiP2pGoNegotiationRequestParam *goNegotiationRequestParam, const char* ifName)
{
    LOGI("OnEventGoNegotiationRequest");
    if (goNegotiationRequestParam == nullptr) {
        return 1;
    }
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onGoNegotiationRequest) {
        char address[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        ConvertMacArr2String(goNegotiationRequestParam->srcAddress,
            goNegotiationRequestParam->srcAddressLen, address, sizeof(address));

        cbk.onGoNegotiationRequest(address, goNegotiationRequestParam->passwordId);
    }
    return 0;
}

int32_t OnEventGoNegotiationCompleted(struct IWpaCallback *self,
    const struct HdiP2pGoNegotiationCompletedParam *goNegotiationCompletedParam, const char* ifName)
{
    if (goNegotiationCompletedParam == nullptr) {
        LOGI("goNegotiationCompletedParam is null");
        return 1;
    }
    int status = goNegotiationCompletedParam->status;
    LOGI("OnEventGoNegotiationCompleted, status is %{public}d", status);
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (status == 0) {
        if (cbk.onGoNegotiationSuccess) {
            cbk.onGoNegotiationSuccess();
        }
    } else {
        if (cbk.onGoNegotiationFailure) {
            cbk.onGoNegotiationFailure(status);
        }
    }
    return 0;
}

int32_t OnEventInvitationReceived(struct IWpaCallback *self,
    const struct HdiP2pInvitationReceivedParam *invitationReceivedParam, const char *ifName)
{
    LOGI("OnEventInvitationReceived");
    if (invitationReceivedParam == nullptr) {
        return 1;
    }
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onInvitationReceived) {
        OHOS::Wifi::HalP2pInvitationInfo cbInfo;
        cbInfo.type = invitationReceivedParam->type;
        cbInfo.persistentNetworkId = invitationReceivedParam->persistentNetworkId;
        cbInfo.operatingFrequency = invitationReceivedParam->operatingFrequency;

        char address[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        ConvertMacArr2String(invitationReceivedParam->srcAddress,
            invitationReceivedParam->srcAddressLen, address, sizeof(address));
        cbInfo.srcAddress = address;

        char address1[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        ConvertMacArr2String(invitationReceivedParam->goDeviceAddress,
            invitationReceivedParam->goDeviceAddressLen, address1, sizeof(address1));
        cbInfo.goDeviceAddress = address1;

        char address2[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        ConvertMacArr2String(invitationReceivedParam->bssid,
            invitationReceivedParam->bssidLen, address2, sizeof(address2));
        cbInfo.bssid = address2;

        cbk.onInvitationReceived(cbInfo);
    }
    return 0;
}

int32_t OnEventInvitationResult(struct IWpaCallback *self,
    const struct HdiP2pInvitationResultParam *invitationResultParam, const char *ifName)
{
    LOGI("OnEventInvitationResult");
    if (invitationResultParam == nullptr) {
        return 1;
    }
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onInvitationResult) {
        char address[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        ConvertMacArr2String(invitationResultParam->bssid,
            invitationResultParam->bssidLen, address, sizeof(address));
        cbk.onInvitationResult(address, invitationResultParam->status);
    }
    return 0;
}

int32_t OnEventGroupFormationSuccess(struct IWpaCallback *self, const char *ifName)
{
    LOGI("OnEventGroupFormationSuccess");
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onGroupFormationSuccess) {
        cbk.onGroupFormationSuccess();
    }
    return 0;
}

int32_t OnEventGroupFormationFailure(struct IWpaCallback *self, const char *reason, const char *ifName)
{
    LOGI("OnEventGroupFormationFailure");
    if (reason == nullptr) {
        return 1;
    }
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onGroupFormationFailure) {
        cbk.onGroupFormationFailure(reason);
    }
    return 0;
}

int32_t OnEventGroupStarted(struct IWpaCallback *self,
    const struct HdiP2pGroupStartedParam *groupStartedParam, const char* ifName)
{
    LOGI("OnEventGroupStarted");
    if (groupStartedParam == nullptr) {
        return 1;
    }
    char tempSsid[WIFI_SSID_LENGTH] = {0};
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onGroupStarted) {
        OHOS::Wifi::HalP2pGroupInfo cbInfo;
        cbInfo.isGo = groupStartedParam->isGo;
        cbInfo.isPersistent = groupStartedParam->isPersistent;
        cbInfo.frequency = groupStartedParam->frequency;
        cbInfo.groupName = (char *)(groupStartedParam->groupIfName);
        StrSafeCopy(tempSsid, sizeof(tempSsid), (char *)groupStartedParam->ssid);
        PrintfDecode((u8 *)tempSsid, sizeof(tempSsid), tempSsid);
        cbInfo.ssid = (char *)(tempSsid);
        cbInfo.psk = (char *)(groupStartedParam->psk);
        cbInfo.passphrase = (char *)(groupStartedParam->passphrase);
        LOGI("OnEventGroupStarted groupName=%{public}s ssid=%{private}s len=%{public}zu",
            cbInfo.groupName.c_str(), OHOS::Wifi::SsidAnonymize(cbInfo.ssid).c_str(), cbInfo.ssid.size());

        char address[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        ConvertMacArr2String(groupStartedParam->goDeviceAddress,
            groupStartedParam->goDeviceAddressLen, address, sizeof(address));
        cbInfo.goDeviceAddress = address;

        cbk.onGroupStarted(cbInfo);
    }
    return 0;
}

int32_t OnEventGroupInfoStarted(struct IWpaCallback *self,
    const struct HdiP2pGroupInfoStartedParam *groupStartedParam, const char* ifName)
{
    LOGI("OnEventGroupInfoStarted");
    if (groupStartedParam == nullptr) {
        return 1;
    }
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    char tempSsid[WIFI_SSID_LENGTH] = {0};
    if (cbk.onGroupStarted) {
        OHOS::Wifi::HalP2pGroupInfo cbInfo;
        cbInfo.isGo = groupStartedParam->isGo;
        cbInfo.isPersistent = groupStartedParam->isPersistent;
        cbInfo.frequency = groupStartedParam->frequency;
        cbInfo.groupName = (char *)(groupStartedParam->groupIfName);
        StrSafeCopy(tempSsid, sizeof(tempSsid), (char *)groupStartedParam->ssid);
        PrintfDecode((u8 *)tempSsid, sizeof(tempSsid), tempSsid);
        cbInfo.ssid = (char *)(tempSsid);
        cbInfo.psk = (char *)(groupStartedParam->psk);
        cbInfo.passphrase = (char *)(groupStartedParam->passphrase);
        char address[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        char address1[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        ConvertMacArr2String(groupStartedParam->goDeviceAddress,
            groupStartedParam->goDeviceAddressLen, address, sizeof(address));
        ConvertMacArr2String(groupStartedParam->goRandomDeviceAddress,
            groupStartedParam->goRandomDeviceAddressLen, address1, sizeof(address1));
        LOGI("OnEventGroupInfoStarted address=%{private}s len %{public}d address1=%{private}s ",
            address, groupStartedParam->goRandomDeviceAddressLen, address1);
        cbInfo.goDeviceAddress = address;
        cbInfo.goRandomAddress = address1;
        cbk.onGroupStarted(cbInfo);
    }
    return 0;
}

int32_t OnEventGroupRemoved(struct IWpaCallback *self,
    const struct HdiP2pGroupRemovedParam *groupRemovedParam, const char* ifName)
{
    LOGI("OnEventGroupRemoved");
    if (groupRemovedParam == nullptr) {
        return 1;
    }
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onGroupRemoved) {
        cbk.onGroupRemoved((char *)(groupRemovedParam->groupIfName), (groupRemovedParam->isGo == 1));
    }
    return 0;
}

int32_t OnEventProvisionDiscoveryCompleted(struct IWpaCallback *self,
    const struct HdiP2pProvisionDiscoveryCompletedParam *provisionDiscoveryCompletedParam, const char* ifName)
{
    LOGI("OnEventProvisionDiscoveryCompleted enter");
    if (provisionDiscoveryCompletedParam == nullptr) {
        return 1;
    }
    LOGI("OnEventProvisionDiscoveryCompleted provDiscStatusCode=%{public}d",
        provisionDiscoveryCompletedParam->provDiscStatusCode);
    uint32_t addressLen = provisionDiscoveryCompletedParam->p2pDeviceAddressLen;
    char address[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
    ConvertMacArr2String(provisionDiscoveryCompletedParam->p2pDeviceAddress,
        addressLen, address, sizeof(address));

    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (provisionDiscoveryCompletedParam->provDiscStatusCode == PD_STATUS_CODE_SHOW_PIN) {
        if (cbk.onProvisionDiscoveryShowPin) {
            cbk.onProvisionDiscoveryShowPin(address,
                (char *)(provisionDiscoveryCompletedParam->generatedPin));
        }
    } else if (provisionDiscoveryCompletedParam->provDiscStatusCode == PD_STATUS_CODE_ENTER_PIN) {
        if (cbk.onProvisionDiscoveryEnterPin) {
            cbk.onProvisionDiscoveryEnterPin(address);
        }
    } else if (provisionDiscoveryCompletedParam->provDiscStatusCode == PD_STATUS_CODE_PBC_REQ) {
        if (cbk.onProvisionDiscoveryPbcRequest) {
            cbk.onProvisionDiscoveryPbcRequest(address);
        }
    } else if (provisionDiscoveryCompletedParam->provDiscStatusCode == PD_STATUS_CODE_PBC_RSP) {
        if (cbk.onProvisionDiscoveryPbcResponse) {
        cbk.onProvisionDiscoveryPbcResponse(address);
    }
    } else if (provisionDiscoveryCompletedParam->provDiscStatusCode == PD_STATUS_CODE_FAIL) {
        if (cbk.onProvisionDiscoveryFailure) {
            cbk.onProvisionDiscoveryFailure();
        }
    }
    return 0;
}

int32_t OnEventFindStopped(struct IWpaCallback *self, const char* ifName)
{
    LOGI("OnEventFindStopped");
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onFindStopped) {
        cbk.onFindStopped();
    }
    return 0;
}

int32_t OnEventServDiscReq(struct IWpaCallback *self,
    const struct HdiP2pServDiscReqInfoParam *servDiscReqInfoParam, const char* ifName)
{
    LOGI("OnEventServDiscReq");
    if (servDiscReqInfoParam == nullptr) {
        return 1;
    }
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onP2pServDiscReq) {
        OHOS::Wifi::HalP2pServDiscReqInfo cbInfo;
        cbInfo.freq = servDiscReqInfoParam->freq;
        cbInfo.dialogToken = servDiscReqInfoParam->dialogToken;
        cbInfo.updateIndic = servDiscReqInfoParam->updateIndic;

        char address[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        ConvertMacArr2String(servDiscReqInfoParam->mac, servDiscReqInfoParam->macLen,
            address, sizeof(address));
        cbInfo.mac = address;

        if (servDiscReqInfoParam->tlvsLen > 0 && servDiscReqInfoParam->tlvs != nullptr) {
            OHOS::Wifi::Char2Vec(servDiscReqInfoParam->tlvs, servDiscReqInfoParam->tlvsLen, cbInfo.tlvList);
        }
        cbk.onP2pServDiscReq(cbInfo);
    }
    return 0;
}

int32_t OnEventServDiscResp(struct IWpaCallback *self,
    const struct HdiP2pServDiscRespParam *servDiscRespParam, const char* ifName)
{
    LOGI("OnEventServDiscResp");
    if (servDiscRespParam == nullptr) {
        return 1;
    }
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onServiceDiscoveryResponse) {
        std::vector<unsigned char> tlvList;
        if (servDiscRespParam->tlvs != nullptr) {
            OHOS::Wifi::Char2Vec(servDiscRespParam->tlvs, servDiscRespParam->tlvsLen, tlvList);
        }
        char address[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        ConvertMacArr2String(servDiscRespParam->srcAddress, servDiscRespParam->srcAddressLen,
            address, sizeof(address));
        cbk.onServiceDiscoveryResponse(address, servDiscRespParam->updateIndicator, tlvList);
    }
    return 0;
}

int32_t OnEventStaConnectState(struct IWpaCallback *self,
    const struct HdiP2pStaConnectStateParam *staConnectStateParam, const char* ifName)
{
    LOGI("OnEventStaConnectState");
    if (staConnectStateParam == nullptr) {
        return 1;
    }
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    char srcAddress[WIFI_HDI_STR_MAC_LENGTH + 1] = {0};
    char address[WIFI_HDI_STR_MAC_LENGTH + 1] = {0};
    ConvertMacArr2String(staConnectStateParam->p2pDeviceAddress,
        staConnectStateParam->p2pDeviceAddressLen, address, sizeof(address));
    ConvertMacArr2String(staConnectStateParam->srcAddress,
        staConnectStateParam->srcAddressLen, srcAddress, sizeof(srcAddress));
    if (staConnectStateParam->state == 1) {
        if (cbk.onStaAuthorized) {
            cbk.onStaAuthorized(address, srcAddress);
        }
    } else {
        if (cbk.onStaDeauthorized) {
            cbk.onStaDeauthorized(address);
        }
    }
    return 0;
}

int32_t OnEventIfaceCreated(struct IWpaCallback *self,
    const struct HdiP2pIfaceCreatedParam *ifaceCreatedParam, const char* ifName)
{
    LOGI("OnEventIfaceCreated");
    if (ifaceCreatedParam == nullptr) {
        return 1;
    }
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onP2pIfaceCreated) {
        cbk.onP2pIfaceCreated(ifName, ifaceCreatedParam->isGo);
    }
    return 0;
}

void OnNativeProcessDeath(int status)
{
    LOGI("OnNativeProcessDeath status=%{public}d", status);
    const std::function<void(int)> &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetDeathCallbackInst();
    if (cbk) {
        cbk(status);
    }
}
#endif
