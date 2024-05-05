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

constexpr int WIFI_HDI_STR_MAC_LENGTH = 17;
constexpr int PD_STATUS_CODE_SHOW_PIN = 0;
constexpr int PD_STATUS_CODE_ENTER_PIN = 1;
constexpr int PD_STATUS_CODE_PBC_REQ = 2;
constexpr int PD_STATUS_CODE_PBC_RSP = 3;
constexpr int PD_STATUS_CODE_FAIL = 4;
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
    if (cbk.onReportDisConnectReason) {
        cbk.onReportDisConnectReason(disconectParam->reasonCode, szBssid);
    }
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
    LOGI("OnEventTempDisabled ssid:%{public}s reason:%{public}s",
        OHOS::Wifi::SsidAnonymize(ssid).c_str(), reason.c_str());
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onWpaSsidWrongKey && (reason == "WRONG_KEY" || reason == "AUTH_FAILED")) {
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

int32_t OnEventStaNotify(struct IWpaCallback *self, const char* notifyParam, const char *ifName)
{
    LOGI("OnEventStaNotify: callback enter!");
    if (strcmp(ifName, "wlan0") != 0) {
        return 1;
    }
    if (notifyParam == NULL) {
        LOGE("OnEventStaNotify: invalid parameter!");
        return 1;
    }
    const OHOS::Wifi::WifiEventCallback &cbk = OHOS::Wifi::WifiStaHalInterface::GetInstance().GetCallbackInst();
    if (cbk.onEventStaNotify) {
        cbk.onEventStaNotify(notifyParam);
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
    } else if (strncmp(apCbParm->content, "AP-DISABLED", strlen("AP-DISABLED")) == 0) {
        event = WIFI_IDL_CBK_CMD_AP_DISABLE;
        if (GetExecDisable() == EXEC_DISABLE) {
            SetExecDisable(0);
            return 0;
        }
    } else if (strncmp(apCbParm->content, "CTRL-EVENT-TERMINATING", strlen("CTRL-EVENT-TERMINATING")) == 0) {
        event = WIFI_IDL_CBK_CMD_AP_DISABLE;
    } else if (strncmp(apCbParm->content, "AP-STA-POSSIBLE-PSK-MISMATCH ",
        strlen("AP-STA-POSSIBLE-PSK-MISMATCH ")) == 0) {
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

int32_t OnEventP2pStateChanged(struct IWpaCallback *self,
    const struct HdiWpaStateChangedParam *statechangedParam, const char* ifName)
{
    LOGI("OnEventP2pStateChanged ifName=%{public}s", ifName);
    if (statechangedParam == NULL) {
        LOGE("OnEventStateChanged: invalid parameter!");
        return 1;
    }
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onConnectSupplicant) {
        cbk.onConnectSupplicant(statechangedParam->status);
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
        OHOS::Wifi::IdlP2pDeviceFound cbInfo;
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
        const int wfdLength = 14; /* wfd info type: 0x000000000000 */
        const int wfdStartPos = 2; /* skip 0x */
        if (deviceInfoParam->wfdLength >= wfdLength && strlen((char *)(deviceInfoParam->wfdDeviceInfo)) >= wfdLength) {
            OHOS::Wifi::HexStringToVec((char *)(deviceInfoParam->wfdDeviceInfo) + wfdStartPos, cbInfo.wfdDeviceInfo);
        }
        cbk.onDeviceFound(cbInfo);
        LOGI("OnEventDeviceFound p2pDeviceAddress=%{private}s deviceName=%{public}s",
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
    LOGI("OnEventGoNegotiationCompleted");
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    if (cbk.onGoNegotiationSuccess) {
        cbk.onGoNegotiationSuccess();
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
        OHOS::Wifi::IdlP2pInvitationInfo cbInfo;
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
    const OHOS::Wifi::P2pHalCallback &cbk = OHOS::Wifi::WifiP2PHalInterface::GetInstance().GetP2pCallbackInst();
    char tempSsid[WIFI_SSID_LENGTH] = {0};
    if (cbk.onGroupStarted) {
        OHOS::Wifi::IdlP2pGroupInfo cbInfo;
        cbInfo.isGo = groupStartedParam->isGo;
        cbInfo.isPersistent = groupStartedParam->isPersistent;
        cbInfo.frequency = groupStartedParam->frequency;
        cbInfo.groupName = (char *)(groupStartedParam->groupIfName);
        StrSafeCopy(tempSsid, sizeof(tempSsid), (char *)groupStartedParam->ssid);
        PrintfDecode((u8 *)tempSsid, sizeof(tempSsid), tempSsid);
        cbInfo.ssid = (char *)(tempSsid);
        cbInfo.psk = (char *)(groupStartedParam->psk);
        cbInfo.passphrase = (char *)(groupStartedParam->passphrase);
        LOGI("OnEventGroupStarted groupName=%{public}s ssid=%{private}s" len:%{public}lu:,
            cbInfo.groupName.c_str(), cbInfo.ssid.c_str(), strlen(cbInfo.ssid.c_str()));

        char address[WIFI_HDI_STR_MAC_LENGTH +1] = {0};
        ConvertMacArr2String(groupStartedParam->goDeviceAddress,
            groupStartedParam->goDeviceAddressLen, address, sizeof(address));
        cbInfo.goDeviceAddress = address;

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
    LOGI("OnEventProvisionDiscoveryCompleted provDiscStatusCode=%{public}d",
        provisionDiscoveryCompletedParam->provDiscStatusCode);
    if (provisionDiscoveryCompletedParam == nullptr) {
        return 1;
    }
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
        OHOS::Wifi::IdlP2pServDiscReqInfo cbInfo;
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
    char address[WIFI_HDI_STR_MAC_LENGTH + 1] = {0};
    ConvertMacArr2String(staConnectStateParam->p2pDeviceAddress,
        staConnectStateParam->p2pDeviceAddressLen, address, sizeof(address));
    if (staConnectStateParam->state == 1) {
        if (cbk.onStaAuthorized) {
            cbk.onStaAuthorized(address);
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

#endif