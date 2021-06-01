/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "sta_service.h"
#include "wifi_log.h"
#include "sta_define.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_STA_SERVICE"

namespace OHOS {
namespace Wifi {
StaService::StaService()
    : pStaStateMachine(nullptr), pStaMonitor(nullptr), msgQueueUp(nullptr), pStaConnectivityManager(nullptr)
{}

StaService::~StaService()
{
    LOGI("StaService::~StaService");
    if (pStaMonitor != nullptr) {
        pStaMonitor->UnInitStaMonitor();
        delete pStaMonitor;
        pStaMonitor = nullptr;
    }

    if (pStaConnectivityManager != nullptr) {
        delete pStaConnectivityManager;
        pStaConnectivityManager = nullptr;
    }

    if (pStaStateMachine != nullptr) {
        delete pStaStateMachine;
        pStaStateMachine = nullptr;
    }
}

ErrCode StaService::InitStaService(WifiMessageQueue<WifiResponseMsgInfo> *pMsgQueueUp)
{
    LOGI("Enter StaService::InitStaService.\n");

    msgQueueUp = pMsgQueueUp;

    if (msgQueueUp == nullptr) {
        LOGE("msgQueueUp is null.\n");
        return WIFI_OPT_FAILED;
    }

    pStaStateMachine = new (std::nothrow) StaStateMachine();
    if (pStaStateMachine == nullptr) {
        LOGE("Alloc pStaStateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }

    if (pStaStateMachine->InitStaStateMachine() != WIFI_OPT_SUCCESS) {
        LOGE("InitStaStateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }

    pStaStateMachine->SetResponseQueue(msgQueueUp);
    pStaMonitor = new (std::nothrow) StaMonitor();
    if (pStaMonitor == nullptr) {
        LOGE("Alloc pStaMonitor failed.\n");
        return WIFI_OPT_FAILED;
    }

    if (pStaMonitor->InitStaMonitor() != WIFI_OPT_SUCCESS) {
        LOGE("InitStaMonitor failed.\n");
        return WIFI_OPT_FAILED;
    }

    pStaMonitor->SetStateMachine(pStaStateMachine);

    pStaConnectivityManager = new (std::nothrow) StaConnectivityManager(pStaStateMachine);
    if (pStaConnectivityManager == nullptr) {
        LOGE("Alloc pStaConnectivityManager failed.\n");
        return WIFI_OPT_FAILED;
    }
    if (pStaConnectivityManager->InitConnectivityManager() != WIFI_OPT_SUCCESS) {
        LOGE("InitConnectivityManager failed.\n");
        return WIFI_OPT_FAILED;
    }
    LOGI("Init staservice successfully.\n");

    return WIFI_OPT_SUCCESS;
}

void StaService::NotifyResult(int msgCode) const
{
    LOGI("Enter StaService::NotifyResult.\n");
    WifiResponseMsgInfo notifyMsg;
    notifyMsg.msgCode = msgCode;
    msgQueueUp->Push(notifyMsg);
    return;
}

ErrCode StaService::EnableWifi() const
{
    LOGI("Enter StaService::EnableWifi.\n");
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_ENABLE_WIFI, STA_CONNECT_MODE);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::DisableWifi() const
{
    LOGI("Enter StaService::DisableWifi.\n");
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_DISABLE_WIFI);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ConnectTo(const WifiDeviceConfig &config) const
{
    LOGI("Enter StaService::ConnectTo.\n");
    int networkId = -1;
    WifiDeviceConfig tempDeviceConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(config.ssid, DEVICE_CONFIG_INDEX_SSID, tempDeviceConfig) == 0) {
        LOGD("A network with the same name already exists in the configuration center!\n");
        networkId = tempDeviceConfig.networkId;
        tempDeviceConfig = config;
        tempDeviceConfig.networkId = networkId;
        pStaConnectivityManager->TrackBlockBssid(config.bssid, true, 0);
    } else {
        LOGD("Connect to a new network\n");
        if (WifiStaHalInterface::GetInstance().GetNextNetworkId(networkId) != WIFI_IDL_OPT_OK) {
            LOGE("StaService::ConnectTo GetNextNetworkId failed!");
            return WIFI_OPT_FAILED;
        }
        LOGI("StaService::ConnectTo GetNextNetworkId succeed!");
        tempDeviceConfig = config;
        tempDeviceConfig.networkId = networkId;
    }

    /* Add the new network to WifiSettings. */
    WifiSettings::GetInstance().AddDeviceConfig(tempDeviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();
    LOGI("keyMgmt is %s", config.keyMgmt.c_str());
    /* Setting the network to wpa */
    WifiIdlDeviceConfig idlConfig;
    idlConfig.networkId = networkId;
    idlConfig.ssid = config.ssid;
    idlConfig.bssid = config.bssid;
    idlConfig.psk = config.preSharedKey;
    idlConfig.keyMgmt = config.keyMgmt;
    idlConfig.priority = config.priority;
    idlConfig.scanSsid = config.hiddenSSID ? 1 : 0;
    idlConfig.eap = config.wifiEapConfig.eap;
    idlConfig.identity = config.wifiEapConfig.identity;
    idlConfig.password = config.wifiEapConfig.password;
    idlConfig.authAlgorithms = config.allowedAuthAlgorithms;
    idlConfig.wepKeyIdx = config.wepTxKeyIndex;
    for (int i = 0; i < MAX_WEPKEYS_SIZE; i++) {
        idlConfig.wepKeys[i] = config.wepKeys[i];
    }

    if (WifiStaHalInterface::GetInstance().SetDeviceConfig(networkId, idlConfig) != WIFI_IDL_OPT_OK) {
        LOGE("StaService::ConnectTo SetDeviceConfig failed!");
        return WIFI_OPT_FAILED;
    }
    LOGI("StaService::ConnectTo  SetDeviceConfig succeed!");
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CONNECT_NETWORK, networkId, NETWORK_SELECTED_BY_THE_USER);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ConnectTo(int networkId) const
{
    LOGI("Enter StaService::ConnectTo, networkId is %{public}d.\n", networkId);

    WifiDeviceConfig config;
    int ret = WifiSettings::GetInstance().GetDeviceConfig(networkId, config);
    if (ret != 0) {
        LOGE("WifiDeviceConfig is null!");
        return WIFI_OPT_FAILED;
    }

    pStaConnectivityManager->TrackBlockBssid(config.bssid, true, 0);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK, networkId, NETWORK_SELECTED_BY_THE_USER);

    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ReConnect() const
{
    LOGI("Enter StaService::ReConnect.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ReAssociate() const
{
    LOGI("Enter StaService::ReAssociate.\n");
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_REASSOCIATE_NETWORK);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::RemoveDeviceConfig(int networkId) const
{
    LOGI("Enter StaService::RemoveDeviceConfig.\n");
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_REMOVE_DEVICE_CONFIG, networkId);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::Disconnect() const
{
    LOGI("Enter StaService::Disconnect.\n");
    WifiLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetLinkedInfo(linkedInfo);
    if (pStaConnectivityManager->TrackBlockBssid(linkedInfo.bssid, false, REASON_CODE_AP_UNABLE_TO_HANDLE_NEW_STA)) {
        LOGI("The blocklist is updated.\n");
    }
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_DISCONNECT);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::StartWps(const WpsConfig &config) const
{
    LOGI("Enter StaService::StartWps.\n");
    InternalMessage *msg = pStaStateMachine->ObtainMessage();
    msg->SetMessageName(WIFI_SVR_CMD_STA_STARTWPS);
    msg->SetArg1(static_cast<int>(config.setup));
    msg->AddStringMessageBody(config.pin);
    msg->AddStringMessageBody(config.bssid);
    pStaStateMachine->SendMessage(msg);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::CancelWps() const
{
    LOGI("Enter StaService::CanceltWps.\n");
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CANCELWPS);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::SetCountryCode() const
{
    LOGI("Enter StaService::SetCountryCode.\n");
    pStaStateMachine->SetCountryCode();
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ConnectivityManager(const std::vector<WifiScanInfo> &scanResults)
{
    LOGI("Enter StaService::ConnectivityManager.\n");
    pStaConnectivityManager->OnScanResultsReadyHandler(scanResults);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::SyncLinkInfo(const std::vector<WifiScanInfo> &scanResults)
{
    LOGI("Enter StaService::SyncLinkInfo.\n");
    pStaStateMachine->SyncLinkInfo(scanResults);
    return WIFI_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS
