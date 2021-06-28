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
#include "wifi_logger.h"
#include "sta_define.h"

DEFINE_WIFILOG_LABEL("StaService");

namespace OHOS {
namespace Wifi {
StaService::StaService()
    : pStaStateMachine(nullptr), pStaMonitor(nullptr), msgQueueUp(nullptr), pStaAutoConnectService(nullptr)
{}

StaService::~StaService()
{
    WIFI_LOGI("StaService::~StaService");
    if (pStaMonitor != nullptr) {
        pStaMonitor->UnInitStaMonitor();
        delete pStaMonitor;
        pStaMonitor = nullptr;
    }

    if (pStaAutoConnectService != nullptr) {
        delete pStaAutoConnectService;
        pStaAutoConnectService = nullptr;
    }

    if (pStaStateMachine != nullptr) {
        delete pStaStateMachine;
        pStaStateMachine = nullptr;
    }
}

ErrCode StaService::InitStaService(WifiMessageQueue<WifiResponseMsgInfo> *pMsgQueueUp)
{
    WIFI_LOGI("Enter StaService::InitStaService.\n");

    msgQueueUp = pMsgQueueUp;

    if (msgQueueUp == nullptr) {
        WIFI_LOGE("msgQueueUp is null.\n");
        return WIFI_OPT_FAILED;
    }

    pStaStateMachine = new (std::nothrow) StaStateMachine();
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("Alloc pStaStateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }

    if (pStaStateMachine->InitStaStateMachine() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitStaStateMachine failed.\n");
        return WIFI_OPT_FAILED;
    }

    pStaStateMachine->SetResponseQueue(msgQueueUp);
    pStaMonitor = new (std::nothrow) StaMonitor();
    if (pStaMonitor == nullptr) {
        WIFI_LOGE("Alloc pStaMonitor failed.\n");
        return WIFI_OPT_FAILED;
    }

    if (pStaMonitor->InitStaMonitor() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitStaMonitor failed.\n");
        return WIFI_OPT_FAILED;
    }

    pStaMonitor->SetStateMachine(pStaStateMachine);

    pStaAutoConnectService = new (std::nothrow) StaAutoConnectService(pStaStateMachine);
    if (pStaAutoConnectService == nullptr) {
        WIFI_LOGE("Alloc pStaAutoConnectService failed.\n");
        return WIFI_OPT_FAILED;
    }
    if (pStaAutoConnectService->InitAutoConnectService() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitAutoConnectService failed.\n");
        return WIFI_OPT_FAILED;
    }
    WIFI_LOGI("Init staservice successfully.\n");

    return WIFI_OPT_SUCCESS;
}

void StaService::NotifyResult(int msgCode) const
{
    WIFI_LOGI("Enter StaService::NotifyResult.\n");
    WifiResponseMsgInfo notifyMsg;
    notifyMsg.msgCode = msgCode;
    msgQueueUp->Push(notifyMsg);
    return;
}

ErrCode StaService::EnableWifi() const
{
    WIFI_LOGI("Enter StaService::EnableWifi.\n");
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_ENABLE_WIFI, STA_CONNECT_MODE);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::DisableWifi() const
{
    WIFI_LOGI("Enter StaService::DisableWifi.\n");
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_DISABLE_WIFI);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ConnectTo(const WifiDeviceConfig &config) const
{
    WIFI_LOGI("Enter StaService::ConnectTo.\n");
    int networkId = -1;
    WifiDeviceConfig tempDeviceConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(config.ssid, DEVICE_CONFIG_INDEX_SSID, tempDeviceConfig) == 0) {
        WIFI_LOGD("A network with the same name already exists in the configuration center!\n");
        networkId = tempDeviceConfig.networkId;
        tempDeviceConfig = config;
        tempDeviceConfig.networkId = networkId;
        pStaAutoConnectService->EnableOrDisableBssid(config.bssid, true, 0);
    } else {
        WIFI_LOGD("Connect to a new network\n");
        if (WifiStaHalInterface::GetInstance().GetNextNetworkId(networkId) != WIFI_IDL_OPT_OK) {
            WIFI_LOGE("StaService::ConnectTo GetNextNetworkId failed!");
            return WIFI_OPT_FAILED;
        }
        WIFI_LOGI("StaService::ConnectTo GetNextNetworkId succeed!");
        tempDeviceConfig = config;
        tempDeviceConfig.networkId = networkId;
    }

    /* Add the new network to WifiSettings. */
    WifiSettings::GetInstance().AddDeviceConfig(tempDeviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();
    WIFI_LOGI("keyMgmt is %s", config.keyMgmt.c_str());
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
    idlConfig.wepKeyIdx = config.wepTxKeyIndex;
    for (int i = 0; i < MAX_WEPKEYS_SIZE; i++) {
        idlConfig.wepKeys[i] = config.wepKeys[i];
    }

    if (WifiStaHalInterface::GetInstance().SetDeviceConfig(networkId, idlConfig) != WIFI_IDL_OPT_OK) {
        WIFI_LOGE("StaService::ConnectTo SetDeviceConfig failed!");
        return WIFI_OPT_FAILED;
    }
    WIFI_LOGI("StaService::ConnectTo  SetDeviceConfig succeed!");
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CONNECT_NETWORK, networkId, NETWORK_SELECTED_BY_THE_USER);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ConnectTo(int networkId) const
{
    WIFI_LOGI("Enter StaService::ConnectTo, networkId is %{public}d.\n", networkId);

    WifiDeviceConfig config;
    int ret = WifiSettings::GetInstance().GetDeviceConfig(networkId, config);
    if (ret != 0) {
        WIFI_LOGE("WifiDeviceConfig is null!");
        return WIFI_OPT_FAILED;
    }

    pStaAutoConnectService->EnableOrDisableBssid(config.bssid, true, 0);
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CONNECT_SAVED_NETWORK, networkId, NETWORK_SELECTED_BY_THE_USER);

    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ReConnect() const
{
    WIFI_LOGI("Enter StaService::ReConnect.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::ReAssociate() const
{
    WIFI_LOGI("Enter StaService::ReAssociate.\n");
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_REASSOCIATE_NETWORK);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::RemoveDeviceConfig(int networkId) const
{
    WIFI_LOGI("Enter StaService::RemoveDeviceConfig.\n");
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_REMOVE_DEVICE_CONFIG, networkId);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::Disconnect() const
{
    WIFI_LOGI("Enter StaService::Disconnect.\n");
    WifiLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetLinkedInfo(linkedInfo);
    if (pStaAutoConnectService->EnableOrDisableBssid(linkedInfo.bssid, false, AP_CANNOT_HANDLE_NEW_STA)) {
        WIFI_LOGI("The blocklist is updated.\n");
    }
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_DISCONNECT);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::StartWps(const WpsConfig &config) const
{
    WIFI_LOGI("Enter StaService::StartWps.\n");
    InternalMessage *msg = pStaStateMachine->CreateMessage();
    msg->SetMessageName(WIFI_SVR_CMD_STA_STARTWPS);
    msg->SetParam1(static_cast<int>(config.setup));
    msg->AddStringMessageBody(config.pin);
    msg->AddStringMessageBody(config.bssid);
    pStaStateMachine->SendMessage(msg);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::CancelWps() const
{
    WIFI_LOGI("Enter StaService::CanceltWps.\n");
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CANCELWPS);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::SetCountryCode() const
{
    WIFI_LOGI("Enter StaService::SetCountryCode.\n");
    pStaStateMachine->SetCountryCode();
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::AutoConnectService(const std::vector<WifiScanInfo> &scanInfos)
{
    WIFI_LOGI("Enter StaService::AutoConnectService.\n");
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfos);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaService::SyncLinkInfo(const std::vector<WifiScanInfo> &scanInfos)
{
    WIFI_LOGI("Enter StaService::SyncLinkInfo.\n");
    pStaStateMachine->SyncLinkInfo(scanInfos);
    return WIFI_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS
