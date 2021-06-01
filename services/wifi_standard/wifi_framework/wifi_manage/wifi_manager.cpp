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

#include "wifi_manager.h"
#include "wifi_global_func.h"
#include "wifi_log.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_auth_center.h"
#include "wifi_config_center.h"
#include "wifi_event_broadcast.h"
#include "wifi_service_manager.h"
#include "wifi_settings.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_MANAGER_MANAGER"

namespace OHOS {
namespace Wifi {
WifiManager &WifiManager::GetInstance()
{
    static WifiManager gWifiManager;
    static std::mutex gInitMutex;
    if (gWifiManager.GetInitStatus() == INIT_UNKNOWN) {
        std::unique_lock<std::mutex> lock(gInitMutex);
        if (gWifiManager.GetInitStatus() == INIT_UNKNOWN) {
            if (gWifiManager.Init() != 0) {
                LOGE("Failed to `WifiManager::Init` !");
            }
        }
    }

    return gWifiManager;
}

WifiManager::WifiManager() : mTid(0), mRunFlag(true), mInitStatus_(INIT_UNKNOWN)
{}

WifiManager::~WifiManager()
{}

int WifiManager::Init()
{
    if (WifiConfigCenter::GetInstance().Init() < 0) {
        LOGE("WifiConfigCenter Init failed!");
        mInitStatus_ = CONFIG_CENTER_INIT_FAILED;
        return -1;
    }
    if (WifiAuthCenter::GetInstance().Init() < 0) {
        LOGE("WifiAuthCenter Init failed!");
        mInitStatus_ = AUTH_CENTER_INIT_FAILED;
        return -1;
    }
    if (WifiServiceManager::GetInstance().Init() < 0) {
        LOGE("WifiServiceManager Init failed!");
        mInitStatus_ = SERVICE_MANAGER_INIT_FAILED;
        return -1;
    }
    if (WifiEventBroadcast::GetInstance().Init() < 0) {
        LOGE("WifiEventBroadcast Init failed!");
        mInitStatus_ = EVENT_BROADCAST_INIT_FAILED;
        return -1;
    }
    mMqUp = std::make_unique<WifiMessageQueue<WifiResponseMsgInfo>>();

    int ret = pthread_create(&mTid, nullptr, DealServiceUpMsg, this);
    if (ret != 0) {
        LOGE("In WifiManager create message deal thread failed!");
        mInitStatus_ = TASK_THREAD_INIT_FAILED;
        return -1;
    }

    mInitStatus_ = INIT_OK;
    return 0;
}

void WifiManager::Exit()
{
    WifiServiceManager::GetInstance().UninstallAllService();
    WifiStaHalInterface::GetInstance().ExitAllIdlClient();
    WifiEventBroadcast::GetInstance().Exit();
    if (mTid != 0) {
        mRunFlag = false;
        WifiResponseMsgInfo msg;
        msg.msgCode = WifiInternalMsgCode::MAIN_EXIT_CODE;
        mMqUp->Push(msg);
        pthread_join(mTid, nullptr);
    }
    return;
}

int WifiManager::PushMsg(const std::string &name, const WifiRequestMsgInfo &msg)
{
    LOGD("WifiManager::PushMsg name: %{public}s", name.c_str());
    BaseService *p = WifiServiceManager::GetInstance().GetServiceInst(name);
    if (p == nullptr) {
        LOGE("Get Service %{public}s failed!", name.c_str());
        return -1;
    }
    p->PushMsg(const_cast<WifiRequestMsgInfo *>(&msg));
    return 0;
}

WifiMessageQueue<WifiResponseMsgInfo> *WifiManager::GetMessageQueue()
{
    return mMqUp.get();
}

int WifiManager::AddDeviceConfig(const WifiDeviceConfig &config, int &networkId)
{
    LOGI("Enter WifiManager::AddDeviceConfig");
    WifiDeviceConfig tempDeviceConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(config.ssid, DEVICE_CONFIG_INDEX_SSID, tempDeviceConfig) == 0) {
        networkId = tempDeviceConfig.networkId;
        return 0;
    } else {
        LOGD("Add a new device config, request wpa to create network id");
        if (WifiStaHalInterface::GetInstance().GetNextNetworkId(networkId) != WIFI_IDL_OPT_OK) {
            LOGE("Failed to GetNextNetworkId!");
            return -1;
        }
        tempDeviceConfig = config;
        tempDeviceConfig.networkId = networkId;
    }

    WifiSettings::GetInstance().AddDeviceConfig(tempDeviceConfig);
    WifiSettings::GetInstance().SyncDeviceConfig();
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
        LOGE("Failed to SetDeviceConfig");
    }
    return 0;
}

InitStatus WifiManager::GetInitStatus()
{
    return mInitStatus_;
}

void *WifiManager::DealServiceUpMsg(void *p)
{
    WifiManager *pInstance = (WifiManager *)p;
    while (pInstance->mRunFlag) {
        /* read and deal response msg */
        WifiResponseMsgInfo msg;
        if (pInstance->mMqUp->Pop(msg) < 0) {
            continue;
        }
        /* deal msg begin */
        LOGI("receive msgcode %{public}d", msg.msgCode);
        if (msg.msgCode == WifiInternalMsgCode::MAIN_EXIT_CODE) {
            LOGI("Receive thread exit msg!");
            return nullptr;
        } else if (msg.msgCode > WifiInternalMsgCode::STA_START_MSG_CODE &&
                   msg.msgCode < WifiInternalMsgCode::STA_END_MSG_CODE) {
            DealStaUpMsg(pInstance, msg);
        } else if (msg.msgCode > WifiInternalMsgCode::AP_START_MSG_CODE &&
                   msg.msgCode < WifiInternalMsgCode::AP_END_MSG_CODE) {
            DealApUpMsg(msg);
        } else if (msg.msgCode > WifiInternalMsgCode::SCAN_START_MSG_CODE &&
                   msg.msgCode < WifiInternalMsgCode::SCAN_END_MSG_CODE) {
            DealScanUpMsg(msg);
        } else {
            LOGI("not deal this msgcode %{public}d, ignore it!", msg.msgCode);
        }
    }
    return nullptr;
}

void WifiManager::DealStaUpMsg(WifiManager *pInstance, const WifiResponseMsgInfo &msg)
{
    switch (msg.msgCode) {
        case WifiInternalMsgCode::STA_OPEN_RES: {
            DealStaOpenRes(pInstance, msg);
            break;
        }
        case WifiInternalMsgCode::STA_CLOSE_RES: {
            DealStaCloseRes(msg);
            break;
        }
        case WifiInternalMsgCode::STA_CONNECT_RES:
        case WifiInternalMsgCode::STA_DISCONNECT_RES: {
            DealStaConnChanged(msg);
            break;
        }
        case WifiInternalMsgCode::STA_START_WPS_RES:
        case WifiInternalMsgCode::STA_CANCEL_WPS_RES: {
            DealWpsChanged(msg);
            break;
        }
        default: {
            LOGI("not deal this msgcode %{public}d, ignore it!", msg.msgCode);
            break;
        }
    }
    return;
}

void WifiManager::DealApUpMsg(const WifiResponseMsgInfo &msg)
{
    switch (msg.msgCode) {
        case WifiInternalMsgCode::AP_OPEN_RES: {
            DealApOpenRes();
            break;
        }
        case WifiInternalMsgCode::AP_CLOSE_RES: {
            DealApCloseRes();
            break;
        }
        case WifiInternalMsgCode::AP_JOIN_RES:
        case WifiInternalMsgCode::AP_LEAVE_RES: {
            DealApConnChanged(msg);
            break;
        }
        default: {
            LOGI("not deal this msgcode %{public}d, ignore it!", msg.msgCode);
            break;
        }
    }
    return;
}

void WifiManager::DealScanUpMsg(const WifiResponseMsgInfo &msg)
{
    switch (msg.msgCode) {
        case WifiInternalMsgCode::SCAN_START_RES: {
            WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING);
            break;
        }
        case WifiInternalMsgCode::SCAN_STOP_RES: {
            WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_SCAN); /* uninstalling scan service */
            WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::CLOSED);
            break;
        }
        case WifiInternalMsgCode::SCAN_RES:
        case WifiInternalMsgCode::SCAN_PARAM_RES: {
            WifiEventCallbackMsg cbMsg;
            cbMsg.msgCode = WIFI_CBK_MSG_SCAN_STATE_CHANGE;
            cbMsg.msgData = msg.params.result;
            WifiEventBroadcast::GetInstance().AddBroadCastMsg(cbMsg);
            break;
        }
        case WifiInternalMsgCode::SCAN_RESULT_RES: {
            WifiRequestMsgInfo staMsg;
            staMsg.msgCode = WifiInternalMsgCode::STA_CONNECT_MANAGE_REQ;
            staMsg.params.scanResults = msg.params.scanResults;
            WifiManager::GetInstance().PushMsg(WIFI_SERVICE_STA, staMsg);
            break;
        }
        default: {
            LOGI("not deal this msgcode %{public}d, ignore it!", msg.msgCode);
            break;
        }
    }
    return;
}

void WifiManager::UploadOpenWifiFailedEvent()
{
    LOGD("DealStaOpenRes:upload wifi open failed event!");
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(WifiState::UNKNOWN);
    WifiEventBroadcast::GetInstance().AddBroadCastMsg(cbMsg);

    return;
}

void WifiManager::UploadOpenWifiSuccessfulEvent()
{
    LOGD("DealStaOpenRes:wifi open successfully!");
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING);
    WifiConfigCenter::GetInstance().SetStaLastRunState(true);

    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(WifiState::ENABLED);
    WifiEventBroadcast::GetInstance().AddBroadCastMsg(cbMsg);

    return;
}
void WifiManager::DealStaOpenRes(WifiManager *pInstance, const WifiResponseMsgInfo &msg)
{
    if (msg.params.result == (int)OperateResState::OPEN_WIFI_FAILED) {
        UploadOpenWifiFailedEvent();
    } else if (msg.params.result == (int)OperateResState::OPEN_WIFI_DISABLED) {
        LOGD("DealStaOpenRes:wifi open failed,close wifi sta service!");
        DealStaCloseRes(msg);
    } else {
        UploadOpenWifiSuccessfulEvent();
        WifiOprMidState scanState = WifiConfigCenter::GetInstance().GetScanMidState();
        if (scanState != WifiOprMidState::CLOSED) {
            return;
        }

        bool bflag = false;
        do {
            if (!WifiConfigCenter::GetInstance().SetScanMidState(scanState, WifiOprMidState::OPENING)) {
                LOGD("set scan mid state opening failed! may be other activity has been operated");
                bflag = true;
                break;
            }
            if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_SCAN) < 0) {
                LOGE("Load %{public}s service failed!", WIFI_SERVICE_SCAN);
                break;
            }
            WifiMessageQueue<WifiResponseMsgInfo> *mqUp = pInstance->mMqUp.get();
            auto srvInst = WifiServiceManager::GetInstance().GetServiceInst(WIFI_SERVICE_SCAN);
            if (srvInst == nullptr) {
                LOGE("Failed to get service instance!");
                break;
            }
            int ret = srvInst->Init(mqUp);
            if (ret < 0) {
                LOGE("Init %{public}s service failed!", WIFI_SERVICE_SCAN);
                WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_SCAN);
                break;
            }
            bflag = true;
        } while (0);
        if (!bflag) {
            WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED);
        }
    }

    return;
}

void WifiManager::DealStaCloseRes(const WifiResponseMsgInfo &msg)
{
    if (msg.params.result == (int)OperateResState::CLOSE_WIFI_FAILED) {
        LOGD("DealStaCloseRes:upload wifi close failed event!");
        WifiEventCallbackMsg cbMsg;
        cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
        cbMsg.msgData = static_cast<int>(WifiState::UNKNOWN);
        WifiEventBroadcast::GetInstance().AddBroadCastMsg(cbMsg);
    }

    WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA); /* uninstalling sta service */
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED);
    WifiConfigCenter::GetInstance().SetWifiStaCloseTime();

    /* Add callback message */
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(WifiState::DISABLED);
    WifiEventBroadcast::GetInstance().AddBroadCastMsg(cbMsg);

    /**
     * Check unload SCAN service
     * When anytime scanning is enabled and the control policy allows, airplane
     * mode and power saving mode are disabled.   --- Do not disable the scan
     * service. Otherwise, disable the SCAN service.
     */
    WifiOprMidState scanState = WifiConfigCenter::GetInstance().GetScanMidState();
    if (scanState != WifiOprMidState::OPENING && scanState != WifiOprMidState::RUNNING) {
        return;
    }
    ScanControlInfo info;
    WifiConfigCenter::GetInstance().GetScanControlInfo(info);
    if (WifiConfigCenter::GetInstance().IsScanAlwaysActive() && IsAllowScanAnyTime(info) &&
        WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_CLOSE &&
        WifiConfigCenter::GetInstance().GetPowerSavingModeState() == MODE_STATE_CLOSE) {
        return;
    }
    /* After check condition over, begin unload SCAN service */
    if (WifiConfigCenter::GetInstance().SetScanMidState(scanState, WifiOprMidState::CLOSING)) {
        BaseService *pService = WifiServiceManager::GetInstance().GetServiceInst(WIFI_SERVICE_SCAN);
        if (pService != nullptr) {
            pService->UnInit();
        } else {
            WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::CLOSED);
        }
    }

    return;
}

void WifiManager::DealStaConnChanged(const WifiResponseMsgInfo &msg)
{
    /* Send Event Broadcast */
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_CONNECTION_CHANGE;
    cbMsg.msgData = static_cast<int>(ConvertConnStateInternal(OperateResState(msg.params.result)));
    cbMsg.linkInfo = msg.params.linkedInfo;
    WifiEventBroadcast::GetInstance().AddBroadCastMsg(cbMsg);

    /* Pushing the connection status to the scanning service */
    if (msg.params.result == static_cast<int>(OperateResState::CONNECT_CONNECTING) ||
        msg.params.result == static_cast<int>(OperateResState::CONNECT_AP_CONNECTED) ||
        msg.params.result == static_cast<int>(OperateResState::DISCONNECT_DISCONNECTING) ||
        msg.params.result == static_cast<int>(OperateResState::DISCONNECT_DISCONNECTED)) {
        WifiRequestMsgInfo scanMsg;
        scanMsg.msgCode = WifiInternalMsgCode::SCAN_NOTIFY_STA_CONN_REQ;
        scanMsg.params.argInt = msg.params.result;
        WifiManager::GetInstance().PushMsg(WIFI_SERVICE_SCAN, scanMsg);
    }
    return;
}

void WifiManager::DealApOpenRes()
{
    WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::OPENING, WifiOprMidState::RUNNING);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(ApState::AP_STATE_STARTED);
    WifiEventBroadcast::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiManager::DealApCloseRes()
{
    WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_AP);
    WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSED);
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_CHANGE;
    cbMsg.msgData = static_cast<int>(ApState::AP_STATE_CLOSED);
    WifiEventBroadcast::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiManager::DealApConnChanged(const WifiResponseMsgInfo &msg)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_JOIN;
    if (msg.msgCode == WifiInternalMsgCode::AP_LEAVE_RES) {
        cbMsg.msgCode = WIFI_CBK_MSG_HOTSPOT_STATE_LEAVE;
    }
    cbMsg.staInfo = msg.params.staInfo;
    WifiEventBroadcast::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}

void WifiManager::DealWpsChanged(const WifiResponseMsgInfo &msg)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_WPS_STATE_CHANGE;
    cbMsg.msgData = msg.params.result;
    if (msg.params.argInt >= 0) {
        cbMsg.pinCode = std::to_string(msg.params.argInt);
        int len = cbMsg.pinCode.length();
        if (len < 8) { /* Fill in 8 digits. */
            cbMsg.pinCode = std::string(8 - len, '0') + cbMsg.pinCode;
        }
    }
    WifiEventBroadcast::GetInstance().AddBroadCastMsg(cbMsg);
    return;
}
} // namespace Wifi
} // namespace OHOS