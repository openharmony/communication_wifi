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
#include "sta_monitor.h"
#include "wifi_idl_define.h"
#include "sta_define.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("StaMonitor");

namespace OHOS {
namespace Wifi {
StaMonitor::StaMonitor() : pStaStateMachine(nullptr)
{}

StaMonitor::~StaMonitor()
{
    WIFI_LOGI("StaMonitor::~StaMonitor");
}

ErrCode StaMonitor::InitStaMonitor()
{
    WIFI_LOGI("Enter StaMonitor::InitStaMonitor.\n");

    WifiEventCallback callBack;
    callBack.onConnectChanged = &(StaMonitor::OnConnectChangedCallBack);
    callBack.onWpaStateChanged = &(StaMonitor::OnWpaStateChangedCallBack);
    callBack.onWpaSsidWrongKey = &(StaMonitor::OnWpaSsidWrongKeyCallBack);
    callBack.onWpsOverlap = &(StaMonitor::OnWpsPbcOverlapCallBack);
    callBack.onWpsTimeOut = &(StaMonitor::OnWPsTimeOutCallBack);
    callBack.pInstance = static_cast<void *>(this);
    if (WifiStaHalInterface::GetInstance().RegisterStaEventCallback(callBack) != WIFI_IDL_OPT_OK) {
        WIFI_LOGE("StaMonitor::InitStaMonitor RegisterStaEventCallback failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}
ErrCode StaMonitor::UnInitStaMonitor() const
{
    WifiEventCallback callBack;
    if (WifiStaHalInterface::GetInstance().RegisterStaEventCallback(callBack) != WIFI_IDL_OPT_OK) {
        WIFI_LOGE("StaMonitor::~StaMonitor RegisterStaEventCallback failed!");
    }
    return WIFI_OPT_SUCCESS;
}

void StaMonitor::SetStateMachine(StaStateMachine *paraStaStateMachine)
{
    pStaStateMachine = paraStaStateMachine;
    return;
}
void StaMonitor::OnConnectChangedCallBack(int status, int networkId, char *bssid, void *pInstance)
{
    WIFI_LOGI("OnConnectChangedCallBack() status:%{public}d,networkId=%{public}d,bssid=%s\n",
        status,
        networkId,
        bssid);

    if (pInstance == nullptr) {
        WIFI_LOGE("OnConnectChangedCallBack pInstance is null.\n");
        return;
    }
    auto pStaMonitor = static_cast<StaMonitor *>(pInstance);
    if (pStaMonitor->pStaStateMachine == nullptr) {
        WIFI_LOGE("OnConnectChangedCallBack pStaMonitor->pStaStateMachine is null.\n");
        return;
    }
    switch (status) {
        case WPA_CB_CONNECTED: {
            pStaMonitor->pStaStateMachine->OnNetworkConnectionEvent(networkId, bssid);
            break;
        }
        case WPA_CB_DISCONNECTED: {
            pStaMonitor->pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT);
            break;
        }
        default:
            break;
    }
}

void StaMonitor::OnWpaStateChangedCallBack(int status, void *pInstance)
{
    WIFI_LOGI("OnWpaStateChangedCallBack() status:%{public}d\n", status);

    if (pInstance == nullptr) {
        WIFI_LOGE("OnWpaStateChangedCallBack pInstance is null.\n");
        return;
    }
    auto pStaMonitor = static_cast<StaMonitor *>(pInstance);
    if (pStaMonitor->pStaStateMachine == nullptr) {
        WIFI_LOGE("OnWpaStateChangedCallBack pStaMonitor->pStaStateMachine is null.\n");
        return;
    }
    /* Notification state machine wpa state changed event. */
    pStaMonitor->pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_WPA_STATE_CHANGE_EVENT, status);
}

void StaMonitor::OnWpaSsidWrongKeyCallBack(int status, void *pInstance)
{
    WIFI_LOGI("OnWpaSsidWrongKeyCallBack() status:%{public}d\n", status);

    if (pInstance == nullptr) {
        WIFI_LOGE("OnWpaSsidWrongKeyCallBack pInstance is null.\n");
        return;
    }
    auto pStaMonitor = static_cast<StaMonitor *>(pInstance);
    if (pStaMonitor->pStaStateMachine == nullptr) {
        WIFI_LOGE("OnWpaSsidWrongKeyCallBack pStaMonitor->pStaStateMachine is null.\n");
        return;
    }

    if (status != 1) {
        WIFI_LOGE("OnWpaSsidWrongKeyCallBack error");
        return;
    }
    /* Notification state machine wpa password wrong event. */
    pStaMonitor->pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT, status);
}
void StaMonitor::OnWpsPbcOverlapCallBack(int status, void *pInstance)
{
    WIFI_LOGI("OnWpsPbcOverlapCallBack() statue:%{public}d\n", status);

    if (pInstance == nullptr) {
        WIFI_LOGE("OnWpsPbcOverlapCallBack pInstance is null.\n");
        return;
    }
    auto pStaMonitor = static_cast<StaMonitor *>(pInstance);
    if (pStaMonitor->pStaStateMachine == nullptr) {
        WIFI_LOGE("OnWpsPbcOverlapCallBack pStaMonitor->pStaStateMachine is null.\n");
        return;
    }
    /* Notification state machine WPS overlap event. */
    pStaMonitor->pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_WPS_OVERLAP_EVENT);
}

void StaMonitor::OnWPsTimeOutCallBack(int status, void *pInstance)
{
    WIFI_LOGI("OnWpsTimeOutCallBack() statue:%{public}d\n", status);

    if (pInstance == nullptr) {
        WIFI_LOGE("OnWpsTimeOutCallBack pInstance is null.\n");
        return;
    }
    auto pStaMonitor = static_cast<StaMonitor *>(pInstance);
    if (pStaMonitor->pStaStateMachine == nullptr) {
        WIFI_LOGE("OnWpsTimeOutCallBack pStaMonitor->pStaStateMachine is null.\n");
        return;
    }
    /* Notification state machine WPS timeout event */
    pStaMonitor->pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_WPS_TIMEOUT_EVNET);
}
}  // namespace Wifi
}  // namespace OHOS