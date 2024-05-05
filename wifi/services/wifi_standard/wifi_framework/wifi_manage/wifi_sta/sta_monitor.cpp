/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include "wifi_supplicant_hal_interface.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_LABEL("StaMonitor");

namespace OHOS {
namespace Wifi {
StaMonitor::StaMonitor(int instId) : pStaStateMachine(nullptr), m_instId(instId)
{}

StaMonitor::~StaMonitor()
{
    WIFI_LOGI("~StaMonitor");
}

ErrCode StaMonitor::InitStaMonitor()
{
    WIFI_LOGI("Enter InitStaMonitor.\n");
    using namespace std::placeholders;
    WifiEventCallback callBack = {
        std::bind(&StaMonitor::OnConnectChangedCallBack, this, _1, _2, _3),
        std::bind(&StaMonitor::OnBssidChangedCallBack, this, _1, _2),
        std::bind(&StaMonitor::OnWpaStateChangedCallBack, this, _1),
        std::bind(&StaMonitor::OnWpaSsidWrongKeyCallBack, this, _1),
        std::bind(&StaMonitor::OnWpsPbcOverlapCallBack, this, _1),
        std::bind(&StaMonitor::OnWpsTimeOutCallBack, this, _1),
        std::bind(&StaMonitor::onWpaConnectionFullCallBack, this, _1),
        std::bind(&StaMonitor::onWpaConnectionRejectCallBack, this, _1),
        std::bind(&StaMonitor::OnWpaStaNotifyCallBack, this, _1),
        std::bind(&StaMonitor::OnReportDisConnectReasonCallBack, this, _1, _2),
    };

    if (WifiStaHalInterface::GetInstance().RegisterStaEventCallback(callBack) != WIFI_IDL_OPT_OK) {
        WIFI_LOGE("InitStaMonitor RegisterStaEventCallback failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

NO_SANITIZE("cfi") ErrCode StaMonitor::UnInitStaMonitor() const
{
    WIFI_LOGI("Enter UnInitStaMonitor.\n");
    WifiEventCallback callBack;
    if (WifiStaHalInterface::GetInstance().RegisterStaEventCallback(callBack) != WIFI_IDL_OPT_OK) {
        WIFI_LOGE("~StaMonitor RegisterStaEventCallback failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

void StaMonitor::SetStateMachine(StaStateMachine *paraStaStateMachine)
{
    if (paraStaStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }
    pStaStateMachine = paraStaStateMachine;
    return;
}

void StaMonitor::OnReportDisConnectReasonCallBack(int reason, const std::string &bssid)
{
    WIFI_LOGI("OnReportDisConnectReasonCallBack() reason=%{public}d, bssid=%{public}s",
        reason, MacAnonymize(bssid).c_str());
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("OnReportDisConnectReasonCallBack pStaStateMachine is nullptr");
        return;
    }

    InternalMessage *msg = pStaStateMachine->CreateMessage();
    if (msg == nullptr) {
        WIFI_LOGE("OnReportDisConnectReasonCallBack CreateMessage failed");
        return;
    }
    msg->SetMessageName(static_cast<int>(WIFI_SVR_CMD_STA_REPORT_DISCONNECT_REASON_EVENT));
    msg->AddStringMessageBody(bssid);
    msg->AddIntMessageBody(reason);
    pStaStateMachine->SendMessage(msg);
}

void StaMonitor::OnConnectChangedCallBack(int status, int networkId, const std::string &bssid)
{
    WIFI_LOGI("OnConnectChangedCallBack() status:%{public}d,networkId=%{public}d,bssid=%{public}s",
        status,
        networkId,
        MacAnonymize(bssid).c_str());
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }
    if (status == WPA_CB_ASSOCIATING || status == WPA_CB_ASSOCIATED) {
        pStaStateMachine->OnNetworkHiviewEvent(status);
    }

    switch (status) {
        case WPA_CB_CONNECTED: {
            pStaStateMachine->OnNetworkConnectionEvent(networkId, bssid);
            break;
        }
        case WPA_CB_DISCONNECTED: {
            pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT, bssid);
            pStaStateMachine->OnNetworkDisconnectEvent(networkId);
            break;
        }
        case WPA_CB_ASSOCIATING:
        case WPA_CB_ASSOCIATED:
            pStaStateMachine->OnNetworkAssocEvent(status, bssid, pStaStateMachine);
            break;
        default:
            break;
    }
}

constexpr int HILINK_NUM = 0X01;
constexpr int EAP_SIM_NUM = 0X02;

void StaMonitor::OnWpaStaNotifyCallBack(const std::string &notifyParam)
{
    WIFI_LOGI("OnWpaStaNotifyCallBack() enter, notifyParam=%{private}s", notifyParam.c_str());
    if (notifyParam.empty()) {
        WIFI_LOGI("OnWpaStaNotifyCallBack() notifyParam is empty");
        return;
    }

    std::string::size_type begPos = 0;
    if ((begPos = notifyParam.find(":")) == std::string::npos) {
        WIFI_LOGI("OnWpaStaNotifyCallBack() notifyParam not find :");
        return;
    }
    std::string type = notifyParam.substr(0, begPos);
    int num = stoi(type);
    std::string data = notifyParam.substr(begPos + 1);
    if (data.empty()) {
        WIFI_LOGI("OnWpaStaNotifyCallBack() data is empty");
        return;
    }
    switch (num) {
        case HILINK_NUM:
            OnWpaHilinkCallBack(data);
            break;
        case EAP_SIM_NUM:
            OnWpaEapSimAuthCallBack(data);
            break;
        default:
            WIFI_LOGI("OnWpaStaNotifyCallBack() undefine event:%{public}d", num);
            break;
    }
}

void StaMonitor::OnWpaHilinkCallBack(const std::string &bssid)
{
    WIFI_LOGI("OnWpaHilinkCallBack() enter");
    pStaStateMachine->SendMessage(WIFI_SVR_COM_STA_HILINK_TRIGGER_WPS, bssid);
    return;
}

void StaMonitor::OnBssidChangedCallBack(const std::string &reason, const std::string &bssid)
{
    WIFI_LOGI("OnBssidChangedCallBack() reason:%{public}s,bssid=%{public}s",
        reason.c_str(),
        MacAnonymize(bssid).c_str());
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }

    WifiLinkedInfo linkedInfo;
    pStaStateMachine->GetLinkedInfo(linkedInfo);
    if (linkedInfo.bssid == bssid) {
        WIFI_LOGW("Sta ignored the event for bssid is the same.");
        return;
    }
    pStaStateMachine->OnBssidChangedEvent(reason, bssid);
}

void StaMonitor::OnWpaStateChangedCallBack(int status)
{
    WIFI_LOGI("OnWpaStateChangedCallBack() status:%{public}d\n", status);
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }
    /* Notification state machine wpa state changed event. */
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_WPA_STATE_CHANGE_EVENT, status);
}

void StaMonitor::OnWpaSsidWrongKeyCallBack(int status)
{
    WIFI_LOGI("OnWpaSsidWrongKeyCallBack() status:%{public}d\n", status);
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }

    if (status != 1) {
        WIFI_LOGE("OnWpaSsidWrongKeyCallBack error.");
        return;
    }
    /* Notification state machine wpa password wrong event. */
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT);
}

void StaMonitor::onWpaConnectionFullCallBack(int status)
{
    LOGI("onWpaConnectionFullCallBack() status:%d.\n", status);
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }

    /* Notification state machine wpa password wrong event. */
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT);
}

void StaMonitor::onWpaConnectionRejectCallBack(int status)
{
    LOGI("onWpsConnectionRejectCallBack() status:%d.\n", status);
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }

    /* Notification state machine wpa password wrong event. */
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_WPA_ASSOC_REJECT_EVENT);
}

void StaMonitor::OnWpsPbcOverlapCallBack(int status)
{
    WIFI_LOGI("OnWpsPbcOverlapCallBack() status:%{public}d\n", status);
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }
    /* Notification state machine WPS overlap event. */
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_WPS_OVERLAP_EVENT);
}

void StaMonitor::OnWpsTimeOutCallBack(int status)
{
    WIFI_LOGI("OnWpsTimeOutCallBack() status:%{public}d\n", status);
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }
    /* Notification state machine WPS timeout event */
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_WPS_TIMEOUT_EVNET, status);
}

/* SIM authentication data format: [GSM-AUTH][:][Rand1][:][Rand2] or [GSM-AUTH][:][Rand1][:][Rand2][:][Rand3]
   AKA/AKA authentication data format: [UMTS-AUTH][:][rand][:][autn]
*/
void StaMonitor::OnWpaEapSimAuthCallBack(const std::string &notifyParam)
{
    WIFI_LOGD("OnWpaEapSimAuthCallBack, notifyParam:%{private}s", notifyParam.c_str());
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }

    std::string delimiter = ":";
    std::vector<std::string> results = getAuthInfo(notifyParam, delimiter);
    int size = results.size();
    if (results[0] == "GSM-AUTH") {
        if ((size != WIFI_SIM_GSM_AUTH_MIN_PARAM_COUNT) && (size != WIFI_SIM_GSM_AUTH_MAX_PARAM_COUNT)) {
            WIFI_LOGE("invalid GSM-AUTH authentication data, size:%{public}d", size);
            return;
        }

        EapSimGsmAuthParam param;
        for (int i = 0; i < size; i++) {
            if (i == 0) {
                continue;
            }
            param.rands.push_back(results[i]);
            WIFI_LOGI("results[%{public}d]:%{public}s", i, results[i].c_str());
        }
        WIFI_LOGI("%{public}s size:%{public}zu", __func__, param.rands.size());
        pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_WPA_EAP_SIM_AUTH_EVENT, param);
    } else if ((results[0] == "UMTS-AUTH") || (results[0] == "UMTS-AUTS")) {
        if (size != WIFI_SIM_UMTS_AUTH_PARAM_COUNT) {
            WIFI_LOGE("invalid UMTS-AUTH authentication data, size:%{public}d", size);
            return;
        }
        EapSimUmtsAuthParam param;
        param.rand = results[1];  // get rand data
        param.autn = results[2];  // get autn data
        WIFI_LOGD("%{public}s rand:%{private}s, autn:%{private}s",
            __func__, param.rand.c_str(), param.autn.c_str());
        pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT, param);
    } else {
        WIFI_LOGE("Invalid authentication type, authType:%{public}s", results[0].c_str());
        return;
    }
}
}  // namespace Wifi
}  // namespace OHOS