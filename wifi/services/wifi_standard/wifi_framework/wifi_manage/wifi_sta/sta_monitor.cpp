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

#include <cstring>
#include "sta_monitor.h"
#include "sta_define.h"
#include "wifi_logger.h"
#include "wifi_supplicant_hal_interface.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_common_util.h"
#include "wifi_hisysevent.h"
#include "wifi_event_callback.h"
#include "wifi_config_center.h"

DEFINE_WIFILOG_LABEL("StaMonitor");

namespace OHOS {
namespace Wifi {
constexpr const char* WPA_CSA_CHANNEL_SWITCH_FREQ_PREFIX = "freq=";
StaMonitor::StaMonitor(int instId) : pStaStateMachine(nullptr), m_instId(instId)
{
    WIFI_LOGI("StaMonitor constuctor insId %{public}d", instId);
}

StaMonitor::~StaMonitor()
{
    WIFI_LOGI("~StaMonitor");
}

ErrCode StaMonitor::InitStaMonitor()
{
    WIFI_LOGI("Enter InitStaMonitor.\n");
    using namespace std::placeholders;
    WifiEventCallback callBack = {
        [this](int status, int code, const std::string &bssid) {
            this->OnConnectChangedCallBack(status, code, bssid);
        },
        [this](const std::string &reason, const std::string &bssid) { this->OnBssidChangedCallBack(reason, bssid); },
        [this](int status, const std::string &ssid) { this->OnWpaStateChangedCallBack(status, ssid); },
        [this]() { this->OnWpaSsidWrongKeyCallBack(); },
        [this](int status) { this->OnWpsPbcOverlapCallBack(status); },
        [this](int status) { this->OnWpsTimeOutCallBack(status); },
        [this]() { this->OnWpaAuthTimeOutCallBack(); },
        [this](int status) { this->OnWpaConnectionFullCallBack(status); },
        [this](int status) { this->OnWpaConnectionRejectCallBack(status); },
        [this](const std::string &notifyParam) { this->OnWpaStaNotifyCallBack(notifyParam); },
        [this](int reason, const std::string &bssid) {},
    };

    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if (WifiStaHalInterface::GetInstance().RegisterStaEventCallback(callBack, ifaceName) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("InitStaMonitor RegisterStaEventCallback failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

NO_SANITIZE("cfi") ErrCode StaMonitor::UnInitStaMonitor() const
{
    WIFI_LOGI("Enter UnInitStaMonitor.\n");
    WifiEventCallback callBack;
    std::string ifaceName = WifiConfigCenter::GetInstance().GetStaIfaceName(m_instId);
    if (WifiStaHalInterface::GetInstance().RegisterStaEventCallback(callBack, ifaceName) != WIFI_HAL_OPT_OK) {
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

void StaMonitor::OnConnectChangedCallBack(int status, int code, const std::string &bssid)
{
    WIFI_LOGI("OnConnectChangedCallBack status:%{public}d, code=%{public}d, bssid=%{public}s, instId=%{public}d",
        status, code, MacAnonymize(bssid).c_str(), m_instId);
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }
    switch (status) {
        case HAL_WPA_CB_CONNECTED: {
            InternalMessagePtr msg = pStaStateMachine->CreateMessage(WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT);
            if (msg == nullptr) {
                WIFI_LOGE("CreateMessage failed");
                return;
            }
            msg->SetParam1(code);
            msg->AddStringMessageBody(bssid);
            pStaStateMachine->SendMessage(msg);
            break;
        }
        case HAL_WPA_CB_DISCONNECTED: {
            InternalMessagePtr msg = pStaStateMachine->CreateMessage(WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT);
            if (msg == nullptr) {
                WIFI_LOGE("CreateMessage failed");
                return;
            }
            msg->SetParam1(code);
            msg->AddStringMessageBody(bssid);
            pStaStateMachine->SendMessage(msg);
            break;
        }
        default:
            break;
    }
}

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
    int num = CheckDataLegal(type);
    std::string data = notifyParam.substr(begPos + 1);
    if (data.empty()) {
        WIFI_LOGI("OnWpaStaNotifyCallBack() data is empty");
        return;
    }
    switch (num) {
        case static_cast<int>(WpaEventCallback::HILINK_NUM):
            OnWpaHilinkCallBack(data);
            break;
        case static_cast<int>(WpaEventCallback::EAP_SIM_NUM):
            OnWpaEapSimAuthCallBack(data);
            break;
        case static_cast<int>(WpaEventCallback::CSA_CHSWITCH_NUM):
            OnWpaCsaChannelSwitchNotifyCallBack(data);
            break;
        case static_cast<int>(WpaEventCallback::MLO_STATE_NUM):
            OnWpaMloStateNotifyCallBack(data);
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
    InternalMessagePtr msg = pStaStateMachine->CreateMessage();
    if (msg == nullptr) {
    WIFI_LOGE("CreateMessage failed");
    return;
    }

    if (strcmp(reason.c_str(), "LINK_SWITCH") == 0) {
        msg->SetMessageName(WIFI_SVR_CMD_STA_LINK_SWITCH_EVENT);
    } else {
        msg->SetMessageName(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
        msg->AddStringMessageBody(reason);
    }
    msg->AddStringMessageBody(bssid);
    pStaStateMachine->SendMessage(msg);
}

void StaMonitor::OnWpaStateChangedCallBack(int status, const std::string &ssid)
{
    WIFI_LOGI("OnWpaStateChangedCallBack() status:%{public}d, ssid=%{public}s", status, SsidAnonymize(ssid).c_str());
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }
    WriteWifiWpaStateHiSysEvent(status);
    /* Notification state machine wpa state changed event. */
    InternalMessagePtr msg = pStaStateMachine->CreateMessage(WIFI_SVR_CMD_STA_WPA_STATE_CHANGE_EVENT);
    if (msg == nullptr) {
        WIFI_LOGE("CreateMessage failed");
        return;
    }
    msg->SetParam1(status);
    msg->AddStringMessageBody(ssid);
    pStaStateMachine->SendMessage(msg);
}

void StaMonitor::OnWpaSsidWrongKeyCallBack()
{
    WIFI_LOGI("OnWpaSsidWrongKeyCallBack");
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }

    /* Notification state machine wpa password wrong event. */
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT);
}

void StaMonitor::OnWpaConnectionFullCallBack(int status)
{
    LOGI("onWpaConnectionFullCallBack() status:%{public}d", status);
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }

    /* Notification state machine wpa password wrong event. */
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT);
}

void StaMonitor::OnWpaConnectionRejectCallBack(int status)
{
    LOGI("onWpsConnectionRejectCallBack() status:%{public}d", status);
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

void StaMonitor::OnWpaAuthTimeOutCallBack()
{
    WIFI_LOGI("OnWpaAuthTimeOutCallBack");
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

void StaMonitor::OnWpaCsaChannelSwitchNotifyCallBack(const std::string &notifyParam)
{
    WIFI_LOGD("%{public}s notifyParam:%{private}s", __FUNCTION__, notifyParam.c_str());
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("%{public}s The statemachine pointer is null.", __FUNCTION__);
        return;
    }
    std::string::size_type freqPos = 0;
    if ((freqPos = notifyParam.find(WPA_CSA_CHANNEL_SWITCH_FREQ_PREFIX)) == std::string::npos) {
        WIFI_LOGE("%{public}s csa channel switch notifyParam not find frequency!", __FUNCTION__);
        return;
    }
    std::string data = notifyParam.substr(freqPos + strlen(WPA_CSA_CHANNEL_SWITCH_FREQ_PREFIX));
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_CSA_CHANNEL_SWITCH_EVENT, CheckDataLegal(data));
}

void StaMonitor::OnWpaMloStateNotifyCallBack(const std::string &notifyParam)
{
    WIFI_LOGD("%{public}s notifyParam=%{public}s", __FUNCTION__, notifyParam.c_str());
    if (pStaStateMachine == nullptr) {
        WIFI_LOGE("%{public}s The statemachine pointer is null.", __FUNCTION__);
        return;
    }
    if (notifyParam.empty()) {
        WIFI_LOGI("OnWpaMloStateNotifyCallBack() notifyParam is empty");
        return;
    }

    std::string::size_type begPos = 0;
    if ((begPos = notifyParam.find(":")) == std::string::npos) {
        WIFI_LOGE("%{public}s notifyParam not find :", __FUNCTION__);
        return;
    }
    std::string featureStr = notifyParam.substr(0, begPos);
    std::string notifyParam2 = notifyParam.substr(begPos + 1);
    if (notifyParam2.empty()) {
        WIFI_LOGE("%{public}s reasonCodeStr is empty", __FUNCTION__);
        return;
    }

    std::string::size_type begPos2 = 0;
    if ((begPos2 = notifyParam2.find(":")) == std::string::npos) {
        WIFI_LOGE("%{public}s notifyParam2 not find :", __FUNCTION__);
        return;
    }
    std::string stateStr = notifyParam2.substr(0, begPos);
    std::string reasonCodeStr = notifyParam2.substr(begPos + 1);
    if (reasonCodeStr.empty()) {
        WIFI_LOGE("%{public}s reasonCodeStr is empty", __FUNCTION__);
        return;
    }

    MloStateParam mloParam = {0};
    mloParam.feature = CheckDataToUint(featureStr);
    mloParam.state = CheckDataToUint(stateStr);
    mloParam.reasonCode = CheckDataToUint(reasonCodeStr);
    WIFI_LOGI("%{public}s feature:%{public}d state:%{public}u reasonCode:%{public}u", __FUNCTION__,
        mloParam.feature, mloParam.mloState, mloParam.reasonCode);

    /* Notify sta state machine mlo state changed event. */
    pStaStateMachine->SendMessage(WIFI_SVR_CMD_STA_MLO_WORK_STATE_EVENT, mloParam);
}
}  // namespace Wifi
}  // namespace OHOS