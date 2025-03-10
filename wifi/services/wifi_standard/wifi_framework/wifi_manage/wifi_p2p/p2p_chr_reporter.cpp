/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "p2p_chr_reporter.h"

#include <regex>
#include "define.h"
#include "wifi_common_util.h"
#include "wifi_hisysevent.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_logger.h"
#include "wifi_msg.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_P2P_LABEL("P2pChrReporter");

void P2pChrReporter::ProcessChrEvent(const std::string &notifyParam)
{
    WIFI_LOGD("ProcessChrEvent notifyParam:%{public}s", notifyParam.c_str());
    if (notifyParam.empty()) {
        WIFI_LOGE("ProcessChrEvent notifyParam is empty");
        return;
    }
    std::string chrEvent = notifyParam;
    size_t start = 0;
    size_t end = 0;
    std::vector<std::string> eventVector;

    chrEvent += "_";
    std::regex pureNumber("-?\\d+");
    while ((end = chrEvent.find('_', start)) != std::string::npos) {
        std::string subNumber = chrEvent.substr(start, end - start);
        if (subNumber.empty() || !std::regex_match(subNumber, pureNumber)) {
            WIFI_LOGE("ProcessChrEvent subNumber is illegal, which is %{public}s", subNumber.c_str());
            return;
        }
        eventVector.push_back(subNumber);
        start = end + 1;
    }

    if (eventVector.size() != INDEX_MINOR_CODE + 1) {
        WIFI_LOGE("ProcessChrEvent number size is not right");
        return;
    }

    int eventType = CheckDataLegal(eventVector[INDEX_EVENT_TYPE]);
    int state = CheckDataLegal(eventVector[INDEX_STATE]);
    int errCode = CheckDataLegal(eventVector[INDEX_REASON_CODE]);
    int minorCode = CheckDataLegal(eventVector[INDEX_MINOR_CODE]);

    WIFI_LOGD("ProcessChrEvent eventType:%{public}d, state:%{public}d, err:%{public}d,"
        "minorErr:%{public}d", eventType, state, errCode, minorCode);
    switch (static_cast<P2pEventCode>(eventType)) {
        case P2P_CHR_EVENT_STATE_CHANGE_BEFORE_GROUP_FORMATION_SUCCESS:
            ReportErrCodeBeforeGroupFormationSucc(state, errCode, minorCode);
            break;
        case P2P_CHR_EVENT_INTERFACE_STATE_CHANGE:
            ReportP2pInterfaceStateChange(state, errCode, minorCode);
            break;
    }
}

void P2pChrReporter::ReportErrCodeBeforeGroupFormationSucc(int state, int errCode, int minorCode)
{
    if (errCode == P2P_STATUS_SUCCESS) {
        if (state == P2P_INVITATION) {
            wpsSuccess_ = true;
        }
        return;
    }
    ReportP2pConnectFailed(state, errCode, minorCode);
}

void P2pChrReporter::ReportP2pInterfaceStateChange(int state, int errCode, int minorCode)
{
    if (!wpsSuccess_ && errCode != DR_TO_SWITCH_MGMT) {
        WIFI_LOGI("wpsSuccess_:%{public}d not success", wpsSuccess_);
        return;
    }
    if (errCode == DR_TO_SWITCH_MGMT) {
        wpsSuccess_ = true;
        return;
    }
    UpdateErrorMessage(state, errCode, minorCode);
}

void P2pChrReporter::UpdateErrorMessage(int state, int errCode, int minorCode)
{
    if (state != P2P_INTERFACE_STATE_DISCONNECTED) {
        lastP2pState_ = state;
        lastErrCode_ = errCode;
        lastMinorCode_ = minorCode;
        return;
    }

    if (!IsNormalErrCode(lastErrCode_)) {
        return;
    }
    WIFI_LOGI("Update errCode:%{public}d, minorCode:%{public}d", errCode, minorCode);
    lastErrCode_ = errCode;
    lastMinorCode_ = minorCode;
}

void P2pChrReporter::UploadP2pChrErrEvent()
{
    if (!wpsSuccess_) {
        WIFI_LOGI("wpsSuccess_:%{public}d not success", wpsSuccess_);
        return;
    }
    if (IsNormalErrCode(lastErrCode_)) {
        WIFI_LOGI("Disconnected with normal error code");
        return;
    }

    if (lastP2pState_ == P2P_INTERFACE_STATE_COMPLETED || lastP2pState_ == GC_CONNECTED) {
        ReportP2pAbnormalDisconnect(lastP2pState_, lastErrCode_, lastMinorCode_);
    }
    if (lastP2pState_ >= P2P_INTERFACE_STATE_SCANNING && lastP2pState_ <= P2P_INTERFACE_STATE_GROUP_HANDSHAKE) {
        ReportP2pConnectFailed(lastP2pState_, lastErrCode_, lastMinorCode_);
    }
}

void P2pChrReporter::ResetState()
{
    WIFI_LOGI("ResetState");
    wpsSuccess_ = false;
    role_ = UNKNOWN_ROLE;
    lastP2pState_ = DEVICE_DISCOVERY;
    lastErrCode_ = P2P_CHR_DEFAULT_REASON_CODE;
    lastMinorCode_ = P2P_CHR_DEFAULT_REASON_CODE;
}

void P2pChrReporter::ReportP2pConnectFailed(int state, int errCode, int minorCode)
{
    int standErrCode = static_cast<int>(GenerateStandardErrCode(P2P_SUB_SYSTEM_ID,
        GetP2pSpecificError(state, errCode)));
    WIFI_LOGI("P2pConnectFailed state:%{public}d, err:%{public}d, minorErr:%{public}d, "
        "DeviceRole:%{public}d, standErrCode:%{public}d", state, errCode, minorCode, role_, standErrCode);
    WriteP2pConnectFailedHiSysEvent(standErrCode, minorCode);
    OnP2pChrErrCodeReport(standErrCode);
}

void P2pChrReporter::ReportP2pAbnormalDisconnect(int state, int errCode, int minorCode)
{
    int standErrCode = static_cast<int>(GenerateStandardErrCode(P2P_SUB_SYSTEM_ID,
        GetP2pSpecificError(state, errCode)));
    WIFI_LOGI("P2pAbnormalDisconnect state:%{public}d, err:%{public}d, minorErr:%{public}d, "
        "DeviceRole:%{public}d, standErrCode:%{public}d", state, errCode, minorCode, role_, standErrCode);
    WriteP2pAbDisConnectHiSysEvent(standErrCode, minorCode);
    OnP2pChrErrCodeReport(standErrCode);
}

uint16_t P2pChrReporter::GetP2pSpecificError(int state, int errCode)
{
    uint8_t standardState = static_cast<uint8_t>(state) & 0x1F;
    uint8_t standardRole = static_cast<uint8_t>(role_);
    uint16_t standardErrCode = static_cast<uint16_t>(errCode) & 0x1FF;
    return (standardState << STATE_OFFSET) | (standardRole << DEVICE_ROLE_OFFSET) | standardErrCode;
}

void P2pChrReporter::SetWpsSuccess(bool success)
{
    WIFI_LOGI("set wpa success, %{public}d -> %{public}d", wpsSuccess_, success);
    wpsSuccess_ = success;
}

void P2pChrReporter::SetDeviceRole(DeviceRole role)
{
    WIFI_LOGI("set device role, %{public}d -> %{public}d", role_, role);
    role_ = role;
}

bool P2pChrReporter::IsNormalErrCode(int errCode)
{
    return (errCode == P2P_CHR_DEFAULT_REASON_CODE ||
            errCode == DISCONNECT_REASON_UNKNOWN ||
            errCode == static_cast<int>(DisconnectDetailReason::DEAUTH_STA_IS_LEFING) ||
            errCode == static_cast<int>(DisconnectDetailReason::DISASSOC_STA_HAS_LEFT));
}

void P2pChrReporter::OnP2pChrErrCodeReport(int errCode)
{
    WifiEventCallbackMsg cbMsg;
    cbMsg.msgCode = WIFI_CBK_MSG_P2P_CHR_ERRCODE_REPORT;
    cbMsg.errCode = errCode;
    WifiInternalEventDispatcher::GetInstance().AddBroadCastMsg(cbMsg);
}

} // namespace Wifi
} // namespace OHOS