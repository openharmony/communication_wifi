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
#include "ap_service.h"
#include <unistd.h>
#include "ap_state_machine.h"
#include "log_helper.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_AP_ApService"
namespace OHOS {
namespace Wifi {
ApService &ApService::GetInstance()
{
    static ApService instance_;
    return instance_;
}

void ApService::DeleteInstance()
{}

ApService::ApService() : mMsgQueueUp(nullptr)
{}

int ApService::Init(WifiMessageQueue<WifiResponseMsgInfo> *mqUp)
{
    if (mqUp == nullptr) {
        LOGE("fatal error!");
        return -1;
    }
    mMsgQueueUp = mqUp;
    EnableHotspot();
    return 0;
}

int ApService::UnInit(void) const
{
    DisableHotspot();
    return 0;
}

int ApService::PushMsg(const WifiRequestMsgInfo *msg) const
{
    if (msg == nullptr) {
        LOGE("fatal error!");
        return -1;
    }
    LOGI("Receive a message from the ServiceManager. msgCode = [%{public}d]", msg->msgCode);
    switch (static_cast<WifiInternalMsgCode>(msg->msgCode)) {
        case WifiInternalMsgCode::AP_ADD_BLOCK_LIST_REQ: {
            AddBlockList(msg->params.stationInfo);
            break;
        }
        case WifiInternalMsgCode::AP_DEL_BLOCK_LIST_REQ: {
            DelBlockList(msg->params.stationInfo);
            break;
        }
        case WifiInternalMsgCode::AP_SET_HOTSPOT_CONFIG_REQ: {
            SetHotspotConfig(msg->params.hotspotConfig);
            break;
        }
        case WifiInternalMsgCode::AP_DISCCONECT_STA_BY_MAC_REQ: {
            DisconnetStation(msg->params.stationInfo);
            break;
        }
        default:
            return -1;
            break;
    }

    return 0;
}

void ApService::BroadcastMsg(const WifiResponseMsgInfo &upMsg) const
{
    mMsgQueueUp->Push(upMsg);
    return;
}

void ApService::OnApStateChange(const ApState &state) const
{
    if (WifiSettings::GetInstance().SetHotspotState(static_cast<int>(state))) {
        LOGE("WifiSetting change state failed");
    }
    switch (state) {
        case ApState::AP_STATE_IDLE: {
            WifiResponseMsgInfo msg;
            msg.msgCode = WifiInternalMsgCode::AP_CLOSE_RES;
            BroadcastMsg(msg);
            break;
        }
        case ApState::AP_STATE_STARTED: {
            WifiResponseMsgInfo msg;
            msg.msgCode = WifiInternalMsgCode::AP_OPEN_RES;
            BroadcastMsg(msg);
            break;
        }
        default: /* don't update other state */
            break;
    }
    return;
}

void ApService::OnHotspotStaJoin(const StationInfo &info) const
{
    WifiResponseMsgInfo msgInfo;
    msgInfo.params.staInfo = info;
    msgInfo.msgCode = AP_JOIN_RES;
    LOGI("OnHotspotStaJoin:,%{public}d,%s,%s,%s",
        msgInfo.msgCode,
        msgInfo.params.staInfo.bssid.c_str(),
        msgInfo.params.staInfo.deviceName.c_str(),
        msgInfo.params.staInfo.ipAddr.c_str());
    BroadcastMsg(msgInfo);
}

void ApService::OnHotspotStaLeave(const StationInfo &info) const
{
    WifiResponseMsgInfo msgInfo;
    msgInfo.params.staInfo = info;
    msgInfo.msgCode = AP_LEAVE_RES;
    LOGI("OnHotspotStaleave:,%{public}d,%s,%s,%s",
        msgInfo.msgCode,
        msgInfo.params.staInfo.bssid.c_str(),
        msgInfo.params.staInfo.deviceName.c_str(),
        msgInfo.params.staInfo.ipAddr.c_str());
    BroadcastMsg(msgInfo);
}

void ApService::EnableHotspot() const
{
    ApStateMachine::GetInstance().SendMessage(static_cast<int>(ApStatemachineEvent::CMD_START_HOTSPOT));
}

void ApService::DisableHotspot() const
{
    ApStateMachine::GetInstance().SendMessage(static_cast<int>(ApStatemachineEvent::CMD_STOP_HOTSPOT));
}

void ApService::SetHotspotConfig(const HotspotConfig &cfg) const
{
    ApStateMachine::GetInstance().SetHotspotConfig(cfg);
    return;
}

void ApService::AddBlockList(const StationInfo &stationInfo) const
{
    ApStateMachine::GetInstance().AddBlockList(stationInfo);
    return;
}

void ApService::DelBlockList(const StationInfo &stationInfo) const
{
    ApStateMachine::GetInstance().DelBlockList(stationInfo);
    return;
}

void ApService::DisconnetStation(const StationInfo &stationInfo) const
{
    ApStateMachine::GetInstance().DisconnetStation(stationInfo);
    return;
}
}  // namespace Wifi
}  // namespace OHOS