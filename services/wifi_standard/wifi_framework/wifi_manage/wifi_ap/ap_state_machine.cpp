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
#include "ap_state_machine.h"
#include <typeinfo>
#include "ipv4_address.h"
#include "ipv6_address.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_AP_ApStateMachine"
namespace OHOS {
namespace Wifi {
ApStateMachine *ApStateMachine::g_instance = nullptr;

ApStateMachine::ApStateMachine() : StateMachine("ApStateMachine")
{}

ApStateMachine::~ApStateMachine()
{
    StopHandlerThread();
}

ApStateMachine &ApStateMachine::GetInstance()
{
    if (g_instance == nullptr) {
        g_instance = new (std::nothrow) ApStateMachine();
        if (g_instance && g_instance->InitialStateMachine()) {
            g_instance->Init();
        } else {
            LOGE("init ApStateMachine error");
            delete g_instance;
            g_instance = nullptr;
        }
    }
    return *g_instance;
}

void ApStateMachine::DeleteInstance()
{
    if (g_instance != nullptr) {
        delete g_instance;
        g_instance = nullptr;
    }
}

void ApStateMachine::Init()
{
    LOGI("ApStateMachine::Init");
    AddState(&mApRootState, nullptr);
    AddState(&mApIdleState, &mApRootState);
    AddState(&mApStartedState, &mApRootState);

    SetInitialState(&mApIdleState);
    Start();
}

void ApStateMachine::StationJoin(StationInfo &staInfo)
{
    InternalMessage *msg = ObtainMessage();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_STATION_JOIN));
    msg->AddStringMessageBody(staInfo.deviceName);
    msg->AddStringMessageBody(staInfo.bssid);
    msg->AddStringMessageBody(staInfo.ipAddr);
    SendMessage(msg);
}

void ApStateMachine::StationLeave(StationInfo &staInfo)
{
    InternalMessage *msg = ObtainMessage();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_STATION_LEAVE));
    msg->AddStringMessageBody(staInfo.deviceName);
    msg->AddStringMessageBody(staInfo.bssid);
    msg->AddStringMessageBody(staInfo.ipAddr);
    SendMessage(msg);
}

void ApStateMachine::SetHotspotConfig(const HotspotConfig &cfg)
{
    InternalMessage *msg = ObtainMessage();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_SET_HOTSPOT_CONFIG));
    msg->AddStringMessageBody(cfg.GetSsid());
    msg->AddStringMessageBody(cfg.GetPreSharedKey());
    msg->AddIntMessageBody(static_cast<int>(cfg.GetSecurityType()));
    msg->AddIntMessageBody(static_cast<int>(cfg.GetBand()));
    msg->AddIntMessageBody(cfg.GetChannel());
    msg->AddIntMessageBody(cfg.GetMaxConn());
    SendMessage(msg);
}

void ApStateMachine::AddBlockList(const StationInfo &staInfo)
{
    InternalMessage *msg = ObtainMessage();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_ADD_BLOCK_LIST));
    msg->AddStringMessageBody(staInfo.deviceName);
    msg->AddStringMessageBody(staInfo.bssid);
    msg->AddStringMessageBody(staInfo.ipAddr);
    SendMessage(msg);
}

void ApStateMachine::DelBlockList(const StationInfo &staInfo)
{
    InternalMessage *msg = ObtainMessage();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_DEL_BLOCK_LIST));
    msg->AddStringMessageBody(staInfo.deviceName);
    msg->AddStringMessageBody(staInfo.bssid);
    msg->AddStringMessageBody(staInfo.ipAddr);
    SendMessage(msg);
}

void ApStateMachine::DisconnetStation(const StationInfo &staInfo)
{
    InternalMessage *msg = ObtainMessage();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_DISCONNECT_STATION));
    msg->AddStringMessageBody(staInfo.deviceName);
    msg->AddStringMessageBody(staInfo.bssid);
    msg->AddStringMessageBody(staInfo.ipAddr);
    SendMessage(msg);
}

void ApStateMachine::UpdateHotspotConfigResult(const bool result)
{
    SendMessage(static_cast<int>(ApStatemachineEvent::CMD_UPDATE_HOTSPOTCONFIG_RESULT), result ? 1 : 0);
}

void ApStateMachine::OnQuitting()
{
    LOGI("[ApStateMachine] OnQuitting");
}

void ApStateMachine::OnHalting()
{
    LOGI("[ApStateMachine] OnHalting");
}
}  // namespace Wifi
}  // namespace OHOS