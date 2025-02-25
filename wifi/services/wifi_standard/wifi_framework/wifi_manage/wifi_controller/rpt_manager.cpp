/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#ifdef FEATURE_RPT_SUPPORT
#include "rpt_manager.h"
#include "wifi_logger.h"
#include "wifi_service_manager.h"
#include "wifi_manager.h"
#include "wifi_config_center.h"

DEFINE_WIFILOG_LABEL("RptManager");

namespace OHOS::Wifi {

RptManager::RptManager(RptManager::Role role, int id) : mid(id), curRole(role), pRptManagerMachine(nullptr)
{}

RptManager::~RptManager()
{
    WIFI_LOGI("Exit.");
    if (pRptManagerMachine != nullptr) {
        pRptManagerMachine = nullptr;
    }
}

ErrCode RptManager::InitRptManager()
{
    pRptManagerMachine = std::make_shared<RptManagerMachine>();
    if (pRptManagerMachine == nullptr) {
        WIFI_LOGE("Alloc pRptManagerMachine failed.\n");
        return WIFI_OPT_FAILED;
    }
    if (pRptManagerMachine->InitRptManagerMachine() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("InitRptManagerMachine failed.\n");
        return WIFI_OPT_FAILED;
    }
    pRptManagerMachine->RegisterCallback(mcb);
    pRptManagerMachine->SendMessage(RPT_CMD_START, static_cast<int>(curRole), mid);
    return WIFI_OPT_SUCCESS;
}

ErrCode RptManager::RegisterCallback(const RptModeCallback &callbacks)
{
    mcb = callbacks;
    return WIFI_OPT_SUCCESS;
}

std::shared_ptr<RptManagerMachine> RptManager::GetMachine()
{
    return pRptManagerMachine;
}

void RptManager::SetRole(Role role)
{
    curRole = role;
}

RptManager::Role RptManager::GetRole()
{
    return curRole;
}

bool RptManager::IsRptRunning()
{
    return pRptManagerMachine != nullptr && pRptManagerMachine->GetCurStateName() == "StartedState";
}

void RptManager::OnP2pConnectionChanged(P2pConnectedState p2pConnState)
{
    if (p2pConnState == P2pConnectedState::P2P_CONNECTED) {
        auto msg = pRptManagerMachine->CreateMessage(RPT_CMD_ON_GROUP_CREATED);
        pRptManagerMachine->SendMessage(msg);
    }
}

void RptManager::OnP2pActionResult(P2pActionCallback action, ErrCode code)
{
    if (action == P2pActionCallback::RemoveGroup && code == ErrCode::WIFI_OPT_SUCCESS) {
        auto msg = pRptManagerMachine->CreateMessage(RPT_CMD_ON_GROUP_REMOVED);
        pRptManagerMachine->SendMessage(msg);
    }
    if (action == P2pActionCallback::CreateGroup && code == ErrCode::WIFI_OPT_FAILED) {
        auto msg = pRptManagerMachine->CreateMessage(RPT_CMD_ON_CREATE_RPT_GROUP_FAILED);
        pRptManagerMachine->SendMessage(msg);
    }

    // After CreateGroup success, need to wait p2pConnState change to P2P_CONNECTED.
    if (action == P2pActionCallback::CreateGroup && code == ErrCode::WIFI_OPT_SUCCESS) {
        pRptManagerMachine->StopTimer(RPT_CMD_ON_CREATE_RPT_GROUP_FAILED);
        pRptManagerMachine->StartTimer(RPT_CMD_ON_CREATE_RPT_GROUP_FAILED，CREATE_GROUP_TIMEOUT);
    }
}

void RptManager::OnP2pClosed()
{
    auto msg = pRptManagerMachine->CreateMessage(RPT_CMD_ON_P2P_CLOSE);
    pRptManagerMachine->SendMessage(msg);
}

void RptManager::OnStationJoin(std::string mac)
{
    auto msg = pRptManagerMachine->CreateMessage(RPT_CMD_ON_STATION_JOIN);
    msg->AddStringMessageBody(mac);
    pRptManagerMachine->SendMessage(msg);
}

void RptManager::OnStationLeave(std::string mac)
{
    auto msg = pRptManagerMachine->CreateMessage(RPT_CMD_ON_STATION_LEAVE);
    msg->AddStringMessageBody(mac);
    pRptManagerMachine->SendMessage(msg);
}

void RptManager::AddBlock(const std::string &mac)
{
    auto msg = pRptManagerMachine->CreateMessage(RPT_CMD_ADD_BLOCK);
    msg->AddStringMessageBody(mac);
    pRptManagerMachine->SendMessage(msg);
}

void RptManager::DelBlock(const std::string &mac)
{
    auto msg = pRptManagerMachine->CreateMessage(RPT_CMD_DEL_BLOCK);
    msg->AddStringMessageBody(mac);
    pRptManagerMachine->SendMessage(msg);
}

ErrCode RptManager::GetStationList(std::vector<StationInfo> &result)
{
#ifndef FEATURE_P2P_SUPPORT
    return WIFI_OPT_P2P_NOT_OPENED;
#else
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->GetRptStationsList(result);
#endif
}

std::string RptManager::GetRptIfaceName()
{
#ifndef FEATURE_P2P_SUPPORT
    return "";
#else
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return "";
    }
    WifiP2pGroupInfo group;
    pService->GetCurrentGroup(group);
    return group.GetInterface();
#endif
}

} // namespace OHOS::Wifi
#endif