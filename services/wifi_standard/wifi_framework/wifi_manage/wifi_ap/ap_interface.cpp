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
#include "ap_interface.h"
#include "ap_config_use.h"
#include "ap_monitor.h"
#include "ap_service.h"
#include "ap_state_machine.h"
#include "wifi_ap_nat_manager.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_AP_ApInterface"
namespace OHOS {
namespace Wifi {
ApInterface::ApInterface()
{
    ApService::GetInstance();
    ApMonitor::GetInstance();
    ApStateMachine::GetInstance();
    WifiApDhcpInterface::GetInstance();
    WifiApNatManager::GetInstance();
    ApConfigUse::GetInstance();
}

ApInterface::~ApInterface()
{
    ApConfigUse::DeleteInstance();
    WifiApNatManager::DeleteInstance();
    WifiApDhcpInterface::DeleteInstance();
    ApStateMachine::DeleteInstance();
    ApMonitor::DeleteInstance();
    ApService::DeleteInstance();
}

int ApInterface::Init(WifiMessageQueue<WifiResponseMsgInfo> *mqUp)
{
    return ApService::GetInstance().Init(mqUp);
}

int ApInterface::PushMsg(WifiRequestMsgInfo *msg)
{
    return ApService::GetInstance().PushMsg(msg);
}

int ApInterface::UnInit(void)
{
    return ApService::GetInstance().UnInit();
}

DECLARE_INIT_SERVICE(ApInterface);
}  // namespace Wifi
}  // namespace OHOS