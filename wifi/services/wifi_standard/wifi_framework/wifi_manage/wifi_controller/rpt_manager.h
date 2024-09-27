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

#ifndef OHOS_RPT_MANAGER_H
#define OHOS_RPT_MANAGER_H

#ifdef FEATURE_RPT_SUPPORT
#include <functional>
#include <string>
#include "wifi_errcode.h"
#include "rpt_manager_state_machine.h"
#include "rpt_interface.h"

namespace OHOS::Wifi {
class RptManager : public RptInterface {
public:
    enum class Role {
        ROLE_UNKNOW = -1,
        ROLE_RPT = 0,
        ROLE_HAS_REMOVED = 1,
    };

    ErrCode RegisterCallback(const RptModeCallback &callbacks);
    explicit RptManager(RptManager::Role role, int id);
    ~RptManager() override;
    ErrCode InitRptManager();
    void SetRole(Role role);
    Role GetRole();
    std::shared_ptr<RptManagerMachine> GetMachine();
    int mid;

    bool IsRptRunning() override;
    ErrCode GetStationList(std::vector<StationInfo> &result) override;
    std::string GetRptIfaceName() override;
    void AddBlock(const std::string &mac) override;
    void DelBlock(const std::string &mac) override;

    void OnP2pActionResult(P2pActionCallback action, ErrCode code) override;
    void OnP2pConnectionChanged(P2pConnectedState p2pConnState) override;
    void OnStationJoin(std::string mac) override;
    void OnStationLeave(std::string mac) override;
    void OnP2pClosed();
private:
    RptManager::Role curRole;
    RptModeCallback mcb;
    std::shared_ptr<RptManagerMachine> pRptManagerMachine;
};
} // namespace OHOS::Wifi
#endif
#endif