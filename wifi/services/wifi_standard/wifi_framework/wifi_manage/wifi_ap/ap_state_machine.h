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
#ifndef OHOS_AP_STATE_MACHINE_H
#define OHOS_AP_STATE_MACHINE_H

#include "state_machine.h"
#include <vector>
#include <shared_mutex>
#include "dhcpd_interface.h"
#include "i_ap_service.h"
#include "ap_root_state.h"
#include "ap_idle_state.h"
#include "ap_started_state.h"

namespace OHOS {
namespace Wifi {
class ApConfigUse;
class ApStationsManager;
class ApMonitor;
class ApStateMachine : public StateMachine {
    friend class ApRootState;
    friend class ApIdleState;
    friend class ApStartedState;
    FRIEND_GTEST(ApStateMachine);

public:
    /**
     * @Description  construction method.
     * @param None
     * @return None
     */
    ApStateMachine(ApStationsManager &apStationsManager, ApRootState &apRootState, ApIdleState &apIdleState,
        ApStartedState &apStartedState, ApMonitor &apMonitor, int id = 0);

    /**
     * @Description  destructor method.
     * @param None
     * @return None
     */
    virtual ~ApStateMachine();

    /**
     * @Description  Reporting New State.
     * @param state - the state.
     * @return None
     */
    void OnApStateChange(ApState state);

    /**
     * @Description  Reporting station change msg.
     * @param staInfo - station information
     * @param act - action event
     * @return None
     */
    void BroadCastStationChange(const StationInfo &staInfo, ApStatemachineEvent act);

    /**
     * @Description  Register callback list to reporting msg.
     * @param callbacks - callback list
     * @return None
     */
    ErrCode RegisterApServiceCallbacks(const IApServiceCallbacks &callbacks);

    /**
     * @Description  Apmonitor Initialization Function.
     * @param None
     * @return None
     */
    void Init();

    /**
     * @Description  Disable dhcp server.
     * @param None
     * @return true - success
     * @return false - fail
     */
    bool StopDhcpServer();

    /**
     * @Description  Enable dhcp server.
     * @param ipAddress - HotspotConfig dhcp server address
     * @param leaseTime - HotspotConfig dhcp lease time
     * @return true - success
     * @return false - fail
     */
    bool StartDhcpServer(const std::string &ipAddress, const int32_t &leaseTime);

    /**
     * @Description  Get the Station List object.
     * @param result - Current connected station info
     * @return true - success
     * @return false - fail
     */
    bool GetConnectedStationInfo(std::map<std::string, StationInfo> &result);

private:
    DISALLOW_COPY_AND_ASSIGN(ApStateMachine);

    /**
     * @Description  Register event handler to apmonitor.
     * @param None
     * @return None
     */
    virtual void RegisterEventHandler();

private:
    std::string m_iface;
    std::shared_mutex m_callbackMutex;
    std::map<std::string, IApServiceCallbacks> m_callbacks;
    /* STA Manager */
    ApStationsManager &m_ApStationsManager;
    /* The reference of RootState */
    ApRootState &m_ApRootState;
    /* The reference of IdleState */
    ApIdleState &m_ApIdleState;
    /* The reference of StartedState */
    ApStartedState &m_ApStartedState;
    ApMonitor &m_ApMonitor;

    DhcpdInterface m_DhcpdInterface;
    int m_id;
}; /* ApStateMachine */
}  // namespace Wifi
}  // namespace OHOS

#endif