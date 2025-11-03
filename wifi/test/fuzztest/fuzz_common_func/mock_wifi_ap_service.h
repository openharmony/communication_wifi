/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_MOCK_AP_SERVICE_H
#define OHOS_MOCK_AP_SERVICE_H

#include "ap_root_state.h"
#include "ap_idle_state.h"
#include "ap_started_state.h"
#include "ap_service.h"
#include "ap_state_machine.h"
#include "ap_monitor.h"
#include "ap_config_use.h"
#include "ap_stations_manager.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {

class ApStateMachine;
class MockApRootState : public ApRootState {
public:
    void GoInState();
    void GoOutState();
    bool ExecuteStateMsg(InternalMessagePtr msg);
}; /* ApRootState */

class MockApIdleState : public ApIdleState {
public:
    explicit MockApIdleState(ApStateMachine &apStateMachine) : ApIdleState(apStateMachine)
    {}
    void GoInState();
    void GoOutState();
    bool ExecuteStateMsg(InternalMessagePtr msg);
};

class MockApStartedState : public ApStartedState {
public:
    MockApStartedState(ApStateMachine &apStateMachine, ApMonitor &apMonitor)
        : ApStartedState(apStateMachine, apMonitor)
    {}
    void GoInState();
    void GoOutState();
    bool ExecuteStateMsg(InternalMessagePtr msg);
};

class MockApService : public ApService {
public:
    explicit MockApService(ApStateMachine &apStateMachine, ApStartedState &apStartedState)
        : ApService(apStateMachine, apStartedState)
    {}
    ErrCode EnableHotspot();
    ErrCode DisableHotspot();
    ErrCode AddBlockList(const StationInfo &stationInfo);
    ErrCode DelBlockList(const StationInfo &stationInfo);
    ErrCode SetHotspotConfig(const HotspotConfig &hotspotConfig);
    ErrCode DisconnetStation(const StationInfo &stationInfo);
    ErrCode RegisterApServiceCallbacks(const IApServiceCallbacks &callbacks);
};

class MockApStateMachine : public ApStateMachine {
public:
    MockApStateMachine(ApStationsManager &apStationsManager, ApRootState &apRootState, ApIdleState &apIdleState,
        ApStartedState &apStartedState, ApMonitor &apMonitor)
        : ApStateMachine(apStationsManager, apRootState, apIdleState, apStartedState, apMonitor)
    {}
    ~MockApStateMachine()
    {}
    void SwitchState(State *targetState);
    void CreateMessage();
    void SendMessage(int what);
    void SendMessage(int what, int arg1);
    void SendMessage(int what, int arg1, int arg2);
    void SendMessage(InternalMessagePtr msg);
    void StartTimer(int timerName, int64_t interval, MsgLogLevel logLevel = MsgLogLevel::LOG_D);
    void StopTimer(int timerName);
};

class MockApMonitor : public ApMonitor {
public:
    void StationChangeEvent(StationInfo &staInfo, const int event);
    void StartMonitor();
    void StopMonitor();
};

class MockApConfigUse : public ApConfigUse {
public:
    void UpdateApChannelConfig(HotspotConfig &apConfig);
    void JudgeConflictBand(HotspotConfig &apConfig);
    int GetBestChannelFor2G();
    int GetBestChannelFor5G();
    std::vector<int> GetChannelFromDrvOrXmlByBand(const BandType &bandType);
    void FilterIndoorChannel(std::vector<int> &channels);
    void Filter165Channel(std::vector<int> &channels);
    void JudgeDbacWithP2p(HotspotConfig &apConfig);
    std::set<int> GetIndoorChanByCountryCode(const std::string &countryCode);
    std::vector<int> GetPreferredChannelByBand(const BandType &bandType);
};

class MockApStationsManager : public ApStationsManager {
public:
    bool AddBlockList(const StationInfo &staInfo);
    bool DelBlockList(const StationInfo &staInfo);
    bool EnableAllBlockList();
    void StationLeave(const std::string &mac);
    void StationJoin(const StationInfo &staInfo);
    bool DisConnectStation(const StationInfo &staInfo);
    std::vector<std::string> GetAllConnectedStations();
};

class MockPendant {
public:
    MockPendant()
        : mockApRootState(),
          mockApIdleState(mockApStateMachine),
          mockApStartedState(mockApStateMachine, mockApMonitor),
          mockApService(mockApStateMachine, mockApStartedState),
          mockApStateMachine(
              mockApStationsManager, mockApRootState, mockApIdleState, mockApStartedState, mockApMonitor),
          mockApConfigUse(),
          mockApStationsManager()
    {}

public:
    MockApRootState &GetMockApRootState()
    {
        return mockApRootState;
    }

    MockApIdleState &GetMockApIdleState()
    {
        return mockApIdleState;
    }

    MockApStartedState &GetMockApStartedState()
    {
        return mockApStartedState;
    }

    MockApService &GetMockApService()
    {
        return mockApService;
    }

    MockApStateMachine &GetMockApStateMachine()
    {
        return mockApStateMachine;
    }

    MockApMonitor &GetMockApMonitor()
    {
        return mockApMonitor;
    }

    MockApConfigUse &GetMockApConfigUse()
    {
        return mockApConfigUse;
    }

    MockApStationsManager &GetMockApStationsManager()
    {
        return mockApStationsManager;
    }

private:
    MockApRootState mockApRootState;
    MockApIdleState mockApIdleState;
    MockApStartedState mockApStartedState;

    MockApService mockApService;
    MockApStateMachine mockApStateMachine;
    MockApMonitor mockApMonitor;

    MockApConfigUse mockApConfigUse;
    MockApStationsManager mockApStationsManager;
};
} /* namespace Wifi */
} /* namespace OHOS */
#endif
