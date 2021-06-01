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

#include "ap_define.h"
#include "ap_idle_state.h"
#include "ap_root_state.h"
#include "ap_started_state.h"
#include "ap_stations_manager.h"
#include "state_machine.h"

namespace OHOS {
namespace Wifi {
class ApStateMachine : public StateMachine {
    friend class ApRootState;
    friend class ApIdleState;
    friend class ApStartedState;

public:
    /**
     * @Description  Obtains a single g_instance.
     * @param None
     * @return The reference of singleton objects
     */
    static ApStateMachine &GetInstance();
    /**
     * @Description  Delete the single g_instance.
     * @param None
     * @return None
     */
    static void DeleteInstance();
    /**
     * @Description  Wrap and send messages.
     * @param staInfo - joined sta info
     * @return None
     */
    void StationJoin(StationInfo &staInfo);
    /**
     * @Description  Wrap and send messages.
     * @param staInfo - left sta info
     * @return None
     */
    void StationLeave(StationInfo &staInfo);
    /**
     * @Description  Wrap and send messages.
     * @param cfg - ap config info
     * @return None
     */
    void SetHotspotConfig(const HotspotConfig &cfg);
    /**
     * @Description  Wrap and send messages.
     * @param stationInfo - sta info which added to blocklist
     * @return None
     */
    void AddBlockList(const StationInfo &stationInfo);
    /**
     * @Description  Wrap and send messages.
     * @param stationInfo - sta info which delete from blocklist
     * @return None
     */
    void DelBlockList(const StationInfo &stationInfo);
    /**
     * @Description  Wrap and send messages.
     * @param stationInfo - sta info to be disconnect
     * @return None
     */
    void DisconnetStation(const StationInfo &stationInfo);
    /**
     * @Description  Send messages.
     * @param result - hostapd started or closed
     * @return None
     */
    void UpdateHotspotConfigResult(const bool result);

private:
    ApStateMachine();
    virtual ~ApStateMachine();
    void Init();
    virtual void OnQuitting() override;
    virtual void OnHalting() override;

    DISALLOW_COPY_AND_ASSIGN(ApStateMachine);

private:
    static ApStateMachine *g_instance;

    /* STA Manager */
    ApStationsManager mApStationsManager;
    /* The reference of RootState */
    ApRootState mApRootState;
    /* The reference of IdleState */
    ApIdleState mApIdleState;
    /* The reference of StartedState */
    ApStartedState mApStartedState;
}; /* ApStateMachine */
}  // namespace Wifi
}  // namespace OHOS

#endif