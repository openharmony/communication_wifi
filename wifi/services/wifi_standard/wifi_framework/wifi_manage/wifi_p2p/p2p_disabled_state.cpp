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
#include "p2p_disabled_state.h"
#include "wifi_config_center.h"
#include "wifi_p2p_hal_interface.h"
#include "p2p_state_machine.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_P2P_LABEL("P2pDisabledState");

namespace OHOS {
namespace Wifi {
P2pDisabledState::P2pDisabledState(P2pStateMachine &stateMachine, WifiP2pGroupManager &groupMgr,
    WifiP2pDeviceManager &deviceMgr, WifiP2pServiceManager &svrMgr)
    : State("P2pDisabledState"),
      p2pStateMachine(stateMachine),
      groupManager(groupMgr),
      deviceManager(deviceMgr),
      serviceManager(svrMgr),
      p2pSmInitFlag(false)
{}
void P2pDisabledState::GoInState()
{
    WIFI_LOGI("             GoInState");
    if (p2pSmInitFlag) {
        p2pStateMachine.ClearAllP2pServiceCallbacks();
        p2pStateMachine.groupManager.ClearAll();
        p2pStateMachine.groupManager.StashGroups();
        p2pStateMachine.StopP2pDhcpClient();
        p2pStateMachine.StopDhcpServer();
        if (p2pStateMachine.pDhcpResultNotify != nullptr) {
            delete p2pStateMachine.pDhcpResultNotify;
            p2pStateMachine.pDhcpResultNotify = nullptr;
        }
    }
    p2pStateMachine.serviceManager.ClearAll();
    deviceManager.ClearAll();
    serviceManager.ClearAll();
    p2pSmInitFlag = true;
}

void P2pDisabledState::GoOutState()
{
    WIFI_LOGI("             GoOutState");
}

bool P2pDisabledState::ExecuteStateMsg(InternalMessagePtr msg)
{
    switch (static_cast<P2P_STATE_MACHINE_CMD>(msg->GetMessageName())) {
        case P2P_STATE_MACHINE_CMD::CMD_P2P_ENABLE: {
            /* WifiP2PHalInterface::createP2pInterface */
            p2pStateMachine.p2pIface = WifiConfigCenter::GetInstance().GetP2pIfaceName();
            p2pStateMachine.RegisterEventHandler();
            p2pStateMachine.p2pMonitor.MonitorBegins(p2pStateMachine.p2pIface);
            p2pStateMachine.StartTimer(
                static_cast<int>(P2P_STATE_MACHINE_CMD::ENABLE_P2P_TIMED_OUT), ENABLE_P2P_TIMED_OUT__INTERVAL);
            bool hasPersisentGroup = p2pStateMachine.HasPersisentGroup();
            WIFI_LOGE("has persisen group %{public}d", hasPersisentGroup);
            if (WifiP2PHalInterface::GetInstance().StartP2p(WifiConfigCenter::GetInstance().GetP2pIfaceName(),
                hasPersisentGroup) == WifiErrorNo::WIFI_HAL_OPT_OK) {
                SetVendorFeatures();
                p2pStateMachine.SwitchState(&p2pStateMachine.p2pEnablingState);
            } else {
                WIFI_LOGE("StartP2p failed.");
                p2pStateMachine.SwitchState(&p2pStateMachine.p2pEnablingState);
                p2pStateMachine.SendMessage(static_cast<int>(P2P_STATE_MACHINE_CMD::CMD_P2P_DISABLE));
            }

            break;
        }

        default:
            return NOT_EXECUTED;
    }
    return EXECUTED;
}

void P2pDisabledState::SetVendorFeatures() const
{
    P2pVendorConfig p2pVendorCfg;
    int ret = WifiSettings::GetInstance().GetP2pVendorConfig(p2pVendorCfg);
    if (ret < 0) {
        WIFI_LOGW("Failed to obtain P2pVendorConfig information.");
    }
#ifdef P2P_RANDOM_MAC_ADDR
    p2pVendorCfg.SetRandomMacSupport(true);
    WifiSettings::GetInstance().SetP2pVendorConfig(p2pVendorCfg);
    WifiSettings::GetInstance().SyncP2pVendorConfig();
#endif
    WIFI_LOGI("P2pVendorConfig random mac is %{public}s", p2pVendorCfg.GetRandomMacSupport() ? "true" : "false");
    WifiP2PHalInterface::GetInstance().SetRandomMacAddr(p2pVendorCfg.GetRandomMacSupport());
}
} // namespace Wifi
} // namespace OHOS