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
#include "ap_stations_manager.h"
#include "ap_monitor.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"
#include "wifi_net_agent.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiApStateMachine");

namespace OHOS {
namespace Wifi {
ApStateMachine::ApStateMachine(ApStationsManager &apStationsManager, ApRootState &apRootState, ApIdleState &apIdleState,
    ApStartedState &apStartedState, ApMonitor &apMonitor, int id)
    : StateMachine("ApStateMachine"),
      m_ApStationsManager(apStationsManager),
      m_ApRootState(apRootState),
      m_ApIdleState(apIdleState),
      m_ApStartedState(apStartedState),
      m_ApMonitor(apMonitor),
      m_id(id)
{
    Init();
}

ApStateMachine::~ApStateMachine()
{
#ifndef WIFI_DHCP_DISABLED
    StopDhcpServer();
    StopHandlerThread();
#endif
    {
        std::unique_lock<std::shared_mutex> lock(m_callbackMutex);
        m_callbacks.clear();
    }
}

void ApStateMachine::Init()
{
    if (!InitialStateMachine("ApStateMachine")) {
        WIFI_LOGE("Ap StateMachine Initialize failed.");
        return;
    }
    StatePlus(&m_ApRootState, nullptr);
    StatePlus(&m_ApIdleState, &m_ApRootState);
    StatePlus(&m_ApStartedState, &m_ApRootState);
    SetFirstState(&m_ApStartedState);
    m_iface = WifiConfigCenter::GetInstance().GetApIfaceName();
    StartStateMachine();
}

void ApStateMachine::OnApStateChange(ApState state)
{
    if (WifiConfigCenter::GetInstance().SetHotspotState(static_cast<int>(state), m_id)) {
        WIFI_LOGE("WifiSetting change state fail.");
    }

    if (state == ApState::AP_STATE_IDLE || state == ApState::AP_STATE_STARTED || state == ApState::AP_STATE_STARTING ||
            state == ApState::AP_STATE_CLOSING) {
        std::unique_lock<std::shared_mutex> lock(m_callbackMutex);
        for (const auto &callBackItem : m_callbacks) {
            if (callBackItem.second.OnApStateChangedEvent != nullptr) {
                callBackItem.second.OnApStateChangedEvent(state, m_id, static_cast<int>(hotspotMode_));
            }
        }
    }
    return;
}

ErrCode ApStateMachine::RegisterApServiceCallbacks(const IApServiceCallbacks &callback)
{
    WIFI_LOGI("RegisterApServiceCallbacks, callback module name: %{public}s", callback.callbackModuleName.c_str());
    std::unique_lock<std::shared_mutex> lock(m_callbackMutex);
    m_callbacks.insert_or_assign(callback.callbackModuleName, callback);
    return ErrCode::WIFI_OPT_SUCCESS;
}

void ApStateMachine::BroadCastStationChange(const StationInfo &staInfo, ApStatemachineEvent act)
{
    std::shared_lock<std::shared_mutex> lock(m_callbackMutex);
    switch (act) {
        case ApStatemachineEvent::CMD_STATION_JOIN:
            for (const auto &callBackItem : m_callbacks) {
                if (callBackItem.second.OnHotspotStaJoinEvent != nullptr) {
                    callBackItem.second.OnHotspotStaJoinEvent(staInfo, m_id);
                }
            }
            break;
        case ApStatemachineEvent::CMD_STATION_LEAVE:
            for (const auto &callBackItem : m_callbacks) {
                if (callBackItem.second.OnHotspotStaLeaveEvent != nullptr) {
                    callBackItem.second.OnHotspotStaLeaveEvent(staInfo, m_id);
                }
            }
            break;
        default:
            WIFI_LOGW("error BroadCastStation msg %{public}d.", act);
            break;
    }
}

bool ApStateMachine::StartDhcpServer(const std::string &ipAddress, const int32_t &leaseTime)
{
    WIFI_LOGI("Enter:StartDhcpServer leaseTime:%{public}d", leaseTime);
#ifndef WIFI_DHCP_DISABLED
    Ipv4Address ipv4(Ipv4Address::invalidInetAddress);
    Ipv6Address ipv6(Ipv6Address::INVALID_INET6_ADDRESS);
    HotspotConfig hotspotConfig;
    WifiSettings::GetInstance().GetHotspotConfig(hotspotConfig, m_id);
    std::string ifaceName = WifiConfigCenter::GetInstance().GetApIfaceName();
    if (!m_DhcpdInterface.StartDhcpServerFromInterface(ifaceName, ipv4, ipv6, ipAddress, true, leaseTime)) {
        WIFI_LOGE("start dhcpd fail.");
        return false;
    }
    WifiNetAgent::GetInstance().AddRoute(ifaceName, ipv4.GetAddressWithString(), ipv4.GetAddressPrefixLength());
    hotspotConfig.SetIpAddress(ipv4.GetAddressWithString());
    WifiSettings::GetInstance().SetHotspotConfig(hotspotConfig, m_id);
    WIFI_LOGI("Start dhcp server for AP finished.");
    return true;
#else
    return true;
#endif
}

bool ApStateMachine::StopDhcpServer()
{
#ifndef WIFI_DHCP_DISABLED
    WIFI_LOGI("Enter:StopDhcpServer");
    std::string ifaceName = WifiConfigCenter::GetInstance().GetApIfaceName();
    if (!m_DhcpdInterface.StopDhcp(ifaceName)) {
        WIFI_LOGE("Close dhcpd fail.");
        return false;
    }
    return true;
#else
    return true;
#endif
}

bool ApStateMachine::GetConnectedStationInfo(std::map<std::string, StationInfo> &result)
{
#ifndef WIFI_DHCP_DISABLED
    std::string ifaceName = WifiConfigCenter::GetInstance().GetApIfaceName();
    return m_DhcpdInterface.GetConnectedStationInfo(ifaceName, result);
#else
    return true;
#endif
}

void ApStateMachine::RegisterEventHandler()
{
    auto handler = [this](int msgName, int param1, int param2, const std::any &messageObj) {
        this->SendMessage(msgName, param1, param2, messageObj);
    };

    m_ApMonitor.RegisterHandler(
        m_iface, [=](ApStatemachineEvent msgName, int param1, int param2, const std::any &messageObj) {
            handler(static_cast<int>(msgName), param1, param2, messageObj);
        });

    m_ApStationsManager.RegisterEventHandler(
        [this](const StationInfo &staInfo, ApStatemachineEvent act) { this->BroadCastStationChange(staInfo, act); });
}

ErrCode ApStateMachine::GetHotspotMode(HotspotMode &mode)
{
    mode = hotspotMode_;
    return WIFI_OPT_SUCCESS;
}

ErrCode ApStateMachine::SetHotspotMode(const HotspotMode &mode)
{
    hotspotMode_ = mode;
    WIFI_LOGI("%{public}s, mode=%{public}d", __func__, static_cast<int>(mode));
    return WIFI_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS
