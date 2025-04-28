/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include "ap_monitor.h"
#include <unistd.h>
#include <functional>

#include "ap_stations_manager.h"
#include "internal_message.h"
#include "wifi_config_center.h"
#include "ap_state_machine.h"
#include "wifi_ap_hal_interface.h"
#include "wifi_logger.h"
#include "dhcpd_interface.h"
#include "wifi_common_util.h"
#include "wifi_hisysevent.h"

#define LESS_INT_MAX_NUM 9

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiApMonitor");

namespace OHOS {
namespace Wifi {
ApMonitor::ApMonitor(int id) : m_id(id)
{}

ApMonitor::~ApMonitor()
{
    StopMonitor();
}

void ApMonitor::OnStaJoinOrLeave(const WifiHalApConnectionNofify &cbInfo)
{
    StationInfo info;
    info.bssid = cbInfo.mac;
    info.bssidType = REAL_DEVICE_ADDRESS;
    info.deviceName = GETTING_INFO;
    info.ipAddr = GETTING_INFO;
    int event = cbInfo.type;
    std::any anySta = info;
    WIFI_LOGI("StationChangeEvent  event: [%{public}d(join=105)] %{public}s . %{private}s . %{private}s.,",
        event,
        info.deviceName.c_str(),
        MacAnonymize(info.bssid).c_str(),
        IpAnonymize(info.ipAddr).c_str());
    SendMessage(m_selectIfacName, ApStatemachineEvent::CMD_ASSOCIATED_STATIONS_CHANGED, event, 0, anySta);
}

void ApMonitor::OnHotspotStateEvent(int state) const
{
    WIFI_LOGI("update HotspotConfig result is [%{public}d].", state);
    if (state == HAL_CBK_CMD_AP_DISABLE) {
        SendMessage(m_selectIfacName, ApStatemachineEvent::CMD_UPDATE_HOTSPOTCONFIG_RESULT, 0, 0, 0);
    } else if (state == HAL_CBK_CMD_AP_ENABLE) {
        SendMessage(m_selectIfacName, ApStatemachineEvent::CMD_UPDATE_HOTSPOTCONFIG_RESULT, 1, 0, 0);
    } else if (state == HAL_CBK_CMD_AP_STA_PSK_MISMATCH_EVENT) {
        WriteSoftApConnectFailHiSysEvent(AP_STA_PSK_MISMATCH_CNT);
    } else {
        WIFI_LOGE("Error: Incorrect status code [%{public}d].", state);
    }
}

void ApMonitor::WpaEventApChannelSwitch(int freq) const
{
    WIFI_LOGI("%{public}s, freq = %{public}d", __func__, freq);
    SendMessage(m_selectIfacName, ApStatemachineEvent::CMD_HOTSPOT_CHANNEL_CHANGED, freq, 0, 0);
}

void ApMonitor::WpaEventApNotifyCallBack(const std::string &notifyParam) const
{
    if (notifyParam.empty()) {
        WIFI_LOGE("%{public}s notifyParam is empty", __func__);
        return;
    }
    std::string::size_type freqPos = 0;
    if ((freqPos = notifyParam.find("freq=")) == std::string::npos) {
        WIFI_LOGE("csa channel switch notifyParam not find frequency!");
        return;
    }
    std::string data = notifyParam.substr(freqPos + strlen("freq="));
    if (data.size() > LESS_INT_MAX_NUM) {
        WIFI_LOGE("%{public}s notifyParam is error", __func__);
        return;
    }
    int freq = CheckDataLegal(data);
    WpaEventApChannelSwitch(freq);
    return;
}

void ApMonitor::StartMonitor()
{
    using namespace std::placeholders;
    IWifiApMonitorEventCallback wifiApEventCallback = {
        [this](const WifiHalApConnectionNofify &cbInfo) { this->OnStaJoinOrLeave(cbInfo); },
        [this](int state) { this->OnHotspotStateEvent(state); },
        [this](const std::string &notifyParam) { this->WpaEventApNotifyCallBack(notifyParam); },
    };
    WifiApHalInterface::GetInstance().RegisterApEvent(wifiApEventCallback, m_id);

    std::string iface = WifiConfigCenter::GetInstance().GetApIfaceName();
    m_selectIfacName = iface;
    m_setMonitorIface.insert(iface);
}

void ApMonitor::SendMessage(
    const std::string &iface, ApStatemachineEvent msgName, int param1, int param2, const std::any &messageObj) const
{
    if (m_setMonitorIface.count(iface) > 0) {
        auto iter = m_mapHandler.find(iface);
        if (iter != m_mapHandler.end()) {
            WIFI_LOGI("Ap Monitor event: iface [%{public}s], eventID [%{public}d].",
                iface.c_str(),
                static_cast<int>(msgName));
            const auto &handler = iter->second;
            handler(msgName, param1, param2, messageObj);
        } else {
            WIFI_LOGE("iface: %{public}s is not register handler.", iface.c_str());
        }
    } else {
        WIFI_LOGW("iface: %{public}s is not monitor.", iface.c_str());
    }
}

void ApMonitor::StopMonitor()
{
    IWifiApMonitorEventCallback wifiApEventCallback = {};
    WifiApHalInterface::GetInstance().RegisterApEvent(wifiApEventCallback, m_id);
}

void ApMonitor::RegisterHandler(const std::string &iface, const std::function<HandlerApMethod> &handler)
{
    auto iter = m_mapHandler.find(iface);
    if (iter != m_mapHandler.end()) {
        iter->second = handler;
    } else {
        m_mapHandler.emplace(std::make_pair(iface, handler));
    }
}

void ApMonitor::UnregisterHandler(const std::string &iface)
{
    auto iter = m_mapHandler.find(iface);
    if (iter != m_mapHandler.end()) {
        m_mapHandler.erase(iter);
    }
}
}  // namespace Wifi
}  // namespace OHOS
