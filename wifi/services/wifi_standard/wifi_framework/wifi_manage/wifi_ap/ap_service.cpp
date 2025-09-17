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

#include "ap_service.h"
#include <unistd.h>
#include "ap_state_machine.h"
#include "wifi_logger.h"
#include "wifi_channel_helper.h"
#include "wifi_config_center.h"
#include "wifi_ap_hal_interface.h"
#include "wifi_country_code_manager.h"
#include "wifi_global_func.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiApService");
namespace OHOS {
namespace Wifi {
const int START_HOTSPOT_TIMEOUT = 5 * 1000;

ApService::ApService(ApStateMachine &apStateMachine, ApStartedState &apStartedState, int id)
    : m_ApStateMachine(apStateMachine), apStartedState_(apStartedState), m_id(id)
{}

ApService::~ApService()
{}

ErrCode ApService::EnableHotspot()
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);

    // notification of registration country code change
    std::string moduleName = "ApService_" + std::to_string(m_id);
    m_apObserver = std::make_shared<WifiCountryCodeChangeObserver>(moduleName, m_ApStateMachine);
    WifiCountryCodeManager::GetInstance().RegisterWifiCountryCodeChangeListener(m_apObserver);
    m_ApStateMachine.OnApStateChange(ApState::AP_STATE_STARTING);
    m_ApStateMachine.RegisterEventHandler();
    apStartedState_.StartMonitor();
#ifdef SUPPORT_LOCAL_RANDOM_MAC
    apStartedState_.SetRandomMac();
#endif
#ifndef OHOS_ARCH_LITE
    if (enhanceService_ != nullptr) {
        apStartedState_.SetEnhanceService(enhanceService_);
    } else {
        WIFI_LOGI("EnableHotspot enhanceService_nullptr");
    }
#endif
    do {
        if (!(apStartedState_.SetCountry())) {
            break;
        }
        if (!(apStartedState_.StartAp())) {
            WIFI_LOGE("enter ApstartedState is failed.");
            break;
        }
        WIFI_LOGI("StartAP is ok.");
        if (!(apStartedState_.SetConfig())) {
            WIFI_LOGE("wifi_settings.hotspotconfig is error.");
            break;
        }
        m_ApStateMachine.SendMessage(static_cast<int>(ApStatemachineEvent::CMD_START_HOTSPOT));
        return ErrCode::WIFI_OPT_SUCCESS;
    } while (0);
    WIFI_LOGI("Ap disabled, set softap toggled false");
    WifiCountryCodeManager::GetInstance()
        .UnregisterWifiCountryCodeChangeListener(m_apObserver);
    WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
    if (!(apStartedState_.StopAp())) {
        WIFI_LOGE("StopAp not going well.");
    }
    m_ApStateMachine.SendMessage(static_cast<int>(ApStatemachineEvent::CMD_STOP_HOTSPOT));
    m_ApStateMachine.StartTimer(static_cast<int>(ApStatemachineEvent::CMD_START_HOTSPOT_TIMEOUT),
        START_HOTSPOT_TIMEOUT);
    return WIFI_OPT_FAILED;
}

ErrCode ApService::DisableHotspot() const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);

    // deregistration country code change notification
    WifiCountryCodeManager::GetInstance()
        .UnregisterWifiCountryCodeChangeListener(m_apObserver);

    m_ApStateMachine.SendMessage(static_cast<int>(ApStatemachineEvent::CMD_STOP_HOTSPOT));
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::SetHotspotConfig(const HotspotConfig &cfg) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    InternalMessagePtr msg = m_ApStateMachine.CreateMessage();
    if (msg == nullptr) {
        return ErrCode::WIFI_OPT_FAILED;
    }
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_SET_HOTSPOT_CONFIG));
    msg->AddStringMessageBody(cfg.GetSsid());
    msg->AddStringMessageBody(cfg.GetPreSharedKey());
    msg->AddIntMessageBody(static_cast<int>(cfg.GetSecurityType()));
    msg->AddIntMessageBody(static_cast<int>(cfg.GetBand()));
    msg->AddIntMessageBody(cfg.GetChannel());
    msg->AddIntMessageBody(cfg.GetBandWidth());
    msg->AddIntMessageBody(cfg.GetMaxConn());
    msg->AddStringMessageBody(cfg.GetIpAddress());
    msg->AddIntMessageBody(cfg.GetLeaseTime());
    m_ApStateMachine.SendMessage(msg);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::SetHotspotIdleTimeout(int time) const
{
    WIFI_LOGI("SetHotspotIdleTimeout");
    InternalMessagePtr msg = m_ApStateMachine.CreateMessage();
    if (msg == nullptr) {
        return ErrCode::WIFI_OPT_FAILED;
    }
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_SET_IDLE_TIMEOUT));
    msg->AddIntMessageBody(time);
    m_ApStateMachine.SendMessage(msg);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::AddBlockList(const StationInfo &stationInfo) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    InternalMessagePtr msg = m_ApStateMachine.CreateMessage();
    if (msg == nullptr) {
        return ErrCode::WIFI_OPT_FAILED;
    }
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_ADD_BLOCK_LIST));
    msg->AddStringMessageBody(stationInfo.deviceName);
    msg->AddStringMessageBody(stationInfo.bssid);
    msg->AddStringMessageBody(stationInfo.ipAddr);
    m_ApStateMachine.SendMessage(msg);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::DelBlockList(const StationInfo &stationInfo) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    InternalMessagePtr msg = m_ApStateMachine.CreateMessage();
    if (msg == nullptr) {
        return ErrCode::WIFI_OPT_FAILED;
    }
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_DEL_BLOCK_LIST));
    msg->AddStringMessageBody(stationInfo.deviceName);
    msg->AddStringMessageBody(stationInfo.bssid);
    msg->AddStringMessageBody(stationInfo.ipAddr);
    m_ApStateMachine.SendMessage(msg);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::DisconnetStation(const StationInfo &stationInfo) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    InternalMessagePtr msg = m_ApStateMachine.CreateMessage();
    if (msg == nullptr) {
        return ErrCode::WIFI_OPT_FAILED;
    }
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_DISCONNECT_STATION));
    msg->AddStringMessageBody(stationInfo.deviceName);
    msg->AddStringMessageBody(stationInfo.bssid);
    msg->AddStringMessageBody(stationInfo.ipAddr);
    m_ApStateMachine.SendMessage(msg);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::GetStationList(std::vector<StationInfo> &result) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    WifiConfigCenter::GetInstance().GetStationList(result);
    if (result.empty()) {
        WIFI_LOGW("GetStationList is empty.");
        return ErrCode::WIFI_OPT_SUCCESS;
    }
    // get dhcp lease info, return full connected station info
    std::map<std::string, StationInfo> tmp;
    if (!m_ApStateMachine.GetConnectedStationInfo(tmp)) {
        WIFI_LOGW("Get connected station info failed!");
        return ErrCode::WIFI_OPT_FAILED;
    }
    for (auto iter = result.begin(); iter != result.end(); ++iter) {
        auto itMap = tmp.find(iter->bssid);
        if (itMap == tmp.end()) {
            continue;
        }
        iter->deviceName = itMap->second.deviceName;
        iter->ipAddr = itMap->second.ipAddr;
    }
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::RegisterApServiceCallbacks(const IApServiceCallbacks &callbacks)
{
    WIFI_LOGI("%{public}s, Instance %{public}d ", __func__, m_id);
    m_ApStateMachine.RegisterApServiceCallbacks(callbacks);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::GetSupportedPowerModel(std::set<PowerModel>& setPowerModelList)
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    /* All modes are currently supported */
    setPowerModelList.insert(PowerModel::SLEEPING);
    setPowerModelList.insert(PowerModel::GENERAL);
    setPowerModelList.insert(PowerModel::THROUGH_WALL);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::GetPowerModel(PowerModel& model)
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    WifiConfigCenter::GetInstance().GetPowerModel(model, m_id);
    LOGI("ApService::GetPowerModel, model=[%{public}d]", static_cast<int>(model));
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::SetPowerModel(const PowerModel& model)
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    LOGI("Enter ApService::SetPowerModel, model=[%d]", static_cast<int>(model));
    if (WifiApHalInterface::GetInstance().SetPowerModel(
        WifiConfigCenter::GetInstance().GetApIfaceName(), static_cast<int>(model)) != WIFI_HAL_OPT_OK) {
        LOGE("SetPowerModel() failed!");
        return WIFI_OPT_FAILED;
    }
    LOGI("SetPowerModel() succeed!");
    WifiConfigCenter::GetInstance().SetPowerModel(model);
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode ApService::WifiCountryCodeChangeObserver::OnWifiCountryCodeChanged(const std::string &wifiCountryCode)
{
    if (strcasecmp(m_lastWifiCountryCode.c_str(), wifiCountryCode.c_str()) == 0) {
        WIFI_LOGI("wifi country code is same, ap not update, code=%{public}s", wifiCountryCode.c_str());
        return WIFI_OPT_SUCCESS;
    }
    WIFI_LOGI("deal wifi country code changed, code=%{public}s", wifiCountryCode.c_str());
    InternalMessagePtr msg = m_stateMachineObj.CreateMessage();
    CHECK_NULL_AND_RETURN(msg, WIFI_OPT_FAILED);
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_UPDATE_COUNTRY_CODE));
    msg->AddStringMessageBody(wifiCountryCode);
    m_stateMachineObj.SendMessage(msg);
    m_lastWifiCountryCode = wifiCountryCode;
    return WIFI_OPT_SUCCESS;
}

void ApService::HandleNetCapabilitiesChanged(const int apStatus)
{
    ApNetworkMonitor::GetInstance().DealApNetworkCapabilitiesChanged(apStatus);
}
 
std::string ApService::WifiCountryCodeChangeObserver::GetListenerModuleName()
{
    return m_listenerModuleName;
}

ErrCode ApService::GetHotspotMode(HotspotMode &mode)
{
    return m_ApStateMachine.GetHotspotMode(mode);
}

ErrCode ApService::SetHotspotMode(const HotspotMode &mode)
{
    return m_ApStateMachine.SetHotspotMode(mode);
}

#ifndef OHOS_ARCH_LITE
void ApService::SetEnhanceService(IEnhanceService* enhanceService)
{
    enhanceService_ = enhanceService;
}
#endif
}  // namespace Wifi
}  // namespace OHOS