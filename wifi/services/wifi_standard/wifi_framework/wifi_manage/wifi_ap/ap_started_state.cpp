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

#include "ap_started_state.h"
#include <cstring>
#include <string>
#include <typeinfo>
#include <vector>
#include <map>
#include "ap_config_use.h"
#include "ap_macro.h"
#include "ap_monitor.h"
#include "ap_service.h"
#include "ap_state_machine.h"
#include "ap_stations_manager.h"
#include "dhcpd_interface.h"
#include "wifi_ap_hal_interface.h"
#include "wifi_ap_nat_manager.h"
#include "wifi_chip_capability.h"
#include "wifi_settings.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiApStartedState");
namespace OHOS {
namespace Wifi {
ApStartedState::ApStartedState(ApStateMachine &apStateMachine, ApConfigUse &apConfigUse, ApMonitor &apMonitor, int id)
    : State("ApStartedState"),
      m_hotspotConfig(HotspotConfig()),
      m_ApStateMachine(apStateMachine),
      m_ApConfigUse(apConfigUse),
      m_ApMonitor(apMonitor),
      m_id(id)
{
    Init();
}

ApStartedState::~ApStartedState()
{}

void ApStartedState::GoInState()
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    m_ApStateMachine.OnApStateChange(ApState::AP_STATE_STARTING);
    WIFI_LOGI("Instance %{public}d %{public}s  GoInState", m_id, GetStateName().c_str());
    m_ApStateMachine.RegisterEventHandler();
    StartMonitor();

    if (StartAp() == false) {
        WIFI_LOGE("enter ApstartedState is failed.");
        m_ApStateMachine.SwitchState(&m_ApStateMachine.m_ApIdleState);
        return;
    }
    WIFI_LOGI("StartAP is ok.");

    if (SetConfig() == false) {
        WIFI_LOGE("wifi_settings.hotspotconfig is error.");
        m_ApStateMachine.SwitchState(&m_ApStateMachine.m_ApIdleState);
        return;
    }

    if (!m_ApStateMachine.m_ApStationsManager.EnableAllBlockList()) {
        WIFI_LOGE("Set Blocklist failed.");
    }

    WIFI_LOGE("Singleton version has not nat and use %{public}s.", AP_INTF);

    if (EnableInterfaceNat() == false) {
        m_ApStateMachine.SwitchState(&m_ApStateMachine.m_ApIdleState);
        return;
    }
    UpdatePowerMode();
    m_ApStateMachine.OnApStateChange(ApState::AP_STATE_STARTED);
    ChipCapability::GetInstance().InitializeChipCapability();
}

void ApStartedState::GoOutState()
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    m_ApStateMachine.OnApStateChange(ApState::AP_STATE_CLOSING);
    DisableInterfaceNat();
    m_ApStateMachine.StopDhcpServer();
    if (!StopAp()) {
        WIFI_LOGE("StopAp not going well.");
    }
    StopMonitor();
    m_ApStateMachine.OnApStateChange(ApState::AP_STATE_IDLE);
    WifiSettings::GetInstance().ClearStationList();
}

void ApStartedState::Init()
{
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_FAIL, &ApStartedState::ProcessCmdFail));
    mProcessFunMap.insert(
        std::make_pair(ApStatemachineEvent::CMD_STATION_JOIN, &ApStartedState::ProcessCmdStationJoin));
    mProcessFunMap.insert(
        std::make_pair(ApStatemachineEvent::CMD_STATION_LEAVE, &ApStartedState::ProcessCmdStationLeave));
    mProcessFunMap.insert(std::make_pair(
        ApStatemachineEvent::CMD_SET_HOTSPOT_CONFIG, (ProcessFun)&ApStartedState::ProcessCmdSetHotspotConfig));
    mProcessFunMap.insert(std::make_pair(
        ApStatemachineEvent::CMD_UPDATE_HOTSPOTCONFIG_RESULT, &ApStartedState::ProcessCmdUpdateConfigResult));
    mProcessFunMap.insert(
        std::make_pair(ApStatemachineEvent::CMD_ADD_BLOCK_LIST, &ApStartedState::ProcessCmdAddBlockList));
    mProcessFunMap.insert(
        std::make_pair(ApStatemachineEvent::CMD_DEL_BLOCK_LIST, &ApStartedState::ProcessCmdDelBlockList));
    mProcessFunMap.insert(
        std::make_pair(ApStatemachineEvent::CMD_STOP_HOTSPOT, &ApStartedState::ProcessCmdStopHotspot));
    mProcessFunMap.insert(
        std::make_pair(ApStatemachineEvent::CMD_DISCONNECT_STATION, &ApStartedState::ProcessCmdDisconnectStation));
}

bool ApStartedState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("fatal error!");
        return false;
    }
    int msgName = msg->GetMessageName();
    WIFI_LOGI("Instance %{public}d ApStartedState Process msgName:%{public}d.", m_id, msgName);

    auto iter = mProcessFunMap.find(static_cast<ApStatemachineEvent>(msgName));
    if (iter == mProcessFunMap.end()) {
        return NOT_EXECUTED;
    }
    ((*this).*(iter->second))(*msg);

    return EXECUTED;
}

bool ApStartedState::SetConfig(HotspotConfig &apConfig)
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    std::vector<int> allowed5GFreq, allowed2GFreq;
    std::vector<int> allowed5GChan, allowed2GChan;
    if (WifiApHalInterface::GetInstance().GetFrequenciesByBand(static_cast<int>(BandType::BAND_2GHZ), allowed2GFreq)) {
        WIFI_LOGW("failed to get 2.4G channel.");
        WifiSettings::GetInstance().SetDefaultFrequenciesByCountryBand(BandType::BAND_2GHZ, allowed2GFreq);
    }
    if (WifiApHalInterface::GetInstance().GetFrequenciesByBand(static_cast<int>(BandType::BAND_5GHZ), allowed5GFreq)) {
        WIFI_LOGW("failed to get 5G channel.");
        WifiSettings::GetInstance().SetDefaultFrequenciesByCountryBand(BandType::BAND_5GHZ, allowed5GFreq);
    }

    m_ApConfigUse.TransformFrequencyIntoChannel(allowed5GFreq, allowed5GChan);
    m_ApConfigUse.TransformFrequencyIntoChannel(allowed2GFreq, allowed2GChan);

    ChannelsTable channelTbs;
    channelTbs[BandType::BAND_2GHZ] = allowed2GChan;
    channelTbs[BandType::BAND_5GHZ] = allowed5GChan;

    if (WifiSettings::GetInstance().SetValidChannels(channelTbs)) {
        WIFI_LOGE("failed to SetValidChannels.");
        return false;
    }

    m_ApConfigUse.CheckBandChannel(apConfig, channelTbs);

    if (WifiApHalInterface::GetInstance().SetSoftApConfig(apConfig, m_id) != WifiErrorNo::WIFI_IDL_OPT_OK) {
        WIFI_LOGE("set hostapd config failed.");
        return false;
    }

    WifiSettings::GetInstance().SetHotspotConfig(apConfig, m_id);
    WifiSettings::GetInstance().SyncHotspotConfig();
    m_ApConfigUse.LogConfig(apConfig);
    WIFI_LOGI("SetConfig OK!.");
    return true;
}

bool ApStartedState::SetConfig()
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    std::string countryCode;
    if (WifiSettings::GetInstance().GetCountryCode(countryCode)) {
        WIFI_LOGE("get countryCode failed.");
        return false;
    }
    if (WifiApHalInterface::GetInstance().SetWifiCountryCode(countryCode, m_id) != WifiErrorNo::WIFI_IDL_OPT_OK) {
        WIFI_LOGE("set countryCode:%{public}s failed.", countryCode.c_str());
        return false;
    }
    WIFI_LOGI("HotspotConfig  CountryCode  = %{public}s.", countryCode.c_str());

    if (WifiSettings::GetInstance().GetHotspotConfig(m_hotspotConfig, m_id)) {
        WIFI_LOGE("GetConfig failed!!!.");
        return false;
    }

    return SetConfig(m_hotspotConfig);
}

bool ApStartedState::StartAp() const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    WifiErrorNo retCode = WifiApHalInterface::GetInstance().StartAp(m_id);
    if (retCode != WifiErrorNo::WIFI_IDL_OPT_OK) {
        WIFI_LOGE("startAp is failed!");
        return false;
    }
    return true;
}

bool ApStartedState::StopAp() const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    WifiErrorNo retCode = WifiApHalInterface::GetInstance().StopAp(m_id);
    if (retCode != WifiErrorNo::WIFI_IDL_OPT_OK) {
        return false;
    }
    return true;
}

void ApStartedState::StartMonitor() const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    m_ApMonitor.StartMonitor();
}

void ApStartedState::StopMonitor() const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    m_ApMonitor.StopMonitor();
}

bool ApStartedState::EnableInterfaceNat() const
{
#ifdef SUPPORT_NAT
    if (!mApNatManager.EnableInterfaceNat(true, IN_INTERFACE, OUT_INTERFACE)) {
        WIFI_LOGE("set nat failed.");
        return false;
    }
#endif
    return true;
}

bool ApStartedState::DisableInterfaceNat() const
{
#ifdef SUPPORT_NAT
    if (!mApNatManager.EnableInterfaceNat(false, IN_INTERFACE, OUT_INTERFACE)) {
        WIFI_LOGE("remove NAT config failed.");
    }
#endif
    return true;
}

void ApStartedState::ProcessCmdFail(InternalMessage &msg) const
{
    WIFI_LOGI("Instance %{public}d State Machine message: %{public}d.", m_id, msg.GetMessageName());
    m_ApStateMachine.SwitchState(&m_ApStateMachine.m_ApIdleState);
}

void ApStartedState::ProcessCmdStationJoin(InternalMessage &msg) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    StationInfo staInfo;
    if (msg.GetMessageObj(staInfo)) {
        m_ApStateMachine.m_ApStationsManager.StationJoin(staInfo);
    } else {
        WIFI_LOGE("failed to get station info.");
    }
}

void ApStartedState::ProcessCmdStationLeave(InternalMessage &msg) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    StationInfo staInfo;
    if (msg.GetMessageObj(staInfo)) {
        m_ApStateMachine.m_ApStationsManager.StationLeave(staInfo.bssid);
    } else {
        WIFI_LOGE("failed to get station info.");
    }
}

void ApStartedState::ProcessCmdSetHotspotConfig(InternalMessage &msg)
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    m_hotspotConfig.SetSsid(msg.GetStringFromMessage());
    m_hotspotConfig.SetPreSharedKey(msg.GetStringFromMessage());
    m_hotspotConfig.SetSecurityType(static_cast<KeyMgmt>(msg.GetIntFromMessage()));
    m_hotspotConfig.SetBand(static_cast<BandType>(msg.GetIntFromMessage()));
    m_hotspotConfig.SetChannel(msg.GetIntFromMessage());
    m_hotspotConfig.SetMaxConn(msg.GetIntFromMessage());

    if (SetConfig(m_hotspotConfig)) {
        WIFI_LOGI("SetSoftApConfig success.");
    } else {
        WIFI_LOGE("SetSoftApConfig failed.");
    }
}

void ApStartedState::ProcessCmdUpdateConfigResult(InternalMessage &msg) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    if (msg.GetParam1() == 1) {
        WIFI_LOGI("Hot update HotspotConfig succeeded.");
        if (WifiSettings::GetInstance().SetHotspotConfig(m_hotspotConfig, m_id)) {
            WIFI_LOGE("set apConfig to settings failed.");
        }
#ifndef WIFI_DHCP_DISABLED
        m_ApStateMachine.StopDhcpServer();
        m_ApStateMachine.StartDhcpServer();
#endif
    } else {
        m_ApStateMachine.SwitchState(&m_ApStateMachine.m_ApIdleState);
    }
}

void ApStartedState::ProcessCmdAddBlockList(InternalMessage &msg) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    StationInfo staInfo;
    staInfo.deviceName = msg.GetStringFromMessage();
    staInfo.bssid = msg.GetStringFromMessage();
    staInfo.ipAddr = msg.GetStringFromMessage();
    WIFI_LOGI("staInfo:%{private}s, %{public}s, %{public}s.",
        staInfo.deviceName.c_str(), MacAnonymize(staInfo.bssid).c_str(), IpAnonymize(staInfo.ipAddr).c_str());
    m_ApStateMachine.m_ApStationsManager.AddBlockList(staInfo);
}

void ApStartedState::ProcessCmdDelBlockList(InternalMessage &msg) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    StationInfo staInfo;
    staInfo.deviceName = msg.GetStringFromMessage();
    staInfo.bssid = msg.GetStringFromMessage();
    staInfo.ipAddr = msg.GetStringFromMessage();
    WIFI_LOGI("staInfo:%{private}s, %{public}s, %{public}s.", staInfo.deviceName.c_str(),
        MacAnonymize(staInfo.bssid).c_str(), IpAnonymize(staInfo.ipAddr).c_str());
    m_ApStateMachine.m_ApStationsManager.DelBlockList(staInfo);
}

void ApStartedState::ProcessCmdStopHotspot(InternalMessage &msg) const
{
    WIFI_LOGI("Instance %{public}d Disable hotspot: %{public}d.", m_id, msg.GetMessageName());
    m_ApStateMachine.SwitchState(&m_ApStateMachine.m_ApIdleState);
}

void ApStartedState::ProcessCmdDisconnectStation(InternalMessage &msg) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    StationInfo staInfo;
    staInfo.deviceName = msg.GetStringFromMessage();
    staInfo.bssid = msg.GetStringFromMessage();
    staInfo.ipAddr = msg.GetStringFromMessage();
    m_ApStateMachine.m_ApStationsManager.DisConnectStation(staInfo);
}

void ApStartedState::UpdatePowerMode() const
{
    WIFI_LOGI("UpdatePowerMode.");
    int model = -1;
    if (WifiApHalInterface::GetInstance().GetPowerModel(model) != WIFI_IDL_OPT_OK) {
        LOGE("GetPowerModel() failed!");
        return;
    }
    LOGI("SetPowerModel(): %{public}d.", model);
    WifiSettings::GetInstance().SetPowerModel(PowerModel(model));
}
}  // namespace Wifi
}  // namespace OHOS
