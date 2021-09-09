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
#include "ipv4_address.h"
#include "ipv6_address.h"
#include "log_helper.h"
#include "wifi_ap_dhcp_interface.h"
#include "wifi_ap_hal_interface.h"
#include "wifi_ap_nat_manager.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("ApStartedState");
namespace OHOS {
namespace Wifi {
ApStartedState::ApStartedState() : State("ApStartedState"), hotspotConfig(HotspotConfig())
{
    Init();
}

ApStartedState::~ApStartedState()
{}

void ApStartedState::GoInState()
{
    OnApStateChange(ApState::AP_STATE_STARTING);
    WIFI_LOGI("%{public}s  Enter", GetStateName().c_str());

    StartMonitor();

    if (StartAp() == false) {
        WIFI_LOGE("enter ApstartedState is failed.");
        ApStateMachine::GetInstance().SwitchState(&ApStateMachine::GetInstance().mApIdleState);
        return;
    }
    WIFI_LOGI("StartAP is ok");

    if (ApConfigUse::GetInstance().ObtainValidChannels() == false) {
        WIFI_LOGE("ObtainValidChannels is error.");
        ApStateMachine::GetInstance().SwitchState(&ApStateMachine::GetInstance().mApIdleState);
        return;
    }

    if (SetConfig() == false) {
        WIFI_LOGE("wifi_settings.hotspotconfig is error.");
        ApStateMachine::GetInstance().SwitchState(&ApStateMachine::GetInstance().mApIdleState);
        return;
    }

    if (!ApStateMachine::GetInstance().mApStationsManager.EnableAllBlockList()) {
        WIFI_LOGE("Set Blocklist failed");
    }
#ifndef AP_NOT_DIRECT_USE_DHCP
    if (StartDhcpServer() == false) {
        ApStateMachine::GetInstance().SwitchState(&ApStateMachine::GetInstance().mApIdleState);
        return;
    }
    if (EnableInterfaceNat() == false) {
        ApStateMachine::GetInstance().SwitchState(&ApStateMachine::GetInstance().mApIdleState);
        return;
    }
#endif
    OnApStateChange(ApState::AP_STATE_STARTED);
}

void ApStartedState::GoOutState()
{
    WIFI_LOGI("%{public}s  Exit", GetStateName().c_str());
    OnApStateChange(ApState::AP_STATE_CLOSING);
    DisableInterfaceNat();
    StopDhcpServer();
    if (!StopAp()) {
        WIFI_LOGE("StopAp not going well!");
    }
    StopMonitor();
    OnApStateChange(ApState::AP_STATE_IDLE);
    WifiSettings::GetInstance().ClearStationList();
    WifiSettings::GetInstance().ClearValidChannels();
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
    WIFI_LOGI("ApStartedState Process msgName:%{public}d", msgName);

    auto iter = mProcessFunMap.find(static_cast<ApStatemachineEvent>(msgName));
    if (iter == mProcessFunMap.end()) {
        return NOT_EXECUTED;
    }
    ((*this).*(iter->second))(*msg);

    return EXECUTED;
}

bool ApStartedState::SetConfig()
{
    if (WifiSettings::GetInstance().GetHotspotConfig(hotspotConfig)) {
        WIFI_LOGE("GetConfig failed!!!");
        return false;
    }
    ApConfigUse::GetInstance().CheckBandChannel(hotspotConfig);
    if (ApConfigUse::GetInstance().SetConfig(hotspotConfig) == false) {
        WIFI_LOGE("SetConfig failed!!!");
        return false;
    }
    return true;
}

bool ApStartedState::StartAp() const
{
    WIFI_LOGI("enter startAp");
    WifiErrorNo retCode = WifiApHalInterface::GetInstance().StartAp();
    if (retCode != WifiErrorNo::WIFI_IDL_OPT_OK) {
        WIFI_LOGE("startAp is failed!");
        return false;
    }
    return true;
}

bool ApStartedState::StopAp() const
{
    WifiErrorNo retCode = WifiApHalInterface::GetInstance().StopAp();
    if (retCode != WifiErrorNo::WIFI_IDL_OPT_OK) {
        return false;
    }
    return true;
}

void ApStartedState::OnApStateChange(const ApState &state) const
{
    ApStateMachine::GetInstance().OnApStateChange(state);
}

void ApStartedState::StartMonitor() const
{
    ApMonitor::GetInstance().StartMonitor();
}

void ApStartedState::StopMonitor() const
{
    ApMonitor::GetInstance().StopMonitor();
}

bool ApStartedState::StartDhcpServer() const
{
    HotspotConfig hotspotCfg;
    if (WifiSettings::GetInstance().GetHotspotConfig(hotspotCfg)) {
        WIFI_LOGE("Failed to get the HotspotConfig from the WifiSettings.");
        hotspotCfg.SetMaxConn(0xFF);
    }
    std::vector<Ipv4Address> vecIpv4Addr;
    std::vector<Ipv6Address> vecIpv6Addr;
    if (!WifiApDhcpInterface::GetInstance().StartDhcpServer(
        ININTERFACE, hotspotCfg.GetMaxConn(), vecIpv4Addr, vecIpv6Addr, true)) {
        WIFI_LOGE("start dhcpd failed.");
        return false;
    }
    return true;
}

bool ApStartedState::StopDhcpServer() const
{
    WIFI_LOGI("Enter:StopDhcpServer");
    if (!WifiApDhcpInterface::GetInstance().StopDhcpServer()) {
        WIFI_LOGE("Close dhcpd failed.");
    }
    return true;
}

bool ApStartedState::EnableInterfaceNat() const
{
    if (!WifiApNatManager::GetInstance().EnableInterfaceNat(true, ININTERFACE, OUTINTERFACE)) {
        WIFI_LOGE("set nat failed.");
        return false;
    }
    return true;
}

bool ApStartedState::DisableInterfaceNat() const
{
    if (!WifiApNatManager::GetInstance().EnableInterfaceNat(false, ININTERFACE, OUTINTERFACE)) {
        WIFI_LOGE("remove NAT config failed.");
    }
    return true;
}

void ApStartedState::ProcessCmdFail(InternalMessage &msg) const
{
    WIFI_LOGI("State Machine message: %{public}d.", msg.GetMessageName());
    ApStateMachine::GetInstance().SwitchState(&ApStateMachine::GetInstance().mApIdleState);
}

void ApStartedState::ProcessCmdStationJoin(InternalMessage &msg) const
{
    WIFI_LOGI("New station join.");
    StationInfo staInfo;
    staInfo.deviceName = msg.GetStringFromMessage();
    staInfo.bssid = msg.GetStringFromMessage();
    staInfo.ipAddr = msg.GetStringFromMessage();
    ApStateMachine::GetInstance().mApStationsManager.StationJoin(staInfo);
}

void ApStartedState::ProcessCmdStationLeave(InternalMessage &msg) const
{
    WIFI_LOGI("Old station leave.");
    StationInfo staInfo;
    staInfo.deviceName = msg.GetStringFromMessage();
    staInfo.bssid = msg.GetStringFromMessage();
    staInfo.ipAddr = msg.GetStringFromMessage();
    ApStateMachine::GetInstance().mApStationsManager.StationLeave(staInfo.bssid);
}

void ApStartedState::ProcessCmdSetHotspotConfig(InternalMessage &msg)
{
    WIFI_LOGI("Set HotspotConfig.");

    hotspotConfig.SetSsid(msg.GetStringFromMessage());
    hotspotConfig.SetPreSharedKey(msg.GetStringFromMessage());
    hotspotConfig.SetSecurityType(static_cast<KeyMgmt>(msg.GetIntFromMessage()));
    hotspotConfig.SetBand(static_cast<BandType>(msg.GetIntFromMessage()));
    hotspotConfig.SetChannel(msg.GetIntFromMessage());
    hotspotConfig.SetMaxConn(msg.GetIntFromMessage());

    WIFI_LOGD("hotspotConfig: %s,%s,%{public}d,%{public}d,%{public}d,%{public}d",
        hotspotConfig.GetSsid().c_str(),
        hotspotConfig.GetPreSharedKey().c_str(),
        static_cast<int>(hotspotConfig.GetSecurityType()),
        static_cast<int>(hotspotConfig.GetBand()),
        hotspotConfig.GetChannel(),
        hotspotConfig.GetMaxConn());

    if (ApConfigUse::GetInstance().SetConfig(hotspotConfig)) {
        WIFI_LOGI("SetSoftApConfig successfully");
    } else {
        WIFI_LOGE("SetSoftApConfig failed");
    }
}

void ApStartedState::ProcessCmdUpdateConfigResult(InternalMessage &msg) const
{
    if (msg.GetParam1() == 1) {
        WIFI_LOGI("Hot update HotspotConfig succeeded.");
        if (WifiSettings::GetInstance().SetHotspotConfig(hotspotConfig)) {
            WIFI_LOGE("set apConfig to settings failed.");
        }
    } else {
        ApStateMachine::GetInstance().SwitchState(&ApStateMachine::GetInstance().mApIdleState);
    }
}

void ApStartedState::ProcessCmdAddBlockList(InternalMessage &msg) const
{
    WIFI_LOGI("Add block list.");
    StationInfo staInfo;
    staInfo.deviceName = msg.GetStringFromMessage();
    staInfo.bssid = msg.GetStringFromMessage();
    staInfo.ipAddr = msg.GetStringFromMessage();
    WIFI_LOGI("staInfo:%s, %s, %s", staInfo.deviceName.c_str(), staInfo.bssid.c_str(), staInfo.ipAddr.c_str());
    ApStateMachine::GetInstance().mApStationsManager.AddBlockList(staInfo);
}

void ApStartedState::ProcessCmdDelBlockList(InternalMessage &msg) const
{
    WIFI_LOGI("Delete block list");
    StationInfo staInfo;
    staInfo.deviceName = msg.GetStringFromMessage();
    staInfo.bssid = msg.GetStringFromMessage();
    staInfo.ipAddr = msg.GetStringFromMessage();
    WIFI_LOGI("staInfo:%s, %s, %s", staInfo.deviceName.c_str(), staInfo.bssid.c_str(), staInfo.ipAddr.c_str());
    ApStateMachine::GetInstance().mApStationsManager.DelBlockList(staInfo);
}

void ApStartedState::ProcessCmdStopHotspot(InternalMessage &msg) const
{
    WIFI_LOGI("Disable hotspot: %{public}d.", msg.GetMessageName());
    ApStateMachine::GetInstance().SwitchState(&ApStateMachine::GetInstance().mApIdleState);
}

void ApStartedState::ProcessCmdDisconnectStation(InternalMessage &msg) const
{
    WIFI_LOGI("Disconnect station.");
    StationInfo staInfo;
    staInfo.deviceName = msg.GetStringFromMessage();
    staInfo.bssid = msg.GetStringFromMessage();
    staInfo.ipAddr = msg.GetStringFromMessage();
    ApStateMachine::GetInstance().mApStationsManager.DisConnectStation(staInfo);
}
}  // namespace Wifi
}  // namespace OHOS