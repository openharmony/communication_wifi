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
#include "wifi_channel_helper.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"
#include "wifi_country_code_manager.h"
#include "wifi_hisysevent.h"
#include "wifi_global_func.h"
#include "wifi_cmd_client.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_randommac_helper.h"
#include "wifi_battery_utils.h"
#include "ap_define.h"
#include "wifi_controller_define.h"

#define SET_DUAL_ANTENNAS 45
DEFINE_WIFILOG_HOTSPOT_LABEL("WifiApStartedState");

namespace OHOS {
namespace Wifi {
const int STA_JOIN_HANDLE_DELAY = 5 * 1000;
ApStartedState::ApStartedState(ApStateMachine &apStateMachine, ApMonitor &apMonitor, int id)
    : State("ApStartedState"),
      m_hotspotConfig(HotspotConfig()),
      m_ApStateMachine(apStateMachine),
      m_ApMonitor(apMonitor),
      m_id(id)
{
    Init();
}

ApStartedState::~ApStartedState()
{}

void ApStartedState::GoInState()
{
    WIFI_LOGI("Instance %{public}d %{public}s  GoInState.", m_id, GetStateName().c_str());
}

void ApStartedState::GoOutState()
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    m_ApStateMachine.StopTimer(static_cast<int>(ApStatemachineEvent::CMD_START_HOTSPOT_TIMEOUT));
    m_ApStateMachine.OnApStateChange(ApState::AP_STATE_CLOSING);
    DisableInterfaceNat();
    m_ApStateMachine.StopDhcpServer();
    if (!StopAp()) {
        WIFI_LOGE("StopAp not going well.");
    }
    StopMonitor();
    m_ApStateMachine.OnApStateChange(ApState::AP_STATE_IDLE);
    WifiConfigCenter::GetInstance().ClearStationList();
    WifiSettings::GetInstance().GetHotspotConfig(m_hotspotConfig, m_id);
    if (!m_hotspotConfig.GetIpAddress().empty() && m_hotspotConfig.GetIpAddress() != AP_DEFAULT_IP) {
        WIFI_LOGI("reset ip");
        m_hotspotConfig.SetIpAddress(AP_DEFAULT_IP);
        WifiSettings::GetInstance().SetHotspotConfig(m_hotspotConfig, m_id);
        WifiSettings::GetInstance().SyncHotspotConfig();
    }
}

void ApStartedState::Init()
{
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_FAIL,
        [this](InternalMessagePtr msg) { this->ProcessCmdFail(msg); }));
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_STATION_JOIN,
        [this](InternalMessagePtr msg) { this->ProcessCmdStationJoin(msg); }));
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_STATION_LEAVE,
        [this](InternalMessagePtr msg) { this->ProcessCmdStationLeave(msg); }));
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_UPDATE_HOTSPOTCONFIG_RESULT,
        [this](InternalMessagePtr msg) { this->ProcessCmdUpdateConfigResult(msg); }));
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_ADD_BLOCK_LIST,
        [this](InternalMessagePtr msg) { this->ProcessCmdAddBlockList(msg); }));
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_DEL_BLOCK_LIST,
        [this](InternalMessagePtr msg) { this->ProcessCmdDelBlockList(msg); }));
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_STOP_HOTSPOT,
        [this](InternalMessagePtr msg) { this->ProcessCmdStopHotspot(msg); }));
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_DISCONNECT_STATION,
        [this](InternalMessagePtr msg) { this->ProcessCmdDisconnectStation(msg); }));
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_SET_IDLE_TIMEOUT,
        (ProcessFun)[this](InternalMessagePtr msg) { this->ProcessCmdSetHotspotIdleTimeout(msg); }));
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_UPDATE_COUNTRY_CODE,
        [this](InternalMessagePtr msg) { this->ProcessCmdUpdateCountryCode(msg); }));
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_HOTSPOT_CHANNEL_CHANGED,
        [this](InternalMessagePtr msg) { this->ProcessCmdHotspotChannelChanged(msg); }));
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_ASSOCIATED_STATIONS_CHANGED,
        [this](InternalMessagePtr msg) { this->ProcessCmdAssociatedStaChanged(msg); }));
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_START_HOTSPOT,
        [this](InternalMessagePtr msg) { this->ProcessCmdEnableAp(msg); }));
    mProcessFunMap.insert(std::make_pair(ApStatemachineEvent::CMD_START_HOTSPOT_TIMEOUT,
        [this](InternalMessagePtr msg) { this->ProcessCmdEnableApTimeout(msg); }));
}

bool ApStartedState::ExecuteStateMsg(InternalMessagePtr msg)
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
    (iter->second)(msg);

    return EXECUTED;
}

bool ApStartedState::SetConfig(HotspotConfig &apConfig)
{
    WIFI_LOGI("set softap config with param, id=%{public}d", m_id);
    ApConfigUse::GetInstance().UpdateApChannelConfig(apConfig);
    {
#ifndef OHOS_ARCH_LITE
        std::unique_lock<std::mutex> lock(enhanceServiceMutex_);
        if ((apConfig.GetBandWidth() == AP_BANDWIDTH_160 ||
                (apConfig.GetChannel() >= CHANNEL50 && apConfig.GetChannel() <= CHANNEL144))) {
            if (enhanceService_ != nullptr && enhanceService_->GetDfsControlData().enableAidfs_) {
                WIFI_LOGI("DfsControl. use Dfs Channel and Aidfs enable, Stop 60s CAC");
                enhanceService_->CloseCAC();
            }
        }
#endif
    }
    std::string ifName = WifiConfigCenter::GetInstance().GetApIfaceName();
    WifiErrorNo setSoftApConfigResult = WifiErrorNo::WIFI_HAL_OPT_OK;
    WifiErrorNo setApPasswdResult = WifiErrorNo::WIFI_HAL_OPT_OK;
    HotspotMode currentMode = HotspotMode::SOFTAP;
    m_ApStateMachine.GetHotspotMode(currentMode);
    if (currentMode == HotspotMode::LOCAL_ONLY_SOFTAP) {
        // The localOnlyHotspot uses the temporary configuration and does not flush to disks,
        // The SSID and password are random values.
        HotspotConfig hotspotConfigTemp = apConfig;
        std::string randomSsid = LOCAL_ONLY_SOFTAP_SSID_PREFIX +
            std::to_string(GetRandomInt(LOCAL_ONLY_SOFTAP_SSID_INIT_SUFFIX, LOCAL_ONLY_SOFTAP_SSID_END_SUFFIX));
        hotspotConfigTemp.SetSsid(randomSsid);
        hotspotConfigTemp.SetPreSharedKey(GetRandomStr(LOCAL_ONLY_SOFTAP_PWD_LEN));
        WifiConfigCenter::GetInstance().SetLocalOnlyHotspotConfig(hotspotConfigTemp);
        setSoftApConfigResult = WifiApHalInterface::GetInstance().SetSoftApConfig(ifName, hotspotConfigTemp, m_id);
        setApPasswdResult = WifiApHalInterface::GetInstance().SetApPasswd(
            hotspotConfigTemp.GetPreSharedKey().c_str(), m_id);
        WIFI_LOGI("set local only hotspot config, ssid=%{public}s", SsidAnonymize(randomSsid).c_str());
    } else {
        setSoftApConfigResult = WifiApHalInterface::GetInstance().SetSoftApConfig(ifName, apConfig, m_id);
        setApPasswdResult = WifiApHalInterface::GetInstance().SetApPasswd(apConfig.GetPreSharedKey().c_str(), m_id);
    }
    if (setSoftApConfigResult != WifiErrorNo::WIFI_HAL_OPT_OK || setApPasswdResult != WifiErrorNo::WIFI_HAL_OPT_OK) {
        WIFI_LOGE("set hostapd config failed.");
        return false;
    }
    return SetConfigExtral(apConfig, ifName);
}
 
bool ApStartedState::SetConfigExtral(HotspotConfig &apConfig, std::string ifName)
{
    if (BatteryUtils::GetInstance().GetBatteryCapacity() > SET_DUAL_ANTENNAS) {
        HotspotConfig hotspotConfig;
        WifiSettings::GetInstance().GetHotspotConfig(hotspotConfig, m_id);
        if (hotspotConfig.GetBand() == BandType::BAND_2GHZ) {
            WifiCmdClient::GetInstance().SendCmdToDriver(ifName, CMD_SET_SOFTAP_2G_MSS, CMD_SET_SOFTAP_MIMOMODE);
        }
    }
    WifiApHalInterface::GetInstance().SetMaxConnectNum(ifName, apConfig.GetChannel(), apConfig.GetMaxConn());
    if (WifiApHalInterface::GetInstance().EnableAp(m_id) != WifiErrorNo::WIFI_HAL_OPT_OK) {
        WIFI_LOGE("Enableap failed.");
        return false;
    }
    if (apConfig.GetIpAddress().empty()) {
        WIFI_LOGI("IP is empty, set default ipaddr");
        apConfig.SetIpAddress(AP_DEFAULT_IP);
    }
    WifiSettings::GetInstance().SetHotspotConfig(apConfig, m_id);
    WifiSettings::GetInstance().SyncHotspotConfig();
    WIFI_LOGI("setConfig success");
    return true;
}

bool ApStartedState::SetConfig()
{
    WIFI_LOGI("set softap config, id=%{public}d", m_id);
    if (WifiSettings::GetInstance().GetHotspotConfig(m_hotspotConfig, m_id)) {
        WIFI_LOGE("get config failed");
        return false;
    }
    return SetConfig(m_hotspotConfig);
}

bool ApStartedState::StartAp() const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    std::string ifaceName = WifiConfigCenter::GetInstance().GetApIfaceName();
    WifiErrorNo retCode = WifiApHalInterface::GetInstance().StartAp(m_id, ifaceName);
    if (retCode != WifiErrorNo::WIFI_HAL_OPT_OK) {
        WIFI_LOGE("startAp is failed!");
        return false;
    }
    WriteWifiApStateHiSysEvent(1);
    return true;
}

bool ApStartedState::StopAp() const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    WifiErrorNo retCode = WifiApHalInterface::GetInstance().StopAp(m_id);
    if (retCode != WifiErrorNo::WIFI_HAL_OPT_OK) {
        return false;
    }
    WriteWifiApStateHiSysEvent(0);
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
    std::string ifaceName = WifiConfigCenter::GetInstance().GetApIfaceName();
    if (!mApNatManager.EnableInterfaceNat(true, ifaceName, ifaceName)) {
        WIFI_LOGE("set nat failed.");
        return false;
    }
#endif
    return true;
}

bool ApStartedState::DisableInterfaceNat() const
{
#ifdef SUPPORT_NAT
    std::string ifaceName = WifiConfigCenter::GetInstance().GetApIfaceName();
    if (!mApNatManager.EnableInterfaceNat(false, ifaceName, ifaceName)) {
        WIFI_LOGE("remove NAT config failed.");
    }
#endif
    return true;
}

void ApStartedState::ProcessCmdFail(InternalMessagePtr msg) const
{
    WIFI_LOGI("Instance %{public}d State Machine message: %{public}d.", m_id, msg->GetMessageName());
    m_ApStateMachine.SwitchState(&m_ApStateMachine.m_ApIdleState);
}

void ApStartedState::ProcessCmdStationJoin(InternalMessagePtr msg)
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    StationInfo staInfo;
    if (!msg->GetMessageObj(staInfo)) {
        WIFI_LOGE("failed to get station info.");
        return;
    }
    if (curAssocMacList.find(staInfo.bssid) == curAssocMacList.end()) {
        WIFI_LOGE("sta has removed.");
        return;
    }
    WriteSoftApOperateHiSysEvent(static_cast<int>(SoftApChrEventType::SOFT_AP_CONN_CNT));
    m_ApStateMachine.m_ApStationsManager.StationJoin(staInfo);
}

void ApStartedState::ProcessCmdStationLeave(InternalMessagePtr msg)
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    StationInfo staInfo;
    WriteSoftApAbDisconnectHiSysEvent(AP_ERR_CODE);
    if (msg->GetMessageObj(staInfo)) {
        m_ApStateMachine.m_ApStationsManager.StationLeave(staInfo.bssid);
    } else {
        WIFI_LOGE("failed to get station info.");
    }
}

void ApStartedState::ProcessCmdUpdateConfigResult(InternalMessagePtr msg) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    if (msg->GetParam1() == 1) {
        WIFI_LOGI("Hot update HotspotConfig succeeded.");
        if (WifiSettings::GetInstance().SetHotspotConfig(m_hotspotConfig, m_id)) {
            WIFI_LOGE("set apConfig to settings failed.");
        }
#ifndef WIFI_DHCP_DISABLED
        m_ApStateMachine.StopDhcpServer();
        if (m_ApStateMachine.StartDhcpServer(m_hotspotConfig.GetIpAddress(), m_hotspotConfig.GetLeaseTime())) {
            m_ApStateMachine.OnApStateChange(ApState::AP_STATE_STARTED);
            m_ApStateMachine.StopTimer(static_cast<int>(ApStatemachineEvent::CMD_START_HOTSPOT_TIMEOUT));
        }
#else
        m_ApStateMachine.OnApStateChange(ApState::AP_STATE_STARTED);
#endif
        WifiSettings::GetInstance().SyncHotspotConfig();
    } else {
        WIFI_LOGI("Ap disabled, set softap toggled false");
        WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
        m_ApStateMachine.SwitchState(&m_ApStateMachine.m_ApIdleState);
    }
}

void ApStartedState::ProcessCmdEnableApTimeout(InternalMessagePtr msg) const
{
    if (WifiConfigCenter::GetInstance().GetHotspotState(m_id) == static_cast<int>(ApState::AP_STATE_STARTED)) {
        WIFI_LOGI("Current state is AP_STATE_STARTED, no need deal CMD_START_HOTSPOT_TIMEOUT.");
        return;
    }
    WIFI_LOGI("Ap enable timeout, set softap toggled false.");
    WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
    m_ApStateMachine.SwitchState(&m_ApStateMachine.m_ApIdleState);
}

void ApStartedState::ProcessCmdAddBlockList(InternalMessagePtr msg) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    StationInfo staInfo;
    staInfo.deviceName = msg->GetStringFromMessage();
    staInfo.bssid = msg->GetStringFromMessage();
    staInfo.ipAddr = msg->GetStringFromMessage();
    WIFI_LOGI("staInfo:%{private}s, %{public}s, %{public}s.",
        staInfo.deviceName.c_str(), MacAnonymize(staInfo.bssid).c_str(), IpAnonymize(staInfo.ipAddr).c_str());
    m_ApStateMachine.m_ApStationsManager.AddBlockList(staInfo);
}

void ApStartedState::ProcessCmdDelBlockList(InternalMessagePtr msg) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    StationInfo staInfo;
    staInfo.deviceName = msg->GetStringFromMessage();
    staInfo.bssid = msg->GetStringFromMessage();
    staInfo.ipAddr = msg->GetStringFromMessage();
    WIFI_LOGI("staInfo:%{private}s, %{public}s, %{public}s.", staInfo.deviceName.c_str(),
        MacAnonymize(staInfo.bssid).c_str(), IpAnonymize(staInfo.ipAddr).c_str());
    m_ApStateMachine.m_ApStationsManager.DelBlockList(staInfo);
}

void ApStartedState::ProcessCmdStopHotspot(InternalMessagePtr msg) const
{
    WIFI_LOGI("Instance %{public}d Disable hotspot: %{public}d.", m_id, msg->GetMessageName());
    m_ApStateMachine.SwitchState(&m_ApStateMachine.m_ApIdleState);
}

void ApStartedState::ProcessCmdDisconnectStation(InternalMessagePtr msg) const
{
    WIFI_LOGI("Instance %{public}d %{public}s", m_id, __func__);
    StationInfo staInfo;
    staInfo.deviceName = msg->GetStringFromMessage();
    staInfo.bssid = msg->GetStringFromMessage();
    staInfo.ipAddr = msg->GetStringFromMessage();
    m_ApStateMachine.m_ApStationsManager.DisConnectStation(staInfo);
}

void ApStartedState::ProcessCmdUpdateCountryCode(InternalMessagePtr msg) const
{
    std::string wifiCountryCode = msg->GetStringFromMessage();
    if (wifiCountryCode.empty() ||
        strncasecmp(wifiCountryCode.c_str(), m_wifiCountryCode.c_str(), WIFI_COUNTRY_CODE_LEN) == 0) {
        WIFI_LOGI("wifi country code is same or empty, code=%{public}s", wifiCountryCode.c_str());
        WifiChannelHelper::GetInstance().UpdateValidFreqs();
        return;
    }
    WifiErrorNo ret = WifiApHalInterface::GetInstance().SetWifiCountryCode(
        WifiConfigCenter::GetInstance().GetApIfaceName(), wifiCountryCode);
    if (ret == WifiErrorNo::WIFI_HAL_OPT_OK) {
        m_wifiCountryCode = wifiCountryCode;
        WIFI_LOGI("update wifi country code success, wifiCountryCode=%{public}s", wifiCountryCode.c_str());
        WifiChannelHelper::GetInstance().UpdateValidFreqs();
        return;
    }
    WIFI_LOGE("update wifi country code fail, wifiCountryCode=%{public}s, ret=%{public}d",
        wifiCountryCode.c_str(), ret);
}

void ApStartedState::UpdatePowerMode() const
{
    WIFI_LOGI("UpdatePowerMode.");
    int model = -1;
    if (WifiApHalInterface::GetInstance().GetPowerModel(
        WifiConfigCenter::GetInstance().GetApIfaceName(), model) != WIFI_HAL_OPT_OK) {
        LOGE("GetPowerModel() failed!");
        return;
    }
    LOGI("SetPowerModel(): %{public}d.", model);
    WifiConfigCenter::GetInstance().SetPowerModel(PowerModel(model));
}

void ApStartedState::ProcessCmdSetHotspotIdleTimeout(InternalMessagePtr msg)
{
    int mTimeoutDelay = msg->GetIntFromMessage();
    WIFI_LOGI("Set hotspot idle time is %{public}d", mTimeoutDelay);
    if (mTimeoutDelay == WifiConfigCenter::GetInstance().GetHotspotIdleTimeout()) {
        return;
    }
    WifiConfigCenter::GetInstance().SetHotspotIdleTimeout(mTimeoutDelay);
}

void ApStartedState::SetRandomMac() const
{
    HotspotConfig curConfig;
    if (WifiSettings::GetInstance().GetHotspotConfig(curConfig, m_id) != 0) {
        WIFI_LOGE("Get hotspot config error");
        return;
    }

    std::string macAddress = curConfig.GetRandomMac();
    if (macAddress == "") {
        WifiRandomMacHelper::GenerateRandomMacAddress(macAddress);
    }

    if (!MacAddress::IsValidMac(macAddress.c_str())) {
        WIFI_LOGE("Mac address is invalid");
        macAddress = "";
        curConfig.SetRandomMac(macAddress);
        WifiSettings::GetInstance().SetHotspotConfig(curConfig, m_id);
        return;
    }
    curConfig.SetRandomMac(macAddress);
    WifiSettings::GetInstance().SetHotspotConfig(curConfig, m_id);
    WIFI_LOGI("Set randomMac: %{public}s", MacAnonymize(macAddress).c_str());
    if (WifiApHalInterface::GetInstance().SetConnectMacAddr(
        WifiConfigCenter::GetInstance().GetApIfaceName(), macAddress) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("%{public}s: failed to set ap MAC address", __func__);
    }
    return;
}

bool ApStartedState::SetCountry()
{
    std::string countryCode;
    WifiCountryCodeManager::GetInstance().GetWifiCountryCode(countryCode);
    if (countryCode.empty() || !IsValidCountryCode(countryCode) ||
        WifiApHalInterface::GetInstance().SetWifiCountryCode(WifiConfigCenter::GetInstance().GetApIfaceName(),
            countryCode) != WifiErrorNo::WIFI_HAL_OPT_OK) {
        WIFI_LOGE("set countryCode=%{public}s failed", countryCode.c_str());
        return false;
    }
    m_wifiCountryCode = std::move(countryCode);
    return true;
}

void ApStartedState::ProcessCmdHotspotChannelChanged(InternalMessagePtr msg)
{
    int freq = msg->GetParam1();
    int channel = TransformFrequencyIntoChannel(freq);
    WIFI_LOGI("%{public}s: update channel to %{public}d", __func__, channel);
    if (channel == -1) {
        return;
    }
    WifiSettings::GetInstance().GetHotspotConfig(m_hotspotConfig, m_id);
    m_hotspotConfig.SetChannel(channel);
    WifiSettings::GetInstance().SetHotspotConfig(m_hotspotConfig, m_id);
}

void ApStartedState::ProcessCmdAssociatedStaChanged(InternalMessagePtr msg)
{
    int event = msg->GetParam1();
    StationInfo staInfo;
    if (!msg->GetMessageObj(staInfo)) {
        WIFI_LOGE("%{public}s:failed to get station info.", __func__);
        return;
    }
    if (staInfo.bssid.empty()) {
        WIFI_LOGE("%{public}s:bssid is empty.", __func__);
        return;
    }
    WIFI_LOGI("%{public}s: associated station event: %{public}d", __func__, event);
    if (event == HAL_CBK_CMD_STA_JOIN) {
        curAssocMacList.insert(staInfo.bssid);
        m_ApStateMachine.MessageExecutedLater(static_cast<int>(ApStatemachineEvent::CMD_STATION_JOIN),
            staInfo, STA_JOIN_HANDLE_DELAY);
        return;
    }
    if (event == HAL_CBK_CMD_STA_LEAVE) {
        if (curAssocMacList.find(staInfo.bssid) != curAssocMacList.end()) {
            curAssocMacList.erase(staInfo.bssid);
            WIFI_LOGI("%{public}s: delete station in curAssocMacList", __func__);
        }
        m_ApStateMachine.SendMessage(static_cast<int>(ApStatemachineEvent::CMD_STATION_LEAVE), staInfo);
    }
    return;
}

void ApStartedState::ProcessCmdEnableAp(InternalMessagePtr msg)
{
    do {
        if (!m_ApStateMachine.m_ApStationsManager.EnableAllBlockList()) {
            WIFI_LOGE("Set Blocklist failed.");
        }
        WIFI_LOGE("Singleton version has not nat and use %{public}s.", AP_INTF);
        if (!EnableInterfaceNat()) {
            break;
        }
        UpdatePowerMode();
        return;
    } while (0);
    WIFI_LOGI("Ap disabled, set softap toggled false");
    WifiConfigCenter::GetInstance().SetSoftapToggledState(false);
    m_ApStateMachine.SwitchState(&m_ApStateMachine.m_ApIdleState);
}

#ifndef OHOS_ARCH_LITE
void ApStartedState::SetEnhanceService(IEnhanceService* enhanceService)
{
    std::unique_lock<std::mutex> lock(enhanceServiceMutex_);
    enhanceService_ = enhanceService;
}
#endif
}  // namespace Wifi
}  // namespace OHOS
