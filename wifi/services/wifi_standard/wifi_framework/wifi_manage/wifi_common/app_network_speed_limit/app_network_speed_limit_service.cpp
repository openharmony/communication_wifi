/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "app_network_speed_limit_service.h"
#include "wifi_logger.h"
#include "wifi_app_parser.h"
#include "wifi_config_center.h"
#include "wifi_sta_hal_interface.h"
#include "app_mgr_client.h"
#include "speed_limit_configs_writer.h"
#include "wifi_app_state_aware.h"
#include "wifi_global_func.h"
#include "net_all_capabilities.h"
#include "net_supplier_info.h"
#include "wifi_service_manager.h"
#include "ienhance_service.h"

namespace OHOS {
namespace Wifi {

DEFINE_WIFILOG_LABEL("AppNetworkSpeedLimitService");
const std::string APP_NETWORK_SPEED_LIMIT_CLASS_NAME = "AppNetworkSpeedLimitService";

namespace {
    const int ON = 1;
    const int OFF = 0;
    const std::string ASYNC_WORK_NAME = "SendLimitInfo";
    const std::string LOW_LATENCY_EXIT_ASYNC_WORK_NAME = "LowLatencyExit";
    const std::string HANDLE_WIFI_CONNECT_CHANGED = "HandleWifiConnectStateChanged";
    const std::string HANDLE_FOREGROUND_APP_CHANGED = "HandleForegroundAppChangedAction";
    const std::string HANDLE_PROCESS_CREATED_EVENT = "HandleProcessCreatedEvent";
    const std::string LIMIT_SPEED = "LimitSpeed";
    const std::string RECEIVE_NETWORK_CONTROL = "ReceiveNetworkControlInfo";
    const std::string FEATURE_GAME_NO_SLEEP = "GameNoSleep";
    const std::string FEATURE_VPN_NO_LIMIT = "VpnNoLimit";
    const int GAME_BOOST_ENABLE = 1;
    const int GAME_BOOST_DISABLE = 0;
    const int BOOST_UDP_TYPE = 17;
    constexpr int64_t LOW_LATENCY_EXIT_TIMEOUT = 3 * 60 * 1000;
}

AppNetworkSpeedLimitService::AppNetworkSpeedLimitService()
{
    Init();
}

AppNetworkSpeedLimitService::~AppNetworkSpeedLimitService() {}


AppNetworkSpeedLimitService &AppNetworkSpeedLimitService::GetInstance()
{
    static AppNetworkSpeedLimitService instance;
    return instance;
}

StaServiceCallback AppNetworkSpeedLimitService::GetStaCallback() const
{
    return m_staCallback;
}

void AppNetworkSpeedLimitService::Init()
{
    m_staCallback.callbackModuleName = APP_NETWORK_SPEED_LIMIT_CLASS_NAME;
    m_staCallback.OnStaConnChanged = [this](OperateResState state, const WifiLinkedInfo &info, int instId) {
        this->DealStaConnChanged(state, info, instId);
    };
    ResetPowerMode();
    InitWifiLimitRecord();
    InitCellarLimitRecord();
    std::string delayTime = AppParser::GetInstance().GetAsyncLimitSpeedDelayTime();
    m_delayTime = CheckDataTolonglong(delayTime);
    m_asyncSendLimit = std::make_unique<WifiEventHandler>("StartSendLimitInfoThread");
    if (IsTopNLimitSpeedSceneInNow()) {
        WIFI_LOGI("%{public}s the current foreground application is TopN.", __FUNCTION__);
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_KEY_FG_APP, BG_LIMIT_LEVEL_3, m_isHighPriorityTransmit);
    }
    WIFI_LOGD("AppNetworkSpeedLimitService initialization complete.");
}

void AppNetworkSpeedLimitService::InitWifiLimitRecord()
{
    m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_GAME] = BG_LIMIT_OFF;
    m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_STREAM] = BG_LIMIT_OFF;
    m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP] = BG_LIMIT_OFF;
    m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_KEY_FG_APP] = BG_LIMIT_OFF;
}

void AppNetworkSpeedLimitService::InitCellarLimitRecord()
{
    m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_MODULE_FOREGROUND_OPT] = BG_LIMIT_OFF;
}

void AppNetworkSpeedLimitService::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId)
{
    if (state == OperateResState::DISCONNECT_DISCONNECTED) {
        HandleWifiConnectStateChanged(false);
    } else if (state == OperateResState::CONNECT_AP_CONNECTED) {
        HandleWifiConnectStateChanged(true);
    }
}

void AppNetworkSpeedLimitService::HandleWifiConnectStateChanged(const bool isWifiConnected)
{
    WIFI_LOGI("%{public}s, isWifiConnected=%{public}d", __FUNCTION__, isWifiConnected);
    m_isWifiConnected = isWifiConnected;
    AsyncParamInfo asyncParamInfo;
    asyncParamInfo.funcName = __FUNCTION__;
    AsyncLimitSpeed(asyncParamInfo);
}

void AppNetworkSpeedLimitService::HandleForegroundAppChangedAction(const AppExecFwk::AppStateData &appStateData)
{
    if (appStateData.state == static_cast<int>(AppExecFwk::AppProcessState::APP_STATE_FOREGROUND) &&
        appStateData.isFocused) {
        AsyncParamInfo asyncParamInfo;
        asyncParamInfo.funcName = __FUNCTION__;
        asyncParamInfo.bundleName = appStateData.bundleName;
        AsyncLimitSpeed(asyncParamInfo);
    }
}

void AppNetworkSpeedLimitService::HandleProcessCreatedEvent(const AppExecFwk::ProcessData &processData)
{
    if (processData.state == AppExecFwk::AppProcessState::APP_STATE_FOREGROUND) {
        return;
    }
    if (!ShouldLimitSpeedInBackground(processData.bundleName)) {
        return;
    }
    if (m_bgUidSet.count(processData.uid) > 0) {
        return;
    }
    AsyncParamInfo asyncParamInfo;
    asyncParamInfo.funcName = HANDLE_PROCESS_CREATED_EVENT;
    asyncParamInfo.bundleName = processData.bundleName;
    AsyncLimitSpeed(asyncParamInfo);
}

bool AppNetworkSpeedLimitService::ShouldLimitSpeedInBackground(const std::string &bundleName)
{
    for (auto &record : m_bgLimitRecordMap) {
        if (!CheckNetWorkCanBeLimited(record.first) || record.second == BG_LIMIT_OFF) {
            continue;
        }
        if (IsLimitSpeedBgApp(record.first, bundleName, m_isHighPriorityTransmit)) {
            return true;
        }
    }
    return false;
}

void AppNetworkSpeedLimitService::LimitSpeed(const int controlId, const int limitMode)
{
    WIFI_LOGI("%{public}s enter, controlId=%{public}d, limitMode=%{public}d", __FUNCTION__, controlId, limitMode);
    if (controlId == BgLimitControl::BG_LIMIT_CONTROL_ID_TEMP) {
        // ignore high temp limit speed
        return;
    }
    AsyncParamInfo asyncParamInfo;
    asyncParamInfo.funcName = __FUNCTION__;
    asyncParamInfo.controlId = controlId;
    asyncParamInfo.limitMode = limitMode;
    AsyncLimitSpeed(asyncParamInfo);
}

int AppNetworkSpeedLimitService::GetBgLimitMaxMode()
{
    if (m_bgLimitRecordMap.empty()) {
        WIFI_LOGE("m_bgLimitRecordMap is empty.\n");
        return -1;
    }
    int maxMode = 0;
    std::map<int, int>::iterator iter;
    for (iter = m_bgLimitRecordMap.begin(); iter != m_bgLimitRecordMap.end(); ++iter) {
        if (!CheckNetWorkCanBeLimited(iter->first)) {
            continue;
        }
        if (iter->second > maxMode) {
            maxMode = iter->second;
        }
    }
    return maxMode;
}

ErrCode AppNetworkSpeedLimitService::GetAppList(std::vector<AppExecFwk::RunningProcessInfo> &appList, bool getFgAppFlag)
{
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    if (WifiAppStateAware::GetInstance().GetProcessRunningInfos(infos) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetProcessRunningInfosByUserId failed.");
        return WIFI_OPT_FAILED;
    }
    if (getFgAppFlag) {
        for (auto iter = infos.begin(); iter != infos.end(); ++iter) {
            if (iter->state_ == AppExecFwk::AppProcessState::APP_STATE_FOREGROUND &&
                iter->isFocused) {
                appList.push_back(*iter);
            }
        }
    } else {
        for (auto iter = infos.begin(); iter != infos.end(); ++iter) {
            if (iter->state_ == AppExecFwk::AppProcessState::APP_STATE_BACKGROUND
                || iter->state_ == AppExecFwk::AppProcessState::APP_STATE_CREATE
                || iter->state_ == AppExecFwk::AppProcessState::APP_STATE_READY) {
                appList.push_back(*iter);
            }
        }
    }

    return WIFI_OPT_SUCCESS;
}

int AppNetworkSpeedLimitService::GetAncoAppList(std::vector<WifiNetworkControlInfo>& ancoAppList, bool getFgAppFlag)
{
    if (getFgAppFlag) {
        for (auto iter = m_AncoAppInfos.begin(); iter != m_AncoAppInfos.end(); ++iter) {
            if (iter->second.state == AncoAppState::ANCO_APP_STATE_FOREGROUND) {
                ancoAppList.push_back(iter->second);
            }
        }
    } else {
        for (auto iter = m_AncoAppInfos.begin(); iter != m_AncoAppInfos.end(); ++iter) {
            if (iter->second.state == AncoAppState::ANCO_APP_STATE_BACKGROUND) {
                ancoAppList.push_back(iter->second);
            }
        }
    }
    return 0;
}
 
bool AppNetworkSpeedLimitService::CheckNetWorkCanBeLimited(const int controlId)
{
    switch (controlId) {
        case BgLimitControl::BG_LIMIT_CONTROL_ID_GAME:
            return true;
        case BgLimitControl::BG_LIMIT_CONTROL_ID_STREAM:
            return true;
        case BgLimitControl::BG_LIMIT_CONTROL_ID_TEMP:
            return m_isWifiConnected;
        case BgLimitControl::BG_LIMIT_CONTROL_ID_KEY_FG_APP:
            return true;
        case BgLimitControl::BG_LIMIT_CONTROL_ID_MODULE_FOREGROUND_OPT:
            return true;
        case BgLimitControl::BG_LIMIT_CONTROL_ID_VIDEO_CALL:
            return true;
        default:
            break;
    }
    return false;
}

void AppNetworkSpeedLimitService::UpdateSpeedLimitConfigs(const int enable)
{
    m_bgUidSet.clear();
    m_bgPidSet.clear();
    m_fgUidSet.clear();
    if (m_limitSpeedMode == BgLimitLevel::BG_LIMIT_OFF) {
        m_bgUidSet.insert(UNKNOWN_UID);
        m_bgPidSet.insert(UNKNOWN_UID);
        m_fgUidSet.insert(UNKNOWN_UID);
        return;
    }
    std::vector<AppExecFwk::RunningProcessInfo> bgAppList;
    std::vector<WifiNetworkControlInfo> bgAncoAppList;
    if (GetAppList(bgAppList, false) < 0) {
        WIFI_LOGE("Get background app list fail.");
    }
    GetAncoAppList(bgAncoAppList, false);
    for (auto &record : m_bgLimitRecordMap) {
        if (!CheckNetWorkCanBeLimited(record.first) || record.second == BG_LIMIT_OFF) {
            continue;
        }
        for (auto iter = bgAppList.begin(); iter != bgAppList.end(); ++iter) {
            if (IsLimitSpeedBgApp(record.first, *iter, enable)) {
                m_bgUidSet.insert(iter->uid_);
                m_bgPidSet.insert(iter->pid_);
            }
        }
        for (auto iter = bgAncoAppList.begin(); iter != bgAncoAppList.end(); ++iter) {
            if (IsLimitSpeedBgApp(record.first, iter->bundleName, enable)) {
                m_bgUidSet.insert(iter->uid);
            }
        }
    }
    std::vector<AppExecFwk::RunningProcessInfo> fgAppList;
    std::vector<WifiNetworkControlInfo> fgAncoAppList;
    if (GetAppList(fgAppList, true) < 0) {
        WIFI_LOGE("Get foreground app list fail.");
    }
    GetAncoAppList(fgAncoAppList, true);
    for (auto iter = fgAppList.begin(); iter != fgAppList.end(); ++iter) {
        m_fgUidSet.insert(iter->uid_);
    }
    for (auto iter = fgAncoAppList.begin(); iter != fgAncoAppList.end(); ++iter) {
        m_fgUidSet.insert(iter->uid);
    }
    FilterLimitSpeedConfigs();
}

bool AppNetworkSpeedLimitService::IsLimitSpeedBgApp(const int controlId, const std::string &bundleName,
    const int enable)
{
    switch (controlId) {
        case BgLimitControl::BG_LIMIT_CONTROL_ID_GAME:
            if (enable == GAME_BOOST_ENABLE) {
                return AppParser::GetInstance().IsLiveStreamApp(bundleName) ? false : true;
            } else {
                return AppParser::GetInstance().IsGameBackgroundLimitApp(bundleName);
            }
        case BgLimitControl::BG_LIMIT_CONTROL_ID_STREAM:
        case BgLimitControl::BG_LIMIT_CONTROL_ID_TEMP:
            return AppParser::GetInstance().IsHighTempLimitSpeedApp(bundleName);
        case BgLimitControl::BG_LIMIT_CONTROL_ID_KEY_FG_APP:
            return AppParser::GetInstance().IsKeyBackgroundLimitApp(bundleName);
        case BgLimitControl::BG_LIMIT_CONTROL_ID_MODULE_FOREGROUND_OPT:
            return true;
        default:
            break;
    }
    WIFI_LOGI("%{public}s invalid controlId", __FUNCTION__);
    return false;
}

bool AppNetworkSpeedLimitService::IsLimitSpeedBgApp(const int controlId,
    const AppExecFwk::RunningProcessInfo &processInfo, const int enable)
{
    for (auto &name : processInfo.bundleNames) {
        if (IsLimitSpeedBgApp(controlId, name, enable)) {
            return true;
        }
    }
    return false;
}

void AppNetworkSpeedLimitService::AsyncLimitSpeed(const AsyncParamInfo &asyncParamInfo)
{
    m_asyncSendLimit->PostAsyncTask([asyncParamInfo, this]() {
            this->HandleRequest(asyncParamInfo);
    });
}

void AppNetworkSpeedLimitService::HandleRequest(const AsyncParamInfo &asyncParamInfo)
{
    if (asyncParamInfo.funcName == HANDLE_WIFI_CONNECT_CHANGED) {
        WifiConnectStateChanged();
    } else if (asyncParamInfo.funcName == HANDLE_FOREGROUND_APP_CHANGED) {
        ForegroundAppChangedAction(asyncParamInfo.bundleName);
    } else if (asyncParamInfo.funcName == HANDLE_PROCESS_CREATED_EVENT) {
        BackgroundAppChangedAction(asyncParamInfo.bundleName);
    } else if (asyncParamInfo.funcName == LIMIT_SPEED) {
        SendLimitCmd2Drv(asyncParamInfo.controlId, asyncParamInfo.limitMode, m_isHighPriorityTransmit);
    } else if (asyncParamInfo.funcName == RECEIVE_NETWORK_CONTROL) {
        if (asyncParamInfo.networkControlInfo.sceneId == BG_LIMIT_CONTROL_ID_GAME) {
            GameNetworkSpeedLimitConfigs(asyncParamInfo.networkControlInfo);
            WifiConfigCenter::GetInstance().SetNetworkControlInfo(asyncParamInfo.networkControlInfo);
        } else if (asyncParamInfo.networkControlInfo.sceneId == BG_LIMIT_CONTROL_ID_VIDEO_CALL) {
            VideoCallNetworkSpeedLimitConfigs(asyncParamInfo.networkControlInfo);
        } else if (asyncParamInfo.networkControlInfo.sceneId == BG_LIMIT_CONTROL_ID_LOW_LATENCY) {
            LowLatencyNetworkSpeedLimitConfigs(asyncParamInfo.networkControlInfo);
        } else {
            UpdateAncoAppInfos(asyncParamInfo.networkControlInfo);
            UpdateNoSpeedLimitConfigs(asyncParamInfo.networkControlInfo);
        }
    }
}

void AppNetworkSpeedLimitService::SendLimitCmd2Drv(const int controlId, const int limitMode, const int enable,
    const int uid)
{
    WIFI_LOGD("enter SendLimitCmd2Drv");
    m_bgLimitRecordMap[controlId] = limitMode;
    // Skip speed limit if VPN is connected
    if (isVpnConnected_) {
        WIFI_LOGD("%{public}s VPN is connected, cancel speed limit setting", __FUNCTION__);
        return;
    }
    m_limitSpeedMode = GetBgLimitMaxMode();
    int64_t delayTime = 0;
    // Downshifting without delay, upshifting with delay.
    if (m_limitSpeedMode >= m_lastLimitSpeedMode) {
        delayTime = m_delayTime;
    }
    WIFI_LOGD("Current maximum speed limit m_limitSpeedMode: %{public}d.", m_limitSpeedMode);
    m_asyncSendLimit->RemoveAsyncTask(ASYNC_WORK_NAME);
    m_asyncSendLimit->PostAsyncTask([uid, enable, this]() {
            this->UpdateSpeedLimitConfigs(enable);
            this->HighPriorityTransmit(uid, BOOST_UDP_TYPE, enable);
            this->SendLimitInfo();
        }, ASYNC_WORK_NAME, delayTime);
}

void AppNetworkSpeedLimitService::SendLimitInfo()
{
    if (m_limitSpeedMode != m_lastLimitSpeedMode) {
        int ret = SetBgLimitMode(m_limitSpeedMode);
        if (ret < 0) {
            WIFI_LOGE("SetBgLimitMode failed, ret = %{public}d.", ret);
            return;
        }
        m_lastLimitSpeedMode = m_limitSpeedMode;
    }

    if (m_lastBgUidSet != m_bgUidSet) {
        if (m_bgUidSet.empty()) {
            m_bgUidSet.insert(UNKNOWN_UID);
        }
        SetBgLimitIdList(std::vector<int>(m_bgUidSet.begin(), m_bgUidSet.end()), SET_BG_UID);
        m_lastBgUidSet = m_bgUidSet;
    }

    if (m_lastBgPidSet != m_bgPidSet) {
        if (m_bgPidSet.empty()) {
            m_bgPidSet.insert(UNKNOWN_UID);
        }
        SetBgLimitIdList(std::vector<int>(m_bgPidSet.begin(), m_bgPidSet.end()), SET_BG_PID);
        m_lastBgPidSet = m_bgPidSet;
    }

    if (m_lastFgUidSet != m_fgUidSet) {
        if (m_fgUidSet.empty()) {
            m_fgUidSet.insert(UNKNOWN_UID);
        }
        SetBgLimitIdList(std::vector<int>(m_fgUidSet.begin(), m_fgUidSet.end()), SET_FG_UID);
        m_lastFgUidSet = m_fgUidSet;
    }

    LogSpeedLimitConfigs();
}

void AppNetworkSpeedLimitService::LogSpeedLimitConfigs()
{
    std::string recordsStr;
    for (auto &record : m_bgLimitRecordMap) {
        recordsStr += std::to_string(record.first);
        recordsStr += ":";
        recordsStr += std::to_string(record.second);
        recordsStr += ",";
    }
    WIFI_LOGI("%{public}s speed limit records= %{public}s, limitMode: %{public}d, m_wifiConnected: %{public}d",
        __FUNCTION__, recordsStr.c_str(), m_lastLimitSpeedMode, m_isWifiConnected.load());
    WIFI_LOGI("%{public}s bgUidSet: %{public}s; bgPidSet: %{public}s; fgUidSet: %{public}s", __FUNCTION__,
        JoinVecToString(std::vector<int>(m_lastBgUidSet.begin(), m_lastBgUidSet.end()), ",").c_str(),
        JoinVecToString(std::vector<int>(m_lastBgPidSet.begin(), m_lastBgPidSet.end()), ",").c_str(),
        JoinVecToString(std::vector<int>(m_lastFgUidSet.begin(), m_lastFgUidSet.end()), ",").c_str());
}

void AppNetworkSpeedLimitService::ReceiveNetworkControlInfo(const WifiNetworkControlInfo &networkControlInfo)
{
    AsyncParamInfo asyncParamInfo;
    asyncParamInfo.funcName = __FUNCTION__;
    asyncParamInfo.networkControlInfo = networkControlInfo;
    AsyncLimitSpeed(asyncParamInfo);
}

void AppNetworkSpeedLimitService::UpdateAncoAppInfos(const WifiNetworkControlInfo &networkControlInfo)
{
    if (networkControlInfo.sceneId == BG_LIMIT_CONTROL_ID_KEY_FG_APP) {
        int uid = networkControlInfo.uid;
        if (m_AncoAppInfos.find(uid) == m_AncoAppInfos.end()) {
            if (networkControlInfo.state != AncoAppState::ANCO_APP_STATE_DIED) {
                m_AncoAppInfos.insert({networkControlInfo.uid, networkControlInfo});
            }
        } else {
            if (networkControlInfo.state == AncoAppState::ANCO_APP_STATE_DIED) {
                m_AncoAppInfos.erase(uid);
            } else if (m_AncoAppInfos[uid].state != networkControlInfo.state) {
                m_AncoAppInfos[uid].state = networkControlInfo.state;
            }
        }
    }
}
 
void AppNetworkSpeedLimitService::UpdateNoSpeedLimitConfigs(const WifiNetworkControlInfo &networkControlInfo)
{
    if (networkControlInfo.state == ON) {
        if (networkControlInfo.sceneId == BG_LIMIT_CONTROL_ID_AUDIO_PLAYBACK) {
            WIFI_LOGI("%{public}s No limit speed uid: %{public}d, pid: %{public}d.", __FUNCTION__,
                networkControlInfo.uid, networkControlInfo.pid);
            m_bgAudioPlaybackUidSet.insert(networkControlInfo.uid);
            m_bgAudioPlaybackPidSet.insert(networkControlInfo.pid);
        } else if (networkControlInfo.sceneId == BG_LIMIT_CONTROL_ID_WINDOW_VISIBLE) {
            WIFI_LOGI("%{public}s No limit speed uid: %{public}d, pid: %{public}d.", __FUNCTION__,
                networkControlInfo.uid, networkControlInfo.pid);
            m_additionalWindowUidSet.insert(networkControlInfo.uid);
            m_additionalWindowPidSet.insert(networkControlInfo.pid);
        }
    } else if (networkControlInfo.state == OFF) {
        if (networkControlInfo.sceneId == BG_LIMIT_CONTROL_ID_AUDIO_PLAYBACK) {
            WIFI_LOGI("%{public}s remove no limit speed uid: %{public}d, pid: %{public}d.", __FUNCTION__,
                networkControlInfo.uid, networkControlInfo.pid);
            m_bgAudioPlaybackUidSet.erase(networkControlInfo.uid);
            m_bgAudioPlaybackPidSet.erase(networkControlInfo.pid);
        } else if (networkControlInfo.sceneId == BG_LIMIT_CONTROL_ID_WINDOW_VISIBLE) {
            WIFI_LOGI("%{public}s remove no limit speed uid: %{public}d, pid: %{public}d.", __FUNCTION__,
                networkControlInfo.uid, networkControlInfo.pid);
            m_additionalWindowUidSet.erase(networkControlInfo.uid);
            m_additionalWindowPidSet.erase(networkControlInfo.pid);
        }
    }
    // update speed limit info
    if (m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_KEY_FG_APP] != BG_LIMIT_OFF ||
        m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_GAME] != BG_LIMIT_OFF ||
        m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP] != BG_LIMIT_OFF) {
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_KEY_FG_APP, m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_KEY_FG_APP],
            m_isHighPriorityTransmit);
    }
}

void AppNetworkSpeedLimitService::FilterLimitSpeedConfigs()
{
    for (const auto& windwoUid : m_additionalWindowUidSet) {
        m_bgUidSet.erase(windwoUid);
        m_fgUidSet.insert(windwoUid);
    }
    for (const auto& windwoPid : m_additionalWindowPidSet) {
        m_bgPidSet.erase(windwoPid);
    }
    for (const auto& audioUid : m_bgAudioPlaybackUidSet) {
        m_bgUidSet.erase(audioUid);
    }
    for (const auto& audioPid : m_bgAudioPlaybackPidSet) {
        m_bgPidSet.erase(audioPid);
    }
}

void AppNetworkSpeedLimitService::WifiConnectStateChanged()
{
    // Reset power mode on WiFi disconnect
    if (!m_isWifiConnected) {
        ResetPowerMode();
    }
    if (m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP] != BG_LIMIT_OFF) {
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_TEMP, m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP],
            m_isHighPriorityTransmit);
    }
}

bool AppNetworkSpeedLimitService::IsTopNLimitSpeedSceneInNow()
{
    std::vector<AppExecFwk::RunningProcessInfo> fgAppList;
    if (GetAppList(fgAppList, true) < 0) {
        WIFI_LOGE("Get foreground app list fail.");
        return false;
    }

    for (auto& foregroundApp : fgAppList) {
        if (AppParser::GetInstance().IsKeyForegroundApp(foregroundApp.processName_)) {
            WIFI_LOGD("Current TopN scenario.");
            return true;
        }
    }
    return false;
}

void AppNetworkSpeedLimitService::ForegroundAppChangedAction(const std::string &bundleName)
{
    // Check and reset power mode on foreground app change
    CheckAndResetGamePowerMode(bundleName);
    if (m_isWifiConnected && m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP] != BG_LIMIT_OFF) {
        WIFI_LOGI("%{public}s high temp speed limit is running, update background app list", __FUNCTION__);
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_TEMP, m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP],
            m_isHighPriorityTransmit);
    }
    // don't distinguishing between WiFi and cellular links
    if (AppParser::GetInstance().IsKeyForegroundApp(bundleName)) {
        WIFI_LOGI("%{public}s top app speed limit is running, update background app list", __FUNCTION__);
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_KEY_FG_APP, BG_LIMIT_LEVEL_3, m_isHighPriorityTransmit);
    } else if (m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_KEY_FG_APP] != BG_LIMIT_OFF) {
        WIFI_LOGI("%{public}s top app speed limit is turnning off, update background app list", __FUNCTION__);
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_KEY_FG_APP, BG_LIMIT_OFF, m_isHighPriorityTransmit);
    }
}

void AppNetworkSpeedLimitService::BackgroundAppChangedAction(const std::string &bundleName)
{
    WIFI_LOGI("%{public}s accept background limit speed bundleName: %{public}s ", __FUNCTION__, bundleName.c_str());
    if (m_isWifiConnected && m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP] != BG_LIMIT_OFF) {
        WIFI_LOGI("%{public}s high temp speed limit is running, update background app list", __FUNCTION__);
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_TEMP, m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP],
            m_isHighPriorityTransmit);
    }
    if (m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_KEY_FG_APP] != BG_LIMIT_OFF) {
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_KEY_FG_APP, BG_LIMIT_LEVEL_3, m_isHighPriorityTransmit);
    }
}

void AppNetworkSpeedLimitService::GameNetworkSpeedLimitConfigs(const WifiNetworkControlInfo &networkControlInfo)
{
    WIFI_LOGI("%{public}s enter game limit configs, game state is %{public}d", __FUNCTION__, networkControlInfo.state);
    switch (networkControlInfo.state) {
        case GameSceneId::MSG_GAME_STATE_START:
        case GameSceneId::MSG_GAME_STATE_FOREGROUND:
            SetActivePowerScenes(POWER_SCENE_GAME, false);
            if (AppParser::GetInstance().IsOverGameRtt(networkControlInfo.bundleName, networkControlInfo.rtt)) {
                SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_GAME, BG_LIMIT_LEVEL_7, GAME_BOOST_ENABLE,
                    networkControlInfo.uid);
            } else {
                SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_GAME, BG_LIMIT_LEVEL_3, GAME_BOOST_DISABLE,
                    networkControlInfo.uid);
            }
            break;
        case GameSceneId::MSG_GAME_STATE_BACKGROUND:
        case GameSceneId::MSG_GAME_STATE_END:
            SetActivePowerScenes(POWER_SCENE_GAME, false);
            SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_GAME, BG_LIMIT_OFF, GAME_BOOST_DISABLE, networkControlInfo.uid);
            break;
        case GameSceneId::MSG_GAME_ENTER_PVP_BATTLE:
            isFirstRtt_.store(true);
            SetActivePowerScenes(POWER_SCENE_GAME, true);
            SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_GAME, BG_LIMIT_LEVEL_7, GAME_BOOST_ENABLE, networkControlInfo.uid);
            break;
        case GameSceneId::MSG_GAME_EXIT_PVP_BATTLE:
            SetActivePowerScenes(POWER_SCENE_GAME, false);
            SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_GAME, BG_LIMIT_LEVEL_3, GAME_BOOST_DISABLE, networkControlInfo.uid);
            break;
        default:
            WIFI_LOGE("%{public}s there is no such state.", __FUNCTION__);
            break;
    }
}

void AppNetworkSpeedLimitService::LowLatencyNetworkSpeedLimitConfigs(const WifiNetworkControlInfo &networkControlInfo)
{
    WIFI_LOGI("%{public}s enter, low latency state is %{public}d", __FUNCTION__, networkControlInfo.state);
    switch (networkControlInfo.state) {
        case LowLatencySceneId::MSG_LOW_LATENCY_ENTER:
            m_asyncSendLimit->RemoveAsyncTask(LOW_LATENCY_EXIT_ASYNC_WORK_NAME);
            m_asyncSendLimit->PostAsyncTask([this]() {
                    this->SetActivePowerScenes(POWER_SCENE_LOW_LATENCY, false);
                }, LOW_LATENCY_EXIT_ASYNC_WORK_NAME, LOW_LATENCY_EXIT_TIMEOUT);
            SetActivePowerScenes(POWER_SCENE_LOW_LATENCY, true);
            break;
        case LowLatencySceneId::MSG_LOW_LATENCY_EXIT:
            m_asyncSendLimit->RemoveAsyncTask(LOW_LATENCY_EXIT_ASYNC_WORK_NAME);
            SetActivePowerScenes(POWER_SCENE_LOW_LATENCY, false);
            break;
        default:
            WIFI_LOGE("%{public}s there is no such state.", __FUNCTION__);
            break;
    }
}

void AppNetworkSpeedLimitService::VideoCallNetworkSpeedLimitConfigs(const WifiNetworkControlInfo &networkControlInfo)
{
    if (networkControlInfo.state == ON) {
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_VIDEO_CALL, BG_LIMIT_LEVEL_7, m_isHighPriorityTransmit);
    } else {
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_VIDEO_CALL, BG_LIMIT_OFF, m_isHighPriorityTransmit);
    }
}

void AppNetworkSpeedLimitService::HighPriorityTransmit(int uid, int protocol, int enable)
{
    if (m_isHighPriorityTransmit == enable || uid == -1) {
        WIFI_LOGI("%{public}s HighPriorityTransmit was setted %{public}d or uid == -1", __FUNCTION__, enable);
        return;
    }
    m_isHighPriorityTransmit = enable;
    WIFI_LOGI("%{public}s enter HighPriorityTransmit, enable is %{public}d.", __FUNCTION__, enable);
    WifiErrorNo ret = WifiStaHalInterface::GetInstance().SetDpiMarkRule(
        WifiConfigCenter::GetInstance().GetStaIfaceName(), uid, protocol, enable);
    if (ret != 0) {
        WIFI_LOGE("%{public}s highPriorityTransmit failed, ret = %{public}d.", __FUNCTION__, ret);
        return;
    }
}

void AppNetworkSpeedLimitService::HandleNetworkConnectivityChange(int32_t bearType, int32_t code)
{
    // Only handle VPN network events
    if (bearType != NetManagerStandard::NetBearType::BEARER_VPN) {
        WIFI_LOGD("%{public}s Non-VPN network event, bearType: %{public}d, ignored",
            __FUNCTION__, bearType);
        return;
    }

    // VPN event: directly update state based on connection code
    bool currentVpnState = (code == NetManagerStandard::NetConnState::NET_CONN_STATE_CONNECTED);
    bool preVpnState = isVpnConnected_.exchange(currentVpnState);
    if (preVpnState != currentVpnState) {
        WIFI_LOGI("%{public}s VPN connection state changed: %{public}d -> %{public}d",
            __FUNCTION__, preVpnState, currentVpnState);
        // Report VPN background no-speed-limit gain statistics
        ReportGameLatencyFeature(currentVpnState, FEATURE_VPN_NO_LIMIT);
    }
}

void AppNetworkSpeedLimitService::SetActivePowerScenes(PowerSceneFlag scene, bool active)
{
    if (!m_isWifiConnected && active) {
        WIFI_LOGI("Set power scenes %{public}d skipped: WiFi not connected.", static_cast<int>(scene));
        return;
    }

    uint32_t oldScenes = activePowerScenes_.load();
    uint32_t newScenes;
    if (active) {
        newScenes = oldScenes | static_cast<uint32_t>(scene);
    } else {
        newScenes = oldScenes & ~static_cast<uint32_t>(scene);
    }

    if (oldScenes == newScenes) {
        WIFI_LOGD("Set power scenes %{public}d skipped: Scenes has not changed.", static_cast<int>(scene));
        return;
    }

    WIFI_LOGI("Set power scenes %{public}d -> %{public}d.", static_cast<int>(oldScenes), static_cast<int>(newScenes));
    activePowerScenes_.store(newScenes);
    UpdatePowerModeByScenes();
}

void AppNetworkSpeedLimitService::UpdatePowerModeByScenes()
{
    int cachedMode = cachedPowerMode_.load();
    int targetMode = (activePowerScenes_.load() != POWER_SCENE_NONE) ? POWER_MODE_ON : POWER_MODE_OFF;
    if (cachedMode == targetMode) {
        WIFI_LOGD("Set power mode %{public}d skipped: Mode has not changed.", targetMode);
        return;
    }

    int frequency = POWER_MODE_FREQUENCY_DEFAULT;
    WifiErrorNo ret = WifiStaHalInterface::GetInstance().SetPmMode("wlan0", frequency, targetMode);
    if (ret != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("Set power mode failed, targetMode: %{public}d, ret: %{public}d.", targetMode, ret);
    } else {
        cachedPowerMode_.store(targetMode);
        // Report game battle no-sleep gain statistics
        ReportGameLatencyFeature(targetMode == POWER_MODE_ON, FEATURE_GAME_NO_SLEEP);
        WIFI_LOGI("Set power mode %{public}d -> %{public}d.", cachedMode, targetMode);
    }
}

void AppNetworkSpeedLimitService::ResetPowerMode()
{
    activePowerScenes_.store(POWER_SCENE_NONE);
    if (cachedPowerMode_.load() == POWER_MODE_OFF) {
        return;
    }
    int frequency = POWER_MODE_FREQUENCY_DEFAULT;
    WifiErrorNo ret = WifiStaHalInterface::GetInstance().SetPmMode("wlan0", frequency, POWER_MODE_OFF);
    if (ret != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("Reset power mode failed, ret: %{public}d.", ret);
    } else {
        cachedPowerMode_.store(POWER_MODE_OFF);
        WIFI_LOGI("Reset power mode to OFF.");
    }
}
 
void AppNetworkSpeedLimitService::CheckAndResetGamePowerMode(const std::string &bundleName)
{
    if ((activePowerScenes_.load() & POWER_SCENE_GAME) == 0) {
        return;
    }
    bool isGame = AppParser::GetInstance().IsRssGameApp(bundleName);
    if (isGame) {
        WIFI_LOGD("%{public}s Foreground app [%{public}s] is game, keep power mode no-sleep",
            __FUNCTION__, bundleName.c_str());
        return;
    }
    // Foreground app is not a game, but in no-sleep mode
    WIFI_LOGI("%{public}s Non-game app [%{public}s], resetting power mode to normal sleep",
        __FUNCTION__, bundleName.c_str());
    SetActivePowerScenes(POWER_SCENE_GAME, false);
}

void AppNetworkSpeedLimitService::UpdateGameRttData(int rtt)
{
    if (!isFirstRtt_.exchange(false)) {
        WIFI_LOGD("%{public}s not waiting for first rtt, ignore", __FUNCTION__);
        return;
    }
    
    WIFI_LOGI("%{public}s first rtt received: %{public}d", __FUNCTION__, rtt);
    if (rtt > 0) {
        WIFI_LOGI("%{public}s online PVP mode detected, keep no-sleep", __FUNCTION__);
    } else {
        WIFI_LOGI("%{public}s single player mode detected, allow sleep", __FUNCTION__);
        SetActivePowerScenes(POWER_SCENE_GAME, false);
    }
}

void AppNetworkSpeedLimitService::ReportGameLatencyFeature(bool enabled, const std::string& featureName)
{
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGD("%{public}s: pEnhanceService is null", __FUNCTION__);
        return;
    }
    pEnhanceService->SetGameLatencyFeatureEnabled(enabled, featureName);
}
} // namespace Wifi
} // namespace OHOS