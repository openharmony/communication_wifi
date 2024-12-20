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
#include "app_mgr_client.h"
#include "speed_limit_configs_writer.h"
#include "wifi_app_state_aware.h"

namespace OHOS {
namespace Wifi {

DEFINE_WIFILOG_LABEL("AppNetworkSpeedLimitService");
const std::string APP_NETWORK_SPEED_LIMIT_CLASS_NAME = "AppNetworkSpeedLimitService";

namespace {
    const int ON = 1;
    const int OFF = 0;
    const std::string ASYNC_WORK_NAME = "SendLimitInfo";
    const std::string HANDLE_WIFI_CONNECT_CHANGED = "HandleWifiConnectStateChanged";
    const std::string HANDLE_FOREGROUND_APP_CHANGED = "HandleForegroundAppChangedAction";
    const std::string LIMIT_SPEED = "LimitSpeed";
    const std::string RECEIVE_NETWORK_CONTROL = "ReceiveNetworkControlInfo";
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
    InitWifiLimitRecord();
    InitCellarLimitRecord();
    m_delayTime = AppParser::GetInstance().GetAsyncLimitSpeedDelayTime();
    m_asyncSendLimit = std::make_unique<WifiEventHandler>("StartSendLimitInfoThread");
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

void AppNetworkSpeedLimitService::LimitSpeed(const int controlId, const int limitMode)
{
    WIFI_LOGI("%{public}s enter, controlId=%{public}d, limitMode=%{public}d", __FUNCTION__, controlId, limitMode);
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
            if (iter->state_ == AppExecFwk::AppProcessState::APP_STATE_BACKGROUND) {
                appList.push_back(*iter);
            }
        }
    }

    return WIFI_OPT_SUCCESS;
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
        default:
            break;
    }
    return false;
}

void AppNetworkSpeedLimitService::UpdateSpeedLimitConfigs(const int controlId, const int limitMode)
{
    m_bgLimitRecordMap[controlId] = limitMode;
    m_bgUidSet.clear();
    m_bgPidSet.clear();
    m_fgUidSet.clear();
    m_limitSpeedMode = GetBgLimitMaxMode();
    if (m_limitSpeedMode == BgLimitLevel::BG_LIMIT_OFF) {
        m_bgUidSet.insert(UNKNOWN_UID);
        m_bgPidSet.insert(UNKNOWN_UID);
        m_fgUidSet.insert(UNKNOWN_UID);
        return;
    }
    std::vector<AppExecFwk::RunningProcessInfo> bgAppList;
    if (GetAppList(bgAppList, false) < 0) {
        WIFI_LOGE("Get background app list fail.");
    }
    for (auto &record : m_bgLimitRecordMap) {
        if (!CheckNetWorkCanBeLimited(record.first) || record.second == BG_LIMIT_OFF) {
            continue;
        }
        for (auto iter = bgAppList.begin(); iter != bgAppList.end(); ++iter) {
            if (IsLimitSpeedBgApp(record.first, iter->processName_)) {
                m_bgUidSet.insert(iter->uid_);
                m_bgPidSet.insert(iter->pid_);
            }
        }
    }
    std::vector<AppExecFwk::RunningProcessInfo> fgAppList;
    if (GetAppList(fgAppList, true) < 0) {
        WIFI_LOGE("Get foreground app list fail.");
    }
    for (auto iter = fgAppList.begin(); iter != fgAppList.end(); ++iter) {
        m_fgUidSet.insert(iter->uid_);
    }
    if (controlId == BG_LIMIT_CONTROL_ID_KEY_FG_APP &&
        m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP] == BG_LIMIT_OFF) {
        FilterLimitSpeedConfigs();
    }
}

bool AppNetworkSpeedLimitService::IsLimitSpeedBgApp(const int controlId, const std::string &bundleName)
{
    switch (controlId) {
        case BgLimitControl::BG_LIMIT_CONTROL_ID_GAME:
            return AppParser::GetInstance().IsBlackListApp(bundleName);
        case BgLimitControl::BG_LIMIT_CONTROL_ID_STREAM:
        case BgLimitControl::BG_LIMIT_CONTROL_ID_TEMP:
            return AppParser::GetInstance().IsHighTempLimitSpeedApp(bundleName);
        case BgLimitControl::BG_LIMIT_CONTROL_ID_KEY_FG_APP:
            return AppParser::GetInstance().IsBackgroundLimitApp(bundleName);
        case BgLimitControl::BG_LIMIT_CONTROL_ID_MODULE_FOREGROUND_OPT:
            return true;
        default:
            break;
    }
    WIFI_LOGI("%{public}s invalid controlId", __FUNCTION__);
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
    } else if (asyncParamInfo.funcName == LIMIT_SPEED) {
        SendLimitCmd2Drv(asyncParamInfo.controlId, asyncParamInfo.limitMode);
    } else if (asyncParamInfo.funcName == RECEIVE_NETWORK_CONTROL) {
        UpdateNoSpeedLimitConfigs(asyncParamInfo.networkControlInfo);
        if (m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_KEY_FG_APP] == BG_LIMIT_OFF) {
            return;
        }
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_KEY_FG_APP, m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_KEY_FG_APP]);
    }
}

void AppNetworkSpeedLimitService::SendLimitCmd2Drv(const int controlId, const int limitMode)
{
    m_asyncSendLimit->RemoveAsyncTask(ASYNC_WORK_NAME);
    m_asyncSendLimit->PostAsyncTask([controlId, limitMode, this]() {
            this->UpdateSpeedLimitConfigs(controlId, limitMode);
            this->SendLimitInfo();
        }, ASYNC_WORK_NAME, CheckDataTolonglong(m_delayTime));
}

void AppNetworkSpeedLimitService::SendLimitInfo()
{
    int ret = SetBgLimitMode(m_limitSpeedMode);
    if (ret < 0) {
        WIFI_LOGE("SetBgLimitMode failed, ret = %{public}d.", ret);
        return;
    }
    SetBgLimitIdList(std::vector<int>(m_bgUidSet.begin(), m_bgUidSet.end()), SET_BG_UID);
    SetBgLimitIdList(std::vector<int>(m_bgPidSet.begin(), m_bgPidSet.end()), SET_BG_PID);
    SetBgLimitIdList(std::vector<int>(m_fgUidSet.begin(), m_fgUidSet.end()), SET_FG_UID);
}

void AppNetworkSpeedLimitService::ReceiveNetworkControlInfo(const WifiNetworkControlInfo &networkControlInfo)
{
    if (!AppParser::GetInstance().IsBackgroundLimitApp(networkControlInfo.bundleName)) {
        WIFI_LOGD("%{public}s It's not speed limit scene.", __FUNCTION__);
        return;
    }
    AsyncParamInfo asyncParamInfo;
    asyncParamInfo.funcName = __FUNCTION__;
    asyncParamInfo.networkControlInfo = networkControlInfo;
    AsyncLimitSpeed(asyncParamInfo);
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
    if (m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP] != BG_LIMIT_OFF) {
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_TEMP, m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP]);
    }
}

void AppNetworkSpeedLimitService::ForegroundAppChangedAction(const std::string &bundleName)
{
    if (m_isWifiConnected && m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP] != BG_LIMIT_OFF) {
        WIFI_LOGI("%{public}s high temp speed limit is running, update background app list", __FUNCTION__);
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_TEMP, m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP]);
    }
    // don't distinguishing between WiFi and cellular links
    if (AppParser::GetInstance().IsKeyForegroundApp(bundleName)) {
        WIFI_LOGI("%{public}s top app speed limit is running, update background app list", __FUNCTION__);
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_KEY_FG_APP, BG_LIMIT_LEVEL_3);
    } else if (m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_KEY_FG_APP] != BG_LIMIT_OFF) {
        WIFI_LOGI("%{public}s top app speed limit is turnning off, update background app list", __FUNCTION__);
        SendLimitCmd2Drv(BG_LIMIT_CONTROL_ID_KEY_FG_APP, BG_LIMIT_OFF);
    }
}
} // namespace Wifi
} // namespace OHOS