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
#include "wifi_common_util.h"
#include "wifi_app_parser.h"
#include "wifi_settings.h"
#include "app_mgr_client.h"
#include "wifi_global_func.h"
#include "speed_limit_configs_writer.h"

namespace OHOS {
namespace Wifi {

DEFINE_WIFILOG_LABEL("AppNetworkSpeedLimitService");
const std::string APP_NETWORK_SPEED_LIMIT_CLASS_NAME = "AppNetworkSpeedLimitService";
constexpr const int APP_INFO_USERID = 100;

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
    using namespace std::placeholders;
    m_staCallback.callbackModuleName = APP_NETWORK_SPEED_LIMIT_CLASS_NAME;
    m_staCallback.OnStaConnChanged = std::bind(&AppNetworkSpeedLimitService::DealStaConnChanged, this, _1, _2, _3);
    InitWifiLimitRecord();
    InitCellarLimitRecord();
}

void AppNetworkSpeedLimitService::InitWifiLimitRecord()
{
    m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_GAME] = BG_LIMIT_OFF;
    m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_STREAM] = BG_LIMIT_OFF;
    m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP] = BG_LIMIT_OFF;
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
    if (m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP] != BG_LIMIT_OFF) {
        LimitSpeed(BG_LIMIT_CONTROL_ID_TEMP, m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP]);
    }
}

void AppNetworkSpeedLimitService::HandleForegroundAppChangedAction(const AppExecFwk::AppStateData &appStateData)
{
    if (appStateData.state == static_cast<int>(AppExecFwk::AppProcessState::APP_STATE_FOREGROUND) &&
        appStateData.isFocused) {
        if (m_isWifiConnected && m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP] != BG_LIMIT_OFF) {
            WIFI_LOGI("%{public}s high temp speed limit is running, update background app list", __FUNCTION__);
            LimitSpeed(BG_LIMIT_CONTROL_ID_TEMP, m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP]);
        }
    }
}

void AppNetworkSpeedLimitService::LimitSpeed(const int controlId, const int limitMode)
{
    WIFI_LOGI("%{public}s enter, controlId=%{public}d, limitMode=%{public}d", __FUNCTION__, controlId, limitMode);
    std::lock_guard<std::mutex> lock(m_mutex);
    UpdateSpeedLimitConfigs(controlId, limitMode);
    int ret = SetBgLimitMode(m_currentLimitMode);
    if (ret < 0) {
        WIFI_LOGE("SetBgLimitMode failed, ret = %{public}d.", ret);
        return;
    }
    SetBgLimitIdList(std::vector<int>(m_bgUidSet.begin(), m_bgUidSet.end()), SET_BG_UID);
    SetBgLimitIdList(std::vector<int>(m_bgPidSet.begin(), m_bgPidSet.end()), SET_BG_PID);
    SetBgLimitIdList(std::vector<int>(m_fgUidSet.begin(), m_fgUidSet.end()), SET_FG_UID);
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
    auto appMgrClient = std::make_unique<AppExecFwk::AppMgrClient>();
    appMgrClient->ConnectAppMgrService();
    AppExecFwk::AppMgrResultCode ret;
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    ret = appMgrClient->GetProcessRunningInfosByUserId(infos, APP_INFO_USERID);
    if (ret != AppExecFwk::AppMgrResultCode::RESULT_OK) {
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
        case BgLimitControl::BG_LIMIT_CONTROL_ID_MODULE_FOREGROUND_OPT:
            return true;
        default:
            break;
    }
    return false;
}

void AppNetworkSpeedLimitService::UpdateSpeedLimitConfigs(const int controlId, const int limitMode)
{
    m_bgUidSet.clear();
    m_bgPidSet.clear();
    m_fgUidSet.clear();
    m_bgLimitRecordMap[controlId] = limitMode;
    m_currentLimitMode = GetBgLimitMaxMode();
    if (m_currentLimitMode == BgLimitLevel::BG_LIMIT_OFF) {
        m_bgUidSet.insert(UNKNOWN_UID);
        m_bgPidSet.insert(UNKNOWN_UID);
        m_fgUidSet.insert(UNKNOWN_UID);
        LogSpeedLimitConfigs();
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
    WIFI_LOGI("%{public}s speed limit records= %{public}s, limitMode: %{public}d, m_isWifiConnected: %{public}d",
        __FUNCTION__, recordsStr.c_str(), m_currentLimitMode, m_isWifiConnected);
    WIFI_LOGI("%{public}s m_bgUidSet: %{public}s; m_bgPidSet: %{public}s; m_fgUidSet: %{public}s", __FUNCTION__,
        JoinVecToString(std::vector<int>(m_bgUidSet.begin(), m_bgUidSet.end()), ",").c_str(),
        JoinVecToString(std::vector<int>(m_bgPidSet.begin(), m_bgPidSet.end()), ",").c_str(),
        JoinVecToString(std::vector<int>(m_fgUidSet.begin(), m_fgUidSet.end()), ",").c_str());
}

bool AppNetworkSpeedLimitService::IsLimitSpeedBgApp(const int controlId, const std::string bundleName)
{
    switch (controlId) {
        case BgLimitControl::BG_LIMIT_CONTROL_ID_GAME:
            return AppParser::GetInstance().IsBlackListApp(bundleName);
        case BgLimitControl::BG_LIMIT_CONTROL_ID_STREAM:
        case BgLimitControl::BG_LIMIT_CONTROL_ID_TEMP:
            return AppParser::GetInstance().IsHighTempLimitSpeedApp(bundleName);
        case BgLimitControl::BG_LIMIT_CONTROL_ID_MODULE_FOREGROUND_OPT:
            return true;
        default:
            break;
    }
    WIFI_LOGI("%{public}s invalid controlId", __FUNCTION__);
    return false;
}

} // namespace Wifi
} // namespace OHOS