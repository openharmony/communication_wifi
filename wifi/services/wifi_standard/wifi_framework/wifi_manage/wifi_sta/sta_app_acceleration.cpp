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

#ifndef OHOS_ARCH_LITE
#include "sta_app_acceleration.h"
#include "wifi_logger.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_common_util.h"
#include "wifi_app_parser.h"
#include "wifi_settings.h"
#include "app_mgr_client.h"

namespace OHOS {
namespace Wifi {

DEFINE_WIFILOG_LABEL("StaAppAcceleration");
const std::string CLASS_NAME = "StaAppAcceleration";

constexpr const int POWER_SAVE_ENABLE = 3;
constexpr const int POWER_SAVE_DISABLE = 4;
constexpr const int GAME_BOOST_ENABLE = 1;
constexpr const int GAME_BOOST_DISABLE = 0;
constexpr const int BOOST_UDP_TYPE = 17;
constexpr const int UNKNOWN_UID = -1;
constexpr const int APP_INFO_USERID = 100;

StaAppAcceleration::StaAppAcceleration(int instId) : gameBoostingFlag(false)
{}

StaAppAcceleration::~StaAppAcceleration()
{}

StaAppAcceleration &StaAppAcceleration::GetInstance()
{
    static StaAppAcceleration gStaAppAcceleration;
    return gStaAppAcceleration;
}

ErrCode StaAppAcceleration::InitAppAcceleration()
{
    m_staCallback.callbackModuleName = CLASS_NAME;
    m_staCallback.OnStaConnChanged = DealStaConnChanged;

    mBgLimitRecordMap[BG_LIMIT_CONTROL_ID_GAME] = BG_LIMIT_OFF;
    mBgLimitRecordMap[BG_LIMIT_CONTROL_ID_STREAM] = BG_LIMIT_OFF;
    mBgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP] = BG_LIMIT_OFF;
    return WIFI_OPT_SUCCESS;
}

void StaAppAcceleration::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId)
{
    if (state == OperateResState::DISCONNECT_DISCONNECTED) {
        StaAppAcceleration::GetInstance().StopAllAppAcceleration();
    }
}

void StaAppAcceleration::HandleScreenStatusChanged(int screenState)
{
    WIFI_LOGI("Enter HandleScreenStatusChanged.\n");

    if (screenState == MODE_STATE_OPEN) {
        SetPowerSaveMode(POWER_SAVE_DISABLE);
    } else if (screenState == MODE_STATE_CLOSE) {
        SetPowerSaveMode(POWER_SAVE_ENABLE);
    } else {
        WIFI_LOGI("mode not handle.\n");
    }
}
void StaAppAcceleration::HandleForegroundAppChangedAction(const std::string &bundleName,
    int uid, int pid, const int state)
{
    if (state == static_cast<int>(AppExecFwk::AppProcessState::APP_STATE_FOREGROUND)) {
        if (AppParser::GetInstance().IsLowLatencyApp(bundleName)) {
            WIFI_LOGI("target app on the foreground.");
            StartGameBoost(uid);
        } else {
            StopGameBoost(uid);
        }
    }
    return;
}

void StaAppAcceleration::SetPowerSaveMode(int mode)
{
    if (mode != POWER_SAVE_DISABLE && POWER_SAVE_ENABLE) {
        WIFI_LOGI("Unsupported mode %{public}d.", mode);
        return;
    }

    WifiLinkedInfo linkedInfo;
    WifiSettings::GetInstance().GetLinkedInfo(linkedInfo);
    WifiErrorNo ret = WifiStaHalInterface::GetInstance().SetPowerSaveMode(linkedInfo.frequency, mode);
    if (ret != 0) {
        WIFI_LOGE("SetPowerSaveMode failed, ret = %{public}d.", ret);
        return;
    }
}

void StaAppAcceleration::StartGameBoost(int uid)
{
    if (!gameBoostingFlag) {
        WIFI_LOGI("start game boost.\n");
        SetGameBoostMode(GAME_BOOST_ENABLE, uid, BOOST_UDP_TYPE, BG_LIMIT_LEVEL_3);
        gameBoostingFlag = true;
        return;
    } else {
        WIFI_LOGE("game boost has started, not handle.\n");
        return;
    }
}

void StaAppAcceleration::StopGameBoost(int uid)
{
    if (gameBoostingFlag) {
        SetGameBoostMode(GAME_BOOST_DISABLE, uid, BOOST_UDP_TYPE, BG_LIMIT_OFF);
        gameBoostingFlag = false;
    }
}

void StaAppAcceleration::SetGameBoostMode(int enable, int uid, int type, int limitMode)
{
    HighPriorityTransmit(uid, type, enable);
    LimitedSpeed(BG_LIMIT_CONTROL_ID_GAME, enable, limitMode);
}

void StaAppAcceleration::HighPriorityTransmit(int uid, int protocol, int enable)
{
    WIFI_LOGI("Enter HighPriorityTransmit.\n");
    WifiErrorNo ret = WifiStaHalInterface::GetInstance().SetDpiMarkRule(uid, protocol, enable);
    if (ret != 0) {
        WIFI_LOGE("HighPriorityTransmit failed, ret = %{public}d.", ret);
        return;
    }
}

void StaAppAcceleration::LimitedSpeed(int controlId, int enable, int limitMode)
{
    WIFI_LOGI("LimitedSpeed: %{public}d, mode: %{public}d.", enable, limitMode);
    if (enable == 0) {
        std::vector<int> resetIds;
        resetIds.push_back(UNKNOWN_UID);
        int resetSize = resetIds.size();
        SetBgLimitIdList(resetIds, resetSize, SET_BG_UID);
        SetBgLimitIdList(resetIds, resetSize, SET_BG_PID);
        SetBgLimitIdList(resetIds, resetSize, SET_FG_UID);
        int ret = WifiStaHalInterface::GetInstance().SetBgLimitMode(BG_LIMIT_OFF);
        if (ret < 0) {
            WIFI_LOGE("SetBgLimitMode failed, ret = %{public}d.", ret);
        }
        return;
    }

    if (!mBgLimitRecordMap.empty()) {
        mBgLimitRecordMap[controlId] = (enable == 0) ? BG_LIMIT_OFF : limitMode;
    }

    int cmdMode = GetBgLimitMaxMode();
    std::vector<AppExecFwk::RunningProcessInfo> bgAppList;
    std::vector<int> bgUidList;
    std::vector<int> bgPidList;
    if (GetAppList(bgAppList, false) < 0) {
        WIFI_LOGE("Get background app list fail.");
    }
    int bgAppSize = bgAppList.size();
    for (auto iter = bgAppList.begin(); iter != bgAppList.end(); ++iter) {
        if (AppParser::GetInstance().IsBlackListApp(iter->processName_)) {
            bgUidList.push_back(iter->uid_);
            bgPidList.push_back(iter->pid_);
        }
    }

    std::vector<AppExecFwk::RunningProcessInfo> fgAppList;
    std::vector<int> fgUidList;
    if (GetAppList(fgAppList, true) < 0) {
        WIFI_LOGE("Get foreground app list fail.");
    }
    int fgAppSize = fgAppList.size();
    for (auto iter = fgAppList.begin(); iter != fgAppList.end(); ++iter) {
        fgUidList.push_back(iter->uid_);
    }
    int ret = WifiStaHalInterface::GetInstance().SetBgLimitMode(cmdMode);
    if (ret < 0) {
        WIFI_LOGE("SetBgLimitMode failed, ret = %{public}d.", ret);
        return;
    }
    SetBgLimitIdList(bgUidList, bgAppSize, SET_BG_UID);
    SetBgLimitIdList(bgPidList, bgAppSize, SET_BG_PID);
    SetBgLimitIdList(fgUidList, fgAppSize, SET_FG_UID);
}

ErrCode StaAppAcceleration::GetAppList(std::vector<AppExecFwk::RunningProcessInfo> &appList, bool getFgAppFlag)
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
            if (iter->state_ == AppExecFwk::AppProcessState::APP_STATE_FOREGROUND) {
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

int StaAppAcceleration::GetBgLimitMaxMode()
{
    if (mBgLimitRecordMap.empty()) {
        WIFI_LOGE("mBgLimitRecordMap is empty.\n");
        return -1;
    }

    int maxMode = 0;
    std::map<int, int>::iterator iter;
    for (iter = mBgLimitRecordMap.begin(); iter != mBgLimitRecordMap.end(); ++iter) {
        if (iter->second > maxMode) {
            maxMode = iter->second;
        }
    }
    return maxMode;
}

void StaAppAcceleration::SetBgLimitIdList(std::vector<int> idList, int size, int type)
{
    int ret = WifiStaHalInterface::GetInstance().SetBgLimitIdList(idList, size, type);
    if (ret < 0) {
        WIFI_LOGE("SetBgLimitIdList failed, ret = %{public}d.", ret);
    }
}

void StaAppAcceleration::StopAllAppAcceleration()
{
    WIFI_LOGI("Wifi disconnected, stop game boost.\n");
    SetPowerSaveMode(POWER_SAVE_ENABLE);
    HighPriorityTransmit(UNKNOWN_UID, BOOST_UDP_TYPE, GAME_BOOST_DISABLE);
    LimitedSpeed(BG_LIMIT_CONTROL_ID_GAME, GAME_BOOST_DISABLE, BG_LIMIT_OFF);
}

} // namespace Wifi
} // namespace OHOS
#endif