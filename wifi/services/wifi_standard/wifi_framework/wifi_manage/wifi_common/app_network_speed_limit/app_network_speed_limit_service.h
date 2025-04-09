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

#ifndef OHOS_WIFI_APP_NETWORK_SPEED_LIMIT_SERVICE_H
#define OHOS_WIFI_APP_NETWORK_SPEED_LIMIT_SERVICE_H

#include <unordered_set>

#include "wifi_errcode.h"
#include "wifi_event_handler.h"
#include "define.h"
#include "app_mgr_interface.h"
#include "sta_service_callback.h"

namespace OHOS {
namespace Wifi {
constexpr const int UNKNOWN_UID = -1;
constexpr const int UNKNOWN_MODE = -1;

enum GameSceneId : int {
    MSG_GAME_STATE_START = 0,
    MSG_GAME_STATE_END = 1,
    MSG_GAME_ENTER_PVP_BATTLE = 2,
    MSG_GAME_EXIT_PVP_BATTLE = 3,
    MSG_GAME_STATE_FOREGROUND = 4,
    MSG_GAME_STATE_BACKGROUND = 5,
};

struct AsyncParamInfo {
    int controlId;
    int limitMode;
    WifiNetworkControlInfo networkControlInfo;
    std::string funcName;
    std::string bundleName;

    AsyncParamInfo()
    {
        controlId = -1;
        limitMode = -1;
        funcName = "";
        bundleName = "";
    }
};

class AppNetworkSpeedLimitService {
public:
    explicit AppNetworkSpeedLimitService();
    ~AppNetworkSpeedLimitService();
    static AppNetworkSpeedLimitService &GetInstance();
    StaServiceCallback GetStaCallback() const;
    void HandleForegroundAppChangedAction(const AppExecFwk::AppStateData &appStateData);
    void ReceiveNetworkControlInfo(const WifiNetworkControlInfo &networkControlInfo);
    void LimitSpeed(const int controlId, const int limitMode);

private:
    void Init();
    void InitWifiLimitRecord();
    void InitCellarLimitRecord();
    void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId = 0);
    void HandleWifiConnectStateChanged(const bool isWifiConnected);
    void SendLimitInfo();
    void FilterLimitSpeedConfigs();
    int GetBgLimitMaxMode();
    ErrCode GetAppList(std::vector<AppExecFwk::RunningProcessInfo> &appList, bool getFgAppFlag);
    bool CheckNetWorkCanBeLimited(const int controlId);
    void UpdateSpeedLimitConfigs(const int enable);
    void UpdateNoSpeedLimitConfigs(const WifiNetworkControlInfo &networkControlInfo);
    bool IsLimitSpeedBgApp(const int controlId, const std::string &bundleName, const int enable);
    bool IsTopNLimitSpeedSceneInNow();
    void AsyncLimitSpeed(const AsyncParamInfo &asyncParamInfo);
    void WifiConnectStateChanged();
    void ForegroundAppChangedAction(const std::string &bundleName);
    void HandleRequest(const AsyncParamInfo &asyncParamInfo);
    void SendLimitCmd2Drv(const int controlId, const int limitMode, const int enable,
        const int uid = -1);
    void HighPriorityTransmit(int uid, int protocol, int enable);
    void GameNetworkSpeedLimitConfigs(const WifiNetworkControlInfo &networkControlInfo);
    void LogSpeedLimitConfigs();

private:
    StaServiceCallback m_staCallback;
    std::atomic<bool> m_isWifiConnected = false;
    int m_isHighPriorityTransmit = 0;
    std::map<int, int> m_bgLimitRecordMap;
    int m_limitSpeedMode{0};
    std::unordered_set<int> m_bgUidSet;
    std::unordered_set<int> m_bgPidSet;
    std::unordered_set<int> m_fgUidSet;
    int m_lastLimitSpeedMode{UNKNOWN_MODE};
    std::unordered_set<int> m_lastBgUidSet;
    std::unordered_set<int> m_lastBgPidSet;
    std::unordered_set<int> m_lastFgUidSet;
    std::unordered_set<int> m_bgAudioPlaybackUidSet;
    std::unordered_set<int> m_bgAudioPlaybackPidSet;
    std::unordered_set<int> m_additionalWindowUidSet;
    std::unordered_set<int> m_additionalWindowPidSet;
    std::unique_ptr<WifiEventHandler> m_asyncSendLimit = nullptr;
    int64_t m_delayTime;
};
} // namespace Wifi
} // namespace OHOS

#endif