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

#include "wifi_errcode.h"
#include "define.h"
#include "app_mgr_interface.h"
#include "sta_service_callback.h"
#include <unordered_set>

namespace OHOS {
namespace Wifi {
constexpr const int UNKNOWN_UID = -1;

class AppNetworkSpeedLimitService {
public:
    explicit AppNetworkSpeedLimitService();
    ~AppNetworkSpeedLimitService();
    static AppNetworkSpeedLimitService &GetInstance();
    StaServiceCallback GetStaCallback() const;
    void HandleForegroundAppChangedAction(const AppExecFwk::AppStateData &appStateData);
    void LimitSpeed(const int controlId, const int level);

private:
    void Init();
    void InitWifiLimitRecord();
    void InitCellarLimitRecord();
    void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId = 0);
    void HandleWifiConnectStateChanged(const bool isWifiConnected);
    int GetBgLimitMaxMode();
    ErrCode GetAppList(std::vector<AppExecFwk::RunningProcessInfo> &appList, bool getFgAppFlag);
    bool CheckNetWorkCanBeLimited(const int controlId);
    void UpdateSpeedLimitConfigs(const int controlId, const int limitMode);
    void LogSpeedLimitConfigs();
    bool IsLimitSpeedBgApp(const int controlId, const std::string bundleName);

private:
    StaServiceCallback m_staCallback;
    bool m_isWifiConnected {false};
    std::map<int, int> m_bgLimitRecordMap;
    int m_currentLimitMode;
    std::unordered_set<int> m_bgUidSet;
    std::unordered_set<int> m_bgPidSet;
    std::unordered_set<int> m_fgUidSet;
    std::mutex m_mutex;
};

} // namespace Wifi
} // namespace OHOS

#endif