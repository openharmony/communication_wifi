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

#ifndef OHOS_WIFI_STA_APP_ACCELERATION_H
#define OHOS_WIFI_STA_APP_ACCELERATION_H

#include "wifi_errcode.h"
#include "define.h"
#include "appmgr/app_mgr_interface.h"
#include "sta_service_callback.h"

namespace OHOS {
namespace Wifi {

class StaAppAcceleration {
public:
    explicit StaAppAcceleration(int instId = 0);
    ~StaAppAcceleration();
    StaServiceCallback GetStaCallback() const;
    ErrCode InitAppAcceleration();
    void HandleScreenStatusChanged(int screenState);
#ifndef OHOS_ARCH_LITE
    void HandleForegroundAppChangedAction(const AppExecFwk::AppStateData &appStateData);
#endif
private:
    void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId = 0);
    void SetPmMode(int mode);
    void StartGameBoost(int uid);
    void StopGameBoost(int uid);
    void SetGameBoostMode(int enable, int uid, int type, int limitMode);
    void HighPriorityTransmit(int uid, int protocol, int enable);
    void StopAllAppAcceleration();

private:
    StaServiceCallback m_staCallback;
    bool gameBoostingFlag;
};

} // namespace Wifi
} // namespace OHOS
#endif
