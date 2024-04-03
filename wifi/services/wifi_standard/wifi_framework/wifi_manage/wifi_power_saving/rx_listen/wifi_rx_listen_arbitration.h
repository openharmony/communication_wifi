/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_POWER_RX_LISTEN_H
#define OHOS_WIFI_POWER_RX_LISTEN_H

#include <string>
#include <mutex>
#include "appmgr/app_mgr_interface.h"
#include "appmgr/app_mgr_constants.h"

namespace OHOS {
namespace Wifi {
class RxListenArbitration {
public:
    RxListenArbitration();
    ~RxListenArbitration();
    static RxListenArbitration &GetInstance();
    void OnForegroundAppChanged(const AppExecFwk::AppStateData &appStateData);

private:
    void CheckRxListenSwitch();

private:
    unsigned int m_arbitrationCond = 0x00;
    bool m_isRxListenOn = false;\
    std::mutex m_condMutex;
};
} // namespace Wifi
} // namespace OHOS

#endif /* OHOS_WIFI_POWER_RX_LISTEN_H */