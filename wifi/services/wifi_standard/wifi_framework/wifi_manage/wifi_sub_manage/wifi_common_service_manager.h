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
#ifndef OHOS_WIFICOMMONSERVICEMANAGER_H
#define OHOS_WIFICOMMONSERVICEMANAGER_H

#include <string>
#include <sys/stat.h>
#include <fcntl.h>
#include "define.h"
#include "wifi_internal_msg.h"
#include "wifi_errcode.h"
#include "wifi_manager.h"
#ifndef OHOS_ARCH_LITE
#include "wifi_app_state_aware.h"
#include "wifi_event_subscriber_manager.h"
#endif

namespace OHOS {
namespace Wifi {
class WifiCommonServiceManager {
public:
    static WifiCommonServiceManager &GetInstance();
    ~WifiCommonServiceManager();
    /**
     * @Description Initialize submodules and message processing threads.
     *              1. Initializing the Configuration Center
     *              2. Initialization permission management
     *              3. Initializing Service Management
     *              4. Initialization event broadcast
     *              5. Initializing a Message Queue
     *              6. Initialize the message processing thread
     *
     * @return int - Init result, when 0 means success, other means some fails happened.
     */
    InitStatus Init();

    /**
     * @Description When exiting, the system exits each submodule and then exits the message processing thread.
     *              1. Uninstall each feature service
     *              2. Exit the event broadcast module
     *              3. Wait for the message processing thread to exit
     *
     */
    void Exit();

#ifndef OHOS_ARCH_LITE
    void OnForegroundAppChanged(const AppExecFwk::AppStateData &appStateData, const int mInstId = 0);
#endif

private:
    WifiCommonServiceManager();
private:
#ifndef OHOS_ARCH_LITE
    WifiAppStateAwareCallbacks mWifiAppStateAwareCallbacks;
#endif
};
} // namespace Wifi
} // namespace OHOS
#endif