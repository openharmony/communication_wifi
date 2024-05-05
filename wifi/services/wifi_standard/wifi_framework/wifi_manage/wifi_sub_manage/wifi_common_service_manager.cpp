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

#include "wifi_common_service_manager.h"
#include <dirent.h>
#include <iconv.h>
#include "wifi_auth_center.h"
#include "wifi_config_center.h"
#include "wifi_global_func.h"
#include "wifi_logger.h"
#ifdef OHOS_ARCH_LITE
#include "wifi_internal_event_dispatcher_lite.h"
#else
#include "wifi_internal_event_dispatcher.h"
#include "wifi_country_code_manager.h"
#endif
#include "wifi_common_def.h"
#include "wifi_common_util.h"
#include "wifi_service_manager.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiCommonServiceManager");

WifiCommonServiceManager &WifiCommonServiceManager::GetInstance()
{
    static WifiCommonServiceManager gWifiCommonServiceManager;
    return gWifiCommonServiceManager;
}

WifiCommonServiceManager::WifiCommonServiceManager()
{}

WifiCommonServiceManager::~WifiCommonServiceManager()
{
    WifiInternalEventDispatcher::GetInstance().Exit();
}

void WifiCommonServiceManager::Exit()
{
    WifiInternalEventDispatcher::GetInstance().Exit();
}
InitStatus WifiCommonServiceManager::Init()
{
#ifndef OHOS_ARCH_LITE
    if (WifiCountryCodeManager::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiCountryCodeManager Init failed!");
        return WIFI_COUNTRY_CODE_MANAGER_INIT_FAILED;
    }
    using namespace std::placeholders;
    mWifiAppStateAwareCallbacks.OnForegroundAppChanged =
        std::bind(&WifiCommonServiceManager::OnForegroundAppChanged, this, _1, _2);
    if (WifiAppStateAware::GetInstance().InitAppStateAware(mWifiAppStateAwareCallbacks) < 0) {
        WIFI_LOGE("WifiAppStateAware Init failed!");
    }
#endif
    if (WifiConfigCenter::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiConfigCenter Init failed!");
        return CONFIG_CENTER_INIT_FAILED;
    }
    if (WifiAuthCenter::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiAuthCenter Init failed!");
        return AUTH_CENTER_INIT_FAILED;
    }

    if (WifiInternalEventDispatcher::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiInternalEventDispatcher Init failed!");
        return EVENT_BROADCAST_INIT_FAILED;
    }
    return INIT_OK;
}
#ifndef OHOS_ARCH_LITE
void WifiCommonServiceManager::OnForegroundAppChanged(const AppExecFwk::AppStateData &appStateData, const int mInstId)
{
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(mInstId);
    if (pService != nullptr) {
        pService->HandleForegroundAppChangedAction(appStateData);
    }
}
#endif
}  // namespace Wifi
}  // namespace OHOS