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

#include "wifi_service_manager.h"
#include <dlfcn.h>
#include "wifi_logger.h"
#include "define.h"
#include "wifi_settings.h"
#include "wifi_common_util.h"
#include "wifi_manager.h"
#ifdef FEATURE_P2P_SUPPORT
#include "p2p_interface.h"
#endif
#include "scan_interface.h"
#include "sta_interface.h"
#ifdef FEATURE_SELF_CURE_SUPPORT
#include "self_cure_interface.h"
#endif
#ifdef FEATURE_AP_SUPPORT
#include "ap_interface.h"
#endif
namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiServiceManager");
WifiServiceManager &WifiServiceManager::GetInstance()
{
    static WifiServiceManager gWifiServiceManager;
    return gWifiServiceManager;
}

WifiServiceManager::WifiServiceManager()
{}

WifiServiceManager::~WifiServiceManager()
{}

int WifiServiceManager::Init()
{
    return 0;
}

int WifiServiceManager::GetServiceDll(const std::string &name, std::string &dlname)
{
    return 0;
}

int WifiServiceManager::CheckPreLoadService(void)
{
    return 0;
}

int WifiServiceManager::LoadStaService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGI("LoadStaService");
    return 0;
}

#ifdef FEATURE_SELF_CURE_SUPPORT
int WifiServiceManager::LoadSelfCureService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGI("WifiServiceManager::LoadSelfCureService");
    return 0;
}
#endif

int WifiServiceManager::LoadScanService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGI("WifiServiceManager::LoadScanService");
    return 0;
}

#ifdef FEATURE_AP_SUPPORT
int WifiServiceManager::LoadApService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGI("WifiServiceManager::LoadApService");
    return 0;
}
#endif

#ifdef FEATURE_P2P_SUPPORT
int WifiServiceManager::LoadP2pService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGI("WifiServiceManager::LoadP2pService");
}
#endif

int WifiServiceManager::LoadEnhanceService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGD("WifiServiceManager::LoadEnhanceService");
    return 0;
}

int WifiServiceManager::CheckAndEnforceService(const std::string &name, bool bCreate)
{
    WIFI_LOGD("WifiServiceManager::CheckAndEnforceService name: %{public}s", name.c_str());
    return 0;
}

IStaService *WifiServiceManager::GetStaServiceInst(int instId)
{
    WIFI_LOGD("WifiServiceManager::GetStaServiceInst, instId: %{public}d", instId);
    return nullptr;
}

#ifdef FEATURE_SELF_CURE_SUPPORT
ISelfCureService *WifiServiceManager::GetSelfCureServiceInst(int instId)
{
    WIFI_LOGD("WifiServiceManager::GetSelfCureServiceInst, instId: %{public}d", instId);
    return nullptr;
}
#endif

IScanService *WifiServiceManager::GetScanServiceInst(int instId)
{
    WIFI_LOGD("WifiServiceManager::GetScanServiceInst, instId: %{public}d", instId);
    return nullptr;
}

#ifdef FEATURE_AP_SUPPORT
bool WifiServiceManager::ApServiceSetHotspotConfig(const HotspotConfig &config, int id)
{
    WIFI_LOGD("WifiServiceManager::GetApServiceInst");
    return true;
}

IApService *WifiServiceManager::GetApServiceInst(int id)
{
    return nullptr;
}
#endif

#ifdef FEATURE_P2P_SUPPORT
IP2pService *WifiServiceManager::GetP2pServiceInst()
{
    return nullptr;
}
#endif

IEnhanceService *WifiServiceManager::GetEnhanceServiceInst()
{
    return nullptr;
}

#ifdef FEATURE_SELF_CURE_SUPPORT
NO_SANITIZE("cfi") int WifiServiceManager::UnloadSelfCureService(bool bPreLoad, int instId)
{
    WIFI_LOGI("WifiServiceManager::UnloadSelfCureService, instId: %{public}d", instId);
    return 0;
}
#endif

NO_SANITIZE("cfi") int WifiServiceManager::UnloadStaService(bool bPreLoad, int instId)
{
    WIFI_LOGI("UnloadStaService, instId: %{public}d", instId);
    return 0;
}

NO_SANITIZE("cfi") int WifiServiceManager::UnloadScanService(bool bPreLoad, int instId)
{
    WIFI_LOGI("UnloadScanService, instId: %{public}d", instId);
    return 0;
}

#ifdef FEATURE_AP_SUPPORT
NO_SANITIZE("cfi") int WifiServiceManager::UnloadApService(bool bPreLoad, int id)
{
    WIFI_LOGI("WifiServiceManager::UnloadApService id=%{public}d", id);
    return 0;
}
#endif

#ifdef FEATURE_P2P_SUPPORT
NO_SANITIZE("cfi") int WifiServiceManager::UnloadP2pService(bool bPreLoad)
{
    return 0;
}
#endif

NO_SANITIZE("cfi") int WifiServiceManager::UnloadEnhanceService(bool bPreLoad)
{
    return 0;
}

int WifiServiceManager::UnloadService(const std::string &name, int id)
{
    return 0;
}

void WifiServiceManager::UninstallAllService()
{
    return;
}
} // namespace Wifi
} // namespace OHOS