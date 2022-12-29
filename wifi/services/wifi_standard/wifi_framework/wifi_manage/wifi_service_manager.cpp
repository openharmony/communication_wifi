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
#ifdef FEATURE_P2P_SUPPORT
    mP2pServiceHandle.Clear();
#endif
#ifdef FEATURE_AP_SUPPORT
    mApServiceHandle.Clear();
#endif
    mStaServiceHandle.Clear();
    mScanServiceHandle.Clear();
#ifdef OHOS_ARCH_LITE
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_STA, "libwifi_sta_service.so"));
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_SCAN, "libwifi_scan_service.so"));
#ifdef FEATURE_AP_SUPPORT
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_AP, "libwifi_ap_service.so"));
#endif
#ifdef FEATURE_P2P_SUPPORT
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_P2P, "libwifi_p2p_service.so"));
#endif
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_AWARE, "libwifi_aware_service.so"));
#else
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_STA, "libwifi_sta_service.z.so"));
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_SCAN, "libwifi_scan_service.z.so"));
#ifdef FEATURE_AP_SUPPORT
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_AP, "libwifi_ap_service.z.so"));
#endif
#ifdef FEATURE_P2P_SUPPORT
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_P2P, "libwifi_p2p_service.z.so"));
#endif
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_AWARE, "libwifi_aware_service.z.so"));
#endif
    return 0;
}

int WifiServiceManager::GetServiceDll(const std::string &name, std::string &dlname)
{
    auto iter = mServiceDllMap.find(name);
    if (iter == mServiceDllMap.end()) {
        return -1;
    }
    dlname = iter->second;
    return 0;
}

int WifiServiceManager::CheckPreLoadService(void)
{
    for (auto iter = mServiceDllMap.begin(); iter != mServiceDllMap.end(); ++iter) {
        bool bLoad = WifiSettings::GetInstance().IsModulePreLoad(iter->first);
        if (bLoad) {
            int ret = CheckAndEnforceService(iter->first, false);
            if (ret < 0) {
                return -1;
            }
        }
    }
    return 0;
}

int WifiServiceManager::LoadStaService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGI("WifiServiceManager::LoadStaService");
    std::unique_lock<std::mutex> lock(mStaMutex);
    if (mStaServiceHandle.handle != nullptr) {
        WIFI_LOGE("WifiServiceManager::handle is not null: %{public}s", dlname.c_str());
        return 0;
    }
    mStaServiceHandle.handle = dlopen(dlname.c_str(), RTLD_LAZY);
    if (mStaServiceHandle.handle == nullptr) {
        WIFI_LOGE("dlopen %{public}s failed: %{public}s!", dlname.c_str(), dlerror());
        return -1;
    }
    mStaServiceHandle.create = (IStaService *(*)()) dlsym(mStaServiceHandle.handle, "Create");
    mStaServiceHandle.destroy = (void *(*)(IStaService *))dlsym(mStaServiceHandle.handle, "Destroy");
    if (mStaServiceHandle.create == nullptr || mStaServiceHandle.destroy == nullptr) {
        WIFI_LOGE("%{public}s dlsym Create or Destroy failed!", dlname.c_str());
        dlclose(mStaServiceHandle.handle);
        mStaServiceHandle.Clear();
        return -1;
    }
    if (bCreate) {
        mStaServiceHandle.pService = mStaServiceHandle.create();
    }
    return 0;
}

int WifiServiceManager::LoadScanService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGI("WifiServiceManager::LoadScanService");
    std::unique_lock<std::mutex> lock(mScanMutex);
    if (mScanServiceHandle.handle != nullptr) {
        WIFI_LOGE("WifiServiceManager::handle is not null: %{public}s", dlname.c_str());
        return 0;
    }
    mScanServiceHandle.handle = dlopen(dlname.c_str(), RTLD_LAZY);
    if (mScanServiceHandle.handle == nullptr) {
        WIFI_LOGE("dlopen %{public}s failed: %{public}s!", dlname.c_str(), dlerror());
        return -1;
    }
    mScanServiceHandle.create = (IScanService *(*)()) dlsym(mScanServiceHandle.handle, "Create");
    mScanServiceHandle.destroy = (void *(*)(IScanService *))dlsym(mScanServiceHandle.handle, "Destroy");
    if (mScanServiceHandle.create == nullptr || mScanServiceHandle.destroy == nullptr) {
        WIFI_LOGE("%{public}s dlsym Create or Destroy failed!", dlname.c_str());
        dlclose(mScanServiceHandle.handle);
        mScanServiceHandle.Clear();
        return -1;
    }
    if (bCreate) {
        mScanServiceHandle.pService = mScanServiceHandle.create();
    }
    return 0;
}

#ifdef FEATURE_AP_SUPPORT
int WifiServiceManager::LoadApService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGI("WifiServiceManager::LoadApService");
    std::unique_lock<std::mutex> lock(mApMutex);
    if (mApServiceHandle.handle != nullptr) {
        WIFI_LOGE("WifiServiceManager::handle is not null: %{public}s", dlname.c_str());
        return 0;
    }
    mApServiceHandle.handle = dlopen(dlname.c_str(), RTLD_LAZY);
    if (mApServiceHandle.handle == nullptr) {
        WIFI_LOGE("dlopen %{public}s failed: %{public}s!", dlname.c_str(), dlerror());
        return -1;
    }
    mApServiceHandle.create = (IApService *(*)(int)) dlsym(mApServiceHandle.handle, "Create");
    mApServiceHandle.destroy = (void *(*)(IApService *))dlsym(mApServiceHandle.handle, "Destroy");
    if (mApServiceHandle.create == nullptr || mApServiceHandle.destroy == nullptr) {
        WIFI_LOGE("%{public}s dlsym Create or Destroy failed!", dlname.c_str());
        dlclose(mApServiceHandle.handle);
        mApServiceHandle.Clear();
        return -1;
    }
    if (bCreate) {
        IApService *service = mApServiceHandle.create(0);
        auto ret = mApServiceHandle.pService.emplace(0, service);
        if (!ret.second) {
            mApServiceHandle.pService[0] = service;
        }
    }
    return 0;
}
#endif

#ifdef FEATURE_P2P_SUPPORT
int WifiServiceManager::LoadP2pService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGI("WifiServiceManager::LoadP2pService");
    std::unique_lock<std::mutex> lock(mP2pMutex);
    if (mP2pServiceHandle.handle != nullptr) {
        WIFI_LOGE("WifiServiceManager::handle is not null: %{public}s", dlname.c_str());
        return 0;
    }
    mP2pServiceHandle.handle = dlopen(dlname.c_str(), RTLD_LAZY);
    if (mP2pServiceHandle.handle == nullptr) {
        WIFI_LOGE("dlopen %{public}s failed: %{public}s!", dlname.c_str(), dlerror());
        return -1;
    }
    mP2pServiceHandle.create = (IP2pService *(*)()) dlsym(mP2pServiceHandle.handle, "Create");
    mP2pServiceHandle.destroy = (void *(*)(IP2pService *))dlsym(mP2pServiceHandle.handle, "Destroy");
    if (mP2pServiceHandle.create == nullptr || mP2pServiceHandle.destroy == nullptr) {
        WIFI_LOGE("%{public}s dlsym Create or Destroy failed!", dlname.c_str());
        dlclose(mP2pServiceHandle.handle);
        mP2pServiceHandle.Clear();
        return -1;
    }
    if (bCreate) {
        mP2pServiceHandle.pService = mP2pServiceHandle.create();
    }
    return 0;
}
#endif

int WifiServiceManager::CheckAndEnforceService(const std::string &name, bool bCreate)
{
    WIFI_LOGD("WifiServiceManager::CheckAndEnforceService name: %{public}s", name.c_str());
    std::string dlname;
    if (GetServiceDll(name, dlname) < 0) {
        WIFI_LOGE("%{public}s does not support", name.c_str());
        return -1;
    }
    WIFI_LOGD("WifiServiceManager::CheckAndEnforceService get dllname: %{public}s", dlname.c_str());
    if (name == WIFI_SERVICE_STA) {
        return LoadStaService(dlname, bCreate);
    }
    if (name == WIFI_SERVICE_SCAN) {
        return LoadScanService(dlname, bCreate);
    }
#ifdef FEATURE_AP_SUPPORT
    if (name == WIFI_SERVICE_AP) {
        return LoadApService(dlname, bCreate);
    }
#endif
#ifdef FEATURE_P2P_SUPPORT
    if (name == WIFI_SERVICE_P2P) {
        return LoadP2pService(dlname, bCreate);
    }
#endif
    return -1;
}

IStaService *WifiServiceManager::GetStaServiceInst()
{
    WIFI_LOGI("WifiServiceManager::GetStaServiceInst");
    std::unique_lock<std::mutex> lock(mStaMutex);
    if (mStaServiceHandle.handle == nullptr) {
        WIFI_LOGE("WifiServiceManager, Sta handle is null");
        return nullptr;
    }
    if (mStaServiceHandle.pService == nullptr) {
        mStaServiceHandle.pService = mStaServiceHandle.create();
    }
    return mStaServiceHandle.pService;
}

IScanService *WifiServiceManager::GetScanServiceInst()
{
    WIFI_LOGI("WifiServiceManager::GetScanServiceInst");
    std::unique_lock<std::mutex> lock(mScanMutex);
    if (mScanServiceHandle.handle == nullptr) {
        WIFI_LOGE("WifiServiceManager, Scan handle is null");
        return nullptr;
    }
    if (mScanServiceHandle.pService == nullptr) {
        mScanServiceHandle.pService = mScanServiceHandle.create();
    }
    return mScanServiceHandle.pService;
}

#ifdef FEATURE_AP_SUPPORT
IApService *WifiServiceManager::GetApServiceInst(int id)
{
    WIFI_LOGI("WifiServiceManager::GetApServiceInst");
    std::unique_lock<std::mutex> lock(mApMutex);
    if (mApServiceHandle.handle == nullptr) {
        WIFI_LOGE("Get ap service instance handle is null.");
        return nullptr;
    }

    auto findInstance = [this, id]() -> IApService* {
        auto it = mApServiceHandle.pService.find(id);
        return (it != mApServiceHandle.pService.end()) ? it->second : nullptr;
    };
    auto apInstance = findInstance();
    if (apInstance != nullptr) {
        WIFI_LOGI("Ap service instance is exist %{public}d", id);
        return apInstance;
    }

    WIFI_LOGI("[Get] create a new ap service instance: %{public}d", id);
    IApService *service = mApServiceHandle.create(id);
    mApServiceHandle.pService[id] = service;
    return service;
}
#endif

#ifdef FEATURE_P2P_SUPPORT
IP2pService *WifiServiceManager::GetP2pServiceInst()
{
    WIFI_LOGI("WifiServiceManager::GetP2pServiceInst");
    std::unique_lock<std::mutex> lock(mP2pMutex);
    if (mP2pServiceHandle.handle == nullptr) {
        WIFI_LOGE("WifiServiceManager, P2p handle is null");
        return nullptr;
    }
    if (mP2pServiceHandle.pService == nullptr) {
        mP2pServiceHandle.pService = mP2pServiceHandle.create();
    }
    return mP2pServiceHandle.pService;
}
#endif

int WifiServiceManager::UnloadStaService(bool bPreLoad)
{
    WIFI_LOGI("WifiServiceManager::UnloadStaService");
    std::unique_lock<std::mutex> lock(mStaMutex);
    if (mStaServiceHandle.handle == nullptr) {
        WIFI_LOGE("WifiServiceManager::UnloadStaService handle is null");
        return 0;
    }
    if (mStaServiceHandle.pService != nullptr) {
        mStaServiceHandle.destroy(mStaServiceHandle.pService);
        mStaServiceHandle.pService = nullptr;
    }
    if (!bPreLoad) {
        dlclose(mStaServiceHandle.handle);
        mStaServiceHandle.Clear();
    }
    return 0;
}

int WifiServiceManager::UnloadScanService(bool bPreLoad)
{
    WIFI_LOGI("WifiServiceManager::UnloadScanService");
    std::unique_lock<std::mutex> lock(mScanMutex);
    if (mScanServiceHandle.handle == nullptr) {
        WIFI_LOGE("WifiServiceManager::UnloadScanService handle is null");
        return 0;
    }
    if (mScanServiceHandle.pService != nullptr) {
        mScanServiceHandle.destroy(mScanServiceHandle.pService);
        mScanServiceHandle.pService = nullptr;
    }
    if (!bPreLoad) {
        dlclose(mScanServiceHandle.handle);
        mScanServiceHandle.Clear();
    }
    return 0;
}

#ifdef FEATURE_AP_SUPPORT
int WifiServiceManager::UnloadApService(bool bPreLoad, int id)
{
    WIFI_LOGI("WifiServiceManager::UnloadApService id=%{public}d, max_id=%{public}d", id, AP_INSTANCE_MAX_NUM);
    {
        std::unique_lock<std::mutex> lock(mApMutex);
        if (mApServiceHandle.handle == nullptr) {
            WIFI_LOGE("WifiServiceManager::UnloadApService handle is null");
            return 0;
        }
    }

    /* Unload all ap service */
    if (id == ALL_AP_ID) {
        for (int i = 0; i < AP_INSTANCE_MAX_NUM; i++) {
            UnloadApService(bPreLoad, i);
        }
    } else {
        std::unique_lock<std::mutex> lock(mApMutex);
        auto iter = mApServiceHandle.pService.find(id);
        if (iter != mApServiceHandle.pService.end()) {
            if (iter->second != nullptr) {
                mApServiceHandle.destroy(iter->second);
                iter->second = nullptr;
            }
            mApServiceHandle.pService.erase(id);
        }
        if (!bPreLoad && mApServiceHandle.pService.empty()) {
            dlclose(mApServiceHandle.handle);
            mApServiceHandle.Clear();
        }
    }
    return 0;
}
#endif

#ifdef FEATURE_P2P_SUPPORT
int WifiServiceManager::UnloadP2pService(bool bPreLoad)
{
    WIFI_LOGI("WifiServiceManager::UnloadP2pService");
    std::unique_lock<std::mutex> lock(mP2pMutex);
    if (mP2pServiceHandle.handle == nullptr) {
        WIFI_LOGE("WifiServiceManager::UnloadP2pService handle is null");
        return 0;
    }
    if (mP2pServiceHandle.pService != nullptr) {
        mP2pServiceHandle.destroy(mP2pServiceHandle.pService);
        mP2pServiceHandle.pService = nullptr;
    }
    if (!bPreLoad) {
        dlclose(mP2pServiceHandle.handle);
        mP2pServiceHandle.Clear();
    }
    return 0;
}
#endif

int WifiServiceManager::UnloadService(const std::string &name, int id)
{
    bool bPreLoad = WifiSettings::GetInstance().IsModulePreLoad(name);
    WIFI_LOGI("WifiServiceManager::UnloadService name: %{public}s", name.c_str());
    if (name == WIFI_SERVICE_STA) {
        return UnloadStaService(bPreLoad);
    }
    if (name == WIFI_SERVICE_SCAN) {
        return UnloadScanService(bPreLoad);
    }
#ifdef FEATURE_AP_SUPPORT
    if (name == WIFI_SERVICE_AP) {
        return UnloadApService(bPreLoad, id);
    }
#endif
#ifdef FEATURE_P2P_SUPPORT
    if (name == WIFI_SERVICE_P2P) {
        return UnloadP2pService(bPreLoad);
    }
#endif
    return -1;
}

void WifiServiceManager::UninstallAllService()
{
    WIFI_LOGI("WifiServiceManager::UninstallAllService");
    UnloadStaService(false);
    UnloadScanService(false);
#ifdef FEATURE_AP_SUPPORT
    UnloadApService(false, ALL_AP_ID); /* all ap services */
#endif
#ifdef FEATURE_P2P_SUPPORT
    UnloadP2pService(false);
#endif
    return;
}
} // namespace Wifi
} // namespace OHOS
