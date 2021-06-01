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
#include "wifi_service_manager.h"
#include <dlfcn.h>
#include "wifi_log.h"
#include "define.h"
#include "wifi_settings.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_MANAGER_SERVICE_MANAGER"

namespace OHOS {
namespace Wifi {
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
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_STA, "libwifi_sta_service.z.so"));
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_SCAN, "libwifi_scan_service.z.so"));
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_AP, "libwifi_ap_service.z.so"));
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_P2P, "libwifi_p2p_service.z.so"));
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_AWARE, "libwifi_aware_service.z.so"));
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

int WifiServiceManager::CheckAndEnforceService(const std::string &name, bool bCreate)
{
    LOGD("WifiServiceManager::CheckAndEnforceService name: %{public}s", name.c_str());
    std::string dlname;
    if (GetServiceDll(name, dlname) < 0) {
        LOGE("%{public}s does not support", name.c_str());
        return -1;
    }
    LOGD("WifiServiceManager::CheckAndEnforceService get dllname: %{public}s", dlname.c_str());
    std::unique_lock<std::mutex> lock(mMutex);
    if (mServiceHandleMap.find(name) == mServiceHandleMap.end()) {
        ServiceHandle tmp;
        tmp.handle = dlopen(dlname.c_str(), RTLD_LAZY);
        if (tmp.handle == nullptr) {
            LOGE("dlopen %{public}s failed: %{public}s!", dlname.c_str(), dlerror());
            return -1;
        }
        tmp.create = (BaseService* (*)()) dlsym(tmp.handle, "Create");
        tmp.destroy = (void *(*)(BaseService*))dlsym(tmp.handle, "Destroy");
        if (tmp.create == nullptr || tmp.destroy == nullptr) {
            LOGE("%{public}s dlsym Create or Destroy failed!", dlname.c_str());
            dlclose(tmp.handle);
            return -1;
        }
        if (bCreate) {
            tmp.bs = tmp.create();
            if (tmp.bs == nullptr) {
                LOGE("create feature service is nullptr");
            }
        }
        mServiceHandleMap.emplace(std::make_pair(name, tmp));
    }
    return 0;
}

BaseService *WifiServiceManager::GetServiceInst(const std::string &name)
{
    LOGD("WifiServiceManager::GetServiceInst name: %{public}s", name.c_str());
    std::unique_lock<std::mutex> lock(mMutex);
    auto iter = mServiceHandleMap.find(name);
    if (iter != mServiceHandleMap.end()) {
        if (iter->second.bs == nullptr) {
            LOGD("WifiServiceManager::GetServiceInst start create feature service");
            iter->second.bs = iter->second.create();
        }
        if (iter->second.bs == nullptr) {
            LOGE("WifiServiceManager::GetServiceInst feature service is nullptr");
        }
        return iter->second.bs;
    }
    return nullptr;
}

int WifiServiceManager::UnloadService(const std::string &name)
{
    bool bPreLoad = WifiSettings::GetInstance().IsModulePreLoad(name);
    LOGD("WifiServiceManager::UnloadService name: %{public}s", name.c_str());
    std::unique_lock<std::mutex> lock(mMutex);
    auto iter = mServiceHandleMap.find(name);
    if (iter != mServiceHandleMap.end()) {
        ServiceHandle &tmp = iter->second;
        tmp.destroy(tmp.bs);
        if (!bPreLoad) {
            dlclose(tmp.handle);
            mServiceHandleMap.erase(iter);
        } else {
            tmp.bs = nullptr;
        }
    }
    return 0;
}

void WifiServiceManager::UninstallAllService()
{
    LOGD("WifiServiceManager::UninstallAllService");
    std::unique_lock<std::mutex> lock(mMutex);
    for (auto iter = mServiceHandleMap.begin(); iter != mServiceHandleMap.end(); ++iter) {
        ServiceHandle &tmp = iter->second;
        tmp.destroy(tmp.bs);
        dlclose(tmp.handle);
    }
    mServiceHandleMap.clear();
    return;
}
} // namespace Wifi
} // namespace OHOS