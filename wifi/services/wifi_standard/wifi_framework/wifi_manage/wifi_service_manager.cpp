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
#ifdef FEATURE_WIFI_PRO_SUPPORT
#include "wifi_pro_interface.h"
#endif
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
#ifdef FEATURE_P2P_SUPPORT
    mP2pServiceHandle.Clear();
#endif
#ifdef FEATURE_AP_SUPPORT
    mApServiceHandle.Clear();
#endif
#ifdef FEATURE_WIFI_PRO_SUPPORT
    mWifiProServiceHandle.Clear();
#endif
#ifdef FEATURE_SELF_CURE_SUPPORT
    mSelfCureServiceHandle.Clear();
#endif
    mStaServiceHandle.Clear();
    mScanServiceHandle.Clear();
    mEnhanceServiceHandle.Clear();
#ifdef OHOS_ARCH_LITE
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_STA, "libwifi_sta_service.so"));
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_SCAN, "libwifi_scan_service.so"));
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_ENHANCE, "libwifi_enhance_interface.z.so"));
#ifdef FEATURE_AP_SUPPORT
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_AP, "libwifi_ap_service.so"));
#endif
#ifdef FEATURE_P2P_SUPPORT
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_P2P, "libwifi_p2p_service.so"));
#endif
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_AWARE, "libwifi_aware_service.so"));
#else
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_STA, "libwifi_sta_service.z.so"));
#ifdef FEATURE_SELF_CURE_SUPPORT
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_SELFCURE, "libwifi_self_cure.z.so"));
#endif
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_SCAN, "libwifi_scan_service.z.so"));
    mServiceDllMap.insert(std::make_pair(WIFI_SERVICE_ENHANCE, "libwifi_enhance_interface.z.so"));
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
            int ret = CheckAndEnforceService(iter->first, 0, false);
            if (ret < 0) {
                return -1;
            }
        }
    }
    return 0;
}

int WifiServiceManager::LoadStaService(const std::string &dlname, int instId, bool bCreate)
{
    WIFI_LOGI("LoadStaService, insId %{public}d", instId);
    std::unique_lock<std::mutex> lock(mStaMutex);
    if (mStaServiceHandle.pService[instId]) {
        WIFI_LOGE("WifiServiceManager::LoadStaService pService is not NULL");
        return 0;
    }
    IStaService *service = new StaInterface(instId);
    mStaServiceHandle.pService[instId] = service;
    WIFI_LOGI("WifiServiceManager::LoadStaService new pService %{public}d", instId);
    WifiManager::GetInstance().GetWifiStaManager()->StopUnloadStaSaTimer();
    return 0;
}

#ifdef FEATURE_WIFI_PRO_SUPPORT
int32_t WifiServiceManager::LoadWifiProService(bool bCreate, int32_t instId)
{
    WIFI_LOGI("WifiServiceManager::LoadWifiProService");
    std::unique_lock<std::mutex> lock(mWifiProMutex);
    if (mWifiProServiceHandle.pService[instId]) {
        WIFI_LOGI("WifiServiceManager::LoadWifiProService pService is not NULL");
        return 0;
    }
    IWifiProService *service = new WifiProInterface();
    WIFI_LOGI("WifiServiceManager::LoadWifiProService new pService %{public}d", instId);
    mWifiProServiceHandle.pService[instId] = service;
    return 0;
}
#endif

#ifdef FEATURE_SELF_CURE_SUPPORT
int WifiServiceManager::LoadSelfCureService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGI("WifiServiceManager::LoadSelfCureService");
    std::unique_lock<std::mutex> lock(mSelfCureMutex);
    if (mSelfCureServiceHandle.pService[0]) {
        return 0;
    }
    ISelfCureService *service = new SelfCureInterface();
    mSelfCureServiceHandle.pService[0] = service;
    return 0;
}
#endif

int WifiServiceManager::LoadScanService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGI("WifiServiceManager::LoadScanService");
    std::unique_lock<std::mutex> lock(mScanMutex);
    if (mScanServiceHandle.pService[0]) {
        return 0;
    }
    IScanService *service = new ScanInterface();
    mScanServiceHandle.pService[0] = service;
    WifiManager::GetInstance().GetWifiScanManager()->StopUnloadScanSaTimer();
    return 0;
}

#ifdef FEATURE_AP_SUPPORT
int WifiServiceManager::LoadApService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGI("WifiServiceManager::LoadApService");
    std::unique_lock<std::mutex> lock(mApMutex);
    if (mApServiceHandle.pService[0]) {
        return 0;
    }
    WifiApServiceUtil wifiApServiceUtil;
    IApService *service = wifiApServiceUtil.CreateApInterface(0);
    if (service == nullptr) {
        WIFI_LOGE("WifiServiceManager::LoadApService create service failed");
        return -1;
    }
    mApServiceHandle.pService[0] = service;
    WifiManager::GetInstance().GetWifiHotspotManager()->StopUnloadApSaTimer();
    return 0;
}
#endif

#ifdef FEATURE_P2P_SUPPORT
int WifiServiceManager::LoadP2pService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGI("WifiServiceManager::LoadP2pService");
    std::unique_lock<std::mutex> lock(mP2pMutex);
    if (mP2pServiceHandle.pService) {
        return 0;
    }
    mP2pServiceHandle.pService = new P2pInterface();
    WifiManager::GetInstance().GetWifiP2pManager()->StopUnloadP2PSaTimer();
    return 0;
}
#endif

int WifiServiceManager::LoadEnhanceService(const std::string &dlname, bool bCreate)
{
    WIFI_LOGD("WifiServiceManager::LoadEnhanceService");
    std::unique_lock<std::mutex> lock(mEnhanceMutex);
    if (mEnhanceServiceHandle.handle != nullptr) {
        WIFI_LOGE("WifiServiceManager::handle is not null: %{public}s", dlname.c_str());
        return 0;
    }
    mEnhanceServiceHandle.handle = dlopen(dlname.c_str(), RTLD_LAZY);
    if (mEnhanceServiceHandle.handle == nullptr) {
        WIFI_LOGE("dlopen %{public}s failed: %{public}s!", dlname.c_str(), dlerror());
        return -1;
    }
    mEnhanceServiceHandle.create = (IEnhanceService *(*)()) dlsym(mEnhanceServiceHandle.handle, "Create");
    mEnhanceServiceHandle.destroy = (void *(*)(IEnhanceService *))dlsym(mEnhanceServiceHandle.handle, "Destroy");
    if (mEnhanceServiceHandle.create == nullptr || mEnhanceServiceHandle.destroy == nullptr) {
        WIFI_LOGE("%{public}s dlsym Create or Destroy failed!", dlname.c_str());
        dlclose(mEnhanceServiceHandle.handle);
        mEnhanceServiceHandle.Clear();
        return -1;
    }
    if (bCreate) {
        mEnhanceServiceHandle.pService = mEnhanceServiceHandle.create();
    }
    return 0;
}

int WifiServiceManager::CheckAndEnforceService(const std::string &name, int instId, bool bCreate)
{
    WIFI_LOGD("WifiServiceManager::CheckAndEnforceService name: %{public}s", name.c_str());
#ifdef FEATURE_WIFI_PRO_SUPPORT
    if (name == WIFI_SERVICE_WIFIPRO) {
        return LoadWifiProService(bCreate, instId);
    }
#endif

    std::string dlname;
    if (GetServiceDll(name, dlname) < 0) {
        WIFI_LOGE("%{public}s does not support", name.c_str());
        return -1;
    }
    WIFI_LOGD("WifiServiceManager::CheckAndEnforceService get dllname: %{public}s", dlname.c_str());
    if (name == WIFI_SERVICE_STA) {
        return LoadStaService(dlname, instId, bCreate);
    }
#ifdef FEATURE_SELF_CURE_SUPPORT
    if (name == WIFI_SERVICE_SELFCURE) {
        return LoadSelfCureService(dlname, bCreate);
    }
#endif
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
    if (name == WIFI_SERVICE_ENHANCE) {
        return LoadEnhanceService(dlname, bCreate);
    }
    return -1;
}

IStaService *WifiServiceManager::GetStaServiceInst(int instId)
{
    WIFI_LOGD("WifiServiceManager::GetStaServiceInst, instId: %{public}d", instId);
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mStaServiceHandle.pService.find(instId);
    if (iter != mStaServiceHandle.pService.end()) {
        WIFI_LOGD("find a new sta service instance, instId: %{public}d", instId);
        return iter->second;
    }

    return nullptr;
}

#ifdef FEATURE_WIFI_PRO_SUPPORT
IWifiProService *WifiServiceManager::GetWifiProServiceInst(int32_t instId)
{
    WIFI_LOGD("WifiServiceManager::GetWifiProServiceInst, instId: %{public}d", instId);
    std::unique_lock<std::mutex> lock(mWifiProMutex);

    auto iter = mWifiProServiceHandle.pService.find(instId);
    if (iter != mWifiProServiceHandle.pService.end()) {
        WIFI_LOGD("find a new WifiPro service instance, instId: %{public}d", instId);
        return iter->second;
    }
    return nullptr;
}
#endif

#ifdef FEATURE_SELF_CURE_SUPPORT
ISelfCureService *WifiServiceManager::GetSelfCureServiceInst(int instId)
{
    WIFI_LOGD("WifiServiceManager::GetSelfCureServiceInst, instId: %{public}d", instId);
    std::unique_lock<std::mutex> lock(mSelfCureMutex);

    auto iter = mSelfCureServiceHandle.pService.find(instId);
    if (iter != mSelfCureServiceHandle.pService.end()) {
        WIFI_LOGD("find a new self cure service instance, instId: %{public}d", instId);
        return iter->second;
    }
    
    return nullptr;
}
#endif

IScanService *WifiServiceManager::GetScanServiceInst(int instId)
{
    WIFI_LOGD("WifiServiceManager::GetScanServiceInst, instId: %{public}d", instId);
    std::unique_lock<std::mutex> lock(mScanMutex);

    auto iter = mScanServiceHandle.pService.find(instId);
    if (iter != mScanServiceHandle.pService.end()) {
        WIFI_LOGD("find a new scan service instance, instId: %{public}d", instId);
        return iter->second;
    }
    
    return nullptr;
}

#ifdef FEATURE_AP_SUPPORT
bool WifiServiceManager::ApServiceSetHotspotConfig(const HotspotConfig &config, int id)
{
    WIFI_LOGD("WifiServiceManager::GetApServiceInst");
    std::unique_lock<std::mutex> lock(mApMutex);
    auto iter = mApServiceHandle.pService.find(id);
    if (iter == mApServiceHandle.pService.end()) {
        WIFI_LOGE("Id %{public}d ap service is null", id);
        return false;
    }
    return iter->second->SetHotspotConfig(config);
}

IApService *WifiServiceManager::GetApServiceInst(int id)
{
    WIFI_LOGD("WifiServiceManager::GetApServiceInst");
    std::unique_lock<std::mutex> lock(mApMutex);
    auto iter = mApServiceHandle.pService.find(id);
    if (iter != mApServiceHandle.pService.end()) {
        WIFI_LOGD("Get id %{public}d ap service instance", id);
        return iter->second;
    }
    return nullptr;
}
#endif

#ifdef FEATURE_P2P_SUPPORT
IP2pService *WifiServiceManager::GetP2pServiceInst()
{
    WIFI_LOGD("WifiServiceManager::GetP2pServiceInst");
    std::unique_lock<std::mutex> lock(mP2pMutex);
    return mP2pServiceHandle.pService;
}
#endif

IEnhanceService *WifiServiceManager::GetEnhanceServiceInst()
{
#ifndef DTFUZZ_TEST
    WIFI_LOGD("WifiServiceManager::GetEnhanceServiceInst");
    std::unique_lock<std::mutex> lock(mEnhanceMutex);
    if (mEnhanceServiceHandle.handle == nullptr) {
        WIFI_LOGE("WifiServiceManager, Enhance handle is null");
        return nullptr;
    }
    if (mEnhanceServiceHandle.pService == nullptr) {
        mEnhanceServiceHandle.pService = mEnhanceServiceHandle.create();
    }
    return mEnhanceServiceHandle.pService;
#else
    return nullptr;
#endif
}

#ifdef FEATURE_WIFI_PRO_SUPPORT
NO_SANITIZE("cfi") int32_t WifiServiceManager::UnloadWifiProService(bool bPreLoad, int32_t instId)
{
    WIFI_LOGI("WifiServiceManager::UnloadWifiProService, instId: %{public}d", instId);
    std::unique_lock<std::mutex> lock(mWifiProMutex);

    auto iter = mWifiProServiceHandle.pService.find(instId);
    if (iter != mWifiProServiceHandle.pService.end()) {
        if (iter->second != nullptr) {
            delete iter->second;
            iter->second = nullptr;
        }
        mWifiProServiceHandle.pService.erase(iter);
    }

    if (!bPreLoad && mWifiProServiceHandle.pService.empty()) {
        mWifiProServiceHandle.Clear();
    }
    return 0;
}
#endif

#ifdef FEATURE_SELF_CURE_SUPPORT
NO_SANITIZE("cfi") int WifiServiceManager::UnloadSelfCureService(bool bPreLoad, int instId)
{
    WIFI_LOGI("WifiServiceManager::UnloadSelfCureService, instId: %{public}d", instId);
    std::unique_lock<std::mutex> lock(mSelfCureMutex);

    auto iter = mSelfCureServiceHandle.pService.find(instId);
    if (iter != mSelfCureServiceHandle.pService.end()) {
        if (iter->second != nullptr) {
            delete iter->second;
            iter->second = nullptr;
        }
        mSelfCureServiceHandle.pService.erase(iter);
    }

    if (!bPreLoad && mSelfCureServiceHandle.pService.empty()) {
        mSelfCureServiceHandle.Clear();
    }
    return 0;
}
#endif

NO_SANITIZE("cfi") int WifiServiceManager::UnloadStaService(bool bPreLoad, int instId)
{
    WIFI_LOGI("UnloadStaService, instId: %{public}d", instId);
    std::unique_lock<std::mutex> lock(mStaMutex);
    auto iter = mStaServiceHandle.pService.find(instId);
    if (iter != mStaServiceHandle.pService.end()) {
        if (iter->second != nullptr) {
            delete iter->second;
            iter->second = nullptr;
        }
        mStaServiceHandle.pService.erase(iter);
    }

    if (!bPreLoad && mStaServiceHandle.pService.empty()) {
        mStaServiceHandle.Clear();
    }
    return 0;
}

NO_SANITIZE("cfi") int WifiServiceManager::UnloadScanService(bool bPreLoad, int instId)
{
    WIFI_LOGI("UnloadScanService, instId: %{public}d", instId);
    std::unique_lock<std::mutex> lock(mScanMutex);

    auto iter = mScanServiceHandle.pService.find(instId);
    if (iter != mScanServiceHandle.pService.end()) {
        if (iter->second != nullptr) {
            delete iter->second;
            iter->second = nullptr;
        }
        mScanServiceHandle.pService.erase(iter);
    }

    if (!bPreLoad && mScanServiceHandle.pService.empty()) {
        mScanServiceHandle.Clear();
    }
    return 0;
}

#ifdef FEATURE_AP_SUPPORT
NO_SANITIZE("cfi") int WifiServiceManager::UnloadApService(bool bPreLoad, int id)
{
    WIFI_LOGI("WifiServiceManager::UnloadApService id=%{public}d", id);
    std::unique_lock<std::mutex> lock(mApMutex);
    auto iter = mApServiceHandle.pService.find(id);
    if (iter != mApServiceHandle.pService.end()) {
        if (iter->second != nullptr) {
            WifiApServiceUtil wifiApServiceUtil;
            wifiApServiceUtil.DestroyApInterface(iter->second);
            iter->second = nullptr;
        }
        mApServiceHandle.pService.erase(id);
    }

    if (!bPreLoad && mApServiceHandle.pService.empty()) {
        mApServiceHandle.Clear();
    }

    return 0;
}
#endif

#ifdef FEATURE_P2P_SUPPORT
NO_SANITIZE("cfi") int WifiServiceManager::UnloadP2pService(bool bPreLoad)
{
    WIFI_LOGI("WifiServiceManager::UnloadP2pService");
    std::unique_lock<std::mutex> lock(mP2pMutex);
    if (mP2pServiceHandle.pService != nullptr) {
        delete mP2pServiceHandle.pService;
        mP2pServiceHandle.pService = nullptr;
    }
    if (!bPreLoad) {
        mP2pServiceHandle.Clear();
    }
    return 0;
}
#endif

NO_SANITIZE("cfi") int WifiServiceManager::UnloadEnhanceService(bool bPreLoad)
{
    WIFI_LOGI("WifiServiceManager::UnloadEnhanceService");
    std::unique_lock<std::mutex> lock(mEnhanceMutex);
    if (mEnhanceServiceHandle.handle == nullptr) {
        WIFI_LOGE("WifiServiceManager::UnloadEnhanceService handle is null");
        return 0;
    }
    if (mEnhanceServiceHandle.pService != nullptr) {
        mEnhanceServiceHandle.destroy(mEnhanceServiceHandle.pService);
        mEnhanceServiceHandle.pService = nullptr;
    }
    if (!bPreLoad) {
        dlclose(mEnhanceServiceHandle.handle);
        mEnhanceServiceHandle.Clear();
    }
    return 0;
}

int WifiServiceManager::UnloadService(const std::string &name, int id)
{
    bool bPreLoad = WifiSettings::GetInstance().IsModulePreLoad(name);
    WIFI_LOGI("UnloadService name: %{public}s", name.c_str());
    if (name == WIFI_SERVICE_STA) {
        return UnloadStaService(bPreLoad, id);
    }
#ifdef FEATURE_WIFI_PRO_SUPPORT
    if (name == WIFI_SERVICE_WIFIPRO) {
        return UnloadWifiProService(bPreLoad, id);
    }
#endif
#ifdef FEATURE_SELF_CURE_SUPPORT
    if (name == WIFI_SERVICE_SELFCURE) {
        return UnloadSelfCureService(bPreLoad, id);
    }
#endif
    if (name == WIFI_SERVICE_SCAN) {
        return UnloadScanService(bPreLoad, id);
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
    if (name == WIFI_SERVICE_ENHANCE) {
        return UnloadEnhanceService(bPreLoad);
    }
    return -1;
}

void WifiServiceManager::UninstallAllService()
{
    WIFI_LOGI("WifiServiceManager::UninstallAllService");
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        UnloadStaService(false, i);
        UnloadScanService(false, i);
    }
#ifdef FEATURE_AP_SUPPORT
    for (int i = 0; i < AP_INSTANCE_MAX_NUM; ++i) {
        UnloadApService(false, i); /* all ap services */
    }
#endif
#ifdef FEATURE_P2P_SUPPORT
    UnloadP2pService(false);
#endif
#ifdef FEATURE_SELF_CURE_SUPPORT
    UnloadSelfCureService(false);
#endif
#ifdef FEATURE_WIFI_PRO_SUPPORT
    UnloadWifiProService(false);
#endif
    return;
}
#ifdef FEATURE_AP_SUPPORT
void* WifiApServiceUtil::libApServiceHandle_ = nullptr;
IApService *WifiApServiceUtil::CreateApInterface(int id)
{
    if (libApServiceHandle_ == nullptr) {
        return nullptr;
    }
    using CreateApInterfaceFunc = IApService *(*)(int);
    CreateApInterfaceFunc createApInterface =
        reinterpret_cast<CreateApInterfaceFunc>(wifiLibraryUtils_.GetFunction("CreateApInterface"));
    if (createApInterface == nullptr) {
        return nullptr;
    }
    return createApInterface(id);
}

void WifiApServiceUtil::DestroyApInterface(IApService *service)
{
    if (libApServiceHandle_ == nullptr) {
        return;
    }
    using DestroyApInterfaceFunc = void (*)(IApService *);
    DestroyApInterfaceFunc destroyApInterface =
        reinterpret_cast<DestroyApInterfaceFunc>(wifiLibraryUtils_.GetFunction("DestroyApInterface"));
    if (destroyApInterface == nullptr) {
        return;
    }
    destroyApInterface(service);
}
#endif
} // namespace Wifi
} // namespace OHOS
