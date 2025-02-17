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

#ifndef OHOS_WIFI_SERVICE_MANAGER_H
#define OHOS_WIFI_SERVICE_MANAGER_H

#include <mutex>
#include <string>
#include <unordered_map>

#include "ista_service.h"
#include "iscan_service.h"
#include "wifi_library_utils.h"
#ifdef FEATURE_AP_SUPPORT
#include "i_ap_service.h"
#endif
#ifdef FEATURE_P2P_SUPPORT
#include "ip2p_service.h"
#endif
#include "ienhance_service.h"
#ifdef FEATURE_SELF_CURE_SUPPORT
#include "iself_cure_service.h"
#endif
#ifdef FEATURE_WIFI_PRO_SUPPORT
#include "iwifi_pro_service.h"
#endif

namespace OHOS {
namespace Wifi {
struct StaServiceHandle {
    std::map<int, IStaService *> pService;
    StaServiceHandle()
    {}
    ~StaServiceHandle()
    {}
    void Clear()
    {
        pService.clear();
    }
};

#ifdef FEATURE_WIFI_PRO_SUPPORT
struct WifiProServiceHandle {
    std::map<int, IWifiProService *> pService;
    WifiProServiceHandle()
    {}
    ~WifiProServiceHandle()
    {}
    void Clear()
    {
        pService.clear();
    }
};
#endif

#ifdef FEATURE_SELF_CURE_SUPPORT
struct SelfCureServiceHandle {
    std::map<int, ISelfCureService *> pService;
    SelfCureServiceHandle()
    {}
    ~SelfCureServiceHandle()
    {}
    void Clear()
    {
        pService.clear();
    }
};
#endif

struct ScanServiceHandle {
    std::map<int, IScanService *> pService;
    ScanServiceHandle()
    {}
    ~ScanServiceHandle()
    {}
    void Clear()
    {
        pService.clear();
    }
};

#ifdef FEATURE_AP_SUPPORT
struct ApServiceHandle {
    std::map<int, IApService *> pService;
    ApServiceHandle()
    {}
    ~ApServiceHandle()
    {}
    void Clear()
    {
        pService.clear();
    }
};
#endif

#ifdef FEATURE_P2P_SUPPORT
struct P2pServiceHandle {
    IP2pService *pService;
    P2pServiceHandle() : pService(nullptr)
    {}
    ~P2pServiceHandle()
    {}
    void Clear()
    {
        pService = nullptr;
    }
};
#endif
struct EnhanceServiceHandle {
    void *handle;
    IEnhanceService *(*create)();
    void *(*destroy)(IEnhanceService *);
    IEnhanceService *pService;
    EnhanceServiceHandle() : handle(nullptr), create(nullptr), destroy(nullptr), pService(nullptr)
    {}
    ~EnhanceServiceHandle()
    {}
    void Clear()
    {
        handle = nullptr;
        create = nullptr;
        destroy = nullptr;
        pService = nullptr;
    }
};
class WifiServiceManager {
public:
    WifiServiceManager();
    ~WifiServiceManager();

    /**
     * @Description Initialize the mapping between feature service names and SO paths
     *
     * @return int - init result, when 0 means success, other means some fails happened
     */
    int Init();

    /**
     * @Description Check preload config, maybe need preload feature service
     *
     * @return int - 0 need preload; other no need preload
     */
    int CheckPreLoadService(void);

    /**
     * @Description Check the feature service. If the service is not loaded, continue to load the service
     *
     * @param name - feature service name
     * @param bCreate - whether create the service instance
     * @return int - 0 success; -1 feature service name not correct or load service failed
     */
    int CheckAndEnforceService(const std::string &name, int instId = 0, bool bCreate = true);

    /**
     * @Description Get the Sta Service Inst object
     *
     * @return IStaService* - sta service pointer, if sta not supported, nullptr is returned
     */
    IStaService *GetStaServiceInst(int instId = 0);

#ifdef FEATURE_SELF_CURE_SUPPORT
    /**
     * @Description Get the SelfCure Service Inst object
     *
     * @return ISelfCureService* - self cure service pointer, if self cure not supported, nullptr is returned
     */
    ISelfCureService *GetSelfCureServiceInst(int instId = 0);
#endif

#ifdef FEATURE_WIFI_PRO_SUPPORT
    /**
     * @Description Get the WifiPro Service Inst object
     *
     * @return IWifiProService* - wifi pro service pointer, if wifi pro not supported, nullptr is returned
     */
    IWifiProService *GetWifiProServiceInst(int32_t instId);
#endif

    /**
     * @Description Get the Scan Service Inst object
     *
     * @return IScanService* - scan service pointer, if scan not supported, nullptr is returned
     */
    IScanService *GetScanServiceInst(int instId = 0);

#ifdef FEATURE_AP_SUPPORT
    /**
     * @Description set hotspots config
     *
     * @return true false
     */
    bool ApServiceSetHotspotConfig(const HotspotConfig &config, int id);
    /**
     * @Description Get the Ap Service Inst object
     *
     * @return IApService* - ap service pointer, if ap not supported, nullptr is returned
     */
    IApService *GetApServiceInst(int id = 0);
#endif

#ifdef FEATURE_P2P_SUPPORT
    /**
     * @Description Get the P2P Service Inst object
     *
     * @return IP2pService* - p2p service pointer, if p2p not supported, nullptr is returned
     */
    IP2pService *GetP2pServiceInst(void);
#endif
    /**
     * @Description Get the Enhance Service Inst object
     *
     * @return IEnhanceService* - Enhance service pointer, if Enhance not supported, nullptr is returned
     */
    IEnhanceService *GetEnhanceServiceInst(void);
    /**
     * @Description unload a feature service
     *
     * @param name - feature service name
     * @return int - 0 success
     */
    int UnloadService(const std::string &name, int id = 0);

    /**
     * @Description Uninstall all loaded feature services
     *
     */
    void UninstallAllService();
    static WifiServiceManager &GetInstance();

private:
    int GetServiceDll(const std::string &name, std::string &dlname);
    int LoadStaService(const std::string &dlname, int instId, bool bCreate);
    int UnloadStaService(bool bPreLoad, int instId = 0);
#ifdef FEATURE_WIFI_PRO_SUPPORT
    int32_t LoadWifiProService(bool bCreate, int32_t instId = 0);
    int32_t UnloadWifiProService(bool bPreLoad, int32_t instId = 0);
#endif
#ifdef FEATURE_SELF_CURE_SUPPORT
    int LoadSelfCureService(const std::string &dlname, bool bCreate);
    int UnloadSelfCureService(bool bPreLoad, int instId = 0);
#endif
    int LoadScanService(const std::string &dlname, bool bCreate);
    int UnloadScanService(bool bPreLoad, int instId = 0);
#ifdef FEATURE_AP_SUPPORT
    int LoadApService(const std::string &dlname, bool bCreate);
    int UnloadApService(bool bPreLoad, int id = 0);
#endif
#ifdef FEATURE_P2P_SUPPORT
    int LoadP2pService(const std::string &dlname, bool bCreate);
    int UnloadP2pService(bool bPreLoad);
#endif
    int LoadEnhanceService(const std::string &dlname, bool bCreate);
    int UnloadEnhanceService(bool bPreLoad);
private:
    std::mutex mStaMutex;
    std::mutex mSelfCureMutex;
    std::mutex mWifiProMutex;
    std::mutex mScanMutex;
    std::mutex mP2pMutex;
    std::mutex mApMutex;
    std::mutex mEnhanceMutex;
    std::unordered_map<std::string, std::string> mServiceDllMap;
    StaServiceHandle mStaServiceHandle;
#ifdef FEATURE_WIFI_PRO_SUPPORT
    WifiProServiceHandle mWifiProServiceHandle;
#endif
#ifdef FEATURE_SELF_CURE_SUPPORT
    SelfCureServiceHandle mSelfCureServiceHandle;
#endif
    ScanServiceHandle mScanServiceHandle;
#ifdef FEATURE_AP_SUPPORT
    ApServiceHandle mApServiceHandle;
#endif
#ifdef FEATURE_P2P_SUPPORT
    P2pServiceHandle mP2pServiceHandle;
#endif
    EnhanceServiceHandle mEnhanceServiceHandle;
};

#ifdef FEATURE_AP_SUPPORT
class WifiApServiceUtil {
public:
    WifiApServiceUtil() : wifiLibraryUtils_ ("libwifi_ap_service.z.so", libApServiceHandle_, false) {}
    ~WifiApServiceUtil() {}
    IApService *CreateApInterface(int id);
    void DestroyApInterface(IApService *apService);
private:
    WifiLibraryUtils wifiLibraryUtils_;
    static void* libApServiceHandle_;
};
#endif
} // namespace Wifi
} // namespace OHOS
#endif