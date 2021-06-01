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

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "base_service.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
struct ServiceHandle {
    void *handle;                    /* Loads the SO handle. */
    BaseService *(*create)();        /* Address of the Create function in the SO. */
    void *(*destroy)(BaseService *); /* Address of the Destroy function in the SO */
    BaseService *bs;                 /* Feature Service Object */
    ServiceHandle() : handle(nullptr), create(nullptr), destroy(nullptr), bs(nullptr)
    {}
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
    int CheckAndEnforceService(const std::string &name, bool bCreate = true);

    /**
     * @Description Obtaining Loaded Feature Service Objects
     *
     * @param name - feature service name
     * @return BaseService* - service pointer, if no feature service is loaded, nullptr is returned
     */
    BaseService *GetServiceInst(const std::string &name);

    /**
     * @Description unload a feature service
     *
     * @param name - feature service name
     * @return int - 0 success
     */
    int UnloadService(const std::string &name);

    /**
     * @Description Uninstall all loaded feature services
     *
     */
    void UninstallAllService();
    static WifiServiceManager &GetInstance();

private:
    int GetServiceDll(const std::string &name, std::string &dlname);
private:
    std::mutex mMutex;
    std::unordered_map<std::string, ServiceHandle> mServiceHandleMap;
    std::unordered_map<std::string, std::string> mServiceDllMap;
};
} // namespace Wifi
} // namespace OHOS
#endif