/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_ASSET_MANAGER_H
#define OHOS_WIFI_ASSET_MANAGER_H
#ifdef SUPPORT_ClOUD_WIFI_ASSET
#include <string>
#include "asset_system_type.h"
#include "asset_system_api.h"
#include "wifi_msg.h"
#include "wifi_event_handler.h"
#include "sta_service_callback.h"

namespace OHOS {
namespace Wifi {
constexpr uint32_t SIZE_OF_ITEM = 13;
constexpr int32_t USER_ID_DEFAULT = 100;
bool IsExistInAsset(const WifiDeviceConfig &config, std::string key);
void SplitString(const std::string &input, const char spChar, std::vector<std::string> &outArray);
bool CheckEap(const WifiDeviceConfig &config);
bool CheckWapi(const WifiDeviceConfig &config);
bool IsWapiOrEap(const WifiDeviceConfig &config);
bool ArrayToWifiDeviceConfig(WifiDeviceConfig &config, std::vector<std::string> &outArray);
bool WifiAssetValid(const WifiDeviceConfig &config);
class WifiAssetManager {
public:
    WifiAssetManager();
 
    ~WifiAssetManager();
 
    static WifiAssetManager &GetInstance();

    void InitUpLoadLocalDeviceSync();
 
    void CloudAssetSync();

    void WifiAssetTriggerSync();
 
    void WifiAssetAdd(const WifiDeviceConfig &config, int32_t userId = USER_ID_DEFAULT, bool flagSync = true);
 
    void WifiAssetQuery(int32_t userId = USER_ID_DEFAULT);
 
    void WifiAssetUpdate(const WifiDeviceConfig &config, int32_t userId = USER_ID_DEFAULT);
 
    void WifiAssetRemove(const WifiDeviceConfig &config,
        int32_t userId = USER_ID_DEFAULT, bool flagSync = true);
 
    void WifiAssetAddPack(const std::vector<WifiDeviceConfig> &wifiDeviceConfigs,
        int32_t userId = USER_ID_DEFAULT, bool flagSync = true, bool firstSync = false);
 
    void WifiAssetRemovePack(const std::vector<WifiDeviceConfig> &wifiDeviceConfigs,
        int32_t userId = USER_ID_DEFAULT, bool flagSync = true);
 
    void WifiAssetRemoveAll(int32_t userId = USER_ID_DEFAULT, bool flagSync = true);
 
    void WifiAssetUpdatePack(const std::vector<WifiDeviceConfig> &wifiDeviceConfigs,
        int32_t userId = USER_ID_DEFAULT);
 
    bool IsWifiConfigChanged(const WifiDeviceConfig &config, const WifiDeviceConfig &oriConfig);
 
    bool IsWifiConfigUpdated(const std::vector<WifiDeviceConfig> newWifiDeviceConfigs, WifiDeviceConfig &config);

    StaServiceCallback GetStaCallback() const;

    void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId);

private:
    std::unique_ptr<WifiEventHandler> assetServiceThread_ = nullptr;
    std::atomic<bool> firstSync_ = false;
    StaServiceCallback staCallback_;
    int currentConnectedNetworkId_ = -1;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
#endif