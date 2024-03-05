/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifi_sa_manager.h"

#include "iremote_broker.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "wifi_logger.h"
#include "wifi_errcode.h"
DEFINE_WIFILOG_LABEL("WifiSaLoadManager");

namespace OHOS {
namespace Wifi {
static constexpr int32_t WIFI_LOADSA_TIMEOUT_MS = 1000;

WifiSaLoadManager& WifiSaLoadManager::GetInstance()
{
    static auto instance = new WifiSaLoadManager();
    return * instance;
}

ErrCode WifiSaLoadManager::LoadWifiSa(int32_t systemAbilityId)
{
    WIFI_LOGD("%{public}s enter, systemAbilityId = [%{public}d] loading", __func__, systemAbilityId);
    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        WIFI_LOGE("%{public}s: get system ability manager failed!", __func__);
        return WIFI_OPT_FAILED;
    }
    auto object = samgr->CheckSystemAbility(systemAbilityId);
    if (object != nullptr) {
        return WIFI_OPT_SUCCESS;
    }
    InitLoadState();
    sptr<WifiSaLoadCallback> loadCallback = new (std::nothrow) WifiSaLoadCallback();
    if (loadCallback == nullptr) {
        WIFI_LOGE("%{public}s: wifi sa load callback failed!", __func__);
        return WIFI_OPT_FAILED;
    }
    int32_t ret = samgr->LoadSystemAbility(systemAbilityId, loadCallback);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("%{public}s: Failed to load system ability, SA Id = [%{public}d], ret = [%{public}d].",
            __func__, systemAbilityId, ret);
        return WIFI_OPT_FAILED;
    }
    return WaitLoadStateChange(systemAbilityId);
}

void WifiSaLoadManager::InitLoadState()
{
    std::unique_lock<std::mutex> lock(locatorMutex_);
    state_ = false;
}

ErrCode WifiSaLoadManager::WaitLoadStateChange(int32_t systemAbilityId)
{
    std::unique_lock<std::mutex> lock(locatorMutex_);
    auto wait = locatorCon_.wait_for(lock, std::chrono::milliseconds(WIFI_LOADSA_TIMEOUT_MS), [this] {
        return state_ == true;
    });
    if (!wait) {
        WIFI_LOGE("locator sa [%{public}d] start time out.", systemAbilityId);
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiSaLoadManager::UnloadWifiSa(int32_t systemAbilityId)
{
    WIFI_LOGI("%{public}s enter, systemAbilityId = [%{public}d] unloading", __func__, systemAbilityId);
    sptr<ISystemAbilityManager> samgr =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        WIFI_LOGE("%{public}s: get system ability manager failed!", __func__);
        return WIFI_OPT_FAILED;
    }
    int32_t ret = samgr->UnloadSystemAbility(systemAbilityId);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("%{public}s: Failed to unload system ability, SA Id = [%{public}d], ret = [%{public}d].",
            __func__, systemAbilityId, ret);
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

void WifiSaLoadManager::LoadSystemAbilitySuccess()
{
    std::unique_lock<std::mutex> lock(locatorMutex_);
    state_ = true;
    locatorCon_.notify_one();
}

void WifiSaLoadManager::LoadSystemAbilityFail()
{
    std::unique_lock<std::mutex> lock(locatorMutex_);
    state_ = false;
    locatorCon_.notify_one();
}

void WifiSaLoadCallback::OnLoadSystemAbilitySuccess(
    int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject)
{
    WIFI_LOGD("WifiSaLoadManager Load SA success, systemAbilityId = [%{public}d]", systemAbilityId);
    WifiSaLoadManager::GetInstance().LoadSystemAbilitySuccess();
}

void WifiSaLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    WIFI_LOGI("WifiSaLoadManager Load SA failed, systemAbilityId = [%{public}d]", systemAbilityId);
    WifiSaLoadManager::GetInstance().LoadSystemAbilityFail();
}
}; // namespace Wifi
}; // namespace OHOS