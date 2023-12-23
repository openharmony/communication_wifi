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

#include "wifi_hotspot_impl.h"
#include <new>
#include "wifi_hotspot_proxy.h"
#include "i_wifi_hotspot_mgr.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "wifi_hotspot_mgr_proxy.h"
#include "wifi_logger.h"
#include "wifi_sa_manager.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiHotspotImpl");

namespace OHOS {
namespace Wifi {
#define RETURN_IF_FAIL(cond)                          \
    do {                                              \
        if (!(cond)) {                                \
            WIFI_LOGI("'%{public}s' failed.", #cond); \
            return WIFI_OPT_FAILED;                   \
        }                                             \
    } while (0)

WifiHotspotImpl::WifiHotspotImpl() : systemAbilityId_(0), instId(0), client_(nullptr)
{}

WifiHotspotImpl::~WifiHotspotImpl()
{}

bool WifiHotspotImpl::Init(int systemAbilityId, int id)
{
    systemAbilityId_ = systemAbilityId;
    instId = id;
    return true;
}

bool WifiHotspotImpl::GetWifiHotspotProxy()
{
    WifiSaLoadManager::GetInstance().LoadWifiSa(systemAbilityId_);
    if (IsRemoteDied() == false) {
        return true;
    }
    sptr<ISystemAbilityManager> sa_mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sa_mgr == nullptr) {
        WIFI_LOGE("failed to get SystemAbilityManager");
        return false;
    }
    sptr<IRemoteObject> object = sa_mgr->GetSystemAbility(systemAbilityId_);
    if (object == nullptr) {
        WIFI_LOGE("failed to get hotspot mgr");
        return false;
    }

    sptr<IWifiHotspotMgr> hotspotMgr = iface_cast<IWifiHotspotMgr>(object);
    if (hotspotMgr == nullptr) {
        hotspotMgr = new (std::nothrow) WifiHotspotMgrProxy(object);
    }
    if (hotspotMgr == nullptr) {
        WIFI_LOGE("wifi hotspot init failed, %{public}d", systemAbilityId_);
        return false;
    }

    sptr<IRemoteObject> service = hotspotMgr->GetWifiRemote(instId);
    if (service == nullptr) {
        WIFI_LOGE("wifi device remote obj is null, %{public}d", instId);
        return false;
    }

    client_ = new (std::nothrow) WifiHotspotProxy(service);
    if (client_ == nullptr) {
        WIFI_LOGE("wifi device id init failed., %{public}d", systemAbilityId_);
        return false;
    }
    return true;
}

ErrCode WifiHotspotImpl::IsHotspotActive(bool &isActive)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->IsHotspotActive(isActive);
}

ErrCode WifiHotspotImpl::IsHotspotDualBandSupported(bool &isSupported)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->IsHotspotDualBandSupported(isSupported);
}

ErrCode WifiHotspotImpl::GetHotspotState(int &state)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->GetHotspotState(state);
}

ErrCode WifiHotspotImpl::GetHotspotConfig(HotspotConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->GetHotspotConfig(config);
}

ErrCode WifiHotspotImpl::SetHotspotConfig(const HotspotConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->SetHotspotConfig(config);
}

ErrCode WifiHotspotImpl::SetHotspotIdleTimeout(int time)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(client_);
    return client_->SetHotspotIdleTimeout(time);
}

ErrCode WifiHotspotImpl::GetStationList(std::vector<StationInfo> &result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->GetStationList(result);
}

ErrCode WifiHotspotImpl::DisassociateSta(const StationInfo &info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->DisassociateSta(info);
}

ErrCode WifiHotspotImpl::EnableHotspot(const ServiceType type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->EnableHotspot(type);
}

ErrCode WifiHotspotImpl::DisableHotspot(const ServiceType type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->DisableHotspot(type);
}

ErrCode WifiHotspotImpl::GetBlockLists(std::vector<StationInfo> &infos)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->GetBlockLists(infos);
}

ErrCode WifiHotspotImpl::AddBlockList(const StationInfo &info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->AddBlockList(info);
}

ErrCode WifiHotspotImpl::DelBlockList(const StationInfo &info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->DelBlockList(info);
}

ErrCode WifiHotspotImpl::GetValidBands(std::vector<BandType> &bands)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->GetValidBands(bands);
}

ErrCode WifiHotspotImpl::GetValidChannels(BandType band, std::vector<int32_t> &validchannels)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->GetValidChannels(band, validchannels);
}

ErrCode WifiHotspotImpl::RegisterCallBack(const sptr<IWifiHotspotCallback> &callback,
    const std::vector<std::string> &event)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->RegisterCallBack(callback, event);
}

ErrCode WifiHotspotImpl::GetSupportedFeatures(long &features)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->GetSupportedFeatures(features);
}

bool WifiHotspotImpl::IsFeatureSupported(long feature)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    long tmpFeatures = 0;
    if (client_->GetSupportedFeatures(tmpFeatures) != WIFI_OPT_SUCCESS) {
        return false;
    }
    return ((tmpFeatures & feature) == feature);
}

ErrCode WifiHotspotImpl::GetSupportedPowerModel(std::set<PowerModel>& setPowerModelList)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->GetSupportedPowerModel(setPowerModelList);
}

ErrCode WifiHotspotImpl::GetPowerModel(PowerModel& model)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->GetPowerModel(model);
}

ErrCode WifiHotspotImpl::SetPowerModel(const PowerModel& model)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->SetPowerModel(model);
}

bool WifiHotspotImpl::IsRemoteDied(void)
{
    return (client_ == nullptr) ? true : client_->IsRemoteDied();
}

ErrCode WifiHotspotImpl::GetApIfaceName(std::string& ifaceName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    return client_->GetApIfaceName(ifaceName);
}
}  // namespace Wifi
}  // namespace OHOS
