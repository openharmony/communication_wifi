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

#include <new>
#include "wifi_hotspot_proxy.h"
#include "wifi_hotspot_impl.h"
#include "iwifi_hotspot_mgr.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "wifi_hotspot_mgr_proxy.h"
#include "wifi_logger.h"
#include "wifi_sa_manager.h"
#include "wifi_common_util.h"
#include "wifi_hisysevent.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiHotspotImpl");

namespace OHOS {
namespace Wifi {
const int HOTSPOT_IDL_ERROR_OFFSET = 3500000;
sptr<WifiHotspotCallbackStub> WifiHotspotImpl::g_wifiHotspotCallbackStub =
    sptr<WifiHotspotCallbackStub>(new (std::nothrow) WifiHotspotCallbackStub());

#define RETURN_IF_FAIL(cond)                          \
    do {                                              \
        if (!(cond)) {                                \
            WIFI_LOGI("'%{public}s' failed.", #cond); \
            return WIFI_OPT_FAILED;                   \
        }                                             \
    } while (0)

WifiHotspotImpl::WifiHotspotImpl() : systemAbilityId_(0), instId(0), client_(nullptr), mRemoteDied(false)
{
    deathRecipient_ = new (std::nothrow) WifiHotspotDeathRecipient(*this);
    if (deathRecipient_ == nullptr) {
        WIFI_LOGE("Create WifiHotspotDeathRecipient failed!");
    }
}

WifiHotspotImpl::~WifiHotspotImpl()
{
    RemoveDeathRecipient();
}

void WifiHotspotImpl::WifiHotspotDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remoteObject)
{
    WIFI_LOGW("Remote hotspot service is died!");
    hotspotImpl_.HandleRemoteDied(remoteObject);
}

void WifiHotspotImpl::HandleRemoteDied(const wptr<IRemoteObject> &remoteObject)
{
    (void)remoteObject;
    std::lock_guard<std::mutex> lock(mutex_);
    mRemoteDied = true;
    client_ = nullptr;
    if (g_wifiHotspotCallbackStub != nullptr) {
        g_wifiHotspotCallbackStub->SetRemoteDied(true);
    } else {
        WIFI_LOGE("g_wifiHotspotCallbackStub is nullptr!");
    }
    WIFI_LOGW("Handle remote died success");
}

bool WifiHotspotImpl::RegisterDeathRecipient(const sptr<IRemoteObject> &remote)
{
    if (remote == nullptr || deathRecipient_ == nullptr) {
        WIFI_LOGE("remote or deathRecipient is null");
        return false;
    }
    if (!remote->IsProxyObject()) {
        WIFI_LOGW("not a proxy object, skip register");
        return true;
    }
    if (!remote->AddDeathRecipient(deathRecipient_)) {
        WIFI_LOGE("AddDeathRecipient failed");
        return false;
    }
    remoteService_ = remote;
    mRemoteDied = false;
    WIFI_LOGI("RegisterDeathRecipient success");
    return true;
}

void WifiHotspotImpl::RemoveDeathRecipient()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (remoteService_ == nullptr) {
        WIFI_LOGI("remoteService_ is nullptr!");
        return;
    }
    if (deathRecipient_ == nullptr) {
        WIFI_LOGI("deathRecipient_ is nullptr!");
        return;
    }
    remoteService_->RemoveDeathRecipient(deathRecipient_);
    remoteService_ = nullptr;
    WIFI_LOGI("RemoveDeathRecipient success");
}

bool WifiHotspotImpl::Init(int systemAbilityId, int id)
{
    systemAbilityId_ = systemAbilityId;
    instId = id;
    return true;
}

bool WifiHotspotImpl::GetWifiHotspotProxy()
{
    if (WifiSaLoadManager::GetInstance().LoadWifiSa(systemAbilityId_) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("failed to load hotspot sa !");
        return false;
    }
    if (!mRemoteDied && client_ != nullptr) {
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
        WIFI_LOGE("wifi hotspot init failed, %{public}d", systemAbilityId_.load());
        return false;
    }

    sptr<IRemoteObject> service;
    OHOS::ErrCode ret = hotspotMgr->GetWifiRemote(instId, service);
    ErrCode err = ErrCodeToWifiErrCode(ret);
    if (FAILED(err)) {
        WIFI_LOGE("GetWifiRemote failed, instId: %{public}d, error code: %{public}d", instId, err);
        return false;
    }
    if (service == nullptr) {
        WIFI_LOGE("wifi device remote obj is null, %{public}d", instId);
        return false;
    }

    return SetupClientWithDeathRecipient(service);
}

bool WifiHotspotImpl::SetupClientWithDeathRecipient(sptr<IRemoteObject> service)
{
    if (!RegisterDeathRecipient(service)) {
        WIFI_LOGE("Register death recipient failed");
        return false;
    }

    client_ = iface_cast<OHOS::Wifi::IWifiHotspot>(service);
    if (client_ == nullptr) {
        client_ = new (std::nothrow) WifiHotspotProxy(service);
    }
    if (client_ == nullptr) {
        WIFI_LOGE("wifi hotspot instId %{public}d init failed. %{public}d",
                  instId, systemAbilityId_.load());
        return false;
    }
    return true;
}

ErrCode WifiHotspotImpl::IsHotspotActive(bool &isActive)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->IsHotspotActive(isActive);
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::IsHotspotDualBandSupported(bool &isSupported)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->IsHotspotDualBandSupported(isSupported);
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::IsOpenSoftApAllowed(bool &isSupported)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->IsOpenSoftApAllowed(isSupported);
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::GetHotspotState(int &state)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->GetHotspotState(state);
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::GetHotspotConfig(HotspotConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    HotspotConfigParcel configParcel(config);
    OHOS::ErrCode ret = client_->GetHotspotConfig(configParcel);
    if (ret == WIFI_OPT_SUCCESS) {
        config = configParcel.ToHotspotConfig();
    }
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::SetHotspotConfig(const HotspotConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->SetHotspotConfig(config);
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::SetHotspotIdleTimeout(int time)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(client_);
    OHOS::ErrCode ret = client_->SetHotspotIdleTimeout(time);
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::GetStationList(std::vector<StationInfo> &result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    std::vector<StationInfoParcel> parcelResult;
    OHOS::ErrCode ret = client_->GetStationList(parcelResult);
    if (ret == WIFI_OPT_SUCCESS) {
        result.clear();
        result.reserve(parcelResult.size());
        for (const auto& p : parcelResult) {
            result.emplace_back(FromParcel(p));
        }
    }
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::DisassociateSta(const StationInfo &info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->DisassociateSta(ToParcel(info));
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::EnableHotspot(const ServiceType type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->EnableHotspot(ToParcel<ServiceTypeParcel>(type));
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::DisableHotspot(const ServiceType type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->DisableHotspot(ToParcel<ServiceTypeParcel>(type));
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::GetBlockLists(std::vector<StationInfo> &infos)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    std::vector<StationInfoParcel> parcelResult;
    OHOS::ErrCode ret = client_->GetBlockLists(parcelResult);
    if (ret == WIFI_OPT_SUCCESS) {
        infos.clear();
        infos.reserve(parcelResult.size());
        for (const auto& p : parcelResult) {
            infos.emplace_back(FromParcel(p));
        }
    }
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::AddBlockList(const StationInfo &info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->AddBlockList(ToParcel(info));
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::DelBlockList(const StationInfo &info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->DelBlockList(ToParcel(info));
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::GetValidBands(std::vector<BandType> &bands)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    std::vector<BandTypeParcel> parcelBands;
    OHOS::ErrCode ret = client_->GetValidBands(parcelBands);
    if (ret == WIFI_OPT_SUCCESS) {
        bands.clear();
        for (const auto& p : parcelBands) {
            bands.emplace_back(FromParcel<BandType>(p));
        }
    }
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::GetValidChannels(BandType band, std::vector<int32_t> &validchannels)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->GetValidChannels(ToParcel<BandTypeParcel>(band), validchannels);
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::RegisterCallBack(const sptr<IWifiHotspotCallback> &callback,
    const std::vector<std::string> &event)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    if (g_wifiHotspotCallbackStub != nullptr) {
        g_wifiHotspotCallbackStub->RegisterCallBack(callback);
    }
    sptr<IRemoteObject> remoteObj = g_wifiHotspotCallbackStub->AsObject();
    sptr<IRemoteObject> &cb = remoteObj;
    OHOS::ErrCode ret = client_->RegisterCallBack(cb, event);
    if (ret > HOTSPOT_IDL_ERROR_OFFSET) {
        ret = WIFI_OPT_SUCCESS;
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), WifiScanFailReason::HOTSPOT_REGISTERCALLBACK_FAIL);
    }
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::GetSupportedFeatures(long &features)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    int64_t featuresInt64 = 0;
    OHOS::ErrCode ret = client_->GetSupportedFeatures(featuresInt64);
    features = static_cast<long>(featuresInt64);
    return ErrCodeToWifiErrCode(ret);
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
    std::set<PowerModelParcel> parcelSet;
    OHOS::ErrCode ret = client_->GetSupportedPowerModel(parcelSet);
    if (ret == WIFI_OPT_SUCCESS) {
        setPowerModelList.clear();
        for (const auto& p : parcelSet) {
            setPowerModelList.insert(FromParcel<PowerModel>(p));
        }
    }
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::GetPowerModel(PowerModel& model)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    PowerModelParcel parcelModel;
    OHOS::ErrCode ret = client_->GetPowerModel(parcelModel);
    if (ret == WIFI_OPT_SUCCESS) {
        model = FromParcel<PowerModel>(parcelModel);
    }
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::SetPowerModel(const PowerModel& model)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->SetPowerModel(ToParcel<PowerModelParcel>(model));
    return ErrCodeToWifiErrCode(ret);
}

bool WifiHotspotImpl::IsRemoteDied(void)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (mRemoteDied) {
        WIFI_LOGW("Remote service is died!");
    }
    return mRemoteDied;
}

ErrCode WifiHotspotImpl::GetApIfaceName(std::string& ifaceName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->GetApIfaceName(ifaceName);
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::EnableLocalOnlyHotspot(const ServiceType type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->EnableLocalOnlyHotspot(ToParcel<ServiceTypeParcel>(type));
    return ErrCodeToWifiErrCode(ret);
}
 
ErrCode WifiHotspotImpl::DisableLocalOnlyHotspot(const ServiceType type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    OHOS::ErrCode ret = client_->DisableLocalOnlyHotspot(ToParcel<ServiceTypeParcel>(type));
    return ErrCodeToWifiErrCode(ret);
}
 
ErrCode WifiHotspotImpl::GetHotspotMode(HotspotMode &mode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    HotspotModeParcel parcelModel;
    OHOS::ErrCode ret = client_->GetHotspotMode(parcelModel);
    if (ret == WIFI_OPT_SUCCESS) {
        mode = FromParcel<HotspotMode>(parcelModel);
    }
    return ErrCodeToWifiErrCode(ret);
}
 
ErrCode WifiHotspotImpl::GetLocalOnlyHotspotConfig(HotspotConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiHotspotProxy());
    HotspotConfigParcel configParcel(config);
    OHOS::ErrCode ret = client_->GetLocalOnlyHotspotConfig(configParcel);
    if (ret == WIFI_OPT_SUCCESS) {
        config = configParcel.ToHotspotConfig();
    }
    return ErrCodeToWifiErrCode(ret);
}

ErrCode WifiHotspotImpl::ErrCodeToWifiErrCode(OHOS::ErrCode errorCode)
{
    ErrCode WifiErrCode = WIFI_OPT_FAILED;
    if (errorCode == WIFI_OPT_SUCCESS) {
        WifiErrCode = static_cast<ErrCode>(errorCode);
    } else if (errorCode > HOTSPOT_IDL_ERROR_OFFSET) {
        WifiErrCode = static_cast<ErrCode>(errorCode - HOTSPOT_IDL_ERROR_OFFSET);
    } else {
        WifiErrCode = WIFI_OPT_FAILED;
    }
    return WifiErrCode;
}
}  // namespace Wifi
}  // namespace OHOS
