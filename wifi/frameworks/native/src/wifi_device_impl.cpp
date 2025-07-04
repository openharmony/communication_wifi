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

#include "wifi_device_impl.h"
#include <new>
#ifndef OHOS_ARCH_LITE
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "wifi_sa_manager.h"
#endif
#include "wifi_device_proxy.h"
#include "wifi_device_mgr_proxy.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_LABEL("WifiDeviceImpl");

namespace OHOS {
namespace Wifi {
#define RETURN_IF_FAIL(cond)                          \
    do {                                              \
        if (!(cond)) {                                \
            WIFI_LOGI("'%{public}s' failed.", #cond); \
            return WIFI_OPT_FAILED;                   \
        }                                             \
    } while (0)

WifiDeviceImpl::WifiDeviceImpl() : systemAbilityId_(0), instId_(0), client_(nullptr)
{}

WifiDeviceImpl::~WifiDeviceImpl()
{
#ifdef OHOS_ARCH_LITE
    WifiDeviceProxy::ReleaseInstance();
#endif
}

bool WifiDeviceImpl::Init(int systemAbilityId, int instId)
{
#ifdef OHOS_ARCH_LITE
    WifiDeviceProxy *deviceProxy = WifiDeviceProxy::GetInstance();
    if (deviceProxy == nullptr) {
        WIFI_LOGE("get wifi device proxy failed.");
        return false;
    }
    if (deviceProxy->Init() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("wifi device proxy init failed.");
        WifiDeviceProxy::ReleaseInstance();
        return false;
    }
    client_ = deviceProxy;
    return true;
#else
    systemAbilityId_ = systemAbilityId;
    instId_ = instId;
    return true;
#endif
}

bool WifiDeviceImpl::GetWifiDeviceProxy()
{
#ifdef OHOS_ARCH_LITE
    return (client_ != nullptr);
#else
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
        WIFI_LOGE("failed to get DEVICE_SERVICE");
        WifiSaLoadManager::GetInstance().LoadWifiSa(systemAbilityId_);
        object = sa_mgr->GetSystemAbility(systemAbilityId_);
        if (object == nullptr) {
            WIFI_LOGE("failed to get DEVICE_SERVICE again!");
            return false;
        }
    }

    sptr<IWifiDeviceMgr> deviceMgr = iface_cast<IWifiDeviceMgr>(object);
    if (deviceMgr == nullptr) {
        deviceMgr = new (std::nothrow) WifiDeviceMgrProxy(object);
    }
    if (deviceMgr == nullptr) {
        WIFI_LOGE("wifi device init failed, %{public}d", systemAbilityId_.load());
        return false;
    }

    sptr<IRemoteObject> service = deviceMgr->GetWifiRemote(instId_);
    if (service == nullptr) {
        WIFI_LOGE("wifi device remote obj is null, %{public}d", instId_);
        return false;
    }

    client_ = iface_cast<IWifiDevice>(service);
    if (client_ == nullptr) {
        client_ = new (std::nothrow) WifiDeviceProxy(service);
    }
    if (client_ == nullptr) {
        WIFI_LOGE("wifi device instId_ %{public}d init failed. %{public}d", instId_, systemAbilityId_.load());
        return false;
    }
    return true;
#endif
}

ErrCode WifiDeviceImpl::EnableWifi()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->EnableWifi();
}

ErrCode WifiDeviceImpl::DisableWifi()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->DisableWifi();
}

ErrCode WifiDeviceImpl::InitWifiProtect(const WifiProtectType &protectType, const std::string &protectName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->InitWifiProtect(protectType, protectName);
}

ErrCode WifiDeviceImpl::GetWifiProtectRef(const WifiProtectMode &protectMode, const std::string &protectName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetWifiProtectRef(protectMode, protectName);
}

ErrCode WifiDeviceImpl::PutWifiProtectRef(const std::string &protectName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->PutWifiProtectRef(protectName);
}

ErrCode WifiDeviceImpl::IsHeldWifiProtectRef(const std::string &protectName, bool &isHeld)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->IsHeldWifiProtectRef(protectName, isHeld);
}

#ifndef OHOS_ARCH_LITE
ErrCode WifiDeviceImpl::IsHeldWifiProtect(bool &isHeld)
{
    std::string bundleName = GetBundleName();
    return IsHeldWifiProtectRef(bundleName, isHeld);
}

ErrCode WifiDeviceImpl::GetWifiProtect(const WifiProtectMode &protectMode)
{
    std::string bundleName = GetBundleName();
    return GetWifiProtectRef(protectMode, bundleName);
}

ErrCode WifiDeviceImpl::PutWifiProtect()
{
    std::string bundleName = GetBundleName();
    return PutWifiProtectRef(bundleName);
}
#endif
ErrCode WifiDeviceImpl::RemoveCandidateConfig(int networkId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->RemoveCandidateConfig(networkId);
}

ErrCode WifiDeviceImpl::RemoveCandidateConfig(const WifiDeviceConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->RemoveCandidateConfig(config);
}

ErrCode WifiDeviceImpl::AddDeviceConfig(const WifiDeviceConfig &config, int &result, bool isCandidate)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->AddDeviceConfig(config, result, isCandidate);
}

ErrCode WifiDeviceImpl::SetWifiRestrictedList(const std::vector<WifiRestrictedInfo> &wifiRestrictedInfoList)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->SetWifiRestrictedList(wifiRestrictedInfoList);
}

ErrCode WifiDeviceImpl::UpdateDeviceConfig(const WifiDeviceConfig &config, int &result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->UpdateDeviceConfig(config, result);
}

ErrCode WifiDeviceImpl::RemoveDevice(int networkId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->RemoveDevice(networkId);
}

ErrCode WifiDeviceImpl::RemoveAllDevice()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->RemoveAllDevice();
}

ErrCode WifiDeviceImpl::SetWifiTxPower(int power)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->SetTxPower(power);
}

ErrCode WifiDeviceImpl::GetDeviceConfigs(std::vector<WifiDeviceConfig> &result, bool isCandidate)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetDeviceConfigs(result, isCandidate);
}

ErrCode WifiDeviceImpl::EnableDeviceConfig(int networkId, bool attemptEnable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->EnableDeviceConfig(networkId, attemptEnable);
}

ErrCode WifiDeviceImpl::DisableDeviceConfig(int networkId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->DisableDeviceConfig(networkId);
}

ErrCode WifiDeviceImpl::AllowAutoConnect(int32_t networkId, bool isAllowed)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->AllowAutoConnect(networkId, isAllowed);
}

ErrCode WifiDeviceImpl::ConnectToNetwork(int networkId, bool isCandidate)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->ConnectToNetwork(networkId, isCandidate);
}

ErrCode WifiDeviceImpl::ConnectToDevice(const WifiDeviceConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->ConnectToDevice(config);
}

ErrCode WifiDeviceImpl::IsConnected(bool &isConnected)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->IsConnected(isConnected);
}

ErrCode WifiDeviceImpl::ReConnect()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->ReConnect();
}

ErrCode WifiDeviceImpl::ReAssociate()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->ReAssociate();
}

ErrCode WifiDeviceImpl::Disconnect()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->Disconnect();
}

ErrCode WifiDeviceImpl::StartWps(const WpsConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->StartWps(config);
}

ErrCode WifiDeviceImpl::CancelWps()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->CancelWps();
}

ErrCode WifiDeviceImpl::IsWifiActive(bool &bActive)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->IsWifiActive(bActive);
}

ErrCode WifiDeviceImpl::GetWifiState(int &state)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetWifiState(state);
}

ErrCode WifiDeviceImpl::GetLinkedInfo(WifiLinkedInfo &info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetLinkedInfo(info);
}

ErrCode WifiDeviceImpl::GetSignalPollInfoArray(std::vector<WifiSignalPollInfo> &wifiSignalPollInfos, int length)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetSignalPollInfoArray(wifiSignalPollInfos, length);
}

ErrCode WifiDeviceImpl::GetDisconnectedReason(DisconnectedReason &reason)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetDisconnectedReason(reason);
}

ErrCode WifiDeviceImpl::IsMeteredHotspot(bool &bMeteredHotspot)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->IsMeteredHotspot(bMeteredHotspot);
}

ErrCode WifiDeviceImpl::GetIpInfo(IpInfo &info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetIpInfo(info);
}

ErrCode WifiDeviceImpl::GetIpv6Info(IpV6Info &info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetIpv6Info(info);
}

ErrCode WifiDeviceImpl::SetCountryCode(const std::string &countryCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->SetCountryCode(countryCode);
}

ErrCode WifiDeviceImpl::GetCountryCode(std::string &countryCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetCountryCode(countryCode);
}

ErrCode WifiDeviceImpl::GetSignalLevel(const int &rssi, const int &band, int &level)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetSignalLevel(rssi, band, level);
}

#ifdef OHOS_ARCH_LITE
ErrCode WifiDeviceImpl::RegisterCallBack(const std::shared_ptr<IWifiDeviceCallBack> &callback,
    const std::vector<std::string> &event)
#else
ErrCode WifiDeviceImpl::RegisterCallBack(const sptr<IWifiDeviceCallBack> &callback,
    const std::vector<std::string> &event)
#endif
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->RegisterCallBack(callback, event);
}

ErrCode WifiDeviceImpl::GetSupportedFeatures(long &features)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetSupportedFeatures(features);
}

ErrCode WifiDeviceImpl::IsFeatureSupported(long feature, bool &isSupported)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    ErrCode ret = client_->IsFeatureSupported(feature, isSupported);
    if (ret != WIFI_OPT_SUCCESS) {
        return ret;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceImpl::GetDeviceMacAddress(std::string &result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetDeviceMacAddress(result);
}

ErrCode WifiDeviceImpl::IsBandTypeSupported(int bandType, bool &supported)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->IsBandTypeSupported(bandType, supported);
}

ErrCode WifiDeviceImpl::Get5GHzChannelList(std::vector<int> &result)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->Get5GHzChannelList(result);
}

ErrCode WifiDeviceImpl::StartPortalCertification()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->StartPortalCertification();
}

bool WifiDeviceImpl::SetLowLatencyMode(bool enabled)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->SetLowLatencyMode(enabled);
}

ErrCode WifiDeviceImpl::SetAppFrozen(std::set<int> pidList, bool isFrozen)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->SetAppFrozen(pidList, isFrozen);
}

ErrCode WifiDeviceImpl::ResetAllFrozenApp()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->ResetAllFrozenApp();
}

ErrCode WifiDeviceImpl::DisableAutoJoin(const std::string &conditionName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->DisableAutoJoin(conditionName);
}

ErrCode WifiDeviceImpl::EnableAutoJoin(const std::string &conditionName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->EnableAutoJoin(conditionName);
}

ErrCode WifiDeviceImpl::RegisterAutoJoinCondition(const std::string &conditionName,
                                                  const std::function<bool()> &autoJoinCondition)
{
    if (!autoJoinCondition) {
        WIFI_LOGE("the target of autoJoinCondition for %{public}s is empty", conditionName.c_str());
        return WIFI_OPT_FAILED;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->RegisterAutoJoinCondition(conditionName, autoJoinCondition);
}

ErrCode WifiDeviceImpl::DeregisterAutoJoinCondition(const std::string &conditionName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->DeregisterAutoJoinCondition(conditionName);
}

ErrCode WifiDeviceImpl::RegisterFilterBuilder(const FilterTag &filterTag,
                                              const std::string &filterName,
                                              const FilterBuilder &filterBuilder)
{
    if (!filterBuilder) {
        WIFI_LOGE("the target of filterBuilder for %{public}s is empty", filterName.c_str());
        return WIFI_OPT_FAILED;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->RegisterFilterBuilder(filterTag, filterName, filterBuilder);
}

ErrCode WifiDeviceImpl::DeregisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->DeregisterFilterBuilder(filterTag, filterName);
}

ErrCode WifiDeviceImpl::RegisterCommonBuilder(const TagType &tagType, const std::string &tagName,
                                              const CommonBuilder &commonBuilder)
{
    if (commonBuilder.IsEmpty()) {
        WIFI_LOGE("the target of commonBuilder for %{public}s is empty", tagName.c_str());
        return WIFI_OPT_FAILED;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->RegisterCommonBuilder(tagType, tagName, commonBuilder);
}
 
ErrCode WifiDeviceImpl::DeregisterCommonBuilder(const TagType &tagType, const std::string &tagName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->DeregisterCommonBuilder(tagType, tagName);
}

bool WifiDeviceImpl::IsRemoteDied(void)
{
    return (client_ == nullptr) ? true : client_->IsRemoteDied();
}

ErrCode WifiDeviceImpl::GetChangeDeviceConfig(ConfigChange& value, WifiDeviceConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetChangeDeviceConfig(value, config);
}

ErrCode WifiDeviceImpl::FactoryReset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->FactoryReset();
}

ErrCode WifiDeviceImpl::ReceiveNetworkControlInfo(const WifiNetworkControlInfo& networkControlInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->ReceiveNetworkControlInfo(networkControlInfo);
}

ErrCode WifiDeviceImpl::LimitSpeed(const int controlId, const int limitMode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->LimitSpeed(controlId, limitMode);
}

ErrCode WifiDeviceImpl::SetLowTxPower(const WifiLowPowerParam wifiLowPowerParam)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->SetLowTxPower(wifiLowPowerParam);
}

ErrCode WifiDeviceImpl::EnableHiLinkHandshake(bool uiFlag, std::string &bssid, WifiDeviceConfig &deviceConfig)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->EnableHiLinkHandshake(uiFlag, bssid, deviceConfig);
}

ErrCode WifiDeviceImpl::SetSatelliteState(const int state)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->SetSatelliteState(state);
}

ErrCode WifiDeviceImpl::EnableSemiWifi()
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->EnableSemiWifi();
}

ErrCode WifiDeviceImpl::GetWifiDetailState(WifiDetailState &state)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetWifiDetailState(state);
}

ErrCode WifiDeviceImpl::StartRoamToNetwork(const int networkId, const std::string bssid, const bool isCandidate)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->StartRoamToNetwork(networkId, bssid, isCandidate);
}

ErrCode WifiDeviceImpl::StartConnectToUserSelectNetwork(int networkId, std::string bssid, bool isCandidate)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->StartConnectToUserSelectNetwork(networkId, bssid, isCandidate);
}

ErrCode WifiDeviceImpl::GetDeviceConfig(const int &networkId, WifiDeviceConfig &config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetDeviceConfig(networkId, config);
}

ErrCode WifiDeviceImpl::SetDpiMarkRule(const std::string &ifaceName, int uid, int protocol, int enable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->SetDpiMarkRule(ifaceName, uid, protocol, enable);
}
 
ErrCode WifiDeviceImpl::UpdateNetworkLagInfo(const NetworkLagType networkLagType, const NetworkLagInfo &networkLagInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->UpdateNetworkLagInfo(networkLagType, networkLagInfo);
}

ErrCode WifiDeviceImpl::FetchWifiSignalInfoForVoWiFi(VoWifiSignalInfo &signalInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->FetchWifiSignalInfoForVoWiFi(signalInfo);
}
 
ErrCode WifiDeviceImpl::IsSupportVoWifiDetect(bool &isSupported)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->IsSupportVoWifiDetect(isSupported);
}
 
ErrCode WifiDeviceImpl::SetVoWifiDetectMode(WifiDetectConfInfo info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->SetVoWifiDetectMode(info);
}
 
ErrCode WifiDeviceImpl::GetVoWifiDetectMode(WifiDetectConfInfo &info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetVoWifiDetectMode(info);
}
 
ErrCode WifiDeviceImpl::SetVoWifiDetectPeriod(int period)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->SetVoWifiDetectPeriod(period);
}
 
ErrCode WifiDeviceImpl::GetVoWifiDetectPeriod(int &period)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetVoWifiDetectPeriod(period);
}

ErrCode WifiDeviceImpl::GetMultiLinkedInfo(std::vector<WifiLinkedInfo> &multiLinkedInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiDeviceProxy());
    return client_->GetMultiLinkedInfo(multiLinkedInfo);
}

}  // namespace Wifi
}  // namespace OHOS
