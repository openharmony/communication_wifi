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

#include "wifi_hotspot_service_impl.h"
#include <csignal>
#include <limits>
#include "wifi_permission_utils.h"
#include "wifi_global_func.h"
#include "wifi_auth_center.h"
#include "wifi_channel_helper.h"
#include "wifi_manager.h"
#include "wifi_hotspot_callback_proxy.h"
#include "wifi_service_manager.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_logger.h"
#include "define.h"
#include "wifi_common_util.h"
#include "wifi_country_code_manager.h"
#include "mac_address.h"
#include "wifi_randommac_helper.h"
#include "ap_config_use.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiHotspotServiceImpl");

namespace OHOS {
namespace Wifi {
const int HOTSPOT_IDL_ERROR_OFFSET = 3500000;

WifiHotspotServiceImpl::WifiHotspotServiceImpl()
{}

WifiHotspotServiceImpl::WifiHotspotServiceImpl(int id) : WifiHotspotStub(id)
{}

WifiHotspotServiceImpl::~WifiHotspotServiceImpl()
{}

int32_t WifiHotspotServiceImpl::IsHotspotActive(bool &bActive)
{
    WIFI_LOGI("Instance %{public}d %{public}s!", m_id, __func__);
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsHotspotActive:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    bActive = IsApServiceRunning() || IsRptRunning();
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::IsHotspotDualBandSupported(bool &isSupported)
{
    WIFI_LOGI("IsHotspotDualBandSupported");
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("IsHotspotDualBandSupported:NOT System APP, PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsHotspotDualBandSupported:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }

    if (WifiPermissionUtils::VerifyManageWifiHotspotPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsHotspotDualBandSupported:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }

    std::vector<BandType> bands;
    ApConfigUse::GetInstance().GetApVaildBands(bands);

    bool is2GSupported = false;
    bool is5GSupported = false;
    isSupported = false;
    for (size_t i = 0; i < bands.size(); i++) {
        if (bands[i] == BandType::BAND_2GHZ) {
            is2GSupported = true;
        } else if (bands[i] == BandType::BAND_5GHZ) {
            is5GSupported = true;
        }
        if (is2GSupported && is5GSupported) {
            isSupported = true;
            break;
        }
    }

    WIFI_LOGI("2.4G band supported: %{public}d, 5G band supported: %{public}d", is2GSupported, is5GSupported);
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::IsOpenSoftApAllowed(bool &isSupported)
{
    WIFI_LOGI("IsOpenSoftApAllowed enter");
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("IsOpenSoftApAllowed:NOT System APP, PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsOpenSoftApAllowed:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }

    if (WifiPermissionUtils::VerifyManageWifiHotspotPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsOpenSoftApAllowed:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    if (WifiManager::GetInstance().GetWifiTogglerManager() == nullptr) {
        WIFI_LOGE("IsOpenSoftApAllowed, GetWifiTogglerManager get failed");
        return HandleHotspotIdlRet(WIFI_OPT_FAILED);
    }
    auto &wifiControllerMachine = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    if (wifiControllerMachine != nullptr && wifiControllerMachine->IsOpenSoftApAllowed(0)) {
        isSupported = true;
        return WIFI_OPT_SUCCESS;
    }
    WIFI_LOGI("IsOpenSoftApAllowed: false");
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::GetHotspotState(int &state)
{
    WIFI_LOGI("Instance %{public}d %{public}s!", m_id, __func__);
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetHotspotState:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }

    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetHotspotState:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }

    state = WifiConfigCenter::GetInstance().GetHotspotState(m_id);
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::GetHotspotConfig(HotspotConfigParcel &parcelconfig)
{
    WIFI_LOGI("Instance %{public}d %{public}s!", m_id, __func__);
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetHotspotConfig:NOT System APP, PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetHotspotConfig:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }

    if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetHotspotConfig:VerifyGetWifiConfigPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    HotspotConfig config;
    WifiSettings::GetInstance().GetHotspotConfig(config, m_id);
    parcelconfig.FromHotspotConfig(config);
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::SetHotspotConfig(const HotspotConfigParcel &parcelconfig)
{
    HotspotConfig config = parcelconfig.ToHotspotConfig();
#ifndef OHOS_ARCH_LITE
    WIFI_LOGI("Inst%{public}d %{public}s, pid:%{public}d, uid:%{public}d, band:%{public}d, "
        "channel:%{public}d", m_id, __func__, GetCallingPid(), GetCallingUid(),
        static_cast<int>(config.GetBand()), config.GetChannel());
#endif
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("SetHotspotConfig:NOT System APP, PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetHotspotConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetHotspotConfig:VerifyGetWifiConfigPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    ErrCode validRetval = VerifyConfigValidity(config);
    if (validRetval != ErrCode::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("SetHotspotConfig:VerifyConfigValidity failed!");
        return HandleHotspotIdlRet(validRetval);
    }
    HotspotConfig lastConfig;
    if (WifiSettings::GetInstance().GetHotspotConfig(lastConfig, m_id) != 0) {
        WIFI_LOGE("Instance %{public}d %{public}s GetHotspotConfig error", m_id, __func__);
        return HandleHotspotIdlRet(WIFI_OPT_FAILED);
    }
    HotspotConfig innerConfig = config;
    if (innerConfig.GetPreSharedKey() != lastConfig.GetPreSharedKey() || !lastConfig.GetPasswdDefault()){
        innerConfig.SetPasswdDefault(false);
    }
    if (lastConfig.GetRandomMac() != "") {
        std::string mac = "";
        if (config.GetSsid() != lastConfig.GetSsid() ||
            config.GetSecurityType() != lastConfig.GetSecurityType()) {
            WifiRandomMacHelper::GenerateRandomMacAddress(mac);
            WIFI_LOGI("Generate new random mac:%{public}s", MacAnonymize(mac).c_str());
        } else {
            mac = lastConfig.GetRandomMac();
        }
        innerConfig.SetRandomMac(mac);
    }
    if (!IsApServiceRunning() ||
        WifiServiceManager::GetInstance().ApServiceSetHotspotConfig(innerConfig, m_id) == false) {
        WifiSettings::GetInstance().SetHotspotConfig(innerConfig, m_id);
        WifiSettings::GetInstance().SyncHotspotConfig();
    }
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::GetLocalOnlyHotspotConfig(HotspotConfigParcel &parcelresult)
{
    WIFI_LOGI("Instance %{public}d %{public}s!", m_id, __func__);
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetHotspotConfig:NOT System APP, PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }
    if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetHotspotConfig:VerifyGetWifiConfigPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetHotspotConfig:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    HotspotConfig result;
    WifiConfigCenter::GetInstance().GetLocalOnlyHotspotConfig(result);
    parcelresult.FromHotspotConfig(result);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::VerifyConfigValidity(const HotspotConfig &config)
{
    std::vector<BandType> bandsFromCenter;
    ApConfigUse::GetInstance().GetApVaildBands(bandsFromCenter);
    HotspotConfig configFromCenter;
    WifiSettings::GetInstance().GetHotspotConfig(configFromCenter, m_id);
    ErrCode validRetval = IsValidHotspotConfig(config, configFromCenter, bandsFromCenter);
    if (validRetval != ErrCode::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Instance %{public}d Hotspot config is invalid!", m_id);
        return validRetval;
    }

    WifiLinkedInfo linkInfo;
    for (int i = 0; i < STA_INSTANCE_MAX_NUM; ++i) {
        WifiConfigCenter::GetInstance().GetLinkedInfo(linkInfo, i);
        if (!linkInfo.ssid.empty() && linkInfo.ssid == config.GetSsid()) {
            WIFI_LOGE("set ssid equal current linked ap ssid, no permission!");
            return WIFI_OPT_INVALID_PARAM;
        }
    }
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::SetHotspotIdleTimeout(int time)
{
    WIFI_LOGI("SetHotspotIdleTimeout");
    if (WifiPermissionUtils::VerifyManageWifiHotspotPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetHotspotIdleTimeout:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    /* Set the hotspot idle timeout unit to 1 minute */
    constexpr int hotspotIdleTimeoutUnit = 60000;
    int maxValue = std::numeric_limits<int>::max() / hotspotIdleTimeoutUnit;
    if (maxValue <= time || time < 0) {
        WIFI_LOGE("SetHotspotIdleTimeout invalid time:%{public}d maxValue is %{public}d", time, maxValue);
        return HandleHotspotIdlRet(WIFI_OPT_INVALID_PARAM);
    }
    int delayTime = time * hotspotIdleTimeoutUnit;
    if (!IsApServiceRunning()) {
        WifiConfigCenter::GetInstance().SetHotspotIdleTimeout(delayTime);
    } else {
        IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst();
        if (pService == nullptr) {
            return HandleHotspotIdlRet(WIFI_OPT_AP_NOT_OPENED);
        }
        ErrCode ret = pService->SetHotspotIdleTimeout(delayTime);
        return HandleHotspotIdlRet(ret);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::VerifyGetStationListPermission()
{
    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetStationList:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (apiVersion == API_VERSION_9) {
#ifndef SUPPORT_RANDOM_MAC_ADDR
        if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetStationList:VerifyGetScanInfosPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
#endif
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetStationList:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifyManageWifiHotspotPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetStationList:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::GetStationList(std::vector<StationInfoParcel> &parcelResult)
{
    WIFI_LOGI("Instance %{public}d %{public}s!", m_id, __func__);
    ErrCode permCode = VerifyGetStationListPermission();
    if (permCode != WIFI_OPT_SUCCESS) {
        return HandleHotspotIdlRet(permCode);
    }
    ErrCode errCode;
    std::vector<StationInfo> result;
    if (IsApServiceRunning()) {
        IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
        if (pService == nullptr) {
            WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
            return HandleHotspotIdlRet(WIFI_OPT_AP_NOT_OPENED);
        }
        errCode = pService->GetStationList(result);
    } else if (IsRptRunning()) {
        auto rptManager = WifiManager::GetInstance().GetRptInterface(m_id);
        errCode = (rptManager != nullptr) ? rptManager->GetStationList(result) : WIFI_OPT_FAILED;
    } else {
        WIFI_LOGE("Instance %{public}d hotspot service is not running!", m_id);
        return HandleHotspotIdlRet(WIFI_OPT_AP_NOT_OPENED);
    }
#ifdef SUPPORT_RANDOM_MAC_ADDR
    if (WifiPermissionUtils::VerifyGetWifiPeersMacPermission() == PERMISSION_DENIED) {
        WIFI_LOGI("%{public}s: GET_WIFI_PEERS_MAC PERMISSION_DENIED", __func__);
        for (auto iter = result.begin(); iter != result.end(); ++iter) {
            WifiMacAddrInfo macAddrInfo;
            macAddrInfo.bssid = iter->bssid;
            macAddrInfo.bssidType = iter->bssidType;
            std::string randomMacAddr =
                WifiConfigCenter::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO, macAddrInfo);
            if (!randomMacAddr.empty() &&
                (macAddrInfo.bssidType == REAL_DEVICE_ADDRESS)) {
                iter->bssid = randomMacAddr;
                iter->bssidType = RANDOM_DEVICE_ADDRESS;
                WIFI_LOGI("%{public}s: the record is updated, bssid:%{private}s, bssidType:%{public}d",
                    __func__, iter->bssid.c_str(), iter->bssidType);
            }
        }
    }
#endif
    parcelResult.clear();
    for (const auto &r : result) {
        parcelResult.emplace_back(ToParcel(r));
    }
    return HandleHotspotIdlRet(errCode);
}

ErrCode WifiHotspotServiceImpl::TransRandomToRealMac(StationInfo &updateInfo, const StationInfo &info)
{
    if (MacAddress::IsValidMac(info.bssid)) {
        if (info.bssidType > REAL_DEVICE_ADDRESS) {
            WIFI_LOGE("%{public}s: invalid bssidType:%{public}d",
                __func__, info.bssidType);
            return WIFI_OPT_INVALID_PARAM;
        }
        WifiMacAddrInfo macAddrInfo;
        macAddrInfo.bssid = info.bssid;
        macAddrInfo.bssidType = info.bssidType;
        std::string macAddr =
            WifiConfigCenter::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO, macAddrInfo);
        if (macAddr.empty()) {
            WIFI_LOGW("no record found, bssid:%{private}s, bssidType:%{public}d",
                macAddrInfo.bssid.c_str(), macAddrInfo.bssidType);
        } else {
            WIFI_LOGI("%{public}s: find the record, bssid:%{private}s, bssidType:%{public}d, randomMac:%{private}s",
                __func__, info.bssid.c_str(), info.bssidType, macAddr.c_str());
            /* random MAC address are translated into real MAC address */
            if (info.bssidType == RANDOM_DEVICE_ADDRESS) {
                updateInfo.bssid = macAddr;
                updateInfo.bssidType = REAL_DEVICE_ADDRESS;
                WIFI_LOGI("%{public}s: the record is updated, bssid:%{private}s, bssidType:%{public}d",
                    __func__, updateInfo.bssid.c_str(), updateInfo.bssidType);
            }
        }
    } else {
        WIFI_LOGW("invalid mac address");
    }
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::DisassociateSta(const StationInfoParcel &parcelInfo)
{
    StationInfo info = FromParcel(parcelInfo);
    WIFI_LOGI("Instance %{public}d %{public}s device name [%{private}s]", m_id, __func__,
        info.deviceName.c_str());
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DisassociateSta:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("DisassociateSta:IsSystemAppByToken NOT System APP, PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }
    if (CheckMacIsValid(info.bssid)) {
        return HandleHotspotIdlRet(WIFI_OPT_INVALID_PARAM);
    }
    if (!IsApServiceRunning()) {
        return HandleHotspotIdlRet(WIFI_OPT_AP_NOT_OPENED);
    }
    StationInfo updateInfo = info;
#ifdef SUPPORT_RANDOM_MAC_ADDR
    TransRandomToRealMac(updateInfo, info);
#endif
    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
    if (pService == nullptr) {
        WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
        return HandleHotspotIdlRet(WIFI_OPT_AP_NOT_OPENED);
    }
    ErrCode ret = pService->DisconnetStation(updateInfo);
    return HandleHotspotIdlRet(ret);
}

int WifiHotspotServiceImpl::CheckOperHotspotSwitchPermission(const ServiceType type)
{
#ifdef FEATURE_AP_EXTENSION
    return (type == ServiceType::WIFI_EXT) ? WifiPermissionUtils::VerifySetWifiInfoPermission() :
        WifiPermissionUtils::VerifyManageWifiHotspotPermission();
#else
    return (type == ServiceType::WIFI_EXT) ? PERMISSION_DENIED :
        WifiPermissionUtils::VerifyManageWifiHotspotPermission();
#endif
}

ErrCode WifiHotspotServiceImpl::CheckCanEnableHotspot(const ServiceType type)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("EnableHotspot:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (CheckOperHotspotSwitchPermission(type) == PERMISSION_DENIED) {
        WIFI_LOGE("EnableHotspot:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiConfigCenter::GetInstance().GetPowerSavingModeState() == 1) {
        WIFI_LOGI("current power saving mode and can not use ap, open failed!");
        return WIFI_OPT_FORBID_POWSAVING;
    }

    if (WifiManager::GetInstance().GetWifiMultiVapManager() == nullptr) {
        WIFI_LOGE("GetWifiMultiVapManager Fail");
        return WIFI_OPT_FAILED;
    }
    
    if (!WifiManager::GetInstance().GetWifiMultiVapManager()->CheckCanUseSoftAp()) {
        WIFI_LOGE("SoftAp is not allowed to use");
        return WIFI_OPT_FAILED;
    }

    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::EnableHotspot(const ServiceTypeParcel parcelType)
{
#ifndef OHOS_ARCH_LITE
    WIFI_LOGI("Inst%{public}d %{public}s, pid:%{public}d, uid:%{public}d", m_id, __func__,
        GetCallingPid(), GetCallingUid());
#endif
    ServiceType type = FromParcel<ServiceType>(parcelType);
    ErrCode errCode = CheckCanEnableHotspot(type);
    if (errCode != WIFI_OPT_SUCCESS) {
        return HandleHotspotIdlRet(errCode);
    }
    WifiManager::GetInstance().StopGetCacResultAndLocalCac(CAC_STOP_BY_AP_REQUEST);

    ErrCode ret = WifiManager::GetInstance().GetWifiTogglerManager()->SoftapToggled(1, m_id);
    return HandleHotspotIdlRet(ret);
}

int32_t WifiHotspotServiceImpl::DisableHotspot(const ServiceTypeParcel parcelType)
{
#ifndef OHOS_ARCH_LITE
    WIFI_LOGI("Inst%{public}d %{public}s, pid:%{public}d, uid:%{public}d", m_id, __func__,
        GetCallingPid(), GetCallingUid());
#endif
    ServiceType type = FromParcel<ServiceType>(parcelType);
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("DisableHotspot:NOT System APP, PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }
    if (CheckOperHotspotSwitchPermission(type) == PERMISSION_DENIED) {
        WIFI_LOGE("EnableHotspot:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    ErrCode ret = WifiManager::GetInstance().GetWifiTogglerManager()->SoftapToggled(0, m_id);
    return HandleHotspotIdlRet(ret);
}

int32_t WifiHotspotServiceImpl::EnableLocalOnlyHotspot(const ServiceTypeParcel parcelType)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    ServiceType type = FromParcel<ServiceType>(parcelType);
    ErrCode errCode = CheckCanEnableHotspot(type);
    if (errCode != WIFI_OPT_SUCCESS) {
        return HandleHotspotIdlRet(errCode);
    }
    if (IsRptRunning() || IsApServiceRunning()) {
        WIFI_LOGI("%{public}s, softap/rpt is running, can not use localOnlyHotspot", __func__);
        return HandleHotspotIdlRet(WIFI_OPT_FAILED);
    }
    auto &wifiControllerMachine = WifiManager::GetInstance().GetWifiTogglerManager()->GetControllerMachine();
    if (wifiControllerMachine != nullptr) {
        wifiControllerMachine->IsLocalOnlyHotspot(true);
    }
    WifiManager::GetInstance().StopGetCacResultAndLocalCac(CAC_STOP_BY_AP_REQUEST);
    ErrCode ret = WifiManager::GetInstance().GetWifiTogglerManager()->SoftapToggled(1, m_id);
    return HandleHotspotIdlRet(ret);
}
 
int32_t WifiHotspotServiceImpl::DisableLocalOnlyHotspot(const ServiceTypeParcel parcelType)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    ServiceType type = FromParcel<ServiceType>(parcelType);
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("DisableHotspot:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (CheckOperHotspotSwitchPermission(type) == PERMISSION_DENIED) {
        WIFI_LOGE("EnableHotspot:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    ErrCode ret = WifiManager::GetInstance().GetWifiTogglerManager()->SoftapToggled(0, m_id);
    return HandleHotspotIdlRet(ret);
}
 
int32_t WifiHotspotServiceImpl::GetHotspotMode(HotspotModeParcel &parcelMode)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetBlockLists:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifyManageWifiHotspotPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetBlockLists:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
    HotspotMode mode;
    if (pService == nullptr) {
        WIFI_LOGE("%{public}s, get hotspot service is null!", __func__);
        mode = HotspotMode::NONE;
        parcelMode = ToParcel<HotspotModeParcel>(mode);
        return HandleHotspotIdlRet(WIFI_OPT_AP_NOT_OPENED);
    }
    ErrCode ret = pService->GetHotspotMode(mode);
    parcelMode = ToParcel<HotspotModeParcel>(mode);
    return HandleHotspotIdlRet(ret);
}

static ErrCode AddApBlockList(int m_id, StationInfo& updateInfo)
{
    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
    if (pService == nullptr) {
        WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
        return WIFI_OPT_AP_NOT_OPENED;
    }
    if (pService->AddBlockList(updateInfo) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AddBlockList: request add hotspot blocklist failed!");
        return WIFI_OPT_FAILED;
    }
    if (pService->DisconnetStation(updateInfo) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AddBlockList: request disconnet station failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

static ErrCode AddRptBlockList(int m_id, StationInfo &info)
{
    auto rptManager = WifiManager::GetInstance().GetRptInterface(m_id);
    if (rptManager == nullptr) {
        return WIFI_OPT_FAILED;
    }
    rptManager->AddBlock(info.bssid);
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::AddBlockList(const StationInfoParcel &parcelInfo)
{
    StationInfo info = FromParcel(parcelInfo);
    WIFI_LOGI("current ap service is %{public}d %{public}s"
        " device name [%{private}s]", m_id, __func__, info.deviceName.c_str());
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("AddBlockList:NOT System APP, PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }
    if (WifiPermissionUtils::VerifyManageWifiHotspotPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("AddBlockList:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("AddBlockList:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    if (CheckMacIsValid(info.bssid)) {
        return HandleHotspotIdlRet(WIFI_OPT_INVALID_PARAM);
    }
    bool isApServiceRunning = IsApServiceRunning();
    bool isRptRunning = IsRptRunning();
    if (!isApServiceRunning && !isRptRunning) {
        WIFI_LOGE("ApService is not running!");
        return HandleHotspotIdlRet(WIFI_OPT_AP_NOT_OPENED);
    }
    StationInfo updateInfo = info;
#ifdef SUPPORT_RANDOM_MAC_ADDR
    TransRandomToRealMac(updateInfo, info);
#endif
    if (WifiSettings::GetInstance().ManageBlockList(info, MODE_ADD, m_id) < 0) {
        WIFI_LOGE("Add block list failed!");
        return HandleHotspotIdlRet(WIFI_OPT_FAILED);
    }

    if (isApServiceRunning) {
        return AddApBlockList(m_id, updateInfo);
    } else if (isRptRunning) {
        return AddRptBlockList(m_id, updateInfo);
    }
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::DelBlockList(const StationInfoParcel &parcelInfo)
{
    StationInfo info = FromParcel(parcelInfo);
    WIFI_LOGI("current ap service is %{public}d %{public}s device name [%{private}s]",
        m_id, __func__, info.deviceName.c_str());
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("DelBlockList:NOT System APP, PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }
    if (WifiPermissionUtils::VerifyManageWifiHotspotPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DelBlockList:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }

    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DelBlockList:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }

    if (CheckMacIsValid(info.bssid)) {
        return HandleHotspotIdlRet(WIFI_OPT_INVALID_PARAM);
    }
    StationInfo updateInfo = info;
#ifdef SUPPORT_RANDOM_MAC_ADDR
    TransRandomToRealMac(updateInfo, info);
#endif
    if (IsApServiceRunning()) {
        IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
        if (pService == nullptr) {
            WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
            return HandleHotspotIdlRet(WIFI_OPT_AP_NOT_OPENED);
        }
        if (pService->DelBlockList(updateInfo) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("request del hotspot blocklist failed!");
            return HandleHotspotIdlRet(WIFI_OPT_FAILED);
        }
    } else if (IsRptRunning()) {
        auto rptManager = WifiManager::GetInstance().GetRptInterface(m_id);
        if (rptManager == nullptr) {
            return HandleHotspotIdlRet(WIFI_OPT_FAILED);
        }
        rptManager->DelBlock(info.bssid);
    }

    if (WifiSettings::GetInstance().ManageBlockList(info, MODE_DEL, m_id) < 0) {
        WIFI_LOGE("Delete block list failed!");
        return HandleHotspotIdlRet(WIFI_OPT_FAILED);
    }
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::GetValidBands(std::vector<BandTypeParcel> &parcelBands)
{
     WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetValidBands:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    std::vector<BandType> bands;
    ApConfigUse::GetInstance().GetApVaildBands(bands);
    parcelBands.clear();
    for (const auto &band : bands) {
        parcelBands.emplace_back(ToParcel<BandTypeParcel>(band));
    }
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::GetValidChannels(BandTypeParcel parcelBand, std::vector<int32_t> &validchannels)
{
    BandType band = FromParcel<BandType>(parcelBand);
    WIFI_LOGI("current ap service is %{public}d %{public}s band %{public}d",
        m_id, __func__, static_cast<int>(band));
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetValidChannels:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }

    if (band == BandType::BAND_NONE) {
        return HandleHotspotIdlRet(WIFI_OPT_INVALID_PARAM);
    }
    ApConfigUse::GetInstance().GetApVaildChannel(band, validchannels);
    return WIFI_OPT_SUCCESS;
}

#ifdef SUPPORT_RANDOM_MAC_ADDR
void WifiHotspotServiceImpl::ProcessMacAddressRandomization(std::vector<StationInfo> &infos)
{
    if (WifiPermissionUtils::VerifyGetWifiPeersMacPermission() == PERMISSION_DENIED) {
        WIFI_LOGI("%{public}s: GET_WIFI_PEERS_MAC PERMISSION_DENIED", __func__);
        for (auto iter = infos.begin(); iter != infos.end(); ++iter) {
            WifiMacAddrInfo macAddrInfo;
            macAddrInfo.bssid = iter->bssid;
            macAddrInfo.bssidType = iter->bssidType;
            std::string randomMacAddr =
                WifiConfigCenter::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::HOTSPOT_MACADDR_INFO, macAddrInfo);
            if (randomMacAddr.empty()) {
                WIFI_LOGI("%{public}s: GenerateRandomMacAddress", __func__);
                WifiRandomMacHelper::GenerateRandomMacAddress(randomMacAddr);
            }
            if (!randomMacAddr.empty() && (macAddrInfo.bssidType == REAL_DEVICE_ADDRESS)) {
                iter->bssid = randomMacAddr;
                iter->bssidType = RANDOM_DEVICE_ADDRESS;
                WIFI_LOGI("%{public}s: the record is updated, bssid:%{private}s, bssidType:%{public}d",
                    __func__, iter->bssid.c_str(), iter->bssidType);
            }
        }
    }
}
#endif

int32_t WifiHotspotServiceImpl::GetBlockLists(std::vector<StationInfoParcel> &parcelInfos)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetBlockLists:NOT System APP, PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }
    if (WifiPermissionUtils::VerifyManageWifiHotspotPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetBlockLists:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }

    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetBlockLists:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    std::vector<StationInfo> infos;
    infos.reserve(parcelInfos.size());
    for (const auto &parcelInfo : parcelInfos) {
        infos.emplace_back(FromParcel(parcelInfo));
    }
#ifdef SUPPORT_RANDOM_MAC_ADDR
    ProcessMacAddressRandomization(infos);
#endif
    if (WifiSettings::GetInstance().GetBlockList(infos, m_id) < 0) {
        WIFI_LOGE("Get block list failed!");
        return HandleHotspotIdlRet(WIFI_OPT_FAILED);
    }
    parcelInfos.clear();
    for (const auto &info : infos) {
        parcelInfos.emplace_back(ToParcel(info));
    }
    return WIFI_OPT_SUCCESS;
}

bool WifiHotspotServiceImpl::IsApServiceRunning()
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetApMidState(m_id);
    if (curState != WifiOprMidState::RUNNING) {
        WIFI_LOGI("current ap state is %{public}d", static_cast<int>(curState));
        return false;
    }
    return true;
}

bool WifiHotspotServiceImpl::IsRptRunning()
{
    WIFI_LOGI("current rpt is %{public}d %{public}s", m_id, __func__);
    auto rptManager = WifiManager::GetInstance().GetRptInterface(m_id);
    return rptManager != nullptr && rptManager->IsRptRunning();
}

int32_t WifiHotspotServiceImpl::RegisterCallBack(const sptr<IRemoteObject> &cbParcel,
    const std::vector<std::string> &event)
{
    WIFI_LOGD("WifiHotspotServiceImpl::RegisterCallBack");
    ErrCode ret = WIFI_OPT_FAILED;
    sptr<IRemoteObject> remote = cbParcel;
    if (remote == nullptr) {
        WIFI_LOGE("RegisterCallBack: remote object is null!");
        return HandleHotspotIdlRet(WIFI_OPT_FAILED);
    }
    sptr<IWifiHotspotCallback> callback = iface_cast<IWifiHotspotCallback>(remote);
    if (callback == nullptr) {
        callback = sptr<WifiHotspotCallbackProxy>::MakeSptr(remote);
        WIFI_LOGI("RegisterCallBack: create new WifiHotspotCallbackProxy!");
    }
    if (mSingleCallback) {
        ret = RegisterCallBack(callback, event);
    } else {
        std::unique_lock<std::mutex> lock(deathRecipientMutex);
        if (deathRecipient_ == nullptr) {
            deathRecipient_ = sptr<WifiHotspotDeathRecipient>::MakeSptr();
        }
        // Add death recipient to remote object if this is the first time to register callback.
        if (remote->IsProxyObject() &&
            !WifiInternalEventDispatcher::GetInstance().HasHotspotRemote(remote, m_id)) {
            remote->AddDeathRecipient(deathRecipient_);
        }

        if (callback != nullptr) {
            for (const auto &eventName : event) {
                ret = WifiInternalEventDispatcher::GetInstance().AddHotspotCallback(remote, callback, eventName, m_id);
            }
        } else {
            WIFI_LOGE("Converted callback is null");
        }
    }

    WIFI_LOGI("RegisterCallBack retcode: %{public}d", ret);
    return HandleHotspotIdlRet(ret);
}

ErrCode WifiHotspotServiceImpl::RegisterCallBack(const sptr<IWifiHotspotCallback> &callback,
    const std::vector<std::string> &event)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RegisterCallBack:VerifyWifiConnectionPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    WifiInternalEventDispatcher::GetInstance().SetSingleHotspotCallback(callback, m_id);
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::GetSupportedFeatures(int64_t &features)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetSupportedFeatures:NOT System APP, PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetSupportedFeatures:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    long features_long = 0;
    int ret = WifiManager::GetInstance().GetSupportedFeatures(features_long);
    features = static_cast<int64_t>(features_long);
    if (ret < 0) {
        WIFI_LOGE("Failed to get supported features!");
        return HandleHotspotIdlRet(WIFI_OPT_FAILED);
    }
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::GetSupportedPowerModel(std::set<PowerModelParcel>& parcelPowerModelSet)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetSupportedPowerModel:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }

    if (!IsApServiceRunning()) {
        return HandleHotspotIdlRet(WIFI_OPT_AP_NOT_OPENED);
    }
    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
    if (pService == nullptr) {
        WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
        return HandleHotspotIdlRet(WIFI_OPT_AP_NOT_OPENED);
    }
    std::set<PowerModel> setPowerModelList;
    pService->GetSupportedPowerModel(setPowerModelList);
    parcelPowerModelSet.clear();
    for (const auto &model : setPowerModelList) {
        parcelPowerModelSet.insert(ToParcel<PowerModelParcel>(model));
    }
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::GetPowerModel(PowerModelParcel& parcelModel)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetPowerModel:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }

    if (!IsApServiceRunning()) {
        return HandleHotspotIdlRet(WIFI_OPT_AP_NOT_OPENED);
    }
    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
    if (pService == nullptr) {
        WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
        return HandleHotspotIdlRet(WIFI_OPT_AP_NOT_OPENED);
    }
    PowerModel model;
    pService->GetPowerModel(model);
    parcelModel = ToParcel<PowerModelParcel>(model);
    return WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::SetPowerModel(PowerModelParcel parcelModel)
{
    WIFI_LOGI("SetPowerModel, m_id is %{public}d %{public}s", m_id, __func__);
    PowerModel model = FromParcel<PowerModel>(parcelModel);
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetPowerModel:VerifySetWifiInfoPermission() PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }

    if (!IsApServiceRunning()) {
        return HandleHotspotIdlRet(WIFI_OPT_AP_NOT_OPENED);
    }
    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
    if (pService == nullptr) {
        WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
        return HandleHotspotIdlRet(WIFI_OPT_AP_NOT_OPENED);
    }
    pService->SetPowerModel(model);
    return WIFI_OPT_SUCCESS;
}

void WifiHotspotServiceImpl::ConfigInfoDump(std::string& result)
{
    HotspotConfig config;
    WifiSettings::GetInstance().GetHotspotConfig(config);
    std::stringstream ss;
    ss << "Hotspot config: " << "\n";
    ss << "  Config.ssid: " << config.GetSsid() << "\n";

    std::map<KeyMgmt, std::string> mapKeyMgmtToStr = {
        {KeyMgmt::NONE, "Open"}, {KeyMgmt::WPA_PSK, "WPA_PSK"}, {KeyMgmt::WPA_EAP, "WPA_EAP"},
        {KeyMgmt::IEEE8021X, "IEEE8021X"}, {KeyMgmt::WPA2_PSK, "WPA2_PSK"}, {KeyMgmt::OSEN, "OSEN"},
        {KeyMgmt::FT_PSK, "FT_PSK"}, {KeyMgmt::FT_EAP, "FT_EAP"}
    };

    auto funcStrKeyMgmt = [&mapKeyMgmtToStr](KeyMgmt secType) {
        std::map<KeyMgmt, std::string>::iterator iter = mapKeyMgmtToStr.find(secType);
        return (iter != mapKeyMgmtToStr.end()) ? iter->second : "Unknown";
    };
    ss << "  Config.security_type: " << funcStrKeyMgmt(config.GetSecurityType()) << "\n";

    auto funcStrBand = [](BandType band) {
        std::string retStr;
        switch (band) {
            case BandType::BAND_2GHZ:
                retStr = "2.4GHz";
                break;
            case BandType::BAND_5GHZ:
                retStr = "5GHz";
                break;
            case BandType::BAND_ANY:
                retStr = "dual-mode frequency band";
                break;
            case BandType::BAND_6GHZ:
                retStr = "6GHz";
                break;
            default:
                retStr = "unknown band";
        }
        return retStr;
    };
    ss << "  Config.band: " << funcStrBand(config.GetBand()) << "\n";
    ss << "  Config.channel: " << config.GetChannel() << "\n";
    ss << "  Config.max_conn: " << config.GetMaxConn() << "\n";
    result += "\n";
    result += ss.str();
    result += "\n";
}

void WifiHotspotServiceImpl::StationsInfoDump(std::string& result)
{
    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst();
    if (pService != nullptr) {
        std::stringstream ss;
        std::vector<StationInfo> vecStations;
        pService->GetStationList(vecStations);
        ss << "Station list size: " << vecStations.size() << "\n";
        int idx = 0;
        for (auto& each : vecStations) {
            ++idx;
            ss << "  Station[" << idx << "].deviceName: " << each.deviceName << "\n";
            ss << "  Station[" << idx << "].bssid: " << MacAnonymize(each.bssid) << "\n";
            ss << "  Station[" << idx << "].bssidType: " << each.bssidType << "\n";
            ss << "  Station[" << idx << "].ipAddr: " << IpAnonymize(each.ipAddr) << "\n";
            ss << "\n";
        }
        result += ss.str();
        result += "\n";
    }

    std::vector<StationInfo> vecBlockStations;
    WifiSettings::GetInstance().GetBlockList(vecBlockStations);
    if (!vecBlockStations.empty()) {
        std::stringstream ss;
        ss << "Block station list size: " << vecBlockStations.size() << "\n";
        int idx = 0;
        for (auto& each : vecBlockStations) {
            ++idx;
            ss << "  BlockStation[" << idx << "].deviceName: " << each.deviceName << "\n";
            ss << "  BlockStation[" << idx << "].bssid: " << MacAnonymize(each.bssid) << "\n";
            ss << "  BlockStation[" << idx << "].bssidType: " << each.bssidType << "\n";
            ss << "  BlockStation[" << idx << "].ipAddr: " << IpAnonymize(each.ipAddr) << "\n";
            ss << "\n";
        }
        result += ss.str();
        result += "\n";
    }
}

void WifiHotspotServiceImpl::SaBasicDump(std::string& result)
{
    WifiHotspotServiceImpl impl;
    bool isActive = impl.IsApServiceRunning();
    result.append("WiFi hotspot active state: ");
    std::string strActive = isActive ? "activated" : "inactive";
    result += strActive + "\n";

    if (isActive) {
        ConfigInfoDump(result);
        StationsInfoDump(result);
    }
}

bool WifiHotspotServiceImpl::IsRemoteDied(void)
{
    return false;
}

ErrCode WifiHotspotServiceImpl::CfgCheckSsid(const HotspotConfig &cfg)
{
    if (cfg.GetSsid().length() < MIN_SSID_LEN || cfg.GetSsid().length() > MAX_SSID_LEN) {
        WIFI_LOGE("Config ssid length is invalid!");
        return ErrCode::WIFI_OPT_INVALID_PARAM;
    }
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::CfgCheckPsk(const HotspotConfig &cfg)
{
    size_t len = cfg.GetPreSharedKey().length();
    if (len < MIN_PSK_LEN || len > MAX_PSK_LEN) {
        WIFI_LOGE("PreSharedKey length error! invalid len: %{public}zu", len);
        return ErrCode::WIFI_OPT_INVALID_PARAM;
    }
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::CfgCheckBand(const HotspotConfig &cfg, std::vector<BandType> &bandsFromCenter)
{
    for (auto it = bandsFromCenter.begin(); it != bandsFromCenter.end(); ++it) {
        if (cfg.GetBand() == *it) {
            return ErrCode::WIFI_OPT_SUCCESS;
        }
    }
    WIFI_LOGE("Hotspot config band is invalid!");
    return ErrCode::WIFI_OPT_INVALID_PARAM;
}

static bool isNumber(std::string &str)
{
    return !str.empty() && (str.find_first_not_of("0123456789") == std::string::npos);
}

ErrCode WifiHotspotServiceImpl::CfgCheckIpAddress(const std::string &ipAddress)
{
    if (ipAddress.empty()) {
        WIFI_LOGI("CfgCheckIpAddress ipAddress is empty.");
        return ErrCode::WIFI_OPT_SUCCESS;
    }
    std::vector<std::string> list{};
    SplitString(ipAddress, ".", list);

    if (list.size() != MAX_IPV4_SPLIT_LEN) {
        WIFI_LOGE("CfgCheckIpAddress split size invalid.");
        return ErrCode::WIFI_OPT_INVALID_PARAM;
    }

    for (auto str : list) {
        if (!isNumber(str) || CheckDataLegal(str) > MAX_IPV4_VALUE || CheckDataLegal(str) < 0) {
            WIFI_LOGE("CfgCheckIpAddress stoi failed.");
            return ErrCode::WIFI_OPT_INVALID_PARAM;
        }
    }

    std::vector ips = {"0.0.0.0", "255.255.255.255", "127.0.0.0"};
    if (std::find(ips.begin(), ips.end(), ipAddress) != ips.end()) {
        WIFI_LOGE("CfgCheckIpAddress unused ip range.");
        return ErrCode::WIFI_OPT_INVALID_PARAM;
    }

    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::IsValidHotspotConfig(const HotspotConfig &cfg, const HotspotConfig &cfgFromCenter,
    std::vector<BandType> &bandsFromCenter)
{
    if (CfgCheckIpAddress(cfg.GetIpAddress()) == ErrCode::WIFI_OPT_INVALID_PARAM) {
        return ErrCode::WIFI_OPT_INVALID_PARAM;
    }
    if (cfg.GetMaxConn() <= 0 || cfg.GetMaxConn() > MAX_AP_CONN) {
        WIFI_LOGE("Open hotspot maxConn is illegal %{public}d !", cfg.GetMaxConn());
        return ErrCode::WIFI_OPT_INVALID_PARAM;
    }
    if (CfgCheckSsid(cfg) == ErrCode::WIFI_OPT_INVALID_PARAM) {
        return ErrCode::WIFI_OPT_INVALID_PARAM;
    }

    if (cfg.GetSecurityType() == KeyMgmt::NONE) {
        if (cfg.GetPreSharedKey().length() > 0) {
            WIFI_LOGE("Open hotspot PreSharedKey length is non-zero error!");
            return ErrCode::WIFI_OPT_INVALID_PARAM;
        }
    } else if (cfg.GetSecurityType() == KeyMgmt::WPA_PSK || cfg.GetSecurityType() == KeyMgmt::WPA2_PSK) {
        if (CfgCheckPsk(cfg) == ErrCode::WIFI_OPT_INVALID_PARAM) {
            return ErrCode::WIFI_OPT_INVALID_PARAM;
        }
    } else {
        WIFI_LOGE("Hotspot securityType is not supported!");
        return ErrCode::WIFI_OPT_INVALID_PARAM;
    }

    if (cfg.GetBand() != cfgFromCenter.GetBand() && bandsFromCenter.size() != 0) {
        if (CfgCheckBand(cfg, bandsFromCenter) == ErrCode::WIFI_OPT_INVALID_PARAM) {
            return ErrCode::WIFI_OPT_INVALID_PARAM;
        }
    }
    if (cfg.GetPreSharedKey() != cfgFromCenter.GetPreSharedKey()) {
        WIFI_LOGI("ApConfig preSharedKey changed from %{public}s to %{public}s",
            PassWordAnonymize(cfgFromCenter.GetPreSharedKey()).c_str(),
            PassWordAnonymize(cfg.GetPreSharedKey()).c_str());
    }
    if (cfg.GetSsid() != cfgFromCenter.GetSsid()) {
        WIFI_LOGI("ApConfig ssid changed from %{public}s to %{public}s",
            SsidAnonymize(cfgFromCenter.GetSsid()).c_str(), SsidAnonymize(cfg.GetSsid()).c_str());
    }
    return ErrCode::WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::GetApIfaceName(std::string& ifaceName)
{
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetBlockLists:NOT System APP, PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetBlockLists:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return HandleHotspotIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    if (IsApServiceRunning()) {
        ifaceName = WifiConfigCenter::GetInstance().GetApIfaceName();
    } else if (IsRptRunning()) {
        auto rptManager = WifiManager::GetInstance().GetRptInterface(m_id);
        ifaceName = (rptManager != nullptr) ? rptManager->GetRptIfaceName() : "";
    }
    return ErrCode::WIFI_OPT_SUCCESS;
}

int32_t WifiHotspotServiceImpl::HandleHotspotIdlRet(ErrCode originRet)
{
    if (originRet == WIFI_OPT_SUCCESS) {
        return WIFI_OPT_SUCCESS;
    } else {
        return originRet + HOTSPOT_IDL_ERROR_OFFSET;
    }
}

ErrCode WifiHotspotServiceImpl::OnBackup(MessageParcel& data, MessageParcel& reply)
{
    UniqueFd fd(-1);
    std::string replyCode = WifiSettings::GetInstance().SetBackupReplyCode(0);
    std::string backupInfo = data.ReadString();
    WIFI_LOGE("OnBackup %{public}s", backupInfo.c_str());
    int ret = WifiSettings::GetInstance().OnHotspotBackup(fd, backupInfo);
    std::fill(backupInfo.begin(), backupInfo.end(), 0);
    if (ret < 0) {
        WIFI_LOGE("OnBackup fail: backup data fail!");
        replyCode = WifiSettings::GetInstance().SetBackupReplyCode(EXTENSION_ERROR_CODE);
        close(fd.Release());
        WifiSettings::GetInstance().RemoveHotspotBackupFile();
        return WIFI_OPT_FAILED;
    }
    if (!reply.WriteFileDescriptor(fd) || !reply.WriteString(replyCode)) {
        close(fd.Release());
        WifiSettings::GetInstance().RemoveHotspotBackupFile();
        WIFI_LOGE("OnBackup fail: reply write fail!");
        return WIFI_OPT_FAILED;
    }
    close(fd.Release());
    WifiSettings::GetInstance().RemoveHotspotBackupFile();
    return WIFI_OPT_SUCCESS;
}
 
ErrCode WifiHotspotServiceImpl::OnRestore(MessageParcel& data, MessageParcel& reply)
{
    UniqueFd fd(data.ReadFileDescriptor());
    std::string replyCode = WifiSettings::GetInstance().SetBackupReplyCode(0);
    std::string restoreInfo = data.ReadString();
    int ret = WifiSettings::GetInstance().OnHotspotRestore(fd, restoreInfo);
    std::fill(restoreInfo.begin(), restoreInfo.end(), 0);
    if (ret < 0) {
        WIFI_LOGE("OnRestore fail: restore data fail!");
        replyCode = WifiSettings::GetInstance().SetBackupReplyCode(EXTENSION_ERROR_CODE);
        close(fd.Release());
        WifiSettings::GetInstance().RemoveHotspotBackupFile();
        return WIFI_OPT_FAILED;
    }
    if (!reply.WriteString(replyCode)) {
        close(fd.Release());
        WifiSettings::GetInstance().RemoveHotspotBackupFile();
        WIFI_LOGE("OnRestore fail: reply write fail!");
        return WIFI_OPT_FAILED;
    }
    close(fd.Release());
    WifiSettings::GetInstance().RemoveHotspotBackupFile();
    return WIFI_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS
