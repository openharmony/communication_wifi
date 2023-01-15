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
#include "wifi_permission_utils.h"
#include "wifi_global_func.h"
#include "wifi_auth_center.h"
#include "wifi_config_center.h"
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_logger.h"
#include "define.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiHotspotServiceImpl");

namespace OHOS {
namespace Wifi {
WifiHotspotServiceImpl::WifiHotspotServiceImpl()
{}

WifiHotspotServiceImpl::WifiHotspotServiceImpl(int id) : WifiHotspotStub(id)
{}

WifiHotspotServiceImpl::~WifiHotspotServiceImpl()
{}

ErrCode WifiHotspotServiceImpl::IsHotspotActive(bool &bActive)
{
    WIFI_LOGI("Instance %{public}d %{public}s!", m_id, __func__);
    if (WifiPermissionUtils::VerifyManageWifiHotspotPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsHotspotActive:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    bActive = IsApServiceRunning();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::IsHotspotDualBandSupported(bool &isSupported)
{
    WIFI_LOGI("IsHotspotDualBandSupported");
    if (WifiPermissionUtils::VerifyGetWifiInfoInternalPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsHotspotDualBandSupported:VerifyGetWifiInfoInternalPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyManageWifiHotspotPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsHotspotDualBandSupported:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    std::vector<BandType> bands;
    if (WifiConfigCenter::GetInstance().GetValidBands(bands) < 0) {
        WIFI_LOGE("IsHotspotDualBandSupported:GetValidBands return failed!");
        return WIFI_OPT_FAILED;
    }

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

ErrCode WifiHotspotServiceImpl::GetHotspotState(int &state)
{
    WIFI_LOGI("Instance %{public}d %{public}s!", m_id, __func__);
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetHotspotState:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetHotspotState:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    state = WifiConfigCenter::GetInstance().GetHotspotState(m_id);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetHotspotConfig(HotspotConfig &result)
{
    WIFI_LOGI("Instance %{public}d %{public}s!", m_id, __func__);
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetHotspotConfig:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetHotspotConfig:VerifyGetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetHotspotConfig(result, m_id);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::SetHotspotConfig(const HotspotConfig &config)
{
    WIFI_LOGI("Instance %{public}d %{public}s band %{public}d", m_id, __func__,
        static_cast<int>(config.GetBand()));
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetHotspotConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetHotspotConfig:VerifyGetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!mGetChannels) {
        IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
        if (IsApServiceRunning() && pService != nullptr) {
            std::vector<int32_t> valid2GChannel;
            std::vector<int32_t> valid5GChannel;
            (void)pService->GetValidChannels(BandType::BAND_2GHZ, valid2GChannel);
            (void)pService->GetValidChannels(BandType::BAND_5GHZ, valid5GChannel);
            if (valid2GChannel.size() + valid5GChannel.size() == 0) {
                WIFI_LOGE("Failed to get supported band and channel!");
            } else {
                mGetChannels = true;
            }
        } else {
            WIFI_LOGE("Instance %{public}d, ap service is not started!", m_id);
        }
    }
    std::vector<BandType> bandsFromCenter;
    WifiConfigCenter::GetInstance().GetValidBands(bandsFromCenter);
    ChannelsTable channInfoFromCenter;
    WifiConfigCenter::GetInstance().GetValidChannels(channInfoFromCenter);
    HotspotConfig configFromCenter;
    WifiConfigCenter::GetInstance().GetHotspotConfig(configFromCenter, m_id);
    ErrCode validRetval = IsValidHotspotConfig(config, configFromCenter, bandsFromCenter, channInfoFromCenter);
    if (validRetval != ErrCode::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Instance %{public}d Hotspot config is invalid!", m_id);
        return validRetval;
    }

    WifiLinkedInfo linkInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkInfo);
    if (!linkInfo.ssid.empty() && linkInfo.ssid == config.GetSsid()) {
        WIFI_LOGE("set ssid equal current linked ap ssid, no permission!");
        return WIFI_OPT_INVALID_PARAM;
    }

    if (!IsApServiceRunning()) {
        WifiConfigCenter::GetInstance().SetHotspotConfig(config, m_id);
        WifiSettings::GetInstance().SyncHotspotConfig();
    } else {
        IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
        if (pService == nullptr) {
            WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
            return WIFI_OPT_AP_NOT_OPENED;
        }
        return pService->SetHotspotConfig(config);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetStationList(std::vector<StationInfo> &result)
{
    WIFI_LOGI("Instance %{public}d %{public}s!", m_id, __func__);
    if (WifiPermissionUtils::VerifyGetWifiInfoInternalPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetStationList:VerifyGetWifiInfoInternalPermission PERMISSION_DENIED!");

        if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetStationList:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }

        if (WifiPermissionUtils::VerifyGetWifiLocalMacPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetStationList:VerifyGetWifiLocalMacPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }

        if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetStationList:VerifyGetScanInfosPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }

        if (WifiPermissionUtils::VerifyManageWifiHotspotPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetStationList:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
    }

    if (!IsApServiceRunning()) {
        WIFI_LOGE("Instance %{public}d hotspot service is not running!", m_id);
        return WIFI_OPT_AP_NOT_OPENED;
    }

    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
    if (pService == nullptr) {
        WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
        return WIFI_OPT_AP_NOT_OPENED;
    }
    return pService->GetStationList(result);
}

ErrCode WifiHotspotServiceImpl::DisassociateSta(const StationInfo &info)
{
    WIFI_LOGI("Instance %{public}d %{public}s device name [%{private}s]", m_id, __func__,
        info.deviceName.c_str());
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DisassociateSta:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (CheckMacIsValid(info.bssid)) {
        return WIFI_OPT_INVALID_PARAM;
    }
    if (!IsApServiceRunning()) {
        return WIFI_OPT_AP_NOT_OPENED;
    }

    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
    if (pService == nullptr) {
        WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
        return WIFI_OPT_AP_NOT_OPENED;
    }
    return pService->DisconnetStation(info);
}

int WifiHotspotServiceImpl::CheckOperHotspotSwitchPermission(const ServiceType type)
{
#ifdef FEATURE_AP_EXTENSION
    return (type == ServiceType::WIFI_EXT) ? WifiPermissionUtils::VerifyManageWifiHotspotExtPermission() :
        WifiPermissionUtils::VerifyManageWifiHotspotPermission();
#else
    return (type == ServiceType::WIFI_EXT) ? PERMISSION_DENIED :
        WifiPermissionUtils::VerifyManageWifiHotspotPermission();
#endif
}

ErrCode WifiHotspotServiceImpl::CheckCanEnableHotspot(const ServiceType type)
{
    if (CheckOperHotspotSwitchPermission(type) == PERMISSION_DENIED) {
        WIFI_LOGE("EnableHotspot:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == 1) {
        WIFI_LOGI("current airplane mode and can not use ap, open failed!");
        return WIFI_OPT_FORBID_AIRPLANE;
    }
    if (WifiConfigCenter::GetInstance().GetPowerSavingModeState() == 1) {
        WIFI_LOGI("current power saving mode and can not use ap, open failed!");
        return WIFI_OPT_FORBID_POWSAVING;
    }

    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiMidState();
    if (curState != WifiOprMidState::CLOSED) {
        WIFI_LOGI("current wifi state is %{public}d, please close sta first!",
            static_cast<int>(curState));
        return WIFI_OPT_NOT_SUPPORTED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::EnableHotspot(const ServiceType type)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    ErrCode errCode = CheckCanEnableHotspot(type);
    if (errCode != WIFI_OPT_SUCCESS) {
        return errCode;
    }

    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetApMidState(m_id);
    if (curState != WifiOprMidState::CLOSED) {
        WIFI_LOGI("current ap is %{public}d, state is %{public}d", m_id, static_cast<int>(curState));
        if (curState == WifiOprMidState::CLOSING) { /* when ap is closing, return */
            return WIFI_OPT_OPEN_FAIL_WHEN_CLOSING;
        } else {
            return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
        }
    }
    if (!WifiConfigCenter::GetInstance().SetApMidState(curState, WifiOprMidState::OPENING, m_id)) {
        WIFI_LOGI("current ap is %{public}d, set ap mid state opening failed!"
            "may be other activity has been operated", m_id);
        return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
    }
    errCode = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_AP) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_AP);
            break;
        }
        IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
        if (pService == nullptr) {
            WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
            break;
        }
        errCode = pService->RegisterApServiceCallbacks(WifiManager::GetInstance().GetApCallback());
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Register ap service callback failed!");
            break;
        }
        errCode = pService->EnableHotspot();
        if (errCode != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("service enable ap failed, ret %{public}d!", static_cast<int>(errCode));
            break;
        }
    } while (false);
    if (errCode != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED, m_id);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_AP, m_id);
    }
    return errCode;
}

ErrCode WifiHotspotServiceImpl::DisableHotspot(const ServiceType type)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (CheckOperHotspotSwitchPermission(type) == PERMISSION_DENIED) {
        WIFI_LOGE("EnableHotspot:VerifyManageWifiHotspotPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetApMidState(m_id);
    if (curState != WifiOprMidState::RUNNING) {
        WIFI_LOGI("current ap state is %{public}d", static_cast<int>(curState));
        if (curState == WifiOprMidState::OPENING) { /* when ap is opening, return */
            return WIFI_OPT_CLOSE_FAIL_WHEN_OPENING;
        } else {
            return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
        }
    }
    if (!WifiConfigCenter::GetInstance().SetApMidState(curState, WifiOprMidState::CLOSING, m_id)) {
        WIFI_LOGI("set ap mid state closing failed! may be other activity has been operated");
        return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
    }
    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
    if (pService == nullptr) {
        WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSED, m_id);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_AP, m_id);
        return WIFI_OPT_SUCCESS;
    }
    ErrCode ret = pService->DisableHotspot();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSING, WifiOprMidState::RUNNING, m_id);
    }
    return ret;
}

ErrCode WifiHotspotServiceImpl::AddBlockList(const StationInfo &info)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s"
        " device name [%{private}s]", m_id, __func__, info.deviceName.c_str());
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("AddBlockList:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("AddBlockList:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (CheckMacIsValid(info.bssid)) {
        return WIFI_OPT_INVALID_PARAM;
    }
    if (!IsApServiceRunning()) {
        WIFI_LOGE("ApService is not running!");
        return WIFI_OPT_AP_NOT_OPENED;
    }

    if (WifiConfigCenter::GetInstance().AddBlockList(info, m_id) < 0) {
        WIFI_LOGE("Add block list failed!");
        return WIFI_OPT_FAILED;
    }
    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
    if (pService == nullptr) {
        WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
        return WIFI_OPT_AP_NOT_OPENED;
    }
    return pService->AddBlockList(info);
}

ErrCode WifiHotspotServiceImpl::DelBlockList(const StationInfo &info)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s device name [%{private}s]",
        m_id, __func__, info.deviceName.c_str());
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DelBlockList:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DelBlockList:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (CheckMacIsValid(info.bssid)) {
        return WIFI_OPT_INVALID_PARAM;
    }

    if (IsApServiceRunning()) {
        IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
        if (pService == nullptr) {
            WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
            return WIFI_OPT_AP_NOT_OPENED;
        }
        if (pService->DelBlockList(info) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("request del hotspot blocklist failed!");
            return WIFI_OPT_FAILED;
        }
    }

    if (WifiConfigCenter::GetInstance().DelBlockList(info, m_id) < 0) {
        WIFI_LOGE("Delete block list failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetValidBands(std::vector<BandType> &bands)
{
     WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetValidBands:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiConfigCenter::GetInstance().GetValidBands(bands) < 0) {
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetValidChannels(BandType band, std::vector<int32_t> &validchannels)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s band %{public}d",
        m_id, __func__, static_cast<int>(band));
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetValidChannels:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (band == BandType::BAND_NONE) {
        return WIFI_OPT_INVALID_PARAM;
    }
    ChannelsTable channInfoFromCenter;
    WifiConfigCenter::GetInstance().GetValidChannels(channInfoFromCenter);
    auto iter = channInfoFromCenter.find(band);
    if (iter != channInfoFromCenter.end()) {
        validchannels = iter->second;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetBlockLists(std::vector<StationInfo> &infos)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetBlockLists:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiConfigCenter::GetInstance().GetBlockLists(infos, m_id) < 0) {
        WIFI_LOGE("Get block list failed!");
        return WIFI_OPT_FAILED;
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

ErrCode WifiHotspotServiceImpl::RegisterCallBack(const sptr<IWifiHotspotCallback> &callback)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RegisterCallBack:VerifyWifiConnectionPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    WifiInternalEventDispatcher::GetInstance().SetSingleHotspotCallback(callback, m_id);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetSupportedFeatures(long &features)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetSupportedFeatures:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    int ret = WifiManager::GetInstance().GetSupportedFeatures(features);
    if (ret < 0) {
        WIFI_LOGE("Failed to get supported features!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetSupportedPowerModel(std::set<PowerModel>& setPowerModelList)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetSupportedPowerModel:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsApServiceRunning()) {
        return WIFI_OPT_AP_NOT_OPENED;
    }
    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
    if (pService == nullptr) {
        WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
        return WIFI_OPT_AP_NOT_OPENED;
    }
    pService->GetSupportedPowerModel(setPowerModelList);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetPowerModel(PowerModel& model)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetPowerModel:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsApServiceRunning()) {
        return WIFI_OPT_AP_NOT_OPENED;
    }
    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
    if (pService == nullptr) {
        WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
        return WIFI_OPT_AP_NOT_OPENED;
    }
    pService->GetPowerModel(model);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::SetPowerModel(const PowerModel& model)
{
    WIFI_LOGI("current ap service is %{public}d %{public}s", m_id, __func__);
    if (!IsApServiceRunning()) {
        return WIFI_OPT_AP_NOT_OPENED;
    }
    IApService *pService = WifiServiceManager::GetInstance().GetApServiceInst(m_id);
    if (pService == nullptr) {
        WIFI_LOGE("Instance %{public}d get hotspot service is null!", m_id);
        return WIFI_OPT_AP_NOT_OPENED;
    }
    pService->SetPowerModel(model);
    return WIFI_OPT_SUCCESS;
}

void WifiHotspotServiceImpl::ConfigInfoDump(std::string& result)
{
    HotspotConfig config;
    WifiConfigCenter::GetInstance().GetHotspotConfig(config);
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
            ss << "  Station[" << idx << "].ipAddr: " << IpAnonymize(each.ipAddr) << "\n";
            ss << "\n";
        }
        result += ss.str();
        result += "\n";
    }

    std::vector<StationInfo> vecBlockStations;
    WifiConfigCenter::GetInstance().GetBlockLists(vecBlockStations);
    if (!vecBlockStations.empty()) {
        std::stringstream ss;
        ss << "Block station list size: " << vecBlockStations.size() << "\n";
        int idx = 0;
        for (auto& each : vecBlockStations) {
            ++idx;
            ss << "  BlockStation[" << idx << "].deviceName: " << each.deviceName << "\n";
            ss << "  BlockStation[" << idx << "].bssid: " << MacAnonymize(each.bssid) << "\n";
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
}  // namespace Wifi
}  // namespace OHOS
