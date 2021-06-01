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

#include "wifi_hotspot_service_impl.h"
#include "wifi_permission_utils.h"
#include "wifi_global_func.h"
#include "wifi_auth_center.h"
#include "wifi_config_center.h"
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_event_broadcast.h"
#include "wifi_logger.h"
#include "define.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiHotspotServiceImpl");

namespace OHOS {
namespace Wifi {
std::mutex WifiHotspotServiceImpl::g_instanceLock;
sptr<WifiHotspotServiceImpl> WifiHotspotServiceImpl::g_instance;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(WifiHotspotServiceImpl::GetInstance().GetRefPtr());

sptr<WifiHotspotServiceImpl> WifiHotspotServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            auto service = new WifiHotspotServiceImpl;
            g_instance = service;
        }
    }
    return g_instance;
}

WifiHotspotServiceImpl::WifiHotspotServiceImpl()
    : SystemAbility(WIFI_HOTSPOT_ABILITY_ID, true), mPublishFlag(false), mState(ServiceRunningState::STATE_NOT_START)
{}

WifiHotspotServiceImpl::~WifiHotspotServiceImpl()
{}

void WifiHotspotServiceImpl::OnStart()
{
    WifiManager::GetInstance();
    if (mState == ServiceRunningState::STATE_RUNNING) {
        WIFI_LOGD("Service has already started.");
        return;
    }
    if (!Init()) {
        WIFI_LOGE("Failed to init service");
        OnStop();
        return;
    }
    mState = ServiceRunningState::STATE_RUNNING;
}

void WifiHotspotServiceImpl::OnStop()
{
    mState = ServiceRunningState::STATE_NOT_START;
    mPublishFlag = false;
}

bool WifiHotspotServiceImpl::Init()
{
    if (!mPublishFlag) {
        bool ret = Publish(WifiHotspotServiceImpl::GetInstance());
        if (!ret) {
            WIFI_LOGE("Failed to publish hotspot service!");
            return false;
        }
        mPublishFlag = true;
    }
    return true;
}

ErrCode WifiHotspotServiceImpl::IsHotspotActive(bool &bActive)
{
    WIFI_LOGI("IsHotspotActive");
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetApMidState();
    bActive = (curState == WifiOprMidState::RUNNING);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetHotspotState(int &state)
{
    WIFI_LOGI("GetHotspotState");
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetHotspotState:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetHotspotState:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    state = WifiConfigCenter::GetInstance().GetHotspotState();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetHotspotConfig(HotspotConfig &result)
{
    WIFI_LOGI("GetHotspotConfig");
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetHotspotConfig:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetHotspotConfig(result);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::SetHotspotConfig(const HotspotConfig &config)
{
    WIFI_LOGI("SetHotspotConfig band %{public}d", static_cast<int>(config.GetBand()));
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetHotspotConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetHotspotConfig:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetHotspotConfig:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    std::vector<BandType> bandsFromCenter;
    WifiConfigCenter::GetInstance().GetValidBands(bandsFromCenter);
    ChannelsTable channInfoFromCenter;
    WifiConfigCenter::GetInstance().GetValidChannels(channInfoFromCenter);
    HotspotConfig configFromCenter;
    WifiConfigCenter::GetInstance().GetHotspotConfig(configFromCenter);
    ErrCode validRetval = IsValidHotspotConfig(config, configFromCenter, bandsFromCenter, channInfoFromCenter);
    if (validRetval != ErrCode::WIFI_OPT_SUCCESS) {
        return validRetval;
    }

    if (!IsApServiceRunning()) {
        WifiConfigCenter::GetInstance().SetHotspotConfig(config);
    } else {
        WifiRequestMsgInfo msg;
        msg.msgCode = WifiInternalMsgCode::AP_SET_HOTSPOT_CONFIG_REQ;
        msg.params.hotspotConfig = config;
        if (WifiManager::GetInstance().PushMsg(WIFI_SERVICE_AP, msg) < 0) {
            WIFI_LOGE("send set hotspot config msg failed!");
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetDeviceMacAddress(std::string &result)
{
    WIFI_LOGI("GetDeviceMacAddress");
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetDeviceMacAddress:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyGetWifiLocalMacPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetDeviceMacAddress:VerifyGetWifiLocalMacPermission "
                  "PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetMacAddress(result);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetStationList(std::vector<StationInfo> &result)
{
    WIFI_LOGI("GetStationList");
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

    WifiConfigCenter::GetInstance().GetStationList(result);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::DisassociateSta(const StationInfo &info)
{
    WIFI_LOGI("DisassociateSta device name [%s]", info.deviceName.c_str());
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

    WifiRequestMsgInfo msg;
    msg.msgCode = WifiInternalMsgCode::AP_DISCCONECT_STA_BY_MAC_REQ;
    msg.params.stationInfo = info;
    if (WifiManager::GetInstance().PushMsg(WIFI_SERVICE_AP, msg) < 0) {
        WIFI_LOGE("send disconnect sta msg failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::CheckCanEnableHotspot(void)
{
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("EnableHotspot:VerifyWifiConnectionPermission PERMISSION_DENIED!");
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
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::EnableHotspot(void)
{
    WIFI_LOGI("EnableHotspot");
    ErrCode errCode = CheckCanEnableHotspot();
    if (errCode != WIFI_OPT_SUCCESS) {
        return errCode;
    }

    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetApMidState();
    if (curState != WifiOprMidState::CLOSED) {
        WIFI_LOGI("current ap state is %{public}d", static_cast<int>(curState));
        if (curState == WifiOprMidState::CLOSING) { /* when ap is closing, return */
            return WIFI_OPT_OPEN_FAIL_WHEN_CLOSING;
        } else {
            return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
        }
    }
    if (!WifiConfigCenter::GetInstance().SetApMidState(curState, WifiOprMidState::OPENING)) {
        WIFI_LOGI("set ap mid state opening failed! may be other activity has been "
                  "operated");
        return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
    }
    bool bflag = false;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_AP) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_AP);
            break;
        }
        WifiMessageQueue<WifiResponseMsgInfo> *mqUp = WifiManager::GetInstance().GetMessageQueue();
        auto srvInst = WifiServiceManager::GetInstance().GetServiceInst(WIFI_SERVICE_AP);
        if (srvInst == nullptr) {
            WIFI_LOGE("Failed to get service instance!");
            return WIFI_OPT_FAILED;
        }
        int ret = srvInst->Init(mqUp);
        if (ret < 0) {
            WIFI_LOGE("Init %{public}s service failed!", WIFI_SERVICE_AP);
            WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_AP);
            break;
        }
        bflag = true;
    } while (false);
    if (!bflag) {
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED);
        return WIFI_OPT_FAILED;
    } else {
        return WIFI_OPT_SUCCESS;
    }
}

ErrCode WifiHotspotServiceImpl::DisableHotspot(void)
{
    WIFI_LOGI("DisableHotspot");
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DisableHotspot:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetApMidState();
    if (curState != WifiOprMidState::RUNNING) {
        WIFI_LOGI("current ap state is %{public}d", static_cast<int>(curState));
        if (curState == WifiOprMidState::OPENING) { /* when ap is opening, return */
            return WIFI_OPT_CLOSE_FAIL_WHEN_OPENING;
        } else {
            return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
        }
    }
    if (!WifiConfigCenter::GetInstance().SetApMidState(curState, WifiOprMidState::CLOSING)) {
        WIFI_LOGI("set ap mid state closing failed! may be other activity has been "
                  "operated");
        return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
    }
    auto srvInst = WifiServiceManager::GetInstance().GetServiceInst(WIFI_SERVICE_AP);
    if (srvInst == nullptr) {
        WIFI_LOGE("Failed to get service instance!");
        return WIFI_OPT_FAILED;
    }
    int ret = srvInst->UnInit();
    if (ret < 0) {
        WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSING, WifiOprMidState::RUNNING);
        return WIFI_OPT_FAILED;
    } else {
        return WIFI_OPT_SUCCESS;
    }
}

ErrCode WifiHotspotServiceImpl::AddBlockList(const StationInfo &info)
{
    WIFI_LOGI("AddBlockList, device name [%s]", info.deviceName.c_str());
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

    if (WifiConfigCenter::GetInstance().AddBlockList(info) < 0) {
        WIFI_LOGE("Add block list failed!");
        return WIFI_OPT_FAILED;
    }
    WifiRequestMsgInfo msg;
    msg.msgCode = WifiInternalMsgCode::AP_ADD_BLOCK_LIST_REQ;
    msg.params.stationInfo = info;
    if (WifiManager::GetInstance().PushMsg(WIFI_SERVICE_AP, msg) < 0) {
        WIFI_LOGE("send set hotspot blocklist msg failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::DelBlockList(const StationInfo &info)
{
    WIFI_LOGI("DelBlockList, device name [%s]", info.deviceName.c_str());
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
        WifiRequestMsgInfo msg;
        msg.msgCode = WifiInternalMsgCode::AP_DEL_BLOCK_LIST_REQ;
        msg.params.stationInfo = info;
        if (WifiManager::GetInstance().PushMsg(WIFI_SERVICE_AP, msg) < 0) {
            WIFI_LOGE("send del hotspot blocklist msg failed!");
            return WIFI_OPT_FAILED;
        }
    }

    if (WifiConfigCenter::GetInstance().DelBlockList(info) < 0) {
        WIFI_LOGE("Delete block list failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetValidBands(std::vector<BandType> &bands)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetValidBands:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsApServiceRunning()) {
        WIFI_LOGE("ApService is not running!");
        return WIFI_OPT_AP_NOT_OPENED;
    }

    if (WifiConfigCenter::GetInstance().GetValidBands(bands) < 0) {
        WIFI_LOGE("Delete block list failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetValidChannels(BandType band, std::vector<int32_t> &validchannels)
{
    WIFI_LOGI("GetValidChannels band %{public}d", static_cast<int>(band));
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetValidChannels:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsApServiceRunning()) {
        WIFI_LOGE("ApService is not running!");
        return WIFI_OPT_AP_NOT_OPENED;
    }

    ChannelsTable channelsInfo;
    if (WifiConfigCenter::GetInstance().GetValidChannels(channelsInfo) < 0) {
        WIFI_LOGE("Failed to obtain data from the configuration center.");
        return WIFI_OPT_FAILED;
    }

    auto it = channelsInfo.find(band);
    if (it == channelsInfo.end()) {
        WIFI_LOGE("The value of band is invalid.");
        return WIFI_OPT_INVALID_PARAM;
    }

    validchannels = channelsInfo[band];

    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotServiceImpl::GetBlockLists(std::vector<StationInfo> &infos)
{
    WIFI_LOGI("GetBlockLists");
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetBlockLists:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiConfigCenter::GetInstance().GetBlockLists(infos) < 0) {
        WIFI_LOGE("Delete block list failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

bool WifiHotspotServiceImpl::IsApServiceRunning()
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetApMidState();
    if (curState != WifiOprMidState::RUNNING) {
        WIFI_LOGI("current ap state is %{public}d", static_cast<int>(curState));
        return false;
    }
    return true;
}

ErrCode WifiHotspotServiceImpl::RegisterCallBack(const sptr<IWifiHotspotCallback> &callback)
{
    WIFI_LOGI("RegisterCallBack");
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RegisterCallBack:VerifyWifiConnectionPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    WifiEventBroadcast::GetInstance().SetSingleHotspotCallback(callback);
    return WIFI_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS
