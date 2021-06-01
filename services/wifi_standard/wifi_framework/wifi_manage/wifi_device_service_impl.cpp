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

#include "wifi_device_service_impl.h"
#include <unistd.h>
#include "wifi_permission_utils.h"
#include "wifi_internal_msg.h"
#include "wifi_auth_center.h"
#include "wifi_config_center.h"
#include "wifi_event_broadcast.h"
#include "wifi_manager.h"
#include "wifi_service_manager.h"
#include "wifi_logger.h"
#include "define.h"

DEFINE_WIFILOG_LABEL("WifiDeviceServiceImpl");
namespace OHOS {
namespace Wifi {
std::mutex WifiDeviceServiceImpl::g_instanceLock;
sptr<WifiDeviceServiceImpl> WifiDeviceServiceImpl::g_instance;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(WifiDeviceServiceImpl::GetInstance().GetRefPtr());

sptr<WifiDeviceServiceImpl> WifiDeviceServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            auto service = new WifiDeviceServiceImpl;
            g_instance = service;
        }
    }
    return g_instance;
}

WifiDeviceServiceImpl::WifiDeviceServiceImpl()
    : SystemAbility(WIFI_DEVICE_ABILITY_ID, true), mPublishFlag(false), mState(ServiceRunningState::STATE_NOT_START)
{}

WifiDeviceServiceImpl::~WifiDeviceServiceImpl()
{}

void WifiDeviceServiceImpl::OnStart()
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

void WifiDeviceServiceImpl::OnStop()
{
    mState = ServiceRunningState::STATE_NOT_START;
    mPublishFlag = false;
}

bool WifiDeviceServiceImpl::Init()
{
    if (!mPublishFlag) {
        bool ret = Publish(WifiDeviceServiceImpl::GetInstance());
        if (!ret) {
            WIFI_LOGE("Failed to publish sta service!");
            return false;
        }
        mPublishFlag = true;
    }
    return true;
}

ErrCode WifiDeviceServiceImpl::EnableWifi()
{
    ErrCode errCode = CheckCanEnableWifi();
    if (errCode != WIFI_OPT_SUCCESS) {
        return errCode;
    }

    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiMidState();
    if (curState != WifiOprMidState::CLOSED) {
        WIFI_LOGI("current wifi state is %{public}d", static_cast<int>(curState));
        if (curState == WifiOprMidState::CLOSING) { /* when current wifi is closing, return */
            return WIFI_OPT_OPEN_FAIL_WHEN_CLOSING;
        } else {
            return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
        }
    }

    if (!WifiConfigCenter::GetInstance().SetWifiMidState(curState, WifiOprMidState::OPENING)) {
        WIFI_LOGI("set wifi mid state opening failed! may be other activity has been operated");
        return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
    }

    bool bflag = false;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_STA) < 0) {
            WIFI_LOGE("Load wifi device service failed!");
            break;
        }
        WifiMessageQueue<WifiResponseMsgInfo> *mqUp = WifiManager::GetInstance().GetMessageQueue();
        auto srvInst = WifiServiceManager::GetInstance().GetServiceInst(WIFI_SERVICE_STA);
        if (srvInst == nullptr) {
            WIFI_LOGE("Failed to get service instance!");
            break;
        }
        int ret = srvInst->Init(mqUp);
        if (ret < 0) {
            WIFI_LOGE("Init wifi device service failed!");
            WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_STA);
            break;
        }
        bflag = true;
    } while (false);
    if (!bflag) {
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED);
        return WIFI_OPT_FAILED;
    } else {
        return WIFI_OPT_SUCCESS;
    }
}

ErrCode WifiDeviceServiceImpl::DisableWifi()
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DisableWifi:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiMidState();
    if (curState != WifiOprMidState::RUNNING) {
        WIFI_LOGI("current wifi state is %{public}d", static_cast<int>(curState));
        if (curState == WifiOprMidState::OPENING) { /* when current wifi is opening, return */
            return WIFI_OPT_CLOSE_FAIL_WHEN_OPENING;
        } else {
            return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
        }
    }
    if (!WifiConfigCenter::GetInstance().SetWifiMidState(curState, WifiOprMidState::CLOSING)) {
        WIFI_LOGI("set wifi mid state opening failed! may be other activity has been operated");
        return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
    }
    auto srvInst = WifiServiceManager::GetInstance().GetServiceInst(WIFI_SERVICE_STA);
    if (srvInst == nullptr) {
        WIFI_LOGE("Failed to get service instance!");
        return WIFI_OPT_FAILED;
    }
    int ret = srvInst->UnInit();
    if (ret < 0) {
        WIFI_LOGE("UnInit wifi device service failed!");
        WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSING, WifiOprMidState::RUNNING);
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::AddDeviceConfig(const WifiDeviceConfig &config, int &result)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("AddDeviceConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    int ret = WifiManager::GetInstance().AddDeviceConfig(config, result);
    if (ret < 0) {
        WIFI_LOGE("Add wifi device config failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::RemoveDeviceConfig(int networkId)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RemoveDeviceConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    WifiRequestMsgInfo msg;
    msg.msgCode = WifiInternalMsgCode::STA_REMOVE_DEVICE_REQ;
    msg.params.argInt = networkId;
    if (WifiManager::GetInstance().PushMsg(WIFI_SERVICE_STA, msg) < 0) {
        WIFI_LOGE("send remove device config msg failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetDeviceConfigs(std::vector<WifiDeviceConfig> &result)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetDeviceConfigs:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetDeviceConfig(result);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::EnableDeviceConfig(int networkId, bool attemptEnable)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("EnableDeviceConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    int ret =
        WifiConfigCenter::GetInstance().SetDeviceState(networkId, (int)WifiDeviceConfigStatus::ENABLED, attemptEnable);
    if (ret < 0) {
        WIFI_LOGE("Enable device config failed! networkid is %{public}d", networkId);
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::DisableDeviceConfig(int networkId)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DisableDeviceConfig:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    int ret = WifiConfigCenter::GetInstance().SetDeviceState(networkId, (int)WifiDeviceConfigStatus::DISABLED);
    if (ret < 0) {
        WIFI_LOGE("Disable Wi-Fi device configuration. failed! networkid is %{public}d", networkId);
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::ConnectTo(int networkId)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("ConnectTo:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    WifiRequestMsgInfo msg;
    msg.msgCode = WifiInternalMsgCode::STA_CONNECT_REQ;
    msg.params.argInt = networkId;
    if (WifiManager::GetInstance().PushMsg(WIFI_SERVICE_STA, msg) < 0) {
        WIFI_LOGE("send connect network msg failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::ConnectTo(const WifiDeviceConfig &config)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("ConnectTo with config:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    WifiRequestMsgInfo msg;
    msg.msgCode = WifiInternalMsgCode::STA_CONNECT_REQ;
    msg.params.deviceConfig = config;
    if (WifiManager::GetInstance().PushMsg(WIFI_SERVICE_STA, msg) < 0) {
        WIFI_LOGE("send connect with device config msg failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::ReConnect()
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("ReConnect:VerifySetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    if (!IsScanServiceRunning()) {
        return WIFI_OPT_SCAN_NOT_OPENED;
    }

    WifiRequestMsgInfo msg;
    msg.msgCode = WifiInternalMsgCode::SCAN_RECONNECT_REQ;
    if (WifiManager::GetInstance().PushMsg(WIFI_SERVICE_SCAN, msg) < 0) {
        WIFI_LOGE("send scan msg failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::ReAssociate(void)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("ReAssociate:VerifySetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    WifiRequestMsgInfo msg;
    msg.msgCode = WifiInternalMsgCode::STA_REASSOCIATE_REQ;
    if (WifiManager::GetInstance().PushMsg(WIFI_SERVICE_STA, msg) < 0) {
        WIFI_LOGE("send disconnect msg failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::Disconnect(void)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("Disconnect:VerifySetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    WifiRequestMsgInfo msg;
    msg.msgCode = WifiInternalMsgCode::STA_DISCONNECT_REQ;
    if (WifiManager::GetInstance().PushMsg(WIFI_SERVICE_STA, msg) < 0) {
        WIFI_LOGE("send disconnect msg failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::StartWps(const WpsConfig &config)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("StartWps:VerifySetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    WifiRequestMsgInfo msg;
    msg.msgCode = WifiInternalMsgCode::STA_START_WPS_REQ;
    msg.params.wpsConfig = config;
    if (WifiManager::GetInstance().PushMsg(WIFI_SERVICE_STA, msg) < 0) {
        WIFI_LOGE("send start wps msg failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::CancelWps(void)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("CancelWps:VerifySetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsStaServiceRunning()) {
        return WIFI_OPT_STA_NOT_OPENED;
    }

    WifiRequestMsgInfo msg;
    msg.msgCode = WifiInternalMsgCode::STA_CANCEL_WPS_REQ;
    if (WifiManager::GetInstance().PushMsg(WIFI_SERVICE_STA, msg) < 0) {
        WIFI_LOGE("send cancel wps msg failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::IsWifiActive(bool &bActive)
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiMidState();
    bActive = (curState == WifiOprMidState::RUNNING);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetWifiState(int &state)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetWifiState:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    state = WifiConfigCenter::GetInstance().GetWifiState();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetLinkedInfo(WifiLinkedInfo &info)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetLinkedInfo:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyGetWifiLocalMacPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetLinkedInfo:VerifyGetWifiLocalMacPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetLinkedInfo:VerifyGetScanInfosPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetLinkedInfo(info);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetDhcpInfo(DhcpInfo &info)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetDhcpInfo:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetDhcpInfo(info);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::SetCountryCode(const std::string &countryCode)
{
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetCountryCode:VerifyWifiConnectionPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().SetCountryCode(countryCode);

    if (IsStaServiceRunning()) {
        WifiRequestMsgInfo msg;
        msg.msgCode = WifiInternalMsgCode::STA_SET_COUNTRY_CODE;
        if (WifiManager::GetInstance().PushMsg(WIFI_SERVICE_STA, msg) < 0) {
            WIFI_LOGE("send set country code msg failed!");
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetCountryCode(std::string &countryCode)
{
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetCountryCode:VerifyWifiConnectionPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().GetCountryCode(countryCode);
    WIFI_LOGI("GetCountryCode: country code is %{public}s", countryCode.c_str());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::RegisterCallBackClient(
    const std::string &name, const sptr<IWifiDeviceCallBack> &callback)
{
    WIFI_LOGI("RegisterCallBackClient");
    if (callback == nullptr) {
        WIFI_LOGE("Get call back client failed!");
        return WIFI_OPT_FAILED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RegisterCallBackClient:VerifyWifiConnectionPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RegisterCallBackClient:VerifyWifiConnectionPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiEventBroadcast::GetInstance().SetSingleStaCallback(callback);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::GetSignalLevel(const int &rssi, const int &band, int &level)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetSignalLevel:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    level = WifiConfigCenter::GetInstance().GetSignalLevel(rssi, band);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceServiceImpl::CheckCanEnableWifi(void)
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("EnableWifi:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    /**
     * when airplane mode opened, if the config "can_use_sta_when_airplanemode"
     * opened, then can open sta; other, return forbid.
     */
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == 1 &&
        !WifiConfigCenter::GetInstance().GetCanUseStaWhenAirplaneMode()) {
        WIFI_LOGI("current airplane mode and can not use sta, open failed!");
        return WIFI_OPT_FORBID_AIRPLANE;
    }
    /* when power saving mode opened, can't open sta, return forbid. */
    if (WifiConfigCenter::GetInstance().GetPowerSavingModeState() == 1) {
        WIFI_LOGI("current power saving mode and can not use sta, open failed!");
        return WIFI_OPT_FORBID_POWSAVING;
    }
    /**
     * Check the interval between the last STA shutdown and the current STA
     * startup.
     */
    double interval = WifiConfigCenter::GetInstance().GetWifiStaInterval();
    if (interval <= REOPEN_STA_INTERVAL) {
        int waitMils = REOPEN_STA_INTERVAL - int(interval) + 1;
        WIFI_LOGI("open wifi too frequent, interval since last close is %lf, and wait "
                  "%{public}d ms",
            interval,
            waitMils);
        usleep(waitMils * MSEC);
    }
    return WIFI_OPT_SUCCESS;
}

bool WifiDeviceServiceImpl::IsStaServiceRunning()
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiMidState();
    if (curState != WifiOprMidState::RUNNING) {
        WIFI_LOGD("current wifi state is %{public}d", static_cast<int>(curState));
        return false;
    }
    return true;
}

bool WifiDeviceServiceImpl::IsScanServiceRunning()
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetScanMidState();
    if (curState != WifiOprMidState::RUNNING) {
        WIFI_LOGD("scan service does not started!");
        return false;
    }
    return true;
}
}  // namespace Wifi
}  // namespace OHOS