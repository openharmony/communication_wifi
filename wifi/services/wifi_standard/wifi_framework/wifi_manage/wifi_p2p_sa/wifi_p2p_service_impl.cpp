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

#include "wifi_p2p_service_impl.h"
#include <file_ex.h>
#include "define.h"
#include "if_config.h"
#include "ip_tools.h"
#include "wifi_auth_center.h"
#include "wifi_channel_helper.h"
#include "wifi_common_util.h"
#include "wifi_config_center.h"
#include "wifi_dumper.h"
#include "wifi_hid2d_service_utils.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_logger.h"
#include "wifi_manager.h"
#include "wifi_net_agent.h"
#include "wifi_permission_utils.h"
#include "wifi_service_manager.h"
#include "wifi_global_func.h"
#include "mac_address.h"
#include "p2p_define.h"
#include "wifi_hisysevent.h"

DEFINE_WIFILOG_P2P_LABEL("WifiP2pServiceImpl");

namespace OHOS {
namespace Wifi {
std::mutex WifiP2pServiceImpl::instanceLock;
std::mutex WifiP2pServiceImpl::g_p2pMutex;
sptr<WifiP2pServiceImpl> WifiP2pServiceImpl::instance;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(WifiP2pServiceImpl::GetInstance().GetRefPtr());

sptr<WifiP2pServiceImpl> WifiP2pServiceImpl::GetInstance()
{
    if (instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock);
        if (instance == nullptr) {
            sptr<WifiP2pServiceImpl> service = new (std::nothrow) WifiP2pServiceImpl;
            instance = service;
        }
    }
    return instance;
}

WifiP2pServiceImpl::WifiP2pServiceImpl()
    : SystemAbility(WIFI_P2P_ABILITY_ID, true), mPublishFlag(false), mState(ServiceRunningState::STATE_NOT_START)
{}

WifiP2pServiceImpl::~WifiP2pServiceImpl()
{}

void WifiP2pServiceImpl::OnStart()
{
    WIFI_LOGI("Start p2p service!");
    if (mState == ServiceRunningState::STATE_RUNNING) {
        WIFI_LOGI("P2p service has already started.");
        return;
    }
    if (WifiManager::GetInstance().Init() < 0) {
        WIFI_LOGE("WifiManager init failed!");
        return;
    }
    if (!Init()) {
        WIFI_LOGE("Failed to init p2p service");
        OnStop();
        return;
    }
    mState = ServiceRunningState::STATE_RUNNING;
    WifiManager::GetInstance().AddSupportedFeatures(WifiFeatures::WIFI_FEATURE_P2P);
    WifiOprMidState p2pState = WifiConfigCenter::GetInstance().GetP2pMidState();
    auto &pWifiP2pManager = WifiManager::GetInstance().GetWifiP2pManager();
    if (p2pState == WifiOprMidState::CLOSED && pWifiP2pManager) {
        pWifiP2pManager->StartUnloadP2PSaTimer();
    }
}

void WifiP2pServiceImpl::OnStop()
{
    mState = ServiceRunningState::STATE_NOT_START;
    mPublishFlag = false;
    WIFI_LOGI("Stop p2p service!");
}

bool WifiP2pServiceImpl::Init()
{
    std::lock_guard<std::mutex> lock(g_p2pMutex);
    if (!mPublishFlag) {
        bool ret = Publish(WifiP2pServiceImpl::GetInstance());
        if (!ret) {
            WIFI_LOGE("Failed to publish p2p service!");
            return false;
        }
        mPublishFlag = true;
    }
    return true;
}

ErrCode WifiP2pServiceImpl::CheckCanEnableP2p(void)
{
    if (WifiPermissionUtils::VerifySameProcessPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("EnableP2p:VerifySameProcessPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    /**
     * when airplane mode opened, if the config "can_open_sta_when_airplanemode"
     * opened, then can open sta; other, return forbid.
     */
    if (WifiConfigCenter::GetInstance().GetAirplaneModeState() == MODE_STATE_OPEN &&
        !WifiSettings::GetInstance().GetCanOpenStaWhenAirplaneMode()) {
        WIFI_LOGI("current airplane mode and can not use p2p, open failed!");
        return WIFI_OPT_FORBID_AIRPLANE;
    }
    if (WifiConfigCenter::GetInstance().GetPowerSavingModeState() == 1) {
        WIFI_LOGW("current power saving mode and can not use p2p, open failed!");
        return WIFI_OPT_FORBID_POWSAVING;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pServiceImpl::EnableP2p(void)
{
    WIFI_LOGI("EnableP2p");
    ErrCode errCode = CheckCanEnableP2p();
    if (errCode != WIFI_OPT_SUCCESS) {
        return errCode;
    }

    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetP2pMidState();
    if (curState != WifiOprMidState::CLOSED) {
        WIFI_LOGW("current p2p state is %{public}d", static_cast<int>(curState));
        if (curState == WifiOprMidState::CLOSING) {
            return WIFI_OPT_OPEN_FAIL_WHEN_CLOSING;
        } else {
            return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
        }
    }
    if (!WifiConfigCenter::GetInstance().SetP2pMidState(curState, WifiOprMidState::OPENING)) {
        WIFI_LOGD("set p2p mid state opening failed!");
        return WIFI_OPT_OPEN_SUCC_WHEN_OPENED;
    }
    ErrCode ret = WIFI_OPT_FAILED;
    do {
        if (WifiServiceManager::GetInstance().CheckAndEnforceService(WIFI_SERVICE_P2P) < 0) {
            WIFI_LOGE("Load %{public}s service failed!", WIFI_SERVICE_P2P);
            break;
        }
        IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
        if (pService == nullptr) {
            WIFI_LOGE("Create %{public}s service failed!", WIFI_SERVICE_P2P);
            break;
        }
        ret = pService->RegisterP2pServiceCallbacks(WifiManager::GetInstance().GetWifiP2pManager()->GetP2pCallback());
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Register p2p service callback failed!");
            break;
        }
        ret = pService->EnableP2p();
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("service EnableP2p failed, ret %{public}d!", static_cast<int>(ret));
            break;
        }
    } while (false);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::OPENING, WifiOprMidState::CLOSED);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_P2P);
    } else {
        WifiManager::GetInstance().GetWifiP2pManager()->StopUnloadP2PSaTimer();
    }
    return ret;
}

ErrCode WifiP2pServiceImpl::DisableP2p(void)
{
    WIFI_LOGI("DisableP2p");
    if (WifiPermissionUtils::VerifySameProcessPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DisableP2p:VerifySameProcessPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetP2pMidState();
    if (curState != WifiOprMidState::RUNNING) {
        WIFI_LOGI("current p2p state is %{public}d", static_cast<int>(curState));
        if (curState == WifiOprMidState::OPENING) {
            return WIFI_OPT_CLOSE_FAIL_WHEN_OPENING;
        } else {
            return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
        }
    }
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    if (!WifiConfigCenter::GetInstance().SetP2pMidState(curState, WifiOprMidState::CLOSING)) {
        WIFI_LOGD("set p2p mid state opening failed! may be other activity has been operated");
        return WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED;
    }
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::CLOSED);
        WifiServiceManager::GetInstance().UnloadService(WIFI_SERVICE_P2P);
        return WIFI_OPT_SUCCESS;
    }
    ErrCode ret = pService->DisableP2p();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::CLOSING, WifiOprMidState::RUNNING);
    }
    return ret;
}

ErrCode WifiP2pServiceImpl::DiscoverDevices(void)
{
    WIFI_LOGI("DiscoverDevices");
    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (apiVersion == API_VERSION_9) {
#ifndef SUPPORT_RANDOM_MAC_ADDR
        if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("DiscoverDevices:VerifyGetScanInfosPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
#endif
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DiscoverDevices:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->DiscoverDevices();
}

ErrCode WifiP2pServiceImpl::StopDiscoverDevices(void)
{
    WIFI_LOGI("StopDiscoverDevices");
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("StopDiscoverDevices:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->StopDiscoverDevices();
}

ErrCode WifiP2pServiceImpl::DiscoverServices(void)
{
    WIFI_LOGI("DiscoverServices");
    if (WifiPermissionUtils::VerifyGetWifiDirectDevicePermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DiscoverServices:VerifyGetWifiDirectDevicePermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->DiscoverServices();
}

ErrCode WifiP2pServiceImpl::StopDiscoverServices(void)
{
    WIFI_LOGI("StopDiscoverServices");
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("StopDiscoverServices:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("StopDiscoverServices:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->StopDiscoverServices();
}

ErrCode WifiP2pServiceImpl::RequestService(const WifiP2pDevice &device, const WifiP2pServiceRequest &request)
{
    WIFI_LOGI("RequestService");
    if (WifiPermissionUtils::VerifyGetWifiDirectDevicePermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RequestService:VerifyGetWifiDirectDevicePermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->RequestService(device, request);
}

ErrCode WifiP2pServiceImpl::PutLocalP2pService(const WifiP2pServiceInfo &srvInfo)
{
    WIFI_LOGI("PutLocalP2pService, service name is [%{public}s]", srvInfo.GetServiceName().c_str());
    if (WifiPermissionUtils::VerifyGetWifiInfoInternalPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("PutLocalP2pService:VerifyGetWifiInfoInternalPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->PutLocalP2pService(srvInfo);
}

ErrCode WifiP2pServiceImpl::DeleteLocalP2pService(const WifiP2pServiceInfo &srvInfo)
{
    WIFI_LOGI("DeleteLocalP2pService, service name is [%{public}s]", srvInfo.GetServiceName().c_str());
    if (WifiPermissionUtils::VerifyGetWifiInfoInternalPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DeleteLocalP2pService:VerifyGetWifiInfoInternalPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->DeleteLocalP2pService(srvInfo);
}

ErrCode WifiP2pServiceImpl::StartP2pListen(int period, int interval)
{
    WIFI_LOGI("StartP2pListen, period %{public}d, interval %{public}d", period, interval);
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("StartP2pListen:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->StartP2pListen(period, interval);
}

ErrCode WifiP2pServiceImpl::StopP2pListen()
{
    WIFI_LOGI("StopP2pListen");
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("StopP2pListen:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->StopP2pListen();
}

ErrCode WifiP2pServiceImpl::CreateGroup(const WifiP2pConfig &config)
{
    int callingUid = GetCallingUid();
    WIFI_LOGI("Uid %{public}d createGroup, network name is [%{public}s]", callingUid, config.GetGroupName().c_str());
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("CreateGroup:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    WifiManager::GetInstance().StopGetCacResultAndLocalCac(CAC_STOP_BY_P2P_REQUEST);

    uint32_t passLen = config.GetPassphrase().length();
    if ((!config.GetPassphrase().empty()) &&
        (passLen < WIFI_P2P_PASSPHRASE_MIN_LEN || passLen > WIFI_P2P_PASSPHRASE_MAX_LEN)) {
        WIFI_LOGE("CreateGroup:VerifyPassphrase length failed!");
        return WIFI_OPT_INVALID_PARAM;
    }
    if ((!config.GetDeviceAddress().empty()) &&
        (CheckMacIsValid(config.GetDeviceAddress()) != 0)) {
        WIFI_LOGE("CreateGroup:VerifyDeviceAddress failed!");
        return WIFI_OPT_INVALID_PARAM;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->CreateGroup(config);
}

ErrCode WifiP2pServiceImpl::RemoveGroup()
{
    WIFI_LOGI("RemoveGroup");
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RemoveGroup:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    WifiP2pGroupInfo config;
    ErrCode ret = pService->GetCurrentGroup(config);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("RemoveGroup:GetCurrentGroup failed!");
        pService->RemoveGroup();
        return WIFI_OPT_FAILED;
    }
    return pService->RemoveGroup();
}

ErrCode WifiP2pServiceImpl::RemoveGroupClient(const GcInfo &info)
{
    WIFI_LOGI("RemoveGroupClient");
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("RemoveGroupClient:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->RemoveGroupClient(info);
}

ErrCode WifiP2pServiceImpl::DeleteGroup(const WifiP2pGroupInfo &group)
{
    WIFI_LOGI("DeleteGroup, group name [%{public}s]", group.GetGroupName().c_str());
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("DeleteGroup:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DeleteGroup:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DeleteGroup:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->DeleteGroup(group);
}

ErrCode WifiP2pServiceImpl::P2pConnect(const WifiP2pConfig &config)
{
    WIFI_LOGI("P2pConnect device address [%{private}s], addressType: %{public}d], "
        "pid:%{public}d, uid:%{public}d ,BundleName:%{public}s",
        config.GetDeviceAddress().c_str(), config.GetDeviceAddressType(),
        GetCallingPid(), GetCallingUid(), GetBundleName().c_str());
    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (apiVersion == API_VERSION_9) {
#ifndef SUPPORT_RANDOM_MAC_ADDR
        if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("P2pConnect:VerifyGetScanInfosPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
#endif
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("P2pConnect:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    WifiManager::GetInstance().StopGetCacResultAndLocalCac(CAC_STOP_BY_P2P_REQUEST);

    if (CheckMacIsValid(config.GetDeviceAddress()) != 0) {
        WIFI_LOGE("P2pConnect:VerifyDeviceAddress failed!");
        return WIFI_OPT_INVALID_PARAM;
    }

    uint32_t passLen = config.GetPassphrase().length();
    if (passLen != 0 && (passLen < WIFI_P2P_PASSPHRASE_MIN_LEN || passLen > WIFI_P2P_PASSPHRASE_MAX_LEN)) {
        WIFI_LOGE("P2pConnect:VerifyPassphrase failed!");
        return WIFI_OPT_INVALID_PARAM;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    WifiP2pConfig updateConfig = config;
#ifdef SUPPORT_RANDOM_MAC_ADDR
    if (MacAddress::IsValidMac(config.GetDeviceAddress())) {
        if (config.GetDeviceAddressType() > REAL_DEVICE_ADDRESS) {
            WIFI_LOGE("%{public}s: invalid bssidType:%{public}d",
                __func__, config.GetDeviceAddressType());
            return WIFI_OPT_INVALID_PARAM;
        }
        WifiMacAddrInfo macAddrInfo;
        macAddrInfo.bssid = config.GetDeviceAddress();
        macAddrInfo.bssidType = config.GetDeviceAddressType();
        std::string randomMacAddr =
            WifiConfigCenter::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO, macAddrInfo);
        if (randomMacAddr.empty()) {
            WIFI_LOGW("no record found, bssid:%{private}s, bssidType:%{public}d",
                macAddrInfo.bssid.c_str(), macAddrInfo.bssidType);
        } else {
            WIFI_LOGI("%{public}s: find the record, bssid:%{private}s, bssidType:%{public}d, randomMac:%{private}s",
                __func__, config.GetDeviceAddress().c_str(), config.GetDeviceAddressType(), randomMacAddr.c_str());
            /* random MAC address are translated into real MAC address */
            if (config.GetDeviceAddressType() == RANDOM_DEVICE_ADDRESS) {
                updateConfig.SetDeviceAddress(randomMacAddr);
                updateConfig.SetDeviceAddressType(REAL_DEVICE_ADDRESS);
                WIFI_LOGI("%{public}s: the record is updated, bssid:%{private}s, bssidType:%{public}d",
                    __func__, updateConfig.GetDeviceAddress().c_str(), updateConfig.GetDeviceAddressType());
            }
        }
    } else {
        WIFI_LOGW("invalid mac address");
    }
#endif

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    WriteP2pKpiCountHiSysEvent(static_cast<int>(P2P_CHR_EVENT::CONN_CNT));
    return pService->P2pConnect(updateConfig);
}

ErrCode WifiP2pServiceImpl::P2pCancelConnect()
{
    WIFI_LOGI("P2pCancelConnect");
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("P2pCancelConnect:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->P2pCancelConnect();
}

ErrCode WifiP2pServiceImpl::QueryP2pLinkedInfo(WifiP2pLinkedInfo &linkedInfo)
{
    WIFI_LOGI("QueryP2pLinkedInfo group owner address:%{private}s, pid: %{public}d, uid: %{public}d",
        linkedInfo.GetGroupOwnerAddress().c_str(), GetCallingPid(), GetCallingUid());
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("QueryP2pLinkedInfo:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    ErrCode ret = pService->QueryP2pLinkedInfo(linkedInfo);
    if (ret == WIFI_OPT_SUCCESS) {
        if (WifiPermissionUtils::VerifyGetWifiLocalMacPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("QueryP2pLinkedInfo:VerifyGetWifiLocalMacPermission PERMISSION_DENIED!");
            linkedInfo.SetIsGroupOwnerAddress("00.00.00.00");
        }
    }

    return ret;
}

ErrCode WifiP2pServiceImpl::GetCurrentGroup(WifiP2pGroupInfo &group)
{
    WIFI_LOGD("GetCurrentGroup pid: %{public}d, uid: %{public}d", GetCallingPid(), GetCallingUid());
    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (apiVersion == API_VERSION_9) {
#ifndef SUPPORT_RANDOM_MAC_ADDR
        if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetCurrentGroup:VerifyGetScanInfosPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
#endif
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetCurrentGroup:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    ErrCode errCode = pService->GetCurrentGroup(group);
#ifdef SUPPORT_RANDOM_MAC_ADDR
    if (WifiPermissionUtils::VerifyGetWifiPeersMacPermission() == PERMISSION_DENIED) {
        WIFI_LOGI("%{public}s: GET_WIFI_PEERS_MAC PERMISSION_DENIED", __func__);
        WifiMacAddrInfo ownMacAddrInfo;
        WifiP2pDevice owner = group.GetOwner();
        ownMacAddrInfo.bssid = owner.GetDeviceAddress();
        ownMacAddrInfo.bssidType = owner.GetDeviceAddressType();
        std::string ownRandomMacAddr =
            WifiConfigCenter::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO,
                ownMacAddrInfo);
        if (!ownRandomMacAddr.empty() && (ownMacAddrInfo.bssidType == REAL_DEVICE_ADDRESS)) {
            owner.SetDeviceAddress(ownRandomMacAddr);
            owner.SetDeviceAddressType(RANDOM_DEVICE_ADDRESS);
            group.SetOwner(owner);

            std::vector<WifiP2pDevice> vecClientDevice = group.GetClientDevices();
            for (auto iter = vecClientDevice.begin(); iter != vecClientDevice.end(); ++iter) {
                WifiMacAddrInfo clientMacAddrInfo;
                clientMacAddrInfo.bssid = iter->GetDeviceAddress();
                clientMacAddrInfo.bssidType = iter->GetDeviceAddressType();
                std::string clientRandomMacAddr =
                    WifiConfigCenter::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::P2P_CURRENT_GROUP_MACADDR_INFO,
                        clientMacAddrInfo);
                if (!clientRandomMacAddr.empty() &&
                    (clientMacAddrInfo.bssidType == REAL_DEVICE_ADDRESS)) {
                    iter->SetDeviceAddress(clientRandomMacAddr);
                    iter->SetDeviceAddressType(RANDOM_DEVICE_ADDRESS);
                    WIFI_LOGI("%{public}s: the record is updated, bssid:%{private}s, bssidType:%{public}d",
                        __func__, iter->GetDeviceAddress().c_str(), iter->GetDeviceAddressType());
                }
            }
            group.SetClientDevices(vecClientDevice);
        }
    }
#endif
    return errCode;
}

ErrCode WifiP2pServiceImpl::GetP2pEnableStatus(int &status)
{
    WIFI_LOGI("GetP2pEnableStatus");
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("GetP2pEnableStatus:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetP2pEnableStatus:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    status = WifiConfigCenter::GetInstance().GetP2pState();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pServiceImpl::GetP2pDiscoverStatus(int &status)
{
    WIFI_LOGI("GetP2pDiscoverStatus");
    if (WifiPermissionUtils::VerifyGetWifiInfoInternalPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetP2pDiscoverStatus:VerifyGetWifiInfoInternalPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->GetP2pDiscoverStatus(status);
}

ErrCode WifiP2pServiceImpl::GetP2pConnectedStatus(int &status)
{
    WIFI_LOGI("GetP2pConnectedStatus");
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("GetP2pConnectedStatus:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetP2pConnectedStatus:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->GetP2pConnectedStatus(status);
}

ErrCode WifiP2pServiceImpl::QueryP2pDevices(std::vector<WifiP2pDevice> &devices)
{
    WIFI_LOGI("QueryP2pDevices");
    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (apiVersion == API_VERSION_9) {
#ifndef SUPPORT_RANDOM_MAC_ADDR
        if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("QueryP2pDevices:VerifyGetScanInfosPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
#endif
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("QueryP2pDevices:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    ErrCode errCode = pService->QueryP2pDevices(devices);
#ifdef SUPPORT_RANDOM_MAC_ADDR
    if (WifiPermissionUtils::VerifyGetWifiPeersMacPermission() == PERMISSION_DENIED) {
        WIFI_LOGI("%{public}s: GET_WIFI_PEERS_MAC PERMISSION_DENIED, size: %{public}zu",
            __func__, devices.size());
        for (auto iter = devices.begin(); iter != devices.end(); ++iter) {
            WifiMacAddrInfo macAddrInfo;
            macAddrInfo.bssid = iter->GetDeviceAddress();
            macAddrInfo.bssidType = iter->GetDeviceAddressType();
            std::string randomMacAddr =
                WifiConfigCenter::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO,
                    macAddrInfo);
            if (!randomMacAddr.empty() &&
                (macAddrInfo.bssidType == REAL_DEVICE_ADDRESS)) {
                iter->SetDeviceAddress(randomMacAddr);
                iter->SetDeviceAddressType(RANDOM_DEVICE_ADDRESS);
                WIFI_LOGI("%{public}s: the record is updated, bssid:%{private}s, bssidType:%{public}d",
                    __func__, iter->GetDeviceAddress().c_str(), iter->GetDeviceAddressType());
            }
        }
    }
#endif
    return errCode;
}

ErrCode WifiP2pServiceImpl::QueryP2pLocalDevice(WifiP2pDevice &device)
{
    WIFI_LOGI("QueryP2pLocalDevice");

    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (apiVersion >= API_VERSION_9 && apiVersion < API_VERSION_11) {
        if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("QueryP2pLocalDevice:VerifyGetWifiConfigPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("QueryP2pLocalDevice:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not runing!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    ErrCode ret = pService->QueryP2pLocalDevice(device);
    if (WifiPermissionUtils::VerifyGetWifiLocalMacPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("QueryP2pLocalDevice:VerifyGetWifiLocalMacPermission PERMISSION_DENIED!");
        device.SetDeviceAddress("00:00:00:00:00:00");
    }
    return ret;
}

ErrCode WifiP2pServiceImpl::QueryP2pGroups(std::vector<WifiP2pGroupInfo> &groups)
{
    WIFI_LOGI("QueryP2pGroups");
    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("QueryP2pGroups:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (apiVersion == API_VERSION_9) {
#ifndef SUPPORT_RANDOM_MAC_ADDR
        if (WifiPermissionUtils::VerifyGetWifiDirectDevicePermission() == PERMISSION_DENIED) {
            WIFI_LOGE("QueryP2pGroups:VerifyGetWifiDirectDevicePermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
#endif
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("QueryP2pGroups:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    ErrCode errCode = pService->QueryP2pGroups(groups);
#ifdef SUPPORT_RANDOM_MAC_ADDR
    if (WifiPermissionUtils::VerifyGetWifiPeersMacPermission() == PERMISSION_DENIED) {
        WIFI_LOGI("%{public}s: GET_WIFI_PEERS_MAC PERMISSION_DENIED", __func__);
        for (auto group = groups.begin(); group != groups.end(); ++group) {
            WifiMacAddrInfo ownMacAddrInfo;
            WifiP2pDevice owner = group->GetOwner();
            ownMacAddrInfo.bssid = owner.GetDeviceAddress();
            ownMacAddrInfo.bssidType = owner.GetDeviceAddressType();
            std::string ownRandomMacAddr =
                WifiConfigCenter::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO,
                    ownMacAddrInfo);
            if (!ownRandomMacAddr.empty() &&
                (ownMacAddrInfo.bssidType == REAL_DEVICE_ADDRESS)) {
                owner.SetDeviceAddress(ownRandomMacAddr);
                owner.SetDeviceAddressType(RANDOM_DEVICE_ADDRESS);
                group->SetOwner(owner);

                std::vector<WifiP2pDevice> vecClientDevice = group->GetPersistentDevices();
                for (auto iter = vecClientDevice.begin(); iter != vecClientDevice.end(); ++iter) {
                    WifiMacAddrInfo clientMacAddrInfo;
                    clientMacAddrInfo.bssid = iter->GetDeviceAddress();
                    clientMacAddrInfo.bssidType = iter->GetDeviceAddressType();
                    std::string clientRandomMacAddr = WifiConfigCenter::GetInstance().GetMacAddrPairs(
                        WifiMacAddrInfoType::P2P_GROUPSINFO_MACADDR_INFO, clientMacAddrInfo);
                    if (!clientRandomMacAddr.empty() &&
                        (clientMacAddrInfo.bssidType == REAL_DEVICE_ADDRESS)) {
                        iter->SetDeviceAddress(clientRandomMacAddr);
                        iter->SetDeviceAddressType(RANDOM_DEVICE_ADDRESS);
                        WIFI_LOGI("%{public}s: the record is updated, bssid:%{private}s, bssidType:%{public}d",
                            __func__, iter->GetDeviceAddress().c_str(), iter->GetDeviceAddressType());
                    }
                }
                group->SetClientDevices(vecClientDevice);
            }
        }
    }
#endif
    return errCode;
}

ErrCode WifiP2pServiceImpl::QueryP2pServices(std::vector<WifiP2pServiceInfo> &services)
{
    WIFI_LOGI("QueryP2pServices");
    if (WifiPermissionUtils::VerifyGetWifiInfoInternalPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("QueryP2pServices:VerifyGetWifiInfoInternalPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->QueryP2pServices(services);
}

ErrCode WifiP2pServiceImpl::RegisterCallBack(const sptr<IWifiP2pCallback> &callback,
    const std::vector<std::string> &event)
{
    WIFI_LOGI("WifiP2pServiceImpl::RegisterCallBack!");
    WifiInternalEventDispatcher::GetInstance().SetSingleP2pCallback(callback);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pServiceImpl::GetSupportedFeatures(long &features)
{
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

bool WifiP2pServiceImpl::IsCallingAllowed()
{
    auto state = WifiConfigCenter::GetInstance().GetWifiDetailState();
    if (state == WifiDetailState::STATE_SEMI_ACTIVE && !WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGW("curr wifi state is semiactive, only allow system app use p2p service");
        return false;
    }
    return true;
}

bool WifiP2pServiceImpl::IsP2pServiceRunning()
{
    if (!IsCallingAllowed()) {
        return false;
    }
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetP2pMidState();
    if (curState != WifiOprMidState::RUNNING) {
        WIFI_LOGW("p2p service does not started!");
        return false;
    }
    return true;
}

ErrCode WifiP2pServiceImpl::SetP2pDeviceName(const std::string &deviceName)
{
    WIFI_LOGI("SetP2pDeviceName:%{private}s", deviceName.c_str());
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("SetP2pDeviceName:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetP2pDeviceName:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetP2pDeviceName:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    uint32_t length = deviceName.length();
    if (length > DEVICE_NAME_LENGTH || length < 0) {
        return WIFI_OPT_INVALID_PARAM;
    }
    WifiSettings::GetInstance().SetP2pDeviceName(deviceName);
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_SUCCESS;
    }
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->SetP2pDeviceName(deviceName);
}

ErrCode WifiP2pServiceImpl::SetP2pWfdInfo(const WifiP2pWfdInfo &wfdInfo)
{
    WIFI_LOGI("SetP2pWfdInfo");
    if (WifiPermissionUtils::VerifyGetWifiInfoInternalPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetP2pWfdInfo:VerifyGetWifiInfoInternalPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->SetP2pWfdInfo(wfdInfo);
}

ErrCode WifiP2pServiceImpl::Hid2dRequestGcIp(const std::string& gcMac, std::string& ipAddr)
{
    WIFI_LOGI("Hid2dRequestGcIp");
    int callingUid = GetCallingUid();
    if (callingUid != SOFT_BUS_SERVICE_UID) {
        WIFI_LOGE("%{public}s, permission denied! uid = %{public}d", __func__, callingUid);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("Hid2dRequestGcIp:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not runing!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->Hid2dRequestGcIp(gcMac, ipAddr);
}

ErrCode WifiP2pServiceImpl::Hid2dSharedlinkIncrease()
{
    int callingUid = GetCallingUid();
    WIFI_LOGI("Uid %{public}d Hid2dSharedlinkIncrease", callingUid);
    if (callingUid != SOFT_BUS_SERVICE_UID) {
        WIFI_LOGE("%{public}s, permission denied! uid = %{public}d", __func__, callingUid);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("Hid2dSharedlinkIncrease:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    int status = static_cast<int>(P2pConnectedState::P2P_DISCONNECTED);
    ErrCode ret = GetP2pConnectedStatus(status);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGI("Hid2dSharedlinkIncrease get P2P connect status error!");
        return ret;
    }
    if (status != static_cast<int>(P2pConnectedState::P2P_CONNECTED)) {
        WIFI_LOGE("Hid2dSharedlinkIncrease P2P not in connected state!");
        return WIFI_OPT_FAILED;
    }
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_FAILED;
    }
    pService->IncreaseSharedLink(callingUid);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pServiceImpl::Hid2dSharedlinkDecrease()
{
    int callingUid = GetCallingUid();
    WIFI_LOGI("Uid %{public}d Hid2dSharedlinkDecrease", callingUid);
    if (callingUid != SOFT_BUS_SERVICE_UID) {
        WIFI_LOGE("%{public}s, permission denied! uid = %{public}d", __func__, callingUid);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("Hid2dSharedlinkDecrease:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not runing!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    pService->DecreaseSharedLink(callingUid);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pServiceImpl::Hid2dCreateGroup(const int frequency, FreqType type)
{
    int callingUid = GetCallingUid();
    WIFI_LOGI("Uid %{public}d Hid2dCreateGroup", callingUid);
    if (callingUid != SOFT_BUS_SERVICE_UID) {
        WIFI_LOGE("%{public}s, permission denied! uid = %{public}d", __func__, callingUid);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("CreateGroup:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    WifiManager::GetInstance().StopGetCacResultAndLocalCac(CAC_STOP_BY_HID2D_REQUEST);

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    WifiConfigCenter::GetInstance().SetP2pBusinessType(P2pBusinessType::P2P_TYPE_HID2D);
    return pService->Hid2dCreateGroup(frequency, type);
}

ErrCode WifiP2pServiceImpl::Hid2dRemoveGcGroup(const std::string& gcIfName)
{
    WIFI_LOGI("Hid2dRemoveGcGroup:, gcIfName: %{public}s", gcIfName.c_str());
    // TO Imple: delete by interface
    int callingUid = GetCallingUid();
    if (callingUid != SOFT_BUS_SERVICE_UID) {
        WIFI_LOGE("%{public}s, permission denied! uid = %{public}d", __func__, callingUid);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    return RemoveGroup();
}

ErrCode WifiP2pServiceImpl::Hid2dConnect(const Hid2dConnectConfig& config)
{
    int callingUid = GetCallingUid();
    WIFI_LOGI("Uid %{public}d Hid2dConnect", callingUid);
    if (callingUid != SOFT_BUS_SERVICE_UID) {
        WIFI_LOGE("%{public}s, permission denied! uid = %{public}d", __func__, callingUid);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifyGetWifiDirectDevicePermission() == PERMISSION_DENIED) {
        WIFI_LOGE("Hid2dConnect:VerifyGetWifiDirectDevicePermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    WifiManager::GetInstance().StopGetCacResultAndLocalCac(CAC_STOP_BY_HID2D_REQUEST);

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    WifiConfigCenter::GetInstance().SetP2pBusinessType(P2pBusinessType::P2P_TYPE_HID2D);
    WriteP2pKpiCountHiSysEvent(static_cast<int>(P2P_CHR_EVENT::MAGICLINK_CNT));
    return pService->Hid2dConnect(config);
}

ErrCode WifiP2pServiceImpl::Hid2dConfigIPAddr(const std::string& ifName, const IpAddrInfo& ipInfo)
{
    WIFI_LOGI("Hid2dConfigIPAddr, ifName: %{public}s", ifName.c_str());
    int callingUid = GetCallingUid();
    if (callingUid != SOFT_BUS_SERVICE_UID) {
        WIFI_LOGE("%{public}s, permission denied! uid = %{public}d", __func__, callingUid);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("Hid2dConfigIPAddr:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    IfConfig::GetInstance().AddIpAddr(ifName, ipInfo.ip, ipInfo.netmask, IpType::IPTYPE_IPV4);
    WifiNetAgent::GetInstance().AddRoute(ifName, ipInfo.ip, IpTools::GetMaskLength(ipInfo.netmask));
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    ErrCode ret = pService->SetGcIpAddress(ipInfo);
    return ret;
}

ErrCode WifiP2pServiceImpl::Hid2dReleaseIPAddr(const std::string& ifName)
{
    WIFI_LOGI("Hid2dReleaseIPAddr");
    int callingUid = GetCallingUid();
    if (callingUid != SOFT_BUS_SERVICE_UID) {
        WIFI_LOGE("%{public}s, permission denied! uid = %{public}d", __func__, callingUid);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("Hid2dReleaseIPAddr:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    IfConfig::GetInstance().FlushIpAddr(ifName, IpType::IPTYPE_IPV4);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pServiceImpl::Hid2dGetRecommendChannel(const RecommendChannelRequest& request,
    RecommendChannelResponse& response)
{
    WIFI_LOGI("Hid2dGetRecommendChannel");
    int callingUid = GetCallingUid();
    if (callingUid != SOFT_BUS_SERVICE_UID) {
        WIFI_LOGE("%{public}s, permission denied! uid = %{public}d", __func__, callingUid);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("Hid2dGetRecommendChannel:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    WifiManager::GetInstance().StopGetCacResultAndLocalCac(CAC_STOP_BY_HID2D_REQUEST);

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not runing!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    int channel = pService->GetP2pRecommendChannel();
    int freq = ChannelToFrequency(channel);
    WIFI_LOGI("Get recommended channel: %{public}d, freq: %{public}d", channel, freq);
    if (channel == 0) {
        WriteP2pKpiCountHiSysEvent(static_cast<int>(P2P_CHR_EVENT::P2P_SUC_2G4_CNT));
    } else {
        WriteP2pKpiCountHiSysEvent(static_cast<int>(P2P_CHR_EVENT::P2P_SUC_5G_CNT));
    }
    response.centerFreq = freq;
    response.status = RecommendStatus::RS_SUCCESS;
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pServiceImpl::Hid2dGetChannelListFor5G(std::vector<int>& vecChannelList)
{
    WIFI_LOGI("Hid2dGetChannelListFor5G");
    int callingUid = GetCallingUid();
    if (callingUid != SOFT_BUS_SERVICE_UID) {
        WIFI_LOGE("%{public}s, permission denied! uid = %{public}d", __func__, callingUid);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("Hid2dGetChannelListFor5G:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    ChannelsTable channels;
    WifiChannelHelper::GetInstance().GetValidChannels(channels);
    if (channels.find(BandType::BAND_5GHZ) != channels.end()) {
        vecChannelList = channels[BandType::BAND_5GHZ];
    }

    if (vecChannelList.size() == 0) {
        std::vector<int> tempFrequenciesList;
        WifiSettings::GetInstance().SetDefaultFrequenciesByCountryBand(BandType::BAND_5GHZ, tempFrequenciesList);
        TransformFrequencyIntoChannel(tempFrequenciesList, vecChannelList);
    }
    std::string strChannel;
    for (auto channel : vecChannelList) {
        strChannel += std::to_string(channel) + ",";
    }
    WIFI_LOGI("5G channel list[%{public}d]: %{public}s",
        (int)vecChannelList.size(), strChannel.c_str());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pServiceImpl::Hid2dGetSelfWifiCfgInfo(SelfCfgType cfgType,
    char cfgData[CFG_DATA_MAX_BYTES], int* getDatValidLen)
{
    WIFI_LOGI("Hid2dGetSelfWifiCfgInfo");
    int callingUid = GetCallingUid();
    if (callingUid != SOFT_BUS_SERVICE_UID) {
        WIFI_LOGE("%{public}s, permission denied! uid = %{public}d", __func__, callingUid);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("Hid2dGetSelfWifiCfgInfo:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not runing!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("Get pEnhanceService service failed!");
        *getDatValidLen = 0;
        return WIFI_OPT_GET_ENHANCE_SVC_FAILED;
    }

    if (pEnhanceService->Hid2dGetSelfWifiCfgInfo(cfgType, cfgData, getDatValidLen) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Hid2dGetSelfWifiCfgInfo failed");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pServiceImpl::Hid2dSetPeerWifiCfgInfo(PeerCfgType cfgType,
    char cfgData[CFG_DATA_MAX_BYTES], int setDataValidLen)
{
    WIFI_LOGI("Hid2dSetPeerWifiCfgInfo");
    int callingUid = GetCallingUid();
    if (callingUid != SOFT_BUS_SERVICE_UID) {
        WIFI_LOGE("%{public}s, permission denied! uid = %{public}d", __func__, callingUid);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("Hid2dSetPeerWifiCfgInfo:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not runing!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("Get pEnhanceService service failed!");
        return WIFI_OPT_GET_ENHANCE_SVC_FAILED;
    }

    if (pEnhanceService->Hid2dSetPeerWifiCfgInfo(cfgType, cfgData, setDataValidLen) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Hid2dSetPeerWifiCfgInfo failed");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pServiceImpl::Hid2dSetUpperScene(const std::string& ifName, const Hid2dUpperScene& scene)
{
    WIFI_LOGI("Hid2dSetUpperScene");
    int callingUid = GetCallingUid();
    if (callingUid != SOFT_BUS_SERVICE_UID && callingUid != CAST_ENGINE_SERVICE_UID &&
        callingUid != MIRACAST_SERVICE_UID && callingUid != SHARE_SERVICE_UID &&
        callingUid != MOUSE_CROSS_SERVICE_UID) {
        WIFI_LOGE("%{public}s, permission denied! uid = %{public}d", __func__, callingUid);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("Hid2dSetUpperScene:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not runing!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    WifiConfigCenter::GetInstance().SetHid2dUpperScene(callingUid, scene);
    return pService->Hid2dSetUpperScene(ifName, scene);
}

ErrCode WifiP2pServiceImpl::MonitorCfgChange(void)
{
    WIFI_LOGI("MonitorCfgChange");
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not runing!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->MonitorCfgChange();
}

void WifiP2pServiceImpl::SaBasicDump(std::string& result)
{
    result.append("P2P enable status: ");
    int status = WifiConfigCenter::GetInstance().GetP2pState();
    std::string strStatus = (status == static_cast<int>(P2pState::P2P_STATE_STARTED)) ? "enable" : "disable";
    result.append(strStatus);
    result += "\n";
}

int32_t WifiP2pServiceImpl::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    WIFI_LOGI("Enter p2p dump func.");
    std::vector<std::string> vecArgs;
    std::transform(args.begin(), args.end(), std::back_inserter(vecArgs), [](const std::u16string &arg) {
        return Str16ToStr8(arg);
    });

    WifiDumper dumper;
    std::string result;
    dumper.P2pDump(SaBasicDump, vecArgs, result);
    if (!SaveStringToFd(fd, result)) {
        WIFI_LOGE("WiFi P2p save string to fd failed.");
        return ERR_OK;
    }
    return ERR_OK;
}

ErrCode WifiP2pServiceImpl::DiscoverPeers(int32_t channelid)
{
    WIFI_LOGE("DiscoverPeers");
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DiscoverPeers:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->DiscoverPeers(channelid);
}

ErrCode WifiP2pServiceImpl::DisableRandomMac(int setmode)
{
    WIFI_LOGE("DisableRandomMac");
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("DisableRandomMac:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsP2pServiceRunning()) {
        WIFI_LOGE("P2pService is not running!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }

    IP2pService *pService = WifiServiceManager::GetInstance().GetP2pServiceInst();
    if (pService == nullptr) {
        WIFI_LOGE("Get P2P service failed!");
        return WIFI_OPT_P2P_NOT_OPENED;
    }
    return pService->DisableRandomMac(setmode);
}

ErrCode WifiP2pServiceImpl::CheckCanUseP2p()
{
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("CheckCanUseP2p: VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (WifiManager::GetInstance().GetWifiMultiVapManager() == nullptr) {
        WIFI_LOGE("CheckCanUseP2p: WifiMultiVapManager is nullptr!");
        return WIFI_OPT_FAILED;
    }

    return ((WifiManager::GetInstance().GetWifiMultiVapManager()->CheckCanUseP2p()) ? WIFI_OPT_SUCCESS
        : WIFI_OPT_NOT_SUPPORTED);
}

bool WifiP2pServiceImpl::IsRemoteDied(void)
{
    return false;
}

ErrCode WifiP2pServiceImpl::Hid2dIsWideBandwidthSupported(bool &isSupport)
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("Hid2dIsWideBandwidthSupported:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("Hid2dIsWideBandwidthSupported get pEnhanceService service failed!");
        return WIFI_OPT_GET_ENHANCE_SVC_FAILED;
    }

    isSupport = pEnhanceService->IsWideBandwidthSupported();
    if (!isSupport) {
        WIFI_LOGE("Hid2dIsWideBandwidthSupported IsWideBandwidthSupported is false");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS
