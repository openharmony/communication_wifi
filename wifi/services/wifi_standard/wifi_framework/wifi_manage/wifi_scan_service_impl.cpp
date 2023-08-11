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

#include "wifi_scan_service_impl.h"
#ifndef OHOS_ARCH_LITE
#include <file_ex.h>
#endif
#include "define.h"
#include "permission_def.h"
#include "wifi_auth_center.h"
#include "wifi_config_center.h"
#include "wifi_dumper.h"
#ifdef OHOS_ARCH_LITE
#include "wifi_internal_event_dispatcher_lite.h"
#else
#include "wifi_internal_event_dispatcher.h"
#endif
#include "wifi_internal_msg.h"
#include "wifi_logger.h"
#include "wifi_manager.h"
#include "wifi_msg.h"
#include "wifi_permission_utils.h"
#include "wifi_scan_callback_proxy.h"
#include "wifi_service_manager.h"
#include "wifi_sta_hal_interface.h"

DEFINE_WIFILOG_SCAN_LABEL("WifiScanServiceImpl");
namespace OHOS {
namespace Wifi {
std::mutex WifiScanServiceImpl::g_instanceLock;
#ifdef OHOS_ARCH_LITE
std::shared_ptr<WifiScanServiceImpl> WifiScanServiceImpl::g_instance;
std::shared_ptr<WifiScanServiceImpl> WifiScanServiceImpl::GetInstance()
#else
sptr<WifiScanServiceImpl> WifiScanServiceImpl::g_instance;
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(WifiScanServiceImpl::GetInstance().GetRefPtr());
sptr<WifiScanServiceImpl> WifiScanServiceImpl::GetInstance()
#endif
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
#ifdef OHOS_ARCH_LITE
            std::shared_ptr<WifiScanServiceImpl> service = std::make_shared<WifiScanServiceImpl>();
#else
            sptr<WifiScanServiceImpl> service = new (std::nothrow) WifiScanServiceImpl;
#endif
            g_instance = service;
        }
    }
    return g_instance;
}

WifiScanServiceImpl::WifiScanServiceImpl()
#ifdef OHOS_ARCH_LITE
    : mPublishFlag(false), mState(ServiceRunningState::STATE_NOT_START)
#else
    : SystemAbility(WIFI_SCAN_ABILITY_ID, true), mPublishFlag(false), mState(ServiceRunningState::STATE_NOT_START)
#endif
{}

WifiScanServiceImpl::~WifiScanServiceImpl()
{}

void WifiScanServiceImpl::OnStart()
{
    if (mState == ServiceRunningState::STATE_RUNNING) {
        WIFI_LOGW("Service has already started.");
        return;
    }
    if (!Init()) {
        WIFI_LOGE("Failed to init service");
        OnStop();
        return;
    }
    mState = ServiceRunningState::STATE_RUNNING;
    WIFI_LOGI("Start scan service!");
    WifiManager::GetInstance();
    WifiOprMidState scanState = WifiConfigCenter::GetInstance().GetScanMidState();
    if (scanState == WifiOprMidState::CLOSED) {
        WifiManager::GetInstance().StartUnloadScanSaTimer();
    }
}

void WifiScanServiceImpl::OnStop()
{
    mState = ServiceRunningState::STATE_NOT_START;
    mPublishFlag = false;
    WIFI_LOGI("Stop scan service!");
}

bool WifiScanServiceImpl::Init()
{
    if (!mPublishFlag) {
#ifdef OHOS_ARCH_LITE
        bool ret = true;
#else
        bool ret = Publish(WifiScanServiceImpl::GetInstance());
#endif
        if (!ret) {
            WIFI_LOGE("Failed to publish scan service!");
            return false;
        }
        mPublishFlag = true;
    }
    return true;
}

ErrCode WifiScanServiceImpl::SetScanControlInfo(const ScanControlInfo &info)
{
    WIFI_LOGI("WifiScanServiceImpl::SetScanControlInfo");
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetScanControlInfo:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().SetScanControlInfo(info);
    if (IsScanServiceRunning()) {
        IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst();
        if (pService == nullptr) {
            return WIFI_OPT_SCAN_NOT_OPENED;
        }
        return pService->OnControlStrategyChanged();
    }

    return WIFI_OPT_SUCCESS;
}

ErrCode WifiScanServiceImpl::Scan()
{
    WIFI_LOGI("Scan");
    if (WifiPermissionUtils::VerifyGetWifiInfoInternalPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("Scan:VerifyGetWifiInfoInternalPermission PERMISSION_DENIED!");

        if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("Scan:VerifySetWifiInfoPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
    #ifndef SUPPORT_RANDOM_MAC_ADDR
        if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("Scan:VerifyGetScanInfosPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
    #endif
    }

    if (!IsScanServiceRunning()) {
        return WIFI_OPT_SCAN_NOT_OPENED;
    }

    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst();
    if (pService == nullptr) {
        return WIFI_OPT_SCAN_NOT_OPENED;
    }
    ErrCode ret = pService->Scan(true);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Scan failed: %{public}d!", static_cast<int>(ret));
    }
    return ret;
}

ErrCode WifiScanServiceImpl::AdvanceScan(const WifiScanParams &params)
{
    WIFI_LOGI("Scan with WifiScanParams, band %{public}u", params.band);
    if (WifiPermissionUtils::VerifyGetWifiInfoInternalPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("AdvanceScan:VerifyGetWifiInfoInternalPermission PERMISSION_DENIED!");

        if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("AdvanceScan:VerifySetWifiInfoPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }

        if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("AdvanceScan:VerifyGetScanInfosPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
    }

    if (!IsScanServiceRunning()) {
        return WIFI_OPT_SCAN_NOT_OPENED;
    }

    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst();
    if (pService == nullptr) {
        return WIFI_OPT_SCAN_NOT_OPENED;
    }
    return pService->ScanWithParam(params);
}

ErrCode WifiScanServiceImpl::IsWifiClosedScan(bool &bOpen)
{
    WIFI_LOGI("IsWifiClosedScan");
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsWifiClosedScan:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    bOpen = WifiConfigCenter::GetInstance().IsScanAlwaysActive();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiScanServiceImpl::GetScanInfoList(std::vector<WifiScanInfo> &result)
{
    WIFI_LOGI("GetScanInfoList");

    if (WifiPermissionUtils::VerifyGetWifiInfoInternalPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetScanInfoList:VerifyGetWifiInfoInternalPermission PERMISSION_DENIED!");
        if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetScanInfoList:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
    #ifndef SUPPORT_RANDOM_MAC_ADDR
        if ((WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) &&
            (WifiPermissionUtils::VerifyGetWifiPeersMacPermission() == PERMISSION_DENIED)) {
            WIFI_LOGE("GetScanInfoList:GET_WIFI_PEERS_MAC && LOCATION PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
    #endif
    }

    WifiConfigCenter::GetInstance().GetScanInfoList(result);
#ifdef SUPPORT_RANDOM_MAC_ADDR
    if (WifiPermissionUtils::VerifyGetWifiPeersMacPermission() == PERMISSION_DENIED) {
        WIFI_LOGI("GetScanInfoList: GET_WIFI_PEERS_MAC PERMISSION_DENIED");
        for (auto iter = result.begin(); iter != result.end(); ++iter) {
            WifiMacAddrInfo macAddrInfo;
            macAddrInfo.bssid = iter->bssid;
            macAddrInfo.bssidType = iter->bssidType;
            std::string randomMacAddr =
                WifiSettings::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO, macAddrInfo);
            WIFI_LOGI("bssid:%{private}s, bssidType:%{public}d, randomMacAddr:%{private}s",
                macAddrInfo.bssid.c_str(), macAddrInfo.bssidType, randomMacAddr.c_str());
            if (!randomMacAddr.empty() &&
                (macAddrInfo.bssidType == REAL_DEVICE_ADDRESS)) {
                iter->bssid = randomMacAddr;
                iter->bssidType = RANDOM_DEVICE_ADDRESS;
            }
        }
    }
#endif
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiScanServiceImpl::SetScanOnlyAvailable(bool bScanOnlyAvailable)
{
    WIFI_LOGD("WifiScanServiceImpl::SetScanOnlyAvailable");
    if (!WifiAuthCenter::IsSystemAppByToken()) {
        WIFI_LOGE("SetScanOnlyAvailable:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetScanOnlyAvailable:VerifySetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetScanOnlyAvailable:VerifySetWifiConfigPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    WifiSettings::GetInstance().SetScanOnlySwitchState(bScanOnlyAvailable);
    if (bScanOnlyAvailable) {
        OpenScanOnlyAvailable();
    } else {
        CloseScanOnlyAvailable();
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiScanServiceImpl::GetScanOnlyAvailable(bool &bScanOnlyAvailable)
{
    WIFI_LOGD("WifiScanServiceImpl::GetScanOnlyAvailable");
    if (!WifiAuthCenter::IsSystemAppByToken()) {
        WIFI_LOGE("GetScanOnlyAvailable: NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetScanOnlyAvailable:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetScanOnlyAvailable:VerifySetWifiConfigPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    bScanOnlyAvailable = WifiSettings::GetInstance().GetScanOnlySwitchState();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiScanServiceImpl::OpenScanOnlyAvailable()
{
    WIFI_LOGI("WifiScanServiceImpl OpenScanOnlyAvailable");
    if (!WifiSettings::GetInstance().CheckScanOnlyAvailable() ||
        !WifiManager::GetInstance().GetLocationModeByDatashare(WIFI_SCAN_ABILITY_ID)) {
        return WIFI_OPT_FAILED;
    }
   
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState();
    WIFI_LOGI("current wifi scan only state is %{public}d", static_cast<int>(curState));
    if (curState != WifiOprMidState::CLOSED) {
        if (curState == WifiOprMidState::CLOSING) { /* when current wifi is closing, return */
            return WIFI_OPT_FAILED;
        } else {
            return WIFI_OPT_SUCCESS;
        }
    }

    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiMidState()) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING);
        return WIFI_OPT_SUCCESS;
    }
    
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::OPENING);
    WifiManager::GetInstance().CheckAndStartScanService();
    int res = WifiStaHalInterface::GetInstance().StartWifi();
    if (res != static_cast<int>(WIFI_IDL_OPT_OK)) {
        WIFI_LOGE("Start Wpa failed");
        return WIFI_OPT_FAILED;
    }
    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst();
    if (pService == nullptr) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED);
        return WIFI_OPT_FAILED;
    }
    ErrCode ret = pService->OpenScanOnly();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED);
        return WIFI_OPT_FAILED;
    }
    WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::RUNNING);

    return WIFI_OPT_SUCCESS;
}

ErrCode WifiScanServiceImpl::CloseScanOnlyAvailable()
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetWifiScanOnlyMidState();
    WIFI_LOGI("current wifi scan only state is %{public}d", static_cast<int>(curState));
    if (curState != WifiOprMidState::RUNNING) {
        if (curState == WifiOprMidState::OPENING) { /* when current wifi is opening, return */
            return WIFI_OPT_FAILED;
        } else {
            return WIFI_OPT_SUCCESS;
        }
    }
    
    if (WifiOprMidState::RUNNING == WifiConfigCenter::GetInstance().GetWifiMidState()) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED);
        return WIFI_OPT_SUCCESS;
    }

    if (!WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(curState, WifiOprMidState::CLOSING)) {
        WIFI_LOGI("set wifi scan only mid state opening failed!");
        return WIFI_OPT_FAILED;
    }
    
    int res = WifiStaHalInterface::GetInstance().StopWifi();
    if (res != static_cast<int>(WIFI_IDL_OPT_OK)) {
        WIFI_LOGE("Stop Wpa failed");
    }
    
    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst();
    if (pService == nullptr) {
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED);
        return WIFI_OPT_SUCCESS;
    }

    ErrCode ret = pService->CloseScanOnly();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGI("set wifi scan only mid state RUNNING");
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::UNKNOWN);
    } else {
        WIFI_LOGI("set wifi scan only mid state closed");
        WifiConfigCenter::GetInstance().SetWifiScanOnlyMidState(WifiOprMidState::CLOSED);
    }

    return WIFI_OPT_SUCCESS;
}

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::RegisterCallBack(const std::shared_ptr<IWifiScanCallback> &callback,
    const std::vector<std::string> &event)
#else
ErrCode WifiScanServiceImpl::RegisterCallBack(const sptr<IWifiScanCallback> &callback,
    const std::vector<std::string> &event)
#endif
{
    WIFI_LOGI("WifiScanServiceImpl::RegisterCallBack!");
    for (const auto &eventName : event) {
        WifiInternalEventDispatcher::GetInstance().SetSingleScanCallback(callback, eventName);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiScanServiceImpl::GetSupportedFeatures(long &features)
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

bool WifiScanServiceImpl::IsScanServiceRunning()
{
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetScanMidState();
    if (curState != WifiOprMidState::RUNNING) {
        WIFI_LOGW("scan service does not started!");
        return false;
    }
    return true;
}

void WifiScanServiceImpl::SaBasicDump(std::string& result)
{
    WifiScanServiceImpl impl;
    bool isRunning = impl.IsScanServiceRunning();
    result.append("Is scan service running: ");
    std::string strRunning = isRunning ? "true" : "false";
    result += strRunning + "\n";
}

#ifndef OHOS_ARCH_LITE
int32_t WifiScanServiceImpl::Dump(int32_t fd, const std::vector<std::u16string>& args)
{
    WIFI_LOGI("Enter scan dump func.");
    std::vector<std::string> vecArgs;
    std::transform(args.begin(), args.end(), std::back_inserter(vecArgs), [](const std::u16string &arg) {
        return Str16ToStr8(arg);
    });

    WifiDumper dumper;
    std::string result;
    dumper.ScanDump(SaBasicDump, vecArgs, result);
    if (!SaveStringToFd(fd, result)) {
        WIFI_LOGE("WiFi scan save string to fd failed.");
        return ERR_OK;
    }
    return ERR_OK;
}
#endif

bool WifiScanServiceImpl::IsRemoteDied(void)
{
    return false;
}
}  // namespace Wifi
}  // namespace OHOS
