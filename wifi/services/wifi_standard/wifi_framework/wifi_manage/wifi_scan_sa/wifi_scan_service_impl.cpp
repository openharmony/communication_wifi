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
#include "define.h"
#include "wifi_auth_center.h"
#include "wifi_config_center.h"
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
#include "wifi_common_util.h"
#include "wifi_hisysevent.h"

DEFINE_WIFILOG_SCAN_LABEL("WifiScanServiceImpl");
namespace OHOS {
namespace Wifi {

#ifdef OHOS_ARCH_LITE
std::mutex WifiScanServiceImpl::g_instanceLock;
std::shared_ptr<WifiScanServiceImpl> WifiScanServiceImpl::g_instance = nullptr;
std::shared_ptr<WifiScanServiceImpl> WifiScanServiceImpl::GetInstance()
{
    if (g_instance == nullptr) {
        std::lock_guard<std::mutex> autoLock(g_instanceLock);
        if (g_instance == nullptr) {
            std::shared_ptr<WifiScanServiceImpl> service = std::make_shared<WifiScanServiceImpl>();
            g_instance = service;
        }
    }
    return g_instance;
}

void WifiScanServiceImpl::OnStart()
{
    if (mState == ServiceRunningState::STATE_RUNNING) {
        WIFI_LOGW("Service has already started.");
        return;
    }

    WifiManager::GetInstance();
    mState = ServiceRunningState::STATE_RUNNING;
    WIFI_LOGI("Start scan service!");
}

void WifiScanServiceImpl::OnStop()
{
    mState = ServiceRunningState::STATE_NOT_START;
    WIFI_LOGI("Stop scan service!");
}
#endif


WifiScanServiceImpl::WifiScanServiceImpl()
#ifdef OHOS_ARCH_LITE
    : mState(ServiceRunningState::STATE_NOT_START)
#endif
{}

#ifndef OHOS_ARCH_LITE
WifiScanServiceImpl::WifiScanServiceImpl(int instId) : WifiScanStub(instId)
{}
#endif

WifiScanServiceImpl::~WifiScanServiceImpl()
{}

ErrCode WifiScanServiceImpl::SetScanControlInfo(const ScanControlInfo &info)
{
    WIFI_LOGI("WifiScanServiceImpl::SetScanControlInfo");
    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetScanControlInfo:VerifySetWifiConfigPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetScanControlInfo:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    WifiConfigCenter::GetInstance().SetScanControlInfo(info, m_instId);
    if (IsScanServiceRunning()) {
        IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(m_instId);
        if (pService == nullptr) {
            return WIFI_OPT_SCAN_NOT_OPENED;
        }
        return pService->OnControlStrategyChanged();
    }

    return WIFI_OPT_SUCCESS;
}

ErrCode WifiScanServiceImpl::Scan(bool compatible)
{
    WIFI_LOGI("Scan, compatible:%{public}d", compatible);
    if (WifiPermissionUtils::VerifyGetWifiInfoInternalPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("Scan:VerifyGetWifiInfoInternalPermission PERMISSION_DENIED!");
        if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("Scan:VerifySetWifiInfoPermission PERMISSION_DENIED!");
#ifndef OHOS_ARCH_LITE
            WriteWifiScanApiFailHiSysEvent(GetBundleName(), -1);
#endif
            return WIFI_OPT_PERMISSION_DENIED;
        }
        if (compatible) {
            if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
                WIFI_LOGE("Scan:VerifyGetScanInfosPermission PERMISSION_DENIED!");
#ifndef OHOS_ARCH_LITE
                WriteWifiScanApiFailHiSysEvent(GetBundleName(), -1);
#endif
                return WIFI_OPT_PERMISSION_DENIED;
            }
        } else {
            if (!WifiAuthCenter::IsSystemAppByToken()) {
                WIFI_LOGE("Scan:NOT System APP, PERMISSION_DENIED!");
#ifndef OHOS_ARCH_LITE
                WriteWifiScanApiFailHiSysEvent(GetBundleName(), -1);
#endif
                return WIFI_OPT_NON_SYSTEMAPP;
            }
            if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
                WIFI_LOGE("Scan:VerifyGetScanInfosPermission PERMISSION_DENIED!");
#ifndef OHOS_ARCH_LITE
                WriteWifiScanApiFailHiSysEvent(GetBundleName(), -1);
#endif
                return WIFI_OPT_PERMISSION_DENIED;
            }
        }
    }
    
    if (!IsScanServiceRunning()) {
#ifndef OHOS_ARCH_LITE
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), -1);
#endif
        return WIFI_OPT_SCAN_NOT_OPENED;
    }

#ifndef OHOS_ARCH_LITE
    UpdateScanMode();
#endif
    return PermissionVerification();
}

ErrCode WifiScanServiceImpl::PermissionVerification()
{
    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(m_instId);
    if (pService == nullptr) {
#ifndef OHOS_ARCH_LITE
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), -1);
#endif
        return WIFI_OPT_SCAN_NOT_OPENED;
    }

    bool externFlag = true;
#ifndef OHOS_ARCH_LITE
    if (WifiAuthCenter::IsNativeProcess()) {
        externFlag = false;
        WIFI_LOGI("Scan: native process start scan !");
    }
#endif
    ErrCode ret = pService->Scan(externFlag);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Scan failed: %{public}d!", static_cast<int>(ret));
#ifndef OHOS_ARCH_LITE
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), -1);
#endif
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

#ifndef OHOS_ARCH_LITE
    UpdateScanMode();
#endif
    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(m_instId);
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

ErrCode WifiScanServiceImpl::GetScanInfoList(std::vector<WifiScanInfo> &result, bool compatible)
{
    WIFI_LOGI("GetScanInfoList, compatible:%{public}d", compatible);

    if (WifiPermissionUtils::VerifyGetWifiInfoInternalPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetScanInfoList:VerifyGetWifiInfoInternalPermission PERMISSION_DENIED!");
        if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("GetScanInfoList:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
        if (compatible) {
            if ((WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) &&
                (WifiPermissionUtils::VerifyGetWifiPeersMacPermission() == PERMISSION_DENIED)) {
                WIFI_LOGE("GetScanInfoList:GET_WIFI_PEERS_MAC && LOCATION PERMISSION_DENIED!");
                return WIFI_OPT_PERMISSION_DENIED;
            }
        }
    }

    WifiConfigCenter::GetInstance().GetScanInfoList(result);
    if (!compatible) {
    #ifdef SUPPORT_RANDOM_MAC_ADDR
        if (WifiPermissionUtils::VerifyGetWifiPeersMacPermission() == PERMISSION_DENIED) {
            WIFI_LOGI("GetScanInfoList: GET_WIFI_PEERS_MAC PERMISSION_DENIED");
            for (auto iter = result.begin(); iter != result.end(); ++iter) {
                WifiMacAddrInfo macAddrInfo;
                macAddrInfo.bssid = iter->bssid;
                macAddrInfo.bssidType = iter->bssidType;
                std::string randomMacAddr =
                    WifiSettings::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO,
                        macAddrInfo);
                WIFI_LOGD("ssid:%{private}s, bssid:%{private}s, bssidType:%{public}d, randomMacAddr:%{private}s",
                    iter->ssid.c_str(), macAddrInfo.bssid.c_str(), macAddrInfo.bssidType, randomMacAddr.c_str());
                if (!randomMacAddr.empty() &&
                    (macAddrInfo.bssidType == REAL_DEVICE_ADDRESS)) {
                    iter->bssid = randomMacAddr;
                    iter->bssidType = RANDOM_DEVICE_ADDRESS;
                }
            }
        }
    #endif
    }
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
    WifiSettings::GetInstance().SetScanOnlySwitchState(bScanOnlyAvailable, m_instId);
    ErrCode errCode = WIFI_OPT_SUCCESS;
    if (bScanOnlyAvailable) {
        errCode = WifiManager::GetInstance().GetWifiTogglerManager()->ScanOnlyToggled(1);
    } else {
        errCode = WifiManager::GetInstance().GetWifiTogglerManager()->ScanOnlyToggled(0);
    }
    return errCode;
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

    bScanOnlyAvailable = WifiSettings::GetInstance().GetScanOnlySwitchState(m_instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiScanServiceImpl::StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason)
{
    WIFI_LOGD("WifiScanServiceImpl::StartWifiPnoScan");
    if (!WifiAuthCenter::IsNativeProcess()) {
        WIFI_LOGE("StartWifiPnoScan:NOT NATIVE PROCESS, PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(m_instId);
    if (pService == nullptr) {
        return WIFI_OPT_SCAN_NOT_OPENED;
    }
    return pService->StartWifiPnoScan(isStartAction, periodMs, suspendReason);
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
        WifiInternalEventDispatcher::GetInstance().SetSingleScanCallback(callback, eventName, m_instId);
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
    WifiOprMidState curState = WifiConfigCenter::GetInstance().GetScanMidState(m_instId);
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

bool WifiScanServiceImpl::IsRemoteDied(void)
{
    return false;
}

#ifndef OHOS_ARCH_LITE
void WifiScanServiceImpl::UpdateScanMode()
{
    int uid = GetCallingUid();
    if (WifiAppStateAware::GetInstance().IsForegroundApp(uid)) {
            WifiSettings::GetInstance().SetAppRunningState(ScanMode::APP_FOREGROUND_SCAN);
        } else {
            WifiSettings::GetInstance().SetAppRunningState(ScanMode::APP_BACKGROUND_SCAN);
        }
}
#endif
}  // namespace Wifi
}  // namespace OHOS
