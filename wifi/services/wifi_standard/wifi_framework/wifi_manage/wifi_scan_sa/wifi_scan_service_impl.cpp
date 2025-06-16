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
#include "wifi_event_subscriber_manager.h"
#include "cJSON.h"

DEFINE_WIFILOG_SCAN_LABEL("WifiScanServiceImpl");
namespace OHOS {
namespace Wifi {

const int USE_SIZE_50 = 50;
const int USES_30 = 30; // 30 s
const int USEM_10 = 10 * 60; // 10 min
const int TIMES_20 = 20;
constexpr int32_t MAX_SCANMACINFO_WHITELIST_LEN = 200;
constexpr const char *FIXED_MAC = "02:00:00:00:00:00";
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

    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanControlInfo(info, m_instId);
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
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("Scan:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        WriteWifiScanApiFailHiSysEvent(WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo().
            GetScanInitiatorName(), WifiScanFailReason::PERMISSION_DENIED);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (compatible) {
        if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("Scan:VerifyGetScanInfosPermission PERMISSION_DENIED!");
            WriteWifiScanApiFailHiSysEvent(WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo().
                GetScanInitiatorName(), WifiScanFailReason::PERMISSION_DENIED);
            return WIFI_OPT_PERMISSION_DENIED;
        }
    } else {
        if (!WifiAuthCenter::IsSystemAccess()) {
            WIFI_LOGE("Scan:NOT System APP, PERMISSION_DENIED!");
            WriteWifiScanApiFailHiSysEvent(WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo().
                GetScanInitiatorName(), WifiScanFailReason::PERMISSION_DENIED);
            return WIFI_OPT_NON_SYSTEMAPP;
        }
        if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
            WIFI_LOGE("Scan:VerifyWifiConnectionPermission PERMISSION_DENIED!");
            WriteWifiScanApiFailHiSysEvent(WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo().
                GetScanInitiatorName(), WifiScanFailReason::PERMISSION_DENIED);
            return WIFI_OPT_PERMISSION_DENIED;
        }
    }
    
    if (!IsScanServiceRunning()) {
        WriteWifiScanApiFailHiSysEvent(WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo().
            GetScanInitiatorName(), WifiScanFailReason::SCAN_SERVICE_NOT_RUNNING);
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
        WriteWifiScanApiFailHiSysEvent(WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo().
            GetScanInitiatorName(), WifiScanFailReason::SCAN_SERVICE_NOT_RUNNING);
        return WIFI_OPT_SCAN_NOT_OPENED;
    }

    bool externFlag = true;
#ifndef OHOS_ARCH_LITE
    if (WifiAuthCenter::IsNativeProcess()) {
        externFlag = false;
        WIFI_LOGI("Scan: native process start scan !");
    }
#endif
    if (!IsWifiScanAllowed(externFlag)) {
        WIFI_LOGE("Scan not allowed!");
        return WIFI_OPT_FAILED;
    }
    ErrCode ret = pService->Scan(externFlag);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Scan failed: %{public}d!", static_cast<int>(ret));
    }
    return ret;
}

ErrCode WifiScanServiceImpl::AdvanceScan(const WifiScanParams &params)
{
    WIFI_LOGI("Scan with WifiScanParams, band %{public}u", params.band);

    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("AdvanceScan:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        WriteWifiScanApiFailHiSysEvent(WifiConfigCenter::GetInstance().GetWifiScanConfig()->
            GetScanDeviceInfo().GetScanInitiatorName(), WifiScanFailReason::PERMISSION_DENIED);
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifyGetScanInfosPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("AdvanceScan:VerifyGetScanInfosPermission PERMISSION_DENIED!");
        WriteWifiScanApiFailHiSysEvent(WifiConfigCenter::GetInstance().GetWifiScanConfig()->
            GetScanDeviceInfo().GetScanInitiatorName(), WifiScanFailReason::PERMISSION_DENIED);
        return WIFI_OPT_PERMISSION_DENIED;
    }

    if (!IsScanServiceRunning()) {
        WriteWifiScanApiFailHiSysEvent(WifiConfigCenter::GetInstance().GetWifiScanConfig()->
            GetScanDeviceInfo().GetScanInitiatorName(), WifiScanFailReason::SCAN_SERVICE_NOT_RUNNING);
        return WIFI_OPT_SCAN_NOT_OPENED;
    }

    bool externFlag = true;
#ifndef OHOS_ARCH_LITE
    UpdateScanMode();
    if (WifiAuthCenter::IsNativeProcess()) {
        externFlag = false;
        WIFI_LOGI("Scan: native process start scan !");
    }
#endif
    if (!IsWifiScanAllowed(externFlag)) {
        WIFI_LOGE("Scan not allowed!");
        return WIFI_OPT_FAILED;
    }
    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(m_instId);
    if (pService == nullptr) {
        WriteWifiScanApiFailHiSysEvent(WifiConfigCenter::GetInstance().GetWifiScanConfig()->
            GetScanDeviceInfo().GetScanInitiatorName(), WifiScanFailReason::SCAN_SERVICE_NOT_RUNNING);
        return WIFI_OPT_SCAN_NOT_OPENED;
    }
    return pService->ScanWithParam(params, externFlag);
}

bool WifiScanServiceImpl::IsWifiScanAllowed(bool externFlag)
{
    WifiScanDeviceInfo scanInfo;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanDeviceInfo(scanInfo);
    if (externFlag) {
        if (WifiConfigCenter::GetInstance().GetWifiState(m_instId) != static_cast<int>(WifiState::ENABLED)) {
            WIFI_LOGW("extern scan not allow when wifi disable");
            return false;
        }
        if (WifiConfigCenter::GetInstance().GetSystemMode() == SystemMode::M_FACTORY_MODE) {
            WIFI_LOGI("extern scan has allowed for FactoryMode.\n");
            return true;
        }
        if (scanInfo.idelState == MODE_STATE_OPEN) {
            WIFI_LOGW("extern scan not allow by power idel state");
            return false;
        }
    }
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService != nullptr) {
        scanInfo.externScan = externFlag;
        scanInfo.isSystemApp = WifiAuthCenter::IsSystemAccess();
        bool allowScan = pEnhanceService->IsScanAllowed(scanInfo);
        WifiConfigCenter::GetInstance().GetWifiScanConfig()->SaveScanDeviceInfo(scanInfo);
        return allowScan;
    }
    return true;
}

ErrCode WifiScanServiceImpl::IsWifiClosedScan(bool &bOpen)
{
    WIFI_LOGI("IsWifiClosedScan");
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsWifiClosedScan:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    bOpen = WifiSettings::GetInstance().GetScanAlwaysState();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiScanServiceImpl::GetScanInfoList(std::vector<WifiScanInfo> &result, bool compatible)
{
    WIFI_LOGI("GetScanInfoList, compatible:%{public}d", compatible);
    int apiVersion = WifiPermissionUtils::GetApiVersion();
    if (apiVersion < API_VERSION_9 && apiVersion != API_VERSION_INVALID) {
        WIFI_LOGE("%{public}s The version %{public}d is too early to be supported", __func__, apiVersion);
        return WIFI_OPT_PERMISSION_DENIED;
    }
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

    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(result);
    if (!compatible) {
    #ifdef SUPPORT_RANDOM_MAC_ADDR
        if (WifiPermissionUtils::VerifyGetWifiPeersMacPermission() == PERMISSION_DENIED ||
            ProcessScanInfoRequest() == WIFI_OPT_PERMISSION_DENIED) {
            for (auto iter = result.begin(); iter != result.end(); ++iter) {
                WifiMacAddrInfo macAddrInfo;
                macAddrInfo.bssid = iter->bssid;
                macAddrInfo.bssidType = iter->bssidType;
                std::string randomMacAddr =
                    WifiConfigCenter::GetInstance().GetMacAddrPairs(WifiMacAddrInfoType::WIFI_SCANINFO_MACADDR_INFO,
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
    } else {
        UpdateScanInfoListNotInWhiteList(result);
    }
    return WIFI_OPT_SUCCESS;
}

void WifiScanServiceImpl::UpdateScanInfoListNotInWhiteList(std::vector<WifiScanInfo> &result)
{
    if (WifiPermissionUtils::VerifyGetWifiPeersMacPermission() == PERMISSION_DENIED && !IsInScanMacInfoWhiteList()) {
        for (auto iter = result.begin(); iter != result.end(); ++iter) {
            iter->bssid = FIXED_MAC;
        }
    }
}

ErrCode WifiScanServiceImpl::ProcessScanInfoRequest()
{
    std::string appId = "";
    std::string packageName = "";
#ifndef OHOS_ARCH_LITE
    GetBundleNameByUid(GetCallingUid(), packageName);
    appId = GetBundleAppIdByBundleName(GetCallingUid(), packageName);
#endif
    if (appId.empty() || packageName.empty()) {
        WIFI_LOGE("ProcessPermissionVerify(), Empty id or packageName");
        return WIFI_OPT_SUCCESS;
    }
 
    std::vector<PackageInfo> specialList;
    if (WifiSettings::GetInstance().GetPackageInfoByName("ScanLimitPackages", specialList) != 0) {
        WIFI_LOGE("ProcessScanInfoRequest GetPackageInfoByName failed");
        return WIFI_OPT_SUCCESS;
    }
 
    bool isFind = false;
    // USE_SIZE_50 avoid endless loops
    for (auto iter = specialList.begin(); iter != specialList.end() && specialList.size() < USE_SIZE_50; ++iter) {
        WIFI_LOGD("speciallist: %{public}s,frontapp %{public}s,list_appid :  %{public}s,appid :  %{public}s",
            (iter->name).c_str(), (packageName).c_str(), (iter->appid).c_str(), appId.c_str());
        if (iter->name == packageName && iter->appid == appId) {
            isFind = true;
            break;
        }
    }

    if (!isFind) {
        return WIFI_OPT_SUCCESS;
    }
    return IsAllowedThirdPartyRequest(appId);
}
 
ErrCode WifiScanServiceImpl::IsAllowedThirdPartyRequest(std::string appId)
{
    // Check if the App is in front
#ifndef OHOS_ARCH_LITE
    if (!WifiAppStateAware::GetInstance().IsForegroundApp(GetCallingUid())) {
        WIFI_LOGE("IsAllowedThirdPartyRequest App not in front.");
        return WIFI_OPT_PERMISSION_DENIED;
    }
#endif
    int64_t nowTime = GetCurrentTimeSeconds();
    std::unique_lock<std::mutex> lock(mThirdPartyScanLimitMutex_);
    if (callTimestampsMap_.count(appId) == 0) {
        callTimestampsMap_[appId] = std::vector<int64_t>();
    } else {
        // Check if the last call is within 30 seconds
        if (!callTimestampsMap_[appId].empty() && nowTime - callTimestampsMap_[appId].back() < USES_30) {
            WIFI_LOGE("IsAllowedThirdPartyRequest, last call is within 30 seconds!");
            return WIFI_OPT_PERMISSION_DENIED;
        }
    }
 
    // Clear call records that have been recorded for more than 10 minutes
    // USE_SIZE_50 avoid endless loops
    auto it = callTimestampsMap_[appId].begin();
    for (; it != callTimestampsMap_[appId].end() && callTimestampsMap_[appId].size() < USE_SIZE_50; ++it) {
        if (nowTime - *it <= USEM_10) {
            break;
        }
    }
    
    callTimestampsMap_[appId].erase(callTimestampsMap_[appId].begin(), it);
 
    // Check whether the number of calls exceeds 19 within 10 minutes
    if (callTimestampsMap_[appId].size() + 1 >= TIMES_20) {
        WIFI_LOGE("IsAllowedThirdPartyRequest 10min over 20!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    callTimestampsMap_[appId].push_back(nowTime);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiScanServiceImpl::SetScanOnlyAvailable(bool bScanOnlyAvailable)
{
    WIFI_LOGD("WifiScanServiceImpl::SetScanOnlyAvailable");
    if (!WifiAuthCenter::IsSystemAccess()) {
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
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetScanOnlyAvailable: NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetScanOnlyAvailable:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetScanOnlyAvailable:VerifyGetWifiConfigPermission() PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }

    bScanOnlyAvailable = WifiSettings::GetInstance().GetScanOnlySwitchState(m_instId);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiScanServiceImpl::StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason)
{
    WIFI_LOGD("WifiScanServiceImpl::StartWifiPnoScan");
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("StartWifiPnoScan:NOT System APP, PERMISSION_DENIED!");
        return WIFI_OPT_NON_SYSTEMAPP;
    }

    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("StartWifiPnoScan:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return WIFI_OPT_PERMISSION_DENIED;
    }
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("StartWifiPnoScan:VerifyWifiConnectionPermission PERMISSION_DENIED!");
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
    std::string packageName = "";
    GetBundleNameByUid(uid, packageName);
    if (WifiAppStateAware::GetInstance().IsForegroundApp(uid)
        || packageName == WifiSettings::GetInstance().GetPackageName("SETTINGS")) {
        WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetAppRunningState(ScanMode::APP_FOREGROUND_SCAN);
    } else {
        WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetAppRunningState(ScanMode::APP_BACKGROUND_SCAN);
    }
}
#endif

bool WifiScanServiceImpl::IsInScanMacInfoWhiteList()
{
#ifndef OHOS_ARCH_LITE
    std::unique_lock<std::mutex> lock(wifiWhiteListMutex_);
    std::string bundleName;
    GetBundleNameByUid(GetCallingUid(), bundleName);
    int64_t currentTime = GetElapsedMicrosecondsSinceBoot();
    if (queryScanMacInfoWhiteListTimeStamp_ == 0 ||
        (currentTime - queryScanMacInfoWhiteListTimeStamp_) / SECOND_TO_MICROSECOND >=
        ONE_DAY_TIME_SECONDS) {
        std::string queryScanMacInfoWhiteList =
            WifiManager::GetInstance().GetWifiEventSubscriberManager()->GetScanMacInfoWhiteListByDatashare();
        queryScanMacInfoWhiteListTimeStamp_ = currentTime;
        scanMacInfoWhiteListStr_ = queryScanMacInfoWhiteList;
    }
    if (scanMacInfoWhiteListStr_.empty()) {
        return false;
    }
    auto *scanMacInfoWhileListRoot = cJSON_Parse(scanMacInfoWhiteListStr_.c_str());
    if (scanMacInfoWhileListRoot == nullptr) {
        return false;
    }
    cJSON* scanMacInfoWifiWhiteList = cJSON_GetObjectItemCaseSensitive(scanMacInfoWhileListRoot, "wifi");
    if (scanMacInfoWifiWhiteList == nullptr) {
        cJSON_Delete(scanMacInfoWhileListRoot);
        return false;
    }
    if (cJSON_IsArray(scanMacInfoWifiWhiteList)) {
        int size = cJSON_GetArraySize(scanMacInfoWifiWhiteList);
        for (int i = 0; i < size && i < MAX_SCANMACINFO_WHITELIST_LEN; i++) {
            cJSON* item = cJSON_GetArrayItem(scanMacInfoWifiWhiteList, i);
            if (item != nullptr && cJSON_IsString(item) &&
                bundleName.find(item->valuestring) != std::string::npos) {
                cJSON_Delete(scanMacInfoWhileListRoot);
                return true;
            }
        }
    }
    cJSON_Delete(scanMacInfoWhileListRoot);
#endif
    return false;
}
}  // namespace Wifi
}  // namespace OHOS
