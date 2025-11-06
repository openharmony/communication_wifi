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
#ifndef OHOS_ARCH_LITE
    const int SCAN_IDL_ERROR_OFFSET = 3300000;
#endif
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

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::SetScanControlInfo(const ScanControlInfo &info)
#else
int32_t WifiScanServiceImpl::SetScanControlInfo(const ScanControlInfoParcel &parcelInfo)
{
    WIFI_LOGI("WifiScanServiceImpl::SetScanControlInfo");
    ScanControlInfo info = parcelInfo.ToScanControlInfo();
    int32_t ret = SetScanControlInfo(info);
    return HandleScanIdlRet(ret);
}
int32_t WifiScanServiceImpl::SetScanControlInfo(const ScanControlInfo &info)
#endif
{
    WIFI_LOGI("WifiScanServiceImpl::SetScanControlInfo (original)");
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

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::Scan(bool compatible)
#else
int32_t WifiScanServiceImpl::Scan(bool compatible, const std::string& bundleName, int32_t &scanResultCode)
{
    WIFI_LOGI("Scan with bundleName: %{public}s, compatible: %{public}d", bundleName.c_str(), compatible);
    scanResultCode = static_cast<int32_t>(WIFI_OPT_FAILED);
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetAppPackageName(bundleName);
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanInitiatorUid(GetCallingUid());
    scanResultCode = Scan(compatible);
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetAppPackageName("");
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanInitiatorUid(-1);
    return HandleScanIdlRet(scanResultCode);
}
int32_t WifiScanServiceImpl::Scan(bool compatible)
#endif
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

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::PermissionVerification()
#else
int32_t WifiScanServiceImpl::PermissionVerification()
#endif
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

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::AdvanceScan(const WifiScanParams &params)
#else
int32_t WifiScanServiceImpl::AdvanceScan(const WifiScanParamsParcel &paramsParcel,
    const std::string &bundleName)
{
    WIFI_LOGD("AdvanceScan (Parcel) called: bundleName=%{public}s, SSID=%{public}s",
        bundleName.c_str(), paramsParcel.ssid.c_str());
    WifiScanParams params = paramsParcel.ToWifiScanParams();
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetAppPackageName(bundleName);
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanInitiatorUid(GetCallingUid());
    int32_t ret = AdvanceScan(params);
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetAppPackageName("");
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SetScanInitiatorUid(-1);
    return HandleScanIdlRet(ret);
}
int32_t WifiScanServiceImpl::AdvanceScan(const WifiScanParams &params)
#endif
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

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::IsWifiClosedScan(bool &bOpen)
#else
int32_t WifiScanServiceImpl::IsWifiClosedScan(bool &bOpen)
#endif
{
    WIFI_LOGI("IsWifiClosedScan");
    ErrCode ret = WIFI_OPT_SUCCESS;
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("IsWifiClosedScan:VerifyGetWifiInfoPermission PERMISSION_DENIED!");
        ret = WIFI_OPT_PERMISSION_DENIED;
        return HandleScanIdlRet(ret);
    }

    bOpen = WifiSettings::GetInstance().GetScanAlwaysState();
    return WIFI_OPT_SUCCESS;
}

#ifndef OHOS_ARCH_LITE
void WifiScanServiceImpl::WriteInfoElementsToParcel(
    const std::vector<WifiInfoElem> &infoElems,
    size_t ieSize,
    size_t maxIeLen,
    Parcel &outParcel)
{
    for (size_t j = 0; j < ieSize; j++) {
        const auto &elem = infoElems[j];
        outParcel.WriteUint32(elem.id);
        size_t ieLen = elem.content.size() < maxIeLen ? elem.content.size() : maxIeLen;
        outParcel.WriteUint32(ieLen);
        for (size_t k = 0; k < ieLen; k++) {
            outParcel.WriteInt32(static_cast<int>(elem.content[k]));
        }
    }
}
 
void WifiScanServiceImpl::SendScanInfo(int32_t contentSize, std::vector<WifiScanInfo> &result,
    ScanAshmemParcel &outAshmemParcel, std::vector<uint32_t> &allSizeUint)
{
    WIFI_LOGI("SendScanInfo (reused logic), contentSize=%{public}d", contentSize);
    constexpr int32_t ASH_MEM_SIZE = 1024 * 300;
 
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem("scaninfo", ASH_MEM_SIZE);
    if (ashmem == nullptr || !ashmem->MapReadAndWriteAshmem()) {
        WIFI_LOGE("Create or map ashmem failed");
        outAshmemParcel = ScanAshmemParcel(nullptr);
        return;
    }
 
    int offset = 0;
    size_t maxIeSize = 256;
    size_t maxIeLen = 1024;
    allSizeUint.clear();
 
    for (int32_t i = 0; i < contentSize; ++i) {
        MessageParcel outParcel;
        outParcel.WriteString(result[i].bssid);
        outParcel.WriteString(result[i].ssid);
        outParcel.WriteInt32(result[i].bssidType);
        outParcel.WriteString(result[i].capabilities);
        outParcel.WriteInt32(result[i].frequency);
        outParcel.WriteInt32(result[i].band);
        outParcel.WriteInt32(static_cast<int>(result[i].channelWidth));
        outParcel.WriteInt32(result[i].centerFrequency0);
        outParcel.WriteInt32(result[i].centerFrequency1);
        outParcel.WriteInt32(result[i].rssi);
        outParcel.WriteInt32(static_cast<int>(result[i].securityType));
 
        size_t ieSize = result[i].infoElems.size() < maxIeSize ? result[i].infoElems.size() : maxIeSize;
        outParcel.WriteUint32(ieSize);
        WriteInfoElementsToParcel(result[i].infoElems, ieSize, maxIeLen, outParcel);
 
        outParcel.WriteInt64(result[i].features);
        outParcel.WriteInt64(result[i].timestamp);
        outParcel.WriteInt32(result[i].wifiStandard);
        outParcel.WriteInt32(result[i].maxSupportedRxLinkSpeed);
        outParcel.WriteInt32(result[i].maxSupportedTxLinkSpeed);
        outParcel.WriteInt32(result[i].disappearCount);
        outParcel.WriteInt32(result[i].isHiLinkNetwork);
        outParcel.WriteBool(result[i].isHiLinkProNetwork);
        outParcel.WriteInt32(static_cast<int>(result[i].supportedWifiCategory));
 
        int dataSize = static_cast<int>(outParcel.GetDataSize());
        if (offset + dataSize > ASH_MEM_SIZE) {
            WIFI_LOGW("Ashmem out of space, stop writing");
            break;
        }
        allSizeUint.emplace_back(dataSize);
        ashmem->WriteToAshmem(reinterpret_cast<void*>(outParcel.GetData()), dataSize, offset);
        offset += dataSize;
    }
    outAshmemParcel = ScanAshmemParcel(ashmem);
 
    ashmem->UnmapAshmem();
}
 
int32_t WifiScanServiceImpl::GetScanInfoList(bool compatible, ScanAshmemParcel &outAshmemParcel,
    std::vector<int32_t> &allSize)
{
    WIFI_LOGI("New GetScanInfoList (compatible=%{public}d)", compatible);
 
    allSize.clear();
 
    std::vector<WifiScanInfo> result;
    int32_t ret = GetScanInfoList(result, compatible);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Original GetScanInfoList failed, ret=%{public}d", ret);
        return HandleScanIdlRet(ret);
    }
 
    std::sort(result.begin(), result.end(), [](const WifiScanInfo& a, const WifiScanInfo& b) {
        return a.rssi > b.rssi;
    });
    int32_t size = static_cast<int>(result.size());
    constexpr int maxSize = 200;
    if (size > maxSize) {
        size = maxSize;
        WIFI_LOGW("Scan result truncated to %{public}d", maxSize);
    }
 
    std::vector<uint32_t> allSizeUint;
    SendScanInfo(size, result, outAshmemParcel, allSizeUint);
 
    for (const auto &len : allSizeUint) {
        if (len > static_cast<uint32_t>(INT32_MAX)) {
            WIFI_LOGE("Single scan info size exceeds INT32_MAX");
            return HandleScanIdlRet(WIFI_OPT_FAILED);
        }
        allSize.emplace_back(static_cast<int32_t>(len));
    }
 
    return WIFI_OPT_SUCCESS;
}
#endif

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::GetScanInfoList(std::vector<WifiScanInfo> &result, bool compatible)
#else
int32_t WifiScanServiceImpl::GetScanInfoList(std::vector<WifiScanInfo> &result, bool compatible)
#endif
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
#ifndef OHOS_ARCH_LITE
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService != nullptr && pEnhanceService->CheckScanInfo(true, GetCallingUid())) {
        WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetExternalScanInfoList(result);
    }
#endif
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
                    (macAddrInfo.bssidType == REAL_DEVICE_ADDRESS)){
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

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::ProcessScanInfoRequest()
#else
int32_t WifiScanServiceImpl::ProcessScanInfoRequest()
#endif
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

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::IsAllowedThirdPartyRequest(std::string appId)
#else
int32_t WifiScanServiceImpl::IsAllowedThirdPartyRequest(std::string appId)
#endif
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

void WifiScanServiceImpl::UpdateScanInfoListNotInWhiteList(std::vector<WifiScanInfo> &result)
{
    if (WifiPermissionUtils::VerifyGetWifiPeersMacPermission() == PERMISSION_DENIED && !IsInScanMacInfoWhiteList()) {
        for (auto iter = result.begin(); iter != result.end(); ++iter) {
            iter->bssid = FIXED_MAC;
        }
    }
}

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::SetScanOnlyAvailable(bool bScanOnlyAvailable)
#else
int32_t WifiScanServiceImpl::SetScanOnlyAvailable(bool bScanOnlyAvailable)
#endif
{
    WIFI_LOGD("WifiScanServiceImpl::SetScanOnlyAvailable");
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("SetScanOnlyAvailable:NOT System APP, PERMISSION_DENIED!");
        return HandleScanIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }
    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetScanOnlyAvailable:VerifySetWifiInfoPermission() PERMISSION_DENIED!");
        return HandleScanIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    if (WifiPermissionUtils::VerifySetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("SetScanOnlyAvailable:VerifySetWifiConfigPermission() PERMISSION_DENIED!");
        return HandleScanIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    WifiSettings::GetInstance().SetScanOnlySwitchState(bScanOnlyAvailable, m_instId);
    ErrCode errCode = WIFI_OPT_SUCCESS;
    if (bScanOnlyAvailable) {
        errCode = WifiManager::GetInstance().GetWifiTogglerManager()->ScanOnlyToggled(1);
    } else {
        errCode = WifiManager::GetInstance().GetWifiTogglerManager()->ScanOnlyToggled(0);
    }
    return HandleScanIdlRet(errCode);
}

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::GetScanOnlyAvailable(bool &bScanOnlyAvailable)
#else
int32_t WifiScanServiceImpl::GetScanOnlyAvailable(bool &bScanOnlyAvailable)
#endif
{
    WIFI_LOGD("WifiScanServiceImpl::GetScanOnlyAvailable");
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("GetScanOnlyAvailable: NOT System APP, PERMISSION_DENIED!");
        return HandleScanIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetScanOnlyAvailable:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return HandleScanIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    if (WifiPermissionUtils::VerifyGetWifiConfigPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetScanOnlyAvailable:VerifyGetWifiConfigPermission() PERMISSION_DENIED!");
        return HandleScanIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }

    bScanOnlyAvailable = WifiSettings::GetInstance().GetScanOnlySwitchState(m_instId);
    return WIFI_OPT_SUCCESS;
}

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason)
#else
int32_t WifiScanServiceImpl::StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason)
#endif
{
    WIFI_LOGD("WifiScanServiceImpl::StartWifiPnoScan");
    if (!WifiAuthCenter::IsSystemAccess()) {
        WIFI_LOGE("StartWifiPnoScan:NOT System APP, PERMISSION_DENIED!");
        return HandleScanIdlRet(WIFI_OPT_NON_SYSTEMAPP);
    }

    if (WifiPermissionUtils::VerifySetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("StartWifiPnoScan:VerifySetWifiInfoPermission PERMISSION_DENIED!");
        return HandleScanIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    if (WifiPermissionUtils::VerifyWifiConnectionPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("StartWifiPnoScan:VerifyWifiConnectionPermission PERMISSION_DENIED!");
        return HandleScanIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
    IScanService *pService = WifiServiceManager::GetInstance().GetScanServiceInst(m_instId);
    if (pService == nullptr) {
        return HandleScanIdlRet(WIFI_OPT_SCAN_NOT_OPENED);
    }
    ErrCode ret =  pService->StartWifiPnoScan(isStartAction, periodMs, suspendReason);
    return HandleScanIdlRet(ret);
}

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::RegisterCallBack(const std::shared_ptr<IWifiScanCallback> &callback,
    const std::vector<std::string> &event)
#else
int32_t WifiScanServiceImpl::RegisterCallBack(
    const sptr<IRemoteObject> &cbParcel, int32_t pid, int32_t tokenId, const std::vector<std::string> &event)
{
    WIFI_LOGI("mahao WifiScanServiceImpl RegisterCallBack");
    WIFI_LOGD("WifiScanServiceImpl::RegisterCallBack (adapt new Stub), pid=%{public}d, tokenId=%{public}d",
        pid, tokenId);
    int32_t ret = WIFI_OPT_FAILED;
 
    do {
        sptr<IRemoteObject> remote = cbParcel;
        sptr<IWifiScanCallback> callback = nullptr;
        callback = iface_cast<IWifiScanCallback>(remote);
        if (callback == nullptr) {
            callback = sptr<WifiScanCallbackProxy>::MakeSptr(remote);
            WIFI_LOGI("Create new WifiScanCallbackProxy for old logic");
        }
 
        if (mSingleCallback) {
            ret = RegisterCallBack(callback, event);
            continue;
        }
        std::unique_lock<std::mutex> lock(deathRecipientMutex);
        if (deathRecipient_ == nullptr) {
            deathRecipient_ = sptr<WifiScanDeathRecipient>::MakeSptr();
        }
        if ((remote->IsProxyObject()) &&
            !WifiInternalEventDispatcher::GetInstance().HasScanRemote(remote, m_instId)) {
            remote->AddDeathRecipient(deathRecipient_);
        }
        if (callback != nullptr) {
            for (const auto &eventName : event) {
                ret = WifiInternalEventDispatcher::GetInstance().AddScanCallback(
                    remote, callback, pid, eventName, tokenId, m_instId);
            }
        } else {
            WIFI_LOGE("Converted callback is null");
        }
    } while (0);
 
    return HandleScanIdlRet(ret);
}
 
int32_t WifiScanServiceImpl::RegisterCallBack(const sptr<IWifiScanCallback> &callback,
    const std::vector<std::string> &event)
#endif
{
    WIFI_LOGI("WifiScanServiceImpl::RegisterCallBack!");
    for (const auto &eventName : event) {
        WifiInternalEventDispatcher::GetInstance().SetSingleScanCallback(callback, eventName, m_instId);
    }
    return WIFI_OPT_SUCCESS;
}

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::GetSupportedFeatures(long &features)
#else
int32_t WifiScanServiceImpl::GetSupportedFeatures(int64_t &features)
#endif
{
    if (WifiPermissionUtils::VerifyGetWifiInfoPermission() == PERMISSION_DENIED) {
        WIFI_LOGE("GetSupportedFeatures:VerifyGetWifiInfoPermission() PERMISSION_DENIED!");
        return HandleScanIdlRet(WIFI_OPT_PERMISSION_DENIED);
    }
#ifdef OHOS_ARCH_LITE
    int ret = WifiManager::GetInstance().GetSupportedFeatures(features);
#else
    long features_long = 0;
    int ret = WifiManager::GetInstance().GetSupportedFeatures(features_long);
    features = static_cast<int64_t>(features_long);
#endif
    if (ret < 0) {
        WIFI_LOGE("Failed to get supported features!");
        return HandleScanIdlRet(WIFI_OPT_FAILED);
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
            if (item != nullptr && cJSON_IsString(item) && item->valuestring != nullptr &&
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

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanServiceImpl::HandleScanIdlRet(ErrCode originRet)
#else
int32_t WifiScanServiceImpl::HandleScanIdlRet(int32_t originRet)
#endif
{
#ifdef OHOS_ARCH_LITE
    return originRet;
#else
    if (originRet == WIFI_OPT_SUCCESS) {
        return WIFI_OPT_SUCCESS;
    } else {
        return originRet + SCAN_IDL_ERROR_OFFSET;
    }
#endif
}

}  // namespace Wifi
}  // namespace OHOS
