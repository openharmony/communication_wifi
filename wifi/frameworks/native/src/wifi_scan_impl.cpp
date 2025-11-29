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

#include "wifi_scan_impl.h"
#ifdef OHOS_ARCH_LITE
#include "i_wifi_scan.h"
#else
#include "iservice_registry.h"
#include "wifi_sa_manager.h"
#include "iwifi_scan.h"
#include "wifi_scan_mgr_proxy.h"
#endif
#include "wifi_logger.h"
#include "wifi_hisysevent.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_SCAN_LABEL("WifiScanImpl");

namespace OHOS {
namespace Wifi {
#ifndef OHOS_ARCH_LITE
const int SCAN_IDL_ERROR_OFFSET = 3300000;
sptr<WifiScanCallbackStub> WifiScanImpl::g_wifiScanCallbackStub =
    sptr<WifiScanCallbackStub>(new (std::nothrow) WifiScanCallbackStub());
#endif
 
#define RETURN_IF_FAIL(cond)                          \
    do {                                              \
        if (!(cond)) {                                \
            WIFI_LOGI("'%{public}s' failed.", #cond); \
            return WIFI_OPT_FAILED;                   \
        }                                             \
    } while (0)

#ifdef OHOS_ARCH_LITE
WifiScanImpl::WifiScanImpl() : systemAbilityId_(0), instId_(0), client_(nullptr)
{}
#else
WifiScanImpl::WifiScanImpl() : systemAbilityId_(0), instId_(0), client_(nullptr), mRemoteDied(false)
{
    deathRecipient_ = new (std::nothrow) WifiScanDeathRecipient(*this);
    if (deathRecipient_ == nullptr) {
        WIFI_LOGE("Create WifiScanDeathRecipient failed!");
    }
}
#endif

WifiScanImpl::~WifiScanImpl()
{
#ifdef OHOS_ARCH_LITE
    WifiScanProxy::ReleaseInstance();
#else
    RemoveDeathRecipient();
#endif
}

#ifndef OHOS_ARCH_LITE
void WifiScanImpl::WifiScanDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remoteObject)
{
    WIFI_LOGW("Remote scan service is died!");
    scanImpl_.HandleRemoteDied(remoteObject);
}
 
void WifiScanImpl::HandleRemoteDied(const wptr<IRemoteObject> &remoteObject)
{
    (void)remoteObject;
    std::lock_guard<std::mutex> lock(mutex_);
 
    mRemoteDied = true;
    client_ = nullptr;
 
    if (g_wifiScanCallbackStub != nullptr) {
        g_wifiScanCallbackStub->SetRemoteDied(true);
    } else {
        WIFI_LOGE("g_wifiScanCallbackStub is nullptr!");
    }
    WIFI_LOGW("Handle remote died success");
}
 
bool WifiScanImpl::RegisterDeathRecipient(const sptr<IRemoteObject> &remote)
{
    if (remote == nullptr || deathRecipient_ == nullptr) {
        WIFI_LOGE("remote or deathRecipient is null");
        return false;
    }
    if (!remote->IsProxyObject()) {
        WIFI_LOGW("not a proxy object, skip register");
        return true;
    }
    if (!remote->AddDeathRecipient(deathRecipient_)) {
        WIFI_LOGE("AddDeathRecipient failed");
        return false;
    }
    remoteService_ = remote;
    mRemoteDied = false;
    WIFI_LOGI("RegisterDeathRecipient success");
    return true;
}
 
void WifiScanImpl::RemoveDeathRecipient()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (remoteService_ == nullptr || deathRecipient_ == nullptr) {
        WIFI_LOGI("remoteService or deathRecipient is null");
        return;
    }
    remoteService_->RemoveDeathRecipient(deathRecipient_);
    remoteService_ = nullptr;
    WIFI_LOGI("RemoveDeathRecipient success");
}
#endif

bool WifiScanImpl::Init(int systemAbilityId, int instId)
{
#ifdef OHOS_ARCH_LITE
    WifiScanProxy *scanProxy = WifiScanProxy::GetInstance();
    if (scanProxy == nullptr) {
        WIFI_LOGE("get wifi scan proxy failed.");
        return false;
    }
    if (scanProxy->Init() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("wifi scan proxy init failed.");
        WifiScanProxy::ReleaseInstance();
        return false;
    }
    client_ = scanProxy;
    return true;
#else
    systemAbilityId_ = systemAbilityId;
    instId_ = instId;
    return true;
#endif
}

bool WifiScanImpl::GetWifiScanProxy()
{
#ifdef OHOS_ARCH_LITE
    return (client_ != nullptr);
#else
    WifiSaLoadManager::GetInstance().LoadWifiSa(systemAbilityId_);
    if (!mRemoteDied && client_ != nullptr) {
        return true;
    }

    sptr<ISystemAbilityManager> sa_mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sa_mgr == nullptr) {
        WIFI_LOGE("failed to get SystemAbilityManager");
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), WifiScanFailReason::PROXY_FAIL);
        return false;
    }

    sptr<IRemoteObject> object = sa_mgr->GetSystemAbility(systemAbilityId_);
    if (object == nullptr) {
        WIFI_LOGE("failed to get SCAN_SERVICE");
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), WifiScanFailReason::PROXY_FAIL);
        return false;
    }

    sptr<IWifiScanMgr> scanMgr = iface_cast<IWifiScanMgr>(object);
    if (scanMgr == nullptr) {
        scanMgr = new (std::nothrow) WifiScanMgrProxy(object);
    }
    if (scanMgr == nullptr) {
        WIFI_LOGE("wifi scan init failed, %{public}d", systemAbilityId_.load());
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), WifiScanFailReason::PROXY_FAIL);
        return false;
    }

    sptr<IRemoteObject> service;
    OHOS::ErrCode ret = scanMgr->GetWifiRemote(instId_, service);
    ErrCode err = ErrCodeToWifiErrCode(ret);
    if (FAILED(err)) {
        WIFI_LOGE("GetWifiRemote failed, instId: %{public}d, error code: %{public}d", instId_, err);
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), WifiScanFailReason::PROXY_FAIL);
        return false;
    }
    if (service == nullptr) {
        WIFI_LOGE("wifi scan remote obj is null, %{public}d", instId_);
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), WifiScanFailReason::PROXY_FAIL);
        return false;
    }

    return SetupClientWithDeathRecipient(service);
#endif
}
 
#ifndef OHOS_ARCH_LITE
bool WifiScanImpl::SetupClientWithDeathRecipient(sptr<IRemoteObject> service)
{
    if (!RegisterDeathRecipient(service)) {
        WIFI_LOGE("Register death recipient failed");
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), WifiScanFailReason::PROXY_FAIL);
        return false;
    }
 
    client_ = iface_cast<OHOS::Wifi::IWifiScan>(service);
    if (client_ == nullptr) {
        client_ = new (std::nothrow) WifiScanProxy(service);
    }
    if (client_ == nullptr) {
        WIFI_LOGE("wifi scan instId_ %{public}d init failed. %{public}d", instId_, systemAbilityId_.load());
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), WifiScanFailReason::PROXY_FAIL);
        return false;
    }
    return true;
}
#endif
 
 
bool WifiScanImpl::IsRemoteDied(void)
{
#ifdef OHOS_ARCH_LITE
    return (client_ == nullptr) ? true : client_->IsRemoteDied();
#else
    std::lock_guard<std::mutex> lock(mutex_);
    if (mRemoteDied) {
        WIFI_LOGW("Remote service is died!");
    }
    return mRemoteDied;
#endif
}

ErrCode WifiScanImpl::SetScanControlInfo(const ScanControlInfo &info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
#ifdef OHOS_ARCH_LITE
    return client_->SetScanControlInfo(info);
#else
    OHOS::ErrCode ret = client_->SetScanControlInfo(info);
    return ErrCodeToWifiErrCode(ret);
#endif
}

ErrCode WifiScanImpl::Scan(bool compatible)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
#ifdef OHOS_ARCH_LITE
    return client_->Scan(compatible);
#else
    std::string bundleName = GetBundleName();
    int32_t scanResultCode = static_cast<int32_t>(WIFI_OPT_FAILED);
    OHOS::ErrCode ipcRet = client_->Scan(compatible, bundleName, scanResultCode);
    WriteWifiScanHiSysEvent(scanResultCode, bundleName);
    return ErrCodeToWifiErrCode(ipcRet);
#endif
}

ErrCode WifiScanImpl::AdvanceScan(const WifiScanParams &params)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
#ifdef OHOS_ARCH_LITE
    return client_->AdvanceScan(params);
#else
    std::string bundleName = GetBundleName();
    OHOS::ErrCode ret = client_->AdvanceScan(params, bundleName);
    return ErrCodeToWifiErrCode(ret);
#endif
}

ErrCode WifiScanImpl::IsWifiClosedScan(bool &bOpen)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
#ifdef OHOS_ARCH_LITE
    return client_->IsWifiClosedScan(bOpen);
#else
    OHOS::ErrCode ret = client_->IsWifiClosedScan(bOpen);
    return ErrCodeToWifiErrCode(ret);
#endif
}

#ifndef OHOS_ARCH_LITE
void WifiScanImpl::GetScanInfoFromParcel(WifiScanInfo &info, MessageParcel &inParcel)
{
    size_t maxIeSize = 256;
    size_t maxIeLen = 1024;
    info.bssid = inParcel.ReadString();
    info.ssid = inParcel.ReadString();
    info.bssidType = inParcel.ReadInt32();
    info.capabilities = inParcel.ReadString();
    info.frequency = inParcel.ReadInt32();
    info.band = inParcel.ReadInt32();
    info.channelWidth = static_cast<WifiChannelWidth>(inParcel.ReadInt32());
    info.centerFrequency0 = inParcel.ReadInt32();
    info.centerFrequency1 = inParcel.ReadInt32();
    info.rssi = inParcel.ReadInt32();
    info.securityType = static_cast<WifiSecurity>(inParcel.ReadInt32());
 
    size_t numInfoElems = inParcel.ReadUint32();
    numInfoElems = numInfoElems < maxIeSize ? numInfoElems : maxIeSize;
    for (size_t m = 0; m < numInfoElems; m++) {
        WifiInfoElem elem;
        elem.id = inParcel.ReadUint32();
        size_t ieLen = inParcel.ReadUint32();
        ieLen = ieLen < maxIeLen ? ieLen : maxIeLen;
        elem.content.resize(ieLen);
        for (size_t n = 0; n < ieLen; n++) {
            elem.content[n] = static_cast<char>(inParcel.ReadInt32());
        }
        info.infoElems.push_back(elem);
    }
 
    info.features = inParcel.ReadInt64();
    info.timestamp = inParcel.ReadInt64();
    info.wifiStandard = inParcel.ReadInt32();
    info.maxSupportedRxLinkSpeed = inParcel.ReadInt32();
    info.maxSupportedTxLinkSpeed = inParcel.ReadInt32();
    info.disappearCount = inParcel.ReadInt32();
    info.isHiLinkNetwork = inParcel.ReadInt32();
    info.isHiLinkProNetwork = inParcel.ReadBool();
    info.supportedWifiCategory = static_cast<WifiCategory>(inParcel.ReadInt32());
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
    info.riskType = static_cast<WifiRiskType>(inParcel.ReadInt32());
#endif
}
 
ErrCode WifiScanImpl::ParseScanInfosFromAshmem(
    sptr<Ashmem> ashmem, const std::vector<int32_t> &allSize, std::vector<WifiScanInfo> &result)
{
    if (!ashmem->MapReadAndWriteAshmem()) {
        WIFI_LOGE("ParseDeviceConfigs ReadAshmem error");
        return WIFI_OPT_FAILED;
    }
 
    int offset = 0;
    for (size_t i = 0; i < allSize.size(); ++i) {
        const void *data = ashmem->ReadFromAshmem(allSize[i], offset);
        if (data == nullptr) {
            offset += allSize[i];
            continue;
        }
 
        MessageParcel inParcel;
        inParcel.WriteBuffer(reinterpret_cast<const char *>(data), allSize[i]);
        inParcel.RewindRead(0);
 
        WifiScanInfo info;
        GetScanInfoFromParcel(info, inParcel);
        result.emplace_back(info);
 
        offset += allSize[i];
    }
 
    ashmem->UnmapAshmem();
    return WIFI_OPT_SUCCESS;
}
#endif
ErrCode WifiScanImpl::GetScanInfoList(std::vector<WifiScanInfo> &result, bool compatible)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
#ifdef OHOS_ARCH_LITE
    return client_->GetScanInfoList(result, compatible);
#else
    ScanAshmemParcel ashmemParcel;
    std::vector<int32_t> allSize;
    OHOS::ErrCode err = client_->GetScanInfoList(compatible, ashmemParcel, allSize);
    ErrCode ret = ErrCodeToWifiErrCode(err);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetScanInfoList from client failed, ret=%{public}d", ret);
        return ret;
    }
 
    sptr<Ashmem> ashmem = ashmemParcel.GetAshmem();
    if (ashmem == nullptr) {
        WIFI_LOGE("Get Ashmem from parcel failed");
        return WIFI_OPT_FAILED;
    }
 
    ret = ParseScanInfosFromAshmem(ashmem, allSize, result);
 
    ashmem->CloseAshmem();
    return ret;
#endif
}

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanImpl::RegisterCallBack(
    const std::shared_ptr<IWifiScanCallback> &callback, const std::vector<std::string> &event)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
    return client_->RegisterCallBack(callback, event);
}
#else
ErrCode WifiScanImpl::RegisterCallBack(const sptr<IWifiScanCallback> &callback, const std::vector<std::string> &event)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
    int32_t pid = GetCallingPid();
    int32_t tokenId = GetCallingTokenId();
    if (g_wifiScanCallbackStub != nullptr) {
        g_wifiScanCallbackStub->RegisterCallBack(callback);
    }
    sptr<IRemoteObject> remoteObj = g_wifiScanCallbackStub->AsObject();
    sptr<IRemoteObject>& cb = remoteObj;
    OHOS::ErrCode ret = client_->RegisterCallBack(cb, pid, tokenId, event);
    if (ret > SCAN_IDL_ERROR_OFFSET) {
        ret = WIFI_OPT_SUCCESS;
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), WifiScanFailReason::SERVICE_REGISTERCALLBACK_FAIL);
    }
    return ErrCodeToWifiErrCode(ret);
}
#endif

ErrCode WifiScanImpl::GetSupportedFeatures(long &features)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
#ifdef OHOS_ARCH_LITE
    return client_->GetSupportedFeatures(features);
#else
    int64_t features_int64 = 0;
    OHOS::ErrCode ret = client_->GetSupportedFeatures(features_int64);
    features = static_cast<long>(features_int64);
    return ErrCodeToWifiErrCode(ret);
#endif
}

bool WifiScanImpl::IsFeatureSupported(long feature)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
#ifdef OHOS_ARCH_LITE
    long tmpFeatures = 0;
#else
    int64_t tmpFeatures = 0;
#endif
    if (client_->GetSupportedFeatures(tmpFeatures) != WIFI_OPT_SUCCESS) {
        return false;
    }
    return ((static_cast<unsigned long>(tmpFeatures) & static_cast<unsigned long>(feature)) ==
        static_cast<unsigned long>(feature));
}

ErrCode WifiScanImpl::SetScanOnlyAvailable(bool bScanOnlyAvailable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
#ifdef OHOS_ARCH_LITE
    return client_->SetScanOnlyAvailable(bScanOnlyAvailable);
#else
    OHOS::ErrCode ret = client_->SetScanOnlyAvailable(bScanOnlyAvailable);
    return ErrCodeToWifiErrCode(ret);
#endif
}

ErrCode WifiScanImpl::GetScanOnlyAvailable(bool &bScanOnlyAvailable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
#ifdef OHOS_ARCH_LITE
    return client_->GetScanOnlyAvailable(bScanOnlyAvailable);
#else
    OHOS::ErrCode ret = client_->GetScanOnlyAvailable(bScanOnlyAvailable);
    return ErrCodeToWifiErrCode(ret);
#endif
}

ErrCode WifiScanImpl::StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
#ifdef OHOS_ARCH_LITE
    return client_->StartWifiPnoScan(isStartAction, periodMs, suspendReason);
#else
    OHOS::ErrCode ret = client_->StartWifiPnoScan(isStartAction, periodMs, suspendReason);
    return ErrCodeToWifiErrCode(ret);
#endif
}

#ifndef OHOS_ARCH_LITE
ErrCode WifiScanImpl::ErrCodeToWifiErrCode(OHOS::ErrCode errorCode)
{
    ErrCode WifiErrCode = WIFI_OPT_FAILED;
    if (errorCode == WIFI_OPT_SUCCESS) {
        WifiErrCode = static_cast<ErrCode>(errorCode);
    } else if (errorCode > SCAN_IDL_ERROR_OFFSET) {
        WifiErrCode = static_cast<ErrCode>(errorCode - SCAN_IDL_ERROR_OFFSET);
    } else {
        WifiErrCode = WIFI_OPT_FAILED;
    }
    return WifiErrCode;
}
#endif
}  // namespace Wifi
}  // namespace OHOS
