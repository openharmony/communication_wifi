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
#include "i_wifi_scan.h"
#ifndef OHOS_ARCH_LITE
#include "iservice_registry.h"
#include "wifi_sa_manager.h"
#endif
#include "wifi_logger.h"
#include "wifi_scan_proxy.h"
#include "wifi_scan_mgr_proxy.h"
#include "wifi_hisysevent.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_SCAN_LABEL("WifiScanImpl");

namespace OHOS {
namespace Wifi {
#define RETURN_IF_FAIL(cond)                          \
    do {                                              \
        if (!(cond)) {                                \
            WIFI_LOGI("'%{public}s' failed.", #cond); \
            return WIFI_OPT_FAILED;                   \
        }                                             \
    } while (0)

WifiScanImpl::WifiScanImpl() : systemAbilityId_(0), instId_(0), client_(nullptr)
{}

WifiScanImpl::~WifiScanImpl()
{
#ifdef OHOS_ARCH_LITE
    WifiScanProxy::ReleaseInstance();
#endif
}

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
    if (IsRemoteDied() == false) {
        return true;
    }

    sptr<ISystemAbilityManager> sa_mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sa_mgr == nullptr) {
        WIFI_LOGE("failed to get SystemAbilityManager");
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), -1);
        return false;
    }

    sptr<IRemoteObject> object = sa_mgr->GetSystemAbility(systemAbilityId_);
    if (object == nullptr) {
        WIFI_LOGE("failed to get SCAN_SERVICE");
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), -1);
        return false;
    }

    sptr<IWifiScanMgr> scanMgr = iface_cast<IWifiScanMgr>(object);
    if (scanMgr == nullptr) {
        scanMgr = new (std::nothrow) WifiScanMgrProxy(object);
    }
    if (scanMgr == nullptr) {
        WIFI_LOGE("wifi scan init failed, %{public}d", systemAbilityId_);
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), -1);
        return false;
    }

    sptr<IRemoteObject> service = scanMgr->GetWifiRemote(instId_);
    if (service == nullptr) {
        WIFI_LOGE("wifi scan remote obj is null, %{public}d", instId_);
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), -1);
        return false;
    }

    client_ = iface_cast<OHOS::Wifi::IWifiScan>(service);
    if (client_ == nullptr) {
        client_ = new (std::nothrow) WifiScanProxy(service);
    }
    if (client_ == nullptr) {
        WIFI_LOGE("wifi scan instId_ %{public}d init failed. %{public}d", instId_, systemAbilityId_);
        WriteWifiScanApiFailHiSysEvent(GetBundleName(), -1);
        return false;
    }
    return true;
#endif
}

ErrCode WifiScanImpl::SetScanControlInfo(const ScanControlInfo &info)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
    return client_->SetScanControlInfo(info);
}

ErrCode WifiScanImpl::Scan(bool compatible)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
    return client_->Scan(compatible);
}

ErrCode WifiScanImpl::AdvanceScan(const WifiScanParams &params)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
    return client_->AdvanceScan(params);
}

ErrCode WifiScanImpl::IsWifiClosedScan(bool &bOpen)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
    return client_->IsWifiClosedScan(bOpen);
}

ErrCode WifiScanImpl::GetScanInfoList(std::vector<WifiScanInfo> &result, bool compatible)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
    return client_->GetScanInfoList(result, compatible);
}

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanImpl::RegisterCallBack(const std::shared_ptr<IWifiScanCallback> &callback,
    const std::vector<std::string> &event)
#else
ErrCode WifiScanImpl::RegisterCallBack(const sptr<IWifiScanCallback> &callback, const std::vector<std::string> &event)
#endif
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
    return client_->RegisterCallBack(callback, event);
}

ErrCode WifiScanImpl::GetSupportedFeatures(long &features)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
    return client_->GetSupportedFeatures(features);
}

bool WifiScanImpl::IsFeatureSupported(long feature)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
    long tmpFeatures = 0;
    if (client_->GetSupportedFeatures(tmpFeatures) != WIFI_OPT_SUCCESS) {
        return false;
    }
    return ((tmpFeatures & feature) == feature);
}

bool WifiScanImpl::IsRemoteDied(void)
{
    return (client_ == nullptr) ? true : client_->IsRemoteDied();
}

ErrCode WifiScanImpl::SetScanOnlyAvailable(bool bScanOnlyAvailable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
    return client_->SetScanOnlyAvailable(bScanOnlyAvailable);
}

ErrCode WifiScanImpl::GetScanOnlyAvailable(bool &bScanOnlyAvailable)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
    return client_->GetScanOnlyAvailable(bScanOnlyAvailable);
}

ErrCode WifiScanImpl::StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RETURN_IF_FAIL(GetWifiScanProxy());
    return client_->StartWifiPnoScan(isStartAction, periodMs, suspendReason);
}
}  // namespace Wifi
}  // namespace OHOS
