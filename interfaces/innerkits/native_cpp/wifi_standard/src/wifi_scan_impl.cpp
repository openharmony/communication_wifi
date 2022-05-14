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

#include "wifi_scan_impl.h"
#include "i_wifi_scan.h"
#ifndef OHOS_ARCH_LITE
#include "iservice_registry.h"
#endif
#include "wifi_logger.h"
#include "wifi_scan_proxy.h"

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

WifiScanImpl::WifiScanImpl(int systemAbilityId) : systemAbilityId_(systemAbilityId), client_(nullptr)
{}

WifiScanImpl::~WifiScanImpl()
{
#ifdef OHOS_ARCH_LITE
    WifiScanProxy::ReleaseInstance();
#endif
}

bool WifiScanImpl::Init()
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
#else
    sptr<ISystemAbilityManager> sa_mgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sa_mgr == nullptr) {
        WIFI_LOGE("failed to get SystemAbilityManager");
        return false;
    }
    sptr<IRemoteObject> object = sa_mgr->GetSystemAbility(systemAbilityId_);
    if (object == nullptr) {
        WIFI_LOGE("failed to get SCAN_SERVICE");
        return false;
    }
    client_ = iface_cast<OHOS::Wifi::IWifiScan>(object);
    if (client_ == nullptr) {
        client_ = new (std::nothrow) WifiScanProxy(object);
    }
    if (client_ == nullptr) {
        WIFI_LOGE("wifi scan init failed. %{public}d", systemAbilityId_);
        return false;
    }
#endif
    return true;
}

ErrCode WifiScanImpl::SetScanControlInfo(const ScanControlInfo &info)
{
    RETURN_IF_FAIL(client_);
    return client_->SetScanControlInfo(info);
}

ErrCode WifiScanImpl::Scan()
{
    RETURN_IF_FAIL(client_);
    return client_->Scan();
}

ErrCode WifiScanImpl::AdvanceScan(const WifiScanParams &params)
{
    RETURN_IF_FAIL(client_);
    return client_->AdvanceScan(params);
}

ErrCode WifiScanImpl::IsWifiClosedScan(bool &bOpen)
{
    RETURN_IF_FAIL(client_);
    return client_->IsWifiClosedScan(bOpen);
}

ErrCode WifiScanImpl::GetScanInfoList(std::vector<WifiScanInfo> &result)
{
    RETURN_IF_FAIL(client_);
    return client_->GetScanInfoList(result);
}

#ifdef OHOS_ARCH_LITE
ErrCode WifiScanImpl::RegisterCallBack(const std::shared_ptr<IWifiScanCallback> &callback)
#else
ErrCode WifiScanImpl::RegisterCallBack(const sptr<IWifiScanCallback> &callback)
#endif
{
    RETURN_IF_FAIL(client_);
    return client_->RegisterCallBack(callback);
}

ErrCode WifiScanImpl::GetSupportedFeatures(long &features)
{
    RETURN_IF_FAIL(client_);
    return client_->GetSupportedFeatures(features);
}

bool WifiScanImpl::IsFeatureSupported(long feature)
{
    RETURN_IF_FAIL(client_);
    long tmpFeatures = 0;
    if (client_->GetSupportedFeatures(tmpFeatures) != WIFI_OPT_SUCCESS) {
        return false;
    }
    return ((tmpFeatures & feature) == feature);
}
}  // namespace Wifi
}  // namespace OHOS