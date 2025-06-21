/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#include "define.h"
#include "wifi_logger.h"
#include "wifi_pro_interface.h"
#include "wifi_pro_service.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiProInterface");

WifiProInterface::WifiProInterface(int32_t instId) : instId_(instId)
{
    WIFI_LOGI("Enter WifiProInterface");
}

WifiProInterface::~WifiProInterface()
{
    WIFI_LOGI("Enter ~WifiProInterface");
}

ErrCode WifiProInterface::InitWifiProService()
{
    WIFI_LOGI("Enter InitWifiProService");
    std::lock_guard<std::mutex> lock(mutex_);
    if (pWifiProService_ == nullptr) {
        pWifiProService_ = std::make_shared<WifiProService>(instId_);
        if (pWifiProService_ == nullptr) {
            WIFI_LOGE("Alloc pWifiProService failed.");
            return WIFI_OPT_FAILED;
        }
        InitCallback();
        if (pWifiProService_->InitWifiProService() != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("InitWifiProService failed.");
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

void WifiProInterface::InitCallback()
{
    using namespace std::placeholders;
    WIFI_LOGI("Enter InitCallback");
    staCallback_.callbackModuleName = "WifiProService";
    staCallback_.OnStaConnChanged = [this](OperateResState state, const WifiLinkedInfo &linkedInfo, int32_t instId) {
        this->DealStaConnChanged(state, linkedInfo, instId);
    };
    staCallback_.OnStaRssiLevelChanged = [this](int32_t rssi, int32_t instId) {
        this->DealRssiLevelChanged(rssi, instId);
    };
    staCallback_.OnWifiHalSignalInfoChange = [this](const WifiSignalPollInfo &wifiSignalPollInfo) {
        this->HandleSignalInfoChange(wifiSignalPollInfo);
    };
}

void WifiProInterface::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &linkedInfo, int32_t instId)
{
    WIFI_LOGD("Enter DealStaConnChanged");
    std::lock_guard<std::mutex> lock(mutex_);
    if (pWifiProService_ == nullptr) {
        WIFI_LOGI("pWifiProService is null");
        return;
    }
    pWifiProService_->HandleStaConnChanged(state, linkedInfo);
}

void WifiProInterface::DealRssiLevelChanged(int32_t rssi, int32_t instId)
{
    WIFI_LOGD("Enter DealRssiLevelChanged");
    std::lock_guard<std::mutex> lock(mutex_);
    if (pWifiProService_ == nullptr) {
        WIFI_LOGI("pWifiProService is null");
        return;
    }
    pWifiProService_->HandleRssiLevelChanged(rssi);
}

void WifiProInterface::DealScanResult(const std::vector<InterScanInfo> &results)
{
    WIFI_LOGD("Enter DealScanResult");
    std::lock_guard<std::mutex> lock(mutex_);
    if (pWifiProService_ == nullptr) {
        WIFI_LOGI("pWifiProService is null");
        return;
    }
    pWifiProService_->HandleScanResult(results);
}

void WifiProInterface::DealQoeReport(const NetworkLagType &networkLagType, const NetworkLagInfo &networkLagInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (pWifiProService_ == nullptr) {
        WIFI_LOGI("pWifiProService is null");
        return;
    }
    pWifiProService_->HandleQoeReport(networkLagType, networkLagInfo);
}

void WifiProInterface::HandleSignalInfoChange(const WifiSignalPollInfo &wifiSignalPollInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (pWifiProService_ == nullptr) {
        WIFI_LOGI("HandleSignalInfoChange, pWifiProService is null");
        return;
    }
    pWifiProService_->HandleWifiHalSignalInfoChange(wifiSignalPollInfo);
}

#ifdef FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT
void WifiProInterface::OnScreenStateChanged(int32_t screenState)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (pWifiProService_ == nullptr) {
        WIFI_LOGI("pWifiProService is null");
        return;
    }
    pWifiProService_->OnScreenStateChanged(screenState);
}
 
void WifiProInterface::OnCellInfoUpdated()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (pWifiProService_ == nullptr) {
        WIFI_LOGI("pWifiProService is null");
        return;
    }
    pWifiProService_->OnCellInfoUpdated();
}
 
void WifiProInterface::OnWifiStateOpen(int32_t state)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (pWifiProService_ == nullptr) {
        WIFI_LOGI("pWifiProService is null");
        return;
    }
    pWifiProService_->OnWifiStateOpen(state);
}
 
void WifiProInterface::OnWifiStateClose(int32_t state)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (pWifiProService_ == nullptr) {
        WIFI_LOGI("pWifiProService is null");
        return;
    }
    pWifiProService_->OnWifiStateClose(state);
}
#endif

StaServiceCallback WifiProInterface::GetStaCallback() const
{
    return staCallback_;
}

}  // namespace Wifi
}  // namespace OHOS
