/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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

#include "self_cure_interface.h"
#include "self_cure_service.h"
#include "wifi_logger.h"
#include "ista_service.h"
#include "wifi_service_manager.h"

DEFINE_WIFILOG_LABEL("SelfCureInterface");

namespace OHOS {
namespace Wifi {
SelfCureInterface::SelfCureInterface(int instId) : pSelfCureService(nullptr), m_instId(instId)
{}

SelfCureInterface::~SelfCureInterface()
{
    WIFI_LOGI("SelfCureInterface::~SelfCureInterface");
    std::lock_guard<std::mutex> lock(mutex);
    // unRegister callback func
    IStaService *pService = WifiServiceManager::GetInstance().GetStaServiceInst(0);
    if (pService == nullptr) {
        WIFI_LOGE("Get %{public}s service failed!", WIFI_SERVICE_STA);
    } else {
        pService->UnRegisterStaServiceCallback(mStaCallback);
    }

    if (pSelfCureService != nullptr) {
        delete pSelfCureService;
        pSelfCureService = nullptr;
    }
}

ErrCode SelfCureInterface::InitSelfCureService()
{
    WIFI_LOGD("Enter SelfCureInterface::InitSelfCureService");
    std::lock_guard<std::mutex> lock(mutex);
    if (pSelfCureService == nullptr) {
        pSelfCureService = new (std::nothrow) SelfCureService(m_instId);
        if (pSelfCureService == nullptr) {
            WIFI_LOGE("Alloc pSelfCureService failed.\n");
            return WIFI_OPT_FAILED;
        }
        InitCallback();
        if (pSelfCureService->InitSelfCureService() != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("InitSelfCureService failed.\n");
            delete pSelfCureService;
            pSelfCureService = nullptr;
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode SelfCureInterface::InitCallback()
{
    using namespace std::placeholders;
    WIFI_LOGD("Enter SelfCureInterface::InitCallback");
    mStaCallback.callbackModuleName = "SelfCureService";
    mStaCallback.OnStaConnChanged = [this](OperateResState state, const WifiLinkedInfo &info, int instId) {
        this->DealStaConnChanged(state, info, instId);
    };
    mStaCallback.OnStaRssiLevelChanged = [this](int rssi, int instId) { this->DealRssiLevelChanged(rssi, instId); };
    mStaCallback.OnDhcpOfferReport = [this](const IpInfo &ipInfo, int instId) {
        this->DealDhcpOfferReport(ipInfo, instId);
    };
    return WIFI_OPT_SUCCESS;
}

StaServiceCallback SelfCureInterface::GetStaCallback() const
{
    WIFI_LOGD("self cure GetStaCallback");
    return mStaCallback;
}

ErrCode SelfCureInterface::NotifyInternetFailureDetected(int forceNoHttpCheck)
{
    WIFI_LOGI("Enter %{public}s", __FUNCTION__);
    std::lock_guard<std::mutex> lock(mutex);
    if (pSelfCureService == nullptr) {
        WIFI_LOGI("pSelfCureService is null");
        return WIFI_OPT_FAILED;
    }
    pSelfCureService->NotifyInternetFailureDetected(forceNoHttpCheck);
    return WIFI_OPT_SUCCESS;
}

ErrCode SelfCureInterface::NotifyP2pConnectStateChanged(const WifiP2pLinkedInfo &info)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (pSelfCureService == nullptr) {
        WIFI_LOGI("pSelfCureService is null");
        return WIFI_OPT_FAILED;
    }
    pSelfCureService->NotifyP2pConnectStateChanged(info);
    return WIFI_OPT_SUCCESS;
}

bool SelfCureInterface::IsSelfCureOnGoing()
{
    std::lock_guard<std::mutex> lock(mutex);
    if (pSelfCureService == nullptr) {
        WIFI_LOGI("pSelfCureService is null");
        return false;
    }
    return pSelfCureService->IsSelfCureOnGoing();
}

bool SelfCureInterface::IsSelfCureL2Connecting()
{
    std::lock_guard<std::mutex> lock(mutex);
    if (pSelfCureService == nullptr) {
        WIFI_LOGI("pSelfCureService is null");
        return false;
    }
    return pSelfCureService->IsSelfCureL2Connecting();
}

ErrCode SelfCureInterface::StopSelfCureWifi(int32_t status)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (pSelfCureService == nullptr) {
        WIFI_LOGI("pSelfCureService is null");
        return WIFI_OPT_FAILED;
    }
    pSelfCureService->StopSelfCureWifi(status);
    return WIFI_OPT_SUCCESS;
}

bool SelfCureInterface::CheckSelfCureWifiResult(int event)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (pSelfCureService == nullptr) {
        WIFI_LOGI("pSelfCureService is null");
        return false;
    }
    return pSelfCureService->CheckSelfCureWifiResult(event);
}

bool SelfCureInterface::IsWifiSelfcureDone()
{
    std::lock_guard<std::mutex> lock(mutex);
    if (pSelfCureService == nullptr) {
        WIFI_LOGI("pSelfCureService is null");
        return false;
    }
    return pSelfCureService->IsWifiSelfcureDone();
}

void SelfCureInterface::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (pSelfCureService == nullptr) {
        WIFI_LOGI("pSelfCureService is null");
        return;
    }
    pSelfCureService->HandleStaConnChanged(state, info);
}

void SelfCureInterface::DealDhcpOfferReport(const IpInfo &ipInfo, int instId)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (pSelfCureService == nullptr) {
        WIFI_LOGI("pSelfCureService is null");
        return;
    }
    pSelfCureService->HandleDhcpOfferReport(ipInfo);
}

void SelfCureInterface::DealRssiLevelChanged(int rssi, int instId)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (pSelfCureService == nullptr) {
        WIFI_LOGI("pSelfCureService is null");
        return;
    }
    pSelfCureService->HandleRssiLevelChanged(rssi);
}

ErrCode SelfCureInterface::NotifyIpv6FailureDetected()
{
    WIFI_LOGD("Enter SelfCureInterface::NotifyIpv6FailureDetected");
    std::lock_guard<std::mutex> lock(mutex);
    if (pSelfCureService == nullptr) {
        WIFI_LOGE("pSelfCureService is null");
        return WIFI_OPT_FAILED;
    }
    bool ret = pSelfCureService->NotifyIpv6FailureDetected();
    return ret ? WIFI_OPT_SUCCESS : WIFI_OPT_FAILED;
}
}  // namespace Wifi
}  // namespace OHOS
