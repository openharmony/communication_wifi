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

#include "sta_interface.h"
#include "sta_service.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("StaInterface");

namespace OHOS {
namespace Wifi {
StaInterface::StaInterface(int instId) : pStaService(nullptr), m_instId(instId)
{}

StaInterface::~StaInterface()
{
    WIFI_LOGI("~StaInterface");
    std::lock_guard<std::mutex> lock(mutex);
    if (pStaService != nullptr) {
        delete pStaService;
        pStaService = nullptr;
    }
}

extern "C" IStaService *Create(int instId = 0)
{
    return new (std::nothrow)StaInterface(instId);
}

extern "C" void Destroy(IStaService *pservice)
{
    delete pservice;
    pservice = nullptr;
}

ErrCode StaInterface::EnableWifi()
{
    WIFI_LOGI("Enter EnableWifi.\n");
    std::lock_guard<std::mutex> lock(mutex);
    if(pStaService == nullptr) {
        pStaService = new (std::nothrow) StaService(m_instId);
        if (pStaService == nullptr) {
            WIFI_LOGE("New StaService failed.\n");
            return WIFI_OPT_FAILED;
        }
        if (pStaService->InitStaService(m_staCallback) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("InitStaService failed.\n");
            delete pStaService;
            pStaService = nullptr;
            return WIFI_OPT_FAILED;
        }
    }

    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->EnableWifi() != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("EnableWifi failed.\n");
        DisableWifi();
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::DisableWifi()
{
    LOGD("Enter StaInterface::DisableWifi.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->DisableWifi() != WIFI_OPT_SUCCESS) {
        LOGD("DisableWifi failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::ConnectToNetwork(int networkId)
{
    LOGD("Enter StaInterface::Connect.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->ConnectToNetwork(networkId) != WIFI_OPT_SUCCESS) {
        LOGD("ConnectTo failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::ConnectToDevice(const WifiDeviceConfig &config)
{
    LOGD("Enter StaInterface::Connect.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->ConnectToDevice(config) != WIFI_OPT_SUCCESS) {
        LOGD("ConnectTo failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::ReConnect()
{
    LOGD("Enter StaInterface::ReConnect.");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->ReConnect() != WIFI_OPT_SUCCESS) {
        LOGD("ReConnect failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::ReAssociate()
{
    LOGD("Enter StaInterface::ReAssociate.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->ReAssociate() != WIFI_OPT_SUCCESS) {
        LOGD("ReAssociate failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::Disconnect()
{
    LOGD("Enter StaInterface::Disconnect.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->Disconnect() != WIFI_OPT_SUCCESS) {
        LOGD("Disconnect failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::AddCandidateConfig(const int uid, const WifiDeviceConfig &config, int& netWorkId)
{
    LOGD("Enter StaInterface::AddCandidateConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->AddCandidateConfig(uid, config, netWorkId);
}

ErrCode StaInterface::ConnectToCandidateConfig(const int uid, const int networkId)
{
    LOGD("Enter StaInterface::ConnectToCandidateConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->ConnectToCandidateConfig(uid, networkId) != WIFI_OPT_SUCCESS) {
        LOGE("ConnectToCandidateConfig failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RemoveCandidateConfig(const int uid, const int networkId)
{
    LOGD("Enter StaInterface::RemoveCandidateConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->RemoveCandidateConfig(uid, networkId) != WIFI_OPT_SUCCESS) {
        LOGE("RemoveCandidateConfig failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RemoveAllCandidateConfig(const int uid)
{
    LOGD("Enter StaInterface::RemoveAllCandidateConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->RemoveAllCandidateConfig(uid) != WIFI_OPT_SUCCESS) {
        LOGE("RemoveAllCandidateConfig failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

int StaInterface::AddDeviceConfig(const WifiDeviceConfig &config)
{
    LOGD("Enter StaInterface::AddDeviceConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->AddDeviceConfig(config);
}

int StaInterface::UpdateDeviceConfig(const WifiDeviceConfig &config)
{
    LOGD("Enter StaInterface::UpdateDeviceConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    return pStaService->UpdateDeviceConfig(config);
}

ErrCode StaInterface::RemoveDevice(int networkId)
{
    LOGD("Enter StaInterface::RemoveDeviceConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->RemoveDevice(networkId) != WIFI_OPT_SUCCESS) {
        LOGD("RemoveDeviceConfig failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RemoveAllDevice()
{
    WIFI_LOGD("Enter StaInterface::RemoveAllDevice.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->RemoveAllDevice() != WIFI_OPT_SUCCESS) {
        WIFI_LOGW("RemoveAllDevice failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}
ErrCode StaInterface::EnableDeviceConfig(int networkId, bool attemptEnable)
{
    LOGD("Enter StaInterface::EnableDeviceConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->EnableDeviceConfig(networkId, attemptEnable);
}

ErrCode StaInterface::DisableDeviceConfig(int networkId)
{
    LOGD("Enter StaInterface::DisableDeviceConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->DisableDeviceConfig(networkId);
}

ErrCode StaInterface::StartWps(const WpsConfig &config)
{
    LOGD("Enter StaInterface::StartWps.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->StartWps(config) != WIFI_OPT_SUCCESS) {
        LOGD("StartWps failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::CancelWps()
{
    LOGD("Enter StaInterface::CancelWps.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->CancelWps() != WIFI_OPT_SUCCESS) {
        LOGD("CancelWps failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::ConnectivityManager(const std::vector<InterScanInfo> &scanInfos)
{
    LOGD("Enter Connection management.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->AutoConnectService(scanInfos) != WIFI_OPT_SUCCESS) {
        LOGD("ConnectivityManager failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RegisterStaServiceCallback(const StaServiceCallback &callbacks)
{
    LOGD("Enter StaInterface::RegisterStaServiceCallback.\n");
    for (StaServiceCallback cb : m_staCallback) {
        if (strcasecmp(callbacks.callbackModuleName.c_str(), cb.callbackModuleName.c_str()) == 0) {
            return WIFI_OPT_SUCCESS;
        }
    }
    m_staCallback.push_back(callbacks);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::SetSuspendMode(bool mode)
{
    LOGI("Enter SetSuspendMode, mode=[%{public}d]!", mode);
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->SetSuspendMode(mode) != WIFI_OPT_SUCCESS) {
        LOGE("SetSuspendMode() failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::SetPowerMode(bool mode)
{
    LOGI("Enter SetPowerMode, mode=[%{public}d]!", mode);
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->SetPowerMode(mode) != WIFI_OPT_SUCCESS) {
        LOGE("SetPowerMode() failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::OnSystemAbilityChanged(int systemAbilityid, bool add)
{
    LOGI("Enter OnSystemAbilityChanged, id[%{public}d], mode=[%{public}d]!",
        systemAbilityid, add);
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->OnSystemAbilityChanged(systemAbilityid, add) != WIFI_OPT_SUCCESS) {
        LOGE("OnSystemAbilityChanged() failed!");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::OnScreenStateChanged(int screenState)
{
    WIFI_LOGI("Enter OnScreenStateChanged, screenState=%{public}d.", screenState);

    if (screenState != MODE_STATE_OPEN && screenState != MODE_STATE_CLOSE) {
        WIFI_LOGE("screenState param is error");
        return WIFI_OPT_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->HandleScreenStatusChanged(screenState);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::DisableAutoJoin(const std::string &conditionName)
{
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->DisableAutoJoin(conditionName);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::EnableAutoJoin(const std::string &conditionName)
{
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->EnableAutoJoin(conditionName);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RegisterAutoJoinCondition(const std::string &conditionName,
                                                const std::function<bool()> &autoJoinCondition)
{
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->RegisterAutoJoinCondition(conditionName, autoJoinCondition);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::DeregisterAutoJoinCondition(const std::string &conditionName)
{
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->DeregisterAutoJoinCondition(conditionName);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RegisterFilterBuilder(const FilterTag &filterTag,
                                            const std::string &filterName,
                                            const FilterBuilder &filterBuilder)
{
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->RegisterFilterBuilder(filterTag, filterName, filterBuilder);
}

ErrCode StaInterface::DeregisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName)
{
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->DeregisterFilterBuilder(filterTag, filterName);
}

ErrCode StaInterface::StartPortalCertification()
{
    WIFI_LOGI("Enter StartPortalCertification");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->StartPortalCertification();
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RenewDhcp()
{
    WIFI_LOGI("Enter StaInterface::RenewDhcp");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->RenewDhcp();
    return WIFI_OPT_SUCCESS;
}

#ifndef OHOS_ARCH_LITE
ErrCode StaInterface::HandleForegroundAppChangedAction(const AppExecFwk::AppStateData &appStateData)
{
    WIFI_LOGI("Enter StaInterface::HandleForegroundAppChangedAction");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->HandleForegroundAppChangedAction(appStateData);
    return WIFI_OPT_SUCCESS;
}
#endif

ErrCode StaInterface::EnableHiLinkHandshake(const WifiDeviceConfig &config, const std::string &bssid)
{
    WIFI_LOGI("Enter StaInterface::EnableHiLinkHandshake");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->EnableHiLinkHandshake(config, bssid);
 
    return WIFI_OPT_SUCCESS;
}
 
ErrCode StaInterface::DeliverStaIfaceData(const std::string &currentMac)
{
    WIFI_LOGI("Enter StaInterface::DeliverStaIfaceData");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->DeliverStaIfaceData(currentMac);
    return WIFI_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS
