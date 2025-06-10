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
#include "wifi_common_event_helper.h"

DEFINE_WIFILOG_LABEL("StaInterface");

namespace OHOS {
namespace Wifi {

const uint32_t VDR_VOWIFI_SYNC_REPORT = 302;

StaInterface::StaInterface(int instId) : pStaService(nullptr), m_instId(instId)
{
    WIFI_LOGI("StaInterface constuctor instId %{public}d", instId);
}

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
    return new StaInterface(instId);
}

extern "C" void Destroy(IStaService *pservice)
{
    delete pservice;
    pservice = nullptr;
}

ErrCode StaInterface::EnableStaService()
{
    WIFI_LOGI("Enter EnableStaService m_instId:%{public}d\n", m_instId);
    std::lock_guard<std::mutex> lock(mutex);
    if (!InitStaServiceLocked()) {
        return WIFI_OPT_FAILED;
    }

    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->EnableStaService() != WIFI_OPT_SUCCESS) {
        LOGE("EnableStaService failed m_instId:%{public}d\n", m_instId);
        pStaService->DisableStaService();
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::DisableStaService()
{
    WIFI_LOGI("Enter DisableStaService m_instId:%{public}d\n", m_instId);
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->DisableStaService() != WIFI_OPT_SUCCESS) {
        LOGE("DisableStaService failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::ConnectToNetwork(int networkId, int type)
{
    LOGI("Enter Connect.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->ConnectToNetwork(networkId, type) != WIFI_OPT_SUCCESS) {
        LOGE("ConnectTo failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::ConnectToDevice(const WifiDeviceConfig &config)
{
    LOGI("Enter Connect.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->ConnectToDevice(config) != WIFI_OPT_SUCCESS) {
        LOGE("ConnectTo failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::StartConnectToBssid(const int32_t networkId, const std::string bssid, int32_t type)
{
    LOGD("Enter StartConnectToBssid");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->StartConnectToBssid(networkId, bssid, type) != WIFI_OPT_SUCCESS) {
        LOGI("StartConnectToBssid failed");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::StartConnectToUserSelectNetwork(int networkId, std::string bssid)
{
    LOGD("Enter StartConnectToUserSelectNetwork");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->StartConnectToUserSelectNetwork(networkId, bssid) != WIFI_OPT_SUCCESS) {
        LOGI("StartConnectToUserSelectNetwork failed");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::ReConnect()
{
    LOGI("Enter ReConnect.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->ReConnect() != WIFI_OPT_SUCCESS) {
        LOGE("ReConnect failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::ReAssociate()
{
    LOGI("Enter ReAssociate.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->ReAssociate() != WIFI_OPT_SUCCESS) {
        LOGE("ReAssociate failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::Disconnect()
{
    LOGI("Enter Disconnect.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->Disconnect() != WIFI_OPT_SUCCESS) {
        LOGE("Disconnect failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::AddCandidateConfig(const int uid, const WifiDeviceConfig &config, int& netWorkId)
{
    LOGI("Enter AddCandidateConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->AddCandidateConfig(uid, config, netWorkId);
}

ErrCode StaInterface::ConnectToCandidateConfig(const int uid, const int networkId)
{
    LOGI("Enter ConnectToCandidateConfig.\n");
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
    LOGI("Enter RemoveCandidateConfig.\n");
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
    LOGI("Enter RemoveAllCandidateConfig.\n");
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
    LOGI("Enter AddDeviceConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->AddDeviceConfig(config);
}

#ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
ErrCode StaInterface::SetWifiRestrictedList(const std::vector<WifiRestrictedInfo> &wifiRestrictedInfoList)
{
    LOGI("Enter SetWifiRestrictedList.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->SetWifiRestrictedList(wifiRestrictedInfoList) != WIFI_OPT_SUCCESS) {
        LOGE("SetWifiRestrictedList failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}
#endif

int StaInterface::UpdateDeviceConfig(const WifiDeviceConfig &config)
{
    LOGI("Enter UpdateDeviceConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->UpdateDeviceConfig(config);
}

ErrCode StaInterface::RemoveDevice(int networkId)
{
    LOGI("Enter RemoveDeviceConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->RemoveDevice(networkId) != WIFI_OPT_SUCCESS) {
        LOGE("RemoveDeviceConfig failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RemoveAllDevice()
{
    LOGI("Enter RemoveAllDevice.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->RemoveAllDevice() != WIFI_OPT_SUCCESS) {
        LOGE("RemoveAllDevice failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}
ErrCode StaInterface::EnableDeviceConfig(int networkId, bool attemptEnable)
{
    LOGI("Enter EnableDeviceConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->EnableDeviceConfig(networkId, attemptEnable);
}

ErrCode StaInterface::DisableDeviceConfig(int networkId)
{
    LOGI("Enter DisableDeviceConfig.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->DisableDeviceConfig(networkId);
}

ErrCode StaInterface::AllowAutoConnect(int32_t networkId, bool isAllowed)
{
    LOGI("Enter AllowAutoConnect.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->AllowAutoConnect(networkId, isAllowed);
}

ErrCode StaInterface::StartWps(const WpsConfig &config)
{
    LOGI("Enter StartWps.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->StartWps(config) != WIFI_OPT_SUCCESS) {
        LOGE("StartWps failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::CancelWps()
{
    LOGI("Enter CancelWps.\n");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    if (pStaService->CancelWps() != WIFI_OPT_SUCCESS) {
        LOGE("CancelWps failed.\n");
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
        LOGE("ConnectivityManager failed.\n");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RegisterStaServiceCallback(const StaServiceCallback &callbacks)
{
    LOGD("Enter RegisterStaServiceCallback.\n");
    for (StaServiceCallback cb : m_staCallback) {
        if (strcasecmp(callbacks.callbackModuleName.c_str(), cb.callbackModuleName.c_str()) == 0) {
            return WIFI_OPT_SUCCESS;
        }
    }
    m_staCallback.push_back(callbacks);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::UnRegisterStaServiceCallback(const StaServiceCallback &callbacks)
{
    LOGD("Enter UnRegisterStaServiceCallback.\n");
    std::vector<StaServiceCallback>::iterator iter = m_staCallback.begin();
    while (iter != m_staCallback.end()) {
        if (strcasecmp(callbacks.callbackModuleName.c_str(), iter->callbackModuleName.c_str()) == 0) {
            m_staCallback.erase(iter);
            break;
        }
        iter++;
    }
 
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->UnRegisterStaServiceCallback(callbacks);
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
    LOGI("Enter DisableAutoJoin");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->DisableAutoJoin(conditionName);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::EnableAutoJoin(const std::string &conditionName)
{
    LOGI("Enter EnableAutoJoin");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->EnableAutoJoin(conditionName);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RegisterAutoJoinCondition(const std::string &conditionName,
                                                const std::function<bool()> &autoJoinCondition)
{
    LOGI("Enter RegisterAutoJoinCondition");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->RegisterAutoJoinCondition(conditionName, autoJoinCondition);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::DeregisterAutoJoinCondition(const std::string &conditionName)
{
    LOGI("Enter DeregisterAutoJoinCondition");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->DeregisterAutoJoinCondition(conditionName);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RegisterFilterBuilder(const FilterTag &filterTag,
                                            const std::string &filterName,
                                            const FilterBuilder &filterBuilder)
{
    LOGI("Enter RegisterFilterBuilder");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->RegisterFilterBuilder(filterTag, filterName, filterBuilder);
}

ErrCode StaInterface::DeregisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName)
{
    LOGI("Enter DeregisterFilterBuilder");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->DeregisterFilterBuilder(filterTag, filterName);
}

ErrCode StaInterface::RegisterCommonBuilder(const TagType &tagType, const std::string &tagName,
                                            const CommonBuilder &commonBuilder)
{
    LOGI("Enter RegisterCommonBuilder");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->RegisterCommonBuilder(tagType, tagName, commonBuilder);
}
 
ErrCode StaInterface::DeregisterCommonBuilder(const TagType &tagType, const std::string &tagName)
{
    LOGI("Enter DeregisterCommonBuilder");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->DeregisterCommonBuilder(tagType, tagName);
}

ErrCode StaInterface::StartPortalCertification()
{
    WIFI_LOGI("Enter StartPortalCertification");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->StartPortalCertification();
    return WIFI_OPT_SUCCESS;
}

#ifndef OHOS_ARCH_LITE
ErrCode StaInterface::HandleForegroundAppChangedAction(const AppExecFwk::AppStateData &appStateData)
{
    WIFI_LOGD("Enter HandleForegroundAppChangedAction");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->HandleForegroundAppChangedAction(appStateData);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::SetEnhanceService(IEnhanceService *enhanceService)
{
    WIFI_LOGI("Enter SetEnhanceService");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->SetEnhanceService(enhanceService);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::SetSelfCureService(ISelfCureService *selfCureService)
{
    WIFI_LOGI("Enter SetSelfCureService");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->SetSelfCureService(selfCureService);
    return WIFI_OPT_SUCCESS;
}
#endif

ErrCode StaInterface::EnableHiLinkHandshake(bool uiFlag, const WifiDeviceConfig &config, const std::string &bssid)
{
    WIFI_LOGI("Enter EnableHiLinkHandshake");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->EnableHiLinkHandshake(uiFlag, config, bssid);

    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::DeliverStaIfaceData(const std::string &currentMac)
{
    WIFI_LOGI("Enter DeliverStaIfaceData");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->DeliverStaIfaceData(currentMac);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::DeliverAudioState(int state)
{
    WIFI_LOGI("Enter DeliverAudioState");
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->DeliverAudioState(state);
    return WIFI_OPT_SUCCESS;
}

bool StaInterface::InitStaServiceLocked()
{
    WIFI_LOGI("InitStaServiceLocked m_instId:%{public}d\n", m_instId);
    if (pStaService == nullptr) {
        pStaService = new (std::nothrow) StaService(m_instId);
        if (pStaService == nullptr) {
            WIFI_LOGE("New StaService m_instId:%{public}d\n", m_instId);
            return false;
        }
        if (pStaService->InitStaService(m_staCallback) != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("InitStaService m_instId:%{public}d\n", m_instId);
            delete pStaService;
            pStaService = nullptr;
            return false;
        }
    }
    return true;
}

ErrCode StaInterface::OnFoldStateChanged(const int foldStatus)
{
    WIFI_LOGI("Enter OnFoldStateChanged, foldStatus = %{public}d", foldStatus);
    if (foldStatus != MODE_STATE_EXPAND && foldStatus != MODE_STATE_FOLDED && foldStatus != MODE_STATE_HALF_FOLD) {
        WIFI_LOGE("foldStatus param is error");
        return WIFI_OPT_INVALID_PARAM;
    }
    std::lock_guard<std::mutex> lock(mutex);
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    pStaService->HandleFoldStatusChanged(foldStatus);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::FetchWifiSignalInfoForVoWiFi(VoWifiSignalInfo &signalInfo)
{
    if (pStaService == nullptr) {
        WIFI_LOGE("pStaService is null.");
        return WIFI_OPT_FAILED;
    }
    signalInfo = pStaService->FetchWifiSignalInfoForVoWiFi();
    return WIFI_OPT_SUCCESS;
}
 
ErrCode StaInterface::IsSupportVoWifiDetect(bool &isSupported)
{
    if (pStaService == nullptr) {
        WIFI_LOGE("pStaService is null.");
        return WIFI_OPT_FAILED;
    }
    std::string ret = pStaService->VoWifiDetect("VoWIFI_DETECT VOWIFI_IS_SUPPORT");
    WIFI_LOGD("IsSupportVoWifiDetect ret: %{public}s", ret.c_str());
    isSupported = (!ret.empty() && (ret == "true" || ret == "ok"));
    return WIFI_OPT_SUCCESS;
}
 
ErrCode StaInterface::SetVoWifiDetectMode(WifiDetectConfInfo info)
{
    if (!(m_wifiDetectConfInfo.wifiDetectMode == info.wifiDetectMode &&
        m_wifiDetectConfInfo.envalueCount == info.envalueCount && m_wifiDetectConfInfo.threshold == info.threshold)) {
        m_wifiDetectConfInfo.wifiDetectMode = info.wifiDetectMode;
        m_wifiDetectConfInfo.envalueCount = info.envalueCount;
        m_wifiDetectConfInfo.threshold = info.threshold;
        if (pStaService == nullptr) {
            WIFI_LOGE("SetVoWifiDetectMode: pStaService is null.");
            return WIFI_OPT_FAILED;
        }
        pStaService->ProcessSetVoWifiDetectMode(info);
    }
    return WIFI_OPT_SUCCESS;
}
 
ErrCode StaInterface::GetVoWifiDetectMode(WifiDetectConfInfo &info)
{
    info.wifiDetectMode = m_wifiDetectConfInfo.wifiDetectMode;
    info.envalueCount = m_wifiDetectConfInfo.envalueCount;
    info.threshold = m_wifiDetectConfInfo.threshold;
    return WIFI_OPT_SUCCESS;
}
 
ErrCode StaInterface::SetVoWifiDetectPeriod(int period)
{
    if (period != m_wifiDetectperiod) {
        m_wifiDetectperiod = period;
        if (pStaService == nullptr) {
            WIFI_LOGE("SetVoWifiDetectPeriod: pStaService is null.");
            return WIFI_OPT_FAILED;
        }
        pStaService->ProcessSetVoWifiDetectPeriod(period);
    }
    return WIFI_OPT_SUCCESS;
}
 
ErrCode StaInterface::GetVoWifiDetectPeriod(int &period)
{
    period = m_wifiDetectperiod;
    return WIFI_OPT_SUCCESS;
}
 
void StaInterface::ProcessVoWifiNetlinkReportEvent(const int type)
{
    if (type == VDR_VOWIFI_SYNC_REPORT) {
        if (pStaService == nullptr) {
            WIFI_LOGE("pVoWifiService_ is null.");
            return;
        }
        int index = 0;
        std::string data;
        WifiCommonEventHelper::PublishVoWifiSignalDetectInterruptEvent(index, data);
    }
}

ErrCode StaInterface::GetSignalPollInfoArray(std::vector<WifiSignalPollInfo> &wifiSignalPollInfos, int length)
{
    WIFI_LOGI("Enter GetSignalPollInfoArray");
    CHECK_NULL_AND_RETURN(pStaService, WIFI_OPT_FAILED);
    return pStaService->GetSignalPollInfoArray(wifiSignalPollInfos, length);
}

void StaInterface::GetDetectNetState(OperateResState &state)
{
    pStaService->GetDetectNetState(state);
}
}  // namespace Wifi
}  // namespace OHOS
