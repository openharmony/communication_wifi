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
}

ErrCode StaInterface::EnableStaService()
{
    WIFI_LOGI("Enter EnableStaService.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::DisableStaService()
{
    LOGI("Enter DisableStaService.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::ConnectToNetwork(int networkId, int type)
{
    LOGI("Enter Connect.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::ConnectToDevice(const WifiDeviceConfig &config)
{
    LOGI("Enter Connect.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::StartConnectToBssid(const int32_t networkId, const std::string bssid, int32_t type)
{
    LOGD("Enter StartConnectToBssid");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::OnFoldStateChanged(const int foldStatus)
{
    LOGD("Enter OnFoldStateChanged");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::StartConnectToUserSelectNetwork(int networkId, std::string bssid)
{
    LOGD("Enter StartConnectToUserSelectNetwork");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::ReConnect()
{
    LOGI("Enter ReConnect.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::ReAssociate()
{
    LOGI("Enter ReAssociate.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::Disconnect()
{
    LOGI("Enter Disconnect.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::AddCandidateConfig(const int uid, const WifiDeviceConfig &config, int& netWorkId)
{
    LOGI("Enter AddCandidateConfig.\n");
        return WIFI_OPT_SUCCESS;
}
ErrCode StaInterface::ConnectToCandidateConfig(const int uid, const int networkId)
{
    LOGI("Enter ConnectToCandidateConfig.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RemoveCandidateConfig(const int uid, const int networkId)
{
    LOGI("Enter RemoveCandidateConfig.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RemoveAllCandidateConfig(const int uid)
{
    LOGI("Enter RemoveAllCandidateConfig.\n");
    return WIFI_OPT_SUCCESS;
}

int StaInterface::AddDeviceConfig(const WifiDeviceConfig &config)
{
    LOGI("Enter AddDeviceConfig.\n");
    return pStaService->AddDeviceConfig(config);
}

int StaInterface::UpdateDeviceConfig(const WifiDeviceConfig &config)
{
    LOGI("Enter UpdateDeviceConfig.\n");
    return pStaService->UpdateDeviceConfig(config);
}

ErrCode StaInterface::RemoveDevice(int networkId)
{
    LOGI("Enter RemoveDeviceConfig.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RemoveAllDevice()
{
    LOGI("Enter RemoveAllDevice.\n");
    return WIFI_OPT_SUCCESS;
}
ErrCode StaInterface::EnableDeviceConfig(int networkId, bool attemptEnable)
{
    LOGI("Enter EnableDeviceConfig.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::DisableDeviceConfig(int networkId)
{
    LOGI("Enter DisableDeviceConfig.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::AllowAutoConnect(int32_t networkId, bool isAllowed)
{
    LOGI("Enter AllowAutoConnect.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::StartWps(const WpsConfig &config)
{
    LOGI("Enter StartWps.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::CancelWps()
{
    LOGI("Enter CancelWps.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::ConnectivityManager(const std::vector<InterScanInfo> &scanInfos)
{
    LOGI("Enter Connection management.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RegisterStaServiceCallback(const StaServiceCallback &callbacks)
{
    LOGD("Enter RegisterStaServiceCallback.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::UnRegisterStaServiceCallback(const StaServiceCallback &callbacks)
{
    LOGD("Enter UnRegisterStaServiceCallback.\n");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::SetSuspendMode(bool mode)
{
    LOGI("Enter SetSuspendMode, mode=[%{public}d]!", mode);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::SetPowerMode(bool mode)
{
    LOGI("Enter SetPowerMode, mode=[%{public}d]!", mode);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::OnSystemAbilityChanged(int systemAbilityid, bool add)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::OnScreenStateChanged(int screenState)
{
    WIFI_LOGI("Enter OnScreenStateChanged, screenState=%{public}d.", screenState);
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::DisableAutoJoin(const std::string &conditionName)
{
    LOGI("Enter DisableAutoJoin");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::EnableAutoJoin(const std::string &conditionName)
{
    LOGI("Enter EnableAutoJoin");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RegisterAutoJoinCondition(const std::string &conditionName,
                                                const std::function<bool()> &autoJoinCondition)
{
    LOGI("Enter RegisterAutoJoinCondition");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::DeregisterAutoJoinCondition(const std::string &conditionName)
{
    LOGI("Enter DeregisterAutoJoinCondition");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RegisterFilterBuilder(const FilterTag &filterTag,
                                            const std::string &filterName,
                                            const FilterBuilder &filterBuilder)
{
    LOGI("Enter RegisterFilterBuilder");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::DeregisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName)
{
    LOGI("Enter DeregisterFilterBuilder");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::RegisterCommonBuilder(const TagType &tagType, const std::string &tagName,
                                            const CommonBuilder &commonBuilder)
{
    LOGI("Enter RegisterCommonBuilder");
    return WIFI_OPT_SUCCESS;
}
 
ErrCode StaInterface::DeregisterCommonBuilder(const TagType &tagType, const std::string &tagName)
{
    LOGI("Enter DeregisterCommonBuilder");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::StartPortalCertification()
{
    WIFI_LOGI("Enter StartPortalCertification");
    return WIFI_OPT_SUCCESS;
}

#ifndef OHOS_ARCH_LITE
ErrCode StaInterface::HandleForegroundAppChangedAction(const AppExecFwk::AppStateData &appStateData)
{
    WIFI_LOGD("Enter HandleForegroundAppChangedAction");
    return WIFI_OPT_SUCCESS;
}
#endif

ErrCode StaInterface::EnableHiLinkHandshake(bool uiFlag, const WifiDeviceConfig &config, const std::string &bssid)
{
    WIFI_LOGI("Enter EnableHiLinkHandshake");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::DeliverStaIfaceData(const std::string &currentMac)
{
    WIFI_LOGI("Enter DeliverStaIfaceData");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::SetEnhanceService(IEnhanceService* enhanceService)
{
    WIFI_LOGI("Enter DeliverStaIfaceData");
    return WIFI_OPT_SUCCESS;
}

ErrCode StaInterface::SetSelfCureService(ISelfCureService *selfCureService)
{
    WIFI_LOGI("Enter SetSelfCureService");
    return WIFI_OPT_SUCCESS;
}

bool StaInterface::InitStaServiceLocked()
{
    return true;
}

ErrCode StaInterface::FetchWifiSignalInfoForVoWiFi(VoWifiSignalInfo &signalInfo)
{
    WIFI_LOGI("Enter FetchWifiSignalInfoForVoWiFi");
    return WIFI_OPT_SUCCESS;
}
 
ErrCode StaInterface::IsSupportVoWifiDetect(bool &isSupported)
{
    WIFI_LOGI("Enter IsSupportVoWifiDetect");
    return WIFI_OPT_SUCCESS;
}
 
ErrCode StaInterface::SetVoWifiDetectMode(WifiDetectConfInfo info)
{
    WIFI_LOGI("Enter SetVoWifiDetectMode");
    return WIFI_OPT_SUCCESS;
}
 
ErrCode StaInterface::GetVoWifiDetectMode(WifiDetectConfInfo &info)
{
    WIFI_LOGI("Enter GetVoWifiDetectMode");
    return WIFI_OPT_SUCCESS;
}
 
ErrCode StaInterface::SetVoWifiDetectPeriod(int period)
{
    WIFI_LOGI("Enter SetVoWifiDetectPeriod");
    return WIFI_OPT_SUCCESS;
}
 
ErrCode StaInterface::GetVoWifiDetectPeriod(int &period)
{
    WIFI_LOGI("Enter GetVoWifiDetectPeriod");
    return WIFI_OPT_SUCCESS;
}
 
void StaInterface::ProcessVoWifiNetlinkReportEvent(const int type)
{
    WIFI_LOGI("Enter ProcessVoWifiNetlinkReportEvent");
}
}  // namespace Wifi
}  // namespace OHOS
