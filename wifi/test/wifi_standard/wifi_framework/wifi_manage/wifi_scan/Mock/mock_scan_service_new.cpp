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

#include "scan_service.h"
#include <cinttypes>
#include "wifi_global_func.h"
#include "wifi_internal_msg.h"
#include "wifi_logger.h"
#include "wifi_config_center.h"
#include "wifi_channel_helper.h"
#include "wifi_scan_config.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_common_util.h"
#include "wifi_hisysevent.h"

namespace OHOS {
namespace Wifi {

ScanService::ScanService(int instId)
{}

ScanService::~ScanService()
{
}

bool ScanService::InitScanService(const IScanSerivceCallbacks &scanSerivceCallbacks)
{
    return true;
}

void ScanService::UnInitScanService()
{
    return;
}

void ScanService::RegisterScanCallbacks(const IScanSerivceCallbacks &iScanSerivceCallbacks)
{
    mScanSerivceCallbacks = iScanSerivceCallbacks;
}

void ScanService::SetEnhanceService(IEnhanceService* enhanceService)
{
    mEnhanceService = enhanceService;
}

void ScanService::ResetScanInterval()
{
    return;
}

void ScanService::HandleScanStatusReport(ScanStatusReport &scanStatusReport)
{
    return;
}

void ScanService::HandleInnerEventReport(ScanInnerEventType innerEvent)
{
    return;
}

ErrCode ScanService::Scan(ScanType scanType)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanService::ScanWithParam(const WifiScanParams &params, ScanType scanType)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanService::DisableScan(bool disable)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanService::StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason)
{
    return WIFI_OPT_SUCCESS;
}

void ScanService::StopPnoScan()
{
}

bool ScanService::SingleScan(ScanConfig &scanConfig)
{
    return true;
}

bool ScanService::GetBandFreqs(ScanBandType band, std::vector<int> &freqs)
{
    return false;
}

bool ScanService::AddScanMessageBody(InternalMessagePtr interMessage, const InterScanConfig &interConfig)
{
    return true;
}

int ScanService::StoreRequestScanConfig(const ScanConfig &scanConfig, const InterScanConfig &interConfig)
{
    return scanConfigStoreIndex;
}

void ScanService::HandleCommonScanFailed(std::vector<int> &requestIndexList)
{
    return;
}

void ScanService::HandleCommonScanInfo(
    std::vector<int> &requestIndexList, std::vector<InterScanInfo> &scanInfoList)
{
    return;
}

void ScanService::HandleScanResults(std::vector<int> &requestIndexList, std::vector<InterScanInfo> &scanInfoList,
    bool &fullScanStored)
{
}

int ScanService::GetWifiMaxSupportedMaxSpeed(const InterScanInfo &scanInfo, const int &maxNumberSpatialStreams)
{
    return 0;
}

void ScanService::ConvertScanInfo(WifiScanInfo &scanInfo, const InterScanInfo &interInfo)
{
}

void ScanService::GetWifiRiskType(std::vector<InterScanInfo> &scanInfos)
{
}

void ScanService::MergeScanResult(std::vector<WifiScanInfo> &results, std::vector<WifiScanInfo> &storeInfoList)
{
}

void ScanService::TryToRestoreSavedNetwork()
{
}

bool ScanService::StoreFullScanInfo(
    const StoreScanConfig &scanConfig, std::vector<InterScanInfo> &scanInfoList)
{
    return true;
}

bool ScanService::StoreUserScanInfo(const StoreScanConfig &scanConfig, std::vector<InterScanInfo> &scanInfoList)
{
    return true;
}

void ScanService::ReportScanStartEvent()
{
}

void ScanService::ReportScanStopEvent()
{
}

void ScanService::ReportScanFinishEvent(int event)
{
}

void ScanService::ReportScanInfos(std::vector<InterScanInfo> &interScanList)
{
    return;
}

void ScanService::ReportStoreScanInfos(std::vector<InterScanInfo> &interScanList)
{
    return;
}

bool ScanService::BeginPnoScan()
{
    return true;
}

bool ScanService::PnoScan(const PnoScanConfig &pnoScanConfig, const InterScanConfig &interScanConfig)
{
    return true;
}

bool ScanService::AddPnoScanMessageBody(InternalMessagePtr interMessage, const PnoScanConfig &pnoScanConfig)
{
    return true;
}

void ScanService::HandlePnoScanInfo(std::vector<InterScanInfo> &scanInfoList)
{
    return;
}

void ScanService::EndPnoScan()
{
    return;
}

void ScanService::HandleScreenStatusChanged()
{
    return;
}

void ScanService::HandleStaStatusChanged(int status)
{
    return;
}

void ScanService::HandleNetworkQualityChanged(int status)
{
}

void ScanService::HandleMovingFreezeChanged()
{
}

void ScanService::HandleCustomStatusChanged(int customScene, int customSceneStatus)
{
    return;
}

void ScanService::HandleGetCustomSceneState(std::map<int, time_t>& sceneMap) const
{
}

void ScanService::HandleAutoConnectStateChanged(bool success)
{
    return;
}

void ScanService::SystemScanProcess(bool scanAtOnce)
{
    return;
}

void ScanService::SystemSingleScanProcess()
{
    return;
}

void ScanService::StopSystemScan()
{
    return;
}

void ScanService::StartSystemTimerScan(bool scanAtOnce)
{
    return;
}

void ScanService::HandleSystemScanTimeout()
{
    return;
}

void ScanService::DisconnectedTimerScan()
{
    return;
}

void ScanService::HandleDisconnectedScanTimeout()
{
    return;
}

void ScanService::RestartPnoScanTimeOut()
{
    return;
}

void ScanService::GetScanControlInfo()
{
    return;
}

ErrCode ScanService::AllowExternScan()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanService::AllowSystemTimerScan()
{
    return WIFI_OPT_SUCCESS;
}

ErrCode ScanService::AllowPnoScan()
{
    return WIFI_OPT_SUCCESS;
}

bool ScanService::AllowSystemSingleScan()
{
    return true;
}

ErrCode ScanService::AllowScanByType(ScanType scanType)
{
    return WIFI_OPT_SUCCESS;
}

void ScanService::SetScanTrustMode()
{
}

void ScanService::ResetToNonTrustMode()
{
}

bool ScanService::IsScanTrustMode() const
{
    return true;
}

void ScanService::AddScanTrustSceneId(int sceneId)
{
}

void ScanService::ClearScanTrustSceneIds()
{
}

bool ScanService::IsInScanTrust(int sceneId) const
{
    return false;
}

bool ScanService::IsMovingFreezeState(ScanMode appRunMode) const
{
    return false;
}

bool ScanService::IsMovingFreezeScaned() const
{
    return false;
}

ErrCode ScanService::ApplyTrustListPolicy(ScanType scanType)
{
    return WIFI_OPT_SUCCESS;
}

int ScanService::GetStaScene()
{
    return 0;
}

bool ScanService::IsExternScanning() const
{
    return false;
}

bool ScanService::IsScanningWithParam()
{
    return false;
}

void ScanService::GetAllowBandFreqsControlInfo(ScanBandType &scanBand, std::vector<int> &freqs)
{
    return;
}

ScanBandType ScanService::ConvertBandNotAllow24G(ScanBandType scanBand)
{
    return SCAN_BAND_UNSPECIFIED;
}

ScanBandType ScanService::ConvertBandNotAllow5G(ScanBandType scanBand)
{
    return SCAN_BAND_UNSPECIFIED;
}

void ScanService::Delete24GhzFreqs(std::vector<int> &freqs)
{
    return;
}

void ScanService::Delete5GhzFreqs(std::vector<int> &freqs)
{
    return;
}

bool ScanService::GetSavedNetworkSsidList(std::vector<std::string> &savedNetworkSsid)
{
    return true;
}

bool ScanService::GetHiddenNetworkSsidList(std::vector<std::string> &hiddenNetworkSsid)
{
    return true;
}

void ScanService::ClearScanControlValue()
{
    return;
}

void ScanService::SetStaCurrentTime()
{
    return;
}

bool ScanService::AllowScanDuringScanning(ScanMode scanMode) const
{
    return true;
}

bool ScanService::AllowScanDuringStaScene(int staScene, ScanMode scanMode)
{
    return true;
}

bool ScanService::AllowScanDuringCustomScene(ScanMode scanMode)
{
    return true;
}

bool ScanService::AllowCustomSceneCheck(const std::map<int, time_t>::const_iterator &customIter, ScanMode scanMode)
{
    return true;
}

bool ScanService::AllowExternScanByIntervalMode(int appId, int scanScene, ScanMode scanMode)
{
    return true;
}

bool ScanService::PnoScanByInterval(int &fixedScanCount, time_t &fixedScanTime, int interval, int count)
{
    return true;
}

#ifdef SUPPORT_SCAN_CONTROL
bool ScanService::SystemScanByInterval(int staScene, int &interval, int &count)
{
    return true;
}
#else
bool ScanService::SystemScanByInterval(int &expScanCount, int &interval, int &count)
{
    return true;
}
#endif

bool ScanService::ExternScanByInterval(int appId, SingleAppForbid &singleAppForbid)
{
    return true;
}

bool ScanService::AllowSingleAppScanByInterval(int appId, ScanIntervalMode scanIntervalMode)
{
    return true;
}

bool ScanService::AllowFullAppScanByInterval(int appId, ScanIntervalMode scanIntervalMode)
{
    return true;
}

bool ScanService::AllowScanByIntervalFixed(int &fixedScanCount, time_t &fixedScanTime, int &interval, int &count)
{
    return true;
}

bool ScanService::AllowScanByIntervalExp(int &expScanCount, int &interval, int &count)
{
    return true;
}

bool ScanService::AllowScanByIntervalContinue(time_t &continueScanTime, int &lessThanIntervalCount, int &interval,
    int &count)
{
    return true;
}

bool ScanService::AllowScanByIntervalBlocklist(
    int appId, time_t &blockListScanTime, int &lessThanIntervalCount, int &interval, int &count)
{
    return true;
}

bool ScanService::AllowScanByDisableScanCtrl()
{
    return true;
}

bool ScanService::AllowScanByMovingFreeze(ScanMode appRunMode)
{
    return true;
}

bool ScanService::AllowScanByHid2dState()
{
    return true;
}

bool ScanService::AllowScanByGameScene()
{
    return true;
}

bool ScanService::IsPackageInTrustList(const std::string &trustList, int sceneId,
    const std::string &appPackageName) const
{
    return false;
}

ErrCode ScanService::SetNetworkInterfaceUpDown(bool upDown)
{
    return WIFI_OPT_SUCCESS;
}

bool ScanService::IsAppInFilterList(const std::vector<PackageInfo> &packageFilter) const
{
    return false;
}

void ScanService::SystemScanConnectedPolicy(int &interval)
{
    return;
}

void ScanService::SystemScanDisconnectedPolicy(int &interval, int &count)
{
    return;
}

void ScanService::InitChipsetInfo()
{
    return;
}

#ifndef OHOS_ARCH_LITE
ErrCode ScanService::WifiCountryCodeChangeObserver::OnWifiCountryCodeChanged(const std::string &wifiCountryCode)
{
    return WIFI_OPT_SUCCESS;
}

std::string ScanService::WifiCountryCodeChangeObserver::GetListenerModuleName()
{
    return "";
}
#endif

int CalculateBitPerTone(int snrDb)
{
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS
