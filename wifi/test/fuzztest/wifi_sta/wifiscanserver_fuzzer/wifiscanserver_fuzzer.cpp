/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifiscanserver_fuzzer.h"
#include "wifi_fuzz_common_func.h"
#include "wifi_config_center.h"
#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "securec.h"
#include "define.h"
#include "wifi_log.h"
#include "scan_interface.h"
#include "wifi_internal_msg.h"
#include "scan_service.h"
#include "xml_parser.h"
#include <mutex>
#include "mock_scan_state_machine.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Wifi {
constexpr int THREE = 3;
constexpr int U32_AT_SIZE_ZERO = 4;
constexpr int SIZE = 10;
constexpr int SIZE_NUMBER = 100;
constexpr int NUM_BYTES = 1;

static bool g_isInsted = false;
static std::unique_ptr<ScanService> pScanService = nullptr;
static std::unique_ptr<ScanInterface> pScanInterface = nullptr;

void MyExit()
{
    pScanService.reset();
    pScanInterface.reset();
    sleep(U32_AT_SIZE_ZERO);
    printf("exiting\n");
}

void InitParam()
{
    if (!g_isInsted) {
        pScanService = std::make_unique<ScanService>();
        pScanService->pScanStateMachine = new MockScanStateMachine();
        pScanService->RegisterScanCallbacks(WifiManagers::GetInstance().GetScanCallback());
        pScanInterface = std::make_unique<ScanInterface>();
        if (pScanService == nullptr || pScanInterface) {
            return;
        }
        pScanService->scanTrustMode = true;
        pScanInterface->Init();
        atexit(MyExit);
        g_isInsted = true;
    }
    return;
}

void ScanInterfaceFuzzTest(FuzzedDataProvider& FDP)
{
    int32_t randomInt = FDP.ConsumeIntegral<int32_t>();
    pScanService->scanStartedFlag = true;
    bool state = FDP.ConsumeBool();
    int period = FDP.ConsumeIntegral<int>();
    int interval = FDP.ConsumeIntegral<int>();
    WifiScanParams wifiScanParams;
    wifiScanParams.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    wifiScanParams.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    wifiScanParams.band = static_cast<ScanBandType>(randomInt % SIZE);
    wifiScanParams.freqs.push_back(period);
    pScanInterface->Scan(state);
    pScanInterface->ScanWithParam(wifiScanParams, false);
    pScanInterface->DisableScan(state);
    pScanInterface->OnScreenStateChanged(period);
    pScanInterface->OnStandbyStateChanged(state);
    pScanInterface->OnMovingFreezeStateChange();
    pScanInterface->OnCustomControlStateChanged(period, interval);
    std::map<int, time_t> sceneMap;
    pScanInterface->OnGetCustomSceneState(sceneMap);
    pScanInterface->OnControlStrategyChanged();
    pScanInterface->OnAutoConnectStateChanged(true);
    ScanInnerEventType innerEvent = static_cast<ScanInnerEventType>(static_cast<int>(randomInt) % THREE + 200);
    pScanService->HandleInnerEventReport(innerEvent);
    pScanService->ScanWithParam(wifiScanParams, ScanType::SCAN_TYPE_EXTERN);
    pScanService->StartWifiPnoScan(state, period, interval);
    pScanService->StopPnoScan();
    pScanInterface->StartWifiPnoScan(state, period, interval);
    pScanInterface->OnClientModeStatusChanged(period);
    pScanInterface->SetNetworkInterfaceUpDown(state);
    pScanInterface->SetEnhanceService(nullptr);
}

void SingleScanFuzzTest(FuzzedDataProvider& FDP)
{
    int32_t randomInt = FDP.ConsumeIntegral<int32_t>();
    ScanConfig scanConfig;
    scanConfig.hiddenNetworkSsid.push_back(FDP.ConsumeBytesAsString(FDP.ConsumeIntegral<size_t>()));
    scanConfig.scanFreqs.push_back(static_cast<int>(FDP.ConsumeIntegral<uint8_t>()));
    scanConfig.backScanPeriod = FDP.ConsumeIntegral<int>();
    scanConfig.fullScanFlag = FDP.ConsumeBool();
    scanConfig.scanType = ScanType::SCAN_TYPE_NATIVE_EXTERN;
    scanConfig.scanningWithParamFlag = FDP.ConsumeBool();
    scanConfig.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    scanConfig.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    scanConfig.scanBand = static_cast<ScanBandType>(randomInt % SIZE);
    pScanService->SingleScan(scanConfig);
}

void GetBandFreqsFuzzTest(FuzzedDataProvider& FDP)
{
    int32_t randomInt = FDP.ConsumeIntegral<int32_t>();
    std::vector<int> scanFreqs;
    scanFreqs.push_back(FDP.ConsumeIntegral<int>());
    ScanBandType band = static_cast<ScanBandType>(randomInt % SIZE);
    pScanService->GetBandFreqs(band, scanFreqs);
}

void AddScanMessageBodyFuzzTest(FuzzedDataProvider& FDP)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    InterScanConfig interConfig;
    interConfig.scanFreqs.push_back(FDP.ConsumeIntegral<int>());
    interConfig.hiddenNetworkSsid.push_back(FDP.ConsumeBytesAsString(FDP.ConsumeIntegral<size_t>()));
    interConfig.backScanPeriod = FDP.ConsumeIntegral<int>();
    interConfig.bssidsNumPerScan = FDP.ConsumeIntegral<int>();
    interConfig.maxScansCache = FDP.ConsumeIntegral<int>();
    interConfig.fullScanFlag = FDP.ConsumeBool();
    pScanService->AddScanMessageBody(msg, interConfig);
}

void StoreRequestScanConfigFuzzTest(FuzzedDataProvider& FDP)
{
    StoreScanConfig config;
    config.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.fullScanFlag = FDP.ConsumeBool();
    int appId = FDP.ConsumeIntegral<int>();
    time_t now = time(nullptr);
    int scanStyle = SCAN_DEFAULT_TYPE;
    std::vector<InterScanInfo> infoList;
    pScanService->StoreFullScanInfo(config, infoList);
    pScanService->HandleStaStatusChanged(appId);
    pScanService->HandleNetworkQualityChanged(appId);
    pScanService->HandleCustomStatusChanged(appId, appId);
    pScanService->IsPackageInTrustList(config.ssid, appId, config.bssid);
    ScanIntervalMode scanIntervalMode;
    scanIntervalMode.intervalMode = static_cast<IntervalMode>(FDP.ConsumeIntegral<int>() % U32_AT_SIZE_ZERO);
    scanIntervalMode.isSingle =  FDP.ConsumeBool();
    scanIntervalMode.scanMode = static_cast<ScanMode>(FDP.ConsumeIntegral<int>() % SIZE);
    scanIntervalMode.scanScene = FDP.ConsumeIntegral<int>();
    scanIntervalMode.interval = FDP.ConsumeIntegral<int>();
    scanIntervalMode.count = FDP.ConsumeIntegral<int>();
    pScanService->SystemScanDisconnectedPolicy(appId, appId);
    pScanService->SystemScanConnectedPolicy(appId);
    pScanService->IsPackageInTrustList(config.ssid, appId, config.bssid);
    pScanService->AllowScanByIntervalBlocklist(appId, now, appId, appId, appId);
    pScanService->AllowScanByIntervalContinue(now, appId, appId, appId);
    pScanService->AllowScanByIntervalFixed(appId, now, appId, appId);
    pScanService->AllowFullAppScanByInterval(appId, scanIntervalMode);
    pScanService->AllowSingleAppScanByInterval(appId, scanIntervalMode);
    pScanService->SystemScanByInterval(appId, appId, appId);
    pScanService->PnoScanByInterval(appId, now, appId, appId);
    ScanType scanType = static_cast<ScanType>(FDP.ConsumeIntegral<int>() % THREE);
    pScanService->ApplyTrustListPolicy(scanType);
    pScanService->HandleCustomStatusChanged(appId, appId);
    int status =  (FDP.ConsumeIntegral<int>() % SIZE + 17);
    pScanService->HandleNetworkQualityChanged(status);
    pScanService->HandleNetworkQualityChanged(status);
    WifiConfigCenter::GetInstance().SetScanGenieState(MODE_STATE_CLOSE);
    WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLED));
    pScanService->SystemScanDisconnectedPolicy(appId, appId);
    pScanService->SetNetworkInterfaceUpDown(true);
    pScanService->staStatus = static_cast<int>(OperateResState::CONNECT_CHECK_PORTAL);
    pScanService->HandlePnoScanInfo(infoList);
    pScanService->ReportScanFinishEvent(appId);
    pScanService->StoreUserScanInfo(config, infoList);
    pScanService->Scan(ScanType::SCAN_TYPE_NATIVE_EXTERN);
    pScanService->AllowExternScan(ScanType::SCAN_TYPE_EXTERN, scanStyle);
    pScanService->AllowSystemTimerScan(ScanType::SCAN_TYPE_SYSTEMTIMER, scanStyle);
    pScanService->AllowExternScan(ScanType::SCAN_TYPE_EXTERN, scanStyle);
}

void StoreRequestScanConfigFuzzTest02(FuzzedDataProvider& FDP)
{
    InterScanInfo scanInfoList;
    scanInfoList.channelWidth = static_cast<WifiChannelWidth>(FDP.ConsumeIntegral<int>() % U32_AT_SIZE_ZERO);
    scanInfoList.wifiMode = FDP.ConsumeIntegral<int>();
    scanInfoList.timestamp = FDP.ConsumeIntegral<int64_t>();
    scanInfoList.bssid = FDP.ConsumeBytesAsString(FDP.ConsumeIntegral<size_t>());
    scanInfoList.rssi = FDP.ConsumeIntegral<int>();
    scanInfoList.ssid = FDP.ConsumeBytesAsString(FDP.ConsumeIntegral<size_t>());
    scanInfoList.capabilities = FDP.ConsumeBytesAsString(FDP.ConsumeIntegral<size_t>());
    scanInfoList.frequency = FDP.ConsumeIntegral<int>();
    scanInfoList.features = FDP.ConsumeIntegral<int64_t>();
    ScanStatusReport scanReport;
    scanReport.scanInfoList.push_back(scanInfoList);
    scanReport.requestIndexList.push_back(FDP.ConsumeIntegral<int>());
    scanReport.innerEvent = static_cast<ScanInnerEventType>(FDP.ConsumeIntegral<int>() % THREE + SIZE_NUMBER);
    scanReport.status = static_cast<ScanStatus>(FDP.ConsumeIntegral<int>() % SIZE);
    std::vector<InterScanInfo> infoList;
    infoList.push_back(scanInfoList);
    PnoScanConfig pnoScanConfig;
    pnoScanConfig.scanInterval = FDP.ConsumeIntegral<int>();
    pnoScanConfig.minRssi2Dot4Ghz = FDP.ConsumeIntegral<int>();
    pnoScanConfig.hiddenNetworkSsid.push_back(FDP.ConsumeBytesAsString(FDP.ConsumeIntegral<size_t>()));
    pnoScanConfig.savedNetworkSsid.push_back(FDP.ConsumeBytesAsString(FDP.ConsumeIntegral<size_t>()));
    pnoScanConfig.minRssi5Ghz = FDP.ConsumeIntegral<int>();
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    InterScanConfig interConfig;
    interConfig.scanFreqs.push_back(FDP.ConsumeIntegral<int>());
    interConfig.hiddenNetworkSsid.push_back(FDP.ConsumeBytesAsString(FDP.ConsumeIntegral<size_t>()));
    interConfig.backScanPeriod = FDP.ConsumeIntegral<int>();
    interConfig.bssidsNumPerScan = FDP.ConsumeIntegral<int>();
    interConfig.maxScansCache = FDP.ConsumeIntegral<int>();
    interConfig.fullScanFlag = FDP.ConsumeBool();
    ScanConfig scanConfig;
    interConfig.hiddenNetworkSsid.push_back(FDP.ConsumeBytesAsString(FDP.ConsumeIntegral<size_t>()));
    scanConfig.scanFreqs.push_back(FDP.ConsumeIntegral<int>());
    scanConfig.backScanPeriod = FDP.ConsumeIntegral<int>();
    scanConfig.fullScanFlag = FDP.ConsumeBool();
    scanConfig.scanType = ScanType::SCAN_TYPE_EXTERN;
    scanConfig.scanningWithParamFlag = FDP.ConsumeBool();
    scanConfig.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    scanConfig.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    scanConfig.scanBand = static_cast<ScanBandType>(FDP.ConsumeIntegral<int>() % SIZE);
    interConfig.hiddenNetworkSsid.push_back(FDP.ConsumeBytesAsString(FDP.ConsumeIntegral<size_t>()));
    pScanService->HandleScanStatusReport(scanReport);
    pScanService->AddPnoScanMessageBody(msg, pnoScanConfig);
    pScanService->PnoScan(pnoScanConfig, interConfig);
    pScanService->StoreRequestScanConfig(scanConfig, interConfig);
    pScanService->HandleCommonScanInfo(scanConfig.scanFreqs, infoList);
    pScanService->HandleCommonScanFailed(scanConfig.scanFreqs);
}

void StoreRequestScanConfigFuzzTest03(FuzzedDataProvider& FDP)
{
    std::vector<InterScanInfo> infoList;
    int appId = FDP.ConsumeIntegral<int>();
    ScanIntervalMode scanIntervalMode;
    scanIntervalMode.intervalMode = static_cast<IntervalMode>(FDP.ConsumeIntegral<int>() % U32_AT_SIZE_ZERO);
    scanIntervalMode.isSingle =  FDP.ConsumeBool();
    scanIntervalMode.scanMode = static_cast<ScanMode>(FDP.ConsumeIntegral<int>() % SIZE);
    scanIntervalMode.scanScene = FDP.ConsumeIntegral<int>();
    scanIntervalMode.interval = FDP.ConsumeIntegral<int>();
    scanIntervalMode.count = FDP.ConsumeIntegral<int>();
    SingleAppForbid singleAppForbid;
    singleAppForbid.scanIntervalMode = scanIntervalMode;
    singleAppForbid.expScanCount = FDP.ConsumeIntegral<int>();
    singleAppForbid.fixedScanCount = FDP.ConsumeIntegral<int>();
    singleAppForbid.appID = FDP.ConsumeIntegral<int>();
    pScanService->SetStaCurrentTime();
    pScanService->InitChipsetInfo();
    pScanService->DisconnectedTimerScan();
    pScanService->HandleDisconnectedScanTimeout();
    pScanService->HandleDisconnectedScanTimeout();
    pScanService->DisconnectedTimerScan();
    pScanService->GetScanControlInfo();
    pScanService->HandleDisconnectedScanTimeout();
    pScanService->EndPnoScan();
    pScanService->ReportScanStartEvent();
    pScanService->ReportScanStopEvent();
    pScanService->ExternScanByInterval(appId, singleAppForbid);
    pScanService->ReportStoreScanInfos(infoList);
    pScanService->ReportScanInfos(infoList);
}

void AllowExternScanByForbidFuzzTest(FuzzedDataProvider& FDP)
{
    int randomInt = FDP.ConsumeIntegral<int>();
    int staScene = FDP.ConsumeIntegral<int>();
    int appId = FDP.ConsumeIntegral<int>();
    int state = FDP.ConsumeIntegral<int>();
    int frequency = FDP.ConsumeIntegral<int>();
    int delaySeconds = FDP.ConsumeIntegral<int>();
    int lastStaFreq = FDP.ConsumeIntegral<int>();
    int p2pFreq = FDP.ConsumeIntegral<int>();
    int p2pEnhanceFreq = FDP.ConsumeIntegral<int>();
    int freq = FDP.ConsumeIntegral<int>();
    bool disable = FDP.ConsumeBool();
    const std::string ifName;
    std::vector<int> scanFreqs;
    int scanStyle = SCAN_DEFAULT_TYPE;
    ScanMode scanMode = static_cast<ScanMode>(randomInt % SIZE);
    pScanService->AllowScanDuringScanning(scanMode);
    pScanService->AllowScanByMovingFreeze(scanMode);
    pScanService->IsMovingFreezeState(scanMode);
    pScanService->AllowExternScanByIntervalMode(appId, staScene, scanMode);
    pScanService->SystemScanByInterval(appId, staScene, appId);
    pScanService->P2pEnhanceStateChange(ifName, state, frequency);
    pScanService->DisableScan(disable);
    pScanService->ResetSingleScanCountAndMessage();
    pScanService->AddSingleScanCountAndMessage(delaySeconds);
    pScanService->GetRelatedFreqs(lastStaFreq, p2pFreq, p2pEnhanceFreq);
    pScanService->StartSingleScanWithoutControlTimer();
    pScanService->SelectTheFreqToSingleScan(lastStaFreq, p2pFreq, p2pEnhanceFreq);
    pScanService->StartSingleScanWithoutControl(freq);
    pScanService->RestartSystemScanTimeOut();
    pScanService->Allow5GApScan(ScanType::SCAN_TYPE_5G_AP, scanStyle);
    pScanService->GetSavedNetworkFreq(scanFreqs);
}

void GetAllowBandFreqsControlInfoFuzzTest(FuzzedDataProvider& FDP)
{
    int randomInt = FDP.ConsumeIntegral<int>();
    std::vector<int> freqs;
    freqs.push_back(FDP.ConsumeIntegral<int>());
    freqs.push_back(FDP.ConsumeIntegral<int>());
    ScanBandType scanBand = static_cast<ScanBandType>(randomInt % SIZE);
    pScanService->GetAllowBandFreqsControlInfo(scanBand, freqs);
    pScanService->Delete24GhzFreqs(freqs);
    pScanService->Delete5GhzFreqs(freqs);
    pScanService->ConvertBandNotAllow24G(scanBand);
    pScanService->ConvertBandNotAllow5G(scanBand);
    std::vector<std::string> savedNetworkSsid;
    savedNetworkSsid.push_back(FDP.ConsumeBytesAsString(FDP.ConsumeIntegral<size_t>()));
    pScanService->GetSavedNetworkSsidList(savedNetworkSsid);
    pScanService->GetHiddenNetworkSsidList(savedNetworkSsid);
    pScanService->ResetScanInterval();
}

void BeginPnoScanFuzzTest(FuzzedDataProvider& FDP)
{
    int randomInt = FDP.ConsumeIntegral<int>();
    int scanStyle = SCAN_DEFAULT_TYPE;
    int maxNumberSpatialStreams = FDP.ConsumeIntegral<int>();
    InterScanInfo scanInfoList;
    scanInfoList.channelWidth = static_cast<WifiChannelWidth>(randomInt % U32_AT_SIZE_ZERO);
    scanInfoList.wifiMode = FDP.ConsumeIntegral<int>();
    pScanService->GetWifiMaxSupportedMaxSpeed(scanInfoList, maxNumberSpatialStreams);
    pScanService->BeginPnoScan();
    pScanService->HandleMovingFreezeChanged();
    pScanService->HandleAutoConnectStateChanged(true);
    pScanService->HandleSystemScanTimeout();
    pScanService->RestartPnoScanTimeOut();
    pScanService->AllowExternScan(ScanType::SCAN_TYPE_EXTERN, scanStyle);
    pScanService->AllowPnoScan(ScanType::SCAN_TYPE_PNO, scanStyle);
    pScanService->SetScanTrustMode();
    pScanService->ClearScanTrustSceneIds();
    pScanService->IsMovingFreezeScaned();
    pScanService->IsExternScanning();
    pScanService->IsScanningWithParam();
    pScanService->ClearScanControlValue();
}

void WifiScanServerFuzzerTest(FuzzedDataProvider& FDP)
{
    InitParam();
    ScanInterfaceFuzzTest(FDP);
    SingleScanFuzzTest(FDP);
    GetBandFreqsFuzzTest(FDP);
    AddScanMessageBodyFuzzTest(FDP);
    StoreRequestScanConfigFuzzTest(FDP);
    StoreRequestScanConfigFuzzTest02(FDP);
    StoreRequestScanConfigFuzzTest03(FDP);
    AllowExternScanByForbidFuzzTest(FDP);
    GetAllowBandFreqsControlInfoFuzzTest(FDP);
    BeginPnoScanFuzzTest(FDP);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    OHOS::Wifi::InitParam();
    OHOS::Wifi::WifiScanServerFuzzerTest(FDP);
    return 0;
}
}
}
