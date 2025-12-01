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

namespace OHOS {
namespace Wifi {
constexpr int THREE = 3;
constexpr int TWO = 2;
constexpr int U32_AT_SIZE_ZERO = 4;
constexpr int SIZE = 10;
constexpr int SIZE_NUMBER = 100;
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

void ScanInterfaceFuzzTest(const uint8_t* data, size_t size)
{
    pScanService->scanStartedFlag = true;
    int index = 0;
    bool state = (static_cast<int>(data[0]) % TWO) ? true : false;
    int period = static_cast<int>(data[index++]);
    int interval = static_cast<int>(data[index++]);
    WifiScanParams wifiScanParams;
    wifiScanParams.ssid = std::string(reinterpret_cast<const char*>(data), size);
    wifiScanParams.bssid = std::string(reinterpret_cast<const char*>(data), size);
    wifiScanParams.band = static_cast<ScanBandType>(static_cast<int>(data[0]) % SIZE);
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
    ScanInnerEventType innerEvent = static_cast<ScanInnerEventType>(static_cast<int>(data[0]) % THREE + 200);
    pScanService->HandleInnerEventReport(innerEvent);
    pScanService->ScanWithParam(wifiScanParams, ScanType::SCAN_TYPE_EXTERN);
    pScanService->StartWifiPnoScan(state, period, interval);
    pScanService->StopPnoScan();
    pScanInterface->StartWifiPnoScan(state, period, interval);
    pScanInterface->OnClientModeStatusChanged(period);
    pScanInterface->SetNetworkInterfaceUpDown(state);
    pScanInterface->SetEnhanceService(nullptr);
}

void SingleScanFuzzTest(const uint8_t* data, size_t size)
{
    ScanConfig scanConfig;
    scanConfig.hiddenNetworkSsid.push_back(std::string(reinterpret_cast<const char*>(data), size));
    scanConfig.scanFreqs.push_back(static_cast<int>(data[0]));
    scanConfig.backScanPeriod = static_cast<int>(data[0]);
    scanConfig.fullScanFlag = (static_cast<int>(data[0]) % TWO) ? true : false;
    scanConfig.scanType = ScanType::SCAN_TYPE_NATIVE_EXTERN;
    scanConfig.scanningWithParamFlag = (static_cast<int>(data[0]) % TWO) ? true : false;
    scanConfig.ssid = std::string(reinterpret_cast<const char*>(data), size);
    scanConfig.bssid = std::string(reinterpret_cast<const char*>(data), size);
    scanConfig.scanBand = static_cast<ScanBandType>(static_cast<int>(data[0]) % SIZE);
    pScanService->SingleScan(scanConfig);
}

void GetBandFreqsFuzzTest(const uint8_t* data, size_t size)
{
    std::vector<int> scanFreqs;
    scanFreqs.push_back(static_cast<int>(data[0]));
    ScanBandType band = static_cast<ScanBandType>(static_cast<int>(data[0]) % SIZE);
    pScanService->GetBandFreqs(band, scanFreqs);
}

void AddScanMessageBodyFuzzTest(const uint8_t* data, size_t size)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    int index = 0;
    InterScanConfig interConfig;
    interConfig.scanFreqs.push_back(static_cast<int>(data[0]));
    interConfig.hiddenNetworkSsid.push_back(std::string(reinterpret_cast<const char*>(data), size));
    interConfig.backScanPeriod = static_cast<int>(data[index++]);
    interConfig.bssidsNumPerScan = static_cast<int>(data[index++]);
    interConfig.maxScansCache = static_cast<int>(data[index++]);
    interConfig.fullScanFlag = (static_cast<int>(data[0]) % TWO) ? true : false;
    pScanService->AddScanMessageBody(msg, interConfig);
}

void StoreRequestScanConfigFuzzTest(const uint8_t* data, size_t size)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    int index = 0;
    InterScanConfig interConfig;
    interConfig.scanFreqs.push_back(static_cast<int>(data[0]));
    interConfig.hiddenNetworkSsid.push_back(std::string(reinterpret_cast<const char*>(data), size));
    interConfig.backScanPeriod = static_cast<int>(data[index++]);
    interConfig.bssidsNumPerScan = static_cast<int>(data[index++]);
    interConfig.maxScansCache = static_cast<int>(data[index++]);
    interConfig.fullScanFlag = (static_cast<int>(data[0]) % TWO) ? true : false;
    ScanConfig scanConfig;
    interConfig.hiddenNetworkSsid.push_back(std::string(reinterpret_cast<const char*>(data), size));
    scanConfig.scanFreqs.push_back(static_cast<int>(data[0]));
    scanConfig.backScanPeriod = static_cast<int>(data[0]);
    scanConfig.fullScanFlag = (static_cast<int>(data[0]) % TWO) ? true : false;
    scanConfig.scanType = ScanType::SCAN_TYPE_EXTERN;
    scanConfig.scanningWithParamFlag = (static_cast<int>(data[0]) % TWO) ? true : false;
    scanConfig.ssid = std::string(reinterpret_cast<const char*>(data), size);
    scanConfig.bssid = std::string(reinterpret_cast<const char*>(data), size);
    scanConfig.scanBand = static_cast<ScanBandType>(static_cast<int>(data[0]) % SIZE);
    StoreScanConfig config;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.fullScanFlag = (static_cast<int>(data[0]) % TWO) ? true : false;
    InterScanInfo scanInfoList;
    scanInfoList.channelWidth = static_cast<WifiChannelWidth>(static_cast<int>(data[0]) % U32_AT_SIZE_ZERO);
    scanInfoList.wifiMode = static_cast<int>(data[0]);
    scanInfoList.timestamp = static_cast<int64_t>(data[0]);
    scanInfoList.bssid = std::string(reinterpret_cast<const char*>(data), size);
    scanInfoList.rssi = static_cast<int>(data[0]);
    scanInfoList.ssid = std::string(reinterpret_cast<const char*>(data), size);
    scanInfoList.capabilities = std::string(reinterpret_cast<const char*>(data), size);
    scanInfoList.frequency = static_cast<int>(data[0]);
    scanInfoList.features = static_cast<int64_t>(data[0]);
    int appId = static_cast<int>(data[0]);
    time_t now = time(nullptr);
    int scanStyle = SCAN_DEFAULT_TYPE;
    std::vector<InterScanInfo> infoList;
    infoList.push_back(scanInfoList);
    pScanService->StoreRequestScanConfig(scanConfig, interConfig);
    pScanService->StoreFullScanInfo(config, infoList);
    pScanService->HandleStaStatusChanged(appId);
    pScanService->HandleNetworkQualityChanged(appId);
    pScanService->DisconnectedTimerScan();
    pScanService->HandleDisconnectedScanTimeout();
    pScanService->AllowExternScan(ScanType::SCAN_TYPE_EXTERN, scanStyle);
    pScanService->HandleCustomStatusChanged(appId, appId);
    pScanService->IsPackageInTrustList(config.ssid, appId, config.bssid);
    ScanStatusReport scanReport;
    scanReport.scanInfoList.push_back(scanInfoList);
    scanReport.requestIndexList.push_back(static_cast<int>(data[0]));
    scanReport.innerEvent = static_cast<ScanInnerEventType>(static_cast<int>(data[0]) % THREE + SIZE_NUMBER);
    scanReport.status = static_cast<ScanStatus>(static_cast<int>(data[0]) % SIZE);
    ScanIntervalMode scanIntervalMode;
    scanIntervalMode.intervalMode = static_cast<IntervalMode>(static_cast<int>(data[0]) % U32_AT_SIZE_ZERO);
    scanIntervalMode.isSingle =  (static_cast<int>(data[0]) % TWO) ? true : false;
    scanIntervalMode.scanMode = static_cast<ScanMode>(static_cast<int>(data[0]) % SIZE);
    scanIntervalMode.scanScene = static_cast<int>(data[0]);
    scanIntervalMode.interval = static_cast<int>(data[0]);
    scanIntervalMode.count = static_cast<int>(data[0]);
    SingleAppForbid singleAppForbid;
    singleAppForbid.scanIntervalMode = scanIntervalMode;
    singleAppForbid.expScanCount = static_cast<int>(data[0]);
    singleAppForbid.fixedScanCount = static_cast<int>(data[0]);
    singleAppForbid.appID = static_cast<int>(data[0]);
    pScanService->InitChipsetInfo();
    pScanService->SystemScanDisconnectedPolicy(appId, appId);
    pScanService->SystemScanConnectedPolicy(appId);
    pScanService->IsPackageInTrustList(config.ssid, appId, config.bssid);
    pScanService->AllowScanByIntervalBlocklist(appId, now, appId, appId, appId);
    pScanService->AllowScanByIntervalContinue(now, appId, appId, appId);
    pScanService->AllowScanByIntervalFixed(appId, now, appId, appId);
    pScanService->AllowFullAppScanByInterval(appId, scanIntervalMode);
    pScanService->AllowSingleAppScanByInterval(appId, scanIntervalMode);
    pScanService->ExternScanByInterval(appId, singleAppForbid);
    pScanService->SystemScanByInterval(appId, appId, appId);
    pScanService->PnoScanByInterval(appId, now, appId, appId);
    pScanService->SetStaCurrentTime();
    ScanType scanType = static_cast<ScanType>(static_cast<int>(data[0]) % THREE);
    pScanService->ApplyTrustListPolicy(scanType);
    pScanService->AllowExternScan(ScanType::SCAN_TYPE_EXTERN, scanStyle);
    pScanService->HandleDisconnectedScanTimeout();
    pScanService->DisconnectedTimerScan();
    pScanService->HandleCustomStatusChanged(appId, appId);
    int status =  (static_cast<int>(data[0]) % SIZE + 17);
    pScanService->HandleNetworkQualityChanged(status);
    pScanService->HandleNetworkQualityChanged(status);
    PnoScanConfig pnoScanConfig;
    pnoScanConfig.scanInterval = static_cast<int>(data[0]);
    pnoScanConfig.minRssi2Dot4Ghz = static_cast<int>(data[0]);
    pnoScanConfig.hiddenNetworkSsid.push_back(std::string(reinterpret_cast<const char*>(data), size));
    pnoScanConfig.savedNetworkSsid.push_back(std::string(reinterpret_cast<const char*>(data), size));
    pnoScanConfig.minRssi5Ghz = static_cast<int>(data[0]);
    WifiConfigCenter::GetInstance().SetScanGenieState(MODE_STATE_CLOSE);
    WifiConfigCenter::GetInstance().SetWifiState(static_cast<int>(WifiState::ENABLED));
    pScanService->SystemScanDisconnectedPolicy(appId, appId);
    pScanService->SetNetworkInterfaceUpDown(true);
    pScanService->staStatus = static_cast<int>(OperateResState::CONNECT_CHECK_PORTAL);
    pScanService->AllowSystemTimerScan(ScanType::SCAN_TYPE_SYSTEMTIMER, scanStyle);
    pScanService->AllowExternScan(ScanType::SCAN_TYPE_EXTERN, scanStyle);
    pScanService->GetScanControlInfo();
    pScanService->HandleDisconnectedScanTimeout();
    pScanService->EndPnoScan();
    pScanService->HandlePnoScanInfo(infoList);
    pScanService->AddPnoScanMessageBody(msg, pnoScanConfig);
    pScanService->PnoScan(pnoScanConfig, interConfig);
    pScanService->ReportScanStartEvent();
    pScanService->ReportStoreScanInfos(infoList);
    pScanService->ReportScanInfos(infoList);
    pScanService->ReportScanFinishEvent(appId);
    pScanService->ReportScanStopEvent();
    pScanService->StoreUserScanInfo(config, infoList);
    pScanService->HandleCommonScanInfo(scanConfig.scanFreqs, infoList);
    pScanService->HandleCommonScanFailed(scanConfig.scanFreqs);
    pScanService->Scan(ScanType::SCAN_TYPE_NATIVE_EXTERN);
    pScanService->HandleScanStatusReport(scanReport);
}

void AllowExternScanByForbidFuzzTest(const uint8_t* data, size_t size)
{
    int staScene = static_cast<int>(data[0]);
    int appId = static_cast<int>(data[0]);
    int scanStyle = SCAN_DEFAULT_TYPE;
    ScanMode scanMode = static_cast<ScanMode>(static_cast<int>(data[0]) % SIZE);
    pScanService->AllowScanDuringScanning(scanMode);
    pScanService->AllowScanByMovingFreeze(scanMode);
    pScanService->IsMovingFreezeState(scanMode);
    pScanService->AllowExternScanByIntervalMode(appId, staScene, scanMode);
    pScanService->SystemScanByInterval(appId, staScene, appId);
    pScanService->Allow5GApScan(ScanType::SCAN_TYPE_5G_AP, scanStyle);
}

void GetAllowBandFreqsControlInfoFuzzTest(const uint8_t* data, size_t size)
{
    std::vector<int> freqs;
    freqs.push_back(static_cast<int>(data[0]));
    freqs.push_back(static_cast<int>(data[1]));
    ScanBandType scanBand = static_cast<ScanBandType>(static_cast<int>(data[0]) % SIZE);
    pScanService->GetAllowBandFreqsControlInfo(scanBand, freqs);
    pScanService->Delete24GhzFreqs(freqs);
    pScanService->Delete5GhzFreqs(freqs);
    pScanService->ConvertBandNotAllow24G(scanBand);
    pScanService->ConvertBandNotAllow5G(scanBand);
    std::vector<std::string> savedNetworkSsid;
    savedNetworkSsid.push_back(std::string(reinterpret_cast<const char*>(data), size));
    pScanService->GetSavedNetworkSsidList(savedNetworkSsid);
    pScanService->GetHiddenNetworkSsidList(savedNetworkSsid);
}

void BeginPnoScanFuzzTest(const uint8_t* data, size_t size)
{
    int maxNumberSpatialStreams = static_cast<int>(data[0]);
    int scanStyle = SCAN_DEFAULT_TYPE;
    InterScanInfo scanInfoList;
    scanInfoList.channelWidth = static_cast<WifiChannelWidth>(static_cast<int>(data[0]) % U32_AT_SIZE_ZERO);
    scanInfoList.wifiMode = static_cast<int>(data[0]);
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

void WifiScanServerFuzzerTest(const uint8_t* data, size_t size)
{
    InitParam();
    ScanInterfaceFuzzTest(data, size);
    SingleScanFuzzTest(data, size);
    GetBandFreqsFuzzTest(data, size);
    AddScanMessageBodyFuzzTest(data, size);
    StoreRequestScanConfigFuzzTest(data, size);
    AllowExternScanByForbidFuzzTest(data, size);
    GetAllowBandFreqsControlInfoFuzzTest(data, size);
    BeginPnoScanFuzzTest(data, size);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    OHOS::Wifi::InitParam();
    OHOS::Wifi::WifiScanServerFuzzerTest(data, size);
    return 0;
}
}
}
