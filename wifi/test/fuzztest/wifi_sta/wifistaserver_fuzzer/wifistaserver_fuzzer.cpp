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

#include "wifistaserver_fuzzer.h"
#include "wifi_fuzz_common_func.h"
#include "mock_sta_state_machine.h"
#include "wifi_config_center.h"
#include "wifi_security_detect.h"
#include "wifi_security_detect_observer.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "securec.h"
#include "define.h"
#include "wifi_log.h"
#include "sta_interface.h"
#include "sta_auto_connect_service.h"
#include "wifi_settings.h"
#include "sta_service.h"
#include "wifi_internal_msg.h"
#include "wifi_telephony_utils.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <mutex>

namespace OHOS {
namespace Wifi {
constexpr int U32_AT_SIZE_ZERO = 4;
constexpr int ZERO = 0;
constexpr int ONE = 1;
constexpr int TWO = 2;
constexpr int THREE = 3;
constexpr int FOUR = 4;
constexpr int FIVE = 5;
constexpr int ID = 123;
constexpr int WORK_ID = 10;
static bool g_isInsted = false;
constexpr int STATE = 20;
constexpr int32_t STATE_NUM = 3;
const int MODEL_ID_1001 = 1001;
const int MODEL_ID_1002 = 1002;
const int MODEL_ID_1003 = 1003;
const int MODEL_ID_1004 = 1004;
const int MODEL_ID_1005 = 1005;
static const int32_t NUM_BYTES = 1;
static std::unique_ptr<StaInterface> pStaInterface = nullptr;
static std::unique_ptr<StaAutoConnectService> pStaAutoConnectService = nullptr;
static std::unique_ptr<StaService> pStaService = nullptr;
static std::unique_ptr<IWifiCountryCodeChangeListener> pStaObserver = nullptr;
StaServiceCallback mStaCallback;

void MyExit()
{
    pStaInterface.reset();
    pStaAutoConnectService.reset();
    pStaObserver.reset();
    pStaService.reset();
    sleep(U32_AT_SIZE_ZERO);
    printf("exiting\n");
}

bool InitParam()
{
    if (!g_isInsted) {
        pStaService = std::make_unique<StaService>();
        pStaService->pStaStateMachine = new MockStaStateMachine();
        pStaService->pStaAutoConnectService = new StaAutoConnectService(pStaService->pStaStateMachine);
        pStaInterface = std::make_unique<StaInterface>();
        pStaAutoConnectService = std::make_unique<StaAutoConnectService>(pStaService->pStaStateMachine);
        atexit(MyExit);
        g_isInsted = true;
    }
    return true;
}

class WifiStaServerManager {
public:
    WifiStaServerManager()
    {
        InitStaServercallback();
    }
    ~WifiStaServerManager() {}
    void DealStaOpen(OperateResState operateResState, int data) {}
    void DealStaClose(OperateResState operateResState, int data) {}
    void DealStaConn(OperateResState operateResState, const WifiLinkedInfo &info, int data) {}
    void DealWps(WpsStartState wpsStartState, const int wpsData, int data) {}
    void DealStaStream(StreamDirection streamDirection, int data) {}
    void DealStaRssiLevel(int temp, int data) {}
    void DealStaSemActive(OperateResState operateResState, int data) {}
    StaServiceCallback& GetStaCallback(void)
    {
        return mStaCallback;
    }

    void InitStaServercallback(void)
    {
        mStaCallback.callbackModuleName = "WifiStaServerManager";
        mStaCallback.OnStaOpenRes = std::bind(&WifiStaServerManager::DealStaOpen, this, std::placeholders::_1,
            std::placeholders::_2);
        mStaCallback.OnStaCloseRes = std::bind(&WifiStaServerManager::DealStaClose, this, std::placeholders::_1,
            std::placeholders::_2);
        mStaCallback.OnStaConnChanged = std::bind(&WifiStaServerManager::DealStaConn, this, std::placeholders::_1,
            std::placeholders::_2, std::placeholders::_3);
        mStaCallback.OnWpsChanged = std::bind(&WifiStaServerManager::DealWps, this, std::placeholders::_1,
            std::placeholders::_2, std::placeholders::_3);
        mStaCallback.OnStaStreamChanged = std::bind(&WifiStaServerManager::DealStaStream, this, std::placeholders::_1,
            std::placeholders::_2);
        mStaCallback.OnStaRssiLevelChanged = std::bind(&WifiStaServerManager::DealStaRssiLevel, this,
            std::placeholders::_1, std::placeholders::_2);
        mStaCallback.OnStaSemiActiveRes = std::bind(&WifiStaServerManager::DealStaSemActive, this,
            std::placeholders::_1, std::placeholders::_2);
        return;
    }
};

void StaServerFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    int index = 0;
    constexpr int blockDurationSize = sizeof(int64_t);
    int64_t blockDuration = -1;
    if (index + blockDurationSize <= static_cast<int>(size)) {
        blockDuration = *reinterpret_cast<const int64_t*>(&data[index]);
        index += blockDurationSize;
    }
    int networkId = FDP.ConsumeIntegral<int>();
    int uid = FDP.ConsumeIntegral<int>();
    bool attemptEnable = FDP.ConsumeBool();
    bool isRemoveAll = FDP.ConsumeBool();
    bool isAllowed = FDP.ConsumeBool();
    std::string cmd = FDP.ConsumeBytesAsString(NUM_BYTES);
    std::string conditionName = FDP.ConsumeBytesAsString(NUM_BYTES);
    FilterTag filterTag = static_cast<FilterTag>(FDP.ConsumeIntegral<int>() % FIVE);
    ConfigChange value = static_cast<ConfigChange>(FDP.ConsumeIntegral<int>() % U32_AT_SIZE_ZERO);
    WpsConfig sconfig;
    sconfig.pin = FDP.ConsumeBytesAsString(NUM_BYTES);
    sconfig.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    sconfig.setup = static_cast<SetupMethod>(FDP.ConsumeIntegral<int>() % FIVE);
    WifiDeviceConfig config;
    config.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.eap = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.clientCert = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.privateKey = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.certEntry.push_back(FDP.ConsumeIntegral<uint8_t>());
    config.wifiEapConfig.encryptedData = FDP.ConsumeBytesAsString(NUM_BYTES);
    pStaInterface->ConnectToNetwork(networkId);
    pStaInterface->ConnectToDevice(config);
    pStaInterface->ReConnect();
    pStaInterface->ReAssociate();
    pStaInterface->Disconnect();
    pStaInterface->AddCandidateConfig(uid, config, networkId);
    pStaInterface->ConnectToCandidateConfig(uid, networkId);
    pStaInterface->RemoveCandidateConfig(uid, networkId);
    pStaInterface->RemoveAllCandidateConfig(uid);
    pStaInterface->AddDeviceConfig(config);
    pStaInterface->UpdateDeviceConfig(config);
    pStaInterface->RemoveDevice(networkId);
    pStaInterface->RemoveAllDevice();
    pStaInterface->EnableDeviceConfig(networkId, attemptEnable);
    pStaInterface->DisableDeviceConfig(networkId, blockDuration);
    pStaInterface->StartWps(sconfig);
    pStaInterface->CancelWps();
    std::vector<InterScanInfo> results;
    pStaInterface->ConnectivityManager(results);
    pStaInterface->SetSuspendMode(attemptEnable);
    pStaInterface->SetPowerMode(attemptEnable);
    pStaInterface->OnSystemAbilityChanged(networkId, attemptEnable);
    pStaInterface->OnScreenStateChanged(networkId);
    pStaInterface->DeregisterAutoJoinCondition(conditionName);
    pStaInterface->DeliverStaIfaceData(conditionName);
    pStaInterface->DisableStaService();
    pStaInterface->StartConnectToBssid(networkId, config.bssid);
    pStaInterface->DisableAutoJoin(config.keyMgmt);
    pStaInterface->EnableAutoJoin(conditionName);
    pStaInterface->StartPortalCertification();
    pStaInterface->EnableHiLinkHandshake(true, config, conditionName);
    pStaInterface->StartWifiDetection();
    pStaInterface->DeregisterFilterBuilder(filterTag, conditionName);
    pStaInterface->AllowAutoConnect(networkId, isAllowed);
    pStaInterface->EnableStaService();
    pStaInterface->StartConnectToUserSelectNetwork(networkId, config.bssid);
    TagType tagType = static_cast<TagType>(data[index++]);
    std::string tagName;
    CommonBuilder commonBuilder;
    pStaInterface->RegisterCommonBuilder(tagType, tagName, commonBuilder);
    pStaInterface->DeregisterCommonBuilder(tagType, tagName);
    pStaInterface->DeliverAudioState(networkId);
    pStaInterface->InitStaServiceLocked();
    pStaInterface->OnFoldStateChanged(networkId);
    VoWifiSignalInfo signalInfo;
    pStaInterface->FetchWifiSignalInfoForVoWiFi(signalInfo);
    pStaInterface->IsSupportVoWifiDetect(isAllowed);
    WifiDetectConfInfo wifiDetectConfInfo;
    pStaInterface->SetVoWifiDetectMode(wifiDetectConfInfo);
    pStaInterface->GetVoWifiDetectMode(wifiDetectConfInfo);
    pStaInterface->SetVoWifiDetectPeriod(networkId);
    pStaInterface->GetVoWifiDetectPeriod(networkId);
    pStaInterface->ProcessVoWifiNetlinkReportEvent(networkId);
    pStaInterface->OnBatteryStateChanged(networkId);
    std::vector<WifiSignalPollInfo> wifiSignalPollInfos = {};
    pStaInterface->GetSignalPollInfoArray(wifiSignalPollInfos, networkId);
    OperateResState state;
    pStaInterface->GetDetectNetState(state);
    pStaService->StartConnectToUserSelectNetwork(networkId, config.bssid);
    pStaService->AllowAutoConnect(networkId, isAllowed);
    pStaService->HandleScreenStatusChanged(networkId);
    pStaService->RegisterCommonBuilder(tagType, tagName, commonBuilder);
    pStaService->DeregisterCommonBuilder(tagType, tagName);
    pStaService->DeliverAudioState(networkId);
    pStaService->HandleFoldStatusChanged(networkId);
    pStaService->VoWifiDetect(cmd);
    pStaService->FetchWifiSignalInfoForVoWiFi();
    pStaService->ConvertToAccessType(networkId, uid);
    pStaService->ProcessSetVoWifiDetectMode(wifiDetectConfInfo);
    pStaService->ProcessSetVoWifiDetectPeriod(networkId);
    pStaService->GetSignalPollInfoArray(wifiSignalPollInfos, networkId);
    pStaService->VoWifiDetectSet(cmd);
    pStaService->GetDetectNetState(state);
    pStaService->UpdateEapConfig(config, config.wifiEapConfig);
    pStaService->RemoveCandidateConfig(uid, networkId);
    pStaService->FindDeviceConfig(config, config);
    pStaService->OnSystemAbilityChanged(networkId, attemptEnable);
    pStaService->NotifyDeviceConfigChange(value, config, isRemoveAll);
    pStaService->AddCandidateConfig(uid, config, networkId);
    pStaService->RemoveAllCandidateConfig(uid);
    pStaService->ConnectToCandidateConfig(uid, networkId);
    pStaService->UpdateDeviceConfig(config);
    pStaService->RemoveDevice(networkId);
    pStaService->RemoveAllDevice();
    pStaService->ConnectToDevice(config);
    pStaService->ConnectToNetwork(networkId);
    pStaService->StartConnectToBssid(networkId, config.bssid);
    pStaService->ReAssociate();
    pStaService->EnableDeviceConfig(networkId, attemptEnable);
    pStaInterface->DisableDeviceConfig(networkId, blockDuration);
    pStaService->Disconnect();
    pStaService->StartWps(sconfig);
    pStaService->CancelWps();
    pStaService->ReConnect();
    pStaService->SetSuspendMode(attemptEnable);
    pStaService->SetPowerMode(attemptEnable);
    pStaService->DisableAutoJoin(conditionName);
    pStaService->EnableAutoJoin(conditionName);
    pStaService->StartPortalCertification();
    pStaService->EnableHiLinkHandshake(true, config, conditionName);
    pStaService->StartWifiDetection();
    pStaService->DeliverStaIfaceData(conditionName);
    WifiTelephonyUtils::GetDataSlotId(index);
    pStaService->AddDeviceConfig(config);
    pStaService->HandleBatteryStatusChanged(networkId);
}

void StaAutoServerFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    std::string conditionName = FDP.ConsumeBytesAsString(NUM_BYTES);
    bool attemptEnable = FDP.ConsumeBool();
    int frequency = FDP.ConsumeIntegral<int>();
    InterScanInfo scanInfoList;
    scanInfoList.channelWidth = static_cast<WifiChannelWidth>(FDP.ConsumeIntegral<int>() % U32_AT_SIZE_ZERO);
    scanInfoList.wifiMode = FDP.ConsumeIntegral<int>();
    scanInfoList.timestamp = FDP.ConsumeIntegral<int64_t>();
    scanInfoList.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    scanInfoList.rssi = FDP.ConsumeIntegral<int>();
    scanInfoList.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    scanInfoList.capabilities = FDP.ConsumeBytesAsString(NUM_BYTES);
    scanInfoList.frequency = FDP.ConsumeIntegral<int>();
    scanInfoList.features = FDP.ConsumeIntegral<int64_t>();
    std::vector<InterScanInfo> scanInfo;
    scanInfo.push_back(scanInfoList);
    WifiLinkedInfo info;
    if (size >= sizeof(WifiLinkedInfo)) {
        info.networkId = FDP.ConsumeIntegral<int>();
        info.rssi = FDP.ConsumeIntegral<int>();
        info.band = FDP.ConsumeIntegral<int>();
        info.linkSpeed = FDP.ConsumeIntegral<int>();
        info.frequency = FDP.ConsumeIntegral<int>();
        info.macType = FDP.ConsumeIntegral<int>();
        info.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
        info.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
        info.macAddress = FDP.ConsumeBytesAsString(NUM_BYTES);
        info.detailedState = static_cast<DetailedState>(FDP.ConsumeIntegral<int>() % STATE);
    }

    WifiDeviceConfig config;
    config.bssid = scanInfoList.bssid;
    config.ssid = scanInfoList.ssid;
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> blocklistBssids;
    std::vector<StaServiceCallback> callbacks;
    NetworkSelectionResult candidate;
    blocklistBssids.push_back(std::string(reinterpret_cast<const char*>(data), size));
    WifiSettings::GetInstance().AddDeviceConfig(config);
    WifiConfigCenter::GetInstance().SaveLinkedInfo(info);
    pStaAutoConnectService->IsAllowAutoJoin();
    pStaAutoConnectService->DeregisterAutoJoinCondition(conditionName);
    pStaAutoConnectService->EnableAutoJoin(conditionName);
    pStaAutoConnectService->Whether24GDevice(frequency);
    pStaAutoConnectService->Whether5GDevice(frequency);
    pStaAutoConnectService->CurrentDeviceGoodEnough(scanInfo, info);
    pStaAutoConnectService->AllowAutoSelectDevice(scanInfo, info);
    pStaAutoConnectService->AllowAutoSelectDevice(info);
    pStaAutoConnectService->RoamingEncryptionModeCheck(config, scanInfoList, info);
    pStaAutoConnectService->RoamingSelection(config, scanInfo, info);
    pStaAutoConnectService->EnableOrDisableBssid(conditionName, attemptEnable, frequency);
    pStaAutoConnectService->firmwareRoamFlag = true;
    pStaAutoConnectService->WhetherDevice5GAvailable(scanInfo);
    pStaAutoConnectService->GetAvailableScanInfos(scanInfo, scanInfo, blocklistBssids, info);
    pStaAutoConnectService->InitAutoConnectService();
    pStaAutoConnectService->SetAutoConnectStateCallback(callbacks);
    pStaAutoConnectService->OverrideCandidateWithUserSelectChoice(candidate);
    pStaAutoConnectService->IsAutoConnectFailByP2PEnhanceFilter(scanInfo);
}

void RegisterDeviceAppraisalTest(FuzzedDataProvider& FDP)
{
    StaDeviceAppraisal *appraisal = nullptr;
    int priority = FDP.ConsumeIntegralInRange<int>(0, STATE_NUM);
    pStaAutoConnectService->RegisterDeviceAppraisal(appraisal, priority);
}

void AllowAutoSelectDeviceTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    InterScanInfo scanInfoList;
    scanInfoList.channelWidth = static_cast<WifiChannelWidth>(FDP.ConsumeIntegral<int>() % U32_AT_SIZE_ZERO);
    scanInfoList.wifiMode = FDP.ConsumeIntegral<int>();
    scanInfoList.timestamp = FDP.ConsumeIntegral<int64_t>();
    scanInfoList.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    scanInfoList.rssi = FDP.ConsumeIntegral<int>();
    scanInfoList.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    scanInfoList.capabilities = FDP.ConsumeBytesAsString(NUM_BYTES);
    scanInfoList.features = FDP.ConsumeIntegral<int64_t>();
    std::vector<InterScanInfo> scanInfo;
    scanInfo.push_back(scanInfoList);
    WifiLinkedInfo info;
    if (size >= sizeof(WifiLinkedInfo)) {
        info.networkId = FDP.ConsumeIntegral<int>();
        info.rssi = FDP.ConsumeIntegral<int>();
        info.band = FDP.ConsumeIntegral<int>();
        info.linkSpeed = FDP.ConsumeIntegral<int>();
        info.macType = FDP.ConsumeIntegral<int>();
        info.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
        info.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
        info.macAddress = FDP.ConsumeBytesAsString(NUM_BYTES);
    }
    info.detailedState = DetailedState::WORKING;
    pStaAutoConnectService->AllowAutoSelectDevice(scanInfo, info);
    info.detailedState = DetailedState::CONNECTION_FULL;
    pStaAutoConnectService->AllowAutoSelectDevice(scanInfo, info);
    info.detailedState = DetailedState::PASSWORD_ERROR;
    pStaAutoConnectService->AllowAutoSelectDevice(scanInfo, info);
    info.detailedState = DetailedState::NOTWORKING;
    pStaAutoConnectService->AllowAutoSelectDevice(scanInfo, info);
}

void StaAutoConnectServiceFuzzTest(FuzzedDataProvider& FDP)
{
    std::string conditionName = FDP.ConsumeBytesAsString(NUM_BYTES);
    pStaAutoConnectService->RegisterAutoJoinCondition(conditionName, []() {return true;});
}

void RegisterStaServiceCallbackFuzzTest()
{
    StaServiceCallback callbacks;
    WifiStaServerManager wifiStaServerManager;
    wifiStaServerManager.InitStaServercallback();
    pStaInterface->RegisterStaServiceCallback(callbacks);
    pStaInterface->UnRegisterStaServiceCallback(callbacks);
    pStaService->UnRegisterStaServiceCallback(callbacks);
}

void StaInterfaceFuzzTest(FuzzedDataProvider& FDP)
{
    std::string conditionName = FDP.ConsumeBytesAsString(NUM_BYTES);
    std::string filterName = FDP.ConsumeBytesAsString(NUM_BYTES);
    FilterTag filterTag = static_cast<FilterTag>(FDP.ConsumeIntegral<int>() % FIVE);
    FilterBuilder filterBuilder = [](auto &compositeWifiFilter) {};
    AppExecFwk::AppStateData appData;
    std::vector<WifiRestrictedInfo> wifiRestrictedInfoList;
    pStaInterface->RegisterAutoJoinCondition(conditionName, []() {return true;});
    pStaInterface->RegisterFilterBuilder(filterTag, filterName, filterBuilder);
    pStaInterface->HandleForegroundAppChangedAction(appData);
    #ifdef FEATURE_WIFI_MDM_RESTRICTED_SUPPORT
    pStaInterface->SetWifiRestrictedList(wifiRestrictedInfoList);
    pStaInterface->ReconnectByMdm();
    #endif
}

void RegisterStaServiceCallbackTest()
{
    std::vector<StaServiceCallback> callbacks;
    WifiStaServerManager wifiStaServerManager;
    wifiStaServerManager.InitStaServercallback();
    pStaService->InitStaService(callbacks);
    pStaService->RegisterStaServiceCallback(callbacks);
}

void ConnectToCandidateConfigTest(FuzzedDataProvider& FDP)
{
    WifiDeviceConfig config;
    int uid = FDP.ConsumeIntegral<int>();
    int networkId = FDP.ConsumeIntegral<int>();
    config.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.uid = ID;
    config.networkId = WORK_ID;
    WifiSettings::GetInstance().AddDeviceConfig(config);
    pStaService->ConnectToCandidateConfig(uid, networkId);
}

void ConvertStringTest()
{
    std::u16string wideText;
    WifiTelephonyUtils::ConvertString(wideText);
}

void UpdateEapConfigTest(FuzzedDataProvider& FDP)
{
    WifiDeviceConfig config;
    config.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.eap = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.clientCert = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.privateKey = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.certEntry.push_back(FDP.ConsumeIntegral<uint8_t>());
    config.wifiEapConfig.encryptedData = FDP.ConsumeBytesAsString(NUM_BYTES);
    std::vector<std::string> eapMethod = {"SIM", "AKA", "AKA"};
    config.wifiEapConfig.eap = FDP.ConsumeBytesAsString(NUM_BYTES);
    pStaService->UpdateEapConfig(config, config.wifiEapConfig);
}

void AddDeviceConfigTest(FuzzedDataProvider& FDP)
{
    WifiDeviceConfig config;
    config.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP.ConsumeBytesAsString(NUM_BYTES);
    std::string EapMethod = "TLS";
    config.wifiEapConfig.eap = EapMethod;
    config.wifiEapConfig.clientCert = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.privateKey = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.certEntry.push_back(FDP.ConsumeIntegral<uint8_t>());
    config.wifiEapConfig.encryptedData = FDP.ConsumeBytesAsString(NUM_BYTES);
    pStaService->AddDeviceConfig(config);
}

void ConnectToNetworkTest(FuzzedDataProvider& FDP)
{
    WifiDeviceConfig config;
    int networkId = 0;
    config.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.networkId = 0;
    WifiSettings::GetInstance().AddDeviceConfig(config);
    pStaService->ConnectToNetwork(networkId);
}

void StartRoamToNetworkTest(FuzzedDataProvider& FDP)
{
    WifiDeviceConfig config;
    int networkId = 0;
    std::string staBssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP.ConsumeBytesAsString(NUM_BYTES);
    config.networkId = 0;
    WifiSettings::GetInstance().AddDeviceConfig(config);
    pStaService->StartConnectToBssid(networkId, staBssid);
}

void StaServiceFuzzTest(FuzzedDataProvider& FDP)
{
    std::string conditionName = FDP.ConsumeBytesAsString(NUM_BYTES);
    std::string ditionName = FDP.ConsumeBytesAsString(NUM_BYTES);
    AppExecFwk::AppStateData appData;
    pStaService->EnableStaService();
    pStaService->DisableStaService();
    pStaService->RegisterAutoJoinCondition(conditionName, []() {return true;});
    pStaService->DeregisterAutoJoinCondition(ditionName);
    pStaService->HandleForegroundAppChangedAction(appData);
}

void RegisterFilterBuilderFuzzTest(FuzzedDataProvider& FDP)
{
    int randomInt = FDP.ConsumeIntegral<int>();
    FilterTag filterTag = static_cast<FilterTag>(randomInt % FIVE);
    std::string filterName = FDP.ConsumeBytesAsString(NUM_BYTES);
    FilterBuilder filterBuilder = [](auto &compositeWifiFilter) {};
    pStaService->RegisterFilterBuilder(filterTag, filterName, filterBuilder);
}
 
void DeregisterFilterBuilderFuzzTest(FuzzedDataProvider& FDP)
{
    int randomInt = FDP.ConsumeIntegral<int>();
    FilterTag filterTag = static_cast<FilterTag>(randomInt % FIVE);
    std::string filterName = FDP.ConsumeBytesAsString(NUM_BYTES);
    pStaService->DeregisterFilterBuilder(filterTag, filterName);
}

void GetImsiFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    int slotId = FDP.ConsumeIntegral<int>();
    int mncLen = FDP.ConsumeIntegral<int>();
    std::string imsi = std::string(reinterpret_cast<const char*>(data), size);
 
    WifiTelephonyUtils::GetPlmn(slotId);
    pStaService->GetMcc(imsi);
    pStaService->GetMnc(imsi, mncLen);
    WifiTelephonyUtils::GetImsi(slotId);
}

void TelephonyUtilsFuzzTest(FuzzedDataProvider& FDP)
{
    int slotId = FDP.ConsumeIntegral<int>();
    int eapSubId = FDP.ConsumeIntegral<int>();
 
    WifiTelephonyUtils::GetDefaultId(slotId);
    WifiTelephonyUtils::GetSimCardState(slotId);
    WifiTelephonyUtils::IsMultiSimEnabled();
    WifiTelephonyUtils::IsSupportCardType(eapSubId);
    WifiTelephonyUtils::GetSlotId(eapSubId);
}

void SimAkaAuthFuzzTest(FuzzedDataProvider& FDP)
{
    int32_t randomInt = FDP.ConsumeIntegral<int32_t>();
    std::string nonce = FDP.ConsumeBytesAsString(NUM_BYTES);
    WifiTelephonyUtils::AuthType authType = static_cast<WifiTelephonyUtils::AuthType>(randomInt % TWO);
    int32_t eapSubId = FDP.ConsumeIntegral<int32_t>();
    SimAkaAuth(nonce, authType, eapSubId);
}

void SecurityDetectFuzzTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    int wifiStandard = FDP.ConsumeIntegral<int>();
    WifiLinkedInfo info;
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return;
    }
    std::string key = FDP.ConsumeBytesAsString(NUM_BYTES);
 
    if (size >= sizeof(WifiLinkedInfo)) {
        info.networkId = FDP.ConsumeIntegral<int>();
        info.rssi = FDP.ConsumeIntegral<int>();
        info.band = FDP.ConsumeIntegral<int>();
        info.linkSpeed = FDP.ConsumeIntegral<int>();
        info.macType = FDP.ConsumeIntegral<int>();
        info.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
        info.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
        info.macAddress = FDP.ConsumeBytesAsString(NUM_BYTES);
    }

    WifiSecurityDetect::GetInstance().SetDatashareReady();
    WifiSecurityDetect::GetInstance().RegisterSecurityDetectObserver();
    WifiSecurityDetect::GetInstance().DealStaConnChanged(OperateResState::CONNECT_AP_CONNECTED, info, 0);
    WifiSecurityDetect::GetInstance().DealStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, info, 0);
    WifiSecurityDetect::GetInstance().SecurityDetect(info);
    WifiSecurityDetect::GetInstance().CreateDataShareHelper();
    WifiSecurityDetect::GetInstance().IsSettingSecurityDetectOn();
    WifiSecurityDetect::GetInstance().UnRegisterSecurityDetectObserver();
    WifiSecurityDetect::GetInstance().AssembleUri(key);
    WifiSecurityDetect::GetInstance().ConverWifiLinkInfoToJson(info, root);
    WifiSecurityDetect::GetInstance().AddWifiStandardToJson(root, wifiStandard);
    cJSON_Delete(root);
}

void SecurityDetectFuzzTest02(FuzzedDataProvider& FDP)
{
    int randomInt = FDP.ConsumeIntegral<int>();
    int networkId = 0;
    int modelId = 0;
    std::string devId = FDP.ConsumeBytesAsString(NUM_BYTES);
    std::string param = FDP.ConsumeBytesAsString(NUM_BYTES);
    int rawvalue = randomInt % FIVE;
SecurityModelResult model;
switch (rawvalue) {
    case ZERO:
        model.devId = "device_001";
        model.modelId = MODEL_ID_1001;
        model.param = "psk";
        model.result = "success";
        break;
    case ONE:
        model.devId = "device_002";
        model.modelId = MODEL_ID_1002;
        model.param = "wpa2";
        model.result = "fail";
        break;
    case TWO:
        model.devId = "device_003";
        model.modelId = MODEL_ID_1003;
        model.param = "invalid";
        model.result = "invalid_params";
        break;
    case THREE:
        model.devId = "device_004";
        model.modelId = MODEL_ID_1004;
        model.param = "unsupported";
        model.result = "not_supported";
        break;
    case FOUR:
        model.devId = "device_005";
        model.modelId = MODEL_ID_1005;
        model.param = "timeout";
        model.result = "timeout";
        break;
    default:
        model.devId = "unknown";
        model.modelId = 0;
        model.param = "unknown";
        model.result = "unknown";
    }
    bool result = FDP.ConsumeBool();
    WifiSecurityDetect::GetInstance().SetChangeNetworkid(networkId);
    WifiSecurityDetect::GetInstance().IsSecurityDetectTimeout(networkId);
    WifiSecurityDetect::GetInstance().SecurityDetectResult(devId, modelId, param, result);
    WifiSecurityDetect::GetInstance().SecurityModelJsonResult(model, result);
}
    
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    if (!OHOS::Wifi::InitParam()) {
        InitParam();
    }
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    FuzzedDataProvider FDP(data, size);
    OHOS::Wifi::StaServerFuzzTest(data, size);
    OHOS::Wifi::StaAutoServerFuzzTest(data, size);
    OHOS::Wifi::AllowAutoSelectDeviceTest(data, size);
    OHOS::Wifi::GetImsiFuzzTest(data, size);
    OHOS::Wifi::SecurityDetectFuzzTest(data, size);
    OHOS::Wifi::RegisterDeviceAppraisalTest(FDP);
    OHOS::Wifi::StaAutoConnectServiceFuzzTest(FDP);
    OHOS::Wifi::StaInterfaceFuzzTest(FDP);
    OHOS::Wifi::ConnectToCandidateConfigTest(FDP);
    OHOS::Wifi::UpdateEapConfigTest(FDP);
    OHOS::Wifi::AddDeviceConfigTest(FDP);
    OHOS::Wifi::ConnectToNetworkTest(FDP);
    OHOS::Wifi::StartRoamToNetworkTest(FDP);
    OHOS::Wifi::StaServiceFuzzTest(FDP);
    OHOS::Wifi::RegisterFilterBuilderFuzzTest(FDP);
    OHOS::Wifi::DeregisterFilterBuilderFuzzTest(FDP);
    OHOS::Wifi::TelephonyUtilsFuzzTest(FDP);
    OHOS::Wifi::SimAkaAuthFuzzTest(FDP);
    OHOS::Wifi::SecurityDetectFuzzTest02(FDP);
    OHOS::Wifi::RegisterStaServiceCallbackFuzzTest();
    OHOS::Wifi::RegisterStaServiceCallbackTest();
    OHOS::Wifi::ConvertStringTest();
    return 0;
}
}
}
