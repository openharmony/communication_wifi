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
#include <mutex>

namespace OHOS {
namespace Wifi {
constexpr int U32_AT_SIZE_ZERO = 4;
constexpr int TWO = 2;
constexpr int THREE = 5;
constexpr int ID = 123;
constexpr int WORK_ID = 10;
static bool g_isInsted = false;
constexpr int STATE = 20;
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
    int index = 0;
    int networkId = static_cast<int>(data[index++]);
    int uid = static_cast<int>(data[index++]);
    bool attemptEnable = (static_cast<int>(data[0]) % TWO) ? true : false;
    bool isRemoveAll = (static_cast<int>(data[0]) % TWO) ? true : false;
    bool isAllowed = (static_cast<int>(data[0]) % TWO) ? true : false;
    std::string cmd = std::string(reinterpret_cast<const char*>(data), size);
    std::string conditionName = std::string(reinterpret_cast<const char*>(data), size);
    FilterTag filterTag = static_cast<FilterTag>(static_cast<int>(data[0]) % THREE);
    ConfigChange value = static_cast<ConfigChange>(static_cast<int>(data[0]) % U32_AT_SIZE_ZERO);
    WpsConfig sconfig;
    sconfig.pin = std::string(reinterpret_cast<const char*>(data), size);
    sconfig.bssid = std::string(reinterpret_cast<const char*>(data), size);
    sconfig.setup = static_cast<SetupMethod>(static_cast<int>(data[0]) % THREE);
    WifiDeviceConfig config;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.eap = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.clientCert = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.privateKey = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.certEntry.push_back(static_cast<uint8_t>(data[index++]));
    config.wifiEapConfig.encryptedData = std::string(reinterpret_cast<const char*>(data), size);
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
    pStaInterface->DisableDeviceConfig(networkId);
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
    pStaService->DisableDeviceConfig(networkId);
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
}

void StaAutoServerFuzzTest(const uint8_t* data, size_t size)
{
    std::string conditionName = std::string(reinterpret_cast<const char*>(data), size);
    bool attemptEnable = (static_cast<int>(data[0]) % TWO) ? true : false;
    int frequency = static_cast<int>(data[0]);
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
    std::vector<InterScanInfo> scanInfo;
    scanInfo.push_back(scanInfoList);
    WifiLinkedInfo info;
    if (size >= sizeof(WifiLinkedInfo)) {
        int index = 0;
        info.networkId = static_cast<int>(data[index++]);
        info.rssi = static_cast<int>(data[index++]);
        info.band = static_cast<int>(data[index++]);
        info.linkSpeed = static_cast<int>(data[index++]);
        info.frequency = static_cast<int>(data[index++]);
        info.macType = static_cast<int>(data[index++]);
        info.ssid = std::string(reinterpret_cast<const char*>(data), size);
        info.bssid = std::string(reinterpret_cast<const char*>(data), size);
        info.macAddress = std::string(reinterpret_cast<const char*>(data), size);
        info.detailedState = static_cast<DetailedState>(static_cast<int>(data[0]) % STATE);
    }

    WifiDeviceConfig config;
    config.bssid = scanInfoList.bssid;
    config.ssid = scanInfoList.ssid;
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> blocklistBssids;
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
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfo);
    pStaAutoConnectService->AutoSelectDevice(config, scanInfo, blocklistBssids, info);
    pStaAutoConnectService->WhetherDevice5GAvailable(scanInfo);
    pStaAutoConnectService->GetAvailableScanInfos(scanInfo, scanInfo, blocklistBssids, info);
    pStaAutoConnectService->IsAutoConnectFailByP2PEnhanceFilter(scanInfo);
    pStaService->AutoConnectService(scanInfo);
}

void RegisterDeviceAppraisalTest(const uint8_t* data, size_t size)
{
    StaDeviceAppraisal *appraisal = nullptr;
    int priority = TWO;
    pStaAutoConnectService->RegisterDeviceAppraisal(appraisal, priority);
}

void AllowAutoSelectDeviceTest(const uint8_t* data, size_t size)
{
    InterScanInfo scanInfoList;
    scanInfoList.channelWidth = static_cast<WifiChannelWidth>(static_cast<int>(data[0]) % U32_AT_SIZE_ZERO);
    scanInfoList.wifiMode = static_cast<int>(data[0]);
    scanInfoList.timestamp = static_cast<int64_t>(data[0]);
    scanInfoList.bssid = std::string(reinterpret_cast<const char*>(data), size);
    scanInfoList.rssi = static_cast<int>(data[0]);
    scanInfoList.ssid = std::string(reinterpret_cast<const char*>(data), size);
    scanInfoList.capabilities = std::string(reinterpret_cast<const char*>(data), size);
    scanInfoList.features = static_cast<int64_t>(data[0]);
    std::vector<InterScanInfo> scanInfo;
    scanInfo.push_back(scanInfoList);
    WifiLinkedInfo info;
    if (size >= sizeof(WifiLinkedInfo)) {
        int index = 0;
        info.networkId = static_cast<int>(data[index++]);
        info.rssi = static_cast<int>(data[index++]);
        info.band = static_cast<int>(data[index++]);
        info.linkSpeed = static_cast<int>(data[index++]);
        info.macType = static_cast<int>(data[index++]);
        info.ssid = std::string(reinterpret_cast<const char*>(data), size);
        info.bssid = std::string(reinterpret_cast<const char*>(data), size);
        info.macAddress = std::string(reinterpret_cast<const char*>(data), size);
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

void StaAutoConnectServiceFuzzTest(const uint8_t* data, size_t size)
{
    std::string conditionName = std::string(reinterpret_cast<const char*>(data), size);
    pStaAutoConnectService->RegisterAutoJoinCondition(conditionName, []() {return true;});
}

void RegisterStaServiceCallbackFuzzTest(const uint8_t* data, size_t size)
{
    StaServiceCallback callbacks;
    WifiStaServerManager wifiStaServerManager;
    wifiStaServerManager.InitStaServercallback();
    pStaInterface->RegisterStaServiceCallback(callbacks);
    pStaInterface->UnRegisterStaServiceCallback(callbacks);
    pStaService->UnRegisterStaServiceCallback(callbacks);
}

void StaInterfaceFuzzTest(const uint8_t* data, size_t size)
{
    std::string conditionName = std::string(reinterpret_cast<const char*>(data), size);
    std::string filterName = std::string(reinterpret_cast<const char*>(data), size);
    FilterTag filterTag = static_cast<FilterTag>(static_cast<int>(data[0]) % THREE);
    FilterBuilder filterBuilder = [](auto &compositeWifiFilter) {};
    AppExecFwk::AppStateData appData;
    pStaInterface->RegisterAutoJoinCondition(conditionName, []() {return true;});
    pStaInterface->RegisterFilterBuilder(filterTag, filterName, filterBuilder);
    pStaInterface->HandleForegroundAppChangedAction(appData);
}

void RegisterStaServiceCallbackTest(const uint8_t* data, size_t size)
{
    std::vector<StaServiceCallback> callbacks;
    WifiStaServerManager wifiStaServerManager;
    wifiStaServerManager.InitStaServercallback();
    pStaService->InitStaService(callbacks);
    pStaService->RegisterStaServiceCallback(callbacks);
}

void ConnectToCandidateConfigTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    int index = 0;
    int uid = static_cast<int>(data[index++]);
    int networkId = static_cast<int>(data[index++]);
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.uid = ID;
    config.networkId = WORK_ID;
    WifiSettings::GetInstance().AddDeviceConfig(config);
    pStaService->ConnectToCandidateConfig(uid, networkId);
}

void ConvertStringTest(const uint8_t* data, size_t size)
{
    std::u16string wideText;
    WifiTelephonyUtils::ConvertString(wideText);
}

void UpdateEapConfigTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    int index = 0;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.eap = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.clientCert = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.privateKey = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.certEntry.push_back(static_cast<uint8_t>(data[index++]));
    config.wifiEapConfig.encryptedData = std::string(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> eapMethod = {"SIM", "AKA", "AKA"};
    config.wifiEapConfig.eap = std::string(reinterpret_cast<const char*>(data), size);
    pStaService->UpdateEapConfig(config, config.wifiEapConfig);
}

void AddDeviceConfigTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    int index = 0;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    std::string EapMethod = "TLS";
    config.wifiEapConfig.eap = EapMethod;
    config.wifiEapConfig.clientCert = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.privateKey = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.certEntry.push_back(static_cast<uint8_t>(data[index++]));
    config.wifiEapConfig.encryptedData = std::string(reinterpret_cast<const char*>(data), size);
    pStaService->AddDeviceConfig(config);
}

void ConnectToNetworkTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    int networkId = 0;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.networkId = 0;
    WifiSettings::GetInstance().AddDeviceConfig(config);
    pStaService->ConnectToNetwork(networkId);
}

void StartRoamToNetworkTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    int networkId = 0;
    std::string staBssid = std::string(reinterpret_cast<const char*>(data), size);
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.networkId = 0;
    WifiSettings::GetInstance().AddDeviceConfig(config);
    pStaService->StartConnectToBssid(networkId, staBssid);
}

void StaServiceFuzzTest(const uint8_t* data, size_t size)
{
    std::string conditionName = std::string(reinterpret_cast<const char*>(data), size);
    std::string ditionName = std::string(reinterpret_cast<const char*>(data), size);
    AppExecFwk::AppStateData appData;
    pStaService->EnableStaService();
    pStaService->DisableStaService();
    pStaService->RegisterAutoJoinCondition(conditionName, []() {return true;});
    pStaService->DeregisterAutoJoinCondition(ditionName);
    pStaService->HandleForegroundAppChangedAction(appData);
}

void RegisterFilterBuilderFuzzTest(const uint8_t* data, size_t size)
{
    FilterTag filterTag = static_cast<FilterTag>(static_cast<int>(data[0]) % THREE);
    std::string filterName = std::string(reinterpret_cast<const char*>(data), size);
    FilterBuilder filterBuilder = [](auto &compositeWifiFilter) {};
    pStaService->RegisterFilterBuilder(filterTag, filterName, filterBuilder);
}

void DeregisterFilterBuilderFuzzTest(const uint8_t* data, size_t size)
{
    FilterTag filterTag = static_cast<FilterTag>(static_cast<int>(data[0]) % THREE);
    std::string filterName = std::string(reinterpret_cast<const char*>(data), size);
    pStaService->DeregisterFilterBuilder(filterTag, filterName);
}

void GetImsiFuzzTest(const uint8_t* data, size_t size)
{
    int index = 0;
    int slotId = static_cast<int>(data[index++]);
    int mncLen = static_cast<int>(data[index++]);
    std::string imsi = std::string(reinterpret_cast<const char*>(data), size);
    WifiTelephonyUtils::GetPlmn(slotId);
    pStaService->GetMcc(imsi);
    pStaService->GetMnc(imsi, mncLen);
    WifiTelephonyUtils::GetImsi(slotId);
}

void TelephonyUtilsFuzzTest(const uint8_t* data)
{
    int index = 0;
    int slotId = static_cast<int>(data[index++]);
    int eapSubId = static_cast<int>(data[index++]);
    WifiTelephonyUtils::GetDefaultId(slotId);
    WifiTelephonyUtils::GetSimCardState(slotId);
    WifiTelephonyUtils::IsMultiSimEnabled();
    WifiTelephonyUtils::IsSupportCardType(eapSubId);
    WifiTelephonyUtils::GetSlotId(eapSubId);
}

void SimAkaAuthFuzzTest(const uint8_t* data, size_t size)
{
    int index = 0;
    std::string nonce = std::string(reinterpret_cast<const char*>(data), size);
    WifiTelephonyUtils::AuthType authType = static_cast<WifiTelephonyUtils::AuthType>(data[index++]);
    int32_t eapSubId = static_cast<int32_t>(data[index++]);
    SimAkaAuth(nonce, authType, eapSubId);
}

void SecurityDetectFuzzTest(const uint8_t* data, size_t size)
{
    WifiLinkedInfo info;
    if (size >= sizeof(WifiLinkedInfo)) {
        int index = 0;
        info.networkId = static_cast<int>(data[index++]);
        info.rssi = static_cast<int>(data[index++]);
        info.band = static_cast<int>(data[index++]);
        info.linkSpeed = static_cast<int>(data[index++]);
        info.macType = static_cast<int>(data[index++]);
        info.ssid = std::string(reinterpret_cast<const char*>(data), size);
        info.bssid = std::string(reinterpret_cast<const char*>(data), size);
        info.macAddress = std::string(reinterpret_cast<const char*>(data), size);
    }
    WifiSecurityDetect::GetInstance().SetDatashareReady();
    WifiSecurityDetect::GetInstance().RegisterSecurityDetectObserver();
    WifiSecurityDetect::GetInstance().DealStaConnChanged(OperateResState::CONNECT_AP_CONNECTED, info, 0);
    WifiSecurityDetect::GetInstance().DealStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, info, 0);
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
    OHOS::Wifi::StaServerFuzzTest(data, size);
    OHOS::Wifi::StaAutoServerFuzzTest(data, size);
    OHOS::Wifi::RegisterDeviceAppraisalTest(data, size);
    OHOS::Wifi::AllowAutoSelectDeviceTest(data, size);
    OHOS::Wifi::StaAutoConnectServiceFuzzTest(data, size);
    OHOS::Wifi::RegisterStaServiceCallbackFuzzTest(data, size);
    OHOS::Wifi::StaInterfaceFuzzTest(data, size);
    OHOS::Wifi::RegisterStaServiceCallbackTest(data, size);
    OHOS::Wifi::ConnectToCandidateConfigTest(data, size);
    OHOS::Wifi::ConvertStringTest(data, size);
    OHOS::Wifi::UpdateEapConfigTest(data, size);
    OHOS::Wifi::AddDeviceConfigTest(data, size);
    OHOS::Wifi::ConnectToNetworkTest(data, size);
    OHOS::Wifi::StartRoamToNetworkTest(data, size);
    OHOS::Wifi::StaServiceFuzzTest(data, size);
    OHOS::Wifi::RegisterFilterBuilderFuzzTest(data, size);
    OHOS::Wifi::DeregisterFilterBuilderFuzzTest(data, size);
    OHOS::Wifi::GetImsiFuzzTest(data, size);
    OHOS::Wifi::TelephonyUtilsFuzzTest(data);
    OHOS::Wifi::SimAkaAuthFuzzTest(data, size);
    OHOS::Wifi::SecurityDetectFuzzTest(data, size);
    return 0;
}
}
}
