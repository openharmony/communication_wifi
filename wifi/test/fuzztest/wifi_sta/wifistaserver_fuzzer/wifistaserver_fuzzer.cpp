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

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "securec.h"
#include "define.h"
#include "wifi_log.h"
#include "sta_interface.h"
#include "sta_auto_connect_service.h"
#include "mock_sta_state_machine.h"
#include "wifi_settings.h"
#include "sta_service.h"
#include "wifi_internal_msg.h"
#include <mutex>

namespace OHOS {
namespace Wifi {
constexpr int U32_AT_SIZE_ZERO = 4;
constexpr int TWO = 2;
constexpr int THREE = 5;
static bool g_isInsted = false;
constexpr int STATE = 20;
static std::unique_ptr<StaInterface> pStaInterface = nullptr;
static std::unique_ptr<StaAutoConnectService> pStaAutoConnectService = nullptr;
static std::unique_ptr<StaService> pStaService = nullptr;
StaStateMachine *pStaStateMachine;

void MyExit()
{
    pStaInterface.reset();
    pStaAutoConnectService.reset();
    pStaService.reset();
    sleep(U32_AT_SIZE_ZERO);
    printf("exiting\n");
}

bool InitParam()
{
    if (!g_isInsted) {
        pStaStateMachine = new (std::nothrow) MockStaStateMachine();
        pStaInterface = std::make_unique<StaInterface>();
        pStaAutoConnectService = std::make_unique<StaAutoConnectService>(pStaStateMachine);
        pStaService = std::make_unique<StaService>();
        if (pStaInterface == nullptr || pStaAutoConnectService == nullptr) {
            return false;
        }
        atexit(MyExit);
        g_isInsted = true;
    }
    return true;
}

void StaServerFuzzTest(const uint8_t* data, size_t size)
{
    int index = 0;
    int networkId = static_cast<int>(data[index++]);
    int uid = static_cast<int>(data[index++]);
    bool attemptEnable = (static_cast<int>(data[0]) % TWO) ? true : false;
    std::string conditionName = std::string(reinterpret_cast<const char*>(data), size);
    WpsConfig sconfig;
    sconfig.pin = std::string(reinterpret_cast<const char*>(data), size);
    sconfig.bssid = std::string(reinterpret_cast<const char*>(data), size);
    sconfig.setup = static_cast<SetupMethod>(static_cast<int>(data[0]) % THREE);
    WifiDeviceConfig config;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
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
    pStaService->AddCandidateConfig(uid, config, networkId);
    pStaService->RemoveAllCandidateConfig(uid);
    pStaService->ConnectToCandidateConfig(uid, networkId);
    pStaService->UpdateDeviceConfig(config);
    pStaService->RemoveDevice(networkId);
    pStaService->RemoveAllDevice();
    pStaService->ConnectToDevice(config);
    pStaService->ConnectToNetwork(networkId);
    pStaService->StartRoamToNetwork(networkId, conditionName);
    pStaService->ReAssociate();
    pStaService->EnableDeviceConfig(networkId, attemptEnable);
    pStaService->DisableDeviceConfig(networkId);
    pStaService->Disconnect();
    pStaService->StartWps(sconfig);
    pStaService->CancelWps();
    pStaService->ReConnect();
    pStaService->SetSuspendMode(attemptEnable);
    pStaService->SetPowerMode(attemptEnable);
    pStaService->SetTxPower(networkId);
    pStaService->DisableAutoJoin(conditionName);
    pStaService->EnableAutoJoin(conditionName);
    pStaService->StartPortalCertification();
    pStaService->EnableHiLinkHandshake(config, conditionName);
    pStaService->DeliverStaIfaceData(conditionName);
    pStaService->GetDataSlotId();
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
    WifiSettings::GetInstance().SaveLinkedInfo(info);
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
    pStaAutoConnectService->ConnectElectedDevice(config);
    pStaAutoConnectService->ClearOvertimeBlockedBssid();
    pStaAutoConnectService->ClearAllBlockedBssids();
    pStaAutoConnectService->GetBlockedBssids(blocklistBssids);
    pStaAutoConnectService->AddOrDelBlockedBssids(conditionName, attemptEnable, frequency);
    pStaAutoConnectService->EnableOrDisableBssid(conditionName, attemptEnable, frequency);
    pStaAutoConnectService->ClearOvertimeBlockedBssid();
    pStaAutoConnectService->firmwareRoamFlag = true;
    pStaAutoConnectService->SetRoamBlockedBssidFirmware(blocklistBssids);
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
    return 0;
}
}
}
