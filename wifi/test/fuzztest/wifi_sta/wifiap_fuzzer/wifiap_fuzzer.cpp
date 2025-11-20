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

#include "wifiap_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "securec.h"
#include "ap_define.h"
#include "wifi_log.h"
#include "wifi_ap_msg.h"
#include <mutex>
#include "ap_config_use.h"
#include "ap_idle_state.h"
#include "ap_interface.h"
#include "ap_root_state.h"
#include "ap_service.h"
#include "ap_stations_manager.h"
#include "wifi_ap_nat_manager.h"
#include "mock_wifi_ap_service.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Wifi {
constexpr int THREE = 3;
constexpr int U32_AT_SIZE_ZERO = 4;
constexpr int SIX = 6;
static const int32_t NUM_BYTES = 1;

MockPendant *pMockPendant = new MockPendant();
std::shared_ptr<ApService> pApService = std::make_shared<ApService>(pMockPendant->GetMockApStateMachine(),
    pMockPendant->GetMockApStartedState());
std::shared_ptr<ApIdleState> pApIdleState = std::make_shared<ApIdleState>(pMockPendant->GetMockApStateMachine());
std::shared_ptr<ApInterface> pApInterface = std::make_shared<ApInterface>();
std::shared_ptr<ApConfigUse> pApConfigUse = std::make_shared<ApConfigUse>();
std::shared_ptr<ApRootState> pApRootState = std::make_shared<ApRootState>();
std::shared_ptr<ApStationsManager> pApStationsManager = std::make_shared<ApStationsManager>();
std::shared_ptr<WifiApNatManager> pWifiApNatManager = std::make_shared<WifiApNatManager>();

void UpdateApChannelConfigFuzzTest()
{
    HotspotConfig apConfig;
    apConfig.SetBand(BandType::BAND_2GHZ);
    apConfig.SetChannel(1);
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.connState = ConnState::DISCONNECTED;
    pApConfigUse->UpdateApChannelConfig(apConfig);
}

void GetBestChannelFor2GFuzzTest()
{
    pApConfigUse->GetBestChannelFor2G();
}

void GetBestChannelFor5GFuzzTest()
{
    HotspotConfig apConfig;
    apConfig.SetBandWidth(AP_BANDWIDTH_DEFAULT);
    pApConfigUse->GetBestChannelFor5G(apConfig);
}

void GetChannelFromDrvOrXmlByBandFuzzTest(FuzzedDataProvider& FDP)
{
    int randomInt = FDP.ConsumeIntegral<int>();
    BandType bandType = static_cast<BandType>(randomInt % SIX);
    pApConfigUse->GetChannelFromDrvOrXmlByBand(bandType);
}

void FilterIndoorChannelFuzzTest()
{
    std::vector<int> channels = {36, 40, 44, 48, 52, 56};
    pApConfigUse->FilterIndoorChannel(channels);
    std::vector<int> channels1 = {};
    pApConfigUse->FilterIndoorChannel(channels1);
}

void Filter165ChannelFuzzTest()
{
    std::vector<int> channels = {36, 165};
    pApConfigUse->Filter165Channel(channels);
}

void JudgeDbacWithP2pFuzzTest()
{
    HotspotConfig apConfig;
    apConfig.SetBand(BandType::BAND_2GHZ);
    pApConfigUse->JudgeDbacWithP2p(apConfig);
}

void GetIndoorChanByCountryCodeFuzzTest(FuzzedDataProvider& FDP)
{
    std::string countryCode = FDP.ConsumeBytesAsString(NUM_BYTES);
    pApConfigUse->GetIndoorChanByCountryCode(countryCode);
}

void GetPreferredChannelByBandFuzzTest(FuzzedDataProvider& FDP)
{
    int randomInt = FDP.ConsumeIntegral<int>();
    BandType bandType = static_cast<BandType>(randomInt % SIX);
    pApConfigUse->GetPreferredChannelByBand(bandType);
}

void WifiApRootStateFuzzTest()
{
    pApRootState->GoInState();
    pApRootState->GoOutState();
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_UPDATE_HOTSPOTCONFIG_RESULT));
    pApRootState->ExecuteStateMsg(msg);
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_START_HOTSPOT));
    pApRootState->ExecuteStateMsg(msg);
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_SET_HOTSPOT_CONFIG));
    pApRootState->ExecuteStateMsg(msg);
    msg = nullptr;
    pApRootState->ExecuteStateMsg(msg);
}

void BlockListAndStationFuzzTest(FuzzedDataProvider& FDP)
{
    StationInfo staInfo;
    staInfo.deviceName = FDP.ConsumeBytesAsString(NUM_BYTES);
    staInfo.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    staInfo.bssidType = FDP.ConsumeIntegral<int>();
    staInfo.ipAddr = FDP.ConsumeBytesAsString(NUM_BYTES);
 
    pApStationsManager->AddBlockList(staInfo);
    pApStationsManager->DelBlockList(staInfo);
    pApStationsManager->StationJoin(staInfo);
    pApStationsManager->DisConnectStation(staInfo);
    pApStationsManager->AddAssociationStation(staInfo);
    pApStationsManager->DelAssociationStation(staInfo);
}

void EnableAllBlockListFuzzTest()
{
    pApStationsManager->EnableAllBlockList();
}

void StationLeaveFuzzTest(FuzzedDataProvider& FDP)
{
    std::string mac = FDP.ConsumeBytesAsString(NUM_BYTES);
    pApStationsManager->StationLeave(mac);
}

void GetAllConnectedStationsFuzzTest()
{
    std::vector<std::string> staMacList;
    std::vector<std::string> staMacListCom;
    std::string staMacList1 = "test_deviceName1";
    std::string staMacList2 = "test_deviceName2";
    staMacList.push_back(staMacList1);
    staMacList.push_back(staMacList2);
    pApStationsManager->GetAllConnectedStations();
}

void EnableInterfaceNatFuzzTest(FuzzedDataProvider& FDP)
{
    bool enable = FDP.ConsumeBool();
    std::string inInterfaceName = FDP.ConsumeBytesAsString(NUM_BYTES);
    std::string outInterfaceName = FDP.ConsumeBytesAsString(NUM_BYTES);
    pWifiApNatManager->EnableInterfaceNat(enable, inInterfaceName, outInterfaceName);
}

void SetForwardingFuzzTest(FuzzedDataProvider& FDP)
{
    bool enable = FDP.ConsumeBool();
    pWifiApNatManager->SetForwarding(enable);
}

void WriteDataToFileFuzzTest(FuzzedDataProvider& FDP)
{
    std::string fileName = "wlan0";
    std::string content = FDP.ConsumeBytesAsString(NUM_BYTES);
    pWifiApNatManager->WriteDataToFile(fileName, content);
}

void EnableHotspotFuzzTest()
{
    pApService->EnableHotspot();
    pApInterface->EnableHotspot();
}

void SetHotspotConfigFuzzTest()
{
    HotspotConfig apConfig;
    apConfig.SetChannel(1);
    apConfig.SetBand(BandType::BAND_2GHZ);
    apConfig.SetBandWidth(AP_BANDWIDTH_DEFAULT);
    pApService->SetHotspotConfig(apConfig);
    pApInterface->SetHotspotConfig(apConfig);
}

void SetHotspotIdleTimeoutFuzzTest(FuzzedDataProvider& FDP)
{
    int time = FDP.ConsumeIntegral<int>();
    pApService->SetHotspotIdleTimeout(time);
    pApInterface->SetHotspotIdleTimeout(time);
}

void AddBlockListFuzzTest(FuzzedDataProvider& FDP)
{
    StationInfo stationInfo;
    stationInfo.deviceName = FDP.ConsumeBytesAsString(NUM_BYTES);
    stationInfo.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    stationInfo.bssidType = FDP.ConsumeIntegral<int>();
    stationInfo.ipAddr = FDP.ConsumeBytesAsString(NUM_BYTES);
    pApService->AddBlockList(stationInfo);
    pApInterface->AddBlockList(stationInfo);
}

void DelBlockListFuzzTest(FuzzedDataProvider& FDP)
{
    StationInfo stationInfo;
    stationInfo.deviceName = FDP.ConsumeBytesAsString(NUM_BYTES);
    stationInfo.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    stationInfo.bssidType = FDP.ConsumeIntegral<int>();
    stationInfo.ipAddr = FDP.ConsumeBytesAsString(NUM_BYTES);
    pApService->DelBlockList(stationInfo);
    pApInterface->DelBlockList(stationInfo);
}

void DisconnetStationFuzzTest(FuzzedDataProvider& FDP)
{
    StationInfo stationInfo;
    stationInfo.deviceName = FDP.ConsumeBytesAsString(NUM_BYTES);
    stationInfo.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
    stationInfo.bssidType = FDP.ConsumeIntegral<int>();
    stationInfo.ipAddr = FDP.ConsumeBytesAsString(NUM_BYTES);
    pApService->DisconnetStation(stationInfo);
    pApInterface->DisconnetStation(stationInfo);
}

void GetStationListFuzzTest()
{
    std::vector<StationInfo> result;
    pApService->GetStationList(result);
    pApInterface->GetStationList(result);
    pApService->DisableHotspot();
}

void RegisterApServiceCallbacksFuzzTest()
{
    IApServiceCallbacks callbacks;
    pApService->RegisterApServiceCallbacks(callbacks);
    pApInterface->RegisterApServiceCallbacks(callbacks);
}

void GetSupportedPowerModelFuzzTest()
{
    std::set<PowerModel> setPowerModelList;
    pApService->GetSupportedPowerModel(setPowerModelList);
    pApInterface->GetSupportedPowerModel(setPowerModelList);
}

void GetPowerModelFuzzTest(FuzzedDataProvider& FDP)
{
    int randomInt = FDP.ConsumeIntegral<int>();
    PowerModel model = static_cast<PowerModel>(randomInt % THREE);
    pApService->GetPowerModel(model);
    pApInterface->GetPowerModel(model);
}

void SetPowerModelFuzzTest(FuzzedDataProvider& FDP)
{
    int randomInt = FDP.ConsumeIntegral<int>();
    PowerModel model = static_cast<PowerModel>(randomInt % THREE);
    pApService->SetPowerModel(model);
    pApInterface->SetPowerModel(model);
}

void WifiApIdleStateFuzzTest()
{
    pApIdleState->GoInState();
    pApIdleState->GoOutState();
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_UPDATE_HOTSPOTCONFIG_RESULT));
    pApIdleState->ExecuteStateMsg(msg);
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_START_HOTSPOT));
    pApIdleState->ExecuteStateMsg(msg);
}

void GetHotspotModeFuzzTest(FuzzedDataProvider& FDP)
{
    int randomInt = FDP.ConsumeIntegral<int>();
    HotspotMode model = static_cast<HotspotMode>(randomInt % THREE);
    pApInterface->GetHotspotMode(model);
    pApService->GetHotspotMode(model);
}

void SetHotspotModeFuzzTest(FuzzedDataProvider& FDP)
{
    int randomInt = FDP.ConsumeIntegral<int>();
    HotspotMode model = static_cast<HotspotMode>(randomInt % THREE);
    pApInterface->SetHotspotMode(model);
    pApService->SetHotspotMode(model);
}

void WifiApFuzzTest(FuzzedDataProvider& FDP)
{
    int apStatus = FDP.ConsumeIntegral<int>();
    bool enable = FDP.ConsumeBool();
    std::string outInterfaceName = FDP.ConsumeBytesAsString(NUM_BYTES);
    pWifiApNatManager->SetInterfaceRoute(enable);
    pWifiApNatManager->SetInterfaceNat(enable, outInterfaceName);
    pApService->HandleNetCapabilitiesChanged(apStatus);
}

void WifiApFuzzTest01()
{
    UpdateApChannelConfigFuzzTest();
    GetBestChannelFor2GFuzzTest();
    GetBestChannelFor5GFuzzTest();
    FilterIndoorChannelFuzzTest();
    Filter165ChannelFuzzTest();
    JudgeDbacWithP2pFuzzTest();
    WifiApRootStateFuzzTest();
    EnableAllBlockListFuzzTest();
    GetAllConnectedStationsFuzzTest();
    EnableHotspotFuzzTest();
    SetHotspotConfigFuzzTest();
    GetStationListFuzzTest();
    RegisterApServiceCallbacksFuzzTest();
    GetSupportedPowerModelFuzzTest();
    WifiApIdleStateFuzzTest();
}


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    FuzzedDataProvider FDP(data, size);
    OHOS::Wifi::GetChannelFromDrvOrXmlByBandFuzzTest(FDP);
    OHOS::Wifi::GetIndoorChanByCountryCodeFuzzTest(FDP);
    OHOS::Wifi::GetPreferredChannelByBandFuzzTest(FDP);
    OHOS::Wifi::BlockListAndStationFuzzTest(FDP);
    OHOS::Wifi::StationLeaveFuzzTest(FDP);
    OHOS::Wifi::EnableInterfaceNatFuzzTest(FDP);
    OHOS::Wifi::SetForwardingFuzzTest(FDP);
    OHOS::Wifi::WriteDataToFileFuzzTest(FDP);
    OHOS::Wifi::SetHotspotIdleTimeoutFuzzTest(FDP);
    OHOS::Wifi::AddBlockListFuzzTest(FDP);
    OHOS::Wifi::DelBlockListFuzzTest(FDP);
    OHOS::Wifi::DisconnetStationFuzzTest(FDP);
    OHOS::Wifi::GetPowerModelFuzzTest(FDP);
    OHOS::Wifi::SetPowerModelFuzzTest(FDP);
    OHOS::Wifi::GetHotspotModeFuzzTest(FDP);
    OHOS::Wifi::SetHotspotModeFuzzTest(FDP);
    OHOS::Wifi::WifiApFuzzTest(FDP);
    OHOS::Wifi::WifiApFuzzTest01()

    return 0;
}
}
}
