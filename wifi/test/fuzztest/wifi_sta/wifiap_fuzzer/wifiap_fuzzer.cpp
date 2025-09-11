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

namespace OHOS {
namespace Wifi {
constexpr int TWO = 2;
constexpr int THREE = 3;
constexpr int U32_AT_SIZE_ZERO = 4;
constexpr int SIX = 6;
FuzzedDataProvider *FDP = nullptr;
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

void UpdateApChannelConfigFuzzTest(const uint8_t* data, size_t size)
{
    HotspotConfig apConfig;
    apConfig.SetBand(BandType::BAND_2GHZ);
    apConfig.SetChannel(1);
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.connState = ConnState::DISCONNECTED;
    pApConfigUse->UpdateApChannelConfig(apConfig);
}

void GetBestChannelFor2GFuzzTest(const uint8_t* data, size_t size)
{
    pApConfigUse->GetBestChannelFor2G();
}

void GetBestChannelFor5GFuzzTest(const uint8_t* data, size_t size)
{
    HotspotConfig apConfig;
    apConfig.SetBandWidth(AP_BANDWIDTH_DEFAULT);
    pApConfigUse->GetBestChannelFor5G(apConfig);
}

void GetChannelFromDrvOrXmlByBandFuzzTest(const uint8_t* data, size_t size)
{
    BandType bandType = static_cast<BandType>(static_cast<int>(data[0]) % SIX);
    pApConfigUse->GetChannelFromDrvOrXmlByBand(bandType);
}

void FilterIndoorChannelFuzzTest(const uint8_t* data, size_t size)
{
    std::vector<int> channels = {36, 40, 44, 48, 52, 56};
    pApConfigUse->FilterIndoorChannel(channels);
    std::vector<int> channels1 = {};
    pApConfigUse->FilterIndoorChannel(channels1);
}

void Filter165ChannelFuzzTest(const uint8_t* data, size_t size)
{
    std::vector<int> channels = {36, 165};
    pApConfigUse->Filter165Channel(channels);
}

void JudgeDbacWithP2pFuzzTest(const uint8_t* data, size_t size)
{
    HotspotConfig apConfig;
    apConfig.SetBand(BandType::BAND_2GHZ);
    pApConfigUse->JudgeDbacWithP2p(apConfig);
}

void GetIndoorChanByCountryCodeFuzzTest(const uint8_t* data, size_t size)
{
    std::string countryCode = std::string(reinterpret_cast<const char*>(data), size);
    pApConfigUse->GetIndoorChanByCountryCode(countryCode);
}

void GetPreferredChannelByBandFuzzTest(const uint8_t* data, size_t size)
{
    BandType bandType = static_cast<BandType>(static_cast<int>(data[0]) % SIX);
    pApConfigUse->GetPreferredChannelByBand(bandType);
}

void WifiApRootStateFuzzTest(const uint8_t* data, size_t size)
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

void BlockListAndStationFuzzTest()
{
    StationInfo staInfo;
    staInfo.deviceName = FDP->ConsumeBytesAsString(NUM_BYTES);
    staInfo.bssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    staInfo.bssidType = FDP->ConsumeIntegral<int>();
    staInfo.ipAddr = FDP->ConsumeBytesAsString(NUM_BYTES);
 
    pApStationsManager->AddBlockList(staInfo);
    pApStationsManager->DelBlockList(staInfo);
    pApStationsManager->StationJoin(staInfo);
    pApStationsManager->DisConnectStation(staInfo);
    pApStationsManager->AddAssociationStation(staInfo);
    pApStationsManager->DelAssociationStation(staInfo);
}

void EnableAllBlockListFuzzTest(const uint8_t* data, size_t size)
{
    pApStationsManager->EnableAllBlockList();
}

void StationLeaveFuzzTest(const uint8_t* data, size_t size)
{
    std::string mac = std::string(reinterpret_cast<const char*>(data), size);
    pApStationsManager->StationLeave(mac);
}

void GetAllConnectedStationsFuzzTest(const uint8_t* data, size_t size)
{
    std::vector<std::string> staMacList;
    std::vector<std::string> staMacListCom;
    std::string staMacList1 = "test_deviceName1";
    std::string staMacList2 = "test_deviceName2";
    staMacList.push_back(staMacList1);
    staMacList.push_back(staMacList2);
    pApStationsManager->GetAllConnectedStations();
}

void EnableInterfaceNatFuzzTest(const uint8_t* data, size_t size)
{
    bool enable = (static_cast<int>(data[0]) % TWO) ? true : false;
    std::string inInterfaceName = std::string(reinterpret_cast<const char*>(data), size);
    std::string outInterfaceName = std::string(reinterpret_cast<const char*>(data), size);
    pWifiApNatManager->EnableInterfaceNat(enable, inInterfaceName, outInterfaceName);
}

void SetForwardingFuzzTest(const uint8_t* data, size_t size)
{
    bool enable = (static_cast<int>(data[0]) % TWO) ? true : false;
    pWifiApNatManager->SetForwarding(enable);
}

void WriteDataToFileFuzzTest(const uint8_t* data, size_t size)
{
    std::string fileName = "wlan0";
    std::string content = std::string(reinterpret_cast<const char*>(data), size);
    pWifiApNatManager->WriteDataToFile(fileName, content);
}

void EnableHotspotFuzzTest(const uint8_t* data, size_t size)
{
    pApService->EnableHotspot();
    pApInterface->EnableHotspot();
}

void SetHotspotConfigFuzzTest(const uint8_t* data, size_t size)
{
    HotspotConfig apConfig;
    apConfig.SetChannel(1);
    apConfig.SetBand(BandType::BAND_2GHZ);
    apConfig.SetBandWidth(AP_BANDWIDTH_DEFAULT);
    pApService->SetHotspotConfig(apConfig);
    pApInterface->SetHotspotConfig(apConfig);
}

void SetHotspotIdleTimeoutFuzzTest(const uint8_t* data, size_t size)
{
    int time = static_cast<int>(data[0]);
    pApService->SetHotspotIdleTimeout(time);
    pApInterface->SetHotspotIdleTimeout(time);
}

void AddBlockListFuzzTest(const uint8_t* data, size_t size)
{
    StationInfo stationInfo;
    int index = 0;
    stationInfo.deviceName = std::string(reinterpret_cast<const char*>(data), size);
    stationInfo.bssid = std::string(reinterpret_cast<const char*>(data), size);
    stationInfo.bssidType = static_cast<int>(data[index++]);
    stationInfo.ipAddr = std::string(reinterpret_cast<const char*>(data), size);
    pApService->AddBlockList(stationInfo);
    pApInterface->AddBlockList(stationInfo);
}

void DelBlockListFuzzTest(const uint8_t* data, size_t size)
{
    StationInfo stationInfo;
    int index = 0;
    stationInfo.deviceName = std::string(reinterpret_cast<const char*>(data), size);
    stationInfo.bssid = std::string(reinterpret_cast<const char*>(data), size);
    stationInfo.bssidType = static_cast<int>(data[index++]);
    stationInfo.ipAddr = std::string(reinterpret_cast<const char*>(data), size);
    pApService->DelBlockList(stationInfo);
    pApInterface->DelBlockList(stationInfo);
}

void DisconnetStationFuzzTest(const uint8_t* data, size_t size)
{
    StationInfo stationInfo;
    int index = 0;
    stationInfo.deviceName = std::string(reinterpret_cast<const char*>(data), size);
    stationInfo.bssid = std::string(reinterpret_cast<const char*>(data), size);
    stationInfo.bssidType = static_cast<int>(data[index++]);
    stationInfo.ipAddr = std::string(reinterpret_cast<const char*>(data), size);
    pApService->DisconnetStation(stationInfo);
    pApInterface->DisconnetStation(stationInfo);
}

void GetStationListFuzzTest(const uint8_t* data, size_t size)
{
    std::vector<StationInfo> result;
    pApService->GetStationList(result);
    pApInterface->GetStationList(result);
}

void RegisterApServiceCallbacksFuzzTest(const uint8_t* data, size_t size)
{
    IApServiceCallbacks callbacks;
    pApService->RegisterApServiceCallbacks(callbacks);
    pApInterface->RegisterApServiceCallbacks(callbacks);
}

void GetSupportedPowerModelFuzzTest(const uint8_t* data, size_t size)
{
    std::set<PowerModel> setPowerModelList;
    pApService->GetSupportedPowerModel(setPowerModelList);
    pApInterface->GetSupportedPowerModel(setPowerModelList);
}

void GetPowerModelFuzzTest(const uint8_t* data, size_t size)
{
    PowerModel model = static_cast<PowerModel>(static_cast<int>(data[0]) % THREE);
    pApService->GetPowerModel(model);
    pApInterface->GetPowerModel(model);
}

void SetPowerModelFuzzTest(const uint8_t* data, size_t size)
{
    PowerModel model = static_cast<PowerModel>(static_cast<int>(data[0]) % THREE);
    pApService->SetPowerModel(model);
    pApInterface->SetPowerModel(model);
}

void WifiApIdleStateFuzzTest(const uint8_t* data, size_t size)
{
    pApIdleState->GoInState();
    pApIdleState->GoOutState();
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_UPDATE_HOTSPOTCONFIG_RESULT));
    pApIdleState->ExecuteStateMsg(msg);
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_START_HOTSPOT));
    pApIdleState->ExecuteStateMsg(msg);
}

void GetHotspotModeFuzzTest(const uint8_t* data, size_t size)
{
    HotspotMode model = static_cast<HotspotMode>(static_cast<int>(data[0]) % THREE);
    pApInterface->GetHotspotMode(model);
    pApService->GetHotspotMode(model);
}

void SetHotspotModeFuzzTest(const uint8_t* data, size_t size)
{
    HotspotMode model = static_cast<HotspotMode>(static_cast<int>(data[0]) % THREE);
    pApInterface->SetHotspotMode(model);
    pApService->SetHotspotMode(model);
}

void WifiApFuzzTest(const uint8_t* data, size_t size)
{
    int index = 0;
    int apStatus = static_cast<int>(data[index++]);
    bool enable = (static_cast<int>(data[0]) % TWO) ? true : false;
    std::string wifiCountryCode = std::string(reinterpret_cast<const char*>(data), size);
    std::string outInterfaceName = std::string(reinterpret_cast<const char*>(data), size);
    pWifiApNatManager->SetInterfaceRoute(enable);
    pWifiApNatManager->SetInterfaceNat(enable, outInterfaceName);
    pApService->DisableHotspot();
    pApService->HandleNetCapabilitiesChanged(apStatus);
    pApService->m_apObserver->OnWifiCountryCodeChanged(wifiCountryCode);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::Wifi::FDP = &fdp;
    OHOS::Wifi::UpdateApChannelConfigFuzzTest(data, size);
    OHOS::Wifi::GetBestChannelFor2GFuzzTest(data, size);
    OHOS::Wifi::GetBestChannelFor5GFuzzTest(data, size);
    OHOS::Wifi::GetChannelFromDrvOrXmlByBandFuzzTest(data, size);
    OHOS::Wifi::FilterIndoorChannelFuzzTest(data, size);
    OHOS::Wifi::Filter165ChannelFuzzTest(data, size);
    OHOS::Wifi::JudgeDbacWithP2pFuzzTest(data, size);
    OHOS::Wifi::GetIndoorChanByCountryCodeFuzzTest(data, size);
    OHOS::Wifi::GetPreferredChannelByBandFuzzTest(data, size);
    OHOS::Wifi::BlockListAndStationFuzzTest();
    OHOS::Wifi::WifiApRootStateFuzzTest(data, size);
    OHOS::Wifi::BlockListAndStationFuzzTest(data, size);
    OHOS::Wifi::EnableAllBlockListFuzzTest(data, size);
    OHOS::Wifi::StationLeaveFuzzTest(data, size);
    OHOS::Wifi::GetAllConnectedStationsFuzzTest(data, size);
    OHOS::Wifi::EnableInterfaceNatFuzzTest(data, size);
    OHOS::Wifi::SetForwardingFuzzTest(data, size);
    OHOS::Wifi::WriteDataToFileFuzzTest(data, size);
    OHOS::Wifi::EnableHotspotFuzzTest(data, size);
    OHOS::Wifi::SetHotspotConfigFuzzTest(data, size);
    OHOS::Wifi::SetHotspotIdleTimeoutFuzzTest(data, size);
    OHOS::Wifi::AddBlockListFuzzTest(data, size);
    OHOS::Wifi::DelBlockListFuzzTest(data, size);
    OHOS::Wifi::DisconnetStationFuzzTest(data, size);
    OHOS::Wifi::GetStationListFuzzTest(data, size);
    OHOS::Wifi::RegisterApServiceCallbacksFuzzTest(data, size);
    OHOS::Wifi::GetSupportedPowerModelFuzzTest(data, size);
    OHOS::Wifi::GetPowerModelFuzzTest(data, size);
    OHOS::Wifi::SetPowerModelFuzzTest(data, size);
    OHOS::Wifi::WifiApIdleStateFuzzTest(data, size);
    OHOS::Wifi::GetHotspotModeFuzzTest(data, size);
    OHOS::Wifi::SetHotspotModeFuzzTest(data, size);
    OHOS::Wifi::WifiApFuzzTest(data, size);
    return 0;
}
}
}
