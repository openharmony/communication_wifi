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

#include "wifihotspotimpl_fuzzer.h"
#include "wifi_fuzz_common_func.h"
#include <fuzzer/FuzzedDataProvider.h>
#include "wifi_hotspot_service_impl.h"
#include "wifi_hotspot_mgr_stub.h"
#include "wifi_hotspot_mgr_service_impl.h"
#include "wifi_log.h"
#include "wifi_global_func.h"
#include "wifi_channel_helper.h"
#include "wifi_settings.h"
#include "wifi_common_def.h"
#include "wifi_manager.h"
#include <vector>
#include <map>
namespace OHOS {
namespace Wifi {
FuzzedDataProvider *FDP = nullptr;
constexpr int BAND_WIFI_TYPES = 6;
constexpr int IDLE_TIME_OUT_MAX = 60;
constexpr int IPADDR_SEG_NUMS = 4;
constexpr int IPADDR_SEG_ZERO = 0;
constexpr int IPADDR_SEG_ONE = 1;
constexpr int IPADDR_SEG_TWO = 2;
constexpr int IPADDR_SEG_THREE = 3;
static bool g_isInsted = false;
std::shared_ptr<WifiHotspotServiceImpl> pWifiHotspotServiceImpl = std::make_shared<WifiHotspotServiceImpl>();
std::shared_ptr<WifiHotspotMgrServiceImpl> pWifiHotspotMgrServiceImpl = std::make_shared<WifiHotspotMgrServiceImpl>();

bool Init()
{
    if (!g_isInsted) {
        if (WifiConfigCenter::GetInstance().GetScanMidState(0) != WifiOprMidState::RUNNING) {
            LOGE("Init setmidstate!");
            WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::RUNNING, 0);
        }
        g_isInsted = true;
    }
    return true;
}

int TransRandomToRealMacFuzzTest(const uint8_t* data, size_t size)
{
    StationInfo updateInfo;
    StationInfo info;
    info.bssid = std::string(reinterpret_cast<const char*>(data), size);
    info.bssidType = RANDOM_DEVICE_ADDRESS;
    pWifiHotspotServiceImpl->TransRandomToRealMac(updateInfo, info);
    return 0;
}

int IsHotspotDualBandSupportedFuzzTest(const uint8_t* data, size_t size)
{
    std::vector<int> bands;
    ChannelsTable node;
    uint32_t key = static_cast<int>(data[0]);
    bands.push_back(key);
    BandType idx = static_cast<BandType>(key % BAND_WIFI_TYPES);
    node[idx] = bands;
    WifiChannelHelper::GetInstance().SetValidChannels(node);
    bool status = true;
    pWifiHotspotServiceImpl->IsHotspotDualBandSupported(status);
    return 0;
}

int IsOpenSoftApAllowedFuzzTest(FuzzedDataProvider& FDP)
{
    bool status = FDP.ConsumeBool();;
    pWifiHotspotServiceImpl->IsOpenSoftApAllowed(status);
    return 0;
}

void SetHotspotConfigFuzzTest(FuzzedDataProvider& FDP)
{
    Init();
    std::vector<int32_t> band_2G_channel = { 1, 2, 3, 4, 5, 6, 7 };
    std::vector<int32_t> band_5G_channel = { 149, 168, 169 };
    ChannelsTable node{{ BandType::BAND_2GHZ, band_2G_channel }, { BandType::BAND_5GHZ, band_5G_channel }};
    HotspotConfig config;
    config.apBandWidth = FDP->ConsumeIntegral<int>();
    WifiChannelHelper::GetInstance().SetValidChannels(node);
    pWifiHotspotServiceImpl->SetHotspotConfig(config);
}

void SetHotspotIdleTimeoutFuzzTest(const uint8_t* data, size_t size)
{
    Init();
    uint32_t time = static_cast<int>(data[0]) % IDLE_TIME_OUT_MAX;
    pWifiHotspotServiceImpl->SetHotspotIdleTimeout(time);
}

void DisassociateStaFuzzTest(const uint8_t* data, size_t size)
{
    StationInfo info;
    info.bssid = std::string(reinterpret_cast<const char*>(data), size);
    info.bssidType = static_cast<int>(data[0]) % IDLE_TIME_OUT_MAX;
    pWifiHotspotServiceImpl->DisassociateSta(info);
    Init();
    pWifiHotspotServiceImpl->AddBlockList(info);
    pWifiHotspotServiceImpl->DelBlockList(info);
    std::set<PowerModel> setPowerModelList;
    pWifiHotspotServiceImpl->GetSupportedPowerModel(setPowerModelList);
    PowerModel model;
    pWifiHotspotServiceImpl->GetPowerModel(model);
    pWifiHotspotServiceImpl->SetPowerModel(model);
}

void RegisterCallBackFuzzTest()
{
    const sptr<IWifiHotspotCallback> callback;
    const std::vector<std::string> event;
    pWifiHotspotServiceImpl->RegisterCallBack(callback, event);
}

void StationsInfoDumpFuzzTest(FuzzedDataProvider& FDP)
{
    std::string result = FDP.ConsumeBytesAsString(NUM_BYTES);
    pWifiHotspotServiceImpl->StationsInfoDump(result);
}

void CfgCheckIpAddressFuzzTest(const uint8_t* data, size_t size)
{
    std::string ipAddr;
    std::stringstream ss;
    if (size < IPADDR_SEG_NUMS) {
        return;
    }
    ss << data[IPADDR_SEG_ZERO] << "." << data[IPADDR_SEG_ONE] << "." << data[IPADDR_SEG_TWO] << "."
        << data[IPADDR_SEG_THREE];
    ss >> ipAddr;
    pWifiHotspotServiceImpl->CfgCheckIpAddress(ipAddr);
}

void IsValidHotspotConfigFuzzTest(const uint8_t* data, size_t size)
{
    HotspotConfig cfg;
    HotspotConfig cfgFromCenter;
    std::vector<BandType> bandsFromCenter;
    cfg.SetIpAddress("192.168.8.100");
    cfg.SetMaxConn(MAX_AP_CONN + 1);
    cfg.SetSecurityType(KeyMgmt::NONE);
    cfg.SetPreSharedKey(std::string(reinterpret_cast<const char*>(data), size));
    pWifiHotspotServiceImpl->IsValidHotspotConfig(cfg, cfgFromCenter, bandsFromCenter);

    cfg.SetSecurityType(KeyMgmt::WPA_PSK);
    pWifiHotspotServiceImpl->IsValidHotspotConfig(cfg, cfgFromCenter, bandsFromCenter);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    OHOS::Wifi::SetHotspotConfigFuzzTest(FDP);
    OHOS::Wifi::StationsInfoDumpFuzzTest(FDP);
    OHOS::Wifi::IsOpenSoftApAllowedFuzzTest(FDP);
    OHOS::Wifi::TransRandomToRealMacFuzzTest(data, size);
    OHOS::Wifi::IsHotspotDualBandSupportedFuzzTest(data, size);
    OHOS::Wifi::SetHotspotIdleTimeoutFuzzTest(data, size);
    OHOS::Wifi::DisassociateStaFuzzTest(data, size);
    OHOS::Wifi::CfgCheckIpAddressFuzzTest(data, size);
    OHOS::Wifi::IsValidHotspotConfigFuzzTest(data, size);
    OHOS::Wifi::RegisterCallBackFuzzTest();
    return 0;
}
}
}
