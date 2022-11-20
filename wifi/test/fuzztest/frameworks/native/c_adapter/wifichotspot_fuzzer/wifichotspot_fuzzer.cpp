/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "securec.h"
#include "wifichotspot_fuzzer.h"
#include "../../../../../../interfaces/kits/c/wifi_hotspot.h"

namespace OHOS {
namespace Wifi {
    bool WifiCHotSpotFuzzerTest(const uint8_t* data, size_t size)
    {
        (void)EnableHotspot();
        (void)DisableHotspot();
        (void)IsHotspotActive();
        IsHotspotDualBandSupportedTest(data, size);
        SetHotspotConfigTest(data, size);
        GetHotspotConfigTest(data, size);
        GetStationListTest(data, size);
        DisassociateStaTest(data, size);
        AddTxPowerInfoTest(data, size);
        return true;
    }
}  // namespace Wifi
}  // namespace OHOS

void IsHotspotDualBandSupportedTest(const uint8_t* data, size_t size)
{
    bool isSupported = false;
    IsHotspotDualBandSupported(&isSupported);
}

void SetHotspotConfigTest(const uint8_t* data, size_t size)
{
    HotspotConfig *config;
    config->ssid = std::string(reinterpret_cast<const char*>(data), size);
    config->preSharedKey = std::string(reinterpret_cast<const char*>(data), size); 
    (void)SetHotspotConfig(config);
}

void GetHotspotConfigTest(const uint8_t* data, size_t size)
{
    HotspotConfig *result;
    int index = 0;

    result->ssid = std::string(reinterpret_cast<const char*>(data), size);
    result->preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    if (size >=3) {
        result->securityType = static_cast<int>(data[index++]);
        result->band = static_cast<int>(data[index++]);
        result->channelNum = static_cast<int>(data[index++]);
    } 
    (void)GetHotspotConfig(result);
}

void GetStationListTest(const uint8_t* data, size_t size)
{
    StationInfo *result;
    unsigned int *size;
    int index = 0;

    result->deviceName = std::string(reinterpret_cast<const char*>(data), size);
    result->bssid = std::string(reinterpret_cast<const char*>(data), size);
    result->ipAddr = std::string(reinterpret_cast<const char*>(data), size);
    if (size >=3) {
        result->securityType = static_cast<int>(data[index++]);
        result->band = static_cast<int>(data[index++]);
        result->channelNum = static_cast<int>(data[index++]);
    } 
    (void)GetStationList(result, size);
}

void DisassociateStaTest(const uint8_t* data, size_t size)
{
    unsigned char *mac = reinterpret_cast<unsigned char *>(data);
    int macLen = static_cast<int> (size);
    (void)DisassociateSta(mac, maclen);
}

void AddTxPowerInfoTest(const uint8_t* data, size_t size)
{
    int power = 0;
    (void)AddTxPowerInfo(int power);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Wifi::WifiCHotSpotFuzzerTest(data, size);
    return 0;
}

