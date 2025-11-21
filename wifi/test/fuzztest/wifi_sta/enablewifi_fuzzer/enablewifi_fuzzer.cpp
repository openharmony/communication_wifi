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

#include "enablewifi_fuzzer.h"
#include "wifi_device.h"
#include <fuzzer/FuzzedDataProvider.h>
namespace OHOS {
namespace Wifi {
    static const int32_t NUM_BYTES = 1;
    std::shared_ptr<WifiDevice> devicePtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    bool EnableWifiFuzzerTest(FuzzedDataProvider& FDP)
    {
        WifiLinkedInfo info;
        std::string get_countryCode = FDP.ConsumeBytesAsString(NUM_BYTES);
        std::string set_countryCode = FDP.ConsumeBytesAsString(NUM_BYTES);
        int addResult;

        WifiDeviceConfig config;
        config.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
        config.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
        config.preSharedKey = FDP.ConsumeBytesAsString(NUM_BYTES);
        config.keyMgmt = FDP.ConsumeBytesAsString(NUM_BYTES);

        info.networkId = FDP.ConsumeIntegral<int>();
        info.rssi = FDP.ConsumeIntegral<int>();
        info.band = FDP.ConsumeIntegral<int>();
        info.linkSpeed = FDP.ConsumeIntegral<int>();
        info.frequency = FDP.ConsumeIntegral<int>();
        info.macType = FDP.ConsumeIntegral<int>();
        info.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
        info.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
        info.macAddress = FDP.ConsumeIntegral<int>();

        if (devicePtr == nullptr) {
            return false;
        }

        bool isCandidate = false;
        devicePtr->EnableWifi();
        devicePtr->RemoveAllDevice();
        devicePtr->SetLowLatencyMode(isCandidate);
        devicePtr->UpdateDeviceConfig(config, addResult);
        devicePtr->GetCountryCode(get_countryCode);
        devicePtr->SetCountryCode(set_countryCode);
        devicePtr->GetLinkedInfo(info);
        devicePtr->IsWifiActive(isCandidate);
        return true;
    }
}  // namespace Wifi
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP (data, size);
    OHOS::Wifi::EnableWifiFuzzerTest(FDP);
    return 0;
}
