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

namespace OHOS {
namespace Wifi {
    std::unique_ptr<WifiDevice> devicePtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    bool EnableWifiFuzzerTest(const uint8_t* data, size_t size)
    {
        WifiLinkedInfo info;
        std::string get_countryCode = std::string(reinterpret_cast<const char*>(data), size);
        std::string set_countryCode = std::string(reinterpret_cast<const char*>(data), size);
        int addResult;

        WifiDeviceConfig config;
        config.ssid = std::string(reinterpret_cast<const char*>(data), size);
        config.bssid = std::string(reinterpret_cast<const char*>(data), size);
        config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
        config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);

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
        }
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
    OHOS::Wifi::EnableWifiFuzzerTest(data, size);
    return 0;
}

