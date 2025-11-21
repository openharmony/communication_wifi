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

#include "connecttodevice_fuzzer.h"
#include "wifi_device.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Wifi {
    static const int32_t NUM_BYTES = 1;
    std::shared_ptr<WifiDevice> devicePtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    bool ConnectToDeviceFuzzerTest(FuzzedDataProvider& FDP)
    {
        if (devicePtr == nullptr) {
            return false;
        }

        WifiDeviceConfig config;
        config.ssid = FDP.ConsumeBytesAsString(NUM_BYTES);
        config.bssid = FDP.ConsumeBytesAsString(NUM_BYTES);
        config.preSharedKey = FDP.ConsumeBytesAsString(NUM_BYTES);
        config.keyMgmt = FDP.ConsumeBytesAsString(NUM_BYTES);
        devicePtr->ConnectToDevice(config);
        return true;
    }
}  // namespace Wifi
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    OHOS::Wifi::ConnectToDeviceFuzzerTest(FDP);
    return 0;
}

