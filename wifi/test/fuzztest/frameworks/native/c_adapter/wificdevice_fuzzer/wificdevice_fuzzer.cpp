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
#include "wificdevice_fuzzer.h"
#include "../../../../../../interfaces/kits/c/wifi_device.h"


void EnableWifiTest()
{
    EnableWifi();
}
void DisableWifiTest()
{
    DisableWifi();
}
void ScanTest()
{
    Scan();
}
void DisconnectTest()
{
    Disconnect();
}
void RemoveDeviceTest(const uint8_t* data, size_t size)
{
    if (size <= 0) {
        return;
    }
    int networkId = static_cast<int>(data[0]);
    RemoveDevice(networkId);
}
void DisableDeviceConfigTest(const uint8_t* data, size_t size)
{
    if (size <= 0) {
        return;
    }
    int networkId = static_cast<int>(data[0]);
    DisableDeviceConfig(networkId);
}
void EnableDeviceConfigTest(const uint8_t* data, size_t size)
{
    if (size <= 0) {
        return;
    }
    int networkId = static_cast<int>(data[0]);
    EnableDeviceConfig(networkId);
}
void ConnectToTest(const uint8_t* data, size_t size)
{
    if (size <= 0) {
        return;
    }
    int networkId = static_cast<int>(data[0]);
    ConnectTo(networkId)
}
namespace OHOS {
namespace Wifi {
    bool WifiCDeviceFuzzerTest(const uint8_t* data, size_t size)
    {
        EnableWifiTest();
        DisableWifiTest();
        ScanTest();
        RemoveDeviceTest(data, size);
        DisableDeviceConfigTest(data, size);
        EnableDeviceConfigTest(data, size);
        ConnectToTest(data, size);
        DisconnectTest();
        return true;
    }
}  // namespace Wifi
}  // namespace OHOS
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Wifi::WifiCDeviceFuzzerTest(data, size);
    return 0;
}

