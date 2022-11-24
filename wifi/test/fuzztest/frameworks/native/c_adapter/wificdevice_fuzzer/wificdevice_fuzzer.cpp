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
#include "securec.h"
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
    ConnectTo(networkId);
}
void AddDeviceConfigTest(const uint8_t* data, size_t size)
{
    int index = 0;
    WifiDeviceConfig config;
    if (size >= sizeof(WifiDeviceConfig)) {
        if (memcpy_s(config.ssid, WIFI_MAX_SSID_LEN, data, WIFI_MAX_SSID_LEN - 1) != EOK) {
            return;
        }
        if (memcpy_s(config.bssid, WIFI_MAC_LEN, data, WIFI_MAC_LEN - 1) != EOK) {
            return;
        }
        if (memcpy_s(config.preSharedKey, WIFI_MAX_KEY_LEN, data, WIFI_MAX_KEY_LEN - 1) != EOK) {
            return;
        }
        config.securityType = static_cast<int>(data[index++]);
        config.netId = static_cast<int>(data[index++]);
        config.freq = static_cast<int>(data[index++]);
        config.wapiPskType = static_cast<int>(data[index++]);
        config.isHiddenSsid = static_cast<int>(data[index++]);
        IpType ipType = STATIC_IP;
        if (ipType % 2 == 1) {
            ipType = DHCP;
        } else if (ipType % 2 == 0) {
            ipType = UNKNOWN;
        }
    }
    int result = static_cast<int>(data[index++]);
    AddDeviceConfig(&config, &result);
}
void AdvanceScanTest(const uint8_t* data, size_t size)
{
    int index = 0;
    WifiScanParams params;
    if (size >= sizeof(WifiScanParams)) {
        if (memcpy_s(params.ssid, WIFI_MAX_SSID_LEN, data, WIFI_MAX_SSID_LEN - 1) != EOK) {
            return;
        }
        if (memcpy_s(params.bssid, WIFI_MAC_LEN, data, WIFI_MAC_LEN - 1) != EOK) {
            return;
        }
        params.scanType = WIFI_FREQ_SCAN;
        params.freqs = static_cast<int>(data[index++]);
        params.band = static_cast<int>(data[index++]);
        params.ssidLen = static_cast<int>(data[index++]);
    }
    AdvanceScan(&params);
}
void GetSignalLevelTest(const uint8_t* data, size_t size)
{
    int rssi = 0;
    int band = 0;
    int index = 0;
    if (size >= 2) {
        rssi = static_cast<int>(data[index++]);
        band = static_cast<int>(data[index++]);
    }
    GetSignalLevel(rssi, band);
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
        AddDeviceConfigTest(data, size);
        AdvanceScanTest(data, size);
        GetSignalLevelTest(data, size);
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

