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
#include "wifi_fuzz_common_func.h"
#include "../../../../../../interfaces/kits/c/wifi_device.h"


static void EnableWifiTest()
{
    EnableWifi();
}
static void DisableWifiTest()
{
    DisableWifi();
}
static void ScanTest()
{
    Scan();
}
static void DisconnectTest()
{
    Disconnect();
}
static void RemoveDeviceTest(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return;
    }
    int networkId = static_cast<int>(data[0]);
    RemoveDevice(networkId);
}
static void DisableDeviceConfigTest(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return;
    }
    int networkId = static_cast<int>(data[0]);
    DisableDeviceConfig(networkId);
}
static void EnableDeviceConfigTest(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return;
    }
    int networkId = static_cast<int>(data[0]);
    EnableDeviceConfig(networkId);
}
static void ConnectToTest(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return;
    }
    int networkId = static_cast<int>(data[0]);
    ConnectTo(networkId);
}
static void AddDeviceConfigTest(const uint8_t* data, size_t size)
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
        config.ipType = static_cast<IpType>(static_cast<int>(data[index++]) % TWO);
    }
    int result = static_cast<int>(data[index++]);
    AddDeviceConfig(&config, &result);
}
static void AdvanceScanTest(const uint8_t* data, size_t size)
{
    WifiScanParams params;
    if (size >= sizeof(WifiScanParams)) {
        if (memcpy_s(params.ssid, WIFI_MAX_SSID_LEN, data, WIFI_MAX_SSID_LEN - 1) != EOK) {
            return;
        }
        if (memcpy_s(params.bssid, WIFI_MAC_LEN, data, WIFI_MAC_LEN - 1) != EOK) {
            return;
        }
        int index = 0;
        params.scanType = WIFI_FREQ_SCAN;
        params.freqs = static_cast<int>(data[index++]);
        params.band = static_cast<int>(data[index++]);
        params.ssidLen = static_cast<int>(data[index++]);
    }
    AdvanceScan(&params);
}
static void GetSignalLevelTest(const uint8_t* data, size_t size)
{
    int rssi = 0;
    int band = 0;
    if (size >= TWO) {
        int index = 0;
        rssi = static_cast<int>(data[index++]);
        band = static_cast<int>(data[index++]);
    }
    GetSignalLevel(rssi, band);
}

static void GetScanInfoListTest(const uint8_t* data, size_t size)
{
    WifiScanInfo result;
    unsigned int mSize;
    if (size >= sizeof(WifiScanInfo)) {
        if (memcpy_s(result.ssid, WIFI_MAX_SSID_LEN, data, WIFI_MAX_SSID_LEN - 1) != EOK) {
            return;
        }

        if (memcpy_s(result.bssid, WIFI_MAC_LEN, data + WIFI_MAX_SSID_LEN, WIFI_MAC_LEN) != EOK) {
            return;
        }
        int index = 0;
        result.securityType = static_cast<int>(data[index++]);
        result.rssi = static_cast<int>(data[index++]);
        result.band = static_cast<int>(data[index++]);
        result.frequency = static_cast<int>(data[index++]);
        result.channelWidth = static_cast<WifiChannelWidth>(static_cast<int>(data[index++]) % WIDTH_INVALID);
        result.centerFrequency0 = static_cast<int>(data[index++]);
        result.centerFrequency1 = static_cast<int>(data[index++]);
        result.timestamp = static_cast<int64_t>(OHOS::Wifi::U32_AT(data));
        mSize = static_cast<unsigned int>(data[0]);
    }
    (void)GetScanInfoList(&result, &mSize);
}

static void GetDeviceConfigsTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig result;
    unsigned int mSize;
    if (size >= sizeof(WifiDeviceConfig)) {
        if (memcpy_s(result.ssid, WIFI_MAX_SSID_LEN, data, WIFI_MAX_SSID_LEN - 1) != EOK) {
            return;
        }

        if (memcpy_s(result.bssid, WIFI_MAC_LEN, data + WIFI_MAX_SSID_LEN, WIFI_MAC_LEN) != EOK) {
            return;
        }

        if (memcpy_s(result.preSharedKey, WIFI_MAX_KEY_LEN, data + WIFI_MAX_SSID_LEN, WIFI_MAX_KEY_LEN - 1) != EOK) {
            return;
        }
        int index = 0;
        result.securityType = static_cast<int>(data[index++]);
        result.netId = static_cast<int>(data[index++]);
        result.freq = static_cast<unsigned int>(data[index++]);
        result.wapiPskType = static_cast<int>(data[index++]);
        result.ipType = static_cast<IpType>(static_cast<int>(data[index++]) % UNKNOWN);
        result.staticIp.ipAddress = static_cast<unsigned int>(data[index++]);
        result.staticIp.gateway = static_cast<unsigned int>(data[index++]);
        result.staticIp.netmask = static_cast<unsigned int>(data[index++]);
        result.isHiddenSsid = static_cast<int>(data[index++]);
        mSize = static_cast<unsigned int>(data[0]);
    }
    (void)GetDeviceConfigs(&result, &mSize);
}

static void ConnectToDeviceTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    if (size >= sizeof(WifiDeviceConfig)) {
        if (memcpy_s(config.ssid, WIFI_MAX_SSID_LEN, data, WIFI_MAX_SSID_LEN - 1) != EOK) {
            return;
        }

        if (memcpy_s(config.bssid, WIFI_MAC_LEN, data + WIFI_MAX_SSID_LEN, WIFI_MAC_LEN) != EOK) {
            return;
        }

        if (memcpy_s(config.preSharedKey, WIFI_MAX_KEY_LEN, data + WIFI_MAX_SSID_LEN, WIFI_MAX_KEY_LEN - 1) != EOK) {
            return;
        }
        int index = 0;
        config.securityType = static_cast<int>(data[index++]);
        config.netId = static_cast<int>(data[index++]);
        config.freq = static_cast<unsigned int>(data[index++]);
        config.wapiPskType = static_cast<int>(data[index++]);
        config.ipType = static_cast<IpType>(static_cast<int>(data[index++]) % UNKNOWN);
        config.staticIp.ipAddress = static_cast<unsigned int>(data[index++]);
        config.staticIp.gateway = static_cast<unsigned int>(data[index++]);
        config.staticIp.netmask = static_cast<unsigned int>(data[index++]);
        config.isHiddenSsid = static_cast<int>(data[index++]);
    }
    (void)ConnectToDevice(&config);
}

static void GetLinkedInfoTest(const uint8_t* data, size_t size)
{
    WifiLinkedInfo result;
    if (size >= sizeof(WifiLinkedInfo)) {
        if (memcpy_s(result.ssid, WIFI_MAX_SSID_LEN, data, WIFI_MAX_SSID_LEN - 1) != EOK) {
            return;
        }

        if (memcpy_s(result.bssid, WIFI_MAC_LEN, data + WIFI_MAX_SSID_LEN, WIFI_MAC_LEN) != EOK) {
            return;
        }
        int index = 0;
        result.rssi = static_cast<int>(data[index++]);
        result.band = static_cast<int>(data[index++]);
        result.frequency = static_cast<int>(data[index++]);
        result.connState = static_cast<WifiConnState>(static_cast<int>(data[index++]) % (WIFI_CONNECTED + 1));
        result.disconnectedReason = static_cast<unsigned short>(data[index++]);
        result.ipAddress = static_cast<unsigned int>(data[index++]);
    }
    (void)GetLinkedInfo(&result);
}

static void GetDeviceMacAddressTest(const uint8_t* data, size_t size)
{
    unsigned char result;
    if (size > 0) {
        result = static_cast<unsigned char>(data[0]);
    }
    (void)GetDeviceMacAddress(&result);
}

static void GetIpInfoTest(const uint8_t* data, size_t size)
{
    IpInfo info;
    if (size >= sizeof(IpInfo)) {
        int index = 0;
        info.ipAddress = static_cast<unsigned int>(data[index++]);
        info.netMask = static_cast<unsigned int>(data[index++]);
        info.netGate = static_cast<unsigned int>(data[index++]);
        info.dns1 = static_cast<unsigned int>(data[index++]);
        info.dns2 = static_cast<unsigned int>(data[index++]);
        info.serverAddress = static_cast<unsigned int>(data[index++]);
        info.leaseDuration = static_cast<int>(data[index++]);
    }
    (void)GetIpInfo(&info);
}

static void SetLowLatencyModeTest(const uint8_t* data, size_t size)
{
    int enabled = 0;
    if (size == 0) {
        return;
    }
    enabled = static_cast<int>(data[0]);
    (void)SetLowLatencyMode(enabled);
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
        (void)IsWifiActive();
        GetScanInfoListTest(data, size);
        GetDeviceConfigsTest(data, size);
        ConnectToDeviceTest(data, size);
        GetLinkedInfoTest(data, size);
        GetDeviceMacAddressTest(data, size);
        GetIpInfoTest(data, size);
        SetLowLatencyModeTest(data, size);
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

