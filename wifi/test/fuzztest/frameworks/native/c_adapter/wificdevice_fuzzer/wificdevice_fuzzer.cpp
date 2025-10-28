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
#include "kits/c/wifi_device.h"
#include <fuzzer/FuzzedDataProvider.h>

static FuzzedDataProvider *FDP = nullptr;
static const int32_t NUM_BYTES = 1;

static void EnableWifiTest()
{
    EnableWifi();
}
static void EnableSemiWifiTest()
{
    EnableSemiWifi();
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
static void RemoveDeviceTest()
{
    int networkId = FDP->ConsumeIntegral<int>();
    RemoveDevice(networkId);
}
static void DisableDeviceConfigTest()
{
    int networkId = FDP->ConsumeIntegral<int>();
    int64_t blockDuration = FDP->ConsumeIntegral<int64_t>();
    DisableDeviceConfig(networkId, blockDuration);
}
static void EnableDeviceConfigTest()
{
    int networkId = FDP->ConsumeIntegral<int>();
    EnableDeviceConfig(networkId);
}
static void ConnectToTest()
{
    int networkId = FDP->ConsumeIntegral<int>();
    ConnectTo(networkId);
}
static void AddDeviceConfigTest()
{
    WifiDeviceConfig config;
    std::string ssid_str = FDP->ConsumeBytesAsString(NUM_BYTES);
    strcpy_s(config.ssid, sizeof(config.ssid), ssid_str.c_str());
    std::vector<unsigned char> bssid_vec = FDP->ConsumeBytes<unsigned char>(NUM_BYTES);
    memcpy_s(config.bssid, sizeof(config.bssid), bssid_vec.data(), bssid_vec.size());
    std::string preSharedKey_str = FDP->ConsumeBytesAsString(NUM_BYTES);
    strcpy_s(config.preSharedKey, sizeof(config.ssid), preSharedKey_str.c_str());
    config.securityType = FDP->ConsumeIntegral<int>();
    config.netId = FDP->ConsumeIntegral<int>();
    config.freq = FDP->ConsumeIntegral<int>();
    config.wapiPskType = FDP->ConsumeIntegral<int>();
    config.isHiddenSsid = FDP->ConsumeIntegral<int>();
    config.ipType = static_cast<IpType>(FDP->ConsumeIntegral<uint8_t>() % TWO);
    int result = FDP->ConsumeIntegral<int>();
    AddDeviceConfig(&config, &result);
}
static void AdvanceScanTest()
{
    WifiScanParams params;
    std::string ssid_str = FDP->ConsumeBytesAsString(NUM_BYTES);
    strcpy_s(params.ssid, sizeof(params.ssid), ssid_str.c_str());
    std::vector<unsigned char> bssid_vec = FDP->ConsumeBytes<unsigned char>(NUM_BYTES);
    memcpy_s(params.bssid, sizeof(params.bssid), bssid_vec.data(), bssid_vec.size());
    params.scanType = static_cast<WifiScanType>(FDP->ConsumeIntegral<uint8_t>() % FOUR);
    params.freqs = FDP->ConsumeIntegral<int>();
    params.band = FDP->ConsumeIntegral<int>();
    params.ssidLen =  FDP->ConsumeIntegral<char>();
    AdvanceScan(&params);
}
static void GetSignalLevelTest()
{
    int rssi = FDP->ConsumeIntegral<int>();
    int band = FDP->ConsumeIntegral<int>();
    GetSignalLevel(rssi, band);
}

static void GetScanInfoListTest()
{
    WifiScanInfo result;
    std::string ssid_str = FDP->ConsumeBytesAsString(NUM_BYTES);
    strcpy_s(result.ssid, sizeof(result.ssid), ssid_str.c_str());
    std::vector<unsigned char> bssid_vec = FDP->ConsumeBytes<unsigned char>(NUM_BYTES);
    memcpy_s(result.bssid, sizeof(result.bssid), bssid_vec.data(), bssid_vec.size());
    result.securityType = FDP->ConsumeIntegral<int>();
    result.rssi = FDP->ConsumeIntegral<int>();
    result.band = FDP->ConsumeIntegral<int>();
    result.frequency = FDP->ConsumeIntegral<int>();
    result.channelWidth = static_cast<WifiChannelWidth>(FDP->ConsumeIntegralInRange<int>(0, WIDTH_INVALID));
    result.centerFrequency0 = FDP->ConsumeIntegral<int>();
    result.centerFrequency1 = FDP->ConsumeIntegral<int>();
    result.timestamp = FDP->ConsumeIntegral<int64_t>();
    unsigned int mSize = FDP->ConsumeIntegral<unsigned int>();
    (void)GetScanInfoList(&result, &mSize);
}

static void GetDeviceConfigsTest()
{
    WifiDeviceConfig result;
    std::string ssid_str = FDP->ConsumeBytesAsString(NUM_BYTES);
    strcpy_s(result.ssid, sizeof(result.ssid), ssid_str.c_str());
    std::vector<unsigned char> bssid_vec = FDP->ConsumeBytes<unsigned char>(NUM_BYTES);
    memcpy_s(result.bssid, sizeof(result.bssid), bssid_vec.data(), bssid_vec.size());
    std::string preSharedKey_str = FDP->ConsumeBytesAsString(NUM_BYTES);
    strcpy_s(result.preSharedKey, sizeof(result.ssid), preSharedKey_str.c_str());
    result.securityType = FDP->ConsumeIntegral<int>();
    result.netId = FDP->ConsumeIntegral<int>();
    result.freq = FDP->ConsumeIntegral<int>();
    result.wapiPskType = FDP->ConsumeIntegral<int>();
    result.ipType = static_cast<IpType>(FDP->ConsumeIntegral<uint8_t>() % UNKNOWN);
    result.staticIp.ipAddress = FDP->ConsumeIntegral<unsigned int>();
    result.staticIp.gateway = FDP->ConsumeIntegral<unsigned int>();
    result.staticIp.netmask = FDP->ConsumeIntegral<unsigned int>();
    result.isHiddenSsid = FDP->ConsumeIntegral<int>();
    unsigned int mSize = FDP->ConsumeIntegral<unsigned int>();
    (void)GetDeviceConfigs(&result, &mSize);
}

static void ConnectToDeviceTest()
{
    WifiDeviceConfig config;
    std::string ssid_str = FDP->ConsumeBytesAsString(NUM_BYTES);
    strcpy_s(config.ssid, sizeof(config.ssid), ssid_str.c_str());
    std::vector<unsigned char> bssid_vec = FDP->ConsumeBytes<unsigned char>(NUM_BYTES);
    memcpy_s(config.bssid, sizeof(config.bssid), bssid_vec.data(), bssid_vec.size());
    std::string preSharedKey_str = FDP->ConsumeBytesAsString(NUM_BYTES);
    strcpy_s(config.preSharedKey, sizeof(config.ssid), preSharedKey_str.c_str());
    config.securityType = FDP->ConsumeIntegral<int>();
    config.netId = FDP->ConsumeIntegral<int>();
    config.freq = FDP->ConsumeIntegral<int>();
    config.wapiPskType = FDP->ConsumeIntegral<int>();
    config.isHiddenSsid = FDP->ConsumeIntegral<int>();
    config.ipType = static_cast<IpType>(FDP->ConsumeIntegral<uint8_t>() % UNKNOWN);
    config.staticIp.ipAddress = FDP->ConsumeIntegral<unsigned int>();
    config.staticIp.gateway = FDP->ConsumeIntegral<unsigned int>();
    config.staticIp.netmask = FDP->ConsumeIntegral<unsigned int>();
    config.isHiddenSsid = FDP->ConsumeIntegral<int>();
    (void)ConnectToDevice(&config);
}

static void GetLinkedInfoTest()
{
    WifiLinkedInfo result;
    std::string ssid_str = FDP->ConsumeBytesAsString(NUM_BYTES);
    strcpy_s(result.ssid, sizeof(result.ssid), ssid_str.c_str());
    std::vector<unsigned char> bssid_vec = FDP->ConsumeBytes<unsigned char>(NUM_BYTES);
    memcpy_s(result.bssid, sizeof(result.bssid), bssid_vec.data(), bssid_vec.size());
    result.frequency = FDP->ConsumeIntegral<int>();
    result.connState = static_cast<WifiConnState>(FDP->ConsumeIntegral<uint8_t>() % (WIFI_CONNECTED + 1));
    result.disconnectedReason = FDP->ConsumeIntegral<unsigned short>();
    result.ipAddress = FDP->ConsumeIntegral<unsigned int>();
    (void)GetLinkedInfo(&result);
}

static void GetDeviceMacAddressTest()
{
    unsigned char result = FDP->ConsumeIntegral<unsigned char>();
    (void)GetDeviceMacAddress(&result);
}

static void GetWifiDetailStateTest()
{
    WifiDetailState state = static_cast<WifiDetailState>(FDP->ConsumeIntegralInRange<int>(-1, 5));
    (void)GetWifiDetailState(&state);
}

static void GetIpInfoTest()
{
    IpInfo info;
    info.ipAddress = FDP->ConsumeIntegral<unsigned int>();
    info.netMask = FDP->ConsumeIntegral<unsigned int>();
    info.netGate = FDP->ConsumeIntegral<unsigned int>();
    info.dns1 = FDP->ConsumeIntegral<unsigned int>();
    info.dns2 = FDP->ConsumeIntegral<unsigned int>();
    info.serverAddress = FDP->ConsumeIntegral<unsigned int>();
    info.leaseDuration = FDP->ConsumeIntegral<int>();
    (void)GetIpInfo(&info);
}

static void SetLowLatencyModeTest()
{
    int enabled = FDP->ConsumeIntegral<int>();
    (void)SetLowLatencyMode(enabled);
}

static void Get5GHzChannelListTest()
{
    int result = FDP->ConsumeIntegral<int>();
    int sizet = FDP->ConsumeIntegral<int>();
    (void)Get5GHzChannelList(&result, &sizet);
}

static void IsBandTypeSupportedTest()
{
    bool supported =  FDP->ConsumeBool();
    int bandType = FDP->ConsumeIntegral<int>();
    (void)IsBandTypeSupported(bandType, &supported);
}

namespace OHOS {
namespace Wifi {
    bool WifiCDeviceFuzzerTest()
    {
        EnableWifiTest();
        DisableWifiTest();
        EnableSemiWifiTest();
        ScanTest();
        RemoveDeviceTest();
        DisableDeviceConfigTest();
        EnableDeviceConfigTest();
        ConnectToTest();
        DisconnectTest();
        AddDeviceConfigTest();
        AdvanceScanTest();
        GetSignalLevelTest();
        (void)IsWifiActive();
        GetScanInfoListTest();
        GetDeviceConfigsTest();
        ConnectToDeviceTest();
        GetLinkedInfoTest();
        GetDeviceMacAddressTest();
        GetWifiDetailStateTest();
        GetIpInfoTest();
        SetLowLatencyModeTest();
        Get5GHzChannelListTest();
        IsBandTypeSupportedTest();
        return true;
    }
}  // namespace Wifi
}  // namespace OHOS
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    FDP = &fdp;
    OHOS::Wifi::WifiCDeviceFuzzerTest();
    return 0;
}

