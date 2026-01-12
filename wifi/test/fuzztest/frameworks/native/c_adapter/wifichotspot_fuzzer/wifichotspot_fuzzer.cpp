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
#include "wifi_fuzz_common_func.h"
#include "kits/c/wifi_hotspot.h"
#include <fuzzer/FuzzedDataProvider.h>

static void SetHotspotConfigTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    HotspotConfig config;

    if (size >= sizeof(HotspotConfig)) {
        if (memcpy_s(config.ssid, WIFI_MAX_SSID_LEN, data, WIFI_MAX_SSID_LEN - 1) != EOK) {
            return;
        }

        if (memcpy_s(config.preSharedKey, WIFI_MAX_KEY_LEN, data, WIFI_MAX_KEY_LEN - 1) != EOK) {
            return;
        }
        config.securityType = FDP.ConsumeIntegral<int>();
        config.band = FDP.ConsumeIntegral<int>();
        config.channelNum = FDP.ConsumeIntegral<int>();
    }
    (void)SetHotspotConfig(&config);
}

static void GetHotspotConfigTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    HotspotConfig result;

    if (size >= sizeof(HotspotConfig)) {
        if (memcpy_s(result.ssid, WIFI_MAX_SSID_LEN, data, WIFI_MAX_SSID_LEN - 1) != EOK) {
            return;
        }

        if (memcpy_s(result.preSharedKey, WIFI_MAX_KEY_LEN, data, WIFI_MAX_KEY_LEN - 1) != EOK) {
            return;
        }
        result.securityType = FDP.ConsumeIntegral<int>();
        result.band = FDP.ConsumeIntegral<int>();
        result.channelNum = FDP.ConsumeIntegral<int>();
    }
    (void)GetHotspotConfig(&result);
}

static void GetStationListTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    StationInfo result;
    unsigned int mSize = 0;

    if (size >= sizeof(StationInfo)) {
        if (memcpy_s(result.macAddress, WIFI_MAC_LEN, data, WIFI_MAC_LEN) != EOK) {
            return;
        }
        result.ipAddress = OHOS::Wifi::U32_AT(data);
        result.disconnectedReason = FDP.ConsumeIntegral<unsigned short>();
        mSize = FDP.ConsumeIntegral<unsigned int>();
    }
    (void)GetStationList(&result, &mSize);
}

static void DisassociateStaTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    unsigned char mac = 0;
    int macLen = 0;
    if (size >= TWO) {
        int index = 0;
        mac = data[index++];
        macLen = FDP.ConsumeIntegral<unsigned int>();
    }
    (void)DisassociateSta(&mac, macLen);
}

static void GetHotspotModeTest(const uint8_t* data, size_t size)
{
    int mode = 3;  // 3: HotspotMode::LOCAL_ONLY_SOFTAP
    (void)GetHotspotMode(&mode);
    FuzzedDataProvider fdp(data, size);
    mode = fdp.ConsumeIntegral<int>();
    (void)GetHotspotMode(&mode);
}
 
static void GetLocalOnlyHotspotConfigTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    HotspotConfig localOnlyResult;
 
    if (size >= sizeof(HotspotConfig)) {
        if (memcpy_s(localOnlyResult.ssid, WIFI_MAX_SSID_LEN, data, WIFI_MAX_SSID_LEN - 1) != EOK) {
            return;
        }
 
        if (memcpy_s(localOnlyResult.preSharedKey, WIFI_MAX_KEY_LEN, data, WIFI_MAX_KEY_LEN - 1) != EOK) {
            return;
        }
        localOnlyResult.securityType = FDP.ConsumeIntegral<int>();
        localOnlyResult.band = FDP.ConsumeIntegral<int>();
        localOnlyResult.channelNum = FDP.ConsumeIntegral<int>();
    }
    (void)GetLocalOnlyHotspotConfig(&localOnlyResult);
}

namespace OHOS {
namespace Wifi {
    bool WifiCHotSpotFuzzerTest(const uint8_t* data, size_t size)
    {
        (void)EnableHotspot();
        (void)DisableHotspot();
        (void)IsHotspotActive();
        (void)AddTxPowerInfo(0);
        SetHotspotConfigTest(data, size);
        GetHotspotConfigTest(data, size);
        GetStationListTest(data, size);
        DisassociateStaTest(data, size);
        (void)EnableLocalOnlyHotspot();
        (void)DisableLocalOnlyHotspot();
        GetHotspotModeTest(data, size);
        GetLocalOnlyHotspotConfigTest(data, size);
        return true;
    }
}  // namespace Wifi
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Wifi::WifiCHotSpotFuzzerTest(data, size);
    return 0;
}

