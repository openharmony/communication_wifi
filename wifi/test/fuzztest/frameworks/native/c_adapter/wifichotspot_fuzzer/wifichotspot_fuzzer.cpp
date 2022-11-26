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
#include "../../../../../../interfaces/kits/c/wifi_hotspot.h"

static void SetHotspotConfigTest(const uint8_t* data, size_t size)
{
    HotspotConfig config;

    if (size >= sizeof(HotspotConfig)) {
        if (memcpy_s(config.ssid, WIFI_MAX_SSID_LEN, data, WIFI_MAX_SSID_LEN - 1) != EOK) {
            return;
        }

        if (memcpy_s(config.preSharedKey, WIFI_MAX_KEY_LEN, data, WIFI_MAX_KEY_LEN - 1) != EOK) {
            return;
        }
        int index = 0;
        config.securityType = static_cast<int>(data[index++]);
        config.band = static_cast<int>(data[index++]);
        config.channelNum = static_cast<int>(data[index++]);
    }
    (void)SetHotspotConfig(&config);
}

static void GetHotspotConfigTest(const uint8_t* data, size_t size)
{
    HotspotConfig result;

    if (size >= sizeof(HotspotConfig)) {
        if (memcpy_s(result.ssid, WIFI_MAX_SSID_LEN, data, WIFI_MAX_SSID_LEN - 1) != EOK) {
            return;
        }

        if (memcpy_s(result.preSharedKey, WIFI_MAX_KEY_LEN, data, WIFI_MAX_KEY_LEN - 1) != EOK) {
            return;
        }
        int index = 0;
        result.securityType = static_cast<int>(data[index++]);
        result.band = static_cast<int>(data[index++]);
        result.channelNum = static_cast<int>(data[index++]);
    }
    (void)GetHotspotConfig(&result);
}

static void GetStationListTest(const uint8_t* data, size_t size)
{
    StationInfo result;
    unsigned int mSize = 0;

    if (size >= sizeof(StationInfo)) {
        if (memcpy_s(result.macAddress, WIFI_MAC_LEN, data, WIFI_MAC_LEN) != EOK) {
            return;
        }
        int index = 0;
        result.ipAddress = OHOS::Wifi::U32_AT(data);
        result.disconnectedReason = static_cast<unsigned short>(data[index++]);
        mSize = static_cast<unsigned int>(data[index++]);
    }
    (void)GetStationList(&result, &mSize);
}

static void DisassociateStaTest(const uint8_t* data, size_t size)
{
    unsigned char mac = 0;
    int macLen = 0;
    if (size >= TWO) {
        int index = 0;
        mac = data[index++];
        macLen = static_cast<unsigned int>(data[index++]);
    }
    (void)DisassociateSta(&mac, macLen);
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

