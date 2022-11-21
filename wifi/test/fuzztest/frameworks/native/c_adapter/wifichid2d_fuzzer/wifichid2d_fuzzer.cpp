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
#include "wifichid2d_fuzzer.h"
#include "../../../../../../interfaces/kits/c/wifi_hid2d.h"

namespace OHOS {
namespace Wifi {
    bool WifiCHid2dFuzzerTest(const uint8_t* data, size_t size)
    {
        Hid2dRequestGcIpTest(data, size);
        Hid2dSharedlinkIncreaseTest();
        Hid2dSharedlinkDecreaseTest();
        Hid2dIsWideBandwidthSupportedTest();
        return true;
    }
}  // namespace Wifi
}  // namespace OHOS

void Hid2dRequestGcIpTest(const uint8_t* data, size_t size)
{
    unsigned char gcMac[MACLEN] = {0};
    unsigned int ipAddr[IPLEN] = {0};
    if (size >= MACLEN) {
        if (memcpy_s(gcMac, MACLEN, data, MACLEN) != EOK) {
            memset_s(gcMac, MACLEN, 0, MACLEN);
        }

        for (int i = 0; i < IPLEN; i++) {
            ipAddr[i] = static_cast<int>(data[i]);
        }
    }

    (void)Hid2dRequestGcIp(gcMac, ipAddr);
}

void Hid2dSharedlinkIncreaseTest(void)
{
    (void)Hid2dSharedlinkIncrease();
}

void Hid2dSharedlinkDecreaseTest(void)
{
    (void)Hid2dSharedlinkDecrease();
}

void Hid2dIsWideBandwidthSupportedTest(void)
{
    (void)Hid2dIsWideBandwidthSupported();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Wifi::WifiCHid2dFuzzerTest(data, size);
    return 0;
}

