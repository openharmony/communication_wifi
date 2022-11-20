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
#include "../../../../../../interfaces/kits/c/wifi_hotspot.h"

namespace OHOS {
namespace Wifi {
    bool WifiCHotSpotFuzzerTest(const uint8_t* data, size_t size)
    {
        HotspotConfig *config = reinterpret_cast<const HotspotConfig*>(data);
        (void)EnableHotspot();
        (void)DisableHotspot();
        (void)IsHotspotActive();
        SetHotspotConfig(config);
        GetHotspotConfig(nullptr);
        GetStationList(nullptr, nullptr);
        DisassociateSta(nullptr, size);
        AddTxPowerInfo(0);
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

