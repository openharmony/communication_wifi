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
#include "wificp2p_fuzzer.h"
#include "../../../../../../interfaces/kits/c/wifi_p2p.h"

namespace OHOS {
namespace Wifi {
    bool WifiCP2PFuzzerTest(const uint8_t* data, size_t size)
    {
        (void)EnableP2p();
        (void)DisableP2p();
        (void)DiscoverDevices();
        (void)StopDiscoverDevices();
        (void)DiscoverServices();
        (void)StopDiscoverServices();
        (void)StopP2pListen();
        (void)RemoveGroup();
        (void)P2pCancelConnect();
        return true;
    }
}  // namespace Wifi
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Wifi::WifiCP2PFuzzerTest(data, size);
    return 0;
}

