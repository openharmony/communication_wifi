/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifiidlclient_fuzzer.h"
#include "wifi_fuzz_common_func.h"

#include <cstddef>
#include <cstdint>

#include "message_parcel.h"
#include "securec.h"
#include "define.h"
#include "i_wifi_supplicant_iface.h"
#include "wifi_log.h"

namespace OHOS {
namespace Wifi {

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    StartSupplicant();
    StopSupplicant();
    ConnectSupplicant();
    DisconnectSupplicant();
    Reconnect();
    Reassociate();
    Disconnect();
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Wifi::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
}
}