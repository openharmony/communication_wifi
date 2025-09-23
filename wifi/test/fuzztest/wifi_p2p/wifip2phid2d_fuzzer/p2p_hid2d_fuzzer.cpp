/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "p2p_hid2d_fuzzer.h"
#include "wifi_hid2d_service_utils.h"

#include <cstddef>
#include <cstdint>

namespace OHOS {
namespace Wifi {
constexpr size_t U32_AT_SIZE_ZERO = 4;

void ClearSharedLinkCountFuzzerTest(const uint8_t *data, size_t size)
{
    SharedLinkManager pShareManager;
    pShareManager.ClearSharedLinkCount();
}

void IncreaseSharedLinkFuzzerTest(const uint8_t *data, size_t size)
{
    SharedLinkManager pShareManager;
    pShareManager.IncreaseSharedLink();
}

void IncreaseSharedLinkFuzzerTest1(const uint8_t *data, size_t size)
{
    SharedLinkManager pShareManager;
    pShareManager.SetGroupUid(-1);
    pShareManager.IncreaseSharedLink();
}

void GetGroupUidFuzzerTest(const uint8_t *data, size_t size)
{
    SharedLinkManager pShareManager;
    int callingUid = static_cast<int>(data[0]);
    pShareManager.GetGroupUid(callingUid);
}

void IpPoolFuzzerTest(const uint8_t *data, size_t size)
{
    IpPool pIpPool;
    std::string gcMac;
    pIpPool.ReleaseIpPool();
}

void WifiHid2dServiceUtilsFuzzerTest(const uint8_t *data, size_t size)
{
    ClearSharedLinkCountFuzzerTest(data, size);
    IncreaseSharedLinkFuzzerTest(data, size);
    IncreaseSharedLinkFuzzerTest1(data, size);
    GetGroupUidFuzzerTest(data, size);
    IpPoolFuzzerTest(data, size);
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    OHOS::Wifi::WifiHid2dServiceUtilsFuzzerTest(data, size);
    return 0;
}
}
}