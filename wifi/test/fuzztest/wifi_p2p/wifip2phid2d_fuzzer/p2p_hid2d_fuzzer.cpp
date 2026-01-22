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
#include "wifi_common_util.h"
#include <fuzzer/FuzzedDataProvider.h>


#include <cstddef>
#include <cstdint>

namespace OHOS {
namespace Wifi {
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr int32_t STATE_NUM = 3;

void ClearSharedLinkCountFuzzerTest()
{
    SharedLinkManager pShareManager;
    pShareManager.ClearSharedLinkCount();
}

void IncreaseSharedLinkFuzzerTest()
{
    SharedLinkManager pShareManager;
    pShareManager.IncreaseSharedLink();
}

void IncreaseSharedLinkFuzzerTest1(FuzzedDataProvider& FDP)
{
    SharedLinkManager pShareManager;
    int uid = FDP.ConsumeIntegralInRange<int>(0, STATE_NUM);
    pShareManager.SetGroupUid(uid);
    pShareManager.IncreaseSharedLink();
}

void IncreaseSharedLinkFuzzerTest2(const uint8_t *data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    SharedLinkManager pShareManager;
    int callingUid = FDP.ConsumeIntegralInRange<int>(0, STATE_NUM);
    pShareManager.IncreaseSharedLink(callingUid);
}

void DecreaseSharedLinkFuzzerTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    SharedLinkManager pShareManager;
    int callingUid = FDP.ConsumeIntegralInRange<int>(0, STATE_NUM);
    pShareManager.DecreaseSharedLink(callingUid);
}
void ClearUidCountFuzzerTest(const uint8_t *data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    SharedLinkManager pShareManager;
    int uid = static_cast<int>(data[0]);
    pShareManager.ClearUidCount(uid);
}

void CheckNeedRemoveGroupFuzzerTest(FuzzedDataProvider& FDP)
{
    SharedLinkManager pShareManager;
    int uid = FDP.ConsumeIntegralInRange<int>(0, STATE_NUM);
    pShareManager.CheckNeedRemoveGroup(uid);
}

void GetGroupUidFuzzerTest(FuzzedDataProvider& FDP)
{
    SharedLinkManager pShareManager;
    
    int callingUid = FDP.ConsumeIntegralInRange<int>(0, STATE_NUM);
    pShareManager.GetGroupUid(callingUid);
}

void IpPoolFuzzerTest()
{
    IpPool pIpPool;
    std::string gcMac;
    pIpPool.ReleaseIpPool();
    pIpPool.ReleaseIp(gcMac);
}

void WifiHid2dServiceUtilsFuzzerTest(const uint8_t *data, size_t size)
{
    IncreaseSharedLinkFuzzerTest2(data, size);
    DecreaseSharedLinkFuzzerTest(data, size);
    ClearUidCountFuzzerTest(data, size);
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    OHOS::Wifi::WifiHid2dServiceUtilsFuzzerTest(data, size);
    OHOS::Wifi::IncreaseSharedLinkFuzzerTest1(FDP);
    OHOS::Wifi::CheckNeedRemoveGroupFuzzerTest(FDP);
    OHOS::Wifi::GetGroupUidFuzzerTest(FDP);
    OHOS::Wifi::IpPoolFuzzerTest();
    OHOS::Wifi::IncreaseSharedLinkFuzzerTest();
    OHOS::Wifi::ClearSharedLinkCountFuzzerTest();
    return 0;
}
}
}