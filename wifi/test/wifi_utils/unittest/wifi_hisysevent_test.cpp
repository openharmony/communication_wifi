/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "wifi_hisysevent_test.h"
#include <limits>

using namespace testing::ext;

namespace OHOS {
namespace Wifi {

HWTEST_F(WifiHisyseventTest, WritePortalStateHiSysEventTest, TestSize.Level1)
{
    WritePortalStateHiSysEvent(0);
}

HWTEST_F(WifiHisyseventTest, WriteArpInfoHiSysEventTest, TestSize.Level1)
{
    WriteArpInfoHiSysEvent(0, 0);
}

HWTEST_F(WifiHisyseventTest, WriteLinkInfoHiSysEventTest, TestSize.Level1)
{
    WriteLinkInfoHiSysEvent(0, 0, 0, 0);
}

HWTEST_F(WifiHisyseventTest, WirteConnectTypeHiSysEventTest, TestSize.Level1)
{
    WirteConnectTypeHiSysEvent("");
}

HWTEST_F(WifiHisyseventTest, WriteWifiWpaStateHiSysEventTest, TestSize.Level1)
{
    WriteWifiWpaStateHiSysEvent(0);
}

HWTEST_F(WifiHisyseventTest, WritePortalAuthExpiredHisyseventTest, TestSize.Level1)
{
    WritePortalAuthExpiredHisysevent(0, 0, 0, 0, false);
}

HWTEST_F(WifiHisyseventTest, WritePortalAuthExpiredHisyseventTes01, TestSize.Level1)
{
    int64_t nums[]{LLONG_MIN, INT_MIN, SHRT_MIN, 0, SHRT_MAX, INT_MAX, LLONG_MAX};
    for (int64_t i : nums) {
        for (int64_t j : nums) {
            WritePortalAuthExpiredHisysevent(0, 0, i, j, false);
        }
    }
}

HWTEST_F(WifiHisyseventTest, WriteWifiStateHiSysEventTest, TestSize.Level1)
{
    WriteWifiStateHiSysEvent(HISYS_SERVICE_TYPE_STA, WifiOperType::ENABLE);
}

}  // namespace Wifi
}  // namespace OHOS