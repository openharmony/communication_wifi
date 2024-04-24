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

}  // namespace Wifi
}  // namespace OHOS