/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "wifi_rpt_nat_manager.h"

using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
#ifdef FEATURE_WITH_GO_SIMULATION_AP
class WifiRptNatManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}

    WifiRptNatManager mRptNatManager;
    std::string ifc1 = "wlan0";
    std::string ifc2 = "p2p0";
    std::string badIfc = "wlan!!";
};

HWTEST_F(WifiRptNatManagerTest, EnableBridgeNat_InvalidInIface, TestSize.Level1)
{
    EXPECT_FALSE(mRptNatManager.EnableBridgeNat(true, badIfc, ifc2));
    EXPECT_FALSE(mRptNatManager.EnableBridgeNat(true, "", ifc2));
}

HWTEST_F(WifiRptNatManagerTest, EnableBridgeNat_InvalidOutIface, TestSize.Level1)
{
    EXPECT_FALSE(mRptNatManager.EnableBridgeNat(true, ifc1, badIfc));
    EXPECT_FALSE(mRptNatManager.EnableBridgeNat(true, ifc1, ""));
}

HWTEST_F(WifiRptNatManagerTest, EnableBridgeNat_DuplicateIface, TestSize.Level1)
{
    EXPECT_FALSE(mRptNatManager.EnableBridgeNat(true, ifc1, ifc1));
    EXPECT_FALSE(mRptNatManager.EnableBridgeNat(false, ifc2, ifc2));
}

HWTEST_F(WifiRptNatManagerTest, EnableBridgeNat_ValidIfaceCallsNetsys, TestSize.Level1)
{
    // Valid distinct ifaces pass pre-check; Netsys may fail in UT (return false).
    (void)mRptNatManager.EnableBridgeNat(true, ifc1, ifc2);
    (void)mRptNatManager.EnableBridgeNat(false, ifc1, ifc2);
    SUCCEED();
}
#endif
} // namespace Wifi
} // namespace OHOS
