/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#include "wifi_scan_controller.h"

using ::testing::ext::TestSize;
namespace OHOS {
namespace Wifi {

class WifiScanControllerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        strongRssiScanStrategy_ = std::make_unique<StrongRssiScanStrategy>();
        periodicScanStrategy_ = std::make_unique<PeriodicScanStrategy>();
    }

    virtual void TearDown()
    {
        strongRssiScanStrategy_.reset();
        periodicScanStrategy_.reset();
    }

    std::unique_ptr<StrongRssiScanStrategy> strongRssiScanStrategy_;
    std::unique_ptr<PeriodicScanStrategy> periodicScanStrategy_;
};

HWTEST_F(WifiScanControllerTest, IsFastScanTest1, TestSize.Level1)
{
    EXPECT_EQ(strongRssiScanStrategy_->IsFastScan(), false);
    EXPECT_EQ(periodicScanStrategy_->IsFastScan(), true);
}

HWTEST_F(WifiScanControllerTest, IsActiveScansExhaustedTest1, TestSize.Level1)
{
    EXPECT_EQ(strongRssiScanStrategy_->IsActiveScansExhausted(), false);
    EXPECT_EQ(periodicScanStrategy_->IsActiveScansExhausted(), false);
}

HWTEST_F(WifiScanControllerTest, TryToScanTest1, TestSize.Level1)
{
    std::unordered_set<int> monitorApFreqs({5240, 5420, 5200});
    EXPECT_EQ(strongRssiScanStrategy_->TryToScan(-66, false, 2270, monitorApFreqs), false);
    EXPECT_EQ(strongRssiScanStrategy_->TryToScan(-65, false, 2270, monitorApFreqs), false);
    EXPECT_EQ(strongRssiScanStrategy_->TryToScan(-54, false, 2270, monitorApFreqs), false);
    EXPECT_EQ(strongRssiScanStrategy_->TryToScan(-44, false, 2270, monitorApFreqs), false);
}

HWTEST_F(WifiScanControllerTest, TryToScanTest2, TestSize.Level1)
{
    std::unordered_set<int> monitorApFreqs({5240, 5420, 5200});
    EXPECT_EQ(periodicScanStrategy_->TryToScan(-65, false, 2270, monitorApFreqs), false);
    EXPECT_EQ(periodicScanStrategy_->TryToScan(-54, true, 2270, monitorApFreqs), false);
    EXPECT_EQ(strongRssiScanStrategy_->TryToScan(-44, true, 2270, monitorApFreqs), false);
}
}
}