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

#include <gtest/gtest.h>
#include "relation_ap.h"

using ::testing::ext::TestSize;
namespace OHOS {
namespace Wifi {

class RelationApTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        relationAp_ = std::make_unique<RelationAp>();
        RelationInfo relationInfo("f1:f2:f3:f4:f5:f6", "f1:f2:f3:f4:f5:f7");
        relationAp_->relationInfo_ = relationInfo;
        relationAp_->apInfo_.bssid = "f1:f2:f3:f4:f5:f6";
    }

    virtual void TearDown()
    {
        relationAp_.reset();
    }

    std::unique_ptr<RelationAp> relationAp_;
};

HWTEST_F(RelationApTest, UpdateInfoTest1, TestSize.Level1)
{
    InterScanInfo scanInfo;
    scanInfo.bssid = "f1:f2:f3:f4:f5:f6";
    scanInfo.rssi = -66;
    relationAp_->UpdateInfo(scanInfo, -70);
    EXPECT_EQ(relationAp_->apInfo_.rssi, -66);
}

HWTEST_F(RelationApTest, InitMonitorInfoTest1, TestSize.Level1)
{
    relationAp_->InitMonitorInfo();
    EXPECT_EQ(relationAp_->apInfo_.rssi, -127);
}
HWTEST_F(RelationApTest, UpdateTriggerScanRssiThresholdTest1, TestSize.Level1)
{
    relationAp_->UpdateTriggerScanRssiThreshold(-65);
    EXPECT_EQ(relationAp_->apInfo_.rssi, -127);
}
}
}