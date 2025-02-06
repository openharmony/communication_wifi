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
#include "relation_info.h"

using ::testing::ext::TestSize;
namespace OHOS {
namespace Wifi {

class RelationInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        relationInfo_ = std::make_unique<RelationInfo>();
    }

    virtual void TearDown()
    {
        relationInfo_.reset();
    }

    std::unique_ptr<RelationInfo> relationInfo_;
};

HWTEST_F(RelationInfoTest, IsOnSameRouterTest1, TestSize.Level1)
{
    EXPECT_EQ(relationInfo_->IsOnSameRouter(), false);
    relationInfo_->relateType_ = 0;
    EXPECT_EQ(relationInfo_->IsOnSameRouter(), true);
    relationInfo_->maxRssi_ = -50;
    relationInfo_->relationRssiWhenMaxRssi_ = -61;
    EXPECT_EQ(relationInfo_->IsOnSameRouter(), false);
}
HWTEST_F(RelationInfoTest, SetMaxRssiTest1, TestSize.Level1)
{
    relationInfo_->SetMaxRssiOnRelationAp(-50, -51);
    EXPECT_EQ(relationInfo_->maxRelationRssi_, -50);
    EXPECT_EQ(relationInfo_->rssiWhenMaxRelationRssi_, -51);
    relationInfo_->SetMaxRssi(-45, -53);
    EXPECT_EQ(relationInfo_->maxRssi_, -45);
    EXPECT_EQ(relationInfo_->relationRssiWhenMaxRssi_, -53);
}
HWTEST_F(RelationInfoTest, ScanRssiThresholdTest1, TestSize.Level1)
{
    relationInfo_->SetSameApTriggerScanRssiThreshold("");
    EXPECT_EQ(relationInfo_->GetScanRssiThreshold(), "");
    relationInfo_->SetSameApTriggerScanRssiThreshold("-105,-104,-103,-102,-101");
    EXPECT_EQ(relationInfo_->GetScanRssiThreshold(), "-105,-104,-103,-102,-101");
}
HWTEST_F(RelationInfoTest, GetTriggerScanRssiThresholdTest1, TestSize.Level1)
{
    relationInfo_->relateType_ = 0;
    relationInfo_->SetMaxRssiOnRelationAp(-50, -51);
    relationInfo_->SetMaxRssi(-45, -53);
    EXPECT_EQ(relationInfo_->GetTriggerScanRssiThreshold(-65), 0);
    EXPECT_EQ(relationInfo_->GetTriggerScanRssiThreshold(-106), 0);
    EXPECT_EQ(relationInfo_->GetTriggerScanRssiThreshold(-44), 0);
    relationInfo_->SetSameApTriggerScanRssiThreshold("-105,-104,-103,-102,-101,-100,-99,-98,"
    "-97,-96,-95,-94,-93,-92,-91,-90,-89,-88,-87,-86,-85,-84,-83,-82,-81,-80,-79,-78,-77,-76,"
    "-75,-74,-73,-72,-71,-70,-69,-68,-67,-66,-65,-64,-63,-62,-61,-60,-59,-58,-57,-56,-55,-54,"
    "-53,-52,-51,-50,-49,-48,-47,-46,-45");
    EXPECT_EQ(relationInfo_->GetTriggerScanRssiThreshold(-65), -65);
}
HWTEST_F(RelationInfoTest, GetTriggerScanRssiThresholdTest2, TestSize.Level1)
{
    relationInfo_->relateType_ = 1;
    relationInfo_->SetMaxRssiOnRelationAp(-50, -51);
    relationInfo_->SetMaxRssi(-45, -53);
    EXPECT_EQ(relationInfo_->GetTriggerScanRssiThreshold(-65), -70);
}
HWTEST_F(RelationInfoTest, GetTriggerScanRssiThresholdTest3, TestSize.Level1)
{
    relationInfo_->relateType_ = 1;
    relationInfo_->SetMaxRssiOnRelationAp(-30, -50);
    relationInfo_->SetMaxRssi(-42, -60);
    relationInfo_->maxScanRssi_ = INVALID_RSSI;
    relationInfo_->minTargetRssi_ = INVALID_RSSI;
    EXPECT_EQ(relationInfo_->GetTriggerScanRssiThreshold(-65), -42);
    relationInfo_->maxScanRssi_ = -60;
    relationInfo_->minTargetRssi_ = -65;
    EXPECT_EQ(relationInfo_->GetTriggerScanRssiThreshold(-65), -60);
    relationInfo_->maxScanRssi_ = -65;
    relationInfo_->minTargetRssi_ = -55;
    EXPECT_EQ(relationInfo_->GetTriggerScanRssiThreshold(-65), -60);
}

HWTEST_F(RelationInfoTest, UpdateSameApTriggerScanRssiThresholdTest1, TestSize.Level1)
{
    EXPECT_EQ(relationInfo_->UpdateSameApTriggerScanRssiThreshold(-65, -70, -106, -90), -65);
    EXPECT_EQ(relationInfo_->UpdateSameApTriggerScanRssiThreshold(-65, -45, -106, -90), -65);
    EXPECT_EQ(relationInfo_->UpdateSameApTriggerScanRssiThreshold(-62, -60, -60, -59), 0);
}
}
}