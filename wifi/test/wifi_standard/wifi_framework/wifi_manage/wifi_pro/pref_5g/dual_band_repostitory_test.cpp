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
#include "dual_band_repostitory.h"
#include "mock_dual_band_data_source.h"

using ::testing::ext::TestSize;
namespace OHOS {
namespace Wifi {

class DualBandRepostitoryTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        dualBandRepostitory_ = std::make_unique<DualBandRepostitory>(
            std::dynamic_pointer_cast<IDualBandDataSource>(std::make_shared<MockDualBandDataSource>()));
    }

    virtual void TearDown()
    {
        dualBandRepostitory_.reset();
    }

    std::unique_ptr<DualBandRepostitory> dualBandRepostitory_;
};

HWTEST_F(DualBandRepostitoryTest, LoadApHistoryInfoTest1, TestSize.Level1)
{
    ApInfo apInfo;
    bool hasHistoryInfo = false;
    dualBandRepostitory_->LoadApHistoryInfo(apInfo, hasHistoryInfo);
    EXPECT_EQ(hasHistoryInfo, false);
}

HWTEST_F(DualBandRepostitoryTest, LoadRelationApInfoTest1, TestSize.Level1)
{
    std::vector<RelationAp> relationApInfo;
    dualBandRepostitory_->LoadRelationApInfo("f1:f2:f3:f4:f5:F6", relationApInfo,
        [](RelationInfo &relation) {return relation.bssid24g_;});
    EXPECT_EQ(relationApInfo.size(), 0);
}
HWTEST_F(DualBandRepostitoryTest, QueryRelationApInfosTest1, TestSize.Level1)
{
    std::unordered_set<std::string> bssidSet({"f1:f2:f3:f4:f5:F6"});
    std::vector<RelationAp> relationAp = dualBandRepostitory_->QueryRelationApInfos(bssidSet);
    EXPECT_EQ(relationAp.size(), 0);
}
}
}