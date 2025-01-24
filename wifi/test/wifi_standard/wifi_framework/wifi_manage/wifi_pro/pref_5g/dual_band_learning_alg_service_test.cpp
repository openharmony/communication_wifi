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
#include "dual_band_learning_alg_service.h"
#include "dual_band_utils.h"

using ::testing::ext::TestSize;
namespace OHOS {
namespace Wifi {

class DualBandLearningAlgServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
    }

    virtual void TearDown()
    {
    }
};

HWTEST_F(DualBandLearningAlgServiceTest, SelectedTest1, TestSize.Level1)
{
    EXPECT_EQ(DualBandLearningAlgService::Selected(DualBandUtils::GetMeanPforLearnAlg(), -70), true);
    EXPECT_EQ(DualBandLearningAlgService::Selected(DualBandUtils::GetMeanPforLearnAlg(), -71), false);
}

HWTEST_F(DualBandLearningAlgServiceTest, UpdateMeanPValueTest1, TestSize.Level1)
{
    std::list<LinkQuality> rate2gList;
    for (int i = 0; i < 5; i++) {
        LinkQuality linkQuality;
        linkQuality.txBytes = 35000;
        linkQuality.rxBytes = 35000;
        linkQuality.signal = -50;
        linkQuality.txrate = 200;
        linkQuality.rxrate = 200;
        rate2gList.push_back(linkQuality);
    }
    std::list<LinkQuality> rate5gList;
    for (int i = 0; i < 5; i++) {
        LinkQuality linkQuality;
        linkQuality.txBytes = 30000;
        linkQuality.rxBytes = 30000;
        linkQuality.signal = -50;
        linkQuality.txrate = 100;
        linkQuality.rxrate = 100;
        rate5gList.push_back(linkQuality);
    }
    int rssi5g = -68;
    std::string meanPString = DualBandUtils::GetMeanPforLearnAlg();
    DualBandLearningAlgService::UpdateMeanPValue(rate2gList, rate5gList, rssi5g, meanPString);
    EXPECT_EQ(meanPString.empty(), false);
    rate5gList.clear();
    for (int i = 0; i < 5; i++) {
        LinkQuality linkQuality;
        linkQuality.txBytes = 50000;
        linkQuality.rxBytes = 50000;
        linkQuality.signal = -50;
        linkQuality.txrate = 300;
        linkQuality.rxrate = 300;
        rate5gList.push_back(linkQuality);
    }
    DualBandLearningAlgService::UpdateMeanPValue(rate2gList, rate5gList, rssi5g, meanPString);
    EXPECT_EQ(meanPString.empty(), false);
}
}
}