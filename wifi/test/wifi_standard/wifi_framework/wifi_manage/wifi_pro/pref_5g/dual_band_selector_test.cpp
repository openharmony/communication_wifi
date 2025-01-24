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
#include "dual_band_selector.h"
#include "dual_band_utils.h"

using ::testing::ext::TestSize;
namespace OHOS {
namespace Wifi {

class DualBandSelectorTest : public testing::Test {
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

HWTEST_F(DualBandSelectorTest, SelectTest1, TestSize.Level1)
{
    ApInfo currentApInfo;
    currentApInfo.rssi = -60;
    currentApInfo.bssid = "f1:f2:f3:f4:f5:f6";
    currentApInfo.channelWidth = WifiChannelWidth::WIDTH_80MHZ;
    currentApInfo.wifiCategory = WifiCategory::WIFI6;
    ApConnectionInfo apConnectionInfo(currentApInfo.bssid);
    apConnectionInfo.AddUseTime(3600);
    currentApInfo.apConnectionInfo = apConnectionInfo;
    std::vector<CandidateRelationApInfo> candidateRelationApInfos;
    ApInfo apInfo;
    apInfo.rssi = -50;
    apInfo.bssid = "f1:f2:f3:f4:f5:f7";
    apInfo.channelWidth = WifiChannelWidth::WIDTH_160MHZ;
    apInfo.wifiCategory = WifiCategory::WIFI7;
    ApConnectionInfo candidateApConnectionInfo(apInfo.bssid);
    candidateApConnectionInfo.AddUseTime(36000);
    apInfo.apConnectionInfo = candidateApConnectionInfo;
    CandidateRelationApInfo candidateRelationApInfo;
    candidateRelationApInfo.apInfo = apInfo;
    candidateRelationApInfo.meanP = DualBandUtils::GetMeanPforLearnAlg();
    candidateRelationApInfos.push_back(candidateRelationApInfo);
    std::shared_ptr<CandidateRelationApInfo> selectedAp =
        DualBandSelector::Select(currentApInfo, candidateRelationApInfos);
    EXPECT_EQ(selectedAp == nullptr, false);
}
}
}