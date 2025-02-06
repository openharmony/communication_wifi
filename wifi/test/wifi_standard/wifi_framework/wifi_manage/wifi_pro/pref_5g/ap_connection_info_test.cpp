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
#include "ap_connection_info.h"

using ::testing::ext::TestSize;
namespace OHOS {
namespace Wifi {

class ApConnectionInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        apConnectionInfo_ = std::make_unique<ApConnectionInfo>();
    }

    virtual void TearDown()
    {
        apConnectionInfo_.reset();
    }

    std::unique_ptr<ApConnectionInfo> apConnectionInfo_;
};

HWTEST_F(ApConnectionInfoTest, setRttProductTest1, TestSize.Level1)
{
    apConnectionInfo_->SetRttProducts("");
    EXPECT_EQ(apConnectionInfo_->GetRttProductString(), "");
}
HWTEST_F(ApConnectionInfoTest, setRttProductTest2, TestSize.Level1)
{
    apConnectionInfo_->SetRttProducts("1,2,3,4,5");
    EXPECT_EQ(apConnectionInfo_->GetRttProductString(), "1,2,3,4,5");
}
HWTEST_F(ApConnectionInfoTest, SetRttPacketVolumesTest1, TestSize.Level1)
{
    apConnectionInfo_->SetRttPacketVolumes("");
    EXPECT_EQ(apConnectionInfo_->GetRttPacketVolumeString(), "");
}
HWTEST_F(ApConnectionInfoTest, SetRttPacketVolumesTest2, TestSize.Level1)
{
    apConnectionInfo_->SetRttPacketVolumes("1,2,3,4,5");
    EXPECT_EQ(apConnectionInfo_->GetRttPacketVolumeString(), "1,2,3,4,5");
}

HWTEST_F(ApConnectionInfoTest, SetOtaLostRatesTest1, TestSize.Level1)
{
    apConnectionInfo_->SetOtaLostRates("");
    EXPECT_EQ(apConnectionInfo_->GetOtaLostRatesString(), "");
}
HWTEST_F(ApConnectionInfoTest, SetOtaLostRatesTest2, TestSize.Level1)
{
    apConnectionInfo_->SetOtaLostRates("0.1,0.2,0.3,0.4,0.5");
    EXPECT_EQ(apConnectionInfo_->GetOtaLostRatesString(), "0.1,0.2,0.3,0.4,0.5");
}

HWTEST_F(ApConnectionInfoTest, SetOtaPktVolumesTest1, TestSize.Level1)
{
    apConnectionInfo_->SetOtaPktVolumes("");
    EXPECT_EQ(apConnectionInfo_->GetOtaPktVolumesString(), "");
}
HWTEST_F(ApConnectionInfoTest, SetOtaPktVolumesTest2, TestSize.Level1)
{
    apConnectionInfo_->SetOtaPktVolumes("1,2,3,4,5");
    EXPECT_EQ(apConnectionInfo_->GetOtaPktVolumesString(), "1,2,3,4,5");
}
HWTEST_F(ApConnectionInfoTest, SetOtaBadPktProductsTest1, TestSize.Level1)
{
    apConnectionInfo_->SetOtaBadPktProducts("");
    EXPECT_EQ(apConnectionInfo_->GetOtaBadPktProductsString(), "");
}
HWTEST_F(ApConnectionInfoTest, SetOtaBadPktProductsTest2, TestSize.Level1)
{
    apConnectionInfo_->SetOtaBadPktProducts("1,2,3,4,5");
    EXPECT_EQ(apConnectionInfo_->GetOtaBadPktProductsString(), "1,2,3,4,5");
}

HWTEST_F(ApConnectionInfoTest, IsFullLinkQualityTest1, TestSize.Level1)
{
    EXPECT_EQ(apConnectionInfo_->IsFullLinkQuality(), false);
    for (int index = 0; index < 5; index++) {
        LinkQuality linkQuality;
        linkQuality.signal = -65;
        linkQuality.txrate = 34;
        apConnectionInfo_->HandleLinkQuality(linkQuality, false, false);
    }
    EXPECT_EQ(apConnectionInfo_->IsFullLinkQuality(), true);
}
HWTEST_F(ApConnectionInfoTest, HandleLinkQualityTest1, TestSize.Level1)
{
    apConnectionInfo_->GetLinkQualitys().clear();
    LinkQuality linkQuality;
    linkQuality.signal = -65;
    linkQuality.txrate = 34;
    apConnectionInfo_->HandleLinkQuality(linkQuality, true, true);
    EXPECT_EQ(apConnectionInfo_->IsFullLinkQuality(), false);
}
HWTEST_F(ApConnectionInfoTest, TotalUseTimeTest1, TestSize.Level1)
{
    EXPECT_EQ(apConnectionInfo_->GetTotalUseTime(), 0);
    apConnectionInfo_->AddUseTime(1000L);
    EXPECT_EQ(apConnectionInfo_->GetTotalUseTime(), 1000L);
    EXPECT_EQ(apConnectionInfo_->GetTotalUseHour(), 0);
    apConnectionInfo_->AddUseTime(3600L);
    EXPECT_EQ(apConnectionInfo_->GetTotalUseHour(), 1);
}

HWTEST_F(ApConnectionInfoTest, GetRssiSatisfyRttThresholdTest1, TestSize.Level1)
{
    EXPECT_EQ(apConnectionInfo_->GetRssiSatisfyRttThreshold(1500, -65), -65);
    apConnectionInfo_->SetRttProducts("0,0,100,0,100,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    apConnectionInfo_->SetRttPacketVolumes("0,0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    EXPECT_EQ(apConnectionInfo_->GetRssiSatisfyRttThreshold(1500, -65), -65);

    apConnectionInfo_->SetRttProducts("0,0,0,0,0,0,0,0,0,0,100,200,0,1000,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    apConnectionInfo_->SetRttPacketVolumes("0,0,0,0,0,0,0,0,0,0,1,2,0,2,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    EXPECT_EQ(apConnectionInfo_->GetRssiSatisfyRttThreshold(1500, -65), -80);
}

HWTEST_F(ApConnectionInfoTest, GetAvgRttOnRssiTest1, TestSize.Level1)
{
    apConnectionInfo_->SetRttProducts("200,0,0,0,0,0,0,0,0,0,0,300,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,100");
    apConnectionInfo_->SetRttPacketVolumes("1,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1");
    EXPECT_EQ(apConnectionInfo_->GetAvgRttOnRssi(-105), 200);
    EXPECT_EQ(apConnectionInfo_->GetAvgRttOnRssi(-30), 100);
    EXPECT_EQ(apConnectionInfo_->GetAvgRttOnRssi(-82), 300);
    EXPECT_EQ(apConnectionInfo_->GetAvgRttOnRssi(-65), 0);
}
HWTEST_F(ApConnectionInfoTest, HandleRttTest1, TestSize.Level1)
{
    apConnectionInfo_->SetRttProducts("0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    apConnectionInfo_->SetRttPacketVolumes("0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    apConnectionInfo_->HandleRtt(-105, 100, 1);
    EXPECT_EQ(apConnectionInfo_->GetRttProductString(), "100,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    EXPECT_EQ(apConnectionInfo_->GetRttPacketVolumeString(), "1,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    apConnectionInfo_->HandleRtt(-90, 100, 1);
    EXPECT_EQ(apConnectionInfo_->GetRttProductString(), "200,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    EXPECT_EQ(apConnectionInfo_->GetRttPacketVolumeString(), "2,0,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0");
    apConnectionInfo_->HandleRtt(-35, 50, 1);
    EXPECT_EQ(apConnectionInfo_->GetRttProductString(), "200,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,50");
    EXPECT_EQ(apConnectionInfo_->GetRttPacketVolumeString(), "2,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1");
    apConnectionInfo_->HandleRtt(-45, 50, 1);
    EXPECT_EQ(apConnectionInfo_->GetRttProductString(), "200,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,100");
    EXPECT_EQ(apConnectionInfo_->GetRttPacketVolumeString(), "2,0,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2");
    apConnectionInfo_->HandleRtt(-89, 100, 1);
    EXPECT_EQ(apConnectionInfo_->GetRttProductString(), "200,100,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,100");
    EXPECT_EQ(apConnectionInfo_->GetRttPacketVolumeString(), "2,1,0,0,0,0,0,0,0,0,0,0,0,"
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2");
}
}
}