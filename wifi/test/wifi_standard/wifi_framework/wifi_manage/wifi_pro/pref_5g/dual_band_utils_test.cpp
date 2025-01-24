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
#include "dual_band_utils.h"

using ::testing::ext::TestSize;
namespace OHOS {
namespace Wifi {

class DualBandUtilsTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {}

    virtual void TearDown()
    {}
};

HWTEST_F(DualBandUtilsTest, GetMeanPVersionTest1, TestSize.Level1)
{
    EXPECT_EQ(DualBandUtils::GetMeanPVersion() > 0, true);
}
HWTEST_F(DualBandUtilsTest, StringToVectorLongTest1, TestSize.Level1)
{
    std::vector<unsigned long> vectorValue;
    std::string str = "1,2,3,4";
    DualBandUtils::StringToVectorLong(str, ',', vectorValue);
    EXPECT_EQ(vectorValue.size(), 4);
}
HWTEST_F(DualBandUtilsTest, StringToVectorDoubleTest1, TestSize.Level1)
{
    std::vector<double> vectorValue;
    std::string str = "1.1,2.0,3,4";
    DualBandUtils::StringToVectorDouble(str, ',', vectorValue);
    EXPECT_EQ(vectorValue.size(), 4);
}
HWTEST_F(DualBandUtilsTest, LongArrToStringTest1, TestSize.Level1)
{
    std::vector<unsigned long> vectorValue({1, 2, 3, 4});
    std::string str = "1,2,3,4";
    EXPECT_EQ(DualBandUtils::LongArrToString(vectorValue, ','), str);
}
HWTEST_F(DualBandUtilsTest, IntArrToStringTest1, TestSize.Level1)
{
    std::vector<int> vectorValue({1, 2, 3, 4});
    std::string str = "1,2,3,4";
    EXPECT_EQ(DualBandUtils::IntArrToString(vectorValue, ','), str);
}
HWTEST_F(DualBandUtilsTest, DoubleArrToStringTest1, TestSize.Level1)
{
    std::vector<double> vectorValue({1.1, 2.0, 3, 4});
    std::string str = "1.1,2,3,4";
    EXPECT_EQ(DualBandUtils::DoubleArrToString(vectorValue, ','), str);
}
HWTEST_F(DualBandUtilsTest, IsEnterpriseTest1, TestSize.Level1)
{
    WifiDeviceConfig wifiDeviceConfig;
    wifiDeviceConfig.keyMgmt = KEY_MGMT_WPA_PSK;
    EXPECT_EQ(DualBandUtils::IsEnterprise(wifiDeviceConfig), false);

    wifiDeviceConfig.keyMgmt = KEY_MGMT_EAP;
    wifiDeviceConfig.wifiEapConfig.eap = EAP_METHOD_TLS;
    EXPECT_EQ(DualBandUtils::IsEnterprise(wifiDeviceConfig), true);
}

HWTEST_F(DualBandUtilsTest, IsSameRouterApTest1, TestSize.Level1)
{
    std::string bssid = "f1:f2:f3:f4:f5:f6";
    std::string anBssid = "f1:f2:f3:f4:f5:f7";
    EXPECT_EQ(DualBandUtils::IsSameRouterAp(bssid, anBssid), true);
    anBssid = "f0:f2:f3:f4:f5:f6";
    EXPECT_EQ(DualBandUtils::IsSameRouterAp(bssid, anBssid), true);
    anBssid = "f1:f3:f3:f4:f5:f6";
    EXPECT_EQ(DualBandUtils::IsSameRouterAp(bssid, anBssid), false);
}
}
}