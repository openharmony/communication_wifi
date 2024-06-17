/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gtest/gtest.h>
#include "wifi_hdi_common.h"

using ::testing::ext::TestSize;
1
#define PROTOCOL_80211_IFTYPE_P2P_CLIENT 8

class WifiHdiCommonTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(WifiHdiCommonTest, HdiGetIeTest, TestSize.Level1)
{
    const uint8_t *ies = nullptr;
    size_t len = 256;
    uint8_t eid = 0;
    const uint8_t *result = HdiGetIe(ies, len, eid);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(WifiHdiCommonTest, HdiBssGetVendorIeTest, TestSize.Level1)
{
    uint8_t ies[] = {0xdd, 0x00, 0x00, 0x00, 0x01, 0x00};
    uint8_t vendorType = 1;
    const uint8_t *result = HdiBssGetVendorIe(ies, sizeof(ies), vendorType);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(WifiHdiCommonTest, HdiBssGetVendorBeaconTest, TestSize.Level1)
{
    const uint8_t *ies = nullptr;
    size_t len = 256;
    size_t beaconIeLen = 0;
    uint32_t vendorType = 0;
    const uint8_t *result = HdiBssGetVendorBeacon(ies, len, beaconIeLen, vendorType);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(WifiHdiCommonTest, HdiBssGetIeExtTest, TestSize.Level1)
{
    const uint8_t *ies = nullptr;
    size_t len = 256;
    uint8_t ext = 0;
    const uint8_t *result = HdiBssGetIeExt(ies, len, ext);
    EXPECT_EQ(result, nullptr);
}

HWTEST_F(WifiHdiCommonTest, HdiSSid2TxtTest, TestSize.Level1)
{
    const uint8_t *ssid = NULL;
    size_t ssidLen = 0;
    const char *result = HdiSSid2Txt(ssid, ssidLen);
    EXPECT_STREQ(result, "");
}

HWTEST_F(WifiHdiCommonTest, IsValidHexCharAndConvertTest, TestSize.Level1)
{
    EXPECT_EQ(IsValidHexCharAndConvert('5'), 5);
    EXPECT_EQ(IsValidHexCharAndConvert('a'), 10);
    EXPECT_EQ(IsValidHexCharAndConvert('F'), 15);
    EXPECT_EQ(IsValidHexCharAndConvert('z'), -1);
}

HWTEST_F(WifiHdiCommonTest, CheckMacIsValidTest, TestSize.Level1)
{
    char macStr[18] = "ab:cd:ef:gh:ij:kl";
    int result = CheckMacIsValid(macStr);
    EXPECT_EQ(result, -1);
    result = CheckMacIsValid(nullptr);
    EXPECT_EQ(result, -1);
}