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
#include "wifi_hdi_util.h"

using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
const int MAC_SIZE = 6;
class WifiHdiUtilTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(WifiHdiUtilTest, Get80211ElemsFromIETest, TestSize.Level1)
{
    const uint8_t *start;
    size_t len = 17;
    struct HdiElems *elems = nullptr;
    int show = 1;

    int result = Get80211ElemsFromIE(start, len, elems, show);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    result = Get80211ElemsFromIE(0, len, elems, show);
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiUtilTest, DelScanInfoLineTest, TestSize.Level1)
{
    ScanInfo pcmd;
    char srcBuf[100] = "123\t456\t789\t012\t345";
    int length = strlen(srcBuf);
    int result = DelScanInfoLine(&pcmd, srcBuf, length);
    EXPECT_EQ(result, 0);
    EXPECT_STREQ(pcmd.bssid, "123");
    EXPECT_EQ(pcmd.freq, 456);
    EXPECT_EQ(pcmd.siglv, 789);
    EXPECT_STREQ(pcmd.flags, "345");
    EXPECT_STREQ(pcmd.ssid, "");
}

HWTEST_F(WifiHdiUtilTest, DelScanInfoLineTest1, TestSize.Level1)
{
    ScanInfo pcmd;
    char srcBuf[100] = "\t\t\t\t\t";
    int length = strlen(srcBuf);
    int result = DelScanInfoLine(&pcmd, srcBuf, length);
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiUtilTest, ConvertMacArr2StringTest_Fail, TestSize.Level1)
{
    const unsigned char *srcMac;
    int srcMacSize = 6;
    char destMacStr[10] = "asdfgh";
    int strLen = 18;

    int result = ConvertMacArr2String(srcMac, srcMacSize, destMacStr, strLen);
    EXPECT_EQ(result, -1);
    result = ConvertMacArr2String(nullptr, srcMacSize, destMacStr, strLen);
    EXPECT_EQ(result, -1);
    result = ConvertMacArr2String(srcMac, 0, destMacStr, strLen);
    EXPECT_EQ(result, -1);
    result = ConvertMacArr2String(srcMac, srcMacSize, nullptr, strLen);
    EXPECT_EQ(result, -1);
    result = ConvertMacArr2String(srcMac, srcMacSize, nullptr, 0);
    EXPECT_EQ(result, -1);
}
HWTEST_F(WifiHdiUtilTest, ConvertMacArr2StringTest_Success, TestSize.Level1)
{
    unsigned char srcMac[MAC_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    char destMacStr[MAC_SIZE];
    int ret = ConvertMacArr2String(srcMac, MAC_SIZE, destMacStr, MAC_SIZE);
    EXPECT_EQ(ret, -1);
    EXPECT_STREQ(destMacStr, "");
}
}
}