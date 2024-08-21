/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "wifi_common_util.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "wifi_logger.h"

using namespace testing::ext;using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiCommonUtilTest");

constexpr int FREQ_2G_MIN = 2412;
constexpr int CHANNEL_14_FREQ = 2484;
constexpr int FREQ_5G_MIN = 5170;
constexpr int CHANNEL_5G_MIN = 34;
constexpr int MIN_24G_CHANNEL = 1;
constexpr int MIN_5G_CHANNEL = 36;
constexpr int CHANNEL_14 = 14;
constexpr int WIFI_MAC_LENS = 6;
constexpr int FREQ_CHANNEL_36 = 5180;
constexpr int MAX_HEX_STR_LEN = 32;
constexpr int MAX_HEX2STRING_TEST_LEN = 14;

class WifiCommonUtilTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};
HWTEST_F(WifiCommonUtilTest, MacStrToArrayTest, TestSize.Level1)
{
    std::string strmac = "00:55:DD:ff:MM";
    unsigned char mac[WIFI_MAC_LENS];
    MacStrToArray(strmac, mac);
}

HWTEST_F(WifiCommonUtilTest, Ip2NumberTest, TestSize.Level1)
{
    std::string strIp = "00:55:DD:ff:MM";
    Ip2Number(strIp);
}

HWTEST_F(WifiCommonUtilTest, GetBrokerProcessNameByPidTest, TestSize.Level1)
{
    int uid = FREQ_5G_MIN;
    int pid = CHANNEL_14;
    GetBrokerProcessNameByPid(uid, pid);
}

HWTEST_F(WifiCommonUtilTest, FrequencyToChannelTest, TestSize.Level1)
{
    EXPECT_EQ(FrequencyToChannel(FREQ_2G_MIN), 1);
    EXPECT_EQ(FrequencyToChannel(CHANNEL_14_FREQ), CHANNEL_14);
    EXPECT_EQ(FrequencyToChannel(FREQ_5G_MIN), CHANNEL_5G_MIN);
    EXPECT_EQ(FrequencyToChannel(CHANNEL_5G_MIN), INVALID_FREQ_OR_CHANNEL);
}

HWTEST_F(WifiCommonUtilTest, ChannelToFrequencyTest, TestSize.Level1)
{
    EXPECT_EQ(ChannelToFrequency(MIN_24G_CHANNEL), FREQ_2G_MIN);
    EXPECT_EQ(ChannelToFrequency(MIN_5G_CHANNEL), FREQ_CHANNEL_36);
    EXPECT_EQ(ChannelToFrequency(FREQ_2G_MIN), INVALID_FREQ_OR_CHANNEL);
}

HWTEST_F(WifiCommonUtilTest, SsidAnonymizeTest, TestSize.Level1)
{
    std::string str = "00:55:DD:ff:MM";
    SsidAnonymize(str);
    std::string strs = "00";
    SsidAnonymize(strs);
    std::string strIp = "00:55:DD";
    SsidAnonymize(strIp);
}

HWTEST_F(WifiCommonUtilTest, Byte2HexStringTest, TestSize.Level1)
{
    WIFI_LOGI("Byte2HexStringTest enter");
    std::string str = "00:55:DD:ff:MM";
    char autsBuf[MAX_HEX_STR_LEN + 1] = { 0 };
    int offset = 0;
    std::vector<uint8_t> nonce(str.begin(), str.end());
    uint8_t autsLen = nonce.size();
    Byte2HexString(&nonce[offset], autsLen, autsBuf, sizeof(autsBuf));
    EXPECT_NE(autsBuf, "30303a35353a44443a66663a4d4d");
}

HWTEST_F(WifiCommonUtilTest, Byte2HexStringFailTest, TestSize.Level1)
{
    WIFI_LOGI("Byte2HexStringFailTest enter");
    char autsBuf[MAX_HEX_STR_LEN + 1] = { 0 };
    std::string str = "00:55:DD:ff:MM";
    std::vector<uint8_t> nonce(str.begin(), str.end());
    uint8_t autsLen = nonce.size();
    Byte2HexString(nullptr, autsLen, autsBuf, sizeof(autsBuf));
    EXPECT_EQ(strlen(autsBuf), 0);
}

HWTEST_F(WifiCommonUtilTest, HexString2ByteTest, TestSize.Level1)
{
    WIFI_LOGI("HexString2ByteTest enter");
    std::string str = "30303a35353a44443a66663a4d4d";
    uint8_t randArray[MAX_HEX2STRING_TEST_LEN] = { 0 };
    memset_s(randArray, sizeof(randArray), 0x0, sizeof(randArray));
    int result = HexString2Byte(str.c_str(), randArray, sizeof(randArray));
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiCommonUtilTest, Byte2HexString2ByteTest, TestSize.Level1)
{
    WIFI_LOGI("Byte2HexString2ByteTest enter");
    char autsBuf[MAX_HEX_STR_LEN + 1] = { 0 };
    std::string srcStr = "00:55:DD:ff:MM";
    std::vector<uint8_t> nonce(srcStr.begin(), srcStr.end());
    uint8_t autsLen = nonce.size();
    Byte2HexString(&nonce[0], autsLen, autsBuf, sizeof(autsBuf));
    EXPECT_TRUE(strlen(autsBuf) > 0);

    uint8_t randArray[MAX_HEX2STRING_TEST_LEN] = { 0 };
    int result = HexString2Byte(autsBuf, randArray, sizeof(randArray));
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiCommonUtilTest, EncodeBase64Test, TestSize.Level1)
{
    WIFI_LOGI("EncodeBase64Test enter");
    std::string str = "abcdefgh";
    std::vector<uint8_t> vecStr(str.begin(), str.end());
    std::string result = EncodeBase64(vecStr);
    EXPECT_EQ(result, "YWJjZGVmZ2g=");
}

HWTEST_F(WifiCommonUtilTest, EncodeBase64Test_1, TestSize.Level1)
{
    WIFI_LOGI("EncodeBase64Test_1 enter");
    std::string str = "";
    std::vector<uint8_t> vecStr(str.begin(), str.end());
    std::string result = EncodeBase64(vecStr);
    EXPECT_TRUE(result.empty());
}

HWTEST_F(WifiCommonUtilTest, DecodeBase64Test, TestSize.Level1)
{
    WIFI_LOGI("DecodeBase64Test enter");
    std::string str = "YWJjZGVmZ2g=";
    std::vector<uint8_t> vecStr;
    bool result = DecodeBase64(str, vecStr);
    EXPECT_TRUE(result);
    EXPECT_EQ("abcdefgh", std::string(vecStr.begin(), vecStr.end()));
}

HWTEST_F(WifiCommonUtilTest, DecodeBase64FildTest_1, TestSize.Level1)
{
    WIFI_LOGI("DecodeBase64FildTest_1 enter");
    std::string str = "YWJ";
    std::vector<uint8_t> vecStr;
    bool result = DecodeBase64(str, vecStr);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiCommonUtilTest, DecodeBase64FildTest_2, TestSize.Level1)
{
    WIFI_LOGI("DecodeBase64FildTest_2 enter");
    std::string str = "YWJjZGVmZ2g==";
    std::vector<uint8_t> vecStr;
    bool result = DecodeBase64(str, vecStr);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiCommonUtilTest, EncodeDecodeBase64Test, TestSize.Level1)
{
    WIFI_LOGI("EncodeDecodeBase64Test enter");
    std::string srcStr = "EncodeDecodeBase64Test";
    std::vector<uint8_t> vecStr(srcStr.begin(), srcStr.end());
    std::string encResult = EncodeBase64(vecStr);
    EXPECT_TRUE(encResult.length() > 0);
    std::vector<uint8_t> destVec;
    bool result = DecodeBase64(encResult, destVec);
    EXPECT_TRUE(result);
    EXPECT_EQ(srcStr, std::string(destVec.begin(), destVec.end()));
}

HWTEST_F(WifiCommonUtilTest, EncodeDecodeBase64TestFail, TestSize.Level1)
{
    WIFI_LOGI("EncodeDecodeBase64TestFail enter");
    std::string srcStr = "EncodeDecodeBase64TestFail";
    std::vector<uint8_t> vecStr(srcStr.begin(), srcStr.end());
    std::string encResult = EncodeBase64(vecStr);
    EXPECT_TRUE(encResult.length() > 0);
    std::vector<uint8_t> destVec;
    bool result = DecodeBase64(encResult + "_test", destVec);
    EXPECT_FALSE(result);
    EXPECT_NE(srcStr, std::string(destVec.begin(), destVec.end()));
}

HWTEST_F(WifiCommonUtilTest, GetAuthInfoTest, TestSize.Level1)
{
    WIFI_LOGI("GetAuthInfoTest enter");
    std::string input = "00::55::DD::ff::MM";
    std::string delimiter = "::";
    std::vector<std::string> result = getAuthInfo(input, delimiter);
    EXPECT_EQ(result.size(), 5);
}

HWTEST_F(WifiCommonUtilTest, GetAuthInfoTest_1, TestSize.Level1)
{
    WIFI_LOGI("GetAuthInfoTest_1 enter");
    std::string input = "00";
    std::string delimiter = "::";
    std::vector<std::string> result = getAuthInfo(input, delimiter);
    EXPECT_EQ(result.size(), 1);
}
}  // namespace Wifi
}  // namespace OHOS