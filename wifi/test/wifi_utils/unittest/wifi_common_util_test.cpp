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
    EXPECT_EQ(MacStrToArray(strmac, mac), EOK);
}

HWTEST_F(WifiCommonUtilTest, Ip2NumberTest, TestSize.Level1)
{
    std::string strIp = "00:55:DD:ff:MM";
    Ip2Number(strIp);
    EXPECT_EQ(Ip2Number(strIp), 0);
}

HWTEST_F(WifiCommonUtilTest, GetBrokerProcessNameByPidTest, TestSize.Level1)
{
    int uid = FREQ_5G_MIN;
    int pid = CHANNEL_14;
    EXPECT_EQ(GetBrokerProcessNameByPid(uid, pid), "");
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
    EXPECT_NE(SsidAnonymize(strIp), "");
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

HWTEST_F(WifiCommonUtilTest, IsBeaconLostTest01, TestSize.Level1)
{
    WIFI_LOGI("IsBeaconLostTest01 enter");
    int32_t screenState = MODE_STATE_OPEN;
    std::string bssid0 = "00::55::DD::ff::MM";
    std::string bssid1 = "01::55::DD::ff::MM";
    WifiSignalPollInfo signalPoll0;
    WifiSignalPollInfo signalPoll1;
    WifiSignalPollInfo signalPoll2;
    WifiSignalPollInfo signalPoll3;
    WifiSignalPollInfo signalPoll4;
    WifiSignalPollInfo signalPoll5;
    signalPoll0.timeStamp = 1;
    signalPoll1.timeStamp = 13;
    signalPoll2.timeStamp = 13;
    signalPoll3.timeStamp = 13;
    signalPoll4.timeStamp = 13;
    signalPoll5.timeStamp = 12;
    signalPoll0.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    signalPoll1.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    signalPoll2.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128};
    signalPoll3.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 129};
    signalPoll4.ext = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    signalPoll5.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    bool result = IsBeaconLost(bssid0, signalPoll0, screenState);
    EXPECT_FALSE(result);
    result = IsBeaconLost(bssid1, signalPoll1, screenState); // bssid
    EXPECT_FALSE(result);
    result = IsBeaconLost(bssid0, signalPoll0, screenState);
    signalPoll1.signal = -55;
    result = IsBeaconLost(bssid0, signalPoll1, screenState); // rssi
    EXPECT_FALSE(result);
    result = IsBeaconLost(bssid0, signalPoll0, screenState);
    signalPoll1.signal = 0;
    signalPoll1.rxBytes = 100;
    result = IsBeaconLost(bssid0, signalPoll1, screenState); // rx
    EXPECT_FALSE(result);
    result = IsBeaconLost(bssid0, signalPoll0, screenState);
    result = IsBeaconLost(bssid0, signalPoll2, screenState); // ext len
    EXPECT_FALSE(result);
}

HWTEST_F(WifiCommonUtilTest, IsBeaconLostTest02, TestSize.Level1)
{
    WIFI_LOGI("IsBeaconLostTest02 enter");
    int32_t screenState = MODE_STATE_OPEN;
    std::string bssid0 = "00::55::DD::ff::MM";
    WifiSignalPollInfo signalPoll0;
    WifiSignalPollInfo signalPoll1;
    WifiSignalPollInfo signalPoll3;
    WifiSignalPollInfo signalPoll4;
    WifiSignalPollInfo signalPoll5;
    WifiSignalPollInfo signalPoll6;
    WifiSignalPollInfo signalPoll7;
    signalPoll0.timeStamp = 1;
    signalPoll1.timeStamp = 13;
    signalPoll3.timeStamp = 13;
    signalPoll4.timeStamp = 13;
    signalPoll5.timeStamp = 12;
    signalPoll6.timeStamp = 15;
    signalPoll7.timeStamp = 25;
    signalPoll0.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    signalPoll1.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    signalPoll3.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 129};
    signalPoll4.ext = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    signalPoll5.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    signalPoll6.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    signalPoll7.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    bool result = IsBeaconLost(bssid0, signalPoll0, screenState);
    result = IsBeaconLost(bssid0, signalPoll3, screenState); // ext rssi ||
    EXPECT_FALSE(result);
    result = IsBeaconLost(bssid0, signalPoll0, screenState);
    result = IsBeaconLost(bssid0, signalPoll4, screenState); // ext rssi &&
    EXPECT_FALSE(result);
    result = IsBeaconLost(bssid0, signalPoll0, screenState);
    result = IsBeaconLost(bssid0, signalPoll5, screenState); // accumulateTime
    EXPECT_FALSE(result);
    result = IsBeaconLost(bssid0, signalPoll1, screenState);
    EXPECT_FALSE(result);
    result = IsBeaconLost(bssid0, signalPoll6, screenState);
    EXPECT_FALSE(result);
    result = IsBeaconLost(bssid0, signalPoll7, screenState);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiCommonUtilTest, IsBeaconLostTest03, TestSize.Level1)
{
    WIFI_LOGI("IsBeaconLostTest03 enter");
    int32_t screenState = MODE_STATE_OPEN;
    std::string bssid0 = "01::55::DD::ff::MM";
    WifiSignalPollInfo signalPoll0;
    WifiSignalPollInfo signalPoll1;
    WifiSignalPollInfo signalPoll3;
    WifiSignalPollInfo signalPoll4;
    WifiSignalPollInfo signalPoll5;
    WifiSignalPollInfo signalPoll6;
    WifiSignalPollInfo signalPoll7;
    signalPoll0.timeStamp = 1;
    signalPoll1.timeStamp = 4;
    signalPoll3.timeStamp = 7;
    signalPoll4.timeStamp = 10;
    signalPoll5.timeStamp = 13;
    signalPoll6.timeStamp = 16;
    signalPoll7.timeStamp = 19;
    signalPoll0.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    signalPoll1.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    signalPoll3.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 0};
    signalPoll4.ext = {0, 128, 0, 0, 0, 0, 0, 0, 0, 0};
    signalPoll5.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    signalPoll6.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    signalPoll7.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    bool result = IsBeaconLost(bssid0, signalPoll0, screenState);
    result = IsBeaconLost(bssid0, signalPoll1, screenState);
    result = IsBeaconLost(bssid0, signalPoll3, screenState);
    result = IsBeaconLost(bssid0, signalPoll4, screenState);
    result = IsBeaconLost(bssid0, signalPoll5, screenState);
    result = IsBeaconLost(bssid0, signalPoll6, screenState);
    EXPECT_TRUE(result);
    result = IsBeaconLost(bssid0, signalPoll6, screenState);
    EXPECT_FALSE(result);
    result = IsBeaconLost(bssid0, signalPoll0, screenState);
    result = IsBeaconLost(bssid0, signalPoll3, screenState);
    result = IsBeaconLost(bssid0, signalPoll4, screenState);
    result = IsBeaconLost(bssid0, signalPoll5, screenState);
    EXPECT_FALSE(result);
    result = IsBeaconLost(bssid0, signalPoll6, screenState);
    EXPECT_TRUE(result);
    result = IsBeaconLost(bssid0, signalPoll7, screenState);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiCommonUtilTest, IsBeaconLostTest04, TestSize.Level1)
{
    WIFI_LOGI("IsBeaconLostTest04 enter");
    int32_t screenState = MODE_STATE_CLOSE;
    std::string bssid0 = "01::55::DD::ff::MM";
    WifiSignalPollInfo signalPoll0;
    WifiSignalPollInfo signalPoll1;
    WifiSignalPollInfo signalPoll3;
    WifiSignalPollInfo signalPoll4;
    signalPoll0.timeStamp = 1;
    signalPoll1.timeStamp = 2;
    signalPoll3.timeStamp = 3;
    signalPoll4.timeStamp = 4;
    signalPoll0.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    signalPoll1.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    signalPoll3.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 0};
    signalPoll4.ext = {128, 128, 128, 128, 128, 128, 128, 128, 128, 0};
    bool result = IsBeaconLost(bssid0, signalPoll0, screenState);
    EXPECT_FALSE(result);
    result = IsBeaconLost(bssid0, signalPoll1, screenState);
    EXPECT_FALSE(result);
    result = IsBeaconLost(bssid0, signalPoll3, screenState);
    result = IsBeaconLost(bssid0, signalPoll4, screenState);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiCommonUtilTest, IsBeaconAbnormalTest, TestSize.Level1)
{
    WIFI_LOGI("IsBeaconAbnormalTest enter");
    std::string bssid0 = "00::55::DD::ff::MM";
    std::string bssid1 = "01::55::DD::ff::MM";
    WifiSignalPollInfo signalPoll0;
    WifiSignalPollInfo signalPoll1;
    WifiSignalPollInfo signalPoll2;
    WifiSignalPollInfo signalPoll3;
    WifiSignalPollInfo signalPoll4;
    WifiSignalPollInfo signalPoll5;
    WifiSignalPollInfo signalPoll6;
    signalPoll0.timeStamp = 1;
    signalPoll1.timeStamp = 6;
    signalPoll2.timeStamp = 6;
    signalPoll3.timeStamp = 6;
    signalPoll4.timeStamp = 5;
    signalPoll5.timeStamp = 11;
    signalPoll6.timeStamp = 12;
    signalPoll0.ext = {129, 129, 130, 130, 135, 135, 138, 138, 139, 139};
    signalPoll1.ext = {129, 129, 130, 130, 135, 135, 138, 138, 139, 139};
    signalPoll2.ext = {129, 129, 130, 130, 135, 135, 138, 138, 139};
    signalPoll3.ext = {129, 129, 130, 130, 135, 135, 138, 138, 139, 150};
    signalPoll4.ext = {129, 129, 130, 130, 135, 135, 138, 138, 139, 139};
    signalPoll5.ext = {129, 129, 130, 130, 135, 135, 138, 138, 139, 139};
    signalPoll6.ext = {129, 129, 130, 130, 135, 135, 138, 138, 139, 139};
    bool result = IsBeaconAbnormal(bssid0, signalPoll0);
    EXPECT_FALSE(result);
    result = IsBeaconAbnormal(bssid1, signalPoll1);
    EXPECT_FALSE(result); // bssid
    result = IsBeaconAbnormal(bssid0, signalPoll0);
    result = IsBeaconAbnormal(bssid0, signalPoll2);
    EXPECT_FALSE(result); // ext len
    result = IsBeaconAbnormal(bssid0, signalPoll0);
    result = IsBeaconAbnormal(bssid0, signalPoll3);
    EXPECT_FALSE(result); // areVectorsEqual
    result = IsBeaconAbnormal(bssid0, signalPoll0);
    result = IsBeaconAbnormal(bssid0, signalPoll4);
    EXPECT_FALSE(result); // accumulateTime
    result = IsBeaconAbnormal(bssid0, signalPoll1);
    EXPECT_TRUE(result);
    result = IsBeaconAbnormal(bssid0, signalPoll5);
    EXPECT_FALSE(result);
    result = IsBeaconAbnormal(bssid0, signalPoll6);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiCommonUtilTest, GetSplitInfoTest, TestSize.Level1)
{
    WIFI_LOGI("GetSplitInfoTest enter");
    std::string input = "00::55::DD::ff::MM";
    std::string delimiter = "::";
    std::vector<std::string> result = GetSplitInfo(input, delimiter);
    EXPECT_EQ(result.size(), 5);
}

HWTEST_F(WifiCommonUtilTest, GetSplitInfoTest_1, TestSize.Level1)
{
    WIFI_LOGI("GetSplitInfoTest_1 enter");
    std::string input = "00";
    std::string delimiter = "::";
    std::vector<std::string> result = GetSplitInfo(input, delimiter);
    EXPECT_EQ(result.size(), 1);
}

HWTEST_F(WifiCommonUtilTest, GetSplitInfoTest_2, TestSize.Level1)
{
    WIFI_LOGI("GetSplitInfoTest_1 enter");
    std::string input = "0000010000";
    std::string delimiter = "0";
    std::vector<std::string> result = GetSplitInfo(input, delimiter);
    EXPECT_EQ(result.size(), 1);
}

HWTEST_F(WifiCommonUtilTest, GetCurrentTimeSecondsTest, TestSize.Level1)
{
    WIFI_LOGI("GetCurrentTimeSecondsTest enter");
    int64_t result = GetCurrentTimeSeconds();
    EXPECT_TRUE(result != 0);
}

HWTEST_F(WifiCommonUtilTest, GetCurrentTimeMilliSecondsTest, TestSize.Level1)
{
    WIFI_LOGI("GetCurrentTimeMilliSecondsTest enter");
    int64_t result = GetCurrentTimeMilliSeconds();
    EXPECT_TRUE(result != 0);
}

HWTEST_F(WifiCommonUtilTest, StringToDoubleTest01, TestSize.Level1)
{
    WIFI_LOGI("StringToDoubleTest01 enter");
    std::string input = "12.34";
    double output = 12.34;
    EXPECT_TRUE(StringToDouble(input) == output);
}


HWTEST_F(WifiCommonUtilTest, StringToDoubleTest02, TestSize.Level1)
{
    WIFI_LOGI("StringToDoubleTest03 enter");
    std::string input = "12.34.56";
    double output = 12.34;
    EXPECT_TRUE(StringToDouble(input) == output);
}

HWTEST_F(WifiCommonUtilTest, StringToDoubleTest03, TestSize.Level1)
{
    WIFI_LOGI("StringToDoubleTest05 enter");
    std::string input = "a12.34";
    double output = 0;
    EXPECT_TRUE(StringToDouble(input) == output);
}

HWTEST_F(WifiCommonUtilTest, StringToUlongTest01, TestSize.Level1)
{
    WIFI_LOGI("StringToUlongTest01 enter");
    std::string input = "12.34";
    unsigned long output = 12;
    EXPECT_TRUE(StringToUlong(input) == output);
}

HWTEST_F(WifiCommonUtilTest, StringToUlongTest02, TestSize.Level1)
{
    WIFI_LOGI("StringToUlongTest02 enter");
    std::string input = "12b";
    unsigned long output = 12;
    EXPECT_TRUE(StringToUlong(input) == output);
}

HWTEST_F(WifiCommonUtilTest, StringToUlongTest03, TestSize.Level1)
{
    WIFI_LOGI("StringToUlongTest03 enter");
    std::string input = "a55";
    unsigned long output = 0;
    EXPECT_TRUE(StringToUlong(input) == output);
}

HWTEST_F(WifiCommonUtilTest, IsBundleInstalledTest01, TestSize.Level1)
{
    WIFI_LOGI("IsBundleInstalledTest01 enter");
    std::string bundleName = "com.ohos.wifitest01";
    EXPECT_FALSE(IsBundleInstalled(bundleName));
}
}  // namespace Wifi
}  // namespace OHOS