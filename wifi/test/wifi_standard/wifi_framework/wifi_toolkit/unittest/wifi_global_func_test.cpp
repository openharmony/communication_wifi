/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "wifi_global_func_test.h"
#include "wifi_global_func.h"
#include "wifi_country_code_define.h"
#include "wifi_ap_msg.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {

constexpr int FREP_2G_MIN = 2412;
constexpr int FREP_5G_MIN = 5170;
constexpr int CHANNEL_14_FREP = 2484;
constexpr int CENTER_FREP_DIFF = 5;
constexpr int CHANNEL_2G_MIN = 1;
constexpr int CHANNEL_5G = 34;
constexpr int CHANNEL_2G = 14;
constexpr uint32_t PLAIN_LENGTH = 10;
const std::string MDM_WIFI_PROP = "persist.edm.wifi_enable";

HWTEST_F(WifiGlobalFuncTest, GetRandomStr, TestSize.Level1)
{
    std::string str = GetRandomStr(0);
    EXPECT_TRUE(str.length() == 0);
    str = GetRandomStr(1);
    EXPECT_TRUE(str.length() == 1);
    str = GetRandomStr(MAX_PSK_LEN);
    EXPECT_TRUE(str.length() == MAX_PSK_LEN);
    str = GetRandomStr(MAX_PSK_LEN + 1);
    EXPECT_TRUE(str.length() == MAX_PSK_LEN);
}

HWTEST_F(WifiGlobalFuncTest, GetRandomInt, TestSize.Level1)
{
    int res = GetRandomInt(0, 100);
    EXPECT_TRUE(res >= 0 && res <= 100);

    res = GetRandomInt(2000, 100);
    EXPECT_TRUE(res == 2000);

    res = GetRandomInt(100, 100);
    EXPECT_TRUE(res == 100);
}

HWTEST_F(WifiGlobalFuncTest, CheckMacIsValid, TestSize.Level1)
{
    std::string str;
    EXPECT_TRUE(CheckMacIsValid(str) == -1);
    str = "00:00:00:00:00:00";
    EXPECT_TRUE(CheckMacIsValid(str) == 0);
    str = "ah:00:00:00:00:00";
    EXPECT_TRUE(CheckMacIsValid(str) == -1);
    str = "AH:00:00:00:00:00";
    EXPECT_TRUE(CheckMacIsValid(str) == -1);
    str = "00.00.00.00.00.00";
    EXPECT_TRUE(CheckMacIsValid(str) == -1);
}

HWTEST_F(WifiGlobalFuncTest, ConvertConnStateInternalTest, TestSize.Level1)
{
    bool isReport = true;
    EXPECT_TRUE(ConvertConnStateInternal(OperateResState::CONNECT_CONNECTING, isReport) == ConnState::CONNECTING);
    EXPECT_TRUE(
        ConvertConnStateInternal(OperateResState::CONNECT_AP_CONNECTED, isReport) == ConnState::CONNECTED);

    EXPECT_TRUE(ConvertConnStateInternal(OperateResState::DISCONNECT_DISCONNECTING, isReport) ==
                ConnState::DISCONNECTING);
    EXPECT_TRUE(
        ConvertConnStateInternal(OperateResState::DISCONNECT_DISCONNECTED, isReport) == ConnState::DISCONNECTED);
    EXPECT_TRUE(
        ConvertConnStateInternal(OperateResState::CONNECT_NETWORK_ENABLED, isReport) == ConnState::UNKNOWN);
    EXPECT_TRUE(
        ConvertConnStateInternal(OperateResState::CONNECT_NETWORK_DISABLED, isReport) == ConnState::UNKNOWN);
    EXPECT_TRUE(
        ConvertConnStateInternal(OperateResState::CONNECT_PASSWORD_WRONG, isReport) == ConnState::UNKNOWN);
    EXPECT_TRUE(
        ConvertConnStateInternal(OperateResState::CONNECT_CONNECTION_FULL, isReport) == ConnState::UNKNOWN);
    EXPECT_TRUE(
        ConvertConnStateInternal(OperateResState::CONNECT_CONNECTION_REJECT, isReport) == ConnState::UNKNOWN);
    EXPECT_TRUE(
        ConvertConnStateInternal(OperateResState::CONNECT_CONNECTING_TIMEOUT, isReport) == ConnState::UNKNOWN);
    EXPECT_TRUE(
        ConvertConnStateInternal(OperateResState::CONNECT_OBTAINING_IP, isReport) == ConnState::OBTAINING_IPADDR);
    EXPECT_TRUE(
        ConvertConnStateInternal(OperateResState::CONNECT_OBTAINING_IP_FAILED, isReport) == ConnState::UNKNOWN);
    EXPECT_TRUE(ConvertConnStateInternal(OperateResState::CONNECT_ASSOCIATING, isReport) == ConnState::UNKNOWN);
    EXPECT_TRUE(ConvertConnStateInternal(OperateResState::CONNECT_ASSOCIATED, isReport) == ConnState::UNKNOWN);
    EXPECT_TRUE(ConvertConnStateInternal(OperateResState::OPEN_WIFI_SUCCEED, isReport) == ConnState::UNKNOWN);
}

HWTEST_F(WifiGlobalFuncTest, IsAllowScanAnyTimeTest, TestSize.Level1)
{
    ScanForbidMode mode;
    mode.scanMode = ScanMode::ANYTIME_SCAN;
    mode.scanScene = SCAN_SCENE_ALL;
    ScanControlInfo info, cont;
    info.scanForbidList.push_back(mode);
    EXPECT_FALSE(IsAllowScanAnyTime(info));
    EXPECT_TRUE(IsAllowScanAnyTime(cont));
}

HWTEST_F(WifiGlobalFuncTest, HexStringToVecTest, TestSize.Level1)
{
    uint8_t plainText[CENTER_FREP_DIFF] = {0};
    uint32_t plainLength = 0;
    uint32_t resultLength;
    EXPECT_TRUE(HexStringToVec("01234", plainText, plainLength, resultLength) == -1);
    EXPECT_TRUE(HexStringToVec("$0", plainText, plainLength, resultLength) == -1);
    EXPECT_TRUE(HexStringToVec("0$", plainText, plainLength, resultLength) == -1);
    EXPECT_TRUE(HexStringToVec("0000", plainText, PLAIN_LENGTH, resultLength) == 0);
    EXPECT_TRUE(HexStringToVec("0000", plainText, PLAIN_LENGTH, resultLength) == 0);
}

HWTEST_F(WifiGlobalFuncTest, IsValidateNumTest, TestSize.Level1)
{
    EXPECT_TRUE(IsValidateNum("4564"));
    EXPECT_FALSE(IsValidateNum("/*"));
    EXPECT_FALSE(IsValidateNum("sdfs"));
    EXPECT_FALSE(IsValidateNum("1ss11"));
}

HWTEST_F(WifiGlobalFuncTest, TransformFrequencyIntoChannelTest, TestSize.Level1)
{
    EXPECT_TRUE(TransformFrequencyIntoChannel(2412) == 1);
    EXPECT_TRUE(TransformFrequencyIntoChannel(5200) == 40);
    EXPECT_TRUE(TransformFrequencyIntoChannel(52000) == -1);
    EXPECT_TRUE(TransformFrequencyIntoChannel(200) == -1);
}

HWTEST_F(WifiGlobalFuncTest, TransformFrequencyIntoChannelTest1, TestSize.Level1)
{
    std::vector<int> freqVector, chanVector;
    int target = FREP_2G_MIN;
    freqVector.push_back(target);
    TransformFrequencyIntoChannel(freqVector, chanVector);
    EXPECT_TRUE(count(chanVector.begin(), chanVector.end(), CHANNEL_2G_MIN) != 0);
}

HWTEST_F(WifiGlobalFuncTest, TransformFrequencyIntoChannelTest2, TestSize.Level1)
{
    std::vector<int> freqVector, chanVector;
    int target = CHANNEL_14_FREP;
    freqVector.push_back(target);
    TransformFrequencyIntoChannel(freqVector, chanVector);
    EXPECT_TRUE(count(chanVector.begin(), chanVector.end(), CHANNEL_2G) != 0);
}

HWTEST_F(WifiGlobalFuncTest, TransformFrequencyIntoChannelTest3, TestSize.Level1)
{
    std::vector<int> freqVector, chanVector;
    int target = FREP_5G_MIN;
    freqVector.push_back(target);
    TransformFrequencyIntoChannel(freqVector, chanVector);
    EXPECT_TRUE(count(chanVector.begin(), chanVector.end(), CHANNEL_5G) != 0);
}

HWTEST_F(WifiGlobalFuncTest, TransformFrequencyIntoChannelTest4, TestSize.Level1)
{
    std::vector<int> freqVector, chanVector;
    int target = CHANNEL_2G_MIN;
    freqVector.push_back(target);
    freqVector.push_back(FREP_5G_MIN);
    TransformFrequencyIntoChannel(freqVector, chanVector);
    EXPECT_TRUE(count(chanVector.begin(), chanVector.end(), CHANNEL_5G) != 0);
}

HWTEST_F(WifiGlobalFuncTest, TransformFreqToBandTest, TestSize.Level1)
{
    EXPECT_TRUE(TransformFreqToBand(2412) == BandType::BAND_2GHZ);
    EXPECT_TRUE(TransformFreqToBand(5200) == BandType::BAND_5GHZ);
}

HWTEST_F(WifiGlobalFuncTest, TransformChannelToBandTest, TestSize.Level1)
{
    EXPECT_TRUE(TransformChannelToBand(1) == BandType::BAND_2GHZ);
    EXPECT_TRUE(TransformChannelToBand(40) == BandType::BAND_5GHZ);
}

HWTEST_F(WifiGlobalFuncTest, IsValid24GHzTest, TestSize.Level1)
{
    EXPECT_TRUE(IsValid24GHz(2412));
    EXPECT_FALSE(IsValid24GHz(5200));
}

HWTEST_F(WifiGlobalFuncTest, IsValid5GHzTest, TestSize.Level1)
{
    EXPECT_TRUE(IsValid24GHz(2412));
    EXPECT_FALSE(IsValid24GHz(5200));
}

HWTEST_F(WifiGlobalFuncTest, IsValid24GChannelTest, TestSize.Level1)
{
    EXPECT_TRUE(IsValid24GChannel(1));
    EXPECT_FALSE(IsValid24GChannel(40));
}

HWTEST_F(WifiGlobalFuncTest, IsValid5GChannelTest, TestSize.Level1)
{
    EXPECT_TRUE(IsValid24GChannel(1));
    EXPECT_FALSE(IsValid24GChannel(40));
}

HWTEST_F(WifiGlobalFuncTest, SplitStringTest, TestSize.Level1)
{
    std::string str = "upnp 10 uuid:xxxxxxxxxxxxx-xxxxx";
    std::vector<std::string> vec;
    OHOS::Wifi::SplitString(str, "", vec);
    ASSERT_TRUE(vec.size() == 1);
    EXPECT_TRUE(vec[0] == str);
    vec.clear();
    OHOS::Wifi::SplitString(str, " ", vec);
    ASSERT_TRUE(vec.size() == 3);
    EXPECT_TRUE(vec[0] == "upnp");
    EXPECT_TRUE(vec[1] == "10");
    EXPECT_TRUE(vec[2] == "uuid:xxxxxxxxxxxxx-xxxxx");
}

HWTEST_F(WifiGlobalFuncTest, SplitStringToIntVectorTest, TestSize.Level1)
{
    std::string str = "1,2,3,4";
    std::vector<int> res = SplitStringToIntVector(str, ",");
    EXPECT_TRUE(res.size() == 4);

    res = SplitStringToIntVector(str, "|");
    EXPECT_TRUE(res.size() == 0);

    res = SplitStringToIntVector(str, "");
    EXPECT_TRUE(res.size() == 0);

    str = "1,2,3,aaa";
    res = SplitStringToIntVector(str, ",");
    EXPECT_TRUE(res.size() == 3);
}

HWTEST_F(WifiGlobalFuncTest, Vec2StreamTest, TestSize.Level1)
{
    std::string prefix = "head|";
    std::vector<char> vecChar;
    std::string sufffix = "|tail";
    std::string result = OHOS::Wifi::Vec2Stream(prefix, vecChar, sufffix);
    std::string expect = "head||tail";
    EXPECT_TRUE(result == expect);
    char tmp = (char)255;
    vecChar.push_back(tmp);
    result = OHOS::Wifi::Vec2Stream(prefix, vecChar, sufffix);
    expect = "head|FF |tail";
    EXPECT_TRUE(result == expect);
    tmp = (char)0;
    vecChar.push_back(tmp);
    result = OHOS::Wifi::Vec2Stream(prefix, vecChar, sufffix);
    expect = "head|FF 00 |tail";
    EXPECT_TRUE(result == expect);
}

HWTEST_F(WifiGlobalFuncTest, IsValidCountryCodeSuccessTest, TestSize.Level1)
{
    EXPECT_TRUE(IsValidCountryCode("CN"));
}

HWTEST_F(WifiGlobalFuncTest, IsValidCountryCodeFailTest, TestSize.Level1)
{
    EXPECT_FALSE(IsValidCountryCode("XX"));
}

HWTEST_F(WifiGlobalFuncTest, ConvertMncToIsoSuccessTest, TestSize.Level1)
{
    int mnc = 460;
    string code;
    EXPECT_TRUE(ConvertMncToIso(mnc, code));
}

HWTEST_F(WifiGlobalFuncTest, ConvertMncToIsoFailTest, TestSize.Level1)
{
    int mnc = 1000;
    string code;
    EXPECT_FALSE(ConvertMncToIso(mnc, code));
}

HWTEST_F(WifiGlobalFuncTest, ConvertStrToUpperTest, TestSize.Level1)
{
    string code = "cn";
    StrToUpper(code);
}

HWTEST_F(WifiGlobalFuncTest, ConvertConvertCharToIntTest, TestSize.Level1)
{
    char c = '2';
    int i = ConvertCharToInt(c);
    EXPECT_TRUE(i == 2);
}

HWTEST_F(WifiGlobalFuncTest, ConvertStringToIntTest, TestSize.Level1)
{
    string str = "2000";
    int i = ConvertStringToInt(str);
    EXPECT_TRUE(i == 2000);
}

HWTEST_F(WifiGlobalFuncTest, GetParamValueTest, TestSize.Level1)
{
    char preValue[WIFI_COUNTRY_CODE_SIZE] = {0};
    GetParamValue(WIFI_COUNTRY_CODE_CONFIG,
        WIFI_COUNTRY_CODE_CONFIG_DEFAULT, preValue, WIFI_COUNTRY_CODE_SIZE);
}

HWTEST_F(WifiGlobalFuncTest, SetParamValueTest, TestSize.Level1)
{
    SetParamValue(WIFI_COUNTRY_CODE_DYNAMIC_UPDATE_KEY, "US");
}

void MdmPropChangeEvt(const char *key, const char *value, void *context)
{}

HWTEST_F(WifiGlobalFuncTest, WatchParamValueTest, TestSize.Level1)
{
    WatchParamValue(MDM_WIFI_PROP.c_str(), MdmPropChangeEvt, nullptr);
}

HWTEST_F(WifiGlobalFuncTest, IsFreqDbacTest, TestSize.Level1)
{
    EXPECT_TRUE(IsFreqDbac(2412, 2417));
    EXPECT_FALSE(IsFreqDbac(2412, 5200));
}

HWTEST_F(WifiGlobalFuncTest, IsChannelDbacTest, TestSize.Level1)
{
    EXPECT_TRUE(IsChannelDbac(1, 2));
    EXPECT_FALSE(IsChannelDbac(1, 40));
}
}  // namespace Wifi
}  // namespace OHOS
