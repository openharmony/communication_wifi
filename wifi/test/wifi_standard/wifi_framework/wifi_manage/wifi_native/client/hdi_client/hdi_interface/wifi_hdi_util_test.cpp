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
#include "log.h"

using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
static std::string g_errLog;
void WifiHdiLogCallback(const LogType type, const LogLevel level,
                        const unsigned int domain, const char *tag,
                        const char *msg)
{
    g_errLog = msg;
}
const int MAC_SIZE = 6;
constexpr int TEN = 10;
class WifiHdiUtilTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        LOG_SetCallback(WifiHdiLogCallback);
    }
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

HWTEST_F(WifiHdiUtilTest, Get80211ElemsFromIETest1, TestSize.Level1)
{
    struct HdiElem *elem = nullptr;
    elem->id = 0;
    elem->datalen = 5;
    elem->data[0] = 0x01;
    elem->data[1] = 0x02;
    struct HdiElems elems;
    int ret = Get80211ElemsFromIE((const uint8_t*)&elem, sizeof(elem), &elems, 1);
    ASSERT_EQ(ret, -1);
    EXPECT_EQ(elems.ssidLen, 5);
    EXPECT_EQ(elems.ratesLen, 5);
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
    result = ConvertMacArr2String(nullptr, srcMacSize, nullptr, 0);
    EXPECT_EQ(result, -1);
    result = ConvertMacArr2String(nullptr, srcMacSize, nullptr, strLen);
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

extern "C" int ConvertChanToFreqMhz(int channel, int band);
HWTEST_F(WifiHdiUtilTest, ConvertChanToFreqMhzTest, TestSize.Level1)
{
    int band = 1;
    int channel = 14;
    int ret = ConvertChanToFreqMhz(channel, band);
    EXPECT_EQ(ret, 2484);
    channel = 1;
    ret = ConvertChanToFreqMhz(channel, band);
    EXPECT_EQ(ret, 2412);
    channel = 15;
    ret = ConvertChanToFreqMhz(channel, band);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(WifiHdiUtilTest, ConvertChanToFreqMhzTest1, TestSize.Level1)
{
    int band = 2;
    int channel = 32;
    int ret = ConvertChanToFreqMhz(channel, band);
    EXPECT_EQ(ret, 5160);
    channel = 1;
    ret = ConvertChanToFreqMhz(channel, band);
    EXPECT_EQ(ret, -1);
    channel = 175;
    ret = ConvertChanToFreqMhz(channel, band);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(WifiHdiUtilTest, ConvertChanToFreqMhzTest2, TestSize.Level1)
{
    int band = 8;
    int channel = 0;
    int ret = ConvertChanToFreqMhz(channel, band);
    EXPECT_EQ(ret, -1);
    channel = 234;
    ret = ConvertChanToFreqMhz(channel, band);
    EXPECT_EQ(ret, -1);
    channel = 1;
    ret = ConvertChanToFreqMhz(channel, band);
    EXPECT_EQ(ret, 5955);
    channel = 233;
    ret = ConvertChanToFreqMhz(channel, band);
    EXPECT_EQ(ret, 7115);
    channel = 2;
    ret = ConvertChanToFreqMhz(channel, band);
    EXPECT_EQ(ret, 5935);

    band = 10;
    ret = ConvertChanToFreqMhz(channel, band);
    EXPECT_EQ(ret, -1);
}

extern "C" int GetHeChanWidth(int heChannelWidth, int centerSegFreq0, int centerSegFreq1);
HWTEST_F(WifiHdiUtilTest, GetHeChanWidthTest, TestSize.Level1)
{
    int heChannelWidth = 0;
    int centerSegFreq0 = 0;
    int centerSegFreq1 = 0;
    int ret = GetHeChanWidth(heChannelWidth, centerSegFreq0, centerSegFreq1);
    EXPECT_EQ(ret, 0);

    heChannelWidth = 1;
    ret = GetHeChanWidth(heChannelWidth, centerSegFreq0, centerSegFreq1);
    EXPECT_EQ(ret, 1);

    heChannelWidth = 2;
    ret = GetHeChanWidth(heChannelWidth, centerSegFreq0, centerSegFreq1);
    EXPECT_EQ(ret, 2);

    heChannelWidth = 4;
    ret = GetHeChanWidth(heChannelWidth, centerSegFreq0, centerSegFreq1);
    EXPECT_EQ(ret, 4);

    centerSegFreq1 = 8;
    ret = GetHeChanWidth(heChannelWidth, centerSegFreq0, centerSegFreq1);
    EXPECT_EQ(ret, 3);

    centerSegFreq1 = 10;
    ret = GetHeChanWidth(heChannelWidth, centerSegFreq0, centerSegFreq1);
    EXPECT_EQ(ret, 4);
}

extern "C" int GetHeCentFreq(int centerSegFreq);
HWTEST_F(WifiHdiUtilTest, GetHeCentFreqTest, TestSize.Level1)
{
    int centerSegFreq = 0;
    int ret = GetHeCentFreq(centerSegFreq);
    EXPECT_EQ(ret, 0);

    centerSegFreq = 1;
    ret = GetHeCentFreq(centerSegFreq);
    EXPECT_EQ(ret, 5955);
}

extern "C" bool GetChanWidthCenterFreqHe(ScanInfo *pcmd, ScanInfoElem *infoElem);
const unsigned int EXT_HE_OPER_EID = 36;
const unsigned int HE_OPER_BASIC_LEN = 6;
const unsigned int GHZ_HE_INFO_EXIST_MASK_6 = 0x02;
#define COLUMN_INDEX_TWO 2
#define COLUMN_INDEX_FIVE 5
HWTEST_F(WifiHdiUtilTest, GetChanWidthCenterFreqHeTest, TestSize.Level1)
{
    ScanInfo pcmd;
    ScanInfoElem infoElem;
    bool ret = GetChanWidthCenterFreqHe(nullptr, nullptr);
    EXPECT_EQ(ret, false);
    ret = GetChanWidthCenterFreqHe(nullptr, &infoElem);
    EXPECT_EQ(ret, false);
    ret = GetChanWidthCenterFreqHe(&pcmd, nullptr);
    EXPECT_EQ(ret, false);
    ret = GetChanWidthCenterFreqHe(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WifiHdiUtilTest, GetChanWidthCenterFreqHeTest1, TestSize.Level1)
{
    ScanInfo pcmd;
    ScanInfoElem infoElem;
    infoElem.content = nullptr;
    infoElem.size = 8;
    bool ret = GetChanWidthCenterFreqHe(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
    infoElem.size = 6;
    ret = GetChanWidthCenterFreqHe(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);

    infoElem.content = (char *)malloc(10);
    ret = GetChanWidthCenterFreqHe(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);

    infoElem.size = 10;
    ret = GetChanWidthCenterFreqHe(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
    free(infoElem.content);
}

HWTEST_F(WifiHdiUtilTest, GetChanWidthCenterFreqHeTest2, TestSize.Level1)
{
    ScanInfo pcmd;
    ScanInfoElem infoElem;
    infoElem.content = (char *)malloc(HE_OPER_BASIC_LEN + 1);
    infoElem.content[0] = 0;
    infoElem.size = HE_OPER_BASIC_LEN + 1;
    bool ret = GetChanWidthCenterFreqHe(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
    free(infoElem.content);
}

HWTEST_F(WifiHdiUtilTest, GetChanWidthCenterFreqHeTest3, TestSize.Level1)
{
    ScanInfo pcmd;
    ScanInfoElem infoElem;
    infoElem.content = (char *)malloc(HE_OPER_BASIC_LEN + 1);
    infoElem.content[0] = EXT_HE_OPER_EID;
    infoElem.size = HE_OPER_BASIC_LEN + 1;
    bool ret = GetChanWidthCenterFreqHe(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
    free(infoElem.content);
}

HWTEST_F(WifiHdiUtilTest, GetChanWidthCenterFreqHeTest4, TestSize.Level1)
{
    ScanInfo pcmd;
    ScanInfoElem infoElem;
    infoElem.content = (char *)malloc(HE_OPER_BASIC_LEN + COLUMN_INDEX_FIVE + 1);
    infoElem.content[0] = EXT_HE_OPER_EID;
    infoElem.content[COLUMN_INDEX_TWO] = GHZ_HE_INFO_EXIST_MASK_6;
    infoElem.size = HE_OPER_BASIC_LEN + COLUMN_INDEX_FIVE + 1;
    bool ret = GetChanWidthCenterFreqHe(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
    free(infoElem.content);
}

#define COLUMN_INDEX_ONE 1
#define COLUMN_INDEX_THREE 3
const unsigned int VHT_OPER_INFO_EXTST_MASK = 0x40;
HWTEST_F(WifiHdiUtilTest, GetChanWidthCenterFreqHeTest5, TestSize.Level1)
{
    ScanInfo pcmd;
    ScanInfoElem infoElem;
    infoElem.content = (char *)malloc(HE_OPER_BASIC_LEN + COLUMN_INDEX_THREE + 1);
    infoElem.content[0] = EXT_HE_OPER_EID;
    infoElem.content[COLUMN_INDEX_ONE] = VHT_OPER_INFO_EXTST_MASK;
    infoElem.size = HE_OPER_BASIC_LEN + COLUMN_INDEX_THREE + 1;
    bool ret = GetChanWidthCenterFreqHe(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
    free(infoElem.content);
}

extern "C" bool GetChanMaxRates(ScanInfo *pcmd, ScanInfoElem *infoElem);
HWTEST_F(WifiHdiUtilTest, GetChanMaxRatesTest, TestSize.Level1)
{
    ScanInfo pcmd;
    ScanInfoElem infoElem;
    bool ret = GetChanMaxRates(nullptr, nullptr);
    EXPECT_EQ(ret, false);
    ret = GetChanMaxRates(nullptr, &infoElem);
    EXPECT_EQ(ret, false);
    ret = GetChanMaxRates(&pcmd, nullptr);
    EXPECT_EQ(ret, false);
    ret = GetChanMaxRates(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WifiHdiUtilTest, GetChanMaxRatesTest1, TestSize.Level1)
{
    ScanInfo pcmd;
    ScanInfoElem infoElem;
    infoElem.content = nullptr;
    infoElem.size = 10;
    bool ret = GetChanMaxRates(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
    infoElem.size = 6;
    ret = GetChanMaxRates(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);

    infoElem.content = (char *)malloc(10);
    ret = GetChanMaxRates(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);

    infoElem.size = 10;
    ret = GetChanMaxRates(&pcmd, &infoElem);
    EXPECT_EQ(ret, true);
    free(infoElem.content);
}
extern "C" bool GetChanExtMaxRates(ScanInfo *pcmd, ScanInfoElem *infoElem);
HWTEST_F(WifiHdiUtilTest, GetChanExtMaxRatesTest, TestSize.Level1)
{
    ScanInfo pcmd;
    ScanInfoElem infoElem;
    bool ret = GetChanExtMaxRates(nullptr, nullptr);
    EXPECT_EQ(ret, false);
    ret = GetChanExtMaxRates(nullptr, &infoElem);
    EXPECT_EQ(ret, false);
    ret = GetChanExtMaxRates(&pcmd, nullptr);
    EXPECT_EQ(ret, false);
    ret = GetChanExtMaxRates(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WifiHdiUtilTest, GetChanExtMaxRatesTest1, TestSize.Level1)
{
    ScanInfo pcmd;
    ScanInfoElem infoElem;
    infoElem.content = nullptr;
    infoElem.size = 6;
    bool ret = GetChanExtMaxRates(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
    infoElem.size = 2;
    ret = GetChanExtMaxRates(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);

    infoElem.content = (char *)malloc(10);
    ret = GetChanExtMaxRates(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);

    infoElem.size = 6;
    ret = GetChanExtMaxRates(&pcmd, &infoElem);
    EXPECT_EQ(ret, true);
    free(infoElem.content);
}

extern "C" int HdiParseExtensionInfo(const uint8_t *pos, size_t elen, struct HdiElems *elems, int show_errors);
HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest, TestSize.Level1)
{
    struct HdiElems elems;
    uint8_t pos[10];
    size_t elen = 0;
    int show = 1;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, -1);

    show = 0;
    ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest1, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_ASSOC_DELAY_INFO;
    size_t elen = 2;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);

    elen = 1;
    ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest2, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_FILS_REQ_PARAMS;
    size_t elen = 2;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);

    elen = 5;
    ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest3, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_FILS_KEY_CONFIRM;
    size_t elen = 2;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest4, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_FILS_SESSION;
    size_t elen = 8;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);

    elen = 9;
    ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest5, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_FILS_HLP_CONTAINER;
    size_t elen = 6;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);

    elen = 14;
    ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest6, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_FILS_IP_ADDR_ASSIGN;
    size_t elen = 5;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest7, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_KEY_DELIVERY;
    size_t elen = 5;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);

    elen = 10;
    ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest8, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_FILS_WRAPPED_DATA;
    size_t elen = 2;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest9, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_FILS_PUBLIC_KEY;
    size_t elen = 2;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);

    elen = 1;
    ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest10, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_FILS_NONCE;
    size_t elen = 16;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);

    elen = 17;
    ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest11, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_OWE_DH_PARAM;
    size_t elen = 1;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);

    elen = 5;
    ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest12, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_PASSWORD_IDENTIFIER;
    size_t elen = 2;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest13, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_OCV_OCI;
    size_t elen = 2;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);

    pos[0] = 0xff;
    ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest14, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_HE_CAPABILITIES;
    size_t elen = 2;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseExtensionInfoTest15, TestSize.Level1)
{
    struct HdiElems elems;
    int show = 1;
    uint8_t pos[10];
    pos[0] = HDI_EID_EXT_HE_OPERATION;
    size_t elen = 2;
    int ret = HdiParseExtensionInfo(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

extern "C" bool HdiGetRsnCapabLen(const uint8_t *rsnxe, size_t rsnxe_len, unsigned int capab);
HWTEST_F(WifiHdiUtilTest, HdiGetRsnCapabLenTest, TestSize.Level1)
{
    uint8_t rsnxe = 0;
    size_t rsnxe_len = 0;
    unsigned int capab = 0;
    bool ret = HdiGetRsnCapabLen(nullptr, rsnxe_len, capab);
    EXPECT_EQ(ret, false);
    ret = HdiGetRsnCapabLen(&rsnxe, rsnxe_len, capab);
    EXPECT_EQ(ret, false);

    rsnxe_len = 1;
    ret = HdiGetRsnCapabLen(nullptr, rsnxe_len, capab);
    EXPECT_EQ(ret, false);

    ret = HdiGetRsnCapabLen(&rsnxe, rsnxe_len, capab);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WifiHdiUtilTest, HdiGetRsnCapabLenTest1, TestSize.Level1)
{
    uint8_t rsnxe[6] = {0x10, 0x00, 0x00, 0x00, 0x00, 0x00};
    size_t rsnxe_len = 6;
    unsigned int capab = 0;
    bool ret = HdiGetRsnCapabLen(rsnxe, rsnxe_len, capab);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WifiHdiUtilTest, HdiGetRsnCapabLenTest2, TestSize.Level1)
{
    uint8_t rsnxe[2] = {0x01, 0x00};
    size_t rsnxe_len = 2;
    unsigned int capab = 0;
    bool ret = HdiGetRsnCapabLen(rsnxe, rsnxe_len, capab);
    EXPECT_EQ(ret, true);

    capab = 1;
    ret = HdiGetRsnCapabLen(rsnxe, rsnxe_len, capab);
    EXPECT_EQ(ret, false);
}

extern "C" int HdiParseVendorSpec(const uint8_t *pos, size_t elen, struct HdiElems *elems, int show);
HWTEST_F(WifiHdiUtilTest, HdiParseVendorSpecTest, TestSize.Level1)
{
    struct HdiElems elems;
    uint8_t pos[10] = {0};
    size_t elen = 3;
    int show = 1;
    int ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, -1);

    show = 0;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(WifiHdiUtilTest, HdiParseVendorSpecTest1, TestSize.Level1)
{
    struct HdiElems elems;
    uint8_t pos[5] = {0x00, 0x50, 0xF2, 0, 0};
    size_t elen = 5;
    int show = 1;
    int ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, -1);

    pos[3] = 1;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
    pos[3] = 2;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
    elen = 4;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, -1);
    elen = 8;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
    pos[4] = 0;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
    pos[4] = 1;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
    pos[4] = 2;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
    pos[4] = 3;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, -1);
    pos[3] = 4;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseVendorSpecTest2, TestSize.Level1)
{
    struct HdiElems elems;
    uint8_t pos[10] = {0};
    pos[0] = 0x50;
    pos[1] = 0x6f;
    pos[2] = 0x9a;
    size_t elen = 4;
    int show = 1;
    int ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, -1);

    pos[3] = 9;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
    pos[3] = 10;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
    pos[3] = 16;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
    pos[3] = 18;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
    pos[3] = 18;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
    pos[3] = 18;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
    pos[3] = 0x1B;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(WifiHdiUtilTest, HdiParseVendorSpecTest3, TestSize.Level1)
{
    struct HdiElems elems;
    uint8_t pos[10] = {0};
    pos[0] = 0x00;
    pos[1] = 0x90;
    pos[2] = 0x4c;
    size_t elen = 4;
    int show = 1;
    int ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, -1);

    pos[3] = 0x33;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
    pos[3] = 0x04;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(WifiHdiUtilTest, HdiParseVendorSpecTest4, TestSize.Level1)
{
    struct HdiElems elems;
    uint8_t pos[10] = {0};
    pos[0] = 0x00;
    pos[1] = 0x13;
    pos[2] = 0x74;
    size_t elen = 4;
    int show = 1;
    int ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);

    pos[3] = 0;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, 0);
    pos[3] = 1;
    ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(WifiHdiUtilTest, HdiParseVendorSpecTest5, TestSize.Level1)
{
    struct HdiElems elems;
    uint8_t pos[10] = {0};
    pos[0] = 5;
    pos[1] = 5;
    pos[2] = 5;
    size_t elen = 4;
    int show = 1;
    int ret = HdiParseVendorSpec(pos, elen, &elems, show);
    EXPECT_EQ(ret, -1);
}

extern "C" void RecordIeNeedParse(unsigned int id, ScanInfoElem *ie, struct NeedParseIe *iesNeedParse);
HWTEST_F(WifiHdiUtilTest, RecordIeNeedParseTest, TestSize.Level1)
{
    ScanInfoElem ie;
    NeedParseIe iesNeedParse;
    RecordIeNeedParse(255, &ie, NULL);
    ASSERT_EQ(iesNeedParse.ieExtern, NULL);

    RecordIeNeedParse(255, &ie, &iesNeedParse);
    ASSERT_EQ(iesNeedParse.ieExtern, &ie);

    RecordIeNeedParse(192, &ie, &iesNeedParse);
    ASSERT_EQ(iesNeedParse.ieVhtOper, &ie);

    RecordIeNeedParse(61, &ie, &iesNeedParse);
    ASSERT_EQ(iesNeedParse.ieHtOper, &ie);

    RecordIeNeedParse(1, &ie, &iesNeedParse);
    ASSERT_EQ(iesNeedParse.ieMaxRate, &ie);

    RecordIeNeedParse(42, &ie, &iesNeedParse);
    ASSERT_EQ(iesNeedParse.ieErp, &ie);

    RecordIeNeedParse(50, &ie, &iesNeedParse);
    ASSERT_EQ(iesNeedParse.ieExtMaxRate, &ie);
}

extern "C" bool CheckHiLinkOUISection(const uint8_t *bytes, uint8_t len);
HWTEST_F(WifiHdiUtilTest, CheckHiLinkOUISectionTest, TestSize.Level1)
{
    EXPECT_EQ(CheckHiLinkOUISection(nullptr, 8), false);
    EXPECT_EQ(CheckHiLinkOUISection(nullptr, 10), false);
}

HWTEST_F(WifiHdiUtilTest, CheckHiLinkOUISectionTest1, TestSize.Level1)
{
    uint8_t bytes[] = {0, 0xE0, 0XFC, 0X81, 0, 0, 0, 0X01, 0};
    EXPECT_EQ(CheckHiLinkOUISection(bytes, 8), false);
}

HWTEST_F(WifiHdiUtilTest, CheckHiLinkOUISectionTest2, TestSize.Level1)
{
    uint8_t bytes[] = {0, 0xE0, 0XFC, 0X80, 0, 0, 0, 0X01, 0};
    EXPECT_EQ(CheckHiLinkOUISection(bytes, 10), false);
}

extern "C" bool GetChanWidthCenterFreqHt(ScanInfo *pcmd, ScanInfoElem* infoElem);
HWTEST_F(WifiHdiUtilTest, GetChanWidthCenterFreqHtTest, TestSize.Level1)
{
    ScanInfo pcmd;
    ScanInfoElem infoElem;
    bool ret = GetChanWidthCenterFreqHt(nullptr, nullptr);
    EXPECT_EQ(ret, false);
    ret = GetChanWidthCenterFreqHt(nullptr, &infoElem);
    EXPECT_EQ(ret, false);
    ret = GetChanWidthCenterFreqHt(&pcmd, nullptr);
    EXPECT_EQ(ret, false);
    ret = GetChanWidthCenterFreqHt(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WifiHdiUtilTest, GetChanWidthCenterFreqHtTest1, TestSize.Level1)
{
    ScanInfo pcmd;
    ScanInfoElem infoElem;
    infoElem.content = nullptr;
    infoElem.size = 10;
    bool ret = GetChanWidthCenterFreqHt(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
    infoElem.size = 2;
    ret = GetChanWidthCenterFreqHt(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);

    infoElem.content = (char *)malloc(10);
    ret = GetChanWidthCenterFreqHt(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);

    infoElem.size = 10;
    ret = GetChanWidthCenterFreqHt(&pcmd, &infoElem);
    EXPECT_EQ(ret, true);
    free(infoElem.content);
}

extern "C" bool GetChanWidthCenterFreqVht(ScanInfo *pcmd, ScanInfoElem* infoElem);
HWTEST_F(WifiHdiUtilTest, GetChanWidthCenterFreqVhtTest, TestSize.Level1)
{
    ScanInfo pcmd;
    ScanInfoElem infoElem;
    bool ret = GetChanWidthCenterFreqVht(nullptr, nullptr);
    EXPECT_EQ(ret, false);
    ret = GetChanWidthCenterFreqVht(nullptr, &infoElem);
    EXPECT_EQ(ret, false);
    ret = GetChanWidthCenterFreqVht(&pcmd, nullptr);
    EXPECT_EQ(ret, false);
    ret = GetChanWidthCenterFreqVht(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WifiHdiUtilTest, GetChanWidthCenterFreqVhtTest1, TestSize.Level1)
{
    ScanInfo pcmd;
    ScanInfoElem infoElem;
    infoElem.content = nullptr;
    infoElem.size = 10;
    bool ret = GetChanWidthCenterFreqVht(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
    infoElem.size = 2;
    ret = GetChanWidthCenterFreqVht(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);

    infoElem.content = (char *)malloc(10);
    ret = GetChanWidthCenterFreqVht(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);

    infoElem.size = 10;
    ret = GetChanWidthCenterFreqVht(&pcmd, &infoElem);
    EXPECT_EQ(ret, false);
    free(infoElem.content);
}

extern "C" int GetHtChanWidth(int secondOffsetChannel);
HWTEST_F(WifiHdiUtilTest, GetHtChanWidthTest, TestSize.Level1)
{
    int secondOffsetChannel = 0;
    int result = GetHtChanWidth(secondOffsetChannel);
    EXPECT_EQ(result, 0);

    secondOffsetChannel = 1;
    result = GetHtChanWidth(secondOffsetChannel);
    EXPECT_EQ(result, 1);
}

extern "C" int GetHtCentFreq0(int primaryFrequency, int secondOffsetChannel);
HWTEST_F(WifiHdiUtilTest, GetHtCentFreq0Test, TestSize.Level1)
{
    int primaryFrequency = -2;
    int secondOffsetChannel = 0;
    int result = GetHtCentFreq0(primaryFrequency, secondOffsetChannel);
    EXPECT_EQ(result, -2);

    secondOffsetChannel = 1;
    result = GetHtCentFreq0(primaryFrequency, secondOffsetChannel);
    EXPECT_EQ(result, 8);

    secondOffsetChannel = 2;
    result = GetHtCentFreq0(primaryFrequency, secondOffsetChannel);
    EXPECT_EQ(result, 0);

    secondOffsetChannel = 3;
    result = GetHtCentFreq0(primaryFrequency, secondOffsetChannel);
    EXPECT_EQ(result, -12);
}

extern "C" int GetVhtChanWidth(int channelType, int centerFrequencyIndex1, int centerFrequencyIndex2);
HWTEST_F(WifiHdiUtilTest, GetVhtChanWidthTest, TestSize.Level1)
{
    int channelType = 0;
    int centerFrequencyIndex1 = 9;
    int centerFrequencyIndex2 = 0;
    int result = GetVhtChanWidth(channelType, centerFrequencyIndex1, centerFrequencyIndex2);
    EXPECT_EQ(result, -1);

    channelType = 1;
    result = GetVhtChanWidth(channelType, centerFrequencyIndex1, centerFrequencyIndex2);
    EXPECT_EQ(result, 2);

    centerFrequencyIndex2 = 1;
    result = GetVhtChanWidth(channelType, centerFrequencyIndex1, centerFrequencyIndex2);
    EXPECT_EQ(result, 3);

    centerFrequencyIndex2 = -1;
    result = GetVhtChanWidth(channelType, centerFrequencyIndex1, centerFrequencyIndex2);
    EXPECT_EQ(result, 4);
}

extern "C" int GetVhtCentFreq(int channelType, int centerFrequencyIndex);
HWTEST_F(WifiHdiUtilTest, GetVhtCentFreqTest, TestSize.Level1)
{
    int result = GetVhtCentFreq(0, 0);
    EXPECT_EQ(result, 0);

    result = GetVhtCentFreq(0, 1);
    EXPECT_EQ(result, 0);

    result = GetVhtCentFreq(1, 0);
    EXPECT_EQ(result, 0);

    result = GetVhtCentFreq(1, 1);
    EXPECT_EQ(result, -1);
}

extern "C" int HexStringToString(const char *str, char *out);
HWTEST_F(WifiHdiUtilTest, HexStringToStringTest, TestSize.Level1)
{
    char out[100];
    EXPECT_EQ(HexStringToString("", out), -1);
    EXPECT_EQ(HexStringToString("1", out), -1);
    EXPECT_EQ(HexStringToString("12", out), 0);
    EXPECT_EQ(HexStringToString("1g", out), 0);
    EXPECT_EQ(HexStringToString("g1", out), 0);
    EXPECT_EQ(HexStringToString("gg", out), 0);
    EXPECT_EQ(HexStringToString("1234567890abcdef", out), 0);
}

extern "C" void GetChanWidthCenterFreq(ScanInfo *pcmd, struct NeedParseIe* iesNeedParse);
HWTEST_F(WifiHdiUtilTest, GetChanWidthCenterFreqTest, TestSize.Level1)
{
    ScanInfo pcmd;
    struct NeedParseIe iesNeedParse;
    GetChanWidthCenterFreq(nullptr, nullptr);
    GetChanWidthCenterFreq(&pcmd, nullptr);
    GetChanWidthCenterFreq(nullptr, &iesNeedParse);
    GetChanWidthCenterFreq(&pcmd, &iesNeedParse);
    EXPECT_NE(pcmd.ieSize, TEN);
}

extern "C" void GetInfoElems(int length, int end, char *srcBuf, ScanInfo *pcmd);
HWTEST_F(WifiHdiUtilTest, GetInfoElemsTest, TestSize.Level1)
{
    char srcBuf[10] = "";
    GetInfoElems(0, 0, srcBuf, nullptr);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiHdiUtilTest, GetInfoElemsTest1, TestSize.Level1)
{
    int length = 10;
    int end = 5;
    char srcBuf[10] = "[123";
    ScanInfo pcmd;
    GetInfoElems(length, end, srcBuf, &pcmd);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiHdiUtilTest, GetInfoElemsTest2, TestSize.Level1)
{
    int length = 10;
    int end = 5;
    char srcBuf[10] = "123";
    ScanInfo pcmd;
    GetInfoElems(length, end, srcBuf, &pcmd);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiHdiUtilTest, GetInfoElemsTest3, TestSize.Level1)
{
    int length = 10;
    int end = 5;
    char srcBuf[10] = "123[";
    ScanInfo pcmd;
    GetInfoElems(length, end, srcBuf, &pcmd);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiHdiUtilTest, GetInfoElemsTest4, TestSize.Level1)
{
    int length = 10;
    int end = 5;
    char srcBuf[10] = "123[]";
    ScanInfo pcmd;
    GetInfoElems(length, end, srcBuf, &pcmd);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiHdiUtilTest, GetInfoElemsTest5, TestSize.Level1)
{
    int length = 10;
    int end = 5;
    char srcBuf[10] = "123[]";
    ScanInfo pcmd;
    pcmd.infoElems = (ScanInfoElem *)calloc(256, sizeof(ScanInfoElem));
    GetInfoElems(length, end, srcBuf, &pcmd);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiHdiUtilTest, GetScanResultInfoElemTest, TestSize.Level1)
{
    ScanInfo scanInfo;
    uint8_t *start = NULL;
    size_t len = 0;
    GetScanResultInfoElem(&scanInfo, start, len);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiHdiUtilTest, GetScanResultInfoElemTest1, TestSize.Level1)
{
    ScanInfo scanInfo;
    uint8_t start[] = {0x01, 0x02, 0x03};
    size_t len = sizeof(start);
    GetScanResultInfoElem(&scanInfo, start, len);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiHdiUtilTest, RouterSupportHiLinkByWifiInfoTest, TestSize.Level1)
{
    uint8_t start[10] = {0};
    size_t len = 10;
    bool result = RouterSupportHiLinkByWifiInfo(nullptr, len);
    EXPECT_FALSE(result);

    result = RouterSupportHiLinkByWifiInfo(start, len);
    EXPECT_FALSE(result);
}
}
}