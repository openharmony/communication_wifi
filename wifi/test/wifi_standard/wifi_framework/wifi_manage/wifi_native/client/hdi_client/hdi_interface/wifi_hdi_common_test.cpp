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

HWTEST_F(WifiHdiCommonTest, HdiTxtPrintfTest, TestSize.Level1)
{
    char str[10];
    int ret = HdiTxtPrintf(str, 0, "Hello, World!");
    EXPECT_EQ(ret, -1);
    EXPECT_STREQ(str, "");
}

HWTEST_F(WifiHdiCommonTest, HdiTxtPrintfTest1, TestSize.Level1)
{
    char str[15];
    int ret = HdiTxtPrintf(str, 15, "Hello, World!");
    EXPECT_EQ(ret, 13);
    EXPECT_STREQ(str, "Hello, World!");
}

HWTEST_F(WifiHdiCommonTest, HdiBufEncodeTest, TestSize.Level1)
{
    char txt[10];
    uint8_t data[] = {'\"'};
    HdiBufEncode(txt, sizeof(txt), data, sizeof(data));
    EXPECT_STREQ(txt, "\\\"");
}

HWTEST_F(WifiHdiCommonTest, HdiBufEncodeTest1, TestSize.Level1)
{
    char txt[10];
    uint8_t data[] = {'\\'};
    HdiBufEncode(txt, sizeof(txt), data, sizeof(data));
    EXPECT_STREQ(txt, "\\\\");
}

HWTEST_F(WifiHdiCommonTest, HdiBufEncodeTest2, TestSize.Level1)
{
    char txt[10];
    uint8_t data[] = {'\033'};
    HdiBufEncode(txt, sizeof(txt), data, sizeof(data));
    EXPECT_STREQ(txt, "\\e");
}

HWTEST_F(WifiHdiCommonTest, HdiBufEncodeTest3, TestSize.Level1)
{
    char txt[10];
    uint8_t data[] = {'\n'};
    HdiBufEncode(txt, sizeof(txt), data, sizeof(data));
    EXPECT_STREQ(txt, "\\n");
}

HWTEST_F(WifiHdiCommonTest, HdiBufEncodeTest4, TestSize.Level1)
{
    char txt[10];
    uint8_t data[] = {'\r'};
    HdiBufEncode(txt, sizeof(txt), data, sizeof(data));
    EXPECT_STREQ(txt, "\\r");
}

HWTEST_F(WifiHdiCommonTest, HdiBufEncodeTest5, TestSize.Level1)
{
    char txt[10];
    uint8_t data[] = {'\t'};
    HdiBufEncode(txt, sizeof(txt), data, sizeof(data));
    EXPECT_STREQ(txt, "\\t");
}

HWTEST_F(WifiHdiCommonTest, HdiBufEncodeTest6, TestSize.Level1)
{
    char txt[10];
    uint8_t data[] = {HDI_POS_TT};
    HdiBufEncode(txt, sizeof(txt), data, sizeof(data));
    EXPECT_STREQ(txt, "\x20");
}

HWTEST_F(WifiHdiCommonTest, HdiBufEncodeTest7, TestSize.Level1)
{
    char txt[10];
    uint8_t data[] = {HDI_POS_OTX};
    HdiBufEncode(txt, sizeof(txt), data, sizeof(data));
    EXPECT_STREQ(txt, "~");
}

HWTEST_F(WifiHdiCommonTest, HdiBufEncodeTest8, TestSize.Level1)
{
    char txt[10];
    uint8_t data[] = {0x50};
    HdiBufEncode(txt, sizeof(txt), data, sizeof(data));
    EXPECT_STREQ(txt, "P");
}

HWTEST_F(WifiHdiCommonTest, HdiBufEncodeTest9, TestSize.Level1)
{
    char txt[10];
    uint8_t data[10] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'};
    HdiBufEncode(txt, sizeof(txt), data, sizeof(data));
    EXPECT_STREQ(txt, "abcdef");
}

HWTEST_F(WifiHdiCommonTest, HdiGetIeTxtTest, TestSize.Level1)
{
    char pos[100] = {0};
    char end[100] = {0};
    const char *proto = "proto";
    uint8_t ie[10] = {0};
    size_t ieLen = 10;

    char* result = HdiGetIeTxt(pos, end, proto, ie, ieLen);
    EXPECT_STREQ(pos, result);
}

HWTEST_F(WifiHdiCommonTest, StrSafeCopyTest, TestSize.Level1)
{
    char dst[10];
    StrSafeCopy(nullptr, 10, "source");
    EXPECT_STREQ(dst, "");
    StrSafeCopy(dst, 10, nullptr);
    EXPECT_STREQ(dst, "");
}

HWTEST_F(WifiHdiCommonTest, StrSafeCopyTest2, TestSize.Level1)
{
    char dst[10] = "source";
    StrSafeCopy(dst, 10, "source");
    EXPECT_STREQ(dst, "source");
}

HWTEST_F(WifiHdiCommonTest, StrSafeCopyTest3, TestSize.Level1)
{
    char dst[10];
    StrSafeCopy(dst, 10, "this is a long source string");
    EXPECT_STREQ(dst, "this is a");
}

HWTEST_F(WifiHdiCommonTest, HdiGetWapiTxtTest, TestSize.Level1)
{
    uint8_t ie[] = {0, 0, 0, 0, 0, 0, 0, 0};
    char pos[] = "test";
    char end[] = "end";
    char* result = HdiGetWapiTxt(pos, end, ie);
    EXPECT_STREQ(result, pos);
}
extern "C" int HdiGetCipherInfo(char *start, char *end, int ciphers, const char *delim);
HWTEST_F(WifiHdiCommonTest, HdiGetCipherInfoTest, TestSize.Level1)
{
    char buffer[100];
    int ret = HdiGetCipherInfo(buffer, buffer + sizeof(buffer), HDI_CIPHER_CCMP_256, ",");
    EXPECT_EQ(ret, 8);
    EXPECT_STREQ(buffer, "CCMP-256");
}

HWTEST_F(WifiHdiCommonTest, HdiGetCipherInfoTest1, TestSize.Level1)
{
    char buffer[100];
    int ret = HdiGetCipherInfo(buffer, buffer + sizeof(buffer), HDI_CIPHER_GCMP_256, ",");
    EXPECT_EQ(ret, 8);
    EXPECT_STREQ(buffer, "GCMP-256");
}

HWTEST_F(WifiHdiCommonTest, HdiGetCipherInfoTest2, TestSize.Level1)
{
    char buffer[100];
    int ret = HdiGetCipherInfo(buffer, buffer + sizeof(buffer), HDI_CIPHER_CCMP, ",");
    EXPECT_EQ(ret, 4);
    EXPECT_STREQ(buffer, "CCMP");
}

HWTEST_F(WifiHdiCommonTest, HdiGetCipherInfoTest3, TestSize.Level1)
{
    char buffer[100];
    int ret = HdiGetCipherInfo(buffer, buffer + sizeof(buffer), HDI_CIPHER_GCMP, ",");
    EXPECT_EQ(ret, 4);
    EXPECT_STREQ(buffer, "GCMP");
}

HWTEST_F(WifiHdiCommonTest, HdiGetCipherInfoTest4, TestSize.Level1)
{
    char buffer[100];
    int ret = HdiGetCipherInfo(buffer, buffer + sizeof(buffer), HDI_CIPHER_TKIP, ",");
    EXPECT_EQ(ret, 4);
    EXPECT_STREQ(buffer, "TKIP");
}

HWTEST_F(WifiHdiCommonTest, HdiGetCipherInfoTest5, TestSize.Level1)
{
    char buffer[100];
    int ret = HdiGetCipherInfo(buffer, buffer + sizeof(buffer), HDI_CIPHER_AES_128_CMAC, ",");
    EXPECT_EQ(ret, 12);
    EXPECT_STREQ(buffer, "AES-128-CMAC");
}

HWTEST_F(WifiHdiCommonTest, HdiGetCipherInfoTest6, TestSize.Level1)
{
    char buffer[100];
    int ret = HdiGetCipherInfo(buffer, buffer + sizeof(buffer), HDI_CIPHER_BIP_GMAC_128, ",");
    EXPECT_EQ(ret, 12);
    EXPECT_STREQ(buffer, "BIP-GMAC-128");
}

HWTEST_F(WifiHdiCommonTest, HdiGetCipherInfoTest7, TestSize.Level1)
{
    char buffer[100];
    int ret = HdiGetCipherInfo(buffer, buffer + sizeof(buffer), HDI_CIPHER_BIP_GMAC_256, ",");
    EXPECT_EQ(ret, 12);
    EXPECT_STREQ(buffer, "BIP-GMAC-256");
}

HWTEST_F(WifiHdiCommonTest, HdiGetCipherInfoTest8, TestSize.Level1)
{
    char buffer[100];
    int ret = HdiGetCipherInfo(buffer, buffer + sizeof(buffer), HDI_CIPHER_BIP_CMAC_256, ",");
    EXPECT_EQ(ret, 12);
    EXPECT_STREQ(buffer, "BIP-CMAC-256");
}

HWTEST_F(WifiHdiCommonTest, HdiGetCipherInfoTest9, TestSize.Level1)
{
    char buffer[100];
    int ret = HdiGetCipherInfo(buffer, buffer + sizeof(buffer), HDI_CIPHER_NONE, ",");
    EXPECT_EQ(ret, 4);
    EXPECT_STREQ(buffer, "NONE");
}

extern "C" int HdiParseIe(const uint8_t *hdiIe, size_t wpaIeLen, struct HdiIeData *data);
HWTEST_F(WifiHdiCommonTest, HdiParseIeTest, TestSize.Level1)
{
    uint8_t hdiIe[] = {HDI_EID_RSN, 0, 0, 0};
    size_t wpaIeLen = sizeof(hdiIe);
    struct HdiIeData data;
    int result = HdiParseIe(hdiIe, wpaIeLen, &data);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiCommonTest, HdiParseIeTest1, TestSize.Level1)
{
    uint8_t hdiIe[] = {0, 0, 0, 0};
    size_t wpaIeLen = sizeof(hdiIe);
    struct HdiIeData data;
    int result = HdiParseIe(hdiIe, wpaIeLen, &data);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiCommonTest, HdiParseIeTest2, TestSize.Level1)
{
    uint8_t hdiIe[] = {HDI_EID_RSN, 0, 0, 0, 0, 0, 0};
    size_t wpaIeLen = sizeof(hdiIe);
    struct HdiIeData data;
    int result = HdiParseIe(hdiIe, wpaIeLen, &data);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiCommonTest, HdiParseIeTest3, TestSize.Level1)
{
    uint8_t hdiIe[] = {HDI_EID_VENDOR_SPECIFIC, 0, 0, 0, 0, 0, 0};
    size_t wpaIeLen = sizeof(hdiIe);
    struct HdiIeData data;
    int result = HdiParseIe(hdiIe, wpaIeLen, &data);
    EXPECT_EQ(result, -1);
}

extern "C" int HdiConvertIeRsn(const uint8_t *rsnIe, size_t rsnIeLen, struct HdiIeData *data);
HWTEST_F(WifiHdiCommonTest, HdiConvertIeRsnTest, TestSize.Level1)
{
    uint8_t rsnIe[10] = {0};
    size_t rsnIeLen = 0;
    struct HdiIeData data;
    int ret = HdiConvertIeRsn(rsnIe, rsnIeLen, &data);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(WifiHdiCommonTest, HdiConvertIeRsnTest1, TestSize.Level1)
{
    uint8_t rsnIe[10] = {0};
    size_t rsnIeLen = 1;
    struct HdiIeData data;
    int ret = HdiConvertIeRsn(rsnIe, rsnIeLen, &data);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(WifiHdiCommonTest, HdiConvertIeRsnTest2, TestSize.Level1)
{
    uint8_t rsnIe[10] = {0};
    rsnIe[1] = HDI_POS_FOURTH;
    size_t rsnIeLen = 5;
    struct HdiIeData data;
    int ret = HdiConvertIeRsn(rsnIe, rsnIeLen, &data);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(WifiHdiCommonTest, HdiConvertIeRsnTest3, TestSize.Level1)
{
    uint8_t rsnIe[10] = {0};
    rsnIe[1] = HDI_POS_FOURTH;
    size_t rsnIeLen = 6;
    struct HdiIeData data;
    int ret = HdiConvertIeRsn(rsnIe, rsnIeLen, &data);
    EXPECT_EQ(ret, -1);
}

extern "C" int HdiConvertIe(const uint8_t *hdiIe, size_t wpaIeLen, struct HdiIeData *data);
HWTEST_F(WifiHdiCommonTest, HdiConvertIeTest, TestSize.Level1)
{
    uint8_t hdiIe[10];
    size_t wpaIeLen = sizeof(struct HdiIeHdr) - 1;
    struct HdiIeData data;
    int result = HdiConvertIe(hdiIe, wpaIeLen, &data);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiCommonTest, HdiConvertIeTest1, TestSize.Level1)
{
    uint8_t hdiIe[10];
    size_t wpaIeLen = sizeof(struct HdiIeHdr) + 1;
    struct HdiIeData data;
    hdiIe[0] = 0x00;
    int result = HdiConvertIe(hdiIe, wpaIeLen, &data);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiCommonTest, HdiConvertIeTest2, TestSize.Level1)
{
    uint8_t hdiIe[10];
    size_t wpaIeLen = sizeof(struct HdiIeHdr) + 1;
    struct HdiIeData data;
    hdiIe[1] = 0x00;
    int result = HdiConvertIe(hdiIe, wpaIeLen, &data);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiCommonTest, HdiConvertIeTest3, TestSize.Level1)
{
    uint8_t hdiIe[10];
    size_t wpaIeLen = sizeof(struct HdiIeHdr) + 1;
    struct HdiIeData data;
    hdiIe[2] = 0x00; hdiIe[3] = 0x00; hdiIe[4] = 0x00;
    int result = HdiConvertIe(hdiIe, wpaIeLen, &data);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiCommonTest, HdiConvertIeRsnTest4, TestSize.Level1)
{
    uint8_t hdiIe[10];
    size_t wpaIeLen = sizeof(struct HdiIeHdr) + 1;
    struct HdiIeData data;
    hdiIe[5] = 0x00; hdiIe[6] = 0x00;
    int result = HdiConvertIe(hdiIe, wpaIeLen, &data);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiCommonTest, HdiConvertIeRsnTest5, TestSize.Level1)
{
    uint8_t hdiIe[10];
    size_t wpaIeLen = sizeof(struct HdiIeHdr) + HDI_SELECTOR_LEN + 1;
    struct HdiIeData data;
    int result = HdiConvertIe(hdiIe, wpaIeLen, &data);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiCommonTest, HdiConvertIeRsnTest6, TestSize.Level1)
{
    uint8_t hdiIe[10];
    size_t wpaIeLen = sizeof(struct HdiIeHdr) + 1;
    struct HdiIeData data;
    int result = HdiConvertIe(hdiIe, wpaIeLen, &data);
    EXPECT_EQ(result, -1);
}