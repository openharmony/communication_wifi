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
#include "wifi_hdi_common.h"
#include "wifi_hdi_util.h"
#include "wifi_hdi_sta_impl.h"

#include "securec.h"
#include "mock_wpa_ctrl.h"
#include "wifi_hal_crpc_server.h"
#include "wifi_hal_common_func.h"
#include "wifi_log.h"


using namespace testing::ext;

namespace OHOS {
namespace Wifi {

constexpr int NETWORK_ID = 15;
constexpr int NUMBER = 188;
constexpr int NUM = 10;

class WifiHdiCommonTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiHdiCommonTest, HdiGetIeTest, TestSize.Level1)
{
    uint8_t ies[NETWORK_ID] = {NUM};
    EXPECT_EQ(HdiGetIe(NULL, 0, 1), NULL);
    EXPECT_EQ(HdiGetIe(ies, HDI_EID_CAG_NUMBER, 1), NULL);
}

HWTEST_F(WifiHdiCommonTest, hex2byteTest, TestSize.Level1)
{
    char str[] = "+++++";
    EXPECT_EQ(hex2byte("4$$"), -1);
    EXPECT_EQ(hex2byte("4$$"), -1);
    EXPECT_EQ(hex2byte("bc7"), NUMBER);
    HdiTxtPrintf(str, 1, "-preauth");
}


HWTEST_F(WifiHdiCommonTest, HdiBssGetVendorIeTest, TestSize.Level1)
{
    uint8_t ies[NETWORK_ID] = {0};
    EXPECT_EQ(HdiBssGetVendorIe(str, 1, HDI_CAP_DMG_IBSS), NULL);
}

HWTEST_F(WifiHdiCommonTest, Get80211ElemsFromIETest, TestSize.Level1)
{
    HdiElems elems;
    uint8_t start[NETWORK_ID] = {0};
    EXPECT_EQ(Get80211ElemsFromIE(NULL, 0, &elems, 1), 0);
    EXPECT_EQ(Get80211ElemsFromIE(start, 0, &elems, 1), 0);

}

HWTEST_F(WifiHdiCommonTest, HdiSSid2TxtTest, TestSize.Level1)
{
    uint8_t ssid[] = {"123456"};
    uint8_t str[] = "";
    const char *pos = HdiSSid2Txt(str, NETWORK_ID);
    EXPECT_TRUE(pos != NULL);
	HdiSSid2Txt(ssid, NETWORK_ID);
}

HWTEST_F(WifiHdiCommonTest, HdiStartScanTest, TestSize.Level1)
{
    ScanSettings settings;
    settings.hiddenSsidSize = NUM;
    EXPECT_EQ(HdiStartScan(&settings), WIFI_HAL_FAILED);
    settings.hiddenSsidSize = 0;
    EXPECT_EQ(HdiStartScan(&settings), WIFI_HAL_FAILED);
}

HWTEST_F(WifiHdiCommonTest, GetHdiScanInfosTest, TestSize.Level1)
{
    ScanInfo infos;
    int size = 0;
    EXPECT_EQ(GetHdiScanInfos(NULL, &size), WIFI_HAL_FAILED);
    EXPECT_EQ(GetHdiScanInfos(&infos, NULL), WIFI_HAL_FAILED);
    EXPECT_EQ(GetHdiScanInfos(&infos, &size), WIFI_HAL_FAILED);
    size = -1;
    EXPECT_EQ(GetHdiScanInfos(&infos, &size), WIFI_HAL_FAILED);
    size = 1;
    EXPECT_EQ(GetHdiScanInfos(&infos, &size), WIFI_HAL_FAILED);
}

HWTEST_F(WifiHdiCommonTest, GetHdiSignalInfoTest, TestSize.Level1)
{
    WpaSignalInfo info;
    settings.hiddenSsidSize = NUM;
    EXPECT_EQ(GetHdiSignalInfo(NULL), -1);
    EXPECT_EQ(GetHdiSignalInfo(&info), 1);
}

HWTEST_F(WifiHdiCommonTest, GetHdiSignalInfoTest, TestSize.Level1)
{
    unsigned char mac[] = 10.189.140.226.00;
    unsigned char info[] = 10.189.140;
    EXPECT_EQ(RegisterHdiStaCallbackEvent(), WIFI_HAL_FAILED);
    EXPECT_EQ(SetAssocMacAddr(NULL, 0), WIFI_HAL_FAILED);
    EXPECT_EQ(SetAssocMacAddr(info, WIFI_MAC_LENGTH), WIFI_HAL_FAILED);
    EXPECT_EQ(SetAssocMacAddr(mac, WIFI_MAC_LENGTH), WIFI_HAL_FAILED);
	UnRegisterHdiStaCallbackEvent();
}
}  // namespace Wifi
}  // namespace OHOS
