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
#include <gmock/gmock.h>
#include "wifi_error_no.h"
#include "wifi_hdi_wpa_sta_impl.h"

using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
constexpr int MAC_LEN = 17;
constexpr int LENTH = 6;
class WifiHdiWpaStaImplTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaStartTest_01, TestSize.Level1)
{
    WifiErrorNo result = HdiWpaStaStart(nullptr);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    result = HdiWpaStaStart("wlan0");
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaStopTest_01, TestSize.Level1)
{
    WifiErrorNo result = HdiWpaStaStop();
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaConnectTest, TestSize.Level1)
{
    int networkId = 1;
    WifiErrorNo result = HdiWpaStaConnect(networkId);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaAddNetworkTest, TestSize.Level1)
{
    int *networkId = nullptr;
    WifiErrorNo result = HdiWpaStaAddNetwork(networkId);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);

    int workld = 1;
    result = HdiWpaStaAddNetwork(&workld);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaDisableNetworkTest, TestSize.Level1)
{
    int networkId = 1;
    WifiErrorNo result = HdiWpaStaDisableNetwork(networkId);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaSaveConfigTest, TestSize.Level1)
{
    WifiErrorNo result = HdiWpaStaSaveConfig();
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaStartWpsPinModeTest, TestSize.Level1)
{
    WifiWpsParam config;
    int pinCode;
    WifiErrorNo result = HdiWpaStaStartWpsPinMode(nullptr, &pinCode);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    result = HdiWpaStaStartWpsPinMode(&config, nullptr);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    result = HdiWpaStaStartWpsPinMode(nullptr, nullptr);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    result = HdiWpaStaStartWpsPinMode(&config, &pinCode);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaStartWpsPbcModeTest, TestSize.Level1)
{
    WifiWpsParam config;
    WifiErrorNo result = HdiWpaStaStartWpsPbcMode(nullptr);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    result = HdiWpaStaStartWpsPbcMode(&config);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaSetCountryCodeTest, TestSize.Level1)
{
    char countryCode[10] = "CN";
    WifiErrorNo result = HdiWpaStaSetCountryCode(countryCode);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaGetCountryCodeTest, TestSize.Level1)
{
    char countryCode[2];
    uint32_t size = 2;
    WifiErrorNo result = HdiWpaStaGetCountryCode(countryCode, size);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaSetSuspendModeTest, TestSize.Level1)
{
    int mode = 1;
    WifiErrorNo result = HdiWpaStaSetSuspendMode(mode);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaListNetworksTest, TestSize.Level1)
{
    struct HdiWifiWpaNetworkInfo networkList[10];
    uint32_t size = 10;
    WifiErrorNo result = HdiWpaListNetworks(networkList, &size);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaGetNetworkTest, TestSize.Level1)
{
    int32_t networkId = 1;
    const char *param = "param";
    char value[10];
    uint32_t valueLen = 10;
    WifiErrorNo result = HdiWpaGetNetwork(networkId, param, value, valueLen);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaSetShellCmdTest, TestSize.Level1)
{
    const char *ifName = "wlan0";
    const char *cmd = "command";
    WifiErrorNo result = HdiWpaStaSetShellCmd(ifName, cmd);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaGetPskPassphraseTest, TestSize.Level1)
{
    char ifName[] = "wlan0";
    char psk[32];
    uint32_t pskLen = 6;
    WifiErrorNo result = HdiWpaStaGetPskPassphrase(ifName, psk, pskLen);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaSetPowerSaveTest, TestSize.Level1)
{
    int enable = true;
    WifiErrorNo result = HdiWpaStaSetPowerSave(enable);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaBlocklistClearTest, TestSize.Level1)
{
    WifiErrorNo result = HdiWpaStaBlocklistClear();
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaAutoConnectTest, TestSize.Level1)
{
    int enable = true;
    WifiErrorNo result = HdiWpaStaAutoConnect(enable);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiStopWpsStaTest, TestSize.Level1)
{
    WifiErrorNo result = HdiStopWpsSta();
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaSetNetworkTest, TestSize.Level1)
{
    int networkId = 1;
    int size = 1;
    WifiErrorNo result = HdiWpaStaSetNetwork(networkId, nullptr, size);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaEnableNetworkTest, TestSize.Level1)
{
    int networkId = 2;
    WifiErrorNo result = HdiWpaStaEnableNetwork(networkId);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaRemoveNetworkTest, TestSize.Level1)
{
    int networkId = 3;
    WifiErrorNo result = HdiWpaStaRemoveNetwork(networkId);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaScanTest, TestSize.Level1)
{
    WifiErrorNo result = HdiWpaStaScan();
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaGetDeviceMacAddressTest, TestSize.Level1)
{
    char macAddr[18] = {0};
    int macAddrLen = 0;
    WifiErrorNo result = HdiWpaStaGetDeviceMacAddress(nullptr, macAddrLen);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);

    result = HdiWpaStaGetDeviceMacAddress(macAddr, macAddrLen);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, ConvertMacToStrFail1, TestSize.Level1)
{
    char *mac = NULL;
    int macSize = LENTH;
    char macStr[MAC_LEN + 1] = "00:00:00:00:00:00";
    int strLen = MAC_LEN + 1;
    int result = ConvertMacToStr(mac, macSize, macStr, strLen);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiWpaStaImplTest, ConvertMacToStrFail2, TestSize.Level1)
{
    char *macStr = NULL;
    int macSize = LENTH;
    char mac[LENTH] = "ABCDE";
    int strLen = MAC_LEN + 1;
    int result = ConvertMacToStr(mac, macSize, macStr, strLen);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiWpaStaImplTest, ConvertMacToStrFail3, TestSize.Level1)
{
    char mac[LENTH] = "ABCDE";
    int macSize = 1;
    char macStr[MAC_LEN + 1] = "00:00:00:00:00:00";
    int strLen = MAC_LEN + 1;
    int result = ConvertMacToStr(mac, macSize, macStr, strLen);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiWpaStaImplTest, ConvertMacToStrFail4, TestSize.Level1)
{
    char mac[LENTH] = "ABCDE";
    int macSize = 7;
    char macStr[MAC_LEN + 1] = "00:00:00:00:00:00";
    int strLen = LENTH;
    int result = ConvertMacToStr(mac, macSize, macStr, strLen);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiWpaStaImplTest, ConvertMacToStrFail5, TestSize.Level1)
{
    char mac[LENTH] = "ABCDE";
    int macSize = 7;
    char macStr[MAC_LEN + 1] = "00:00:00:00:00:00";
    int strLen = MAC_LEN + 1;
    int result = ConvertMacToStr(mac, macSize, macStr, strLen);
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaStaImplTest, ConvertMacToStrFail6, TestSize.Level1)
{
    char mac[LENTH] = "ABCDE";
    int macSize = LENTH;
    char macStr[MAC_LEN + 1] = "00:00:00:00:00:00";
    int strLen = MAC_LEN;
    int result = ConvertMacToStr(mac, macSize, macStr, strLen);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiWpaStaImplTest, ConvertMacToStrFail7, TestSize.Level1)
{
    char mac[LENTH] = "ABCDE";
    int macSize = LENTH;
    char macStr[MAC_LEN + 1] = "00:00:00:00:00:00";
    int strLen = LENTH;
    int result = ConvertMacToStr(mac, macSize, macStr, strLen);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiWpaStaImplTest, ConvertMacToStrFail8, TestSize.Level1)
{
    char *macStr = NULL;
    int macSize = 7;
    char *mac = NULL;
    int strLen = MAC_LEN + 1;
    int result = ConvertMacToStr(mac, macSize, macStr, strLen);
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiHdiWpaStaImplTest, ConvertMacToStrSuccess, TestSize.Level1)
{
    char mac[LENTH] = "ABCDE";
    int macSize = LENTH;
    char macStr[MAC_LEN + 1] = "00:00:00:00:00:00";
    int strLen = MAC_LEN + 1;
    int result = ConvertMacToStr(mac, macSize, macStr, strLen);
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaDisconnectTest, TestSize.Level1)
{
    WifiErrorNo result = HdiWpaStaDisconnect();
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaReassociateTest, TestSize.Level1)
{
    WifiErrorNo result = HdiWpaStaReassociate();
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaStaImplTest, HdiWpaStaReconnectTest, TestSize.Level1)
{
    WifiErrorNo result = HdiWpaStaReconnect();
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}
}
}