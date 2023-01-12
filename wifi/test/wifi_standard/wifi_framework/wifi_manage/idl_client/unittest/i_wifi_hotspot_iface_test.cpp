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
#include <gtest/gtest.h>
#include <securec.h>
#include "i_wifi_hotspot_iface.h"

using ::testing::_;
using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {

constexpr int NETWORK_ID = 0;
constexpr int WPA_PSK = 1;
constexpr int MODE1 = 2;
constexpr int LENTH = 15;
constexpr int BAND_2GHZ = 1;
constexpr int BAND_5GHZ = 2;

class IWifihotspotIfaceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}
};

HWTEST_F(IWifihotspotIfaceTest, StartSoftApTest, TestSize.Level1)
{
    int pid = NETWORK_ID;
    EXPECT_TRUE(StartSoftAp(pid) == WIFI_IDL_OPT_OK)；
}

HWTEST_F(IWifihotspotIfaceTest, StopSoftApTest, TestSize.Level1)
{
    int pid = NETWORK_ID;
    EXPECT_TRUE(StopSoftAp(pid) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifihotspotIfaceTest, SetHostapdConfigTest, TestSize.Level1)
{
    int pid = NETWORK_ID;
    HostapdConfig config;
    if (strcpy_s(config.ssid, sizeof(config.ssid), "Hwmate") != EOK) {
        return;
    }
    config.ssidLen = strlen(config->ssid);
    if (strcpy_s(config.preSharedKey, sizeof(config.preSharedKey), "A123456")) {
        return;
    }
    config.preSharedKeyLen = strlen(config->preSharedKey);
    config.securityType = WPA_PSK;
    config.band = BAND_5GHZ;
    config.channel = 6;
    config.maxConn = 20;
    EXPECT_TRUE(SetHostapdConfig(&config, pid) == WIFI_IDL_OPT_FAILED);
}

HWTEST_F(IWifihotspotIfaceTest, GetStaInfosTest, TestSize.Level1)
{
    int pid = NETWORK_ID;
    char *infos = nullptr;
    if (strcpy_s(infos, sizeof(infos), "CHINA") != EOK) {
        return;
    }
    int *size = &MODE1;
    EXPECT_TRUE(GetStaInfos(infos, size, pid) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifihotspotIfaceTest, SetMacFilterTest, TestSize.Level1)
{
    int pid = NETWORK_ID;
    char *mac = nullptr;
    if (strcpy_s(mac, sizeof(mac), "AA:BB:CC:DD") != EOK) {
        return;
    }
    int len = strlen(mac);
    EXPECT_TRUE(SetMacFilter(unsigned char*)mac, len, pid) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifihotspotIfaceTest, DelMacFilterTest, TestSize.Level1)
{
    int pid = NETWORK_ID;
    char *mac = nullptr;
    if (strcpy_s(mac, sizeof(mac), "AA:BB:CC:DD") != EOK) {
        return;
    }
    int len = strlen(mac);
    EXPECT_TRUE(DelMacFilter(unsigned char*)mac, len, pid) == WIFI_IDL_OPT_OK);
}


HWTEST_F(IWifihotspotIfaceTest, DisassociateStaTest, TestSize.Level1)
{
    int pid = NETWORK_ID;
    char *mac = nullptr;
    if (strcpy_s(mac, sizeof(mac), "AA:BB:CC:DD") != EOK) {
        return;
    }
    int len = strlen(mac);
    EXPECT_TRUE(DisassociateSta(unsigned char*)mac, len, pid) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifihotspotIfaceTest, GetValidFrequenciesForBandTest, TestSize.Level1)
{
    int pid = NETWORK_ID;
    int32_t band = BAND_2GHZ;
    int *frequencies = nullptr;
    int *size = &LENTH;
    EXPECT_TRUE(GetValidFrequenciesForBand(band, frequencies, size, pid) == WIFI_IDL_OPT_FAILED);
}

HWTEST_F(IWifihotspotIfaceTest, SetCountryCodeTest, TestSize.Level1)
{
    int pid = NETWORK_ID;
    char *code = nullptr;
    if (strcpy_s(code, sizeof(code), "AA:BB:CC:DD") != EOK) {
        return;
    }
    EXPECT_TRUE(SetCountryCode(code, pid) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifihotspotIfaceTest, RegisterAsscociatedEventTest, TestSize.Level1)
{
    int pid = NETWORK_ID;
    IWifiApEventCallback callback;
    RegisterAsscociatedEvent(callback, pid);
    EXPECT_TRUE(RegisterAsscociatedEvent(callback, pid) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifihotspotIfaceTest, WpaSetPowerModelTest, TestSize.Level1)
{
    int pid = NETWORK_ID;
    int mode = MODE1;
    EXPECT_TRUE(WpaSetPowerModel(mode, pid) == WIFI_IDL_OPT_FAILED);
}

HWTEST_F(IWifihotspotIfaceTest, WpaGetPowerModelTest, TestSize.Level1)
{
    int pid = NETWORK_ID;
    int *mode = &MODE1;
    EXPECT_TRUE(WpaGetPowerModel(mode, pid) == WIFI_IDL_OPT_FAILED);
}
}
}
