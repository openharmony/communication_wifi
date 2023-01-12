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
#include <gmock/gmock.h>
#include <cstddef>
#include <cstdint>
#include "securec.h"
#include "i_wifi_chip.h"

using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {

constexpr int NETWORK_ID = 15;
constexpr int PROVDISC = 2;
constexpr int TIME = 2;
constexpr int MODE = 2;

class IWifiChipTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(IWifiChipTest, GetChipIdSuccess, TestSize.Level1)
{
    int32_t *id = &NETWORK_ID;
    EXPECT_TRUE(GetChipId(id) == WIFI_IDL_OPT_FAILED);
}

HWTEST_F(IWifiChipTest, CreateIfaceSuccess, TestSize.Level1)
{
    int32_t type = PROVDISC;
    IWifiIface iface;
    iface.type = PROVDISC;
    iface.index = MODE;
    if (strcpy_s(iface.name, sizeof(iface.name), "networkId") != EOK) {
        return;
    }
    if (strcpy_s(iface.macAddr, sizeof(iface.macAddr), "00:00:00:00") != EOK) {
        return;
    }
    EXPECT_TRUE(CreateIface(type, &iface) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiChipTest, GetIfaceSuccess, TestSize.Level1)
{
    char *ifname = nullptr;
    IWifiIface iface;
    iface.type = PROVDISC;
    iface.index = MODE;
    if (strcpy_s(iface.name, sizeof(iface.name), "networkId") != EOK) {
        return;
    }
    if (strcpy_s(iface.macAddr, sizeof(iface.macAddr), "00:00:00:00") != EOK) {
        return;
    }

    if (strcpy_s(ifname, sizeof(ifname), "networkId") != EOK) {
        return;
    }
    EXPECT_TRUE(GetIface(ifname, &iface) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiChipTest, GetIfaceNamesSucess, TestSize.Level1)
{
    int32_t type = PROVDISC;
    char *ifaces = nullptr;
    int32_t size = MODE;
    if (strcpy_s(ifaces, sizeof(ifaces), "00:00:00:00") != EOK) {
        return;
    }
    EXPECT_TRUE(GetIfaceNames(type, ifaces, size) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiChipTest, RemoveIfaceSuccess, TestSize.Level1)
{
    char *ifaces = nullptr;
    if (strcpy_s(ifaces, sizeof(ifaces), "networkId") != EOK) {
        return;
    }
    EXPECT_TRUE(RemoveIface(ifaces) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiChipTest, GetSupportedComboModesSuccess, TestSize.Level1)
{
    int32_t *modes = &MODE;
    int32_t *size = &NETWORK_ID;
    EXPECT_TRUE(GetSupportedComboModes(modes, size) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiChipTest, ConfigComboModesSuccess, TestSize.Level1)
{
    int32_t networkId = NETWORK_ID;
    EXPECT_TRUE(ConfigComboModes(networkId) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiChipTest, GetComboModesSuccess, TestSize.Level1)
{
    int32_t *id = &TIME;
    EXPECT_TRUE(GetComboModes(id) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiChipTest, P2pSetPowerSaveSuccess, TestSize.Level1)
{
    IWifiChipEventCallback callback;
    EXPECT_TRUE(RegisterEventCallback(callback) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiChipTest, P2pSetWfdEnableSuccess, TestSize.Level1)
{
    char *bytes = nullptr;
    int32_t *size = &TIME;
    if (strcpy_s(bytes, sizeof(bytes), "networkId") != EOK) {
        return;
    }
    EXPECT_TRUE(RequestFirmwareDebugDump(enable) == WIFI_IDL_OPT_OK);
}
} // namespace Wifi
} // namespace OHOS

