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
#include "i_wifi_chip.h"
#include "i_wifi_hotspot_iface.h"
#include "i_wifi_iface.h"
#include "mock_wifi_public.h"
#include "i_wifi_sta_iface.h"
#include "i_wifi_p2p_iface.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
constexpr int LENTH = 5;
constexpr int LENMAC = 17;
const std::string IFACENAME = "wlan0";

class IWifiIfaceTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}

    static void onStaJoinOrLeaveTest(const CStationInfo *info, int id)
    {
    }
};

HWTEST_F(IWifiIfaceTest, GetNameTest, TestSize.Level1)
{
    char ifname[LENTH] = "test";
    int32_t size = LENTH;
    GetName(ifname, size);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(GetName(ifname, size) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, GetTypeTest, TestSize.Level1)
{
    int32_t type = 1;
    GetType(&type);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(GetType(&type) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, StartSoftApTest, TestSize.Level1)
{
    int id = 0;
    char ifName[IFACENAME.size() + 1];
    IFACENAME.copy(ifName, IFACENAME.size() + 1);
    ifName[IFACENAME.size()] = '\0';
    StartSoftAp(id, ifName);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(StartSoftAp(id, ifName) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, StopSoftApTest, TestSize.Level1)
{
    int id = 0;
    StopSoftAp(id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(StopSoftAp(id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, SetHostapdConfigTest, TestSize.Level1)
{
    HostapdConfig config;
    int id = 0;
    SetHostapdConfig(&config, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(SetHostapdConfig(&config, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, GetStaInfosTest, TestSize.Level1)
{
    char infos[] = "GetStaInfosTest";
    int32_t size = 1;
    int id = 0;
    GetStaInfos(infos, &size, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(GetStaInfos(infos, &size, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, SetMacFilterTest, TestSize.Level1)
{
    unsigned char mac[] = "00:00:00:00:00:00";
    int lenMac = LENMAC;
    int id = 0;
    SetMacFilter(mac, lenMac, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(SetMacFilter(mac, lenMac, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, DelMacFilterTest, TestSize.Level1)
{
    unsigned char mac[] = "00:00:00:00:00:00";
    int lenMac = LENMAC;
    int id = 0;
    DelMacFilter(mac, lenMac, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(DelMacFilter(mac, lenMac, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, DisassociateStaTest, TestSize.Level1)
{
    unsigned char mac[] = "00:00:00:00:00:00";
    int lenMac = LENMAC;
    int id = 0;
    DisassociateSta(mac, lenMac, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(DisassociateSta(mac, lenMac, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, GetValidFrequenciesForBandTest, TestSize.Level1)
{
    int32_t band = 1;
    int frequencies = 1;
    int32_t size = 1;
    int id = 0;
    GetValidFrequenciesForBand(band, &frequencies, &size, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(GetValidFrequenciesForBand(band, &frequencies, &size, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, SetCountryCodeTest, TestSize.Level1)
{
    const char code = 0;
    int id = 0;
    SetCountryCode(&code, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(SetCountryCode(&code, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, RegisterAsscociatedEventTest, TestSize.Level1)
{
    IWifiApEventCallback callback;
    int id = 0;
    RegisterAsscociatedEvent(callback, id);
    callback.onStaJoinOrLeave = onStaJoinOrLeaveTest;
    RegisterAsscociatedEvent(callback, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(RegisterAsscociatedEvent(callback, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, WpaSetPowerModelTest, TestSize.Level1)
{
    const int model = 1;
    int id = 0;
    WpaSetPowerModel(model, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(WpaSetPowerModel(model, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, WpaGetPowerModelTest, TestSize.Level1)
{
    int model = 1;
    int id = 0;
    WpaGetPowerModel(&model, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(WpaGetPowerModel(&model, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, IsChipSupportCsaTest, TestSize.Level1)
{
    bool isSupport = false;
    IsChipSupportCsa(&isSupport);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_FALSE(IsChipSupportCsa(&isSupport));
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, IsChipSupportRadarDetectTest, TestSize.Level1)
{
    bool isSupport = false;
    IsChipSupportRadarDetect(&isSupport);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_FALSE(IsChipSupportRadarDetect(&isSupport));
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, IsChipSupportDfsChannelTest, TestSize.Level1)
{
    bool isSupport = false;
    IsChipSupportDfsChannel(&isSupport);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_FALSE(IsChipSupportDfsChannel(&isSupport));
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, IsChipSupportIndoorChannelTest, TestSize.Level1)
{
    bool isSupport = false;
    IsChipSupportIndoorChannel(&isSupport);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_FALSE(IsChipSupportIndoorChannel(&isSupport));
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, GetChipId, TestSize.Level1)
{
    int32_t id = 0;
    GetChipId(&id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(GetChipId(&id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, CreateIface, TestSize.Level1)
{
    int32_t id = 0;
    IWifiIface iface;
    CreateIface(id, &iface);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(CreateIface(id, &iface) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, GetIface, TestSize.Level1)
{
    char ifname[] = "wifitest";
    IWifiIface iface;
    GetIface(ifname, &iface);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(GetIface(ifname, &iface) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, GetIfaceNames, TestSize.Level1)
{
    int32_t type = 0;
    char ifname[] = "wifitest";
    int32_t size = 1;
    GetIfaceNames(type, ifname, size);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(GetIfaceNames(type, ifname, size) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, RemoveIface, TestSize.Level1)
{
    char ifname[] = "wifitest";
    RemoveIface(ifname);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(RemoveIface(ifname) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, ConfigComboModes, TestSize.Level1)
{
    int32_t mode = 0;
    ConfigComboModes(mode);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(ConfigComboModes(mode) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, GetComboModes, TestSize.Level1)
{
    int32_t id = 0;
    GetComboModes(&id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(GetComboModes(&id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, RequestFirmwareDebugDump, TestSize.Level1)
{
    unsigned char ifname[] = "wifitest";
    int32_t id = 0;
    RequestFirmwareDebugDump(ifname, &id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(RequestFirmwareDebugDump(ifname, &id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, GetStaCapabilitiesTest, TestSize.Level1)
{
    int32_t capabilities = 1;
    GetStaCapabilities(&capabilities);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(GetStaCapabilities(&capabilities) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, RunCmdTest, TestSize.Level1)
{
    int32_t cmdId = LENTH;
    int32_t bufSize = LENMAC;
    char ifname[LENTH] = "test";
    unsigned char mac[] = "00:00:00:00:00";
    RunCmd(ifname, cmdId, mac, bufSize);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(RunCmd(ifname, cmdId, mac, bufSize) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(IWifiIfaceTest, P2pConnectTest, TestSize.Level1)
{
    P2pConnectInfo info;
    P2pConnect(&info);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_CALL(MockWifiPublic::GetInstance(), RemoteCall(_)).WillOnce(Return(-1));
    EXPECT_TRUE(P2pConnect(&info) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}
}  // namespace Wifi
}  // namespace OHOS