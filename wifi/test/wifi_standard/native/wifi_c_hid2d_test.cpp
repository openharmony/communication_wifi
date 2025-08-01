/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "securec.h"
#include "kits/c/wifi_hid2d.h"
#include "kits/c/wifi_device.h"
#include "wifi_logger.h"

using ::testing::_;
using ::testing::Return;
using ::testing::ext::TestSize;
DEFINE_WIFILOG_LABEL("WifiCHid2dStubTest");

namespace OHOS {
namespace Wifi {

constexpr unsigned int IP[IPV4_ARRAY_LEN] = {192, 168, 2, 5};

class WifiHid2dTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiHid2dTest, Hid2dRequestGcIpTests, TestSize.Level1)
{
    unsigned char gcMac[MAC_LEN];
    unsigned int ipAddr[IPV4_ARRAY_LEN];
    Hid2dRequestGcIp(gcMac, ipAddr);
    EXPECT_EQ(Hid2dRequestGcIp(gcMac, ipAddr), -128);
}

HWTEST_F(WifiHid2dTest, Hid2dSharedlinkIncreaseTests, TestSize.Level1)
{
    Hid2dSharedlinkIncrease();
    EXPECT_EQ(Hid2dSharedlinkIncrease(), -128);
}

HWTEST_F(WifiHid2dTest, Hid2dSharedlinkDecreaseTests, TestSize.Level1)
{
    Hid2dSharedlinkDecrease();
    EXPECT_EQ(Hid2dSharedlinkDecrease(), -128);
}

HWTEST_F(WifiHid2dTest, Hid2dCreateGroupTests, TestSize.Level1)
{
    int frequency = 0;
    FreqType type = FreqType::FREQUENCY_160M;
    Hid2dCreateGroup(frequency, type);
    EXPECT_NE(Hid2dCreateGroup(frequency, type), 0);
}

HWTEST_F(WifiHid2dTest, Hid2dRemoveGcGroupTests, TestSize.Level1)
{
    char gcIfName[IF_NAME_LEN];
    Hid2dRemoveGcGroup(gcIfName);
    EXPECT_EQ(Hid2dRemoveGcGroup(gcIfName), -128);
}

HWTEST_F(WifiHid2dTest, Hid2dConnectTests, TestSize.Level1)
{
    WIFI_LOGI("Hid2dConnectTests enter");
    Hid2dConnectConfig config;
    Hid2dConnect(&config);
    EXPECT_NE(Hid2dConnect(&config), 0);
}

HWTEST_F(WifiHid2dTest, Hid2dConfigIPAddrTests, TestSize.Level1)
{
    char ifName[IF_NAME_LEN];
    IpAddrInfo ipInfo;
    memcpy_s(ipInfo.ip, sizeof(IP), IP, sizeof(IP));
    Hid2dConfigIPAddr(ifName, &ipInfo);
    EXPECT_EQ(Hid2dConfigIPAddr(ifName, &ipInfo), -128);
}

HWTEST_F(WifiHid2dTest, Hid2dReleaseIPAddrTests, TestSize.Level1)
{
    char ifName[IF_NAME_LEN];
    Hid2dReleaseIPAddr(ifName);
    EXPECT_EQ(Hid2dReleaseIPAddr(ifName), -128);
}

HWTEST_F(WifiHid2dTest, Hid2dGetRecommendChannelTests, TestSize.Level1)
{
    WIFI_LOGI("Hid2dGetRecommendChannelTests enter");
    RecommendChannelRequest request;
    RecommendChannelResponse response;
    Hid2dGetRecommendChannel(&request, &response);
    EXPECT_EQ(Hid2dGetRecommendChannel(&request, &response), -128);
}

HWTEST_F(WifiHid2dTest, Hid2dGetChannelListFor5GTests, TestSize.Level1)
{
    int *chanList = nullptr;
    int len = 0;
    Hid2dGetChannelListFor5G(chanList, len);
    EXPECT_NE(Hid2dGetChannelListFor5G(chanList, len), 0);
}

HWTEST_F(WifiHid2dTest, Hid2dGetSelfWifiCfgInfoTests, TestSize.Level1)
{
    WIFI_LOGI("Hid2dGetSelfWifiCfgInfoTests enter");
    SelfCfgType cfgType = SelfCfgType::TYPE_OF_GET_SELF_CONFIG;
    char cfgData[CFG_DATA_MAX_BYTES];
    int getDatValidLen = 0;
    Hid2dGetSelfWifiCfgInfo(cfgType, cfgData, &getDatValidLen);
    EXPECT_EQ(Hid2dGetSelfWifiCfgInfo(cfgType, cfgData, &getDatValidLen), -128);
}

HWTEST_F(WifiHid2dTest, Hid2dSetPeerWifiCfgInfoTests, TestSize.Level1)
{
    PeerCfgType cfgType = PeerCfgType::TYPE_OF_SET_PEER_CONFIG;
    char cfgData[CFG_DATA_MAX_BYTES] = "test";
    int setDataValidLen = 1;
    Hid2dSetPeerWifiCfgInfo(cfgType, cfgData, setDataValidLen);
    EXPECT_EQ(Hid2dSetPeerWifiCfgInfo(cfgType, cfgData, setDataValidLen), -128);
}

HWTEST_F(WifiHid2dTest, Hid2dIsWideBandwidthSupportedTests, TestSize.Level1)
{
    EXPECT_EQ(Hid2dIsWideBandwidthSupported(), 1);
}

HWTEST_F(WifiHid2dTest, Hid2dSetUpperSceneTests, TestSize.Level1)
{
    char ifName[IF_NAME_LEN];
    Hid2dUpperScene scene;
    scene.scene = 1;
    scene.fps = 1;
    scene.bw = 1;
    Hid2dSetUpperScene(ifName, &scene);
    EXPECT_NE(Hid2dSetUpperScene(ifName, &scene), 0);
}
}
}
