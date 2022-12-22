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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../../../interfaces/kits/c/wifi_hid2d.h"
#include "../../../interfaces/kits/c/wifi_device.h"

using ::testing::_;
using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
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
}

HWTEST_F(WifiHid2dTest, Hid2dSharedlinkIncreaseTests, TestSize.Level1)
{
    Hid2dSharedlinkIncrease();
}

HWTEST_F(WifiHid2dTest, Hid2dSharedlinkDecreaseTests, TestSize.Level1)
{
    Hid2dSharedlinkDecrease();
}

HWTEST_F(WifiHid2dTest, Hid2dCreateGroupTests, TestSize.Level1)
{
    int frequency = 0;
    FreqType type = FreqType::FREQUENCY_160M;
    Hid2dCreateGroup(frequency, type);
}

HWTEST_F(WifiHid2dTest, Hid2dRemoveGcGroupTests, TestSize.Level1)
{
    char gcIfName[IF_NAME_LEN];
    Hid2dRemoveGcGroup(gcIfName);
}

HWTEST_F(WifiHid2dTest, Hid2dConnectTests, TestSize.Level1)
{
    Hid2dConnectConfig *config;
    Hid2dConnect(config);
}

HWTEST_F(WifiHid2dTest, Hid2dConfigIPAddrTests, TestSize.Level1)
{
    char ifName[IF_NAME_LEN];
    IpAddrInfo* ipInfo;
    Hid2dConfigIPAddr(ifName, ipInfo);
}

HWTEST_F(WifiHid2dTest, Hid2dReleaseIPAddrTests, TestSize.Level1)
{
    char ifName[IF_NAME_LEN];
    Hid2dReleaseIPAddr(ifName);
}

HWTEST_F(WifiHid2dTest, Hid2dGetRecommendChannelTests, TestSize.Level1)
{
    RecommendChannelRequest *request = nullptr;
    RecommendChannelResponse *response = nullptr;
    Hid2dGetRecommendChannel(request, response);
}

HWTEST_F(WifiHid2dTest, Hid2dGetChannelListFor5GTests, TestSize.Level1)
{
    int *chanList = nullptr;
    int len = 0;
    Hid2dGetChannelListFor5G(chanList, len);
}

HWTEST_F(WifiHid2dTest, Hid2dGetSelfWifiCfgInfoTests, TestSize.Level1)
{
    SelfCfgType cfgType = SelfCfgType::TYPE_OF_GET_SELF_CONFIG;
    char cfgData[CFG_DATA_MAX_BYTES];
    int* getDatValidLen = nullptr;
    Hid2dGetSelfWifiCfgInfo(cfgType, cfgData, getDatValidLen);
}

HWTEST_F(WifiHid2dTest, Hid2dIsWideBandwidthSupportedTests, TestSize.Level1)
{
    Hid2dIsWideBandwidthSupported();
}

HWTEST_F(WifiHid2dTest, Hid2dSetUpperSceneTests, TestSize.Level1)
{
    char ifName[IF_NAME_LEN];
    Hid2dUpperScene *scene;
    Hid2dSetUpperScene(ifName, scene);
}
}
}
