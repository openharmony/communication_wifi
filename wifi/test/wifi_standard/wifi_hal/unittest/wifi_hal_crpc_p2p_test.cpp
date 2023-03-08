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
#include "securec.h"
#include "wifi_hal_crpc_p2p.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Eq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
const int CONTEXT_BUFFER = 1024;
class WifiHalCrpcP2pTets : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiHalCrpcP2pTets, RpcP2pSetWpsSecondaryDeviceTypeTest, TestSize.Level1)
{
    RpcServer svr, *server = nullptr;
    Context cont, *context = nullptr;
    EXPECT_EQ(RpcP2pSetWpsSecondaryDeviceType(server, &cont), -1);
    EXPECT_EQ(RpcP2pSetWpsSecondaryDeviceType(&svr, context), -1);
    context = CreateContext(CONTEXT_BUFFER);
    EXPECT_EQ(RpcP2pSetWpsSecondaryDeviceType(&svr, &cont), -1);
    RpcP2pSetWpsSecondaryDeviceType(&svr, context);
}

HWTEST_F(WifiHalCrpcP2pTets, RpcP2pGetPeerTest, TestSize.Level1)
{
    RpcServer svr, *server = nullptr;
    Context cont, *context = nullptr;
    EXPECT_EQ(RpcP2pGetPeer(server, &cont), -1);
    EXPECT_EQ(RpcP2pGetPeer(&svr, context), -1);
    context = CreateContext(CONTEXT_BUFFER);
    RpcP2pGetPeer(&svr, context);
}

HWTEST_F(WifiHalCrpcP2pTets, RpcP2pGetFrequenciesTest, TestSize.Level1)
{
    RpcServer svr, *server = nullptr;
    Context cont, *context = nullptr;
    EXPECT_EQ(RpcP2pGetFrequencies(server, &cont), -1);
    EXPECT_EQ(RpcP2pGetFrequencies(&svr, context), -1);
    context = CreateContext(CONTEXT_BUFFER);
    RpcP2pGetFrequencies(&svr, context);
}

HWTEST_F(WifiHalCrpcP2pTets, RpcP2pSetGroupConfigTest, TestSize.Level1)
{
    RpcServer svr, *server = nullptr;
    Context cont, *context = nullptr;
    EXPECT_EQ(RpcP2pSetGroupConfig(server, &cont), -1);
    EXPECT_EQ(RpcP2pSetGroupConfig(&svr, context), -1);
    context = CreateContext(CONTEXT_BUFFER);
    RpcP2pSetGroupConfig(&svr, context);
}

HWTEST_F(WifiHalCrpcP2pTets, RpcP2pGetGroupConfigTest, TestSize.Level1)
{
    RpcServer svr, *server = nullptr;
    Context cont, *context = nullptr;
    EXPECT_EQ(RpcP2pGetGroupConfig(server, &cont), -1);
    EXPECT_EQ(RpcP2pGetGroupConfig(&svr, context), -1);
    context = CreateContext(CONTEXT_BUFFER);
    RpcP2pGetGroupConfig(&svr, context);
}

HWTEST_F(WifiHalCrpcP2pTets, RpcP2pAddNetworkTest, TestSize.Level1)
{
    RpcServer svr, *server = nullptr;
    Context cont, *context = nullptr;
    EXPECT_EQ(RpcP2pAddNetwork(server, &cont), -1);
    EXPECT_EQ(RpcP2pAddNetwork(&svr, context), -1);
    context = CreateContext(CONTEXT_BUFFER);
    RpcP2pAddNetwork(&svr, context);
}

HWTEST_F(WifiHalCrpcP2pTets, RpcP2pHid2dConnectTest, TestSize.Level1)
{
    RpcServer svr, *server = nullptr;
    Context cont, *context = nullptr;
    EXPECT_EQ(RpcP2pHid2dConnect(server, &cont), -1);
    EXPECT_EQ(RpcP2pHid2dConnect(&svr, context), -1);
    context = CreateContext(CONTEXT_BUFFER);
    RpcP2pHid2dConnect(&svr, context);
}
} // namespace Wifi
} // namespace OHOS
