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
#include <gtest/gtest.h>

#include "wifi_p2p_upnp_service_info.h"

using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
    static std::string g_errLog = "wifitest";
class WifiP2pUpnpServiceInfoTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}

public:
    void WarpCreate()
    {
        std::string uuid;
        std::string device;
        std::vector<std::string> services;
        services.push_back(std::string("TestUpnpService"));
        std::string svrName("TestSvrName");
        WifiP2pUpnpServiceInfo::Create(uuid, device, services, svrName);
    }
    void WarpCreateSupQuery()
    {
        std::string uuid;
        std::string data;
        std::string device;
    	std::string svrName;
        std::vector<std::string> services;
    	WifiP2pUpnpServiceInfo::Create(uuid, device, services, svrName).BuildWpaQuery(uuid, data, svrName);
    }
};

HWTEST_F(WifiP2pUpnpServiceInfoTest, Create, TestSize.Level1)
{
    WarpCreate();
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

HWTEST_F(WifiP2pUpnpServiceInfoTest, BuildWpaQuery, TestSize.Level1)
{
    WarpCreateSupQuery();
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

HWTEST_F(WifiP2pUpnpServiceInfoTest, CheckSuccess, TestSize.Level1)
{
    const std::string uuid = "550e8400-e29b-41d4-a716-446655440000";
    std::vector<std::string> services;
    services.push_back("urn:schemas-upnp-org:service:ContentDirectory:1");
    EXPECT_EQ(WifiP2pUpnpServiceInfo::Check(uuid, "urn:schemas-upnp-org:device:MediaServer:1",
        services, "upnp-svc"), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pUpnpServiceInfoTest, CheckInvalidUuid, TestSize.Level1)
{
    std::vector<std::string> services;
    EXPECT_EQ(WifiP2pUpnpServiceInfo::Check("invalid-uuid", "device", services, "svc"),
        ErrCode::WIFI_OPT_INVALID_PARAM);
    EXPECT_EQ(WifiP2pUpnpServiceInfo::Check("550e8400e29b41d4a716446655440000", "device", services, "svc"),
        ErrCode::WIFI_OPT_INVALID_PARAM);
}

HWTEST_F(WifiP2pUpnpServiceInfoTest, CheckInvalidLength, TestSize.Level1)
{
    const std::string uuid = "550e8400-e29b-41d4-a716-446655440000";
    std::vector<std::string> services;
    std::string overDevice(WifiP2pUpnpServiceInfo::MAX_UPNP_DEVICE_LEN + 1, 'd');
    std::string overName(WifiP2pUpnpServiceInfo::MAX_UPNP_SERVICE_NAME_LEN + 1, 'n');
    EXPECT_EQ(WifiP2pUpnpServiceInfo::Check(uuid, overDevice, services, "svc"),
        ErrCode::WIFI_OPT_INVALID_PARAM);
    EXPECT_EQ(WifiP2pUpnpServiceInfo::Check(uuid, "device", services, overName),
        ErrCode::WIFI_OPT_INVALID_PARAM);
}
}  // namespace Wifi
}  // namespace OHOS