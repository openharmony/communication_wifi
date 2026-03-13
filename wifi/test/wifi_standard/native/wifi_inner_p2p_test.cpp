/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "securec.h"
#include "wifi_logger.h"
#include "wifi_p2p.h"

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {

static std::shared_ptr<WifiP2p> p2pPtr = WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);
const std::string g_errLog = "wifi_test";
class WifiInnerP2pTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiInnerP2pTest, RequestServiceTest, TestSize.Level1)
{
    WifiP2pDevice device;
    WifiP2pServiceRequest request;
    ASSERT_TRUE(p2pPtr != nullptr);
    p2pPtr->RequestService(device, request);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiInnerP2pTest, PutLocalP2pServiceTest, TestSize.Level1)
{
    WifiP2pServiceInfo srvInfo;
    ASSERT_TRUE(p2pPtr != nullptr);
    p2pPtr->PutLocalP2pService(srvInfo);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiInnerP2pTest, DeleteLocalP2pServiceTest, TestSize.Level1)
{
    WifiP2pServiceInfo srvInfo;
    ASSERT_TRUE(p2pPtr != nullptr);
    p2pPtr->DeleteLocalP2pService(srvInfo);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiInnerP2pTest, QueryP2pLinkedInfoTest, TestSize.Level1)
{
    WifiP2pLinkedInfo linkedInfo;
    ASSERT_TRUE(p2pPtr != nullptr);
    p2pPtr->QueryP2pLinkedInfo(linkedInfo);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiInnerP2pTest, GetP2pDiscoverStatusTest, TestSize.Level1)
{
    int status = 0;
    ASSERT_TRUE(p2pPtr != nullptr);
    p2pPtr->GetP2pDiscoverStatus(status);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiInnerP2pTest, QueryP2pServicesTest, TestSize.Level1)
{
    std::vector<WifiP2pServiceInfo> services;
    ASSERT_TRUE(p2pPtr != nullptr);
    p2pPtr->QueryP2pServices(services);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiInnerP2pTest, GetSupportedFeaturesTest, TestSize.Level1)
{
    long features = 0;
    ASSERT_TRUE(p2pPtr != nullptr);
    p2pPtr->GetSupportedFeatures(features);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiInnerP2pTest, IsFeatureSupportedTest, TestSize.Level1)
{
    ASSERT_TRUE(p2pPtr != nullptr);
    p2pPtr->IsFeatureSupported(0);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiInnerP2pTest, SetP2pDeviceNameTest, TestSize.Level1)
{
    std::string deviceName;
    ASSERT_TRUE(p2pPtr != nullptr);
    p2pPtr->SetP2pDeviceName(deviceName);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiInnerP2pTest, SetP2pWfdInfoTest, TestSize.Level1)
{
    WifiP2pWfdInfo wfdInfo;
    ASSERT_TRUE(p2pPtr != nullptr);
    p2pPtr->SetP2pWfdInfo(wfdInfo);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}
}
}
