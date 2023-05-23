/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <vector>
#include "wifi_p2p_msg.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
constexpr int TIMES = 253;
constexpr unsigned char DATA = 0x12;
class WifiP2PMsgTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pWifiP2pWfdInfo = std::make_unique<WifiP2pWfdInfo>();
        pWifiP2pGroupInfo = std::make_unique<WifiP2pGroupInfo>();
        pWifiP2pServiceRequest = std::make_unique<WifiP2pServiceRequest>();
        pWifiP2pServiceResponse = std::make_unique<WifiP2pServiceResponse>();
    }
    virtual void TearDown()
    {
        pWifiP2pWfdInfo.reset();
        pWifiP2pGroupInfo.reset();
        pWifiP2pServiceRequest.reset();
        pWifiP2pServiceResponse.reset();
    }

public:
    std::unique_ptr<WifiP2pWfdInfo> pWifiP2pWfdInfo;
    std::unique_ptr<WifiP2pGroupInfo> pWifiP2pGroupInfo;
    std::unique_ptr<WifiP2pServiceRequest> pWifiP2pServiceRequest;
    std::unique_ptr<WifiP2pServiceResponse> pWifiP2pServiceResponse;
};

HWTEST_F(WifiP2PMsgTest, isSessionAvailableTest, TestSize.Level1)
{
    bool enabled = true;
    pWifiP2pWfdInfo->setSessionAvailable(enabled);
    enabled = false;
    pWifiP2pWfdInfo->setSessionAvailable(enabled);
    EXPECT_FALSE(pWifiP2pWfdInfo->isSessionAvailable());
}

HWTEST_F(WifiP2PMsgTest, AddClientDeviceTest, TestSize.Level1)
{
    WifiP2pDevice clientDevice;
    clientDevice.SetDeviceName("AddClientDeviceTest");
    pWifiP2pGroupInfo->AddClientDevice(clientDevice);
    pWifiP2pGroupInfo->AddClientDevice(clientDevice);
}

HWTEST_F(WifiP2PMsgTest, RemoveClientDeviceTest, TestSize.Level1)
{
    WifiP2pDevice clientDevice;
    clientDevice.SetDeviceName("RemoveClientDevice");
    pWifiP2pGroupInfo->AddClientDevice(clientDevice);
    WifiP2pDevice clientDevice1;
    clientDevice1.SetDeviceName("clientDevice1");
    pWifiP2pGroupInfo->RemoveClientDevice(clientDevice1);
}

HWTEST_F(WifiP2PMsgTest, IsContainsDeviceTest, TestSize.Level1)
{
    WifiP2pDevice clientDevice;
    clientDevice.SetDeviceAddress("00:11:22:33:44:55");
    pWifiP2pGroupInfo->AddClientDevice(clientDevice);
    WifiP2pDevice clientDevice2;
    clientDevice2.SetDeviceAddress("aa:aa:aa:aa:aa:aa");
    EXPECT_TRUE(pWifiP2pGroupInfo->IsContainsDevice(clientDevice2) == false);
    EXPECT_TRUE(pWifiP2pGroupInfo->IsContainsDevice(clientDevice) == true);
}

HWTEST_F(WifiP2PMsgTest, WifiP2pServiceRequestTest, TestSize.Level1)
{
    std::vector<unsigned char> query;
    std::vector<unsigned char> ret;
    pWifiP2pServiceRequest->SetQuery(query);
    ret = pWifiP2pServiceRequest->GetTlv();
    EXPECT_TRUE(count(ret.begin(), ret.end(), 0x00) != 0);
    query.push_back(0x00);
    query.push_back(0x00);
    pWifiP2pServiceRequest->SetQuery(query);
    pWifiP2pServiceRequest->GetTlv();
    for (int i = 0; i < TIMES; i++) {
        query.push_back(DATA);
    }
    pWifiP2pServiceRequest->SetQuery(query);
    pWifiP2pServiceRequest->GetTlv();
}

HWTEST_F(WifiP2PMsgTest, WifiP2pServiceResponseTest, TestSize.Level1)
{
    std::vector<unsigned char> data;
    pWifiP2pServiceResponse->SetData(data);
    pWifiP2pServiceResponse->GetTlv();
    data.push_back(0x00);
    data.push_back(0x00);
    pWifiP2pServiceResponse->SetData(data);
    pWifiP2pServiceResponse->GetTlv();
    for (int i = 0; i < TIMES; i++) {
        data.push_back(DATA);
    }
    pWifiP2pServiceResponse->SetData(data);
    pWifiP2pServiceResponse->GetTlv();
}
} // namespace Wifi
} // namespace OHOS
