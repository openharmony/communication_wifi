/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#include "perf_5g_handover_service.h"
#include "network_status_history_manager.h"
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"

using ::testing::ext::TestSize;
namespace OHOS {
namespace Wifi {
const int FRE_2G = 2740;

class Perf5gHandoverServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        perf5gHandoverService_ = std::make_unique<Perf5gHandoverService>();
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.bssid = "f1:f2:f3:f4:f5:f6";
        wifiLinkedInfo.ssid = "testSsid";
        wifiLinkedInfo.frequency = FRE_2G;
        wifiLinkedInfo.isMloConnected = false;
        std::string beforeBssid = "";
        perf5gHandoverService_->OnConnected(wifiLinkedInfo);
    }

    virtual void TearDown()
    {
        perf5gHandoverService_.reset();
    }

    std::unique_ptr<Perf5gHandoverService> perf5gHandoverService_;
};

HWTEST_F(Perf5gHandoverServiceTest, OnConnectedTest1, TestSize.Level1)
{
    EXPECT_EQ(perf5gHandoverService_->connectedAp_ == nullptr, false);
}
HWTEST_F(Perf5gHandoverServiceTest, NetworkStatusChangedTest1, TestSize.Level1)
{
    perf5gHandoverService_->NetworkStatusChanged(NetworkStatus::HAS_INTERNET);
    EXPECT_EQ(perf5gHandoverService_->pWifiScanController_ == nullptr, false);
}
HWTEST_F(Perf5gHandoverServiceTest, ScanResultUpdatedTest1, TestSize.Level1)
{
    std::vector<InterScanInfo> scanInfos;
    InterScanInfo scanInfo;
    scanInfo.bssid = "f1:f2:f3:f4:f5:f6";
    scanInfo.rssi = -65;
    scanInfos.push_back(scanInfo);
    perf5gHandoverService_->ScanResultUpdated(scanInfos);
    EXPECT_EQ(perf5gHandoverService_->connectedAp_->apInfo.rssi, -65);
}
HWTEST_F(Perf5gHandoverServiceTest, HandleSignalInfoChangeTest1, TestSize.Level1)
{
    WifiSignalPollInfo wifiSignalPollInfo;
    wifiSignalPollInfo.signal = -65;
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageObj(wifiSignalPollInfo);
    perf5gHandoverService_->HandleSignalInfoChange(msg);
    EXPECT_EQ(perf5gHandoverService_->connectedAp_->apInfo.apConnectionInfo.linkQualitys_.size(), 1);
}
HWTEST_F(Perf5gHandoverServiceTest, QoeUpdateTest1, TestSize.Level1)
{
    NetworkLagInfo networkLagInfo;
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageObj(networkLagInfo);
    perf5gHandoverService_->QoeUpdate(msg);
    EXPECT_EQ(perf5gHandoverService_->connectedAp_->apInfo.apConnectionInfo.GetRttProductString() == "", false);
}
HWTEST_F(Perf5gHandoverServiceTest, OnDisconnectedTest1, TestSize.Level1)
{
    perf5gHandoverService_->OnDisconnected();
    EXPECT_EQ(perf5gHandoverService_->connectedAp_, nullptr);
}
HWTEST_F(Perf5gHandoverServiceTest, PrintRelationAps1, TestSize.Level1)
{
    RelationAp ap1;
    ap1.apInfo_.ssid = "test1";
    ap1.apInfo_.keyMgmt = "EAP";
    ap1.apInfo_.bssid = "11111";
    perf5gHandoverService_->relationAps_.push_back(ap1);
    perf5gHandoverService_->PrintRelationAps();
    EXPECT_EQ(perf5gHandoverService_->connectedAp_, nullptr);
}
}
}