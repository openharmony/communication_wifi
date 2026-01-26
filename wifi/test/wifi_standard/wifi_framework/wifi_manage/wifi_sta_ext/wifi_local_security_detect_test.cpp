/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "wifi_local_security_detect_test.h"
#include "wifi_hisysevent.h"
#include <gtest/gtest.h>

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace Wifi {

HWTEST_F(WifiLocalSecurityDetectTest, DealStaConnChangedNetworkEnabledTest, TestSize.Level1)
{
    OperateResState state = OperateResState::CONNECT_NETWORK_ENABLED;
    WifiLinkedInfo info;
    info.networkId = 1;
    int instId = 1;
    wifiLocalSecurityDetect_->DealStaConnChanged(state, info, instId);
    EXPECT_TRUE(wifiLocalSecurityDetect_->canAccessInternetThroughWifi_);
}

HWTEST_F(WifiLocalSecurityDetectTest, DealStaConnChangedOtherStateTest, TestSize.Level1)
{
    OperateResState state = OperateResState::CONNECT_NETWORK_DISABLED;
    WifiLinkedInfo info;
    info.networkId = 1;
    int instId = 1;
    wifiLocalSecurityDetect_->DealStaConnChanged(state, info, instId);
    EXPECT_FALSE(wifiLocalSecurityDetect_->canAccessInternetThroughWifi_);
}

HWTEST_F(WifiLocalSecurityDetectTest, SetApInfoTest, TestSize.Level1)
{
    WifiLinkedInfo info;
    info.ssid = "TestNetwork";
    info.bssid = "00:11:22:33:44:55";
    info.frequency = 2437;
    info.band = 1;
    info.rssi = -50;

    wifiLocalSecurityDetect_->SetApInfo(info);
    EXPECT_EQ(wifiLocalSecurityDetect_->apInfo_.ssid, "TestNetwork");
    EXPECT_EQ(wifiLocalSecurityDetect_->apInfo_.bssid, "00:11:22:33:44:55");
    EXPECT_EQ(wifiLocalSecurityDetect_->apInfo_.frequency, 2437);
    EXPECT_EQ(wifiLocalSecurityDetect_->apInfo_.band, 1);
    EXPECT_EQ(wifiLocalSecurityDetect_->apInfo_.rssi, -50);
}

HWTEST_F(WifiLocalSecurityDetectTest, ResetApInfoTest, TestSize.Level1)
{
    WifiLinkedInfo info;
    info.ssid = "TestNetwork";
    info.bssid = "00:11:22:33:44:55";
    info.frequency = 2437;
    info.band = 1;
    info.rssi = -50;

    wifiLocalSecurityDetect_->ResetApInfo();
    EXPECT_EQ(wifiLocalSecurityDetect_->apInfo_.ssid, "");
    EXPECT_EQ(wifiLocalSecurityDetect_->apInfo_.bssid, "");
    EXPECT_EQ(wifiLocalSecurityDetect_->apInfo_.frequency, 0);
    EXPECT_EQ(wifiLocalSecurityDetect_->apInfo_.band, -1);
    EXPECT_EQ(wifiLocalSecurityDetect_->apInfo_.rssi, -1);
    EXPECT_EQ(wifiLocalSecurityDetect_->apInfo_.cloudRiskType, static_cast<int>(WifiCloudRiskType::UNKNOWN));
}

HWTEST_F(WifiLocalSecurityDetectTest, HandleWifiDisconnectedTest, TestSize.Level1)
{
    WifiLinkedInfo info;
    info.networkId = 1;

    wifiLocalSecurityDetect_->HandleWifiDisconnected(info);
    EXPECT_EQ(wifiLocalSecurityDetect_->currentUseNetworkId_, -1);
}

HWTEST_F(WifiLocalSecurityDetectTest, OnDnsResultReportNotAccessWifiTest, TestSize.Level1)
{
    wifiLocalSecurityDetect_->canAccessInternetThroughWifi_ = false;
    std::list<NetDnsResultReport> dnsResultList;
    NetDnsResultReport report;
    report.host_ = "example.com";
    NetDnsResultAddrInfo addrInfo;
    addrInfo.addr_ = "192.168.1.100";
    report.addrlist_.push_back(addrInfo);
    dnsResultList.push_back(report);

    int32_t result = wifiLocalSecurityDetect_->dnsResultCallback_->OnDnsResultReport(1, dnsResultList);
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiLocalSecurityDetectTest, CheckDomainInDnsCacheTest, TestSize.Level1)
{
    wifiLocalSecurityDetect_->lastAddRecordTime_ = -1;
    wifiLocalSecurityDetect_->AddRecordToDnsCache("test.com", IpType::PUBLIC);

    auto it = wifiLocalSecurityDetect_->CheckDomainInDnsCache("test.com");
    EXPECT_NE(it, wifiLocalSecurityDetect_->domainHistoryCache_.end());

    auto it2 = wifiLocalSecurityDetect_->CheckDomainInDnsCache("nonexistent.com");
    EXPECT_EQ(it2, wifiLocalSecurityDetect_->domainHistoryCache_.end());
}

HWTEST_F(WifiLocalSecurityDetectTest, CheckPublicToPrivateTransitionPublicToPrivateTest, TestSize.Level1)
{
    wifiLocalSecurityDetect_->lastAddRecordTime_ = -1;
    wifiLocalSecurityDetect_->AddRecordToDnsCache("test1.com", IpType::PUBLIC);

    bool result = wifiLocalSecurityDetect_->CheckPublicToPrivateTransition("test1.com", IpType::PRIVATE);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiLocalSecurityDetectTest, CheckPublicToPrivateTransitionPublicToPublicTest, TestSize.Level1)
{
    wifiLocalSecurityDetect_->lastAddRecordTime_ = -1;
    wifiLocalSecurityDetect_->AddRecordToDnsCache("test2.com", IpType::PUBLIC);

    bool result = wifiLocalSecurityDetect_->CheckPublicToPrivateTransition("test2.com", IpType::PUBLIC);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiLocalSecurityDetectTest, CheckPublicToPrivateTransitionPrivateToPrivateTest, TestSize.Level1)
{
    wifiLocalSecurityDetect_->lastAddRecordTime_ = -1;
    wifiLocalSecurityDetect_->AddRecordToDnsCache("test3.com", IpType::PRIVATE);

    bool result = wifiLocalSecurityDetect_->CheckPublicToPrivateTransition("test3.com", IpType::PRIVATE);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiLocalSecurityDetectTest, CheckPublicToPrivateTransitionPrivateToPublicTest, TestSize.Level1)
{
    wifiLocalSecurityDetect_->lastAddRecordTime_ = -1;
    wifiLocalSecurityDetect_->AddRecordToDnsCache("test4.com", IpType::PRIVATE);

    bool result = wifiLocalSecurityDetect_->CheckPublicToPrivateTransition("test4.com", IpType::PUBLIC);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiLocalSecurityDetectTest, CheckPublicToPrivateTransitionNonexistentTest, TestSize.Level1)
{
    bool result = wifiLocalSecurityDetect_->CheckPublicToPrivateTransition("test123.com", IpType::PRIVATE);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiLocalSecurityDetectTest, UpdateDnsCacheAddTest, TestSize.Level1)
{
    RecordDeque records;
    wifiLocalSecurityDetect_->UpdateDnsCache(records, "test1.com", IpType::PRIVATE);
    EXPECT_FALSE(records.empty());
    EXPECT_EQ(records.size(), 1);
    EXPECT_EQ(records.front().domain, "test1.com");
    EXPECT_EQ(records.front().ipType, IpType::PRIVATE);
}

HWTEST_F(WifiLocalSecurityDetectTest, UpdateDnsCacheUpdateTest, TestSize.Level1)
{
    RecordDeque records;
    wifiLocalSecurityDetect_->UpdateDnsCache(records, "test1.com", IpType::PUBLIC);
    EXPECT_EQ(records.size(), 1);
    wifiLocalSecurityDetect_->UpdateDnsCache(records, "test1.com", IpType::PRIVATE);
    wifiLocalSecurityDetect_->UpdateDnsCache(records, "test2.com", IpType::PRIVATE);
    wifiLocalSecurityDetect_->UpdateDnsCache(records, "test3.com", IpType::PUBLIC);
    EXPECT_EQ(records.size(), 3);
    EXPECT_EQ(records.front().domain, "test1.com");
    EXPECT_EQ(records.front().ipType, IpType::PRIVATE);
    wifiLocalSecurityDetect_->UpdateDnsCache(records, "test1.com", IpType::PUBLIC);
    EXPECT_EQ(records.front().domain, "test2.com");
    EXPECT_EQ(records.back().domain, "test1.com");
    EXPECT_EQ(records.back().ipType, IpType::PUBLIC);
}

HWTEST_F(WifiLocalSecurityDetectTest, IsPrivateIPV4PrivateTest, TestSize.Level1)
{
    EXPECT_TRUE(wifiLocalSecurityDetect_->IsPrivateIp("192.168.1.1"));
    EXPECT_TRUE(wifiLocalSecurityDetect_->IsPrivateIp("10.0.0.1"));
    EXPECT_TRUE(wifiLocalSecurityDetect_->IsPrivateIp("172.16.5.1"));
}

HWTEST_F(WifiLocalSecurityDetectTest, IsPrivateIPV4PublicTest, TestSize.Level1)
{
    EXPECT_FALSE(wifiLocalSecurityDetect_->IsPrivateIp("8.8.8.8"));
    EXPECT_FALSE(wifiLocalSecurityDetect_->IsPrivateIp("114.114.114.114"));
}

HWTEST_F(WifiLocalSecurityDetectTest, IsPrivateIPV6Test, TestSize.Level1)
{
    EXPECT_TRUE(wifiLocalSecurityDetect_->IsPrivateIp("fc00::1"));
    EXPECT_FALSE(wifiLocalSecurityDetect_->IsPrivateIp("2001:db8::1"));
}

HWTEST_F(WifiLocalSecurityDetectTest, IsPrivateIPInvalidTest, TestSize.Level1)
{
    EXPECT_FALSE(wifiLocalSecurityDetect_->IsPrivateIp("invalid"));
    EXPECT_FALSE(wifiLocalSecurityDetect_->IsPrivateIp(""));
}

HWTEST_F(WifiLocalSecurityDetectTest, HasPrivateIpContainPrivateTest, TestSize.Level1)
{
    std::list<NetDnsResultAddrInfo> addrList;
    NetDnsResultAddrInfo addr1;
    addr1.addr_ = "192.168.1.100";
    addrList.push_back(addr1);

    bool result = wifiLocalSecurityDetect_->HasPrivateIp(addrList);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiLocalSecurityDetectTest, HasPrivateIpNoPrivateTest, TestSize.Level1)
{
    std::list<NetDnsResultAddrInfo> addrList;
    NetDnsResultAddrInfo addr1;
    addr1.addr_ = "8.8.8.8";
    addrList.push_back(addr1);

    bool result = wifiLocalSecurityDetect_->HasPrivateIp(addrList);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiLocalSecurityDetectTest, HasPrivateIpEmptyTest, TestSize.Level1)
{
    std::list<NetDnsResultAddrInfo> addrList;

    bool result = wifiLocalSecurityDetect_->HasPrivateIp(addrList);
    EXPECT_FALSE(result);
}

}  // namespace Wifi
}  // namespace OHOS