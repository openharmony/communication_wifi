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
#include "arp_checker.h"
#include "dns_checker.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
class ArpCheckerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        std::string ifname = "network";
        std::string hwAddr = "192.168.3.6";
        std::string gatewayAddr = "192.168.3.1";
        std::string ipAddr = "10.3.1";
        pArpChecker = std::make_unique<ArpChecker>();
        pDnsChecker = std::make_unique<DnsChecker>();
        pArpChecker->Start(ifname, hwAddr, ipAddr, gatewayAddr);
    }
    virtual void TearDown()
    {
        pArpChecker.reset();
        pDnsChecker.reset();
    }

public:
    std::unique_ptr<ArpChecker> pArpChecker;
    std::unique_ptr<DnsChecker> pDnsChecker;
};

HWTEST_F(ArpCheckerTest, DoArp_FAIL, TestSize.Level1)
{
    int timeoutMillis = 0;
    std::string targetIp = "192.168.3.66";
    bool isFillSenderIp = false;
    EXPECT_TRUE(pArpChecker->DoArpCheck(timeoutMillis, isFillSenderIp) == false);
}

HWTEST_F(ArpCheckerTest, Start_FAIL, TestSize.Level1)
{
    std::string priDns = "192.168.3.66";
    std::string secondDns = "socket";
    pDnsChecker->Start(priDns, secondDns);
}

HWTEST_F(ArpCheckerTest, Stop_FAIL, TestSize.Level1)
{
    pDnsChecker->Stop();
}

HWTEST_F(ArpCheckerTest, formatHostAdress_Test, TestSize.Level1)
{
    char hostAddress[] = "192.168.3.66";
    char host[] = "socket";
    pDnsChecker->formatHostAdress(hostAddress, host);
}

HWTEST_F(ArpCheckerTest, DoDnsCheck_Test, TestSize.Level1)
{
    std::string hostAddress = "192.168.3.66";
    pDnsChecker->DoDnsCheck(hostAddress, 1);
}

HWTEST_F(ArpCheckerTest, recvDnsData_Test, TestSize.Level1)
{
    char hostAddress[] = "192.168.3.66";
    pDnsChecker->recvDnsData(hostAddress, 1, 0);
}

HWTEST_F(ArpCheckerTest, checkDnsValid_Test, TestSize.Level1)
{
    std::string hostAddress = "192.168.3.66";
    std::string secondDns = "socket";
    pDnsChecker->checkDnsValid(hostAddress, secondDns, 0);
}

HWTEST_F(ArpCheckerTest, recvDnsData01_Test, TestSize.Level1)
{
    char hostAddress[] = "192.168.3.66";
    pDnsChecker->dnsSocket = -1;
    pDnsChecker->recvDnsData(hostAddress, 1, 0);
}

HWTEST_F(ArpCheckerTest, DoArp_FAIL2, TestSize.Level1)
{
    int timeoutMillis = 0;
    std::string targetIp = "192.168.3.66";
    bool isFillSenderIp = false;
    EXPECT_TRUE(pArpChecker->DoArpCheck(timeoutMillis, isFillSenderIp) == false);
}

HWTEST_F(ArpCheckerTest, checkDnsValid_FAIL2, TestSize.Level1)
{
    std::string hostAddress = "192.168.3.66";
    std::string secondDns = "socket";
    pDnsChecker->socketCreated = true;
    pDnsChecker->checkDnsValid(hostAddress, "", 0);
    pDnsChecker->checkDnsValid(hostAddress, secondDns, 0);
}

HWTEST_F(ArpCheckerTest, formatHostAdress_FAIL2, TestSize.Level1)
{
    char hostAddress[] = "192.168.3.66";
    char host[] = "socket";
    pDnsChecker->socketCreated = true;
    pDnsChecker->formatHostAdress(hostAddress, nullptr);
    pDnsChecker->formatHostAdress(nullptr, host);
}
}  // namespace Wifi
}  // namespace OHOS
