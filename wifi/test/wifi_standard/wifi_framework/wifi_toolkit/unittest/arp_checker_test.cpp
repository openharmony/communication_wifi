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
        pArpChecker.reset(new ArpChecker());
    }
    virtual void TearDown()
    {
        pArpChecker.reset();
    }

public:
    std::unique_ptr<ArpChecker> pArpChecker;
};

HWTEST_F(ArpCheckerTest, ArpChecker_Success, TestSize.Level1)
{
    std::string ifname;
    std::string hwAddr = "0000000000";
    std::string ipAddr = "network";
    pArpChecker->ArpChecker(&ifname, &hwAddr, &ipAddr);
}

HWTEST_F(ArpCheckerTest, ArpChecker_FAIL, TestSize.Level1)
{
    std::string ifname = "";
    std::string hwAddr;
    std::string ipAddr;
    pArpChecker->ArpChecker();
}

HWTEST_F(ArpCheckerTest, ArpChecker_FAIL, TestSize.Level1)
{
    pArpChecker->~ArpChecker();
}

HWTEST_F(ArpCheckerTest, DoArp_FAIL, TestSize.Level1)
{
    int timeoutMillis = 0;
    std::string targetIp = "192.168.3.66";
    bool isFillSenderIp = false;
    EXPECT_TRUE(pArpChecker->DoArp(&timeoutMillis, &targetIp, &isFillSenderIp) == false);
}

HWTEST_F(ArpCheckerTest, DoArp_Success, TestSize.Level1)
{
    int timeoutMillis = 1;
    std::string targetIp = "192.168.3.66";
    bool isFillSenderIp = true;
    EXPECT_TRUE(pArpChecker->DoArp(&timeoutMillis, &targetIp, &isFillSenderIp) == true);
}

}  // namespace Wifi
}  // namespace OHOS
