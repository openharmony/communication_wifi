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

uint8_t NUMBLE = 10;
uint8_t SIZE = 1;

class RawSocketTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pRawSocket.reset(new RawSocket());
    }
    virtual void TearDown()
    {
        pArpChecker.reset();
    }

public:
    std::unique_ptr<RawSocket> pRawSocket;
};

HWTEST_F(RawSocketTest, ArpChecker_Fail1, TestSize.Level1)
{
    char iface[] = "";
    uint16_t protocol;
    EXPECT_TRUE(pRawSocket->CreateSocket(iface, protocol) == -1);
}

HWTEST_F(RawSocketTest, ArpChecker_Fail2, TestSize.Level1)
{
    char iface[] = "config";
    uint16_t protocol;
    EXPECT_TRUE(pRawSocket->CreateSocket(iface, protocol) == -1);
}

HWTEST_F(RawSocketTest, ArpChecker_Fail3, TestSize.Level1)
{
    char iface[] = "ens33";
    uint16_t protocol = -1;
    EXPECT_TRUE(pRawSocket->CreateSocket(iface, protocol) == -1);
}

HWTEST_F(RawSocketTest, ArpChecker_Success, TestSize.Level1)
{
    char iface[] = "ens33";
    uint16_t protocol = 123456789;
    EXPECT_TRUE(pRawSocket->CreateSocket(iface, protocol) == -1);
}

HWTEST_F(RawSocketTest, ArpChecker_Success, TestSize.Level1)
{
	uint8_t *buff = nullptr;
    int count = 10;
    uint8_t *destHwaddr = nullptr;
    EXPECT_TRUE(pRawSocket->Send(buff, count, destHwaddr) == -1);
}

HWTEST_F(RawSocketTest, ArpChecker_Success, TestSize.Level1)
{
	uint8_t *buff = &NUMBLE;
    int count = 10;
    uint8_t *destHwaddr = &SIZE;
    EXPECT_TRUE(pRawSocket->Send(buff, count, destHwaddr) == -1);
}

HWTEST_F(RawSocketTest, ArpChecker_Success, TestSize.Level1)
{
	uint8_t *buff = &NUMBLE;
    int count = 10;
    uint8_t *destHwaddr = &SIZE;
    pRawSocket->ifaceIndex = 33;
    pRawSocket->socketFd_ = 5;
    EXPECT_TRUE(pRawSocket->Send(buff, count, destHwaddr) == 0);
}

HWTEST_F(RawSocketTest, ArpChecker_Success, TestSize.Level1)
{
	uint8_t *buff = &NUMBLE;
    int count = 10;
    int timeoutMillis = 10;
    pRawSocket->socketFd_ = -1;
    EXPECT_TRUE(pRawSocket->Recv(buff, count, destHwaddr) == -1);
}

HWTEST_F(RawSocketTest, ArpChecker_Success, TestSize.Level1)
{
	uint8_t *buff = nullptr;
    int count = 10;
    int timeoutMillis = 1;
    pRawSocket->socketFd_ = 0;
    EXPECT_TRUE(pRawSocket->Recv(buff, count, timeoutMillis) == -1);
}

HWTEST_F(RawSocketTest, ArpChecker_Success, TestSize.Level1)
{
	uint8_t *buff = &NUMBLE;
    int count = 1;
    int timeoutMillis = 50;
    pRawSocket->socketFd_ = 1;
    EXPECT_TRUE(pRawSocket->Recv(buff, count, timeoutMillis) == 1);
}

HWTEST_F(RawSocketTest, Close_Success, TestSize.Level1)
{
    pRawSocket->socketFd_ = 1;
    EXPECT_TRUE(pRawSocket->Close() == -1);
}
}  // namespace Wifi
}  // namespace OHOS

