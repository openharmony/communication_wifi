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
#include "raw_socket.h"

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
        pRawSocket.reset();
    }

public:
    std::unique_ptr<RawSocket> pRawSocket;
};

HWTEST_F(RawSocketTest, CreateSocket_Fail1, TestSize.Level1)
{
    char *iface = nullptr;
    uint16_t protocol = 0;
    EXPECT_TRUE(pRawSocket->CreateSocket(iface, protocol) == -1);
}

HWTEST_F(RawSocketTest, CreateSocket_Fail2, TestSize.Level1)
{
    char iface[] = "config";
    uint16_t protocol = 0;
    EXPECT_TRUE(pRawSocket->CreateSocket(iface, protocol) == -1);
}

HWTEST_F(RawSocketTest, Send_Fail1, TestSize.Level1)
{
    uint8_t *buff = nullptr;
    int count = 10;
    uint8_t *destHwaddr = nullptr;
    EXPECT_TRUE(pRawSocket->Send(buff, count, destHwaddr) == -1);
}

HWTEST_F(RawSocketTest, Send_Fail2, TestSize.Level1)
{
    uint8_t *buff = &NUMBLE;
    int count = 10;
    uint8_t *destHwaddr = &SIZE;
    pRawSocket->Close();
    EXPECT_TRUE(pRawSocket->Send(buff, count, destHwaddr) == -1);
}

HWTEST_F(RawSocketTest, Recv_Fail, TestSize.Level1)
{
    uint8_t *buff = &NUMBLE;
    int count = 10;
    int timeoutMillis = 10;
    EXPECT_TRUE(pRawSocket->Recv(buff, count, timeoutMillis) == 0);
}

HWTEST_F(RawSocketTest, Close_Success, TestSize.Level1)
{
    EXPECT_TRUE(pRawSocket->Close() == -1);
}

HWTEST_F(RawSocketTest, Send_Fail3, TestSize.Level1)
{
    uint8_t *buff = &NUMBLE;
    int count = 10;
    uint8_t *destHwaddr = nullptr;
    EXPECT_TRUE(pRawSocket->Send(buff, count, destHwaddr) == -1);
}

HWTEST_F(RawSocketTest, Send_Fail4, TestSize.Level1)
{
    uint8_t *buff = &NUMBLE;
    int count = 10;
    uint8_t *destHwaddr = nullptr;
    EXPECT_TRUE(pRawSocket->Send(buff, count, destHwaddr) == -1);
}

HWTEST_F(RawSocketTest, SetNonBlock_Test, TestSize.Level1)
{
    EXPECT_FALSE(pRawSocket->SetNonBlock(1));
}
}  // namespace Wifi
}  // namespace OHOS

