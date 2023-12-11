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

#include <sys/socket.h>
#include <gtest/gtest.h>
#include "server.h"
#include "evloop.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
static constexpr int MAX_SIZE = 10;
static constexpr int MASK = 0x02;
static constexpr int MASK_2 = 0x05;
static constexpr int MASK_3 = 0x06;
static constexpr int MASK_4 = 0x07;

class ServerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}
};

HWTEST_F(ServerTest, CreateEventLoopTest, TestSize.Level1)
{
    EventLoop *loop = nullptr;
    loop = CreateEventLoop(1);
    EXPECT_TRUE(loop->setSize == 1);
    EXPECT_TRUE(CreateEventLoop(-1) == nullptr);
}

HWTEST_F(ServerTest, AddFdEventFail, TestSize.Level1)
{
    int fd = 0;
    unsigned int addMas = 0x01;
    EventLoop loop;
    StopEventLoop(nullptr);
    StopEventLoop(&loop);
    EXPECT_TRUE(AddFdEvent(nullptr, fd, addMas) == -1);
}

HWTEST_F(ServerTest, AddFdEventFail2, TestSize.Level1)
{
    int fd = 0;
    unsigned int addMas = 0x01;
    EventLoop loop;
    loop.setSize = -1;
    EXPECT_TRUE(AddFdEvent(&loop, fd, addMas) == -1);
}

HWTEST_F(ServerTest, AddFdEventFail3, TestSize.Level1)
{
    int fd = 0;
    unsigned int addMas = 0x01;
    FdMask mask;
    mask.mask = 0x01;
    EventLoop loop;
    loop.setSize = 1;
    loop.fdMasks = &mask;
    EXPECT_TRUE(AddFdEvent(&loop, fd, addMas) == 0);
}

HWTEST_F(ServerTest, AddFdEventFail4, TestSize.Level1)
{
    int fd = 0;
    unsigned int addMas = MASK;
    FdMask mask;
    mask.mask = 0x01;
    EventLoop loop;
    loop.setSize = 1;
    loop.fdMasks = &mask;
    int ret = AddFdEvent(&loop, fd, addMas);
    EXPECT_TRUE(ret == -1 || ret == 0);
}

HWTEST_F(ServerTest, AddFdEventSuccess, TestSize.Level1)
{
    int fd = 1;
    unsigned int addMas = MASK;
    FdMask mask;
    mask.mask = MASK;
    EventLoop loop;
    loop.setSize = 2;
    loop.fdMasks = &mask;
    int ret = AddFdEvent(&loop, fd, addMas);
    EXPECT_TRUE(ret == -1 || ret == 0);
}

HWTEST_F(ServerTest, DelFdEventFail, TestSize.Level1)
{
    int fd = 0;
    unsigned int delMask = 0x01;
    EXPECT_TRUE(DelFdEvent(nullptr, fd, delMask) == -1);
}

HWTEST_F(ServerTest, DelFdEventFail2, TestSize.Level1)
{
    EventLoop loop;
    loop.setSize = -1;
    int fd = 0;
    unsigned int delMask = 0x01;
    EXPECT_TRUE(DelFdEvent(&loop, fd, delMask) == 0);
}

HWTEST_F(ServerTest, DelFdEventFail3, TestSize.Level1)
{
    int fd = 0;
    unsigned int delMask = 0x01;
    FdMask mask;
    mask.mask = 0x00;
    EventLoop loop;
    loop.setSize = 1;
    loop.fdMasks = &mask;
    EXPECT_TRUE(DelFdEvent(&loop, fd, delMask) == 0);
}

HWTEST_F(ServerTest, DelFdEventFail4, TestSize.Level1)
{
    int fd = 0;
    unsigned int delMask = MASK;
    FdMask mask;
    mask.mask = 0x01;
    EventLoop loop;
    loop.setSize = 1;
    loop.fdMasks = &mask;
    EXPECT_TRUE(DelFdEvent(&loop, fd, delMask) == 0);
}

HWTEST_F(ServerTest, DelFdEventFail5, TestSize.Level1)
{
    int fd = 0;
    unsigned int delMask = MASK_3;
    FdMask mask;
    mask.mask = MASK_4;
    EventLoop loop;
    loop.setSize = 1;
    loop.fdMasks = &mask;
    int ret = DelFdEvent(&loop, fd, delMask);
    EXPECT_TRUE(ret == -1 || ret == 0);
    DelFdEvent(&loop, fd, MASK_2);
}

HWTEST_F(ServerTest, CreateRpcServerTest, TestSize.Level1)
{
    RpcServer *server = nullptr;
    char path[] = "./unix_sock_test.sock";
    EXPECT_TRUE(CreateRpcServer(nullptr) == nullptr);
    server = CreateRpcServer(path);
}

HWTEST_F(ServerTest, RegisterCallbackTest, TestSize.Level1)
{
    EventLoop loop;
    loop.stop = 0;
    RpcServer server;
    server.loop = &loop;
    Context context;
    EXPECT_TRUE(RegisterCallback(nullptr, MAX_SIZE, nullptr) == -1);
    EXPECT_TRUE(RegisterCallback(&server, MAX_SIZE, nullptr) == -1);
    EXPECT_TRUE(RegisterCallback(&server, MAX_SIZE, &context) == 0);
}

HWTEST_F(ServerTest, UnRegisterCallbackTest, TestSize.Level1)
{
    EventLoop loop;
    loop.stop = 0;
    RpcServer server;
    server.loop = &loop;
    Context context;
    EXPECT_TRUE(UnRegisterCallback(nullptr, MAX_SIZE, nullptr) == -1);
    EXPECT_TRUE(UnRegisterCallback(&server, MAX_SIZE, nullptr) == -1);
    EXPECT_TRUE(UnRegisterCallback(&server, MAX_SIZE, &context) == 0);
}
}  // namespace Wifi
}  // namespace OHOS
