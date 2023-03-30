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

#include "net_test.h"
#include <sys/socket.h>
#include "server.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
static constexpr int MAX_SIZE = 10240;

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
public:
    RpcServer server;
};

HWTEST_F(ServerTest, RunRpcLoopTest, TestSize.Level1)
{
    RpcServer *server;
    server->loop->stop = 0;
    server->nEvents = 1;
    server->events = 100;
    EXPECT_TRUE(RunRpcLoop(NULL) == -1);
    EXPECT_TRUE(RunRpcLoop(server) == 0);
}

HWTEST_F(ServerTest, CreateRpcServerTest, TestSize.Level1)
{
    char path[] = "./unix_sock_test.sock"
    EXPECT_TRUE(CreateRpcServer(NULL) == NULL);
    EXPECT_TRUE(CreateRpcServer(path) == 0);
}

HWTEST_F(ServerTest, RegisterCallbackTest, TestSize.Level1)
{
    RpcServer *server;
    server->loop->stop = 0;
    Context *context;
    EXPECT_TRUE(RegisterCallback(NULL, 10, NULL) == -1);
    EXPECT_TRUE(RegisterCallback(server, 10, NULL) == -1);
    EXPECT_TRUE(RegisterCallback(server, 10, context) == 0);
}

HWTEST_F(ServerTest, UnRegisterCallbackTest, TestSize.Level1)
{
    RpcServer *server;
    server->loop->stop = 0;
    Context *context;
    EXPECT_TRUE(UnRegisterCallback(NULL, 10, NULL) == -1);
    EXPECT_TRUE(UnRegisterCallback(server, 10, NULL) == -1);
    EXPECT_TRUE(UnRegisterCallback(server, 10, context) == 0);
}

HWTEST_F(ServerTest, EmitEventTest, TestSize.Level1)
{
    RpcServer *server;
    server->nEvents = 100;
    server->isHandlingMsg  = true;
    int event = 10;
    EXPECT_TRUE(EmitEvent(NULL, event) == NULL);
    EXPECT_TRUE(EmitEvent(server, event) == -1);
    EXPECT_TRUE(EmitEvent(server, event) == 0);
}

HWTEST_F(ServerTest, CreateRpcServerTest, TestSize.Level1)
{
    char path[] = "./unix_sock_test.sock"
    EXPECT_TRUE(CreateRpcServer(NULL) == NULL);
    EXPECT_TRUE(CreateRpcServer(path) == 0);
}
}  // namespace Wifi
}  // namespace OHOS
