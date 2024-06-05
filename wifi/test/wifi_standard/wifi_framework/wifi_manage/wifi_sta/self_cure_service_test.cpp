/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "self_cure_service.h"
#include "wifi_logger.h"
#include "self_cure_common.h"
#include "wifi_internal_msg.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class SelfCureServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pSelfCureService = std::make_unique<SelfCureService>();
    }

    virtual void TearDown()
    {
        pSelfCureService.reset();
    }

    std::unique_ptr<SelfCureService> pSelfCureService;

    void InitSelfCureServiceTest()
    {
        pSelfCureService->InitSelfCureService();
    }

    void RegisterSelfCureServiceCallbackTest()
    {
        std::vector<SelfCureServiceCallback> callbacks;
        pSelfCureService->RegisterSelfCureServiceCallback(callbacks);
    }

    void HandleRssiLevelChangedTest()
    {
        int rssi = MIN_VAL_LEVEL_4;
        pSelfCureService->HandleRssiLevelChanged(rssi);
    }

    void HandleP2pConnChangedTest()
    {
        WifiP2pLinkedInfo info;
        pSelfCureService->HandleP2pConnChanged(info);
    }

    void HandleStaConnChangedTest()
    {
        OperateResState state = OperateResState::CONNECT_AP_CONNECTED;
        WifiLinkedInfo info;
        pSelfCureService->HandleStaConnChanged(state, info);
    }

    void HandleStaOpenResTest()
    {
        OperateResState state = OperateResState::OPEN_WIFI_SUCCEED;
        pSelfCureService->HandleStaOpenRes(state);
        state = OperateResState::CONNECT_AP_CONNECTED;
        pSelfCureService->HandleStaOpenRes(state);
    }
};

HWTEST_F(SelfCureServiceTest, InitSelfCureServiceTest, TestSize.Level1)
{
    InitSelfCureServiceTest();
}

HWTEST_F(SelfCureServiceTest, RegisterSelfCureServiceCallbackTest, TestSize.Level1)
{
    RegisterSelfCureServiceCallbackTest();
}

HWTEST_F(SelfCureServiceTest, HandleRssiLevelChangedTest, TestSize.Level1)
{
    HandleRssiLevelChangedTest();
}

HWTEST_F(SelfCureServiceTest, HandleP2pConnChangedTest, TestSize.Level1)
{
    HandleP2pConnChangedTest();
}

HWTEST_F(SelfCureServiceTest, HandleStaConnChangedTest, TestSize.Level1)
{
    HandleStaConnChangedTest();
}

HWTEST_F(SelfCureServiceTest, HandleStaOpenResTest, TestSize.Level1)
{
    HandleStaOpenResTest();
}

} // namespace Wifi
} // namespace OHOS