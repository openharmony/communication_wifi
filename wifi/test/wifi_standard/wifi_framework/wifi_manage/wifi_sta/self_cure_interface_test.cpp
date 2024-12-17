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
#include "self_cure_interface.h"
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

constexpr int TEN = 10;

class SelfCureInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pSelfCureInterface = std::make_unique<SelfCureInterface>();
        if (pSelfCureInterface != nullptr) {
            pSelfCureInterface->InitSelfCureService();
        }
    }

    virtual void TearDown()
    {
        pSelfCureInterface.reset();
    }

    std::unique_ptr<SelfCureInterface> pSelfCureInterface;

    void InitSelfCureServiceTest()
    {
        pSelfCureInterface->InitSelfCureService();
    }

    void InitCallbackTest()
    {
        pSelfCureInterface->InitCallback();
    }

    void GetStaCallbackTest()
    {
        StaServiceCallback callback;
        EXPECT_EQ(pSelfCureInterface->GetStaCallback().callbackModuleName,
            pSelfCureInterface->mStaCallback.callbackModuleName);
    }

    void DealStaConnChangedTest()
    {
        OperateResState state = OperateResState::CONNECT_AP_CONNECTED;
        WifiLinkedInfo info;
        int instId = 0;
        pSelfCureInterface->DealStaConnChanged(state, info, instId);
        pSelfCureInterface->pSelfCureService = nullptr;
        pSelfCureInterface->DealStaConnChanged(state, info, instId);
    }

    void DealRssiLevelChangedTest()
    {
        int rssi = MIN_VAL_LEVEL_4;
        int instId = 0;
        pSelfCureInterface->DealRssiLevelChanged(rssi, instId);
        pSelfCureInterface->pSelfCureService = nullptr;
        pSelfCureInterface->DealRssiLevelChanged(rssi, instId);
    }
};

HWTEST_F(SelfCureInterfaceTest, InitSelfCureServiceTest, TestSize.Level1)
{
    InitSelfCureServiceTest();
}

HWTEST_F(SelfCureInterfaceTest, InitCallbackTest, TestSize.Level1)
{
    InitCallbackTest();
}

HWTEST_F(SelfCureInterfaceTest, GetStaCallbackTest, TestSize.Level1)
{
    GetStaCallbackTest();
}

HWTEST_F(SelfCureInterfaceTest, DealStaConnChangedTest, TestSize.Level1)
{
    DealStaConnChangedTest();
}

HWTEST_F(SelfCureInterfaceTest, DealRssiLevelChangedTest, TestSize.Level1)
{
    DealRssiLevelChangedTest();
}

HWTEST_F(SelfCureInterfaceTest, NotifyInternetFailureDetectedTest, TestSize.Level1)
{
    int forceNoHttpCheck = 0;
    pSelfCureInterface->NotifyInternetFailureDetected(forceNoHttpCheck);
    pSelfCureInterface->pSelfCureService = nullptr;
    pSelfCureInterface->NotifyInternetFailureDetected(forceNoHttpCheck);
}

HWTEST_F(SelfCureInterfaceTest, IsSelfCureOnGoingTest, TestSize.Level1)
{
    EXPECT_EQ(pSelfCureInterface->IsSelfCureOnGoing(), false);
}

} // namespace Wifi
} // namespace OHOS