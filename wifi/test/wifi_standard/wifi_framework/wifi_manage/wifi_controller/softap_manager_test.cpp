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
#include "softap_manager.h"
#include "mock_softap_manager_state_machine.h"

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
class SoftApManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pSoftApManager = std::make_unique<SoftApManager>(SoftApManager::Role::ROLE_SOFTAP, 0);
        if (pSoftApManager != nullptr) {
            pSoftApManager->pSoftapManagerMachine = new MockSoftapManagerStateMachine();
        }
        pSoftApManager->GetMachine()->SendMessage(SOFTAP_CMD_START,
            static_cast<int>(HotspotMode::SOFTAP), 0);
    }

    virtual void TearDown()
    {
        if (pSoftApManager != nullptr) {
            pSoftApManager->GetMachine()->SendMessage(SOFTAP_CMD_STOP);
            pSoftApManager.reset();
        }
    }

    std::unique_ptr<SoftApManager> pSoftApManager;

    void SetRoleTest()
    {
        if (pSoftApManager != nullptr) {
            pSoftApManager->SetRole(SoftApManager::Role::ROLE_UNKNOW);
            EXPECT_TRUE(pSoftApManager->GetRole() == SoftApManager::Role::ROLE_UNKNOW);
        }
    }

    void RegisterCallbackTest()
    {
        SoftApModeCallback cb;
        if (pSoftApManager != nullptr) {
            EXPECT_TRUE(pSoftApManager->RegisterCallback(cb) == WIFI_OPT_SUCCESS);
        }
    }
};

HWTEST_F(SoftApManagerTest, SetRoleTest, TestSize.Level1)
{
    SetRoleTest();
}

HWTEST_F(SoftApManagerTest, RegisterCallbackTest, TestSize.Level1)
{
    RegisterCallbackTest();
}
}
}