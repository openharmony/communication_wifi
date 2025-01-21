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
#include "concrete_clientmode_manager.h"
#include "mock_concrete_manager_state_machine.h"

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
        static std::string g_errLog;
    void ConcreteClientModeManagerCallback(const LogType type, const LogLevel level, 
    const unsigned int domain, const char *tag, const char *msg)
    {
        g_errLog = msg;
    }
class ConcreteClientModeManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pConcreteModeManager = std::make_unique<ConcreteClientModeManager>(ConcreteManagerRole::ROLE_CLIENT_STA, 0);
        if (pConcreteModeManager != nullptr) {
            pConcreteModeManager->pConcreteMangerMachine = new MockConcreteMangerMachine();
        }
        pConcreteModeManager->GetMachine()->SendMessage(CONCRETE_CMD_START,
            static_cast<int>(ConcreteManagerRole::ROLE_CLIENT_STA), 0);
            LOG_SetCallback(ConcreteClientModeManagerCallback);
    }
    }

    virtual void TearDown()
    {
        if (pConcreteModeManager != nullptr) {
            pConcreteModeManager->GetMachine()->SendMessage(CONCRETE_CMD_STOP);
            pConcreteModeManager.reset();
        }
    }

    std::unique_ptr<ConcreteClientModeManager> pConcreteModeManager;

    void SetRoleTest()
    {
        if (pConcreteModeManager != nullptr) {
            pConcreteModeManager->SetRole(ConcreteManagerRole::ROLE_UNKNOW);
        }
    }

    void RegisterCallbackTest()
    {
        ConcreteModeCallback cb;
        if (pConcreteModeManager != nullptr) {
            EXPECT_TRUE(pConcreteModeManager->RegisterCallback(cb) == WIFI_OPT_SUCCESS);
        }
    }
};

HWTEST_F(ConcreteClientModeManagerTest, SetRoleTest, TestSize.Level1)
{
    SetRoleTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(ConcreteClientModeManagerTest, RegisterCallbackTest, TestSize.Level1)
{
    RegisterCallbackTest();
}
}
}