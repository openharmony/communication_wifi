/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "mock_wifi_manager.h"
#include "mock_wifi_settings.h"
#include "mock_wifi_sta_hal_interface.h"
#include "mock_scan_service.h"
#include "scan_state_machine.h"

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <chrono>

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

class ScanStateMachineTest2 : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetSupportHwPnoFlag()).Times(AtLeast(0));
        pScanStateMachine = std::make_unique<ScanStateMachine>();
        pScanStateMachine->InitScanStateMachine();
        pScanService = std::make_unique<MockScanService>();
        pScanStateMachine->EnrollScanStatusListener(
            std::bind(&MockScanService::HandleScanStatusReport, pScanService.get(), std::placeholders::_1));
    }
    void TearDown() override
    {
        pScanStateMachine.reset();
        pScanService.reset();
    }

    std::unique_ptr<MockScanService> pScanService;
    std::unique_ptr<ScanStateMachine> pScanStateMachine;

public:
    void InitExeMsgSuccess0()
    {
        pScanStateMachine->initState->ExecuteStateMsg(nullptr);
    }

    void HardwareReadyExeMsgSuccess0()
    {
        pScanStateMachine->hardwareReadyState->ExecuteStateMsg(nullptr);
    }

    void CommonScanExeMsgSuccess0()
    {
        pScanStateMachine->commonScanState->ExecuteStateMsg(nullptr);
    }

    void CommonScanUnworkedExeMsgSuccess0()
    {
        pScanStateMachine->commonScanUnworkedState->ExecuteStateMsg(nullptr);
    }

    void CommonScanningExeMsgSuccess0()
    {
        pScanStateMachine->commonScanningState->ExecuteStateMsg(nullptr);
    }
}

HWTEST_F(ScanStateMachineTest2, InitExeMsgSuccess0, TestSize.Level1)
{
    InitExeMsgSuccess0();
}

HWTEST_F(ScanStateMachineTest2, HardwareReadyExeMsgSuccess0, TestSize.Level1)
{
    HardwareReadyExeMsgSuccess0();
}

HWTEST_F(ScanStateMachineTest2, CommonScanExeMsgSuccess0, TestSize.Level1)
{
    CommonScanExeMsgSuccess0();
}

HWTEST_F(ScanStateMachineTest2, CommonScanUnworkedExeMsgSuccess0, TestSize.Level1)
{
    CommonScanUnworkedExeMsgSuccess0();
}

HWTEST_F(ScanStateMachineTest2, CommonScanningExeMsgSuccess0, TestSize.Level1)
{
    CommonScanningExeMsgSuccess0();
}
}
}