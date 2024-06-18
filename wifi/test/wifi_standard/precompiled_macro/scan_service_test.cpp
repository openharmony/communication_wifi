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
#include "scan_service.h"
#include <gtest/gtest.h>
#include "mock_wifi_manager.h"
#include "mock_wifi_settings.h"
#include "mock_scan_state_machine.h"
#include "mock_wifi_scan_interface.h"
 
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
 
class ScanServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pScanService = std::make_unique<ScanService>();
        pScanService->pScanStateMachine = new MockScanStateMachine();
        pScanService->RegisterScanCallbacks(WifiManager::GetInstance().GetScanCallback());
    }
    virtual void TearDown()
    {
        pScanService.reset();
    }
 
public:
    std::unique_ptr<ScanService> pScanService;
 
    void SystemScanByIntervalSuccess()
    {
        int expScanCount = 1;
        int interval = 1;
        const int constTest = 2;
        int count = constTest;
        EXPECT_EQ(pScanService->SystemScanByInterval(expScanCount, interval, count), true);
    }
};
 
HWTEST_F(ScanServiceTest, SystemScanByIntervalSuccess, TestSize.Level1)
{
    SystemScanByIntervalSuccess();
}
 
}  // namespace Wifi
}  // namespace OHOS