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
#include "sta_monitor.h"
#include <gtest/gtest.h>
#include "sta_state_machine.h"
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"
#include "mock_wifi_sta_hal_interface.h"
#include <string>

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

class StaMonitorTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pStaMonitor = std::make_unique<StaMonitor>();
        pStaMonitor->pStaStateMachine = new StaStateMachine();
        InitStaMonitorSuccess();
    }
    virtual void TearDown()
    {
        pStaMonitor.reset();
    }

public:
    std::unique_ptr<StaMonitor> pStaMonitor;
    void InitStaMonitorSuccess();
};

void StaMonitorTest::InitStaMonitorSuccess()
{
    MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
    EXPECT_TRUE(pStaMonitor->InitStaMonitor() == WIFI_OPT_SUCCESS);
}

HWTEST_F(StaMonitorTest, OnConnectChangedCallBackTest01, TestSize.Level1)
{
    int status = HAL_WPA_CB_ASSOCIATING;
    int networkId = 1;
    std::string bssid = "01:23:45:67:89:AB";
    pStaMonitor->OnConnectChangedCallBack(status, networkId, bssid);
    status = HAL_WPA_CB_ASSOCIATED;
    pStaMonitor->OnConnectChangedCallBack(status, networkId, bssid);
    status = HAL_WPA_CB_ASSOCIATING;
    pStaMonitor->OnConnectChangedCallBack(status, networkId, bssid);
    EXPECT_NE(pStaMonitor->m_instId, TEN);
}

HWTEST_F(StaMonitorTest, OnWpaStaNotifyCallBackTest01, TestSize.Level1)
{
    std::string notifyParam = "02:23:45:67:89:AB";
    pStaMonitor->OnWpaStaNotifyCallBack(notifyParam);
    EXPECT_NE(pStaMonitor->m_instId, TEN);
}

HWTEST_F(StaMonitorTest, OnWpaAuthTimeOutCallBackTest01, TestSize.Level1)
{
    pStaMonitor->OnWpaAuthTimeOutCallBack();
    EXPECT_NE(pStaMonitor->m_instId, TEN);
}

HWTEST_F(StaMonitorTest, OnWpaEapSimAuthCallBackTest01, TestSize.Level1)
{
    std::string notifyParam = "01:23:45:67:89:AB";
    pStaMonitor->pStaStateMachine = nullptr;
    pStaMonitor->OnWpaEapSimAuthCallBack(notifyParam);
    EXPECT_NE(pStaMonitor->m_instId, TEN);
}

HWTEST_F(StaMonitorTest, OnWpaEapSimAuthCallBackTest02, TestSize.Level1)
{
    std::string notifyParam = "01:23:45:67:89:AB";
    pStaMonitor->OnWpaEapSimAuthCallBack(notifyParam);
    EXPECT_NE(pStaMonitor->m_instId, TEN);
}

} // WIFI
} // OHOS