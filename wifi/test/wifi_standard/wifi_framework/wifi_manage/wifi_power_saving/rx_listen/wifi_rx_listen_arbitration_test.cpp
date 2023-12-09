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

#include "wifi_rx_listen_arbitration.h"
#include "mock_wifi_cmd_client.h"
#include "mock_wifi_app_parser.h"
#include <gtest/gtest.h>
#include "app_mgr_interface.h"
#include "app_mgr_constants.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {

class RxListenArbitrationTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pRxListenArbitration = std::make_unique<RxListenArbitration>();
    }
    virtual void TearDown()
    {
        pRxListenArbitration.reset();
    }
public:
    std::unique_ptr<RxListenArbitration> pRxListenArbitration;
}

HWTEST_F(RxListenArbitrationTest, OnForegroundAppChanged_DisableRxListen, TestSize.Level1)
{
    WIFI_LOGI("OnForegroundAppChanged_DisableRxListen enter!");
    AppExecFwk::AppStateData appState = AppExecFwk::AppStateData();
    appState.bundleName = "com.huawei.gameApp";
    appState.state = static_cast<int>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    appState.isFocused = true;
    pRxListenArbitration->m_arbitrationCond = 0x00;
    pRxListenArbitration->m_isRxListenOn = true;
    EXPECT_CALL(WifiPowerCmdClient::GetInstance(), SendCmdToDriver(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(AppParser::GetInstance(), GetInstance(appState.bundleName)).WillOnce(Return(true));
    pRxListenArbitration->OnForegroundAppChanged(appState);
    EXPECT_FALSE(pRxListenArbitration->m_isRxListenOn);
}

HWTEST_F(RxListenArbitrationTest, OnForegroundAppChanged_EnableRxListen, TestSize.Level1)
{
    WIFI_LOGI("OnForegroundAppChanged_EnableRxListen enter!");
    AppExecFwk::AppStateData appState = AppExecFwk::AppStateData();
    appState.bundleName = "com.huawei.otherApp";
    appState.state = static_cast<int>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    appState.isFocused = true;
    pRxListenArbitration->m_arbitrationCond = 0x01;
    pRxListenArbitration->m_isRxListenOn = false;
    EXPECT_CALL(WifiPowerCmdClient::GetInstance(), SendCmdToDriver(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(AppParser::GetInstance(), GetInstance(appState.bundleName)).WillOnce(Return(false));
    pRxListenArbitration->OnForegroundAppChanged(appState);
    EXPECT_TRUE(pRxListenArbitration->m_isRxListenOn);
}
} // namespace Wifi
} // namespace OHOS