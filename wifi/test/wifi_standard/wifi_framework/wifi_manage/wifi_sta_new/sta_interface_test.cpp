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
#include "sta_interface.h"
#include <mutex>
#include <condition_variable>
#include <gtest/gtest.h>
#include <sys/time.h>
#include "mock_sta_service.h"
#include "mock_wifi_settings.h"
#include "mock_wifi_sta_hal_interface.h"

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

class StaInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() override
    {
        pStaInterface.reset(new StaInterface(0));
        pStaInterface->pStaService = new MockWifiStaService();
        pMockStaService = (MockWifiStaService *)pStaInterface->pStaService;
    }
    virtual void TearDown() override
    {
        pStaInterface.reset();
    }
    
public:
    std::unique_ptr<StaInterface> pStaInterface;
    MockWifiStaService *pMockStaService = nullptr;
};

HWTEST_F(StaInterfaceTest, StartConnectToBssidTest01, TestSize.Level1)
{
    int networkId = 0;
    std::string bssid = "01:23:45:67:89:ab";
    EXPECT_CALL(*pMockStaService, StartConnectToBssid(_, _, _)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
    EXPECT_TRUE(pStaInterface->StartConnectToBssid(networkId, bssid, NETWORK_SELECTED_BY_USER) == WIFI_OPT_SUCCESS);
}

HWTEST_F(StaInterfaceTest, StartConnectToUserSelectNetworkTest01, TestSize.Level1)
{
    int networkId = 0;
    std::string bssid = "01:23:45:67:89:ab";
    EXPECT_CALL(*pMockStaService, StartConnectToUserSelectNetwork(_, _)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
    EXPECT_TRUE(pStaInterface->StartConnectToUserSelectNetwork(networkId, bssid) == WIFI_OPT_SUCCESS);
}

HWTEST_F(StaInterfaceTest, RegisterStaServiceCallbackTest01, TestSize.Level1)
{
    StaServiceCallback callbacks;
    callbacks.callbackModuleName = "test";
    pStaInterface->m_staCallback.push_back(callbacks);
    EXPECT_TRUE(pStaInterface->RegisterStaServiceCallback(callbacks) == WIFI_OPT_SUCCESS);
}

HWTEST_F(StaInterfaceTest, SetPowerModeTest01, TestSize.Level1)
{
    bool mode = true;
    EXPECT_CALL(*pMockStaService, SetPowerMode(_)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
    EXPECT_TRUE(pStaInterface->SetPowerMode(mode) == WIFI_OPT_SUCCESS);
}

HWTEST_F(StaInterfaceTest, OnSystemAbilityChangedTest01, TestSize.Level1)
{
    int systemAbilityid = 0;
    bool add = true;
    EXPECT_CALL(*pMockStaService, OnSystemAbilityChanged(_, _)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
    EXPECT_TRUE(pStaInterface->OnSystemAbilityChanged(systemAbilityid, add) == WIFI_OPT_SUCCESS);
}

HWTEST_F(StaInterfaceTest, StartPortalCertificationTest01, TestSize.Level1)
{
    EXPECT_TRUE(pStaInterface->StartPortalCertification() == WIFI_OPT_SUCCESS);
}

HWTEST_F(StaInterfaceTest, StartWifiDetectionTest01, TestSize.Level1)
{
    EXPECT_TRUE(pStaInterface->StartWifiDetection() == WIFI_OPT_SUCCESS);
}

HWTEST_F(StaInterfaceTest, HandleForegroundAppChangedActionTest01, TestSize.Level1)
{
    AppExecFwk::AppStateData appStateData;
    appStateData.uid = 1;
    EXPECT_TRUE(pStaInterface->HandleForegroundAppChangedAction(appStateData) == WIFI_OPT_SUCCESS);
}

HWTEST_F(StaInterfaceTest, InitStaServiceLockedTest01, TestSize.Level1)
{
    EXPECT_CALL(*pMockStaService, InitStaService(_)).WillRepeatedly(Return(WIFI_OPT_FAILED));
    EXPECT_FALSE(pStaInterface->InitStaServiceLocked() == false);
}

} // WIFI
} // OHOS