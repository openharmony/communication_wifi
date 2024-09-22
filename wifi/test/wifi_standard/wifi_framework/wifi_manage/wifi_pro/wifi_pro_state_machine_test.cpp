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
#include <string>
#include <vector>
#include "define.h"
#include "wifi_log.h"
#include "wifi_errcode.h"
#include "state_machine.h"
#include "wifi_pro_common.h"
#include "iscan_service.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_pro_state_machine.h"
#include "wifi_service_manager.h"
#include "wifi_pro_utils.h"
#include "net_conn_client.h"
#include "mock_wifi_config_center.h"
 
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
 
class WifiProStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pWifiProStateMachine_ = std::make_unique<WifiProStateMachine>();
        pWifiProStateMachine_->Initialize();
    }
 
    virtual void TearDown()
    {
        if (pWifiProStateMachine_->pCurrWifiInfo_ != nullptr) {
            pWifiProStateMachine_->pCurrWifiInfo_.reset();
        }
        
        if (pWifiProStateMachine_->pCurrWifiDeviceConfig_ != nullptr) {
            pWifiProStateMachine_->pCurrWifiDeviceConfig_.reset();
        }
 
        pWifiProStateMachine_.reset();
    }
 
    std::unique_ptr<WifiProStateMachine> pWifiProStateMachine_;
};
 
HWTEST_F(WifiProStateMachineTest, HandleRssiChangedInLinkMonitorStateTest, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_RSSI_CHANGED);
    msg->SetParam1(-30);
    auto pWiFiLinkMonitorState = pWifiProStateMachine_->pWifiLinkMonitorState_;
    pWiFiLinkMonitorState->rssiLevel2Or3ScanedCounter_ = 1;
    pWiFiLinkMonitorState->HandleRssiChangedInMonitor(msg);
    EXPECT_EQ(pWiFiLinkMonitorState->rssiLevel2Or3ScanedCounter_, 1);
}
 
HWTEST_F(WifiProStateMachineTest, IsReachWifiScanThresholdTest01, TestSize.Level1)
{
    // wifi signal 4 bars
    int32_t signalLevel = SIG_LEVEL_4;
    int32_t ret = pWifiProStateMachine_->IsReachWifiScanThreshold(signalLevel);
    EXPECT_EQ(ret, false);
}
 
HWTEST_F(WifiProStateMachineTest, IsReachWifiScanThresholdTest02, TestSize.Level1)
{
    // The wifi signal is lower than 3 bars
    int32_t signalLevel = SIG_LEVEL_2;
    int32_t ret = pWifiProStateMachine_->IsReachWifiScanThreshold(signalLevel);
    EXPECT_EQ(ret, true);
}
 
HWTEST_F(WifiProStateMachineTest, IsReachWifiScanThresholdTest03, TestSize.Level1)
{
    // The wifi signal is equal to 3 bars, and there are switching records within 14 days
    int32_t signalLevel = SIG_LEVEL_3;
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.supplicantState = SupplicantState::INVALID;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
    pWifiProStateMachine_->pCurrWifiInfo_ = std::make_shared<WifiLinkedInfo>(wifiLinkedInfo);
 
    WifiDeviceConfig wifiDeviceConfig;
    wifiDeviceConfig.lastTrySwitchWifiTimestamp = WifiProUtils::GetCurrentTimeMs();
    pWifiProStateMachine_->pCurrWifiDeviceConfig_ = std::make_shared<WifiDeviceConfig>(wifiDeviceConfig);
    bool ret = pWifiProStateMachine_->IsReachWifiScanThreshold(signalLevel);
    EXPECT_EQ(ret, true);
}
 
HWTEST_F(WifiProStateMachineTest, IsReachWifiScanThresholdTest04, TestSize.Level1)
{
    // The wifi signal is equal to 3 bars, and there is no connection record within 14 days.
    int32_t signalLevel = SIG_LEVEL_3;
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.supplicantState = SupplicantState::INVALID;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
    pWifiProStateMachine_->pCurrWifiInfo_ = std::make_shared<WifiLinkedInfo>(wifiLinkedInfo);
 
    WifiDeviceConfig wifiDeviceConfig;
    wifiDeviceConfig.lastTrySwitchWifiTimestamp = 0;
    pWifiProStateMachine_->pCurrWifiDeviceConfig_ = std::make_shared<WifiDeviceConfig>(wifiDeviceConfig);
    bool ret = pWifiProStateMachine_->IsReachWifiScanThreshold(signalLevel);
    EXPECT_EQ(ret, false);
}
} // namespace Wifi
} // namespace OHOS