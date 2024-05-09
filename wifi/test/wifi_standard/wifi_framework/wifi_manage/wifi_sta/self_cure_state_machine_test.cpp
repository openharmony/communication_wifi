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
#include "mock_wifi_settings.h"
#include "internal_message.h"
#include "define.h"
#include "self_cure_common.h"
#include "self_cure_state_machine.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "wifi_logger.h"

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
static const int64_t TIME_MILLS = 1615153293123;
static const std::string CURR_BSSID = "11:22:33:ef:ac:0e";

class SelfCureStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pSelfCureStateMachine = std::make_unique<SelfCureStateMachine>();
        pSelfCureStateMachine->Initialize();
    }

    virtual void TearDown()
    {
        pSelfCureStateMachine.reset();
    }

    std::unique_ptr<SelfCureStateMachine> pSelfCureStateMachine;

    void Wifi6SelfCureStateGoInStateSuccess()
    {
        LOGI("Enter Wifi6SelfCureStateGoInStateSuccess");
        pSelfCureStateMachine->pWifi6SelfCureState->GoInState();
    }

    void Wifi6SelfCureStateGoOutStateSuccess()
    {
        LOGI("Enter Wifi6SelfCureStateGoOutStateSuccess");
        pSelfCureStateMachine->pWifi6SelfCureState->GoOutState();
    }

    void InitExeMsgFail()
    {
        LOGI("Enter InitExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(nullptr));
    }

    void InitExeMsgSuccess1()
    {
        LOGI("Enter InitExeMsgSuccess1");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_WIFI6_SELFCURE);
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(&msg));
    }

    void InitExeMsgSuccess2()
    {
        LOGI("Enter InitExeMsgSuccess2");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_WIFI6_BACKOFF_SELFCURE);
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(&msg));
    }

    void CanArpReachableFailedTest()
    {
        LOGI("Enter CanArpReachableFailedTest");
        IpInfo ipInfo;
        ipInfo.gateway = 0;
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_FALSE(pSelfCureStateMachine->CanArpReachable());
    }

    void CanArpReachableTest()
    {
        LOGI("Enter CanArpReachableTest");
        IpInfo ipInfo;
        ipInfo.gateway = 1;
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_FALSE(pSelfCureStateMachine->CanArpReachable());
    }

    void InitExeMsgSuccess3()
    {
        LOGI("Enter InitExeMsgSuccess3");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_WIFI6_WITH_HTC_PERIODIC_ARP_DETECTED);
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(&msg));
    }

    void InitExeMsgSuccess4()
    {
        LOGI("Enter InitExeMsgSuccess4");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_PERIODIC_ARP_DETECTED);
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(&msg));
    }

    void InitExeMsgSuccess5()
    {
        LOGI("Enter InitExeMsgSuccess5");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_WIFI6_WITH_HTC_ARP_FAILED_DETECTED);
        EXPECT_CALL(WifiSettings::GetInstance(), InsertWifi6BlackListCache(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), RemoveWifi6BlackListCache(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifi6BlackListCache(_)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(&msg));
    }

    void InitExeMsgSuccess6()
    {
        LOGI("Enter InitExeMsgSuccess6");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_ARP_FAILED_DETECTED);
        EXPECT_CALL(WifiSettings::GetInstance(), InsertWifi6BlackListCache(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), RemoveWifi6BlackListCache(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifi6BlackListCache(_)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(&msg));
    }

    void GetNowMilliSecondsTest()
    {
        LOGI("Enter GetNowMilliSecondsTest");
        pSelfCureStateMachine->GetNowMilliSeconds();
    }

    void SendBlaListToDriverTest()
    {
        LOGI("Enter SendBlaListToDriverTest");
        std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache = {};
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifi6BlackListCache(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifi6BlackListCache), Return(0)));
        pSelfCureStateMachine->SendBlaListToDriver();
    }

    void SendBlaListToDriverTest2()
    {
        LOGI("Enter SendBlaListToDriverTest2");
        std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache;
        std::string currentBssid = CURR_BSSID;
        Wifi6BlackListInfo wifi6BlackListInfo(1, TIME_MILLS);
        wifi6BlackListCache.emplace(std::make_pair(currentBssid, wifi6BlackListInfo));

        EXPECT_CALL(WifiSettings::GetInstance(), GetWifi6BlackListCache(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifi6BlackListCache), Return(0)));
        pSelfCureStateMachine->SendBlaListToDriver();
    }

    void BlackListToStringTest()
    {
        LOGI("Enter BlackListToStringTest");
        std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache = {};
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifi6BlackListCache(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifi6BlackListCache), Return(0)));
        pSelfCureStateMachine->BlackListToString(wifi6BlackListCache);
    }

    void BlackListToStringTest2()
    {
        LOGI("Enter BlackListToStringTest2");
        std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache;
        std::string currentBssid = CURR_BSSID;
        Wifi6BlackListInfo wifi6BlackListInfo(1, TIME_MILLS);
        wifi6BlackListCache.emplace(std::make_pair(currentBssid, wifi6BlackListInfo));

        EXPECT_CALL(WifiSettings::GetInstance(), GetWifi6BlackListCache(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifi6BlackListCache), Return(0)));
        pSelfCureStateMachine->BlackListToString(wifi6BlackListCache);
    }

    void ParseWifi6BlackListInfoTest()
    {
        LOGI("Enter ParseWifi6BlackListInfoTest");
        std::string currentBssid = CURR_BSSID;
        Wifi6BlackListInfo wifi6BlackListInfo(1, TIME_MILLS);
        std::pair<std::string, Wifi6BlackListInfo> iter = std::make_pair(CURR_BSSID, wifi6BlackListInfo);
        pSelfCureStateMachine->ParseWifi6BlackListInfo(iter);
    }

    void AgeOutWifi6BlackTest()
    {
        LOGI("Enter AgeOutWifi6BlackTest");
        std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache;
        std::string currentBssid = CURR_BSSID;
        Wifi6BlackListInfo wifi6BlackListInfo(1, TIME_MILLS);
        wifi6BlackListCache.emplace(std::make_pair(currentBssid, wifi6BlackListInfo));
        EXPECT_CALL(WifiSettings::GetInstance(), RemoveWifi6BlackListCache(_)).Times(AtLeast(0));
        pSelfCureStateMachine->AgeOutWifi6Black(wifi6BlackListCache);
    }

    void ShouldTransToWifi6SelfCureTest()
    {
        LOGI("Enter ShouldTransToWifi6SelfCureTest");
        std::string currConnectedBssid = "";
        InternalMessage msg;
        msg.SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine->ShouldTransToWifi6SelfCure(&msg, currConnectedBssid));
    }

    void ShouldTransToWifi6SelfCureTest2()
    {
        LOGI("Enter ShouldTransToWifi6SelfCureTest2");
        std::string currConnectedBssid = CURR_BSSID;
        EXPECT_CALL(WifiSettings::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        InternalMessage msg;
        msg.SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine->ShouldTransToWifi6SelfCure(&msg, currConnectedBssid));
    }

    void GetCurrentBssidTest()
    {
        LOGI("Enter GetCurrentBssidTest");
        std::string currConnectedBssid = "";
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_)).Times(AtLeast(0));
        pSelfCureStateMachine->GetCurrentBssid();
    }

    void IsWifi6NetworkTest()
    {
        LOGI("Enter IsWifi6NetworkTest");
        std::string currConnectedBssid = "";
        EXPECT_FALSE(pSelfCureStateMachine->IsWifi6Network(currConnectedBssid));
    }

    void IsWifi6NetworkTest2()
    {
        LOGI("Enter IsWifi6NetworkTest2");
        std::string currConnectedBssid = CURR_BSSID;
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.supportedWifiCategory = WifiCategory::DEFAULT;
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        EXPECT_FALSE(pSelfCureStateMachine->IsWifi6Network(currConnectedBssid));
    }

    void IsWifi6NetworkTest3()
    {
        LOGI("Enter IsWifi6NetworkTest3");
        std::string currConnectedBssid = CURR_BSSID;
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.supportedWifiCategory = WifiCategory::WIFI6;
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        EXPECT_TRUE(pSelfCureStateMachine->IsWifi6Network(currConnectedBssid));
    }
};

HWTEST_F(SelfCureStateMachineTest, Wifi6SelfCureStateGoInStateSuccess, TestSize.Level1)
{
    Wifi6SelfCureStateGoInStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, Wifi6SelfCureStateGoOutStateSuccess, TestSize.Level1)
{
    Wifi6SelfCureStateGoOutStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, InitExeMsgFail, TestSize.Level1)
{
    InitExeMsgFail();
}

HWTEST_F(SelfCureStateMachineTest, InitExeMsgSuccess1, TestSize.Level1)
{
    InitExeMsgSuccess1();
}

HWTEST_F(SelfCureStateMachineTest, InitExeMsgSuccess2, TestSize.Level1)
{
    InitExeMsgSuccess2();
}

HWTEST_F(SelfCureStateMachineTest, CanArpReachableFailedTest, TestSize.Level1)
{
    CanArpReachableFailedTest();
}

HWTEST_F(SelfCureStateMachineTest, CanArpReachableTest, TestSize.Level1)
{
    CanArpReachableTest();
}

HWTEST_F(SelfCureStateMachineTest, InitExeMsgSuccess3, TestSize.Level1)
{
    InitExeMsgSuccess3();
}

HWTEST_F(SelfCureStateMachineTest, InitExeMsgSuccess4, TestSize.Level1)
{
    InitExeMsgSuccess4();
}

HWTEST_F(SelfCureStateMachineTest, InitExeMsgSuccess5, TestSize.Level1)
{
    InitExeMsgSuccess5();
}

HWTEST_F(SelfCureStateMachineTest, InitExeMsgSuccess6, TestSize.Level1)
{
    InitExeMsgSuccess6();
}

HWTEST_F(SelfCureStateMachineTest, GetNowMilliSecondsTest, TestSize.Level1)
{
    GetNowMilliSecondsTest();
}

HWTEST_F(SelfCureStateMachineTest, SendBlaListToDriverTest, TestSize.Level1)
{
    SendBlaListToDriverTest();
}

HWTEST_F(SelfCureStateMachineTest, SendBlaListToDriverTest2, TestSize.Level1)
{
    SendBlaListToDriverTest2();
}

HWTEST_F(SelfCureStateMachineTest, BlackListToStringTest, TestSize.Level1)
{
    BlackListToStringTest();
}

HWTEST_F(SelfCureStateMachineTest, BlackListToStringTest2, TestSize.Level1)
{
    BlackListToStringTest2();
}

HWTEST_F(SelfCureStateMachineTest, ParseWifi6BlackListInfoTest, TestSize.Level1)
{
    ParseWifi6BlackListInfoTest();
}

HWTEST_F(SelfCureStateMachineTest, AgeOutWifi6BlackTest, TestSize.Level1)
{
    AgeOutWifi6BlackTest();
}

HWTEST_F(SelfCureStateMachineTest, ShouldTransToWifi6SelfCureTest, TestSize.Level1)
{
    ShouldTransToWifi6SelfCureTest();
}

HWTEST_F(SelfCureStateMachineTest, ShouldTransToWifi6SelfCureTest2, TestSize.Level1)
{
    ShouldTransToWifi6SelfCureTest2();
}

HWTEST_F(SelfCureStateMachineTest, GetCurrentBssidTest, TestSize.Level1)
{
    GetCurrentBssidTest();
}

HWTEST_F(SelfCureStateMachineTest, IsWifi6NetworkTest, TestSize.Level1)
{
    IsWifi6NetworkTest();
}

HWTEST_F(SelfCureStateMachineTest, IsWifi6NetworkTest2, TestSize.Level1)
{
    IsWifi6NetworkTest2();
}

HWTEST_F(SelfCureStateMachineTest, IsWifi6NetworkTest3, TestSize.Level1)
{
    IsWifi6NetworkTest3();
}

} // namespace Wifi
} // namespace OHOS
