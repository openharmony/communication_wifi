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
#include "internal_message.h"
#include "sta_define.h"
#include "define.h"
#include "sta_state_machine.h"
#include "sta_service.h"
#include "wifi_app_state_aware.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"
#include "mock_if_config.h"
#include "mock_wifi_manager.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

errno_t strcpy_s(char *strDest, size_t destMax, const char *strSrc)
{
    int retCode = memcpy_s(strDest, destMax, strSrc, strlen(strSrc));
    if (retCode != 0) {
        return 1;
    }
    return 1;
}

namespace OHOS {
namespace Wifi {
static const std::string RANDOMMAC_SSID = "testwifi";
static const std::string RANDOMMAC_PASSWORD = "testwifi";
static const std::string RANDOMMAC_BSSID = "01:23:45:67:89:a0";
static constexpr int NAPI_MAX_STR_LENT = 127;

class StaStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase()
    {
        WifiAppStateAware& wifiAppStateAware = WifiAppStateAware::GetInstance();
        wifiAppStateAware.appChangeEventHandler.reset();
        wifiAppStateAware.mAppStateObserver = nullptr;
        wifiAppStateAware.appMgrProxy_ = nullptr;
    }
    virtual void SetUp()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveDisconnectedReason(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine.reset(new StaStateMachine());
        pStaStateMachine->InitStaStateMachine();
        pStaStateMachine->InitWifiLinkedInfo();
        pStaStateMachine->InitLastWifiLinkedInfo();
    }
    virtual void TearDown()
    {
        pStaStateMachine.reset();
    }
    std::unique_ptr<StaStateMachine> pStaStateMachine;

    void ConfigStaticIpAddressSuccess1()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_IPV4;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->pDhcpResultNotify->pStaStateMachine = nullptr;
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressSuccess2()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->pDhcpResultNotify->pStaStateMachine = nullptr;
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressSuccess3()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_MIX;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        pStaStateMachine->pDhcpResultNotify->pStaStateMachine = nullptr;
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressFail()
    {
        pStaStateMachine->currentTpType = IPTYPE_BUTT;
        StaticIpAddress staticIpAddress;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_FALSE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ReplaceEmptyDnsTest()
    {
        DhcpResult *result = nullptr;
        pStaStateMachine->ReplaceEmptyDns(result);
        DhcpResult resultO;
        std::string dns = "0.0.0.0";
        pStaStateMachine->ReplaceEmptyDns(&resultO);
        memcpy_s(resultO.strOptDns2, NAPI_MAX_STR_LENT, dns.c_str(), dns.length());
        pStaStateMachine->ReplaceEmptyDns(&resultO);
        memcpy_s(resultO.strOptDns1, NAPI_MAX_STR_LENT, dns.c_str(), dns.length());
        memset_s(resultO.strOptDns2, NAPI_MAX_STR_LENT, 0x0, NAPI_MAX_STR_LENT);
        pStaStateMachine->ReplaceEmptyDns(&resultO);
        memcpy_s(resultO.strOptDns1, NAPI_MAX_STR_LENT, dns.c_str(), dns.length());
        memcpy_s(resultO.strOptDns2, NAPI_MAX_STR_LENT, dns.c_str(), dns.length());
        pStaStateMachine->ReplaceEmptyDns(&resultO);
    }

    void SetExternalSimTest()
    {
        int value = 1;
        pStaStateMachine->SetExternalSim("wlan0", EAP_METHOD_NONE, value);
    }

    void FillSuiteB192CfgTest()
    {
        WifiHalDeviceConfig  halDeviceConfig;
        halDeviceConfig.keyMgmt = "WPA-EAP";
        pStaStateMachine->FillSuiteB192Cfg(halDeviceConfig);
    }

    void GetGsmAuthResponseWithoutLengthTest()
    {
        EapSimGsmAuthParam param;
        param.rands.push_back("aaaaa");
        pStaStateMachine->GetGsmAuthResponseWithoutLength(param);
    }

    void GetGsmAuthResponseWithLengthTest()
    {
        EapSimGsmAuthParam param;
        param.rands.push_back("aaaaa");
        pStaStateMachine->GetGsmAuthResponseWithLength(param);
    }

    void StartDetectTimerTest()
    {
        int detectType = DETECT_TYPE_PERIODIC;
        pStaStateMachine->StartDetectTimer(detectType);
    }

    void DealApRoamingStateTimeoutTest()
    {
        InternalMessagePtr msg = nullptr;
        pStaStateMachine->DealApRoamingStateTimeout(msg);
    }

    void SaveDhcpResultTest()
    {
        DhcpResult *dest = nullptr;
        DhcpResult *source = nullptr;
        pStaStateMachine->pDhcpResultNotify->SaveDhcpResult(dest, source);
        DhcpResult destObj;
        DhcpResult sourceObj;
        pStaStateMachine->pDhcpResultNotify->SaveDhcpResult(&destObj, &sourceObj);
    }

    void SaveDhcpResultExtTest()
    {
        DhcpResult *dest = nullptr;
        DhcpResult *source = nullptr;
        pStaStateMachine->pDhcpResultNotify->SaveDhcpResultExt(dest, source);
        DhcpResult destObj;
        DhcpResult sourceObj;
        pStaStateMachine->pDhcpResultNotify->SaveDhcpResultExt(&destObj, &sourceObj);
    }

    void TryToSaveIpV4ResultExtTest()
    {
        IpInfo ipInfo;
        IpV6Info ipv6Info;
        DhcpResult *result = nullptr;
        pStaStateMachine->pDhcpResultNotify->TryToSaveIpV4ResultExt(ipInfo, ipv6Info, result);
        DhcpResult result1;
        pStaStateMachine->pDhcpResultNotify->TryToSaveIpV4ResultExt(ipInfo, ipv6Info, &result1);
    }

    void TryToSaveIpV4ResultTest()
    {
        IpInfo ipInfo;
        IpV6Info ipv6Info;
        DhcpResult *result = nullptr;
        pStaStateMachine->pDhcpResultNotify->TryToSaveIpV4Result(ipInfo, ipv6Info, result);
        DhcpResult result1;
        pStaStateMachine->pDhcpResultNotify->TryToSaveIpV4Result(ipInfo, ipv6Info, &result1);
    }

    void TryToSaveIpV6ResultTest()
    {
        IpInfo ipInfo;
        IpV6Info ipv6Info;
        DhcpResult *result = nullptr;
        pStaStateMachine->pDhcpResultNotify->TryToSaveIpV6Result(ipInfo, ipv6Info, result);
        DhcpResult result1;
        pStaStateMachine->pDhcpResultNotify->TryToSaveIpV6Result(ipInfo, ipv6Info, &result1);
    }

    void SetConnectMethodTest()
    {
        int connectMethod = NETWORK_SELECTED_BY_AUTO;
        pStaStateMachine->SetConnectMethod(connectMethod);
        connectMethod = NETWORK_SELECTED_BY_USER;
        pStaStateMachine->SetConnectMethod(connectMethod);
    }
};

HWTEST_F(StaStateMachineTest, ConfigStaticIpAddressSuccess1, TestSize.Level1)
{
    ConfigStaticIpAddressSuccess1();
}

HWTEST_F(StaStateMachineTest, ConfigStaticIpAddressSuccess2, TestSize.Level1)
{
    ConfigStaticIpAddressSuccess2();
}

HWTEST_F(StaStateMachineTest, ConfigStaticIpAddressSuccess3, TestSize.Level1)
{
    ConfigStaticIpAddressSuccess3();
}

HWTEST_F(StaStateMachineTest, ConfigStaticIpAddressFail, TestSize.Level1)
{
    ConfigStaticIpAddressFail();
}

HWTEST_F(StaStateMachineTest, ReplaceEmptyDnsTest, TestSize.Level1)
{
    ReplaceEmptyDnsTest();
}

HWTEST_F(StaStateMachineTest, SetExternalSimTest, TestSize.Level1)
{
    SetExternalSimTest();
}

HWTEST_F(StaStateMachineTest, FillSuiteB192CfgTest, TestSize.Level1)
{
    FillSuiteB192CfgTest();
}

HWTEST_F(StaStateMachineTest, GetGsmAuthResponseWithoutLengthTest, TestSize.Level1)
{
    GetGsmAuthResponseWithoutLengthTest();
}

HWTEST_F(StaStateMachineTest, GetGsmAuthResponseWithLengthTest, TestSize.Level1)
{
    GetGsmAuthResponseWithLengthTest();
}

HWTEST_F(StaStateMachineTest, StartDetectTimerTest, TestSize.Level1)
{
    StartDetectTimerTest();
}

HWTEST_F(StaStateMachineTest, DealApRoamingStateTimeoutTest, TestSize.Level1)
{
    DealApRoamingStateTimeoutTest();
}

HWTEST_F(StaStateMachineTest, SaveDhcpResultTest, TestSize.Level1)
{
    SaveDhcpResultTest();
}

HWTEST_F(StaStateMachineTest, SaveDhcpResultExtTest, TestSize.Level1)
{
    SaveDhcpResultExtTest();
}

HWTEST_F(StaStateMachineTest, TryToSaveIpV4ResultExtTest, TestSize.Level1)
{
    TryToSaveIpV4ResultExtTest();
}

HWTEST_F(StaStateMachineTest, TryToSaveIpV4ResultTest, TestSize.Level1)
{
    TryToSaveIpV4ResultTest();
}

HWTEST_F(StaStateMachineTest, TryToSaveIpV6ResultTest, TestSize.Level1)
{
    TryToSaveIpV6ResultTest();
}

HWTEST_F(StaStateMachineTest, SetConnectMethodTest, TestSize.Level1)
{
    SetConnectMethodTest();
}
}
}