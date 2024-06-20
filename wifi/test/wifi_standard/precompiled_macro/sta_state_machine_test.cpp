#include <gtest/gtest.h>
#include "internal_message.h"
#include "sta_define.h"
#include "define.h"
#include "sta_state_machine.h"
#include "sta_service.h"
#include "wifi_app_state_aware.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
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
    memcpy_s(strDest, destMax, strSrc, strlen(strSrc));
    return 1;
}

namespace OHOS {
namespace Wifi {
static const std::string RANDOMMAC_SSID = "testwifi";
static const std::string RANDOMMAC_PASSWORD = "testwifi";
static const std::string RANDOMMAC_BSSID = "01:23:45:67:89:a0";


class StaStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase() 
    {
       
    }
    static void TearDownTestCase()
    {
        WifiAppStateAware& wifiAppStateAware = WifiAppStateAware::GetInstance();
        wifiAppStateAware.appChangeEventHandler.reset();
        wifiAppStateAware.mAppStateObserver = nullptr;
        wifiAppStateAware.appMgrProxy_ = nullptr;
    }
    virtual void SetUp()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetPortalUri(_)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveDisconnectedReason(_, _)).Times(testing::AtLeast(0));
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
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_IPV4;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->pDhcpResultNotify->pStaStateMachine = nullptr;
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressSuccess2()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->pDhcpResultNotify->pStaStateMachine = nullptr;
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressSuccess3()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_MIX;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        pStaStateMachine->pDhcpResultNotify->pStaStateMachine = nullptr;
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressFail()
    {
        pStaStateMachine->currentTpType = IPTYPE_BUTT;
        StaticIpAddress staticIpAddress;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_FALSE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ReplaceEmptyDnsTest()
    {
        DhcpResult *result =nullptr;
        pStaStateMachine->ReplaceEmptyDns(result);
        DhcpResult resultO;
        memcpy_s(resultO.strOptDns1, 127, "11:22:33:44", strlen("11:22:33:44"));
        memcpy_s(resultO.strOptDns2, 127, "11:22:33:45", strlen("11:22:33:45"));
        pStaStateMachine->ReplaceEmptyDns(&resultO);
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

}
}