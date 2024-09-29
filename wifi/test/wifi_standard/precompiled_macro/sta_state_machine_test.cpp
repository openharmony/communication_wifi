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
#include "mock_wifi_sta_hal_interface.h"
#include "wifi_error_no.h"

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

void DealDhcpOfferReport(const OHOS::Wifi::IpInfo &ipInfo, int instId)
{
}

namespace OHOS {
namespace Wifi {
static const std::string RANDOMMAC_SSID = "testwifi";
static const std::string RANDOMMAC_PASSWORD = "testwifi";
static const std::string RANDOMMAC_BSSID = "01:23:45:67:89:a0";
static constexpr int NAPI_MAX_STR_LENT = 127;
static constexpr int MIN_5G_FREQUENCY = 5160;
static constexpr int TEST_2G_FREQUENCY = 2456;
static constexpr int INVALID_RSSI1 = -128;
static constexpr int GATE_WAY = 124;
constexpr int TWO = 2;

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
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("sta"));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->pDhcpResultNotify->pStaStateMachine = nullptr;
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressSuccess2()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("sta"));
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
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("sta"));
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
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("sta"));
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
        MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_FAILED);
        pStaStateMachine->SetExternalSim("wlan0", EAP_METHOD_NONE, value);
    }

    void FillSuiteB192CfgTest()
    {
        WifiHalDeviceConfig  halDeviceConfig;
        halDeviceConfig.keyMgmt = "WPA-EAP";
        pStaStateMachine->FillSuiteB192Cfg(halDeviceConfig);
    }

    void ConvertDeviceCfgSuccess()
    {
        std::vector<WifiScanInfo> scanInfoList;
        WifiScanInfo temp;
        temp.ssid = "123";
        temp.bssid ="456";
        temp.capabilities = "PSK+SAE";
        scanInfoList.push_back(temp);
        WifiDeviceConfig config;
        config.keyMgmt = "WEP";
        config.ssid = "123";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(TWO)
            .WillOnce(DoAll(SetArgReferee<0>(scanInfoList), Return(0)));
        EXPECT_EQ(WIFI_OPT_FAILED, pStaStateMachine->ConvertDeviceCfg(config));
    }

    void GetGsmAuthResponseWithoutLengthTest()
    {
        EapSimGsmAuthParam param;
        param.rands.push_back("30303a35353a44443a66663a4d4d");
        EXPECT_EQ(pStaStateMachine->GetGsmAuthResponseWithoutLength(param), "");
    }

    void GetGsmAuthResponseWithLengthTest()
    {
        EapSimGsmAuthParam param;
        param.rands.push_back("30303a35353a44443a66663a4d4d");
        EXPECT_EQ(pStaStateMachine->GetGsmAuthResponseWithLength(param), "");
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
        if (snprintf_s(result1.strOptClientId, sizeof(result1.strOptClientId), sizeof(result1.strOptClientId) - 1,
                "%s", "0.0.0.1") < 0) {
            return;
        }
        if (snprintf_s(result1.strOptRouter1, sizeof(result1.strOptRouter1), sizeof(result1.strOptRouter1) - 1,
                "%s", "0.0.0.1") < 0) {
            return;
        }
        result1.iptype  = 0;
        ipv6Info.linkIpV6Address  = "0";
        ipv6Info.globalIpV6Address  = "0";
        ipv6Info.randGlobalIpV6Address  = "0";
        ipv6Info.gateway  = "0";
        ipv6Info.netmask  = "0";
        ipv6Info.primaryDns  = "0";
        ipv6Info.secondDns  = "0";
        ipv6Info.uniqueLocalAddress1  = "0";
        ipv6Info.uniqueLocalAddress2  = "0";
        ipv6Info.dnsAddr.push_back("11");
        StaStateMachine staStateMachine;
        pStaStateMachine->pDhcpResultNotify->SetStaStateMachine(&staStateMachine);
        pStaStateMachine->pDhcpResultNotify->TryToSaveIpV6Result(ipInfo, ipv6Info, &result1);
    }

    void SetConnectMethodTest()
    {
        int connectMethod = NETWORK_SELECTED_BY_AUTO;
        pStaStateMachine->SetConnectMethod(connectMethod);
        connectMethod = NETWORK_SELECTED_BY_USER;
        pStaStateMachine->SetConnectMethod(connectMethod);
    }

    void InvokeOnDhcpOfferReportTest()
    {
        IpInfo ipInfo;
        StaServiceCallback callback;
        callback.OnDhcpOfferReport = DealDhcpOfferReport;
        pStaStateMachine->RegisterStaServiceCallback(callback);
        pStaStateMachine->InvokeOnDhcpOfferReport(ipInfo);
    }

    void FillSuiteB192CfgTest2()
    {
        WifiHalDeviceConfig  halDeviceConfig;
        halDeviceConfig.keyMgmt = "WPA-EAP-SUITE-B-192";
        pStaStateMachine->FillSuiteB192Cfg(halDeviceConfig);
    }

    void DealSignalPollResultTest()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiLinkedStandardAndMaxSpeed(_)).Times(testing::AtLeast(0));
        pStaStateMachine->DealSignalPollResult();
        pStaStateMachine->linkedInfo.lastTxPackets = 1;
        pStaStateMachine->linkedInfo.lastRxPackets = 1;
        pStaStateMachine->linkedInfo.lastPacketDirection = 1;
        pStaStateMachine->DealSignalPacketChanged(0, 0);
    }
    void ConvertDeviceCfgSuccess1()
    {
        std::vector<WifiScanInfo> scanInfoList;
        WifiScanInfo temp;
        temp.ssid = "123";
        temp.bssid ="456";
        temp.capabilities = "PSK+SAE";
        scanInfoList.push_back(temp);
        WifiDeviceConfig config;
        config.keyMgmt = "SAE";
        config.ssid = "123";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(scanInfoList), Return(0)));
        EXPECT_EQ(WIFI_OPT_SUCCESS, pStaStateMachine->ConvertDeviceCfg(config));
    }

    void SetExternalSimTest1()
    {
        int value = 1;
        MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
        pStaStateMachine->SetExternalSim("wlan0", EAP_METHOD_NONE, value);
    }

    void UpdateLinkInfoRssiTest()
    {
        WifiStaHalInterface::GetInstance().mInfo.frequency  = MIN_5G_FREQUENCY;
        WifiStaHalInterface::GetInstance().mInfo.txrate = MIN_5G_FREQUENCY;
        WifiStaHalInterface::GetInstance().mInfo.rxrate  = MIN_5G_FREQUENCY;
        MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
        int rssi = INVALID_RSSI1;
        int outRssi = pStaStateMachine->UpdateLinkInfoRssi(rssi);
        EXPECT_EQ(outRssi, INVALID_RSSI_VALUE);
    }
    void CurrentIsRandomizedMacTest()
    {
        MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
        pStaStateMachine->CurrentIsRandomizedMac();
    }

    void HilinkSaveConfigTest()
    {
        WifiDeviceConfig deviceConfig;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(deviceConfig.bssid, DEVICE_CONFIG_INDEX_BSSID, _, _))
            .Times(AtLeast(0)).WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(-1)));
        pStaStateMachine->HilinkSaveConfig();
    }

    void DealConnectionEventSuccess()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceAfterConnect(_)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceState(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetUserLastSelectedNetworkId(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->m_hilinkFlag = true;
        pStaStateMachine->DealConnectionEvent(msg);
    }

    void DealWpaWrongPskEventFail1()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillOnce(Return(1))
            .WillRepeatedly(Return(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(WIFI_SVR_CMD_STA_REPORT_DISCONNECT_REASON_EVENT);
        pStaStateMachine->DealWpaLinkFailEvent(msg);
    }

    void DealWpaWrongPskEventFail2()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillOnce(Return(1))
            .WillRepeatedly(Return(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(WIFI_SVR_CMD_STA_WPS_TIMEOUT_EVNET);
        pStaStateMachine->DealWpaLinkFailEvent(msg);
    }

    void DealStartWpsCmdSuccess()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
        pStaStateMachine->DealStartWpsCmd(msg);
    }

    void DealScreenStateChangedEventTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(static_cast<int>(MODE_STATE_OPEN));
        pStaStateMachine->DealScreenStateChangedEvent(msg);
        msg->SetParam1(static_cast<int>(MODE_STATE_CLOSE));
        pStaStateMachine->DealScreenStateChangedEvent(msg);
    }

       void DealCancelWpsCmdSuccess1()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillRepeatedly(Return(-1));
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        pStaStateMachine->wpsState = SetupMethod::PBC;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
        pStaStateMachine->DealCancelWpsCmd(msg);
    }

    void DealCancelWpsCmdSuccess2()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillRepeatedly(Return(-1));
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        pStaStateMachine->wpsState = SetupMethod::DISPLAY;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
        pStaStateMachine->DealCancelWpsCmd(msg);
    }

    void DealCancelWpsCmdSuccess3()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillRepeatedly(Return(-1));
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::KEYPAD;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
        pStaStateMachine->DealCancelWpsCmd(msg);
    }

    void DealCancelWpsCmdFail1()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::PBC;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
        pStaStateMachine->DealCancelWpsCmd(msg);
    }

    void DealCancelWpsCmdFail2()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::DISPLAY;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
        pStaStateMachine->DealCancelWpsCmd(msg);
    }

    void DealCancelWpsCmdFail3()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::KEYPAD;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
        pStaStateMachine->DealCancelWpsCmd(msg);
        pStaStateMachine->DealCancelWpsCmd(nullptr);
    }
    void CanArpReachableTest()
    {
        IpInfo ipInfo;
        ipInfo.gateway =GATE_WAY;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        pStaStateMachine->CanArpReachable();
    }
    void PortalExpiredDetectTest()
    {
        pStaStateMachine->portalState = PortalState::AUTHED;
        pStaStateMachine->portalExpiredDetectCount = PORTAL_EXPERIED_DETECT_MAX_COUNT;
        pStaStateMachine->PortalExpiredDetect();
    }
    void IsGoodSignalQualityTest()
    {
        pStaStateMachine->linkedInfo.frequency = MIN_5G_FREQUENCY;
        pStaStateMachine->linkedInfo.chload = TWO;
        pStaStateMachine->linkedInfo.rssi = INVALID_RSSI1;
        EXPECT_FALSE(pStaStateMachine->IsGoodSignalQuality());
    }
    void IsGoodSignalQualityTest1()
    {
        pStaStateMachine->linkedInfo.frequency = TEST_2G_FREQUENCY;
        pStaStateMachine->linkedInfo.chload = TWO;
        pStaStateMachine->linkedInfo.rssi = INVALID_RSSI1;
        EXPECT_FALSE(pStaStateMachine->IsGoodSignalQuality());
    }
    void IsGoodSignalQualityTest2()
    {
        pStaStateMachine->linkedInfo.frequency = MIN_5G_FREQUENCY;
        pStaStateMachine->linkedInfo.chload = MIN_5G_FREQUENCY;
        pStaStateMachine->linkedInfo.rssi = -1;
        EXPECT_FALSE(pStaStateMachine->IsGoodSignalQuality());
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

HWTEST_F(StaStateMachineTest, ConvertDeviceCfgSuccess, TestSize.Level1)
{
    ConvertDeviceCfgSuccess();
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

HWTEST_F(StaStateMachineTest, SetExternalSimTest1, TestSize.Level1)
{
    SetExternalSimTest1();
}

HWTEST_F(StaStateMachineTest, UpdateLinkInfoRssiTest, TestSize.Level1)
{
    UpdateLinkInfoRssiTest();
}

HWTEST_F(StaStateMachineTest, CurrentIsRandomizedMacTest, TestSize.Level1)
{
    CurrentIsRandomizedMacTest();
}

HWTEST_F(StaStateMachineTest, HilinkSaveConfigTest, TestSize.Level1)
{
    HilinkSaveConfigTest();
}

HWTEST_F(StaStateMachineTest, DealConnectionEventSuccess, TestSize.Level1)
{
    DealConnectionEventSuccess();
}

HWTEST_F(StaStateMachineTest, DealWpaWrongPskEventFail1, TestSize.Level1)
{
    DealWpaWrongPskEventFail1();
}

HWTEST_F(StaStateMachineTest, DealWpaWrongPskEventFail2, TestSize.Level1)
{
    DealWpaWrongPskEventFail2();
}

HWTEST_F(StaStateMachineTest, DealStartWpsCmdSuccess, TestSize.Level1)
{
    DealStartWpsCmdSuccess();
}

HWTEST_F(StaStateMachineTest, DealScreenStateChangedEventTest, TestSize.Level1)
{
    DealScreenStateChangedEventTest();
}

HWTEST_F(StaStateMachineTest, InvokeOnDhcpOfferReportTest, TestSize.Level1)
{
    InvokeOnDhcpOfferReportTest();
}

HWTEST_F(StaStateMachineTest, DealCancelWpsCmdSuccess1, TestSize.Level1)
{
    DealCancelWpsCmdSuccess1();
}

HWTEST_F(StaStateMachineTest, DealCancelWpsCmdSuccess2, TestSize.Level1)
{
    DealCancelWpsCmdSuccess2();
}

HWTEST_F(StaStateMachineTest, DealCancelWpsCmdSuccess3, TestSize.Level1)
{
    DealCancelWpsCmdSuccess3();
}

HWTEST_F(StaStateMachineTest, DealCancelWpsCmdFail1, TestSize.Level1)
{
    DealCancelWpsCmdFail1();
}

HWTEST_F(StaStateMachineTest, DealCancelWpsCmdFail2, TestSize.Level1)
{
    DealCancelWpsCmdFail2();
}

HWTEST_F(StaStateMachineTest, DealCancelWpsCmdFail3, TestSize.Level1)
{
    DealCancelWpsCmdFail3();
}

HWTEST_F(StaStateMachineTest, CanArpReachableTest, TestSize.Level1)
{
    CanArpReachableTest();
}

HWTEST_F(StaStateMachineTest, PortalExpiredDetectTest, TestSize.Level1)
{
    PortalExpiredDetectTest();
}

HWTEST_F(StaStateMachineTest, IsGoodSignalQualityTest, TestSize.Level1)
{
    IsGoodSignalQualityTest();
}

HWTEST_F(StaStateMachineTest, IsGoodSignalQualityTest1, TestSize.Level1)
{
    IsGoodSignalQualityTest1();
}

HWTEST_F(StaStateMachineTest, IsGoodSignalQualityTest2, TestSize.Level1)
{
    IsGoodSignalQualityTest2();
}
}
}