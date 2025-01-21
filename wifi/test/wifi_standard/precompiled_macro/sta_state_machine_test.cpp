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
#include "mock_block_connect_service.h"
#include "log.h"

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
static std::string g_errLog;
void StaMachineLogCallback(const LogType type, const LogLevel level,
                            const unsigned int domain, const char *tag, const char *msg)
{
    g_errLog = msg;
}
static const std::string RANDOMMAC_SSID = "testwifi";
static const std::string RANDOMMAC_PASSWORD = "testwifi";
static const std::string RANDOMMAC_BSSID = "01:23:45:67:89:a0";
static constexpr int NAPI_MAX_STR_LENT = 127;
static constexpr int MIN_5G_FREQUENCY = 5160;
static constexpr int INVALID_RSSI1 = -128;
static constexpr int GATE_WAY = 124;
constexpr int TWO = 2;
constexpr int TEN = 10;

class StaStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase()
    {
        WifiAppStateAware& wifiAppStateAware = WifiAppStateAware::GetInstance();
        wifiAppStateAware.appChangeEventHandler.reset();
        wifiAppStateAware.mAppStateObserver = nullptr;
    }
    virtual void SetUp()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveDisconnectedReason(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine.reset(new StaStateMachine());
        pStaStateMachine->InitStaStateMachine();
        pStaStateMachine->InitWifiLinkedInfo();
        LOG_SetCallback(StaMachineLogCallback);
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
        EXPECT_EQ(WIFI_OPT_FAILED, pStaStateMachine->ConvertDeviceCfg(config, temp.bssid));
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
        pStaStateMachine->pApRoamingState->DealApRoamingStateTimeout(msg);
    }

    void SaveDhcpResultTest()
    {
        DhcpResult *dest = nullptr;
        DhcpResult *source = nullptr;
        pStaStateMachine->pDhcpResultNotify->SaveDhcpResult(dest, source);
        DhcpResult destObj;
        DhcpResult sourceObj;
        pStaStateMachine->pDhcpResultNotify->SaveDhcpResult(&destObj, &sourceObj);
        EXPECT_NE(pStaStateMachine->currentTpType, TEN);
    }

    void SaveDhcpResultExtTest()
    {
        DhcpResult *dest = nullptr;
        DhcpResult *source = nullptr;
        pStaStateMachine->pDhcpResultNotify->SaveDhcpResultExt(dest, source);
        DhcpResult destObj;
        DhcpResult sourceObj;
        pStaStateMachine->pDhcpResultNotify->SaveDhcpResultExt(&destObj, &sourceObj);
        EXPECT_NE(pStaStateMachine->currentTpType, TEN);
    }

    void TryToSaveIpV4ResultExtTest()
    {
        IpInfo ipInfo;
        IpV6Info ipv6Info;
        DhcpResult *result = nullptr;
        pStaStateMachine->pDhcpResultNotify->TryToSaveIpV4ResultExt(ipInfo, ipv6Info, result);
        DhcpResult result1;
        pStaStateMachine->pDhcpResultNotify->TryToSaveIpV4ResultExt(ipInfo, ipv6Info, &result1);
        EXPECT_NE(pStaStateMachine->currentTpType, TEN);
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
        pStaStateMachine->pDhcpResultNotify->TryToSaveIpV6Result(ipInfo, ipv6Info, &result1);
        EXPECT_NE(pStaStateMachine->currentTpType, TEN);
    }

    void SetConnectMethodTest()
    {
        int connectMethod = NETWORK_SELECTED_BY_AUTO;
        pStaStateMachine->SetConnectMethod(connectMethod);
        connectMethod = NETWORK_SELECTED_BY_USER;
        pStaStateMachine->SetConnectMethod(connectMethod);
        EXPECT_NE(pStaStateMachine->currentTpType, TEN);
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
        EXPECT_EQ(WIFI_OPT_SUCCESS, pStaStateMachine->ConvertDeviceCfg(config, temp.bssid));
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
        pStaStateMachine->pApLinkingState->DealWpaLinkFailEvent(msg);
        EXPECT_NE(pStaStateMachine->currentTpType, TEN);
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
        pStaStateMachine->pApLinkingState->DealWpaLinkFailEvent(msg);
        EXPECT_NE(pStaStateMachine->currentTpType, TEN);
    }

    void DealWpaWrongPskEventFail3()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillOnce(Return(1))
            .WillRepeatedly(Return(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT);
        pStaStateMachine->pApLinkingState->DealWpaLinkFailEvent(msg);
        pStaStateMachine->pApLinkingState->DealWpaLinkFailEvent(nullptr);
    }
 
    void DealWpaWrongPskEventFail4()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT);
        pStaStateMachine->pApLinkingState->DealWpaLinkFailEvent(msg);
    }
 
    void DealWpaWrongPskEventSuccess()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(WIFI_SVR_CMD_STA_WPA_ASSOC_REJECT_EVENT);
        pStaStateMachine->pApLinkingState->DealWpaLinkFailEvent(msg);
    }

    void DealScreenStateChangedEventTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(static_cast<int>(MODE_STATE_OPEN));
        pStaStateMachine->DealScreenStateChangedEvent(msg);
        msg->SetParam1(static_cast<int>(MODE_STATE_CLOSE));
        pStaStateMachine->DealScreenStateChangedEvent(msg);
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

    void StopDhcpSuccess1()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(IfConfig::GetInstance(), FlushIpAddr(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_IPV4;
        pStaStateMachine->StopDhcp();
        EXPECT_NE(pStaStateMachine->currentTpType, TEN);
    }
 
    void StopDhcpSuccess2()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(IfConfig::GetInstance(), FlushIpAddr(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        pStaStateMachine->StopDhcp();
        EXPECT_NE(pStaStateMachine->currentTpType, TEN);
    }
};

HWTEST_F(StaStateMachineTest, ConfigStaticIpAddressSuccess1, TestSize.Level1)
{
    ConfigStaticIpAddressSuccess1();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, ConfigStaticIpAddressSuccess2, TestSize.Level1)
{
    ConfigStaticIpAddressSuccess2();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, ConfigStaticIpAddressSuccess3, TestSize.Level1)
{
    ConfigStaticIpAddressSuccess3();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, ConfigStaticIpAddressFail, TestSize.Level1)
{
    ConfigStaticIpAddressFail();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, ReplaceEmptyDnsTest, TestSize.Level1)
{
    ReplaceEmptyDnsTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);   
}

HWTEST_F(StaStateMachineTest, SetExternalSimTest, TestSize.Level1)
{
    SetExternalSimTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, FillSuiteB192CfgTest, TestSize.Level1)
{
    FillSuiteB192CfgTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, ConvertDeviceCfgSuccess, TestSize.Level1)
{
    ConvertDeviceCfgSuccess();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, GetGsmAuthResponseWithoutLengthTest, TestSize.Level1)
{
    GetGsmAuthResponseWithoutLengthTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, GetGsmAuthResponseWithLengthTest, TestSize.Level1)
{
    GetGsmAuthResponseWithLengthTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, StartDetectTimerTest, TestSize.Level1)
{
    StartDetectTimerTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealApRoamingStateTimeoutTest, TestSize.Level1)
{
    DealApRoamingStateTimeoutTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, SaveDhcpResultTest, TestSize.Level1)
{
    SaveDhcpResultTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, SaveDhcpResultExtTest, TestSize.Level1)
{
    SaveDhcpResultExtTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, TryToSaveIpV4ResultExtTest, TestSize.Level1)
{
    TryToSaveIpV4ResultExtTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, TryToSaveIpV4ResultTest, TestSize.Level1)
{
    TryToSaveIpV4ResultTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, TryToSaveIpV6ResultTest, TestSize.Level1)
{
    TryToSaveIpV6ResultTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, SetConnectMethodTest, TestSize.Level1)
{
    SetConnectMethodTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, SetExternalSimTest1, TestSize.Level1)
{
    SetExternalSimTest1();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
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

HWTEST_F(StaStateMachineTest, DealScreenStateChangedEventTest, TestSize.Level1)
{
    DealScreenStateChangedEventTest();
}

HWTEST_F(StaStateMachineTest, InvokeOnDhcpOfferReportTest, TestSize.Level1)
{
    InvokeOnDhcpOfferReportTest();
}

HWTEST_F(StaStateMachineTest, CanArpReachableTest, TestSize.Level1)
{
    CanArpReachableTest();
}

HWTEST_F(StaStateMachineTest, PortalExpiredDetectTest, TestSize.Level1)
{
    PortalExpiredDetectTest();
}

HWTEST_F(StaStateMachineTest, DealWpaWrongPskEventFail1, TestSize.Level1)
{
    DealWpaWrongPskEventFail1();
}
 
HWTEST_F(StaStateMachineTest, DealWpaWrongPskEventFail2, TestSize.Level1)
{
    DealWpaWrongPskEventFail2();
}

HWTEST_F(StaStateMachineTest, StopDhcpSuccess1, TestSize.Level1)
{
    StopDhcpSuccess1();
}
 
HWTEST_F(StaStateMachineTest, StopDhcpSuccess2, TestSize.Level1)
{
    StopDhcpSuccess2();
}

HWTEST_F(StaStateMachineTest, DealWpaWrongPskEventFail3, TestSize.Level1)
{
    DealWpaWrongPskEventFail3();
}
 
HWTEST_F(StaStateMachineTest, DealWpaWrongPskEventFail4, TestSize.Level1)
{
    DealWpaWrongPskEventFail4();
}
 
HWTEST_F(StaStateMachineTest, DealWpaWrongPskEventSuccess, TestSize.Level1)
{
    DealWpaWrongPskEventSuccess();
}

HWTEST_F(StaStateMachineTest, InitStateHandleNetworkConnectionEventTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    pStaStateMachine->pInitState->pStaStateMachine->m_hilinkFlag = true;
    pStaStateMachine->pInitState->pStaStateMachine->targetNetworkId_ = INVALID_NETWORK_ID;
    pStaStateMachine->pInitState->HandleNetworkConnectionEvent(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, InitStateHandleNetworkConnectionEventTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    pStaStateMachine->pInitState->pStaStateMachine->m_hilinkFlag = false;
    pStaStateMachine->pInitState->pStaStateMachine->targetNetworkId_ = UNKNOWN_HILINK_NETWORK_ID;
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(0));
    pStaStateMachine->pInitState->HandleNetworkConnectionEvent(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, InitStateUpdateCountryCodeTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    pStaStateMachine->pInitState->UpdateCountryCode(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, InitStateAllowAutoConnectTest01, TestSize.Level1)
{
    pStaStateMachine->pInitState->pStaStateMachine->linkedInfo.connState = ConnState::CONNECTING;
    EXPECT_EQ(pStaStateMachine->pInitState->AllowAutoConnect(), false);
}

HWTEST_F(StaStateMachineTest, InitStateAllowAutoConnectTest02, TestSize.Level1)
{
    pStaStateMachine->pInitState->pStaStateMachine->linkedInfo.connState = ConnState::SCANNING;
    pStaStateMachine->pInitState->pStaStateMachine->isCurrentRoaming_ = false;
    pStaStateMachine->pInitState->pStaStateMachine->linkedInfo.supplicantState = SupplicantState::ASSOCIATING;
    EXPECT_EQ(pStaStateMachine->pInitState->AllowAutoConnect(), false);
    pStaStateMachine->pInitState->pStaStateMachine->linkedInfo.supplicantState = SupplicantState::ASSOCIATED;
    pStaStateMachine->pInitState->AllowAutoConnect();
    pStaStateMachine->pInitState->pStaStateMachine->linkedInfo.supplicantState = SupplicantState::AUTHENTICATING;
    pStaStateMachine->pInitState->AllowAutoConnect();
    pStaStateMachine->pInitState->pStaStateMachine->linkedInfo.supplicantState = SupplicantState::FOUR_WAY_HANDSHAKE;
    pStaStateMachine->pInitState->AllowAutoConnect();
    pStaStateMachine->pInitState->pStaStateMachine->linkedInfo.supplicantState = SupplicantState::GROUP_HANDSHAKE;
    pStaStateMachine->pInitState->AllowAutoConnect();

    pStaStateMachine->pInitState->pStaStateMachine->linkedInfo.supplicantState = SupplicantState::INVALID;
    pStaStateMachine->pInitState->pStaStateMachine->m_hilinkFlag = true;
    EXPECT_EQ(pStaStateMachine->pInitState->AllowAutoConnect(), false);

    pStaStateMachine->pInitState->pStaStateMachine->m_hilinkFlag = false;
    EXPECT_EQ(pStaStateMachine->pInitState->AllowAutoConnect(), true);
}

HWTEST_F(StaStateMachineTest, InitStateStartConnectEventTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    int test = 1;
    msg->SetParam1(test);
    pStaStateMachine->pInitState->pStaStateMachine->linkedInfo.networkId = 1;
    pStaStateMachine->pInitState->StartConnectEvent(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, InitStateStartConnectEventTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    int test = 1;
    msg->SetParam1(test);
    msg->SetParam2(NETWORK_SELECTED_BY_USER);

    pStaStateMachine->pInitState->pStaStateMachine->linkedInfo.networkId = 2;
    pStaStateMachine->pInitState->pStaStateMachine->targetNetworkId_ = 2;
    pStaStateMachine->pInitState->StartConnectEvent(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, IsNewConnectionInProgressTest01, TestSize.Level1)
{
    pStaStateMachine->targetNetworkId_ = INVALID_NETWORK_ID;
    EXPECT_EQ(pStaStateMachine->IsNewConnectionInProgress(), false);
}

HWTEST_F(StaStateMachineTest, IsNewConnectionInProgressTest02, TestSize.Level1)
{
    pStaStateMachine->targetNetworkId_ = UNKNOWN_HILINK_NETWORK_ID;
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(0));
    pStaStateMachine->IsNewConnectionInProgress();

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(1));
    pStaStateMachine->IsNewConnectionInProgress();
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, DealDisconnectEventInLinkStateTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    int disReason = 8;
    msg->SetParam1(disReason);
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiSelfcureReset()).WillRepeatedly(Return(false));
    pStaStateMachine->pLinkState->pStaStateMachine->targetNetworkId_ = INVALID_NETWORK_ID;
    pStaStateMachine->pLinkState->DealDisconnectEventInLinkState(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, StopWifiProcessInLinkStateTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    pStaStateMachine->pLinkState->StopWifiProcessInLinkState(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, LinkStateDealWpaStateChangeTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    int status = 5;
    msg->SetParam1(status);
    pStaStateMachine->pLinkState->DealWpaStateChange(msg);

    status = 1;
    msg->SetParam1(status);
    pStaStateMachine->pLinkState->DealWpaStateChange(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, SeparatedStateExecuteStateMsgTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(WIFI_SVR_CMD_STA_DISABLE_STA);
    EXPECT_TRUE(pStaStateMachine->pSeparatedState->ExecuteStateMsg(msg));
}

HWTEST_F(StaStateMachineTest, SeparatedStateExecuteStateMsgTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(WIFI_SVR_CMD_STA_RECONNECT_NETWORK);
    EXPECT_TRUE(pStaStateMachine->pSeparatedState->ExecuteStateMsg(msg));
}

HWTEST_F(StaStateMachineTest, ApLinkingStateGoInStateTest01, TestSize.Level1)
{
    pStaStateMachine->pApLinkingState->GoInState();
    pStaStateMachine->pApLinkingState->GoOutState();
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, ApLinkingStateExecuteStateMsgTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(WIFI_SVR_CMD_STA_DISCONNECT);
    EXPECT_TRUE(pStaStateMachine->pApLinkingState->ExecuteStateMsg(msg));

    msg->SetMessageName(WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT);
    pStaStateMachine->pApLinkingState->ExecuteStateMsg(msg);

    msg->SetMessageName(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
    pStaStateMachine->pApLinkingState->ExecuteStateMsg(msg);

    msg->SetMessageName(CMD_NETWORK_CONNECT_TIMEOUT);
    pStaStateMachine->pApLinkingState->ExecuteStateMsg(msg);

    msg->SetMessageName(WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT);
    pStaStateMachine->pApLinkingState->ExecuteStateMsg(msg);

    msg->SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_SIM_AUTH_EVENT);
    pStaStateMachine->pApLinkingState->ExecuteStateMsg(msg);
}

HWTEST_F(StaStateMachineTest, ApLinkedStateHandleNetWorkConnectionEventTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    pStaStateMachine->pApLinkedState->pStaStateMachine->m_hilinkFlag = true;
    pStaStateMachine->pApLinkedState->HandleNetWorkConnectionEvent(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, ApLinkingStateHandleStaBssidChangedEventTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    pStaStateMachine->pApLinkingState->HandleStaBssidChangedEvent(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, LinkStateDealConnectTimeOutCmdTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    pStaStateMachine->pLinkState->pStaStateMachine->targetNetworkId_ = 1;
    pStaStateMachine->pLinkState->pStaStateMachine->mLastConnectNetId = 1;
    pStaStateMachine->pLinkState->DealConnectTimeOutCmd(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, ApLinkingStateDealWpaLinkFailEventTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    pStaStateMachine->pApLinkingState->pStaStateMachine->targetNetworkId_ = INVALID_NETWORK_ID;
    msg->SetMessageName(WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT);
    pStaStateMachine->pApLinkingState->DealWpaLinkFailEvent(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, ApLinkingStateDealWpaLinkFailEventTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    pStaStateMachine->pApLinkingState->pStaStateMachine->targetNetworkId_ = INVALID_NETWORK_ID;
    msg->SetMessageName(WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT);
    pStaStateMachine->pApLinkingState->DealWpaLinkFailEvent(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, ApLinkingStateDealWpaLinkFailEventTest03, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    pStaStateMachine->pApLinkingState->pStaStateMachine->targetNetworkId_ = INVALID_NETWORK_ID;
    msg->SetMessageName(WIFI_SVR_CMD_STA_WPA_ASSOC_REJECT_EVENT);
    pStaStateMachine->pApLinkingState->DealWpaLinkFailEvent(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, ApLinkedStateGoInStateTest01, TestSize.Level1)
{
#ifdef OHOS_ARCH_LITE
#undef OHOS_ARCH_LITE
    pStaStateMachine->pApLinkedState->pStaStateMachine->m_instId = INSTID_WLAN0;
    pStaStateMachine->m_NetWorkState = sptr<NetStateObserver>(new (std::nothrow)NetStateObserver());
    pStaStateMachine->pApLinkedState->GoInState();
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);

    pStaStateMachine->pApLinkedState->pStaStateMachine->m_instId = INSTID_WLAN1;
    pStaStateMachine->pApLinkedState->GoInState();
#endif
}

HWTEST_F(StaStateMachineTest, StartDisConnectToNetworkTest01, TestSize.Level1)
{
    MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_OK);
    pStaStateMachine->StartDisConnectToNetwork();
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, StartDisConnectToNetworkTest02, TestSize.Level1)
{
    MockWifiStaHalInterface::GetInstance().SetRetResult(WIFI_HAL_OPT_FAILED);
    pStaStateMachine->StartDisConnectToNetwork();
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, RegisterDhcpCallBackTest01, TestSize.Level1)
{
    EXPECT_NE(pStaStateMachine->RegisterDhcpCallBack(), TEN);
}

HWTEST_F(StaStateMachineTest, AfterApLinkedprocessTest01, TestSize.Level1)
{
    std::string bssid = "TEST";
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(1));
    pStaStateMachine->AfterApLinkedprocess(bssid);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, AfterApLinkedprocessTest02, TestSize.Level1)
{
    std::string bssid = "TEST";
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(0));
    pStaStateMachine->AfterApLinkedprocess(bssid);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, OnDhcpOfferTest01, TestSize.Level1)
{
    int status = 0;
    const char *ifname = nullptr;
    DhcpResult result;
    pStaStateMachine->pDhcpResultNotify->OnDhcpOffer(status, ifname, &result);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, AppendFastTransitionKeyMgmtTest01, TestSize.Level1)
{
    WifiScanInfo scanInfo;
    scanInfo.capabilities = "FT/EAP";
    WifiHalDeviceConfig halDeviceConfig;
    pStaStateMachine->AppendFastTransitionKeyMgmt(scanInfo, halDeviceConfig);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);

    scanInfo.capabilities = "FT/PSK";
    pStaStateMachine->AppendFastTransitionKeyMgmt(scanInfo, halDeviceConfig);

    scanInfo.capabilities = "FT/SAE";
    pStaStateMachine->AppendFastTransitionKeyMgmt(scanInfo, halDeviceConfig);

    scanInfo.capabilities = "TEST";
    pStaStateMachine->AppendFastTransitionKeyMgmt(scanInfo, halDeviceConfig);
}

HWTEST_F(StaStateMachineTest, ConvertDeviceCfgTest01, TestSize.Level1)
{
    WifiDeviceConfig config;
    config.ssid = "TEST";
    config.keyMgmt = "SAE";
    std::vector<WifiScanInfo> scanInfoList;
    WifiScanInfo wifiScanInfo;
    wifiScanInfo.ssid = "TEST";
    wifiScanInfo.capabilities = "PSK+SAE";
    scanInfoList.push_back(wifiScanInfo);
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->SaveScanInfoList(scanInfoList);
    pStaStateMachine->ConvertDeviceCfg(config, wifiScanInfo.ssid);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, DealCsaChannelChangedTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    pStaStateMachine->DealCsaChannelChanged(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, DealWpaStateChangeTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    pStaStateMachine->DealWpaStateChange(msg);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, FillSuiteB192CfgTest01, TestSize.Level1)
{
    WifiHalDeviceConfig halDeviceConfig;
    halDeviceConfig.keyMgmt = "WPA-EAP-SUITE-B-192";
    pStaStateMachine->FillSuiteB192Cfg(halDeviceConfig);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, InsertOrUpdateNetworkStatusHistoryTest01, TestSize.Level1)
{
    NetworkStatus networkStatus = NetworkStatus::NO_INTERNET;
    bool updatePortalAuthTime = true;
    pStaStateMachine->networkStatusHistoryInserted = true;
    pStaStateMachine->InsertOrUpdateNetworkStatusHistory(networkStatus, updatePortalAuthTime);
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, IsGoodSignalQualityTest01, TestSize.Level1)
{
    pStaStateMachine->IsGoodSignalQuality();
    EXPECT_NE(pStaStateMachine->currentTpType, TEN);
}

HWTEST_F(StaStateMachineTest, DealGetDhcpIpTimeoutTest, TestSize.Level1)
{
    InternalMessagePtr msg = nullptr;
    pStaStateMachine->pGetIpState->DealGetDhcpIpTimeout(msg);
    InternalMessagePtr msg1 = std::make_shared<InternalMessage>();
    msg1->SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT);
    pStaStateMachine->pGetIpState->DealGetDhcpIpTimeout(msg1);
}

}
}