/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#include "mock_dhcp_service.h"
#include "mock_if_config.h"
#include "mock_wifi_chip_hal_interface.h"
#include "mock_wifi_manager.h"
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"
#include "sta_define.h"
#include "define.h"
#include "sta_state_machine.h"
#include "sta_service.h"
#include "wifi_app_state_aware.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "mock_wifi_sta_hal_interface.h"
#include "mock_wifi_supplicant_hal_interface.h"
#include "mock_block_connect_service.h"
#include "wifi_history_record_manager.h"
#include "sta_define.h"
#include "wifi_telephony_utils.h"
#include "wifi_battery_utils.h"
#include "ip_qos_monitor.h"

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
static const std::string RANDOMMAC_SSID = "testwifi";
static const std::string RANDOMMAC_PASSWORD = "testwifi";
static const std::string RANDOMMAC_BSSID = "01:23:45:67:89:a0";
constexpr int TEST_FAIL_REASON = 16;
constexpr int UMTS_AUTH_TYPE_TAG = 0xdb;
constexpr int UMTS_AUTS_TYPE_TAG = 0xdc;
constexpr int WPA3_BLACKMAP_MAX_NUM = 20;
constexpr int TWO = 2;
constexpr int INVALID_RSSI1 = -128;
constexpr int INVALID_RSSI2 = 200;
constexpr int VALID_RSSI3 = -80;
constexpr int VALID_RSSI4 = 156;
constexpr int INVALID_RSSI5 = 100;
static constexpr int MAX_STR_LENT = 127;
constexpr int CHIPSET_FEATURE_CAPABILITY_WIFI6_TEST = 127;
constexpr int CHIPSET_FEATURE_CAPABILITY_WIFI7_TEST = 255;
constexpr int TEN = 10;
constexpr int MAX_NO_INTERNET_CNTS = 3;
static const std::string TEMP_TEST_DATA = "1234567890abcdef1234567890abcdef";
static std::string g_errLog;
    void StaStateMachineCallback(const LogType type, const LogLevel level,
                                 const unsigned int domain, const char *tag,
                                 const char *msg)
    {
        g_errLog = msg;
    }
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
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine.reset(new StaStateMachine());
        pStaStateMachine->InitStaStateMachine();
        pStaStateMachine->InitWifiLinkedInfo();
        ArpStateHandler arpHandle = nullptr;
        pStaStateMachine->RegisterStaServiceCallback(WifiManager::GetInstance().GetStaCallback());
        pStaService = std::make_unique<StaService>();
        LOG_SetCallback(StaStateMachineCallback);
    }
    virtual void TearDown()
    {
        pStaStateMachine.reset();
        pStaService.reset();
    }
    void SleepMs(const int sleepMs)
    {
        std::unique_lock<std::mutex> lck(mMtxBlock);
        mCvTest.wait_for(lck, std::chrono::milliseconds(sleepMs));
    }
    std::unique_ptr<StaStateMachine> pStaStateMachine;
    std::unique_ptr<StaService> pStaService;
    std::mutex mMtxBlock;
    std::condition_variable mCvTest;

    void DealConnectTimeOutCmd()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(1));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->pLinkState->DealConnectTimeOutCmd(msg);
    }

    void InitStateGoInStateSuccess()
    {
        pStaStateMachine->pInitState->GoInState();
    }

    void InitStateGoOutStateSuccess()
    {
        pStaStateMachine->pInitState->GoOutState();
    }

    void ClosedStateExeMsgSuccess()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), ReloadDeviceConfig()).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_ENABLE_STA);
        EXPECT_TRUE(pStaStateMachine->pClosedState->ExecuteStateMsg(msg));
    }

    void CLosedStateExeMsgFail1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_DISABLE_STA);
        EXPECT_TRUE(pStaStateMachine->pClosedState->ExecuteStateMsg(msg));
    }

    void InitStateExeMsgFail2()
    {
        EXPECT_FALSE(pStaStateMachine->pInitState->ExecuteStateMsg(nullptr));
    }

    void ConvertDeviceCfgSuccess()
    {
        WifiDeviceConfig config;
        config.keyMgmt = "WEP";
        std::string apBssid = RANDOMMAC_BSSID;
        std::string ifname = "wlan0";
        EXPECT_EQ(WIFI_OPT_SUCCESS, pStaStateMachine->ConvertDeviceCfg(config, apBssid, ifname));
    }

    void ConvertDeviceCfgFail1()
    {
        WifiDeviceConfig config;
        std::string apBssid = RANDOMMAC_BSSID;
        std::string ifname = "wlan0";
        EXPECT_EQ(WIFI_OPT_SUCCESS, pStaStateMachine->ConvertDeviceCfg(config, apBssid, ifname));
    }

    void ConvertDeviceCfgFail2()
    {
        WifiDeviceConfig config;
        std::string apBssid = RANDOMMAC_BSSID;
        std::string ifname = "wlan0";
        EXPECT_EQ(WIFI_OPT_SUCCESS, pStaStateMachine->ConvertDeviceCfg(config, apBssid, ifname));
    }

    void ConvertDeviceCfgFail3() const
    {
        WifiDeviceConfig config;
        std::string apBssid = "";
        std::string ifname = "wlan0";
        EXPECT_EQ(WIFI_OPT_SUCCESS, pStaStateMachine->ConvertDeviceCfg(config, apBssid, ifname));
    }

    void StartWifiProcessSuccess()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _)).Times(testing::AtLeast(1));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), ReloadDeviceConfig()).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        WifiDeviceConfig wifiDeviceConfig;
        std::vector<WifiDeviceConfig> results;
        wifiDeviceConfig.networkId = 1;
        results.push_back(wifiDeviceConfig);
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(results), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), SetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->pClosedState->StartWifiProcess();
    }

    void StartWifiProcessFail2()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _)).Times(testing::AtLeast(1));
        EXPECT_CALL(WifiSettings::GetInstance(), SetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->pClosedState->StartWifiProcess();
    }

    void StartWifiProcessFail1()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), ReloadDeviceConfig()).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        WifiDeviceConfig wifiDeviceConfig;
        std::vector<WifiDeviceConfig> results;
        wifiDeviceConfig.networkId = 1;
        results.push_back(wifiDeviceConfig);
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(results), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), SetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->pClosedState->StartWifiProcess();
    }

    void StopWifiProcessSuccess1()
    {
        pStaStateMachine->currentTpType = IPTYPE_IPV4;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaCloseRes(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->pClosedState->StopWifiProcess();
    }

    void StopWifiProcessSuccess2()
    {
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaCloseRes(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->pClosedState->StopWifiProcess();
    }

    void StopWifiProcessSuccess3()
    {
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaCloseRes(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->pClosedState->StopWifiProcess();
    }

    void StopWifiProcessFail()
    {
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaCloseRes(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->pClosedState->StopWifiProcess();
    }

    void InitStaSMHandleMapSuccess()
    {
        EXPECT_EQ(WIFI_OPT_SUCCESS, pStaStateMachine->pLinkState->InitStaSMHandleMap());
    }

    void DealConnectTimeOutCmdSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        pStaStateMachine->pLinkState->DealConnectTimeOutCmd(msg);
    }

    void DealConnectTimeOutCmdFail()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->pLinkState->DealConnectTimeOutCmd(nullptr);
        pStaStateMachine->pLinkState->DealConnectTimeOutCmd(msg);
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
        msg->SetMessageName(WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT);
        pStaStateMachine->pApLinkingState->DealWpaLinkFailEvent(msg);
        pStaStateMachine->pApLinkingState->DealWpaLinkFailEvent(nullptr);
    }

    void DealWpaWrongPskEventFail2()
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

    void DealReassociateCmdSuccess()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        pStaStateMachine->DealReassociateCmd(msg);
    }

    void DealReassociateCmdFail1()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        pStaStateMachine->DealReassociateCmd(nullptr);
    }

    void DealReassociateCmdFail2()
    {
        pStaStateMachine->DealReassociateCmd(nullptr);
    }

    void StartConnectToNetworkSuccess()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StartConnectToNetwork(0, "wifitest/123", 0);
    }

    void StartConnectToNetworkSuccess2()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StartConnectToNetwork(0, "wifitest/123", NETWORK_SELECTED_BY_FAST_RECONNECT);
    }

    void StartConnectToNetworkFail1()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(1));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        EXPECT_TRUE(pStaStateMachine->StartConnectToNetwork(0, "wifitest/123", 0) == WIFI_OPT_FAILED);
    }

    void StartConnectToNetworkFail4()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(1));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        EXPECT_TRUE(pStaStateMachine->StartConnectToNetwork(0, "wifitest/123", 0) == WIFI_OPT_FAILED);
    }

    void StartConnectToNetworkFali3()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StartConnectToNetwork(0, "wifitest/123", 0);
    }

    void SetRandomMacSuccess1()
    {
        WifiDeviceConfig deviceConfig;
        deviceConfig.wifiPrivacySetting = WifiPrivacyConfig::DEVICEMAC ;
        deviceConfig.keyMgmt = KEY_MGMT_WPA_PSK;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(deviceConfig), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        pStaStateMachine->SetRandomMac(deviceConfig, "");
    }

    void SetRandomMacFail1()
    {
        WifiDeviceConfig deviceConfig;
        deviceConfig.wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
        deviceConfig.keyMgmt = KEY_MGMT_SAE;
        WifiStoreRandomMac randomMacInfo;
        randomMacInfo.ssid = RANDOMMAC_SSID;
        randomMacInfo.keyMgmt = KEY_MGMT_WEP;
        randomMacInfo.preSharedKey = RANDOMMAC_PASSWORD;
        randomMacInfo.peerBssid = RANDOMMAC_BSSID;
        pStaStateMachine->MacAddressGenerate(randomMacInfo);
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(deviceConfig), Return(-1)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        pStaStateMachine->SetRandomMac(deviceConfig, "");
    }

    void SetRandomMacFail2()
    {
        WifiDeviceConfig deviceConfig;
        deviceConfig.wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(deviceConfig), Return(0)));
        std::string MacAddress = RANDOMMAC_SSID;
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).
            WillRepeatedly(DoAll(SetArgReferee<0>(MacAddress), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        pStaStateMachine->SetRandomMac(deviceConfig, "");
    }

    void StartConnectToBssidSuccess()
    {
        pStaStateMachine->StartConnectToBssid(0, "a2:b1:f5:c7:d1");
    }

    void SeparatedStateGoInStateSuccess()
    {
        pStaStateMachine->pSeparatedState->GoInState();
    }

    void SeparatedStateGoOutStateSuccess()
    {
        pStaStateMachine->pSeparatedState->GoOutState();
    }

    void TryToSaveIpV4ResultHostnameMatchTest()
    {
        IpInfo ipInfo;
        IpV6Info ipv6Info;
        DhcpResult result;
        
        // 测试所有条件满足的情况：包含hostname、IP匹配172.20.10.、掩码>=24
        memset_s(&result, sizeof(result), 0, sizeof(result));
        result.iptype = 0; // IPv4
        
        if (snprintf_s(result.strOptVendor, sizeof(result.strOptVendor), sizeof(result.strOptVendor) - 1,
                "%s", "hostname:TestHost") < 0) {
            return;
        }
        
        if (snprintf_s(result.strOptClientId, sizeof(result.strOptClientId), sizeof(result.strOptClientId) - 1,
                "%s", "172.20.10.100") < 0) {
            return;
        }
        
        if (snprintf_s(result.strOptSubnet, sizeof(result.strOptSubnet), sizeof(result.strOptSubnet) - 1,
                "%s", "255.255.255.0") < 0) {
            return;
        }
        
        if (snprintf_s(result.strOptRouter1, sizeof(result.strOptRouter1), sizeof(result.strOptRouter1) - 1,
                "%s", "172.20.10.1") < 0) {
            return;
        }
        
        pStaStateMachine->linkedInfo.isDataRestricted = 0;
        pStaStateMachine->pDhcpResultNotify->TryToSaveIpV4Result(ipInfo, ipv6Info, &result);
        EXPECT_EQ(pStaStateMachine->linkedInfo.isDataRestricted, 1);
    }

    void TryToSaveIpV4ResultHostnameNoMatchTest()
    {
        IpInfo ipInfo;
        IpV6Info ipv6Info;
        DhcpResult result;
        
        // 测试不包含hostname的情况
        memset_s(&result, sizeof(result), 0, sizeof(result));
        result.iptype = 0; // IPv4
        
        if (snprintf_s(result.strOptVendor, sizeof(result.strOptVendor), sizeof(result.strOptVendor) - 1,
                "%s", "test vendor string") < 0) {
            return;
        }
        
        if (snprintf_s(result.strOptClientId, sizeof(result.strOptClientId), sizeof(result.strOptClientId) - 1,
                "%s", "172.20.10.100") < 0) {
            return;
        }
        
        if (snprintf_s(result.strOptSubnet, sizeof(result.strOptSubnet), sizeof(result.strOptSubnet) - 1,
                "%s", "255.255.255.0") < 0) {
            return;
        }
        
        if (snprintf_s(result.strOptRouter1, sizeof(result.strOptRouter1), sizeof(result.strOptRouter1) - 1,
                "%s", "172.20.10.1") < 0) {
            return;
        }
        
        pStaStateMachine->linkedInfo.isDataRestricted = 0;
        pStaStateMachine->pDhcpResultNotify->TryToSaveIpV4Result(ipInfo, ipv6Info, &result);
        EXPECT_EQ(pStaStateMachine->linkedInfo.isDataRestricted, 0);
    }

    void TryToSaveIpV4ResultIpNoMatchTest()
    {
        IpInfo ipInfo;
        IpV6Info ipv6Info;
        DhcpResult result;
        
        // 测试IP不匹配172.20.10.的情况
        memset_s(&result, sizeof(result), 0, sizeof(result));
        result.iptype = 0; // IPv4
        
        if (snprintf_s(result.strOptVendor, sizeof(result.strOptVendor), sizeof(result.strOptVendor) - 1,
                "%s", "hostname:TestHost") < 0) {
            return;
        }
        
        if (snprintf_s(result.strOptClientId, sizeof(result.strOptClientId), sizeof(result.strOptClientId) - 1,
                "%s", "192.168.1.100") < 0) {
            return;
        }
        
        if (snprintf_s(result.strOptSubnet, sizeof(result.strOptSubnet), sizeof(result.strOptSubnet) - 1,
                "%s", "255.255.255.0") < 0) {
            return;
        }
        
        if (snprintf_s(result.strOptRouter1, sizeof(result.strOptRouter1), sizeof(result.strOptRouter1) - 1,
                "%s", "192.168.1.1") < 0) {
            return;
        }
        
        pStaStateMachine->linkedInfo.isDataRestricted = 0;
        pStaStateMachine->pDhcpResultNotify->TryToSaveIpV4Result(ipInfo, ipv6Info, &result);
        EXPECT_EQ(pStaStateMachine->linkedInfo.isDataRestricted, 0);
    }

    void TryToSaveIpV4ResultMaskNoMatchTest()
    {
        IpInfo ipInfo;
        IpV6Info ipv6Info;
        DhcpResult result;
        
        // 测试掩码长度<24的情况
        memset_s(&result, sizeof(result), 0, sizeof(result));
        result.iptype = 0; // IPv4
        
        if (snprintf_s(result.strOptVendor, sizeof(result.strOptVendor), sizeof(result.strOptVendor) - 1,
                "%s", "hostname:TestHost") < 0) {
            return;
        }

        if (snprintf_s(result.strOptClientId, sizeof(result.strOptClientId), sizeof(result.strOptClientId) - 1,
                "%s", "172.20.10.100") < 0) {
            return;
        }
        
        if (snprintf_s(result.strOptSubnet, sizeof(result.strOptSubnet), sizeof(result.strOptSubnet) - 1,
                "%s", "255.255.254.0") < 0) {
            return;
        }
        
        if (snprintf_s(result.strOptRouter1, sizeof(result.strOptRouter1), sizeof(result.strOptRouter1) - 1,
                "%s", "172.20.10.1") < 0) {
            return;
        }
        
        pStaStateMachine->linkedInfo.isDataRestricted = 0;
        pStaStateMachine->pDhcpResultNotify->TryToSaveIpV4Result(ipInfo, ipv6Info, &result);
        EXPECT_EQ(pStaStateMachine->linkedInfo.isDataRestricted, 0);
    }

    void SeparatedStateExeMsgSuccess1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT);
        EXPECT_TRUE(pStaStateMachine->pSeparatedState->ExecuteStateMsg(msg));
    }

    void SeparatedStateExeMsgSuccess2()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_ENABLE_STA);
        EXPECT_TRUE(pStaStateMachine->pSeparatedState->ExecuteStateMsg(msg));
    }

    void SeparatedStateExeMsgFail()
    {
        EXPECT_FALSE(pStaStateMachine->pSeparatedState->ExecuteStateMsg(nullptr));
    }

    void DealReConnectCmdSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTING;
        pStaStateMachine->pLinkedState->DealNetworkCheck(msg);
        pStaStateMachine->pLinkedState->DealNetworkCheck(nullptr);
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceConnFailedCount(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), IncreaseDeviceConnFailedCount(_, _, _)).Times(testing::AtLeast(0));
        pStaStateMachine->pSeparatedState->DealReConnectCmdInSeparatedState(msg);
    }

    void DealReConnectCmdFail()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->pSeparatedState->DealReConnectCmdInSeparatedState(msg);
        pStaStateMachine->pSeparatedState->DealReConnectCmdInSeparatedState(nullptr);
    }

    void ApLinkedStateGoInStateSuccess()
    {
        pStaStateMachine->pApLinkedState->GoInState();
    }

    void ApLinkedStateGoOutStateSuccess()
    {
        pStaStateMachine->pApLinkedState->GoOutState();
    }

    void ApLinkedStateExeMsgSuccess1()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(1));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_DISCONNECT);
        EXPECT_TRUE(pStaStateMachine->pApLinkedState->ExecuteStateMsg(msg));
    }

    void ApLinkedStateExeMsgSuccess2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT);
        EXPECT_TRUE(pStaStateMachine->pApLinkedState->ExecuteStateMsg(msg));
    }

    void ApLinkedStateExeMsgFail1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
        EXPECT_TRUE(pStaStateMachine->pApLinkedState->ExecuteStateMsg(msg));
    }

    void ApLinkedStateExeMsgFai2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(CMD_SIGNAL_POLL);
        EXPECT_TRUE(pStaStateMachine->pApLinkedState->ExecuteStateMsg(msg));
        EXPECT_FALSE(pStaStateMachine->pApLinkedState->ExecuteStateMsg(nullptr));
    }

    void ApLinkedStateExeMsgSuccess3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT);
        pStaStateMachine->pApLinkedState->ExecuteStateMsg(msg);
    }

    void ApLinkedStateExeMsgSuccess4()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(0);
        pStaStateMachine->pApLinkedState->ExecuteStateMsg(msg);
    }

    void ApLinkedStateExeMsgLinkSwitch()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_LINK_SWITCH_EVENT);
        msg->AddStringMessageBody("wifitest");
        pStaStateMachine->pApLinkedState->ExecuteStateMsg(msg);
    }

    void DealStartRoamCmdInApLinkedStateSuccess()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->pApLinkedState->DealStartRoamCmdInApLinkedState(msg);
    }

    void DealStartRoamCmdInApLinkedStateFail1()
    {
        pStaStateMachine->pApLinkedState->DealStartRoamCmdInApLinkedState(nullptr);
    }

    void DealStartRoamCmdInApLinkedStateFail2()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->pApLinkedState->DealStartRoamCmdInApLinkedState(msg);
    }

    void DealStartRoamCmdInApLinkedStateFail3()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->pApLinkedState->DealStartRoamCmdInApLinkedState(msg);
    }

    void StartDisConnectToNetworkSuccess()
    {
        pStaStateMachine->StartDisConnectToNetwork();
    }

    void StartDisConnectToNetworkFail()
    {
        pStaStateMachine->StartDisConnectToNetwork();
    }

    void GetIpStateStateGoInStateSuccess1()
    {
        WifiDeviceConfig config;
        config.wifiProxyconfig.configureMethod = ConfigureProxyMethod::MANUALCONFIGUE;
        config.wifiIpConfig.assignMethod = AssignIpMethod::STATIC;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
        pStaStateMachine->pGetIpState->GoInState();
    }

    void GetIpStateStateGoInStateSuccess2()
    {
        pStaStateMachine->isRoam = true;
        WifiDeviceConfig config;
        config.wifiProxyconfig.configureMethod = ConfigureProxyMethod::MANUALCONFIGUE;
        config.wifiIpConfig.assignMethod = AssignIpMethod::DHCP;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDhcpIpType(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
        pStaStateMachine->enhanceService_ = nullptr;
        pStaStateMachine->pGetIpState->GoInState();
    }

    void GetIpStateStateGoInStateSuccess3()
    {
        pStaStateMachine->isRoam = false;
        WifiDeviceConfig config;
        config.wifiProxyconfig.configureMethod = ConfigureProxyMethod::MANUALCONFIGUE;
        config.wifiIpConfig.assignMethod = AssignIpMethod::DHCP;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDhcpIpType(_)).WillRepeatedly(Return(IPTYPE_IPV4));
        pStaStateMachine->enhanceService_ = nullptr;
        pStaStateMachine->pGetIpState->GoInState();
    }

    void GetIpStateStateGoOutStateSuccess()
    {
        pStaStateMachine->pGetIpState->GoOutState();
    }

    void GetIpStateStateExeMsgSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(DHCP_RESULT);
        msg->SetParam2(0);
        msg->SetMessageName(WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT);
        StaStateMachine staStateMachine;
        pStaStateMachine->pGetIpState->pStaStateMachine = &staStateMachine;
        pStaStateMachine->pGetIpState->pStaStateMachine->pDhcpResultNotify
            = new StaStateMachine::DhcpResultNotify(&staStateMachine);
        pStaStateMachine->pGetIpState->pStaStateMachine->pDhcpResultNotify->pStaStateMachine = &staStateMachine;
        pStaStateMachine->pGetIpState->ExecuteStateMsg(msg);
        if (pStaStateMachine->pGetIpState->pStaStateMachine->pDhcpResultNotify != nullptr) {
            delete pStaStateMachine->pGetIpState->pStaStateMachine->pDhcpResultNotify;
            pStaStateMachine->pGetIpState->pStaStateMachine->pDhcpResultNotify = nullptr;
        }
    }

    void GetIpStateStateExeMsgFail()
    {
        EXPECT_CALL(BlockConnectService::GetInstance(),
        UpdateNetworkSelectStatus(_, _, _))
        .WillRepeatedly(Return(-1));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        StaStateMachine staStateMachine;
        pStaStateMachine->pGetIpState->pStaStateMachine = &staStateMachine;
        pStaStateMachine->pGetIpState->pStaStateMachine->pDhcpResultNotify
            = new StaStateMachine::DhcpResultNotify(&staStateMachine);
        pStaStateMachine->pGetIpState->pStaStateMachine->pDhcpResultNotify->pStaStateMachine = &staStateMachine;
        msg->SetMessageName(WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT);
        msg->SetParam1(DHCP_JUMP);
        pStaStateMachine->pGetIpState->ExecuteStateMsg(msg);
        msg->SetParam1(DHCP_FAIL);
        pStaStateMachine->pGetIpState->ExecuteStateMsg(msg);
        msg->SetParam1(DHCP_OFFER_REPORT);
        pStaStateMachine->pGetIpState->ExecuteStateMsg(msg);
        msg->SetParam1(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
        pStaStateMachine->pGetIpState->ExecuteStateMsg(msg);
        pStaStateMachine->pGetIpState->ExecuteStateMsg(nullptr);
        if (pStaStateMachine->pGetIpState->pStaStateMachine->pDhcpResultNotify != nullptr) {
            delete pStaStateMachine->pGetIpState->pStaStateMachine->pDhcpResultNotify;
            pStaStateMachine->pGetIpState->pStaStateMachine->pDhcpResultNotify = nullptr;
        }
    }

    void GetIpStateStateIsPublicESSTest()
    {
        std::vector<WifiScanInfo> scanResults;
        WifiScanInfo scanInfo;
        scanInfo.ssid = "1234";
        scanResults.push_back(scanInfo);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).
            WillRepeatedly(DoAll(SetArgReferee<0>(scanResults), Return(0)));
        WifiLinkedInfo linkedInfo;
        linkedInfo.ssid = "1234";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).
            WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pStaStateMachine->pGetIpState->IsPublicESS();
    }

    void ConfigStaticIpAddressSuccess1()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_IPV4;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        ;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressSuccess2()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressSuccess3()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_MIX;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressFail()
    {
        pStaStateMachine->currentTpType = IPTYPE_BUTT;
        StaticIpAddress staticIpAddress;
        pStaStateMachine->isRoam = false;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_FALSE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void HandleNetCheckResultSuccess1()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(TWO);
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_IS_WORKING, "");
    }

    void HandleNetCheckResultSuccess3()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(TWO);
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_IS_PORTAL, "");
    }
    void HandleNetCheckResultSuccess4()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(TWO);
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_NOTWORKING, "");
    }

    void HandleNetCheckResultSuccess5()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(TWO);
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->lastCheckNetState_ = OperateResState::CONNECT_CHECK_PORTAL;
        pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_IS_PORTAL, "");
    }
    
    void HandleNetCheckResultTxRxGoodButNoInternetFalseTest() const
    {
        IpQosMonitor::GetInstance().lastTxRxGood_ = false;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).WillRepeatedly(Return(MODE_STATE_OPEN));
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
 
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(1));
        pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_NOTWORKING, "");
    }

    void HandleNetCheckResultFail()
    {
        pStaStateMachine->linkedInfo.connState = ConnState::DISCONNECTED;
        pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_NOTWORKING, "");
    }

    void TestHandleNetCheckResultIsPortal1()
    {
        // test hilink and not open
        WifiLinkedInfo linkedInfo1;
        linkedInfo1.isHiLinkNetwork = 1;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).
            WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo1), Return(0)));
        WifiDeviceConfig wifiDeviceConfig1;
        wifiDeviceConfig1.networkStatusHistory = 149;  // 149: convert to binary 10010101
        wifiDeviceConfig1.keyMgmt = KEY_MGMT_WPA_PSK;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).
            WillRepeatedly(DoAll(SetArgReferee<1>(wifiDeviceConfig1), Return(0)));
        pStaStateMachine->HandleNetCheckResultIsPortal(SystemNetWorkState::NETWORK_IS_WORKING, false);

        pStaStateMachine->mIsWifiInternetCHRFlag = true;
        pStaStateMachine->HandleNetCheckResultIsPortal(SystemNetWorkState::NETWORK_IS_WORKING, false);
        // tet not hilink and open
        WifiLinkedInfo linkedInfo2;
        linkedInfo1.isHiLinkNetwork = 0;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).
            WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo2), Return(0)));
        WifiDeviceConfig wifiDeviceConfig2;
        wifiDeviceConfig2.networkStatusHistory = 149;  // 149: convert to binary 10010101
        wifiDeviceConfig2.keyMgmt = KEY_MGMT_NONE;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).
            WillRepeatedly(DoAll(SetArgReferee<1>(wifiDeviceConfig2), Return(0)));
        pStaStateMachine->HandleNetCheckResultIsPortal(SystemNetWorkState::NETWORK_IS_WORKING, false);
    }

    void TestTryModifyPortalAttribute1()
    {
        pStaStateMachine->linkedInfo.networkId = INVALID_NETWORK_ID;
        pStaStateMachine->TryModifyPortalAttribute(SystemNetWorkState::NETWORK_NOTWORKING);

        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillOnce(Return(-1));
        pStaStateMachine->TryModifyPortalAttribute(SystemNetWorkState::NETWORK_NOTWORKING);
    }

    void TestTryModifyPortalAttribute2()
    {
        // SystemNetWorkState::NETWORK_NOTWORKING
        WifiDeviceConfig wifiDeviceConfig1;
        wifiDeviceConfig1.networkStatusHistory = 149;  // 149: convert to binary 10010101
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).
            WillRepeatedly(DoAll(SetArgReferee<1>(wifiDeviceConfig1), Return(0)));
        pStaStateMachine->TryModifyPortalAttribute(SystemNetWorkState::NETWORK_NOTWORKING);

        WifiDeviceConfig wifiDeviceConfig2;
        wifiDeviceConfig2.networkStatusHistory = 21;  // 21: convert to binary 010101
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).
            WillRepeatedly(DoAll(SetArgReferee<1>(wifiDeviceConfig2), Return(0)));
        pStaStateMachine->TryModifyPortalAttribute(SystemNetWorkState::NETWORK_NOTWORKING);
    }

    void TestTryModifyPortalAttribute3()
    {
        // SystemNetWorkState::NETWORK_IS_WORKING
        WifiDeviceConfig wifiDeviceConfig3;
        wifiDeviceConfig3.networkStatusHistory = 149;  // 149: convert to binary 10010101
        wifiDeviceConfig3.keyMgmt = KEY_MGMT_NONE;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).
            WillRepeatedly(DoAll(SetArgReferee<1>(wifiDeviceConfig3), Return(0)));
        pStaStateMachine->TryModifyPortalAttribute(SystemNetWorkState::NETWORK_IS_WORKING);

        WifiDeviceConfig wifiDeviceConfig4;
        wifiDeviceConfig4.networkStatusHistory = 149;  // 149: convert to binary 10010101
        wifiDeviceConfig4.keyMgmt = KEY_MGMT_WPA_PSK;
        pStaStateMachine->linkedInfo.isHiLinkNetwork = false;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).
            WillRepeatedly(DoAll(SetArgReferee<1>(wifiDeviceConfig4), Return(0)));
        pStaStateMachine->TryModifyPortalAttribute(SystemNetWorkState::NETWORK_IS_WORKING);

        WifiDeviceConfig wifiDeviceConfig5;
        wifiDeviceConfig5.networkStatusHistory = 149;  // 149: convert to binary 10010101
        wifiDeviceConfig5.keyMgmt = KEY_MGMT_WPA_PSK;
        pStaStateMachine->linkedInfo.isHiLinkNetwork = true;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).
            WillRepeatedly(DoAll(SetArgReferee<1>(wifiDeviceConfig5), Return(0)));
        pStaStateMachine->TryModifyPortalAttribute(SystemNetWorkState::NETWORK_IS_WORKING);

        WifiDeviceConfig wifiDeviceConfig6;
        wifiDeviceConfig6.networkStatusHistory = 21;  // 21: convert to binary 010101
        wifiDeviceConfig6.keyMgmt = KEY_MGMT_WPA_PSK;
        pStaStateMachine->linkedInfo.isHiLinkNetwork = true;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).
            WillRepeatedly(DoAll(SetArgReferee<1>(wifiDeviceConfig6), Return(0)));
        pStaStateMachine->TryModifyPortalAttribute(SystemNetWorkState::NETWORK_IS_WORKING);
    }

    void TestTryModifyPortalAttribute4()
    {
        // SystemNetWorkState::NETWORK_IS_PORTAL
        WifiDeviceConfig wifiDeviceConfig7;
        wifiDeviceConfig7.networkStatusHistory = 21;  // 21: convert to binary 010101
        wifiDeviceConfig7.keyMgmt = KEY_MGMT_WPA_PSK;
        pStaStateMachine->linkedInfo.isHiLinkNetwork = false;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).
            WillRepeatedly(DoAll(SetArgReferee<1>(wifiDeviceConfig7), Return(0)));
        pStaStateMachine->TryModifyPortalAttribute(SystemNetWorkState::NETWORK_IS_PORTAL);

        WifiDeviceConfig wifiDeviceConfig8;
        wifiDeviceConfig8.networkStatusHistory = 21;  // 21: convert to binary 010101
        wifiDeviceConfig8.keyMgmt = KEY_MGMT_WPA_PSK;
        pStaStateMachine->linkedInfo.isHiLinkNetwork = true;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).
            WillRepeatedly(DoAll(SetArgReferee<1>(wifiDeviceConfig8), Return(0)));
        pStaStateMachine->TryModifyPortalAttribute(SystemNetWorkState::NETWORK_IS_PORTAL);
    }
 
    void TestChangePortalAttribute()
    {
        WifiDeviceConfig config1;
        pStaStateMachine->ChangePortalAttribute(false, config1);
 
        WifiDeviceConfig config2;
        pStaStateMachine->ChangePortalAttribute(true, config2);
    }

    void TestUpdatePortalState(std::map<PortalState, PortalState> &map, SystemNetWorkState netState)
    {
        bool updatePortalAuthTime = false;
        for (auto& pair : map) {
            auto initState = pair.first;
            auto expectState = pair.second;

            pStaStateMachine->portalState = initState;
            pStaStateMachine->UpdatePortalState(netState, updatePortalAuthTime);
            EXPECT_EQ(pStaStateMachine->portalState, expectState);
        }
    }

    void LinkedStateGoOutStateSuccess()
    {
        pStaStateMachine->pLinkedState->GoOutState();
    }

    void LinkedStateExeMsgSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
        msg->AddStringMessageBody("ASSOC_COMPLETE");
        pStaStateMachine->pLinkedState->ExecuteStateMsg(msg);
    }

    void LinkedStateExeMsgFail4()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_SIGNAL_POLL);
        msg->AddStringMessageBody("hello");
        pStaStateMachine->pLinkedState->ExecuteStateMsg(msg);
    }

    void LinkedStateExeMsgFail3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
        msg->AddStringMessageBody("ASSOC_COMPLETE");
        pStaStateMachine->pLinkedState->ExecuteStateMsg(msg);
    }

    void LinkedStateExeMsgFail2()
    {
        IpInfo ipInfo;
        IpV6Info ipv6Info;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipv6Info), Return(0)));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(0);
        msg->SetParam1(DhcpReturnCode::DHCP_IP_EXPIRED);
        pStaStateMachine->pLinkedState->ExecuteStateMsg(msg);
        msg->SetMessageName(WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT);
        pStaStateMachine->pLinkedState->ExecuteStateMsg(msg);
        pStaStateMachine->linkedInfo.connState = ConnState::DISCONNECTED;
        msg->SetMessageName(WIFI_SVR_CMD_STA_PORTAL_BROWSE_NOTIFY_EVENT);
        pStaStateMachine->pLinkedState->ExecuteStateMsg(msg);
    }

    void LinkedStateExeMsgFail()
    {
        pStaStateMachine->pLinkedState->ExecuteStateMsg(nullptr);
    }

    void LinkedStateCheckIfRestoreWifiSuccess()
    {
        pStaStateMachine->pLinkedState->CheckIfRestoreWifi();
        EXPECT_NE(pStaStateMachine->linkedInfo.networkId, TEN);
    }
 
    void ApRoamingStateGoInStateSuccess()
    {
        pStaStateMachine->pApRoamingState->GoInState();
    }

    void ApRoamingStateGoOutStateSuccess()
    {
        pStaStateMachine->pApRoamingState->GoOutState();
    }

    void ApRoamingStateExeMsgSuccess()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT);
        EXPECT_TRUE(pStaStateMachine->pApRoamingState->ExecuteStateMsg(msg));
    }

    void ApRoamingStateExeMsgFail()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_ERROR);
        EXPECT_FALSE(pStaStateMachine->pApRoamingState->ExecuteStateMsg(nullptr));
        EXPECT_FALSE(pStaStateMachine->pApRoamingState->ExecuteStateMsg(msg));
    }

    void AfterApLinkedprocessSuccess1()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(-1));
        WifiHalGetDeviceConfig config;
        config.value = "hmwifi";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        std::string bssid = "wifitest";
        pStaStateMachine->AfterApLinkedprocess(bssid);
    }

    void AfterApLinkedprocessSuccess2()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(0));
        WifiHalGetDeviceConfig config;
        config.value = "hmwifi";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        std::string bssid = "wifitest";
        pStaStateMachine->AfterApLinkedprocess(bssid);
        EXPECT_NE(pStaStateMachine->linkedInfo.networkId, TEN);
    }

    void DhcpResultNotifyOnSuccessTest()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::CONNECTED;
        pStaStateMachine->isRoam = false;
        IpInfo ipInfo;
        ipInfo.ipAddress = IpTools::ConvertIpv4Address("192.168.0.2");
        ipInfo.gateway = IpTools::ConvertIpv4Address("192.168.0.1");
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _)).Times(testing::AtLeast(0));
    }

    void DhcpResultNotifyOnSuccessTest1()
    {
        std::string ifname = "wlan0";
        DhcpResult result;
        pStaStateMachine->pDhcpResultNotify->OnSuccess(0, nullptr, &result);
        pStaStateMachine->pDhcpResultNotify->OnSuccess(0, ifname.c_str(), nullptr);
        pStaStateMachine->pDhcpResultNotify->OnSuccess(0, ifname.c_str(), &result);
    }

    void DhcpResultNotifyOnFailedTest1()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::CONNECTED;
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _)).Times(testing::AtLeast(0));
        std::string ifname = "wlan0";
        std::string reason = "test";
        pStaStateMachine->pDhcpResultNotify->OnFailed(0, ifname.c_str(), reason.c_str());
    }

    void DhcpResultNotifyOnFailedTest2()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::DISCONNECTING;
        pStaStateMachine->isRoam = false;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _)).Times(testing::AtLeast(0));
        std::string ifname = "wlan1";
        std::string reason = "test";
        pStaStateMachine->pDhcpResultNotify->OnFailed(DHCP_RENEW_FAILED, ifname.c_str(), reason.c_str());
    }

    void DhcpResultNotifyOnFailedTest3()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::DISCONNECTED;
        pStaStateMachine->isRoam = true;
        std::string ifname = "wlan1";
        std::string reason = "test";
        pStaStateMachine->pDhcpResultNotify->OnFailed(DHCP_LEASE_EXPIRED, ifname.c_str(), reason.c_str());
        EXPECT_NE(pStaStateMachine->linkedInfo.networkId, TEN);
    }

    void DhcpResultNotifyEventTest()
    {
        pStaStateMachine->pDhcpResultNotify->DhcpResultNotifyEvent(DhcpReturnCode::DHCP_RENEW_FAIL);
    }

    void SaveLinkstateSuccess()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->SaveLinkstate(ConnState::CONNECTED, DetailedState::CONNECTED);
    }

    void ConvertFreqToChannelTest()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillOnce(Return(1));
        pStaStateMachine->ConvertFreqToChannel();
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        pStaStateMachine->linkedInfo.frequency = FREQ_2G_MIN;
        pStaStateMachine->ConvertFreqToChannel();

        pStaStateMachine->linkedInfo.frequency = FREQ_2G_MAX;
        pStaStateMachine->ConvertFreqToChannel();

        pStaStateMachine->linkedInfo.frequency = CHANNEL_14_FREQ;
        pStaStateMachine->ConvertFreqToChannel();

        pStaStateMachine->linkedInfo.frequency = FREQ_5G_MIN;
        pStaStateMachine->ConvertFreqToChannel();
    }

    void LinkStateGoInStateSuccess()
    {
        pStaStateMachine->pLinkState->GoInState();
    }

    void LinkStateGoOutStateSuccess()
    {
        pStaStateMachine->pLinkState->GoOutState();
    }

    void LinkStateExeMsgSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->pLinkState->ExecuteStateMsg(msg);
    }

    void LinkStateExeMsgFail()
    {
        EXPECT_FALSE(pStaStateMachine->pLinkState->ExecuteStateMsg(nullptr));
    }

    void UpdateExpandOffsetRange()
    {
        const int rssiThreshold = 7;
        const int halfFoldRssiValue = 2;
        pStaStateMachine->pLinkedState->isExpandUpdateRssi_ = false;
        pStaStateMachine->linkedInfo.rssi = rssiThreshold;
        pStaStateMachine->foldStatus_ = EXPAND;
        pStaStateMachine->pLinkedState->halfFoldRssi_ = halfFoldRssiValue;
        pStaStateMachine->pLinkedState->UpdateExpandOffset();
        EXPECT_EQ(pStaStateMachine->pLinkedState->rssiOffset_, RSSI_OFFSET_DEFAULT);
    }

    void UpdateExpandOffsetMin()
    {
        const int halfFoldRssiValue = 2;
        const int rssiThreshold = 1;
        pStaStateMachine->pLinkedState->isExpandUpdateRssi_ = false;
        pStaStateMachine->linkedInfo.rssi = rssiThreshold;
        pStaStateMachine->foldStatus_ = EXPAND;
        pStaStateMachine->pLinkedState->halfFoldRssi_ = halfFoldRssiValue;
        pStaStateMachine->pLinkedState->UpdateExpandOffset();
        EXPECT_NE(pStaStateMachine->pLinkedState->rssiOffset_, RSSI_OFFSET_DEFAULT);
    }

    void UpdateExpandOffsetDefault()
    {
        const int rssiThreshold = 5;
        const int halfFoldRssiValue = 2;
        const int rssiExpected = 3;
        pStaStateMachine->pLinkedState->isExpandUpdateRssi_ = false;
        pStaStateMachine->linkedInfo.rssi = rssiThreshold;
        pStaStateMachine->foldStatus_ = EXPAND;
        pStaStateMachine->pLinkedState->halfFoldRssi_ = halfFoldRssiValue;
        pStaStateMachine->pLinkedState->UpdateExpandOffset();
        EXPECT_EQ(pStaStateMachine->pLinkedState->rssiOffset_, rssiExpected);
    }

    void UpdateExpandOffsetMax()
    {
        const int halfFoldRssiValue = 2;
        const int rssiExpected = 10;
        const int rssiThreshold = 15;
        pStaStateMachine->pLinkedState->isExpandUpdateRssi_ = false;
        pStaStateMachine->linkedInfo.rssi = rssiThreshold;
        pStaStateMachine->foldStatus_ = EXPAND;
        pStaStateMachine->pLinkedState->halfFoldRssi_ = halfFoldRssiValue;
        pStaStateMachine->pLinkedState->UpdateExpandOffset();
        EXPECT_EQ(pStaStateMachine->pLinkedState->rssiOffset_, rssiExpected);
    }

    void FoldStatusNotifyHalfFold()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(HALF_FOLD);
        pStaStateMachine->pLinkedState->FoldStatusNotify(msg);
        EXPECT_TRUE(pStaStateMachine->pLinkedState->isExpandUpdateRssi_);
        EXPECT_EQ(pStaStateMachine->foldStatus_, HALF_FOLD);
    }

    void FoldStatusNotifyExpand()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(EXPAND);
        pStaStateMachine->pLinkedState->FoldStatusNotify(msg);
        EXPECT_FALSE(pStaStateMachine->pLinkedState->isExpandUpdateRssi_);
        EXPECT_EQ(pStaStateMachine->foldStatus_, EXPAND);
    }

    void FoldStatusNotifyOtherStatus()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(FOLDED);
        pStaStateMachine->pLinkedState->FoldStatusNotify(msg);
        EXPECT_TRUE(pStaStateMachine->pLinkedState->isExpandUpdateRssi_);
        EXPECT_NE(pStaStateMachine->foldStatus_, HALF_FOLD);
        EXPECT_NE(pStaStateMachine->foldStatus_, EXPAND);
    }

    void DealNetworkRemovedSuccessTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiLinkedInfo info;
        msg->SetParam1(static_cast<int>(info.networkId));
        pStaStateMachine->pLinkState->DealNetworkRemoved(msg);
    }

    void DealNetworkRemovedFailTest()
    {
        pStaStateMachine->pLinkState->DealNetworkRemoved(nullptr);
    }

    void OnNetManagerRestartSuccess()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiState(_)).WillRepeatedly(Return(1));
        pStaStateMachine->OnNetManagerRestart();
    }

    void OnNetManagerRestartFail()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiState(_)).WillRepeatedly(Return(1));
        pStaStateMachine->OnNetManagerRestart();
    }

    void OnBssidChangedEventSuccess()
    {
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->linkedInfo.bssid = RANDOMMAC_BSSID;
        pStaStateMachine->linkedInfo.ssid = RANDOMMAC_SSID;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(0));
        WifiDeviceConfig config;
        config.bssid = RANDOMMAC_BSSID;
        config.ssid = RANDOMMAC_SSID;
        pStaStateMachine->ReUpdateNetLinkInfo(config);
    }

    void ReUpdateNetLinkInfoTest1()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::NOTWORKING;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        WifiLinkedInfo linkedInfo;
        linkedInfo.connState = ConnState::CONNECTED;
        linkedInfo.ssid = "111111";
        linkedInfo.bssid = "222222";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).
            WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("sta"));
        WifiDeviceConfig config;
        config.ssid = "111111";
        config.bssid = "222222";
        pStaStateMachine->ReUpdateNetLinkInfo(config);
    }

    void UpdateLinkInfoRssiTest()
    {
        int rssi = INVALID_RSSI1;
        int outRssi = pStaStateMachine->UpdateLinkInfoRssi(rssi);
        EXPECT_EQ(outRssi, INVALID_RSSI_VALUE);

        rssi = INVALID_RSSI2;
        outRssi = pStaStateMachine->UpdateLinkInfoRssi(rssi);
        EXPECT_EQ(outRssi, INVALID_RSSI_VALUE);

        rssi = VALID_RSSI3;
        outRssi = pStaStateMachine->UpdateLinkInfoRssi(rssi);
        EXPECT_EQ(outRssi, VALID_RSSI3);

        rssi = VALID_RSSI4;
        outRssi = pStaStateMachine->UpdateLinkInfoRssi(rssi);
        EXPECT_EQ(outRssi, (VALID_RSSI4 - SIGNAL_INFO));

        rssi = INVALID_RSSI5;
        outRssi = pStaStateMachine->UpdateLinkInfoRssi(rssi);
        EXPECT_EQ(outRssi, INVALID_RSSI_VALUE);
    }

    void UpdateLinkRssiTest()
    {
        WifiSignalPollInfo signalInfo;
        signalInfo.signal = INVALID_RSSI1;
        pStaStateMachine->UpdateLinkRssi(signalInfo);

        signalInfo.signal = INVALID_RSSI2;
        pStaStateMachine->UpdateLinkRssi(signalInfo);

        signalInfo.signal = VALID_RSSI3;
        pStaStateMachine->UpdateLinkRssi(signalInfo);

        signalInfo.signal = VALID_RSSI4;
        pStaStateMachine->UpdateLinkRssi(signalInfo);
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

    void HandleForegroundAppChangedActionTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_FOREGROUND_APP_CHANGED_EVENT);
        AppExecFwk::AppStateData appStateData;
        appStateData.bundleName = "com.ohos.sceneboard";
        appStateData.isFocused = true;
        msg->SetMessageObj(appStateData);
        pStaStateMachine->HandleForegroundAppChangedAction(msg);
    }

    void DealSignalPacketChangedTest()
    {
        pStaStateMachine->linkedInfo.lastTxPackets = -1;
        pStaStateMachine->linkedInfo.lastRxPackets = -1;
        pStaStateMachine->linkedInfo.lastPacketDirection = 1;
        pStaStateMachine->DealSignalPacketChanged(0, 0);
    }

    void GetWpa3FailCountSuccessTest()
    {
        int failreason = 0;
        std::string ssid = RANDOMMAC_SSID;
        pStaStateMachine->GetWpa3FailCount(failreason, ssid);
    }

    void GetWpa3FailCountFailTest()
    {
        int failreason = -1;
        std::string ssid = RANDOMMAC_SSID;
        pStaStateMachine->GetWpa3FailCount(failreason, ssid);
    }

    void AddWpa3FailCountSuccessTest()
    {
        int failreason = 0;
        std::string ssid = RANDOMMAC_SSID;
        pStaStateMachine->AddWpa3FailCount(failreason, ssid);
    }

    void AddWpa3FailCountFailTest()
    {
        int failreason = -1;
        std::string ssid = RANDOMMAC_SSID;
        pStaStateMachine->AddWpa3FailCount(failreason, ssid);
    }

    void AddWpa3BlackMapTest()
    {
        std::string ssid = RANDOMMAC_SSID;
        for (int i = 0; i < WPA3_BLACKMAP_MAX_NUM; i++) {
            pStaStateMachine->AddWpa3BlackMap(std::to_string(i));
        }
        pStaStateMachine->AddWpa3BlackMap(ssid);
    }

    void IsInWpa3BlackMapTest()
    {
        std::string ssid = RANDOMMAC_SSID;
        pStaStateMachine->IsInWpa3BlackMap(ssid);
    }

    void OnWifiWpa3SelfCureSuccessTest()
    {
        int failreason = TEST_FAIL_REASON;
        int networkId = 0;
        pStaStateMachine->OnWifiWpa3SelfCure(failreason, networkId);
    }

    void OnWifiWpa3SelfCureFailTest()
    {
        int failreason = 0;
        int networkId = 0;
        pStaStateMachine->OnWifiWpa3SelfCure(failreason, networkId);
    }

    void IsWpa3TransitionTest()
    {
        pStaStateMachine->IsWpa3Transition(RANDOMMAC_SSID, RANDOMMAC_BSSID);
    }

    void InvokeOnStaConnChanged(const OperateResState &state, WifiLinkedInfo &info)
    {
        if (info.connState == ConnState::CONNECTED) {
            pStaStateMachine->InvokeOnStaConnChanged(state, info);
        }
    }

    void InvokeOnStaStreamChanged(const StreamDirection &direction)
    {
        pStaStateMachine->InvokeOnStaStreamChanged(direction);
        EXPECT_NE(pStaStateMachine->linkedInfo.networkId, TEN);
    }

    void InvokeOnStaRssiLevelChanged(int level)
    {
        pStaStateMachine->InvokeOnStaRssiLevelChanged(level);
        EXPECT_NE(pStaStateMachine->linkedInfo.networkId, TEN);
    }
    void DealHiLinkDataToWpaFailTest()
    {
        pStaStateMachine->DealHiLinkDataToWpa(nullptr);
    }

    void DealHiLinkDataToWpaSuccessTest1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_COM_STA_ENABLE_HILINK);
        std::string cmd = "ENABLE=1 BSSID=01:23:45:67:89:a0";
        msg->SetMessageObj(cmd);
        pStaStateMachine->DealHiLinkDataToWpa(msg);
    }

    void DealHiLinkDataToWpaSuccessTest2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_COM_STA_HILINK_DELIVER_MAC);
        std::string cmd = "HILINK_MAC=01:23:45:67:89:a0";
        msg->SetMessageObj(cmd);
        pStaStateMachine->DealHiLinkDataToWpa(msg);
    }

    void DealHiLinkDataToWpaSuccessTest3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_COM_STA_ENABLE_HILINK);
        std::string bssid = "01:23:45:67:89:a0";
        msg->SetMessageObj(bssid);
        pStaStateMachine->DealHiLinkDataToWpa(msg);
    }

    void DealHiLinkDataToWpaSuccessTest4()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(0);
        std::string bssid = "01:23:45:67:89:a0";
        msg->SetMessageObj(bssid);
        pStaStateMachine->DealHiLinkDataToWpa(msg);
    }

    void DealHiLinkDataToWpaSuccessTest5()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_COM_STA_HILINK_TRIGGER_WPS);
        std::string bssid = "01:23:45:67:89:a0";
        msg->SetMessageObj(bssid);
        pStaStateMachine->DealHiLinkDataToWpa(msg);
    }

    void IsDisConnectReasonShouldStopTimerSuccessTest()
    {
        int event = 8;
        EXPECT_TRUE(pStaStateMachine->IsDisConnectReasonShouldStopTimer(event));
    }

    void IsDisConnectReasonShouldStopTimerFailedTest()
    {
        int event = 0;
        EXPECT_FALSE(pStaStateMachine->IsDisConnectReasonShouldStopTimer(event));
    }

    void ShouldUseFactoryMacSuccess()
    {
        WifiDeviceConfig deviceConfig;
        deviceConfig.keyMgmt = KEY_MGMT_WPA_PSK;
        deviceConfig.networkId = 1;
        pStaStateMachine->mLastConnectNetId = 0;
        pStaStateMachine->mConnectFailedCnt = 0;
        EXPECT_FALSE(pStaStateMachine->ShouldUseFactoryMac(deviceConfig));
        pStaStateMachine->mConnectFailedCnt++ ;
        EXPECT_FALSE(pStaStateMachine->ShouldUseFactoryMac(deviceConfig));
        pStaStateMachine->mConnectFailedCnt++ ;
        EXPECT_TRUE(pStaStateMachine->ShouldUseFactoryMac(deviceConfig));
    }

    void ShouldUseFactoryMacFail()
    {
        WifiDeviceConfig deviceConfig;
        deviceConfig.keyMgmt = KEY_MGMT_NONE;
        EXPECT_FALSE(pStaStateMachine->ShouldUseFactoryMac(deviceConfig));
        deviceConfig.keyMgmt = KEY_MGMT_WPA_PSK;
        deviceConfig.networkId = 1;
        pStaStateMachine->mLastConnectNetId = 0;
        pStaStateMachine->mConnectFailedCnt = 1;
        EXPECT_FALSE(pStaStateMachine->ShouldUseFactoryMac(deviceConfig));
    }

    void InitRandomMacInfoTest()
    {
        const std::string bssid = "";
        WifiDeviceConfig deviceConfig;
        deviceConfig.keyMgmt = KEY_MGMT_NONE;
        WifiStoreRandomMac randomMacInfo;
        pStaStateMachine->InitRandomMacInfo(deviceConfig, bssid, randomMacInfo);
    }

    void GetDataSlotIdTest()
    {
        WifiTelephonyUtils::GetDataSlotId(0);
        WifiTelephonyUtils::GetDataSlotId(-1);
    }
    void GetDefaultIdTest()
    {
        WifiTelephonyUtils::GetDefaultId(WIFI_INVALID_SIM_ID);
        WifiTelephonyUtils::GetDefaultId(1);
    }

    void GetSimCardStateTest()
    {
        WifiTelephonyUtils::GetSimCardState(0);
    }

    void IsValidSimIdTest()
    {
        pStaStateMachine->IsValidSimId(0);
        EXPECT_EQ(pStaStateMachine->IsValidSimId(1), true);
    }
    void IsMultiSimEnabledTest()
    {
        WifiTelephonyUtils::IsMultiSimEnabled();
    }
    void SimAkaAuthTest()
    {
    #ifdef TELEPHONE_CORE_SERVICE_ENABLE
        EXPECT_EQ(WifiTelephonyUtils::SimAkaAuth("", WifiTelephonyUtils::AuthType::SIM_TYPE, 0), "");
    #endif
    }

    void GetGsmAuthResponseWithLengthTest()
    {
        EapSimGsmAuthParam param;
        param.rands.push_back(TEMP_TEST_DATA);
        EXPECT_EQ(pStaStateMachine->GetGsmAuthResponseWithLength(param), "");
    }

    void GetGsmAuthResponseWithoutLengthTest()
    {
        EapSimGsmAuthParam param;
        param.rands.push_back(TEMP_TEST_DATA);
        EXPECT_EQ(pStaStateMachine->GetGsmAuthResponseWithoutLength(param), "");
    }

    void PreWpaEapUmtsAuthEventTest()
    {
        pStaStateMachine->PreWpaEapUmtsAuthEvent();
    }

    void FillUmtsAuthReqTest()
    {
        EapSimUmtsAuthParam param;
        param.rand = TEMP_TEST_DATA;
        param.autn = TEMP_TEST_DATA;
        EXPECT_NE(pStaStateMachine->FillUmtsAuthReq(param).size(), 0);
    }
    void ParseAndFillUmtsAuthParamTest()
    {
        std::vector<uint8_t> nonce;
        nonce.push_back(UMTS_AUTH_TYPE_TAG);
        pStaStateMachine->ParseAndFillUmtsAuthParam(nonce);
        nonce.clear();
        nonce.push_back(UMTS_AUTS_TYPE_TAG);
        pStaStateMachine->ParseAndFillUmtsAuthParam(nonce);
    }

    void GetUmtsAuthResponseTest()
    {
        EapSimUmtsAuthParam param;
        EXPECT_EQ(pStaStateMachine->GetUmtsAuthResponse(param), "");
    }

    void DealWpaEapSimAuthEventTest()
    {
        InternalMessagePtr msg = nullptr;
        pStaStateMachine->DealWpaEapSimAuthEvent(msg);
        InternalMessagePtr msg1 = std::make_shared<InternalMessage>();
        msg1->SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_SIM_AUTH_EVENT);
        EapSimGsmAuthParam param;
        param.rands.push_back(TEMP_TEST_DATA);
        msg1->SetMessageObj(param);
        pStaStateMachine->DealWpaEapSimAuthEvent(msg1);
        InternalMessagePtr msg2 = std::make_shared<InternalMessage>();
        msg2->SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT);
        msg2->SetMessageObj(param);
        pStaStateMachine->DealWpaEapSimAuthEvent(msg2);
    }
    void HandlePortalNetworkPorcessTests()
    {
        pStaStateMachine->HandlePortalNetworkPorcess();
    }

    void DealWpaEapUmtsAuthEventTest()
    {
        InternalMessagePtr msg = nullptr;
        pStaStateMachine->DealWpaEapUmtsAuthEvent(msg);
        InternalMessagePtr msg1 = std::make_shared<InternalMessage>();
        EapSimUmtsAuthParam param;
        msg1->SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT);
        msg1->SetMessageObj(param);
        pStaStateMachine->DealWpaEapUmtsAuthEvent(msg1);
        InternalMessagePtr msg2 = std::make_shared<InternalMessage>();
        msg2->SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT);
        param.rand = TEMP_TEST_DATA;
        param.autn = TEMP_TEST_DATA;
        msg2->SetMessageObj(param);
        WifiDeviceConfig wifiDeviceConfig;
        wifiDeviceConfig.networkId = 1;
        wifiDeviceConfig.wifiEapConfig.eapSubId = 0;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).
            WillRepeatedly(DoAll(SetArgReferee<1>(wifiDeviceConfig), Return(0)));
        pStaStateMachine->DealWpaEapUmtsAuthEvent(msg2);
    }

    void HilinkSaveConfigTest()
    {
        pStaStateMachine->HilinkSaveConfig();
    }

    void SyncDeviceEverConnectedStateTest(bool hasNet)
    {
        pStaStateMachine->SyncDeviceEverConnectedState(hasNet);
    }

    void DealGetDhcpIpTimeoutTest()
    {
        InternalMessagePtr msg = nullptr;
        pStaStateMachine->pGetIpState->DealGetDhcpIpv4Timeout(msg);
        InternalMessagePtr msg1 = std::make_shared<InternalMessage>();
        msg1->SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT);
        pStaStateMachine->pGetIpState->DealGetDhcpIpv4Timeout(msg1);
    }

    void FillSuiteB192CfgTest()
    {
        WifiHalDeviceConfig  halDeviceConfig;
        halDeviceConfig.keyMgmt = "WPA-EAP-SUITE-B-192";
        pStaStateMachine->FillSuiteB192Cfg(halDeviceConfig);
    }

    void ReplaceEmptyDnsTest()
    {
        DhcpResult *result = nullptr;
        pStaStateMachine->ReplaceEmptyDns(result);
        DhcpResult resultO;
        std::string bssid1 = "11:22:33:44";
        std::string bssid2 = "11:22:33:44";
        strcpy_s(resultO.strOptDns1, MAX_STR_LENT, bssid1.c_str());
        strcpy_s(resultO.strOptDns2, MAX_STR_LENT, bssid2.c_str());
        pStaStateMachine->ReplaceEmptyDns(&resultO);
    }

    void SetSupportedWifiCategoryTestBssidIsEmpty()
    {
        pStaStateMachine->linkedInfo.bssid = "";
        pStaStateMachine->SetSupportedWifiCategory();
        EXPECT_EQ(pStaStateMachine->linkedInfo.supportedWifiCategory, WifiCategory::DEFAULT);
    }

    void SetSupportedWifiCategoryTestWifi6()
    {
        pStaStateMachine->linkedInfo.bssid = "123";
        EXPECT_CALL(*WifiConfigCenter::GetInstance().GetWifiScanConfig(),
            GetWifiCategoryRecord(_)).WillRepeatedly(Return(WifiCategory::WIFI6));
        pStaStateMachine->SetSupportedWifiCategory();
        EXPECT_EQ(pStaStateMachine->linkedInfo.supportedWifiCategory, WifiCategory::WIFI6);
        EXPECT_EQ(pStaStateMachine->linkedInfo.isMloConnected, false);
    }

    void SetSupportedWifiCategoryTestWifi7NotMlo()
    {
        pStaStateMachine->linkedInfo.bssid = "123";
        EXPECT_CALL(*WifiConfigCenter::GetInstance().GetWifiScanConfig(),
            GetWifiCategoryRecord(_)).WillRepeatedly(Return(WifiCategory::WIFI7));
        MockWifiStaHalInterface::GetInstance().SetChipsetFeatureCapability(CHIPSET_FEATURE_CAPABILITY_WIFI6_TEST);
        pStaStateMachine->SetSupportedWifiCategory();
        EXPECT_EQ(pStaStateMachine->linkedInfo.supportedWifiCategory, WifiCategory::WIFI7);
        EXPECT_EQ(pStaStateMachine->linkedInfo.isMloConnected, false);
    }

    void SetSupportedWifiCategoryTestWifi7IsMlo()
    {
        pStaStateMachine->linkedInfo.bssid = "123";
        EXPECT_CALL(*WifiConfigCenter::GetInstance().GetWifiScanConfig(),
            GetWifiCategoryRecord(_)).WillRepeatedly(Return(WifiCategory::WIFI7));
        MockWifiStaHalInterface::GetInstance().SetChipsetFeatureCapability(CHIPSET_FEATURE_CAPABILITY_WIFI7_TEST);
        pStaStateMachine->SetSupportedWifiCategory();
        EXPECT_EQ(pStaStateMachine->linkedInfo.supportedWifiCategory, WifiCategory::WIFI7);
        EXPECT_EQ(pStaStateMachine->linkedInfo.isMloConnected, true);
    }

    void DealMloConnectionLinkTestWifi6()
    {
        pStaStateMachine->linkedInfo.supportedWifiCategory = WifiCategory::WIFI6;
        pStaStateMachine->linkedInfo.isMloConnected = false;
        pStaStateMachine->linkedInfo.bssid = "123";

        pStaStateMachine->DealMloConnectionLinkInfo();
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveMloLinkedInfo(_, _))
            .WillRepeatedly(Return(0));
    }

    void DealMloConnectionLinkTestWifi7NotMlo()
    {
        pStaStateMachine->linkedInfo.supportedWifiCategory = WifiCategory::WIFI7;
        pStaStateMachine->linkedInfo.isMloConnected = false;
        pStaStateMachine->linkedInfo.bssid = "123";

        pStaStateMachine->DealMloConnectionLinkInfo();
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveMloLinkedInfo(_, _))
            .WillRepeatedly(Return(0));
    }

    void DealMloConnectionLinkTestWifi7IsMlo()
    {
        pStaStateMachine->linkedInfo.supportedWifiCategory = WifiCategory::WIFI7;
        pStaStateMachine->linkedInfo.isMloConnected = true;
        pStaStateMachine->linkedInfo.bssid = "123";
        pStaStateMachine->DealMloConnectionLinkInfo();
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveMloLinkedInfo(_, _))
            .WillRepeatedly(Return(0));
    }

    void AudioStateNotifyTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(AUDIO_ON_VOIP);
        pStaStateMachine->DealAudioStateChangedEvent(msg);
        EXPECT_EQ(pStaStateMachine->isAudioOn_, AUDIO_ON_VOIP);
        msg->SetParam1(AUDIO_ON_AUDIO);
        pStaStateMachine->DealAudioStateChangedEvent(msg);
        EXPECT_EQ(pStaStateMachine->isAudioOn_, AUDIO_ON_AUDIO);
        msg->SetParam1(AUDIO_OFF);
        pStaStateMachine->DealAudioStateChangedEvent(msg);
        EXPECT_EQ(pStaStateMachine->isAudioOn_, AUDIO_OFF);
    }

    void HandleInternetAccessChangedTest1()
    {
        SystemNetWorkState internetAccessStatus = SystemNetWorkState::NETWORK_IS_WORKING;
        pStaStateMachine->lastInternetIconStatus_ = SystemNetWorkState::NETWORK_IS_WORKING;
        pStaStateMachine->HandleInternetAccessChanged(internetAccessStatus);
        pStaStateMachine->lastInternetIconStatus_ = SystemNetWorkState::NETWORK_NOTWORKING;
        pStaStateMachine->HandleInternetAccessChanged(internetAccessStatus);
    }

    void HandleInternetAccessChangedTest2()
    {
        SystemNetWorkState internetAccessStatus = SystemNetWorkState::NETWORK_NOTWORKING;
        pStaStateMachine->lastInternetIconStatus_ = SystemNetWorkState::NETWORK_IS_WORKING;
        pStaStateMachine->noInternetAccessCnt_ = 1;
        pStaStateMachine->HandleInternetAccessChanged(internetAccessStatus);
        pStaStateMachine->noInternetAccessCnt_ = MAX_NO_INTERNET_CNTS;
        pStaStateMachine->lastSignalLevel_ = 1;
        pStaStateMachine->HandleInternetAccessChanged(internetAccessStatus);
        pStaStateMachine->noInternetAccessCnt_ = MAX_NO_INTERNET_CNTS;
        pStaStateMachine->lastSignalLevel_ = TEST_FAIL_REASON;
        pStaStateMachine->HandleInternetAccessChanged(internetAccessStatus);
    }

    void UpdateLinkedBssidTest()
    {
        std::string bssid = "11:22:33:44:55:66";
        pStaStateMachine->UpdateLinkedBssid(bssid);
    }

        void CloseNoInternetDialogTest()
    {
        pStaStateMachine-> CloseNoInternetDialog();
    }

    void DhcpResultNotifySuccessOrderTest() const
    {
        DhcpResult result;
        std::string ifname = "wlan0";
        // 1. 仅IPv4成功
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success = true;
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success = false;
        pStaStateMachine->pDhcpResultNotify->OnSuccess(0, ifname.c_str(), &result);
        EXPECT_TRUE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success);
        EXPECT_FALSE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success);

        // 2. 仅IPv6成功
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success = false;
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success = true;
        pStaStateMachine->pDhcpResultNotify->OnSuccess(0, ifname.c_str(), &result);
        EXPECT_FALSE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success);
        EXPECT_TRUE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success);

        // 3. 两者都成功
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success = true;
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success = true;
        pStaStateMachine->pDhcpResultNotify->OnSuccess(0, ifname.c_str(), &result);
        EXPECT_TRUE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success);
        EXPECT_TRUE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success);

        // 4. 两者都失败
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success = false;
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success = false;
        pStaStateMachine->pDhcpResultNotify->OnFailed(0, ifname.c_str(), "fail");
        EXPECT_FALSE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success);
        EXPECT_FALSE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success);

        // 5. 顺序测试：先IPv4后IPv6
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success = false;
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success = false;
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success = true;
        EXPECT_TRUE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success);
        EXPECT_FALSE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success);
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success = true;
        EXPECT_TRUE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success);
        EXPECT_TRUE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success);

        // 6. 顺序测试：先IPv6后IPv4
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success = false;
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success = false;
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success = true;
        EXPECT_FALSE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success);
        EXPECT_TRUE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success);
        pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success = true;
        EXPECT_TRUE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv4Success);
        EXPECT_TRUE(pStaStateMachine->pDhcpResultNotify->isDhcpIpv6Success);
    }
};
HWTEST_F(StaStateMachineTest, HandleInternetAccessChanged_01, TestSize.Level1)
{
    HandleInternetAccessChangedTest1();
    EXPECT_FALSE(g_errLog.find("ignore rssi changed")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, HandleInternetAccessChanged_02, TestSize.Level1)
{
    HandleInternetAccessChangedTest2();
    EXPECT_FALSE(g_errLog.find("ignore rssi changed")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, UpdateExpandOffsetRange, TestSize.Level1)
{
    UpdateExpandOffsetRange();
}

HWTEST_F(StaStateMachineTest, UpdateExpandOffsetMin, TestSize.Level1)
{
    UpdateExpandOffsetMin();
}

HWTEST_F(StaStateMachineTest, UpdateExpandOffsetDefault, TestSize.Level1)
{
    UpdateExpandOffsetDefault();
}

HWTEST_F(StaStateMachineTest, UpdateExpandOffsetMax, TestSize.Level1)
{
    UpdateExpandOffsetMax();
}

HWTEST_F(StaStateMachineTest, FoldStatusNotifyHalfFold, TestSize.Level1)
{
    FoldStatusNotifyHalfFold();
}

HWTEST_F(StaStateMachineTest, FoldStatusNotifyExpand, TestSize.Level1)
{
    FoldStatusNotifyExpand();
}

HWTEST_F(StaStateMachineTest, FoldStatusNotifyOtherStatus, TestSize.Level1)
{
    FoldStatusNotifyOtherStatus();
}

HWTEST_F(StaStateMachineTest, ShouldUseFactoryMacSuccess, TestSize.Level1)
{
    ShouldUseFactoryMacSuccess();
}

HWTEST_F(StaStateMachineTest, ShouldUseFactoryMacFail, TestSize.Level1)
{
    ShouldUseFactoryMacFail();
}

HWTEST_F(StaStateMachineTest, IsDisConnectReasonShouldStopTimerSuccessTest, TestSize.Level1)
{
    IsDisConnectReasonShouldStopTimerSuccessTest();
}

HWTEST_F(StaStateMachineTest, IsDisConnectReasonShouldStopTimerFailedTest, TestSize.Level1)
{
    IsDisConnectReasonShouldStopTimerFailedTest();
}

HWTEST_F(StaStateMachineTest, DealConnectTimeOutCmd, TestSize.Level1)
{
    DealConnectTimeOutCmd();
}

HWTEST_F(StaStateMachineTest, InitStateGoInStateSuccess, TestSize.Level1)
{
    InitStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, InitStateGoOutStateSuccess, TestSize.Level1)
{
    InitStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, ClosedStateExeMsgSuccess, TestSize.Level1)
{
    ClosedStateExeMsgSuccess();
}

HWTEST_F(StaStateMachineTest, ClosedStateExeMsgSuccessFgAppChanged, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(WIFI_SVR_CMD_STA_FOREGROUND_APP_CHANGED_EVENT);
    AppExecFwk::AppStateData appStateData;
    appStateData.bundleName = "com.ohos.whatever";
    appStateData.isFocused = true;
    msg->SetMessageObj(appStateData);
    EXPECT_TRUE(pStaStateMachine->pClosedState->ExecuteStateMsg(msg));
}

HWTEST_F(StaStateMachineTest, CLosedStateExeMsgFail1, TestSize.Level1)
{
    CLosedStateExeMsgFail1();
}

HWTEST_F(StaStateMachineTest, InitStateExeMsgFail2, TestSize.Level1)
{
    InitStateExeMsgFail2();
}

HWTEST_F(StaStateMachineTest, ConvertDeviceCfgSuccess, TestSize.Level1)
{
    ConvertDeviceCfgSuccess();
}

HWTEST_F(StaStateMachineTest, ConvertDeviceCfgFail1, TestSize.Level1)
{
    ConvertDeviceCfgFail1();
}

HWTEST_F(StaStateMachineTest, ConvertDeviceCfgFail2, TestSize.Level1)
{
    ConvertDeviceCfgFail2();
}

HWTEST_F(StaStateMachineTest, ConvertDeviceCfgFail3, TestSize.Level1)
{
    ConvertDeviceCfgFail3();
}

HWTEST_F(StaStateMachineTest, StartWifiProcessSuccess, TestSize.Level1)
{
    StartWifiProcessSuccess();
}

HWTEST_F(StaStateMachineTest, StartWifiProcessFail2, TestSize.Level1)
{
    StartWifiProcessFail2();
}

HWTEST_F(StaStateMachineTest, StartWifiProcessFail1, TestSize.Level1)
{
    StartWifiProcessFail1();
}

HWTEST_F(StaStateMachineTest, StopWifiProcessSuccess1, TestSize.Level1)
{
    StopWifiProcessSuccess1();
}

HWTEST_F(StaStateMachineTest, StopWifiProcessSuccess2, TestSize.Level1)
{
    StopWifiProcessSuccess2();
}

HWTEST_F(StaStateMachineTest, StopWifiProcessSuccess3, TestSize.Level1)
{
    StopWifiProcessSuccess3();
}

HWTEST_F(StaStateMachineTest, StopWifiProcessFail, TestSize.Level1)
{
    StopWifiProcessFail();
}

HWTEST_F(StaStateMachineTest, LinkedStateExeMsgFail, TestSize.Level1)
{
    LinkedStateExeMsgFail();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, LinkedStateExeMsgSuccess, TestSize.Level1)
{
    LinkedStateExeMsgSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, LinkedStateExeMsgFail4, TestSize.Level1)
{
    LinkedStateExeMsgFail4();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, LinkedStateExeMsgFail3, TestSize.Level1)
{
    LinkedStateExeMsgFail3();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, LinkedStateExeMsgFail2, TestSize.Level1)
{
    LinkedStateExeMsgFail2();
}

HWTEST_F(StaStateMachineTest, LinkedStateCheckIfRestoreWifiSuccess, TestSize.Level1)
{
    LinkedStateCheckIfRestoreWifiSuccess();
}

HWTEST_F(StaStateMachineTest, InitStaSMHandleMapSuccess, TestSize.Level1)
{
    InitStaSMHandleMapSuccess();
}

HWTEST_F(StaStateMachineTest, DealConnectTimeOutCmdSuccess, TestSize.Level1)
{
    DealConnectTimeOutCmdSuccess();
}

HWTEST_F(StaStateMachineTest, DealConnectTimeOutCmdFail, TestSize.Level1)
{
    DealConnectTimeOutCmdFail();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealReassociateCmdSuccess, TestSize.Level1)
{
    DealReassociateCmdSuccess();
}

HWTEST_F(StaStateMachineTest, DealReassociateCmdFail1, TestSize.Level1)
{
    DealReassociateCmdFail1();
}

HWTEST_F(StaStateMachineTest, DealReassociateCmdFail2, TestSize.Level1)
{
    DealReassociateCmdFail2();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealStartRoamCmdInApLinkedStateSuccess, TestSize.Level1)
{
    DealStartRoamCmdInApLinkedStateSuccess();
}

HWTEST_F(StaStateMachineTest, DealStartRoamCmdInApLinkedStateFail1, TestSize.Level1)
{
    DealStartRoamCmdInApLinkedStateFail1();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealStartRoamCmdInApLinkedStateFail2, TestSize.Level1)
{
    DealStartRoamCmdInApLinkedStateFail2();
}

HWTEST_F(StaStateMachineTest, DealStartRoamCmdInApLinkedStateFail3, TestSize.Level1)
{
    DealStartRoamCmdInApLinkedStateFail3();
}

HWTEST_F(StaStateMachineTest, StartConnectToNetworkSuccess, TestSize.Level1)
{
    StartConnectToNetworkSuccess();
}

HWTEST_F(StaStateMachineTest, StartConnectToNetworkSuccess2, TestSize.Level1)
{
    StartConnectToNetworkSuccess2();
}

HWTEST_F(StaStateMachineTest, StartConnectToNetworkFail1, TestSize.Level1)
{
    StartConnectToNetworkFail1();
}

HWTEST_F(StaStateMachineTest, StartConnectToNetworkFali3, TestSize.Level1)
{
    StartConnectToNetworkFali3();
}
/**
 * @tc.name: StartConnectToNetworkFali4
 * @tc.desc: StartConnectToNetwork()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, StartConnectToNetworkFail4, TestSize.Level1)
{
    StartConnectToNetworkFail4();
}

HWTEST_F(StaStateMachineTest, SetRandomMacSuccess1, TestSize.Level1)
{
    SetRandomMacSuccess1();
}

HWTEST_F(StaStateMachineTest, SetRandomMacFail1, TestSize.Level1)
{
    SetRandomMacFail1();
}

HWTEST_F(StaStateMachineTest, SetRandomMacFail2, TestSize.Level1)
{
    SetRandomMacFail2();
}

HWTEST_F(StaStateMachineTest, StartConnectToBssidSuccess, TestSize.Level1)
{
    StartConnectToBssidSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, SeparatedStateGoInStateSuccess, TestSize.Level1)
{
    SeparatedStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, SeparatedStateGoOutStateSuccess, TestSize.Level1)
{
    SeparatedStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, SeparatedStateExeMsgSuccess1, TestSize.Level1)
{
    SeparatedStateExeMsgSuccess1();
}

HWTEST_F(StaStateMachineTest, SeparatedStateExeMsgSuccess2, TestSize.Level1)
{
    SeparatedStateExeMsgSuccess2();
}

HWTEST_F(StaStateMachineTest, SeparatedStateExeMsgFail, TestSize.Level1)
{
    SeparatedStateExeMsgFail();
}

HWTEST_F(StaStateMachineTest, ApLinkedStateGoInStateSuccess, TestSize.Level1)
{
    ApLinkedStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, ApLinkedStateGoOutStateSuccess, TestSize.Level1)
{
    ApLinkedStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, ApLinkedStateExeMsgSuccess1, TestSize.Level1)
{
    ApLinkedStateExeMsgSuccess1();
}

HWTEST_F(StaStateMachineTest, ApLinkedStateExeMsgSuccess2, TestSize.Level1)
{
    ApLinkedStateExeMsgSuccess2();
}

HWTEST_F(StaStateMachineTest, ApLinkedStateExeMsgFail1, TestSize.Level1)
{
    ApLinkedStateExeMsgFail1();
}

HWTEST_F(StaStateMachineTest, ApLinkedStateExeMsgFai2, TestSize.Level1)
{
    ApLinkedStateExeMsgFai2();
}

HWTEST_F(StaStateMachineTest, StartDisConnectToNetworkSuccess, TestSize.Level1)
{
    StartDisConnectToNetworkSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, StartDisConnectToNetworkFail, TestSize.Level1)
{
    StartDisConnectToNetworkFail();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, GetIpStateStateGoInStateSuccess1, TestSize.Level1)
{
    GetIpStateStateGoInStateSuccess1();
}

HWTEST_F(StaStateMachineTest, GetIpStateStateGoInStateSuccess2, TestSize.Level1)
{
    GetIpStateStateGoInStateSuccess2();
}

HWTEST_F(StaStateMachineTest, GetIpStateStateGoInStateSuccess3, TestSize.Level1)
{
    GetIpStateStateGoInStateSuccess3();
}

HWTEST_F(StaStateMachineTest, GetIpStateStateGoOutStateSuccess, TestSize.Level1)
{
    GetIpStateStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, GetIpStateStateExeMsgSuccess, TestSize.Level1)
{
    GetIpStateStateExeMsgSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, GetIpStateStateExeMsgFail, TestSize.Level1)
{
    GetIpStateStateExeMsgFail();
}

HWTEST_F(StaStateMachineTest, GetIpStateStateIsPublicESSTest, TestSize.Level1)
{
    GetIpStateStateIsPublicESSTest();
}

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

HWTEST_F(StaStateMachineTest, HandleNetCheckResultSuccess1, TestSize.Level1)
{
    HandleNetCheckResultSuccess1();
}

HWTEST_F(StaStateMachineTest, HandleNetCheckResultSuccess3, TestSize.Level1)
{
    HandleNetCheckResultSuccess3();
}

HWTEST_F(StaStateMachineTest, HandleNetCheckResultSuccess4, TestSize.Level1)
{
    HandleNetCheckResultSuccess4();
}

HWTEST_F(StaStateMachineTest, HandleNetCheckResultSuccess5, TestSize.Level1)
{
    HandleNetCheckResultSuccess5();
}

HWTEST_F(StaStateMachineTest, HandleNetCheckResultSuccess6, TestSize.Level1)
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(TWO);
    pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
    pStaStateMachine->lastCheckNetState_ = OperateResState::CONNECT_CHECK_PORTAL;
    pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_IS_WORKING, "");
}

HWTEST_F(StaStateMachineTest, HandleNetCheckResultSuccess7, TestSize.Level1)
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(TWO);
    pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
    pStaStateMachine->lastCheckNetState_ = OperateResState::CONNECT_NETWORK_ENABLED;
    pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_IS_PORTAL, "");
}

HWTEST_F(StaStateMachineTest, HandleNetCheckResultSuccess8, TestSize.Level1)
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(TWO);
    pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
    pStaStateMachine->lastCheckNetState_ = OperateResState::CONNECT_CHECK_PORTAL;
    pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_NOTWORKING, "");
}

HWTEST_F(StaStateMachineTest, HandleNetCheckResultTxRxGoodButNoInternetTest, TestSize.Level1)
{
    IpQosMonitor::GetInstance().lastTxRxGood_ = true;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).WillRepeatedly(Return(MODE_STATE_OPEN));
        
    pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(1));
    EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(
        OperateResState::CONNECT_NETWORK_ENABLED, _, _)).Times(AtLeast(1));
    pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_NOTWORKING, "");
        
    IpQosMonitor::GetInstance().lastTxRxGood_ = false;
}
 
HWTEST_F(StaStateMachineTest, HandleNetCheckResultTxRxGoodButNoInternetFalseTest, TestSize.Level1)
{
    HandleNetCheckResultTxRxGoodButNoInternetFalseTest();
}

HWTEST_F(StaStateMachineTest, HandleNetCheckResultFail, TestSize.Level1)
{
    HandleNetCheckResultFail();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, TestHandleNetCheckResultIsPortal, TestSize.Level1)
{
    TestHandleNetCheckResultIsPortal1();
}

HWTEST_F(StaStateMachineTest, TestTestPublishPortalNitificationAndLogin, TestSize.Level1)
{
    // TestPublishPortalNitificationAndLogin1
    pStaStateMachine->m_instId = INSTID_WLAN1;  // 设置非 INSTID_WLAN0 的值
    pStaStateMachine->autoPullBrowserFlag = false;
    pStaStateMachine->portalReCheck_ = false;
 
    // Act
    pStaStateMachine->PublishPortalNitificationAndLogin();
 
    // Assert
    EXPECT_FALSE(pStaStateMachine->portalReCheck_);
    EXPECT_FALSE(pStaStateMachine->autoPullBrowserFlag);
 
    // TestPublishPortalNitificationAndLogin2
    pStaStateMachine->m_instId = INSTID_WLAN0;
    pStaStateMachine->autoPullBrowserFlag = false;
    pStaStateMachine->portalReCheck_ = false;
    pStaStateMachine->lastCheckNetState_ = OperateResState::CONNECT_NETWORK_ENABLED;
    // Act
    EXPECT_CALL(WifiConfigCenter::GetInstance(), IsAllowPopUp()).WillRepeatedly(Return(true));
    pStaStateMachine->PublishPortalNitificationAndLogin();
 
    // Assert
    EXPECT_TRUE(pStaStateMachine->portalReCheck_);
    EXPECT_FALSE(pStaStateMachine->autoPullBrowserFlag);
 
 
    // TestPublishPortalNitificationAndLogin3
    pStaStateMachine->m_instId = INSTID_WLAN0;
    pStaStateMachine->autoPullBrowserFlag = false;
    pStaStateMachine->portalReCheck_ = false;
    pStaStateMachine->lastCheckNetState_ = OperateResState::CONNECT_CHECK_PORTAL;
    // Act
    pStaStateMachine->PublishPortalNitificationAndLogin();
    // Assert
    EXPECT_FALSE(pStaStateMachine->portalReCheck_);
    EXPECT_FALSE(pStaStateMachine->autoPullBrowserFlag);
 
    // TestPublishPortalNitificationAndLogin4()
    pStaStateMachine->m_instId = INSTID_WLAN0;
    pStaStateMachine->autoPullBrowserFlag = false;
    pStaStateMachine->portalReCheck_ = true;
    pStaStateMachine->lastCheckNetState_ = OperateResState::CONNECT_CHECK_PORTAL;
    // Act
    pStaStateMachine->PublishPortalNitificationAndLogin();
    // Assert
    EXPECT_FALSE(pStaStateMachine->portalReCheck_);
    EXPECT_TRUE(pStaStateMachine->autoPullBrowserFlag);
}

HWTEST_F(StaStateMachineTest, TestTryModifyPortalAttribute, TestSize.Level1)
{
    TestTryModifyPortalAttribute1();
    TestTryModifyPortalAttribute2();
    TestTryModifyPortalAttribute3();
    TestTryModifyPortalAttribute4();
}
 
HWTEST_F(StaStateMachineTest, TestChangePortalAttribute, TestSize.Level1)
{
    TestChangePortalAttribute();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, TestUpdatePortalState1, TestSize.Level1)
{
    std::map<PortalState, PortalState> map = {
        {PortalState::UNCHECKED,   PortalState::NOT_PORTAL},
        {PortalState::NOT_PORTAL, PortalState::NOT_PORTAL},
        {PortalState::UNAUTHED,   PortalState::AUTHED},
        {PortalState::AUTHED,     PortalState::AUTHED},
        {PortalState::EXPERIED,   PortalState::AUTHED},
    };
    TestUpdatePortalState(map, SystemNetWorkState::NETWORK_IS_WORKING);
}

HWTEST_F(StaStateMachineTest, TestUpdatePortalState2, TestSize.Level1)
{
    std::map<PortalState, PortalState> map = {
        {PortalState::UNCHECKED,   PortalState::UNAUTHED},
        {PortalState::NOT_PORTAL, PortalState::EXPERIED},
        {PortalState::UNAUTHED,   PortalState::UNAUTHED},
        {PortalState::AUTHED,     PortalState::EXPERIED},
        {PortalState::EXPERIED,   PortalState::EXPERIED},
    };
    TestUpdatePortalState(map, SystemNetWorkState::NETWORK_IS_PORTAL);
}

HWTEST_F(StaStateMachineTest, ApRoamingStateGoInStateSuccess, TestSize.Level1)
{
    ApRoamingStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, ApRoamingStateGoOutStateSuccess, TestSize.Level1)
{
    ApRoamingStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, ApRoamingStateExeMsgSuccess, TestSize.Level1)
{
    ApRoamingStateExeMsgSuccess();
}

HWTEST_F(StaStateMachineTest, ApRoamingStateExeMsgFail, TestSize.Level1)
{
    ApRoamingStateExeMsgFail();
}

/**
 * @tc.name: AfterApLinkedprocessSuccess1
 * @tc.desc: AfterApLinkedprocess()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, AfterApLinkedprocessSuccess1, TestSize.Level1)
{
    AfterApLinkedprocessSuccess1();
}

HWTEST_F(StaStateMachineTest, AfterApLinkedprocessSuccess2, TestSize.Level1)
{
    AfterApLinkedprocessSuccess2();
}

HWTEST_F(StaStateMachineTest, DhcpResultNotifyOnSuccessTest, TestSize.Level1)
{
    DhcpResultNotifyOnSuccessTest();
}

HWTEST_F(StaStateMachineTest, DhcpResultNotifyOnFailedTest1, TestSize.Level1)
{
    DhcpResultNotifyOnFailedTest1();
}

HWTEST_F(StaStateMachineTest, DhcpResultNotifyOnFailedTest2, TestSize.Level1)
{
    DhcpResultNotifyOnFailedTest2();
}

HWTEST_F(StaStateMachineTest, DhcpResultNotifyOnFailedTest3, TestSize.Level1)
{
    DhcpResultNotifyOnFailedTest3();
}

HWTEST_F(StaStateMachineTest, DhcpResultNotifyEventTest, TestSize.Level1)
{
    DhcpResultNotifyEventTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, SaveLinkstateSuccess, TestSize.Level1)
{
    SaveLinkstateSuccess();
}

HWTEST_F(StaStateMachineTest, ConvertFreqToChannelTest, TestSize.Level1)
{
    ConvertFreqToChannelTest();
}

HWTEST_F(StaStateMachineTest, LinkStateGoInStateSuccess, TestSize.Level1)
{
    LinkStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, LinkStateGoOutStateSuccess, TestSize.Level1)
{
    LinkStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, LinkStateExeMsgSuccess, TestSize.Level1)
{
    LinkStateExeMsgSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, LinkStateExeMsgFail, TestSize.Level1)
{
    LinkStateExeMsgFail();
}

HWTEST_F(StaStateMachineTest, OnNetManagerRestartSuccess, TestSize.Level1)
{
    OnNetManagerRestartSuccess();
}

HWTEST_F(StaStateMachineTest, OnNetManagerRestartFail, TestSize.Level1)
{
    OnNetManagerRestartFail();
}

HWTEST_F(StaStateMachineTest, DealReConnectCmdFail, TestSize.Level1)
{
    DealReConnectCmdFail();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealReConnectCmdSuccess, TestSize.Level1)
{
    DealReConnectCmdSuccess();
}

/**
 * @tc.name: ReUpdateNetLinkInfoTest1
 * @tc.desc: ReUpdateNetLinkInfo()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, ReUpdateNetLinkInfoTest1, TestSize.Level1)
{
    ReUpdateNetLinkInfoTest1();
}

HWTEST_F(StaStateMachineTest, UpdateLinkInfoRssiTest, TestSize.Level1)
{
    UpdateLinkInfoRssiTest();
}

HWTEST_F(StaStateMachineTest, UpdateLinkRssiTest, TestSize.Level1)
{
    UpdateLinkRssiTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

/**
 * @tc.name: DealSignalPollResultTest
 * @tc.desc: DealSignalPollResult()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, DealSignalPollResultTest, TestSize.Level1)
{
    DealSignalPollResultTest();
}

/**
 * @tc.name: DealSignalPollResultTestPollPeriod1s
 * @tc.desc: DealSignalPollResult()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, DealSignalPollResultTestPollPeriod1s, TestSize.Level1)
{
    pStaStateMachine->staSignalPollDelayTime_ = STA_SIGNAL_POLL_DELAY_WITH_TASK;
    pStaStateMachine->DealSignalPollResult();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

/**
 * @tc.name: HandleForegroundAppChangedActionTest
 * @tc.desc: HandleForegroundAppChangedAction()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, HandleForegroundAppChangedActionTest, TestSize.Level1)
{
    HandleForegroundAppChangedActionTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

/**
 * @tc.name: DealSignalPacketChangedTest
 * @tc.desc: DealSignalPacketChanged()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, DealSignalPacketChangedTest, TestSize.Level1)
{
    DealSignalPacketChangedTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, GetWpa3FailCountSuccessTest, TestSize.Level1)
{
    GetWpa3FailCountSuccessTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, GetWpa3FailCountFailTest, TestSize.Level1)
{
    GetWpa3FailCountFailTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, AddWpa3FailCountSuccessTest, TestSize.Level1)
{
    AddWpa3FailCountSuccessTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, AddWpa3FailCountFailTest, TestSize.Level1)
{
    AddWpa3FailCountFailTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, AddWpa3BlackMapTest, TestSize.Level1)
{
    AddWpa3BlackMapTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, IsInWpa3BlackMapTest, TestSize.Level1)
{
    IsInWpa3BlackMapTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, OnWifiWpa3SelfCureSuccessTest, TestSize.Level1)
{
    OnWifiWpa3SelfCureSuccessTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, OnWifiWpa3SelfCureFailTest, TestSize.Level1)
{
    OnWifiWpa3SelfCureFailTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, IsWpa3TransitionTest, TestSize.Level1)
{
    IsWpa3TransitionTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, InvokeOnStaConnChangedTest, TestSize.Level1)
{
    WifiLinkedInfo linkedInfo;
    InvokeOnStaConnChanged(OperateResState::OPEN_WIFI_SUCCEED, linkedInfo);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, InvokeOnStaStreamChangedTest, TestSize.Level1)
{
    InvokeOnStaStreamChanged(StreamDirection::STREAM_DIRECTION_UP);
}

HWTEST_F(StaStateMachineTest, InvokeOnStaRssiLevelChangedTest, TestSize.Level1)
{
    int rssi = -61;
    InvokeOnStaRssiLevelChanged(rssi);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealNetworkRemovedFailTest, TestSize.Level1)
{
    DealNetworkRemovedFailTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealNetworkRemovedSuccessTest, TestSize.Level1)
{
    DealNetworkRemovedSuccessTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealHiLinkDataToWpaFailTest, TestSize.Level1)
{
    DealHiLinkDataToWpaFailTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealHiLinkDataToWpaSuccessTest1, TestSize.Level1)
{
    DealHiLinkDataToWpaSuccessTest1();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealHiLinkDataToWpaSuccessTest2, TestSize.Level1)
{
    DealHiLinkDataToWpaSuccessTest2();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealHiLinkDataToWpaSuccessTest3, TestSize.Level1)
{
    DealHiLinkDataToWpaSuccessTest3();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealFillWapiCfgTest, TestSize.Level1)
{
    WifiDeviceConfig config;
    WifiHalDeviceConfig halDeviceConfig;
    config.keyMgmt = KEY_MGMT_WAPI_CERT;
    pStaStateMachine->FillWapiCfg(config, halDeviceConfig);
    EXPECT_NE(halDeviceConfig.wepKeyIdx, TEN);
}

HWTEST_F(StaStateMachineTest, InitRandomMacInfoTest, TestSize.Level1)
{
    InitRandomMacInfoTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, GetDataSlotIdTest, TestSize.Level1)
{
    GetDataSlotIdTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, GetDefaultIdTest, TestSize.Level1)
{
    GetDefaultIdTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, GetSimCardStateTest, TestSize.Level1)
{
    GetSimCardStateTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, IsValidSimIdTest, TestSize.Level1)
{
    IsValidSimIdTest();
}

HWTEST_F(StaStateMachineTest, IsMultiSimEnabledTest, TestSize.Level1)
{
    IsMultiSimEnabledTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, SimAkaAuthTest, TestSize.Level1)
{
    SimAkaAuthTest();
}

HWTEST_F(StaStateMachineTest, GetGsmAuthResponseWithLengthTest, TestSize.Level1)
{
    GetGsmAuthResponseWithLengthTest();
}

HWTEST_F(StaStateMachineTest, GetGsmAuthResponseWithoutLengthTest, TestSize.Level1)
{
    GetGsmAuthResponseWithoutLengthTest();
}

HWTEST_F(StaStateMachineTest, PreWpaEapUmtsAuthEventTest, TestSize.Level1)
{
    PreWpaEapUmtsAuthEventTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, FillUmtsAuthReqTest, TestSize.Level1)
{
    FillUmtsAuthReqTest();
}

HWTEST_F(StaStateMachineTest, ParseAndFillUmtsAuthParamTest, TestSize.Level1)
{
    ParseAndFillUmtsAuthParamTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, GetUmtsAuthResponseTest, TestSize.Level1)
{
    GetUmtsAuthResponseTest();
}

HWTEST_F(StaStateMachineTest, DealWpaEapSimAuthEventTest, TestSize.Level1)
{
    DealWpaEapSimAuthEventTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, HandlePortalNetworkPorcessTests, TestSize.Level1)
{
    HandlePortalNetworkPorcessTests();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealWpaEapUmtsAuthEventTest, TestSize.Level1)
{
    DealWpaEapUmtsAuthEventTest();
}

HWTEST_F(StaStateMachineTest, HilinkSaveConfigTest, TestSize.Level1)
{
    HilinkSaveConfigTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, SyncDeviceEverConnectedStateTest, TestSize.Level1)
{
    bool hasNet = false;
    SyncDeviceEverConnectedStateTest(hasNet);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, ReplaceEmptyDnsTest, TestSize.Level1)
{
    ReplaceEmptyDnsTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, ApLinkedStateExeMsgSuccess3, TestSize.Level1)
{
    ApLinkedStateExeMsgSuccess3();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, ApLinkedStateExeMsgSuccess4, TestSize.Level1)
{
    ApLinkedStateExeMsgSuccess4();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, ApLinkedStateExeMsgLinkSwitch, TestSize.Level1)
{
    ApLinkedStateExeMsgLinkSwitch();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealHiLinkDataToWpaSuccessTest4, TestSize.Level1)
{
    DealHiLinkDataToWpaSuccessTest4();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, DealHiLinkDataToWpaSuccessTest5, TestSize.Level1)
{
    DealHiLinkDataToWpaSuccessTest5();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, SetSupportedWifiCategoryTestBssidIsEmpty, TestSize.Level1)
{
    SetSupportedWifiCategoryTestBssidIsEmpty();
}

HWTEST_F(StaStateMachineTest, SetSupportedWifiCategoryTestWifi6, TestSize.Level1)
{
    SetSupportedWifiCategoryTestWifi6();
}

HWTEST_F(StaStateMachineTest, SetSupportedWifiCategoryTestWifi7NotMlo, TestSize.Level1)
{
    SetSupportedWifiCategoryTestWifi7NotMlo();
}

HWTEST_F(StaStateMachineTest, SetSupportedWifiCategoryTestWifi7IsMlo, TestSize.Level1)
{
    SetSupportedWifiCategoryTestWifi7IsMlo();
}

HWTEST_F(StaStateMachineTest, DealMloConnectionLinkTestWifi6, TestSize.Level1)
{
    DealMloConnectionLinkTestWifi6();
}

HWTEST_F(StaStateMachineTest, DealMloConnectionLinkTestWifi7NotMlo, TestSize.Level1)
{
    DealMloConnectionLinkTestWifi7NotMlo();
}

HWTEST_F(StaStateMachineTest, DealMloConnectionLinkTestWifi7IsMlo, TestSize.Level1)
{
    DealMloConnectionLinkTestWifi7IsMlo();
}

HWTEST_F(StaStateMachineTest, CloseNoInternetDialogTest, TestSize.Level1)
{
    CloseNoInternetDialogTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, UpdateLinkedBssidTest, TestSize.Level1)
{
    UpdateLinkedBssidTest();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaStateMachineTest, AudioStateNotifyTest, TestSize.Level1)
{
    AudioStateNotifyTest();
}

HWTEST_F(StaStateMachineTest, DhcpResultNotifyClearTest, TestSize.Level1)
{
    StaStateMachine staStateMachine;
    pStaStateMachine->pDhcpResultNotify
        = new StaStateMachine::DhcpResultNotify(&staStateMachine);
    pStaStateMachine->pDhcpResultNotify->DhcpIpv6Result.isOptSuc = 1;
    pStaStateMachine->pDhcpResultNotify->Clear();
    EXPECT_TRUE(pStaStateMachine->pDhcpResultNotify->DhcpIpv6Result.isOptSuc == 0);
    pStaStateMachine->pDhcpResultNotify->DhcpIpv4Result.isOptSuc = 1;
    pStaStateMachine->pDhcpResultNotify->Clear();
    EXPECT_TRUE(pStaStateMachine->pDhcpResultNotify->DhcpIpv4Result.isOptSuc == 0);
}

HWTEST_F(StaStateMachineTest, DhcpResultNotifyClear2Test, TestSize.Level1)
{
    StaStateMachine staStateMachine;
    pStaStateMachine->pDhcpResultNotify
        = new StaStateMachine::DhcpResultNotify(&staStateMachine);
    pStaStateMachine->pDhcpResultNotify->DhcpIpv6Result.isOptSuc = 1;
    pStaStateMachine->pDhcpResultNotify->ClearDhcpResult(&pStaStateMachine->pDhcpResultNotify->DhcpIpv6Result);
    EXPECT_TRUE(pStaStateMachine->pDhcpResultNotify->DhcpIpv6Result.isOptSuc == 0);
    pStaStateMachine->pDhcpResultNotify->DhcpIpv4Result.isOptSuc = 1;
    pStaStateMachine->pDhcpResultNotify->ClearDhcpResult(&pStaStateMachine->pDhcpResultNotify->DhcpIpv4Result);
    EXPECT_TRUE(pStaStateMachine->pDhcpResultNotify->DhcpIpv4Result.isOptSuc == 0);
}

HWTEST_F(StaStateMachineTest, TryToSaveIpV4ResultHostnameMatchTest, TestSize.Level1)
{
    TryToSaveIpV4ResultHostnameMatchTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, TryToSaveIpV4ResultHostnameNoMatchTest, TestSize.Level1)
{
    TryToSaveIpV4ResultHostnameNoMatchTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, TryToSaveIpV4ResultIpNoMatchTest, TestSize.Level1)
{
    TryToSaveIpV4ResultIpNoMatchTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(StaStateMachineTest, TryToSaveIpV4ResultMaskNoMatchTest, TestSize.Level1)
{
    TryToSaveIpV4ResultMaskNoMatchTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

#ifdef READ_MAC_FROM_OEM
HWTEST_F(StaStateMachineTest, GetRealMacAddressFromOemInfoTest, TestSize.Level1)
{
    EXPECT_TRUE(pStaStateMachine->pClosedState->GetRealMacAddressFromOemInfo());
}
#endif
 
HWTEST_F(StaStateMachineTest, GetRealMacAddressFromHalTest, TestSize.Level1)
{
    pStaStateMachine->pClosedState->GetRealMacAddressFromHal();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

#ifdef DYNAMIC_ADJUST_WIFI_POWER_SAVE
HWTEST_F(StaStateMachineTest, DealWifiPowerSaveWhenBatteryStatusNotifyTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetParam1(MODE_STATE_CLOSE);
    msg->SetMessageName(WIFI_BATTERY_STATE_CHANGED_NOTIFY_EVENT);
    EXPECT_TRUE(pStaStateMachine->pLinkedState->ExecuteStateMsg(msg));
}

HWTEST_F(StaStateMachineTest, DealWifiPowerSaveWhenBatteryStatusNotifyTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetParam1(MODE_STATE_OPEN);
    msg->SetMessageName(WIFI_BATTERY_STATE_CHANGED_NOTIFY_EVENT);
    EXPECT_TRUE(pStaStateMachine->pLinkedState->ExecuteStateMsg(msg));
}

HWTEST_F(StaStateMachineTest, DealWifiPowerSaveWhenScreenStatusNotifyTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetParam1(MODE_STATE_CLOSE);
    msg->SetMessageName(WIFI_SCREEN_STATE_CHANGED_NOTIFY_EVENT);
    EXPECT_TRUE(pStaStateMachine->pLinkedState->ExecuteStateMsg(msg));
}

HWTEST_F(StaStateMachineTest, DealWifiPowerSaveWhenScreenStatusNotifyTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetParam1(MODE_STATE_OPEN);
    msg->SetMessageName(WIFI_SCREEN_STATE_CHANGED_NOTIFY_EVENT);
    EXPECT_TRUE(pStaStateMachine->pLinkedState->ExecuteStateMsg(msg));
}
#endif

HWTEST_F(StaStateMachineTest, DealDisconnectEventInLinkStateTest01, TestSize.Level1)
{
    ConnState currentState = pStaStateMachine->linkedInfo.connState;
    pStaStateMachine->linkedInfo.networkId = 1;
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    int disReason = 8;
    msg->SetParam1(disReason);
    pStaStateMachine->pLinkState->pStaStateMachine->targetNetworkId_ = 0;
    pStaStateMachine->pLinkState->DealDisconnectEventInLinkState(msg);
    EXPECT_TRUE(currentState == pStaStateMachine->linkedInfo.connState);
}

HWTEST_F(StaStateMachineTest, TryFastReconnectTest01, TestSize.Level1)
{
    int reason = 3;
    std::string bssid = "xx:xx:xx:xx:xx:xx";
    bool ret = pStaStateMachine->pLinkState->TryFastReconnect(reason, bssid);
    EXPECT_FALSE(ret);
}

HWTEST_F(StaStateMachineTest, TryFastReconnectTest02, TestSize.Level1)
{
    int reason = static_cast<int>(Wifi80211ReasonCode::WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA);
    std::string bssid = "xx:xx:xx:xx:xx:xx";
    pStaStateMachine->linkedInfo.rssi = -99;
    pStaStateMachine->linkedInfo.band = 2;
    bool ret = pStaStateMachine->pLinkState->TryFastReconnect(reason, bssid);
    EXPECT_FALSE(ret);
}

HWTEST_F(StaStateMachineTest, NotAllowConnectToNetworkTest01, TestSize.Level1)
{
    pStaStateMachine->targetNetworkId_ = 0;
    EXPECT_FALSE(pStaStateMachine->pInitState->NotAllowConnectToNetwork(1, RANDOMMAC_BSSID, NETWORK_SELECTED_BY_AUTO));
}

HWTEST_F(StaStateMachineTest, HasMultiBssidApTest01, TestSize.Level1)
{
    WifiDeviceConfig config;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
    EXPECT_FALSE(pStaStateMachine->HasMultiBssidAp(config));
}
} // namespace Wifi
} // namespace OHOS