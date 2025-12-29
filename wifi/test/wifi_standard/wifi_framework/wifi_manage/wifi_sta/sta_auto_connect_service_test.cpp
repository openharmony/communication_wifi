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
#include "sta_auto_connect_service.h"
#include "sta_state_machine.h"
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"
#include "mock_device_appraisal.h"
#include <gtest/gtest.h>
#include <vector>

#include "wifi_errcode.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "sta_device_appraisal.h"
#include "wifi_native_struct.h"
#include "wifi_error_no.h"
#include "mock_block_connect_service.h"

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
constexpr int NETWORK_ID = 15;
constexpr int BAND = 2;
constexpr int RSSI = 8;
constexpr int SMALLER_THAN_RSSI_DELIMITING_VALUE = -66;
constexpr int FREQUENCY = 5200;
constexpr int INVALIDRSSI = -90;
constexpr int TWO = 2;
static std::string g_errLog;
void StaAutoConnectServiceCallback(const LogType type, const LogLevel level, const unsigned int domain,
                                   const char *tag, const char *msg)
{
    g_errLog = msg;
}

class StaAutoConnectServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pStaStateMachine = new (std::nothrow) StaStateMachine();
        pStaAutoConnectService = new (std::nothrow) StaAutoConnectService(pStaStateMachine);
        pMockDeviceAppraisal = new (std::nothrow) MockDeviceAppraisal();
        InitAutoConnectService();
        LOG_SetCallback(StaAutoConnectServiceCallback);
    }
    virtual void TearDown()
    {
        if (pStaStateMachine != nullptr) {
            delete pStaStateMachine;
            pStaStateMachine = nullptr;
        }

        if (pStaAutoConnectService != nullptr) {
            delete pStaAutoConnectService;
            pStaAutoConnectService = nullptr;
        }

        if (pMockDeviceAppraisal != nullptr) {
            delete pMockDeviceAppraisal;
            pMockDeviceAppraisal = nullptr;
        }
    }

public:
    StaStateMachine *pStaStateMachine;
    StaAutoConnectService *pStaAutoConnectService;
    MockDeviceAppraisal *pMockDeviceAppraisal;

public:
    void InitAutoConnectService();
    void GetScanInfoConfig(InterScanInfo &scanInfo) const;
    void GetWifiDeviceConfig(WifiDeviceConfig &deviceConfig) const;
    void GetInterScanInfoVector(std::vector<InterScanInfo> &scanInfos) const;
    void GetWifiLinkedInfo(WifiLinkedInfo &info);
    void GetAllDeviceInfos(WifiDeviceConfig &deviceConfig, std::vector<InterScanInfo> &scanInfos,
        std::vector<std::string> &blockedBssids, WifiLinkedInfo &info);

    void InitAutoConnectServiceSuccess();
    void ClearSecondaryStateMachinePtrSuccess();
    void OnScanResultsReadyHandlerSuccess1();
    void OnScanResultsReadyHandlerSuccess2();
    void OnScanResultsReadyHandlerFail1();
    void OnScanResultsReadyHandlerFail2();
    void OnScanResultsReadyHandlerFail3();
    void OnScanResultsReadyHandlerFail4();
    void OnScanResultsReadyHandlerFail5();
    void OnScanResultsReadyHandlerFail6();
    void EnableOrDisableBssidSuccess1();
    void EnableOrDisableBssidSuccess2();
    void EnableOrDisableBssidFail1();
    void EnableOrDisableBssidFail2();
    void EnableOrDisableBssidFail3();
    void EnableOrDisableBssidFail4();
    void AutoSelectDeviceSuccess1();
    void AutoSelectDeviceSuccess2();
    void AutoSelectDeviceSuccess3();
    void AutoSelectDeviceFail1();
    void AutoSelectDeviceFail2();
    void AutoSelectDeviceFail3();
    void AutoSelectDeviceFail4();
    void AutoSelectDeviceFail5();
    void AutoSelectDeviceFail6();
    void RegisterDeviceAppraisalSuccess();
    void RegisterDeviceAppraisalFail1();
    void RegisterDeviceAppraisalFail2();
    void GetAvailableScanInfosSuccess();
    void GetAvailableScanInfosSuccess1();
    void GetAvailableScanInfosSuccess2();
    void GetAvailableScanInfosSuccess3();
    void AllowAutoSelectDeviceSuccess1();
    void AllowAutoSelectDeviceSuccess2();
    void AllowAutoSelectDeviceSuccess3();
    void AllowAutoSelectDeviceSuccess4();
    void AllowAutoSelectDeviceFail1();
    void AllowAutoSelectDeviceFail2();
    void AllowAutoSelectDeviceFail3();
    void AllowAutoSelectDeviceFail4();
    void AllowAutoSelectDeviceFail5();
    void CurrentDeviceGoodEnoughSuccess();
    void CurrentDeviceGoodEnoughFail1();
    void CurrentDeviceGoodEnoughFail2();
    void CurrentDeviceGoodEnoughFail3();
    void CurrentDeviceGoodEnoughFail4();
    void CurrentDeviceGoodEnoughFail5();
    void WhetherDevice5GAvailableSuccess();
    void WhetherDevice5GAvailableFail();
    void RoamingEncryptionModeCheckSuccess();
    void RoamingEncryptionModeCheckFail1();
    void RoamingEncryptionModeCheckFail2();
    void RoamingEncryptionModeCheckFail3();
    void RoamingEncryptionModeCheckFail4();
    void RoamingSelectionSuccess1();
    void RoamingSelectionFail1();
    void RoamingSelectionFail2();
    void RoamingSelectionFail3();
    void RoamingSelectionFail4();
    void DisableAutoJoinSuccess();
    void EnableAutoJoinSuccess();
    void RegisterAutoJoinConditionSuccess();
    void DeregisterAutoJoinConditionSuccess();
    void IsAutoConnectFailByP2PEnhanceFilterSucc1();
    void IsAutoConnectFailByP2PEnhanceFilterSucc2();
    void IsAutoConnectFailByP2PEnhanceFilterFail1();
    void OnScanInfosReadyHandlerWithSupplicantTransientState() const;
    void OnScanInfosReadyHandlerWithAsyncTaskDeduplication() const;
};

void StaAutoConnectServiceTest::InitAutoConnectService()
{
    WifiHalRoamCapability capability;
    capability.maxBlocklistSize = TWO;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsScoreSlope(_)).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsInitScore(_)).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsSameBssidScore(_)).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsSameNetworkScore(_)).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsFrequency5GHzScore(_)).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsLastSelectionScore(_)).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsSecurityScore(_)).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetSavedDeviceAppraisalPriority(_)).Times(AtLeast(1));
    EXPECT_CALL(WifiSettings::GetInstance(), GetExternDeviceAppraisalPriority()).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), ReloadDeviceConfig()).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsNormalScore(_)).Times(AtLeast(0));

    pStaAutoConnectService->InitAutoConnectService();
    for (int i = 0; i < MAX_APPRAISAL_NUM; i++) {
        pStaAutoConnectService->pAppraisals[i] = nullptr;
    }
    pStaAutoConnectService->pAppraisals[0] = pMockDeviceAppraisal;
}

void StaAutoConnectServiceTest::GetScanInfoConfig(InterScanInfo &scanInfo) const
{
    scanInfo.bssid = "2a:76:93:47:e2:8a";
    scanInfo.ssid = "HMWIFI_W2_EAP_G2_03";
    scanInfo.band = NETWORK_ID;
    scanInfo.rssi = RSSI;
    scanInfo.securityType = WifiSecurity::OPEN;
}

void StaAutoConnectServiceTest::GetWifiDeviceConfig(WifiDeviceConfig &deviceConfig) const
{
    deviceConfig.bssid = "2a:76:93:47:e2:8a";
    deviceConfig.band = BAND;
    deviceConfig.networkId = NETWORK_ID;
    deviceConfig.ssid = "HMWIFI_W2_EAP_G2_03";
    deviceConfig.keyMgmt = "123456";
}

void StaAutoConnectServiceTest::GetInterScanInfoVector(std::vector<InterScanInfo> &scanInfos) const
{
    InterScanInfo scanInfo;
    GetScanInfoConfig(scanInfo);
    scanInfos.push_back(scanInfo);
}

void StaAutoConnectServiceTest::GetWifiLinkedInfo(WifiLinkedInfo &info)
{
    info.detailedState = DetailedState::WORKING; // WORKING
    info.bssid = "2a:76:93:47:e2:8a";
    info.ssid = "HMWIFI_W2_EAP_G2_03";
    info.networkId = NETWORK_ID;
    info.connState = ConnState::CONNECTED;
}

void StaAutoConnectServiceTest::GetAllDeviceInfos(WifiDeviceConfig &deviceConfig, std::vector<InterScanInfo> &scanInfos,
    std::vector<std::string> &blockedBssids, WifiLinkedInfo &info)
{
    GetWifiDeviceConfig(deviceConfig);
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
}

void StaAutoConnectServiceTest::InitAutoConnectServiceSuccess()
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsScoreSlope(_))
        .Times(AtLeast(1))
        .WillOnce(Return(WIFI_HAL_OPT_OK));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsInitScore(_)).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsSameBssidScore(_)).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsSameNetworkScore(_)).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsFrequency5GHzScore(_)).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsLastSelectionScore(_)).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetScoretacticsSecurityScore(_)).Times(AtLeast(0));
    EXPECT_CALL(WifiSettings::GetInstance(), ReloadDeviceConfig()).Times(AtLeast(0));

    EXPECT_CALL(WifiSettings::GetInstance(), GetSavedDeviceAppraisalPriority(_)).Times(AtLeast(1));
    EXPECT_CALL(WifiSettings::GetInstance(), GetExternDeviceAppraisalPriority()).Times(AtLeast(0));

    EXPECT_TRUE(pStaAutoConnectService->InitAutoConnectService() == WIFI_OPT_SUCCESS);
}

void StaAutoConnectServiceTest::OnScanResultsReadyHandlerSuccess1()
{
    std::vector<InterScanInfo> scanInfos;
    scanInfos.emplace_back();
    WifiLinkedInfo infoPrimary;
    infoPrimary.connState = ConnState::UNKNOWN;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(infoPrimary), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(Return(-1)); // if it is false, it will do process.
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(1));
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfos);
}


void StaAutoConnectServiceTest::OnScanResultsReadyHandlerSuccess2()
{
    std::vector<InterScanInfo> scanInfos;
    scanInfos.emplace_back();
    WifiLinkedInfo infoPrimary;
    infoPrimary.connState = ConnState::DISCONNECTED; // DISCONNECTED
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(infoPrimary), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(1));
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfos);
}

void StaAutoConnectServiceTest::OnScanResultsReadyHandlerFail1()
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo infoPrimary;
    infoPrimary.connState = ConnState::SCANNING;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(infoPrimary), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(0);
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfos);
}

void StaAutoConnectServiceTest::OnScanResultsReadyHandlerFail2()
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo infoPrimary;
    infoPrimary.connState = ConnState::CONNECTING;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(infoPrimary), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(0);
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfos);
}

void StaAutoConnectServiceTest::OnScanResultsReadyHandlerFail3()
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo infoPrimary;
    infoPrimary.connState = ConnState::AUTHENTICATING;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(infoPrimary), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(0);
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfos);
}

void StaAutoConnectServiceTest::OnScanResultsReadyHandlerFail4()
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo infoPrimary;
    infoPrimary.connState = ConnState::OBTAINING_IPADDR;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(infoPrimary), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(0);
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfos);
}

void StaAutoConnectServiceTest::OnScanResultsReadyHandlerFail5()
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo infoPrimary;
    infoPrimary.connState = ConnState::CONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(infoPrimary), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(0);
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfos);
}

void StaAutoConnectServiceTest::OnScanResultsReadyHandlerFail6()
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo infoPrimary;
    infoPrimary.connState = ConnState::DISCONNECTING;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(infoPrimary), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(0);
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfos);
}

void StaAutoConnectServiceTest::OnScanInfosReadyHandlerWithSupplicantTransientState() const
{
    std::vector<InterScanInfo> scanInfos;
    scanInfos.emplace_back();
    WifiLinkedInfo infoPrimary;
    infoPrimary.connState = ConnState::DISCONNECTED;
    infoPrimary.supplicantState = SupplicantState::FOUR_WAY_HANDSHAKE;  // Transient state
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(infoPrimary), Return(0)));
    // Should not proceed to device config due to transient state check
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(0);
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfos);
}

void StaAutoConnectServiceTest::OnScanInfosReadyHandlerWithAsyncTaskDeduplication() const
{
    // Test async task deduplication logic
    std::vector<InterScanInfo> scanInfos;
    scanInfos.emplace_back();
    WifiLinkedInfo infoPrimary;
    infoPrimary.connState = ConnState::UNKNOWN;
    infoPrimary.supplicantState = SupplicantState::DISCONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(infoPrimary), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(Return(-1));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
    
    // Call twice to test task deduplication
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfos);
    pStaAutoConnectService->OnScanInfosReadyHandler(scanInfos);
}

void StaAutoConnectServiceTest::IsAutoConnectFailByP2PEnhanceFilterSucc1()
{
    std::vector<InterScanInfo> scanInfos;
    scanInfos.emplace_back();
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pEnhanceFreq()).WillOnce(Return(0));
    EXPECT_FALSE(pStaAutoConnectService->IsAutoConnectFailByP2PEnhanceFilter(scanInfos));
}

void StaAutoConnectServiceTest::IsAutoConnectFailByP2PEnhanceFilterSucc2()
{
    std::vector<InterScanInfo> scanInfos;
    scanInfos.emplace_back();
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pEnhanceFreq()).WillOnce(Return(FREQUENCY));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(1));
    EXPECT_TRUE(pStaAutoConnectService->IsAutoConnectFailByP2PEnhanceFilter(scanInfos));
}

void StaAutoConnectServiceTest::IsAutoConnectFailByP2PEnhanceFilterFail1()
{
    std::vector<InterScanInfo> scanInfos;
    GetInterScanInfoVector(scanInfos);
    scanInfos[0].frequency = FREQUENCY;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pEnhanceFreq()).WillOnce(Return(FREQUENCY));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(1));
    EXPECT_FALSE(pStaAutoConnectService->IsAutoConnectFailByP2PEnhanceFilter(scanInfos));
}

void StaAutoConnectServiceTest::EnableOrDisableBssidSuccess1()
{
    std::string bssid = "d8:c7:71:2f:14:d9";
    EXPECT_TRUE(pStaAutoConnectService->EnableOrDisableBssid(bssid, false, AP_CANNOT_HANDLE_NEW_STA));
}

void StaAutoConnectServiceTest::EnableOrDisableBssidSuccess2()
{
    std::string bssid = "d8:c7:71:2f:14:d9";
    EXPECT_TRUE(pStaAutoConnectService->EnableOrDisableBssid(bssid, false, AP_CANNOT_HANDLE_NEW_STA));
    EXPECT_TRUE(pStaAutoConnectService->EnableOrDisableBssid(bssid, true, AP_CANNOT_HANDLE_NEW_STA));
}

void StaAutoConnectServiceTest::EnableOrDisableBssidFail1()
{
    std::string bssid = "";
    EXPECT_FALSE(pStaAutoConnectService->EnableOrDisableBssid(bssid, true, AP_CANNOT_HANDLE_NEW_STA));
}

void StaAutoConnectServiceTest::EnableOrDisableBssidFail2()
{
    std::string bssid = "";
    EXPECT_FALSE(pStaAutoConnectService->EnableOrDisableBssid(bssid, false, AP_CANNOT_HANDLE_NEW_STA));
}

void StaAutoConnectServiceTest::EnableOrDisableBssidFail3()
{
    std::string bssid = "d8:c7:71:2f:14:d9";
    EXPECT_TRUE(pStaAutoConnectService->EnableOrDisableBssid(bssid, true, AP_CANNOT_HANDLE_NEW_STA));
}

void StaAutoConnectServiceTest::EnableOrDisableBssidFail4()
{
    std::string bssid = "d8:c7:71:2f:14:d9";
    const int AP_CANNOT_HANDLE_NEW_STA_ERR = 1;
    EXPECT_TRUE(pStaAutoConnectService->EnableOrDisableBssid(bssid, false, AP_CANNOT_HANDLE_NEW_STA_ERR));
}

void StaAutoConnectServiceTest::AutoSelectDeviceSuccess1()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    GetAllDeviceInfos(deviceConfig, scanInfos, blockedBssids, info);

    EXPECT_CALL(WifiSettings::GetInstance(), GetWhetherToAllowNetworkSwitchover(_)).WillOnce(Return(true));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(Return(-1)); // if it is false, it will do process.
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
    EXPECT_CALL(*(pMockDeviceAppraisal), DeviceAppraisals(_, _, _)).WillOnce(Return(WIFI_OPT_SUCCESS));

    EXPECT_TRUE(pStaAutoConnectService->AutoSelectDevice(deviceConfig, scanInfos, blockedBssids, info) ==
        WIFI_OPT_SUCCESS);
}

void StaAutoConnectServiceTest::AutoSelectDeviceSuccess2()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    GetAllDeviceInfos(deviceConfig, scanInfos, blockedBssids, info);
    info.detailedState = DetailedState::DISCONNECTED; // DISCONNECTED

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
    EXPECT_CALL(*(pMockDeviceAppraisal), DeviceAppraisals(_, _, _)).WillOnce(Return(WIFI_OPT_SUCCESS));

    EXPECT_TRUE(pStaAutoConnectService->AutoSelectDevice(deviceConfig, scanInfos, blockedBssids, info) ==
        WIFI_OPT_SUCCESS);
}

void StaAutoConnectServiceTest::AutoSelectDeviceSuccess3()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    GetAllDeviceInfos(deviceConfig, scanInfos, blockedBssids, info);
    info.detailedState = DetailedState::NOTWORKING; // NOTWORKING

    EXPECT_CALL(WifiSettings::GetInstance(), GetWhetherToAllowNetworkSwitchover(_))
        .Times(AtLeast(1))
        .WillOnce(Return(true));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
    EXPECT_CALL(*(pMockDeviceAppraisal), DeviceAppraisals(_, _, _)).WillOnce(Return(WIFI_OPT_SUCCESS));

    EXPECT_TRUE(pStaAutoConnectService->AutoSelectDevice(deviceConfig, scanInfos, blockedBssids, info) ==
        WIFI_OPT_SUCCESS);
}

void StaAutoConnectServiceTest::AutoSelectDeviceFail1()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    GetAllDeviceInfos(deviceConfig, scanInfos, blockedBssids, info);

    EXPECT_CALL(WifiSettings::GetInstance(), GetWhetherToAllowNetworkSwitchover(_)).WillOnce(Return(false));

    EXPECT_TRUE(pStaAutoConnectService->AutoSelectDevice(deviceConfig, scanInfos, blockedBssids, info) ==
        WIFI_OPT_FAILED);
}

void StaAutoConnectServiceTest::AutoSelectDeviceFail2()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    GetAllDeviceInfos(deviceConfig, scanInfos, blockedBssids, info);

    EXPECT_CALL(WifiSettings::GetInstance(), GetWhetherToAllowNetworkSwitchover(_)).WillOnce(Return(true));
    /* CurrentDeviceGoodEnough:: There is enough devices, so need not devices at start. */
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillOnce(DoAll(SetArgReferee<1>(deviceConfig), Return(0))); // if it is true, it will do not process.
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetUserLastSelectedNetworkId(_)).Times(AtLeast(0)).WillOnce(Return(0));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).Times(AtLeast(0));
    EXPECT_TRUE(pStaAutoConnectService->AutoSelectDevice(deviceConfig, scanInfos, blockedBssids, info) ==
        WIFI_OPT_FAILED);
}

void StaAutoConnectServiceTest::AutoSelectDeviceFail3()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    GetAllDeviceInfos(deviceConfig, scanInfos, blockedBssids, info);

    EXPECT_CALL(WifiSettings::GetInstance(), GetWhetherToAllowNetworkSwitchover(_)).WillOnce(Return(true));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(Return(-1)); // if it is false, it will do process.
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
    EXPECT_CALL(*(pMockDeviceAppraisal), DeviceAppraisals(_, _, _)).WillOnce(Return(WIFI_OPT_FAILED));

    EXPECT_TRUE(pStaAutoConnectService->AutoSelectDevice(deviceConfig, scanInfos, blockedBssids, info) ==
        WIFI_OPT_FAILED);
}

void StaAutoConnectServiceTest::AutoSelectDeviceFail4()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    GetAllDeviceInfos(deviceConfig, scanInfos, blockedBssids, info);
    info.detailedState = DetailedState::DISCONNECTED; // DISCONNECTED

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
    EXPECT_CALL(*(pMockDeviceAppraisal), DeviceAppraisals(_, _, _)).WillOnce(Return(WIFI_OPT_FAILED));

    EXPECT_TRUE(pStaAutoConnectService->AutoSelectDevice(deviceConfig, scanInfos, blockedBssids, info) ==
        WIFI_OPT_FAILED);
}

void StaAutoConnectServiceTest::AutoSelectDeviceFail5()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    GetAllDeviceInfos(deviceConfig, scanInfos, blockedBssids, info);
    info.detailedState = DetailedState::NOTWORKING; // NOTWORKING

    EXPECT_CALL(WifiSettings::GetInstance(), GetWhetherToAllowNetworkSwitchover(_))
        .Times(AtLeast(1))
        .WillOnce(Return(false));

    EXPECT_TRUE(pStaAutoConnectService->AutoSelectDevice(deviceConfig, scanInfos, blockedBssids, info) ==
        WIFI_OPT_FAILED);
}

void StaAutoConnectServiceTest::AutoSelectDeviceFail6()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    GetAllDeviceInfos(deviceConfig, scanInfos, blockedBssids, info);
    info.detailedState = DetailedState::NOTWORKING; // NOTWORKING

    EXPECT_CALL(WifiSettings::GetInstance(), GetWhetherToAllowNetworkSwitchover(_))
        .Times(AtLeast(1))
        .WillOnce(Return(true));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
    EXPECT_CALL(*(pMockDeviceAppraisal), DeviceAppraisals(_, _, _)).WillOnce(Return(WIFI_OPT_FAILED));

    EXPECT_TRUE(pStaAutoConnectService->AutoSelectDevice(deviceConfig, scanInfos, blockedBssids, info) ==
        WIFI_OPT_FAILED);
}

void StaAutoConnectServiceTest::RegisterDeviceAppraisalSuccess()
{
    StaDeviceAppraisal *appraisal = nullptr;
    int priority = 1; // 0~6
    EXPECT_TRUE(pStaAutoConnectService->RegisterDeviceAppraisal(appraisal, priority) == true);
}

void StaAutoConnectServiceTest::RegisterDeviceAppraisalFail1()
{
    StaDeviceAppraisal *appraisal = nullptr;
    int priority = -1; // 0~6
    EXPECT_TRUE(pStaAutoConnectService->RegisterDeviceAppraisal(appraisal, priority) == false);
}


void StaAutoConnectServiceTest::RegisterDeviceAppraisalFail2()
{
    StaDeviceAppraisal *appraisal = nullptr;
    int priority = 7; // 0~6
    EXPECT_TRUE(pStaAutoConnectService->RegisterDeviceAppraisal(appraisal, priority) == false);
}

void StaAutoConnectServiceTest::GetAvailableScanInfosSuccess()
{
    std::vector<InterScanInfo> availableScanInfos;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    GetInterScanInfoVector(availableScanInfos);
    GetInterScanInfoVector(scanInfos);
    std::string bssid1 = "2a:76:93:47:e2:8a";
    blockedBssids.push_back(bssid1);
    GetWifiLinkedInfo(info);
    WifiDeviceConfig deviceConfig;
    GetWifiDeviceConfig(deviceConfig);

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(deviceConfig.bssid, DEVICE_CONFIG_INDEX_BSSID, _, _))
    .Times(AtLeast(0)).WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(0)));

    pStaAutoConnectService->GetAvailableScanInfos(availableScanInfos, scanInfos, blockedBssids, info);
}

void StaAutoConnectServiceTest::GetAvailableScanInfosSuccess1()
{
    std::vector<InterScanInfo> availableScanInfos;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    GetInterScanInfoVector(availableScanInfos);

    InterScanInfo scanInfo;
    scanInfo.bssid = "2a:76:93:47:e2:8a";
    scanInfo.ssid = "";
    scanInfo.band = NETWORK_ID;
    scanInfo.rssi = RSSI;
    scanInfo.securityType = WifiSecurity::OPEN;
    scanInfos.push_back(scanInfo);

    std::string bssid1 = "2a:76:93:47:e2:8a";
    blockedBssids.push_back(bssid1);
    GetWifiLinkedInfo(info);
    WifiDeviceConfig deviceConfig;
    GetWifiDeviceConfig(deviceConfig);
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(deviceConfig.bssid, DEVICE_CONFIG_INDEX_BSSID, _, _))
    .Times(AtLeast(0)).WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(0)));
    pStaAutoConnectService->GetAvailableScanInfos(availableScanInfos, scanInfos, blockedBssids, info);
}

void StaAutoConnectServiceTest::GetAvailableScanInfosSuccess2()
{
    std::vector<InterScanInfo> availableScanInfos;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    GetInterScanInfoVector(availableScanInfos);

    InterScanInfo scanInfo;
    scanInfo.bssid = "2a:76:93:47:e2:8a";
    scanInfo.ssid = "HMWIFI_W2_EAP_G2_03";
    scanInfo.band = NETWORK_ID;
    scanInfo.rssi = INVALIDRSSI;
    scanInfo.securityType = WifiSecurity::OPEN;
    scanInfos.push_back(scanInfo);

    std::string bssid1 = "2a:76:93:47:e2:8a";
    blockedBssids.push_back(bssid1);
    GetWifiLinkedInfo(info);
    WifiDeviceConfig deviceConfig;
    GetWifiDeviceConfig(deviceConfig);
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(deviceConfig.bssid, DEVICE_CONFIG_INDEX_BSSID, _, _))
    .Times(AtLeast(0)).WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(0)));
    pStaAutoConnectService->GetAvailableScanInfos(availableScanInfos, scanInfos, blockedBssids, info);
}

void StaAutoConnectServiceTest::GetAvailableScanInfosSuccess3()
{
    std::vector<InterScanInfo> availableScanInfos;
    std::vector<InterScanInfo> scanInfos;
    std::vector<std::string> blockedBssids;
    WifiLinkedInfo info;
    GetInterScanInfoVector(availableScanInfos);

    InterScanInfo scanInfo;
    scanInfo.bssid = "2a:76:93:47:e2:8a";
    scanInfo.ssid = "HMWIFI_W2_EAP_G2_03";
    scanInfo.band = NETWORK_ID;
    scanInfo.rssi = INVALIDRSSI;
    scanInfo.securityType = WifiSecurity::OPEN;
    scanInfo.frequency = FREQUENCY;
    scanInfos.push_back(scanInfo);

    std::string bssid1 = "2a:76:93:47:e2:8a";
    blockedBssids.push_back(bssid1);
    GetWifiLinkedInfo(info);
    WifiDeviceConfig deviceConfig;
    GetWifiDeviceConfig(deviceConfig);
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(deviceConfig.bssid, DEVICE_CONFIG_INDEX_BSSID, _, _))
    .Times(AtLeast(0)).WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(0)));
    pStaAutoConnectService->GetAvailableScanInfos(availableScanInfos, scanInfos, blockedBssids, info);
}

void StaAutoConnectServiceTest::AllowAutoSelectDeviceSuccess1()
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);

    EXPECT_CALL(WifiSettings::GetInstance(), GetWhetherToAllowNetworkSwitchover(_)).WillOnce(Return(true));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(Return(-1)); // if it is false, it will do process.
    EXPECT_TRUE(pStaAutoConnectService->AllowAutoSelectDevice(scanInfos, info) == true);
}

void StaAutoConnectServiceTest::AllowAutoSelectDeviceSuccess2()
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    info.detailedState = DetailedState::DISCONNECTED;
    EXPECT_TRUE(pStaAutoConnectService->AllowAutoSelectDevice(scanInfos, info) == true);
}

void StaAutoConnectServiceTest::AllowAutoSelectDeviceSuccess3()
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    info.detailedState = DetailedState::NOTWORKING;

    EXPECT_CALL(WifiSettings::GetInstance(), GetWhetherToAllowNetworkSwitchover(_)).WillOnce(Return(true));
    EXPECT_TRUE(pStaAutoConnectService->AllowAutoSelectDevice(scanInfos, info) == true);
}

void StaAutoConnectServiceTest::AllowAutoSelectDeviceSuccess4()
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    info.detailedState = DetailedState::PASSWORD_ERROR;

    EXPECT_CALL(WifiSettings::GetInstance(), GetWhetherToAllowNetworkSwitchover(_)).WillOnce(Return(true));
    EXPECT_TRUE(pStaAutoConnectService->AllowAutoSelectDevice(scanInfos, info) == true);
}

void StaAutoConnectServiceTest::AllowAutoSelectDeviceFail1()
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);

    EXPECT_CALL(WifiSettings::GetInstance(), GetWhetherToAllowNetworkSwitchover(_)).WillOnce(Return(false));
    EXPECT_TRUE(pStaAutoConnectService->AllowAutoSelectDevice(scanInfos, info) == false);
}

void StaAutoConnectServiceTest::AllowAutoSelectDeviceFail2()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    deviceConfig.networkId = 0;

    EXPECT_CALL(WifiSettings::GetInstance(), GetWhetherToAllowNetworkSwitchover(_)).WillOnce(Return(true));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillOnce(DoAll(SetArgReferee<1>(deviceConfig), Return(0))); // if it is true, it will do not process.
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetUserLastSelectedNetworkId(_)).Times(AtLeast(1)).WillOnce(Return(0));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).Times(AtLeast(0));
    EXPECT_TRUE(pStaAutoConnectService->AllowAutoSelectDevice(scanInfos, info) == false);
}

void StaAutoConnectServiceTest::AllowAutoSelectDeviceFail3()
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    info.detailedState = DetailedState::NOTWORKING;

    EXPECT_CALL(WifiSettings::GetInstance(), GetWhetherToAllowNetworkSwitchover(_)).WillOnce(Return(false));
    EXPECT_TRUE(pStaAutoConnectService->AllowAutoSelectDevice(scanInfos, info) == false);
}

void StaAutoConnectServiceTest::AllowAutoSelectDeviceFail4()
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    info.detailedState = DetailedState::INVALID;

    EXPECT_TRUE(pStaAutoConnectService->AllowAutoSelectDevice(scanInfos, info) == false);
}

void StaAutoConnectServiceTest::AllowAutoSelectDeviceFail5()
{
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetWifiLinkedInfo(info);
    info.detailedState = DetailedState::INVALID;
    EXPECT_TRUE(pStaAutoConnectService->AllowAutoSelectDevice(scanInfos, info) == false);
}

void StaAutoConnectServiceTest::CurrentDeviceGoodEnoughSuccess()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    deviceConfig.networkId = 0;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillOnce(DoAll(SetArgReferee<1>(deviceConfig), Return(0)));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetUserLastSelectedNetworkId(_)).Times(AtLeast(1)).WillOnce(Return(0));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetUserLastSelectedNetworkTimeVal(_)).Times(AtLeast(1));
    EXPECT_TRUE(pStaAutoConnectService->CurrentDeviceGoodEnough(scanInfos, info) == true);
}


void StaAutoConnectServiceTest::CurrentDeviceGoodEnoughFail1()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillOnce(DoAll(SetArgReferee<1>(deviceConfig), Return(-1)));
    EXPECT_TRUE(pStaAutoConnectService->CurrentDeviceGoodEnough(scanInfos, info) == false);
}

void StaAutoConnectServiceTest::CurrentDeviceGoodEnoughFail2()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    deviceConfig.isEphemeral = true;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillOnce(DoAll(SetArgReferee<1>(deviceConfig), Return(0)));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetUserLastSelectedNetworkId(_))
        .Times(AtLeast(1))
        .WillOnce(Return(INVALID_NETWORK_ID));

    EXPECT_TRUE(pStaAutoConnectService->CurrentDeviceGoodEnough(scanInfos, info) == false);
}

void StaAutoConnectServiceTest::CurrentDeviceGoodEnoughFail3()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    deviceConfig.isEphemeral = false;
    deviceConfig.keyMgmt = "NONE";
    deviceConfig.wepTxKeyIndex = -1;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillOnce(DoAll(SetArgReferee<1>(deviceConfig), Return(0)));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetUserLastSelectedNetworkId(_))
        .Times(AtLeast(1))
        .WillOnce(Return(INVALID_NETWORK_ID));

    EXPECT_TRUE(pStaAutoConnectService->CurrentDeviceGoodEnough(scanInfos, info) == false);
}


void StaAutoConnectServiceTest::CurrentDeviceGoodEnoughFail4()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    info.rssi = SMALLER_THAN_RSSI_DELIMITING_VALUE;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillOnce(DoAll(SetArgReferee<1>(deviceConfig), Return(0)));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetUserLastSelectedNetworkId(_))
        .Times(AtLeast(1))
        .WillOnce(Return(INVALID_NETWORK_ID));

    EXPECT_TRUE(pStaAutoConnectService->CurrentDeviceGoodEnough(scanInfos, info) == false);
}

void StaAutoConnectServiceTest::CurrentDeviceGoodEnoughFail5()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    info.band = static_cast<int>(BandType::BAND_2GHZ);
    info.frequency = MIN_24_FREQUENCY + 1;
    scanInfos[0].band = NETWORK_5G_BAND;
    scanInfos[0].frequency = MIN_5_FREQUENCY + 1;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillOnce(DoAll(SetArgReferee<1>(deviceConfig), Return(0)));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetUserLastSelectedNetworkId(_))
        .Times(AtLeast(1))
        .WillOnce(Return(INVALID_NETWORK_ID));

    EXPECT_TRUE(pStaAutoConnectService->CurrentDeviceGoodEnough(scanInfos, info) == false);
}

void StaAutoConnectServiceTest::WhetherDevice5GAvailableSuccess()
{
    std::vector<InterScanInfo> scanInfos;
    GetInterScanInfoVector(scanInfos);
    scanInfos[0].band = NETWORK_5G_BAND;
    scanInfos[0].frequency = MIN_5_FREQUENCY + 1;

    EXPECT_TRUE(pStaAutoConnectService->WhetherDevice5GAvailable(scanInfos) == true);
}

void StaAutoConnectServiceTest::WhetherDevice5GAvailableFail()
{
    std::vector<InterScanInfo> scanInfos;
    GetInterScanInfoVector(scanInfos);

    EXPECT_TRUE(pStaAutoConnectService->WhetherDevice5GAvailable(scanInfos) == false);
}

void StaAutoConnectServiceTest::RoamingEncryptionModeCheckSuccess()
{
    WifiDeviceConfig deviceConfig;
    InterScanInfo scanInfo;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetScanInfoConfig(scanInfo);
    GetWifiLinkedInfo(info);
    info.connState = ConnState::CONNECTED;
    scanInfo.securityType = WifiSecurity::WEP;
    deviceConfig.wepTxKeyIndex = 0;
    deviceConfig.keyMgmt = "NONE";
    scanInfo.rssi = 8;
    info.rssi = 1;
    int indexType = DEVICE_CONFIG_INDEX_SSID;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(scanInfo.ssid, indexType, _, _))
        .WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(0)));

    EXPECT_TRUE(pStaAutoConnectService->RoamingEncryptionModeCheck(deviceConfig, scanInfo, info) == true);
}

void StaAutoConnectServiceTest::RoamingEncryptionModeCheckFail1()
{
    WifiDeviceConfig deviceConfig;
    InterScanInfo scanInfo;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetScanInfoConfig(scanInfo);
    GetWifiLinkedInfo(info);
    int indexType = DEVICE_CONFIG_INDEX_SSID;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(scanInfo.ssid, indexType, _, _))
        .WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(0)));

    EXPECT_TRUE(pStaAutoConnectService->RoamingEncryptionModeCheck(deviceConfig, scanInfo, info) == false);
}

void StaAutoConnectServiceTest::RoamingEncryptionModeCheckFail2()
{
    WifiDeviceConfig deviceConfig;
    InterScanInfo scanInfo;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetScanInfoConfig(scanInfo);
    GetWifiLinkedInfo(info);
    scanInfo.securityType = WifiSecurity::WEP;
    deviceConfig.wepTxKeyIndex = -1;
    int indexType = DEVICE_CONFIG_INDEX_SSID;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(scanInfo.ssid, indexType, _, _))
        .WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(0)));

    EXPECT_TRUE(pStaAutoConnectService->RoamingEncryptionModeCheck(deviceConfig, scanInfo, info) == false);
}

void StaAutoConnectServiceTest::RoamingEncryptionModeCheckFail3()
{
    WifiDeviceConfig deviceConfig;
    InterScanInfo scanInfo;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetScanInfoConfig(scanInfo);
    GetWifiLinkedInfo(info);
    info.connState = ConnState::CONNECTED;
    scanInfo.securityType = WifiSecurity::PSK;
    deviceConfig.wepTxKeyIndex = 1;
    deviceConfig.keyMgmt = "NONE";
    int indexType = DEVICE_CONFIG_INDEX_SSID;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(scanInfo.ssid, indexType, _, _))
        .WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(0)));

    EXPECT_TRUE(pStaAutoConnectService->RoamingEncryptionModeCheck(deviceConfig, scanInfo, info) == false);
}

void StaAutoConnectServiceTest::RoamingEncryptionModeCheckFail4()
{
    WifiDeviceConfig deviceConfig;
    InterScanInfo scanInfo;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetScanInfoConfig(scanInfo);
    GetWifiLinkedInfo(info);
    info.connState = ConnState::CONNECTED;
    scanInfo.securityType = WifiSecurity::WEP;
    deviceConfig.wepTxKeyIndex = 1;
    deviceConfig.keyMgmt = "WPA-PSK";
    int indexType = DEVICE_CONFIG_INDEX_SSID;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(scanInfo.ssid, indexType, _, _))
        .WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(0)));

    EXPECT_TRUE(pStaAutoConnectService->RoamingEncryptionModeCheck(deviceConfig, scanInfo, info) == false);
}

void StaAutoConnectServiceTest::RoamingSelectionSuccess1()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    deviceConfig.wepTxKeyIndex = 0;
    deviceConfig.keyMgmt = "NONE";
    info.connState = ConnState::CONNECTED;
    scanInfos[0].securityType = WifiSecurity::WEP;
    scanInfos[0].rssi = 8;
    scanInfos[0].ssid = "ohos";
    scanInfos[0].bssid = "2a:76:93:47:e2:8e";
    info.ssid = "ohos";
    info.bssid = "2a:76:93:47:e2:8b";
    info.rssi = 1;
    int indexType = DEVICE_CONFIG_INDEX_SSID;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(scanInfos[0].ssid, indexType, _, _))
        .WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(0)));

    EXPECT_TRUE(pStaAutoConnectService->RoamingSelection(deviceConfig, scanInfos, info) == true);
}

void StaAutoConnectServiceTest::RoamingSelectionFail1()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    info.connState = ConnState::CONNECTED;
    info.bssid = "2a:76:93:47:e2:8b";

    int indexType = DEVICE_CONFIG_INDEX_SSID;


    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(scanInfos[0].ssid, indexType, _, _))
        .WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(0)));

    EXPECT_TRUE(pStaAutoConnectService->RoamingSelection(deviceConfig, scanInfos, info) == false);
}

void StaAutoConnectServiceTest::RoamingSelectionFail2()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    deviceConfig.wepTxKeyIndex = -1;
    scanInfos[0].securityType = WifiSecurity::WEP;
    info.connState = ConnState::CONNECTED;
    info.bssid = "2a:76:93:47:e2:8b";
    int indexType = DEVICE_CONFIG_INDEX_SSID;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(scanInfos[0].ssid, indexType, _, _))
        .WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(0)));

    EXPECT_TRUE(pStaAutoConnectService->RoamingSelection(deviceConfig, scanInfos, info) == false);
}

void StaAutoConnectServiceTest::RoamingSelectionFail3()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    deviceConfig.wepTxKeyIndex = 1;
    deviceConfig.keyMgmt = "NONE";
    scanInfos[0].securityType = WifiSecurity::PSK;
    info.connState = ConnState::CONNECTED;
    info.bssid = "2a:76:93:47:e2:8b";
    info.connState = ConnState::CONNECTED;
    int indexType = DEVICE_CONFIG_INDEX_SSID;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(scanInfos[0].ssid, indexType, _, _))
        .WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(0)));

    EXPECT_TRUE(pStaAutoConnectService->RoamingSelection(deviceConfig, scanInfos, info) == false);
}

void StaAutoConnectServiceTest::RoamingSelectionFail4()
{
    WifiDeviceConfig deviceConfig;
    std::vector<InterScanInfo> scanInfos;
    WifiLinkedInfo info;
    GetWifiDeviceConfig(deviceConfig);
    GetInterScanInfoVector(scanInfos);
    GetWifiLinkedInfo(info);
    deviceConfig.wepTxKeyIndex = 1;
    deviceConfig.keyMgmt = "WPA-PSK";
    scanInfos[0].securityType = WifiSecurity::WEP;
    info.connState = ConnState::CONNECTED;
    info.bssid = "2a:76:93:47:e2:8b";
    info.connState = ConnState::CONNECTED;
    int indexType = DEVICE_CONFIG_INDEX_SSID;

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(scanInfos[0].ssid, indexType, _, _))
        .WillOnce(DoAll(SetArgReferee<TWO>(deviceConfig), Return(0)));

    EXPECT_TRUE(pStaAutoConnectService->RoamingSelection(deviceConfig, scanInfos, info) == false);
}

void StaAutoConnectServiceTest::DisableAutoJoinSuccess()
{
    std::string conditionName;
    pStaAutoConnectService->DisableAutoJoin(conditionName);
}
 
void StaAutoConnectServiceTest::EnableAutoJoinSuccess()
{
    std::string conditionName;
    pStaAutoConnectService->EnableAutoJoin(conditionName);
}
 
void StaAutoConnectServiceTest::RegisterAutoJoinConditionSuccess()
{
    std::string conditionName;
    pStaAutoConnectService->RegisterAutoJoinCondition(conditionName, []() {return true;});
}
void StaAutoConnectServiceTest::DeregisterAutoJoinConditionSuccess()
{
    std::string conditionName;
    pStaAutoConnectService->DeregisterAutoJoinCondition(conditionName);
}

/* ************************ HWTEST_F  ************************************ */


HWTEST_F(StaAutoConnectServiceTest, InitAutoConnectServiceSuccess, TestSize.Level0)
{
    InitAutoConnectServiceSuccess();
}

HWTEST_F(StaAutoConnectServiceTest, OnScanResultsReadyHandlerSuccess1, TestSize.Level0)
{
    OnScanResultsReadyHandlerSuccess1();
}

HWTEST_F(StaAutoConnectServiceTest, OnScanResultsReadyHandlerSuccess2, TestSize.Level0)
{
    OnScanResultsReadyHandlerSuccess2();
}

HWTEST_F(StaAutoConnectServiceTest, OnScanResultsReadyHandlerFail1, TestSize.Level0)
{
    OnScanResultsReadyHandlerFail1();
}

HWTEST_F(StaAutoConnectServiceTest, OnScanResultsReadyHandlerFail2, TestSize.Level0)
{
    OnScanResultsReadyHandlerFail2();
}

HWTEST_F(StaAutoConnectServiceTest, OnScanResultsReadyHandlerFail3, TestSize.Level0)
{
    OnScanResultsReadyHandlerFail3();
}

HWTEST_F(StaAutoConnectServiceTest, OnScanResultsReadyHandlerFail4, TestSize.Level0)
{
    OnScanResultsReadyHandlerFail4();
}


HWTEST_F(StaAutoConnectServiceTest, OnScanResultsReadyHandlerFail5, TestSize.Level0)
{
    OnScanResultsReadyHandlerFail5();
}


HWTEST_F(StaAutoConnectServiceTest, OnScanResultsReadyHandlerFail6, TestSize.Level0)
{
    OnScanResultsReadyHandlerFail6();
}

HWTEST_F(StaAutoConnectServiceTest, EnableOrDisableBssidSuccess1, TestSize.Level0)
{
    EnableOrDisableBssidSuccess1();
}

HWTEST_F(StaAutoConnectServiceTest, EnableOrDisableBssidSuccess2, TestSize.Level0)
{
    EnableOrDisableBssidSuccess2();
}

HWTEST_F(StaAutoConnectServiceTest, EnableOrDisableBssidFail1, TestSize.Level0)
{
    EnableOrDisableBssidFail1();
}

HWTEST_F(StaAutoConnectServiceTest, EnableOrDisableBssidFail2, TestSize.Level0)
{
    EnableOrDisableBssidFail2();
}

HWTEST_F(StaAutoConnectServiceTest, EnableOrDisableBssidFail3, TestSize.Level0)
{
    EnableOrDisableBssidFail3();
}

HWTEST_F(StaAutoConnectServiceTest, EnableOrDisableBssidFail4, TestSize.Level0)
{
    EnableOrDisableBssidFail4();
}

HWTEST_F(StaAutoConnectServiceTest, AutoSelectDeviceSuccess1, TestSize.Level0)
{
    AutoSelectDeviceSuccess1();
}

HWTEST_F(StaAutoConnectServiceTest, AutoSelectDeviceSuccess2, TestSize.Level0)
{
    AutoSelectDeviceSuccess2();
}

HWTEST_F(StaAutoConnectServiceTest, AutoSelectDeviceSuccess3, TestSize.Level0)
{
    AutoSelectDeviceSuccess3();
}

HWTEST_F(StaAutoConnectServiceTest, AutoSelectDeviceFail1, TestSize.Level0)
{
    AutoSelectDeviceFail1();
}

HWTEST_F(StaAutoConnectServiceTest, AutoSelectDeviceFail2, TestSize.Level0)
{
    AutoSelectDeviceFail2();
}

HWTEST_F(StaAutoConnectServiceTest, AutoSelectDeviceFail3, TestSize.Level0)
{
    AutoSelectDeviceFail3();
}

HWTEST_F(StaAutoConnectServiceTest, AutoSelectDeviceFail4, TestSize.Level0)
{
    AutoSelectDeviceFail4();
}

HWTEST_F(StaAutoConnectServiceTest, AutoSelectDeviceFail5, TestSize.Level0)
{
    AutoSelectDeviceFail5();
}

HWTEST_F(StaAutoConnectServiceTest, AutoSelectDeviceFail6, TestSize.Level0)
{
    AutoSelectDeviceFail6();
}

HWTEST_F(StaAutoConnectServiceTest, RegisterDeviceAppraisalSuccess, TestSize.Level0)
{
    RegisterDeviceAppraisalSuccess();
}

HWTEST_F(StaAutoConnectServiceTest, RegisterDeviceAppraisalFail1, TestSize.Level0)
{
    RegisterDeviceAppraisalFail1();
}

HWTEST_F(StaAutoConnectServiceTest, RegisterDeviceAppraisalFail2, TestSize.Level0)
{
    RegisterDeviceAppraisalFail2();
}

HWTEST_F(StaAutoConnectServiceTest, GetAvailableScanInfosSuccess, TestSize.Level0)
{
    GetAvailableScanInfosSuccess();
}

HWTEST_F(StaAutoConnectServiceTest, GetAvailableScanInfosSuccess1, TestSize.Level0)
{
    GetAvailableScanInfosSuccess1();
}

HWTEST_F(StaAutoConnectServiceTest, GetAvailableScanInfosSuccess2, TestSize.Level0)
{
    GetAvailableScanInfosSuccess2();
}

HWTEST_F(StaAutoConnectServiceTest, GetAvailableScanInfosSuccess3, TestSize.Level0)
{
    GetAvailableScanInfosSuccess3();
}

HWTEST_F(StaAutoConnectServiceTest, AllowAutoSelectDeviceSuccess1, TestSize.Level0)
{
    AllowAutoSelectDeviceSuccess1();
}

HWTEST_F(StaAutoConnectServiceTest, AllowAutoSelectDeviceSuccess2, TestSize.Level0)
{
    AllowAutoSelectDeviceSuccess2();
}

HWTEST_F(StaAutoConnectServiceTest, AllowAutoSelectDeviceSuccess3, TestSize.Level0)
{
    AllowAutoSelectDeviceSuccess3();
}

HWTEST_F(StaAutoConnectServiceTest, AllowAutoSelectDeviceSuccess4, TestSize.Level0)
{
    AllowAutoSelectDeviceSuccess4();
}

HWTEST_F(StaAutoConnectServiceTest, AllowAutoSelectDeviceFail1, TestSize.Level0)
{
    AllowAutoSelectDeviceFail1();
}

HWTEST_F(StaAutoConnectServiceTest, AllowAutoSelectDeviceFail2, TestSize.Level0)
{
    AllowAutoSelectDeviceFail2();
}

HWTEST_F(StaAutoConnectServiceTest, AllowAutoSelectDeviceFail3, TestSize.Level0)
{
    AllowAutoSelectDeviceFail3();
}

HWTEST_F(StaAutoConnectServiceTest, AllowAutoSelectDeviceFail4, TestSize.Level0)
{
    AllowAutoSelectDeviceFail4();
}

HWTEST_F(StaAutoConnectServiceTest, AllowAutoSelectDeviceFail5, TestSize.Level0)
{
    AllowAutoSelectDeviceFail5();
}

HWTEST_F(StaAutoConnectServiceTest, CurrentDeviceGoodEnoughSuccess, TestSize.Level0)
{
    CurrentDeviceGoodEnoughSuccess();
}

HWTEST_F(StaAutoConnectServiceTest, CurrentDeviceGoodEnoughFail1, TestSize.Level0)
{
    CurrentDeviceGoodEnoughFail1();
}

HWTEST_F(StaAutoConnectServiceTest, CurrentDeviceGoodEnoughFail2, TestSize.Level0)
{
    CurrentDeviceGoodEnoughFail2();
}

HWTEST_F(StaAutoConnectServiceTest, CurrentDeviceGoodEnoughFail3, TestSize.Level0)
{
    CurrentDeviceGoodEnoughFail3();
}


HWTEST_F(StaAutoConnectServiceTest, CurrentDeviceGoodEnoughFail4, TestSize.Level0)
{
    CurrentDeviceGoodEnoughFail4();
}

HWTEST_F(StaAutoConnectServiceTest, CurrentDeviceGoodEnoughFail5, TestSize.Level0)
{
    CurrentDeviceGoodEnoughFail5();
}

HWTEST_F(StaAutoConnectServiceTest, WhetherDevice5GAvailableSuccess, TestSize.Level0)
{
    WhetherDevice5GAvailableSuccess();
}

HWTEST_F(StaAutoConnectServiceTest, WhetherDevice5GAvailableFail, TestSize.Level0)
{
    WhetherDevice5GAvailableFail();
}

HWTEST_F(StaAutoConnectServiceTest, RoamingEncryptionModeCheckSuccess, TestSize.Level0)
{
    RoamingEncryptionModeCheckSuccess();
}

HWTEST_F(StaAutoConnectServiceTest, RoamingEncryptionModeCheckFail1, TestSize.Level0)
{
    RoamingEncryptionModeCheckFail1();
}

HWTEST_F(StaAutoConnectServiceTest, RoamingEncryptionModeCheckFail2, TestSize.Level0)
{
    RoamingEncryptionModeCheckFail2();
}

HWTEST_F(StaAutoConnectServiceTest, RoamingEncryptionModeCheckFail3, TestSize.Level0)
{
    RoamingEncryptionModeCheckFail3();
}

HWTEST_F(StaAutoConnectServiceTest, RoamingEncryptionModeCheckFail4, TestSize.Level0)
{
    RoamingEncryptionModeCheckFail4();
}

HWTEST_F(StaAutoConnectServiceTest, RoamingSelectionSuccess1, TestSize.Level0)
{
    RoamingSelectionSuccess1();
}

HWTEST_F(StaAutoConnectServiceTest, RoamingSelectionFail1, TestSize.Level0)
{
    RoamingSelectionFail1();
}

HWTEST_F(StaAutoConnectServiceTest, RoamingSelectionFail2, TestSize.Level0)
{
    RoamingSelectionFail2();
}

HWTEST_F(StaAutoConnectServiceTest, RoamingSelectionFail3, TestSize.Level0)
{
    RoamingSelectionFail3();
}

HWTEST_F(StaAutoConnectServiceTest, RoamingSelectionFail4, TestSize.Level0)
{
    RoamingSelectionFail4();
}

HWTEST_F(StaAutoConnectServiceTest, DisableAutoJoinSuccess, TestSize.Level0)
{
    DisableAutoJoinSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaAutoConnectServiceTest, EnableAutoJoinSuccess, TestSize.Level0)
{
    EnableAutoJoinSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaAutoConnectServiceTest, RegisterAutoJoinConditionSuccess, TestSize.Level0)
{
    RegisterAutoJoinConditionSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaAutoConnectServiceTest, DeregisterAutoJoinConditionSuccess, TestSize.Level0)
{
    DeregisterAutoJoinConditionSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaAutoConnectServiceTest, IsAutoConnectFailByP2PEnhanceFilterSucc1, TestSize.Level0)
{
    IsAutoConnectFailByP2PEnhanceFilterSucc1();
}

HWTEST_F(StaAutoConnectServiceTest, IsAutoConnectFailByP2PEnhanceFilterSucc2, TestSize.Level0)
{
    IsAutoConnectFailByP2PEnhanceFilterSucc2();
}

HWTEST_F(StaAutoConnectServiceTest, IsAutoConnectFailByP2PEnhanceFilterFail1, TestSize.Level0)
{
    IsAutoConnectFailByP2PEnhanceFilterFail1();
}

HWTEST_F(StaAutoConnectServiceTest, OnScanInfosReadyHandlerWithSupplicantTransientState, TestSize.Level0)
{
    OnScanInfosReadyHandlerWithSupplicantTransientState();
}

HWTEST_F(StaAutoConnectServiceTest, OnScanInfosReadyHandlerWithAsyncTaskDeduplication, TestSize.Level0)
{
    OnScanInfosReadyHandlerWithAsyncTaskDeduplication();
}

HWTEST_F(StaAutoConnectServiceTest, IsCandidateWithUserSelectChoiceHiddenSucc, TestSize.Level0)
{
    NetworkSelectionResult candidate;
    candidate.wifiDeviceConfig.networkId = 1;
    candidate.wifiDeviceConfig.hiddenSSID = true;
    candidate.wifiDeviceConfig.networkSelectionStatus.connectChoice = 1;
    struct timespec times = {0, 0};
    clock_gettime(CLOCK_BOOTTIME, &times);
    long currentTime = static_cast<int64_t>(times.tv_sec) * MSEC + times.tv_nsec / (MSEC * MSEC);
    candidate.wifiDeviceConfig.networkSelectionStatus.connectChoiceTimestamp = currentTime - MSEC;
    candidate.wifiDeviceConfig.networkSelectionStatus.status == WifiDeviceConfigStatus::ENABLED;
    EXPECT_TRUE(pStaAutoConnectService->IsCandidateWithUserSelectChoiceHidden(candidate));
}

HWTEST_F(StaAutoConnectServiceTest, IsCandidateWithUserSelectChoiceHiddenFail, TestSize.Level0)
{
    NetworkSelectionResult candidate;
    candidate.wifiDeviceConfig.networkId = 1;
    candidate.wifiDeviceConfig.hiddenSSID = false;
    candidate.wifiDeviceConfig.networkSelectionStatus.connectChoice = 1;
    struct timespec times = {0, 0};
    clock_gettime(CLOCK_BOOTTIME, &times);
    long currentTime = static_cast<int64_t>(times.tv_sec) * MSEC + times.tv_nsec / (MSEC * MSEC);
    candidate.wifiDeviceConfig.networkSelectionStatus.connectChoiceTimestamp = currentTime - MSEC;
    candidate.wifiDeviceConfig.networkSelectionStatus.status == WifiDeviceConfigStatus::ENABLED;
    EXPECT_FALSE(pStaAutoConnectService->IsCandidateWithUserSelectChoiceHidden(candidate));
}

HWTEST_F(StaAutoConnectServiceTest, IsCandidateWithUserSelectChoiceHiddenFail1, TestSize.Level0)
{
    NetworkSelectionResult candidate;
    candidate.wifiDeviceConfig.networkId = 1;
    candidate.wifiDeviceConfig.hiddenSSID = true;
    candidate.wifiDeviceConfig.networkSelectionStatus.connectChoice = 1;
    candidate.wifiDeviceConfig.networkSelectionStatus.networkDisableCount = 1;
    struct timespec times = {0, 0};
    clock_gettime(CLOCK_BOOTTIME, &times);
    long currentTime = static_cast<int64_t>(times.tv_sec) * MSEC + times.tv_nsec / (MSEC * MSEC);
    candidate.wifiDeviceConfig.networkSelectionStatus.connectChoiceTimestamp = currentTime - MSEC;
    candidate.wifiDeviceConfig.networkSelectionStatus.status == WifiDeviceConfigStatus::ENABLED;
    EXPECT_FALSE(pStaAutoConnectService->IsCandidateWithUserSelectChoiceHidden(candidate));
}
} // Wifi
} // OHOS
