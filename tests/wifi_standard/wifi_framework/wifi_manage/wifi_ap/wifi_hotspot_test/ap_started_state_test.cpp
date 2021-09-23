/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include "ap_define.h"
#include "ap_started_state.h"

#include "mock_pendant.h"

#include "mock_wifi_ap_hal_interface.h"
#include "mock_wifi_ap_nat_manager.h"
#include "mock_wifi_settings.h"
#include "mock_network_interface.h"
#include "mock_system_interface.h"

#include "mock_ap_monitor.h"
#include "operator_overload.h"
#include "wifi_log.h"

using ::testing::_;
using ::testing::A;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;

namespace OHOS {
namespace Wifi {
const std::string mac = "AA:BB:CC:DD:EE:FF";
static StationInfo staInfo = {
    "test_deviceName",
    mac.c_str(),
    "127.0.0.1",
};

HotspotConfig apcfg;
ChannelsTable channelTbs;
const int TEST_AP_CHANNEL = 6;
const int TEST_MAX_CONN = 10;

std::vector<StationInfo> valueList = {
    {
        "test_deviceName",
        "DA:BB:CC:DD:EE:FF",
        "127.0.0.3",
    },
    {
        "test_deviceName",
        "DA:BB:CC:DD:EE:FF",
        "127.0.0.3",
    },
};

class ApStartedState_test : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        WifiSettings::GetInstance();
        WifiApHalInterface::GetInstance();

        pMockPendant = new MockPendant();
        pMockApMonitor = &(pMockPendant->GetMockApMonitor());
        pMockApStationsManager = &(pMockPendant->GetMockApStationsManager());
        pMockApStateMachine = &(pMockPendant->GetMockApStateMachine());
        pMockApConfigUse = &(pMockPendant->GetMockApConfigUse());
        pMockApStateMachine->InitialStateMachine();
        pMockApNatManager = new MockWifiApNatManager();

        pApStartedState = new ApStartedState(*pMockApStateMachine, *pMockApConfigUse, *pMockApMonitor);

        msg = new InternalMessage();
        apcfg.SetSsid(std::string("UnitTestAp"));
        apcfg.SetPreSharedKey(std::string("123456789"));
        apcfg.SetSecurityType(KeyMgmt::WPA2_PSK);
        apcfg.SetBand(BandType::BAND_2GHZ);
        apcfg.SetChannel(TEST_AP_CHANNEL);
        apcfg.SetMaxConn(TEST_MAX_CONN);
        WrapHotspotConfig() = apcfg;

        std::vector<int32_t> band_2G_channel = {1, 2, 3, 4, 5, 6, 7};
        std::vector<int32_t> band_5G_channel = {149, 168, 169};
        channelTbs = {{BandType::BAND_2GHZ, band_2G_channel}, {BandType::BAND_5GHZ, band_5G_channel}};
    }
    virtual void TearDown()
    {
        EXPECT_CALL(WifiApHalInterface::GetInstance(), RegisterApEvent(_))
            .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
        delete pApStartedState;

        delete pMockPendant;

        pApStartedState = nullptr;

        pMockPendant = nullptr;
        pMockApStateMachine = nullptr;
        pMockApConfigUse = nullptr;
        pMockApMonitor = nullptr;
        pMockApStationsManager = nullptr;

        delete pMockApNatManager;
        pMockApNatManager = nullptr;

        delete msg;
    }

public:
    bool WrapStartAp() const
    {
        return pApStartedState->StartAp();
    }
    bool WrapStopAp() const
    {
        return WrapStartAp();
    }
    bool WrapSetConfig(HotspotConfig &apConfig)
    {
        return pApStartedState->SetConfig(apConfig);
    }
    bool WrapSetConfig() const
    {
        return pApStartedState->SetConfig();
    }
    void WrapOnApStateChange(const ApState &state)
    {
        pApStartedState->OnApStateChange(state);
    }
    void WrapStartMonitor() const
    {
        pApStartedState->StartMonitor();
    }
    void WrapStopMonitor() const
    {
        pApStartedState->StopMonitor();
    }
    bool WrapStartDhcpServer() const
    {
        return pMockApStateMachine->StartDhcpServer();
    }
    bool WrapStopDhcpServer() const
    {
        return pMockApStateMachine->StopDhcpServer();
    }
    bool WrapEnableInterfaceNat() const
    {
        return pApStartedState->EnableInterfaceNat();
    }
    bool WrapDisableInterfaceNat() const
    {
        return pApStartedState->DisableInterfaceNat();
    }

public:
    void WrapProcessCmdFail(InternalMessage &message)
    {
        pApStartedState->ProcessCmdFail(message);
    }
    void WrapProcessCmdStationJoin(InternalMessage &message)
    {
        pApStartedState->ProcessCmdStationJoin(message);
    }
    void WrapProcessCmdStationLeave(InternalMessage &message)
    {
        pApStartedState->ProcessCmdStationLeave(message);
    }
    void WrapProcessCmdSetHotspotConfig(InternalMessage &message)
    {
        pApStartedState->ProcessCmdSetHotspotConfig(message);
    }
    void WrapProcessCmdUpdateConfigResult(InternalMessage &message)
    {
        pApStartedState->ProcessCmdUpdateConfigResult(message);
    }
    void WrapProcessCmdAddBlockList(InternalMessage &message)
    {
        pApStartedState->ProcessCmdAddBlockList(message);
    }
    void WrapProcessCmdDelBlockList(InternalMessage &message)
    {
        pApStartedState->ProcessCmdDelBlockList(message);
    }
    void WrapProcessCmdStopHotspot(InternalMessage &message)
    {
        pApStartedState->ProcessCmdStopHotspot(message);
    }
    void WrapProcessCmdDisconnectStation(InternalMessage &message)
    {
        pApStartedState->ProcessCmdDisconnectStation(message);
    }

public:
    HotspotConfig &WrapHotspotConfig()
    {
        return pApStartedState->m_hotspotConfig;
    }

public:
    InternalMessage *msg;

    ApStartedState *pApStartedState;

    MockPendant *pMockPendant;

    MockApStationsManager *pMockApStationsManager;
    MockApStateMachine *pMockApStateMachine;
    MockApMonitor *pMockApMonitor;
    MockApConfigUse *pMockApConfigUse;
    MockWifiApNatManager *pMockApNatManager;
};
TEST_F(ApStartedState_test, GoInState_SUCCESS)
{
    std::vector<StationInfo> results;
    EXPECT_CALL(MockNetworkInterface::GetInstance(), FetchIpAddress(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(MockNetworkInterface::GetInstance(), AddIpAddress(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(WifiSettings::GetInstance(), SetHotspotState(A<int>())).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiApHalInterface::GetInstance(), StartAp()).WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    std::string countryCode = "CN";
    EXPECT_CALL(WifiSettings::GetInstance(), GetCountryCode(Eq("")))
        .WillRepeatedly(DoAll(testing::SetArgReferee<0>(countryCode), Return(0)));
    EXPECT_CALL(WifiApHalInterface::GetInstance(), SetWifiCountryCode(Eq(countryCode)))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_CALL(WifiSettings::GetInstance(), GetHotspotConfig(A<HotspotConfig &>()))
        .WillRepeatedly(DoAll(SetArgReferee<0>(apcfg), Return(0)));
    EXPECT_CALL(WifiApHalInterface::GetInstance(), GetFrequenciesByBand(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_CALL(WifiSettings::GetInstance(), SetValidChannels(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiApHalInterface::GetInstance(), SetSoftApConfig(Eq(apcfg)))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_CALL(*pMockApStateMachine, StartDhcpServer()).WillRepeatedly(Return(true));
    EXPECT_CALL(*pMockApNatManager, EnableInterfaceNat(Eq(true), StrEq(IN_INTERFACE), StrEq(OUT_INTERFACE)))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*pMockApConfigUse, TransformFrequencyIntoChannel(_, _)).WillRepeatedly(Return());
    EXPECT_CALL(*pMockApMonitor, StartMonitor()).WillRepeatedly(Return());
    EXPECT_CALL(*pMockApConfigUse, CheckBandChannel(Eq(apcfg), _)).WillRepeatedly(Return());
    EXPECT_CALL(*pMockApConfigUse, LogConfig(Eq(apcfg))).WillRepeatedly(Return());
    EXPECT_CALL(WifiSettings::GetInstance(), GetBlockList(Eq(results)))
        .WillRepeatedly(DoAll(SetArgReferee<0>(valueList), Return(ErrCode::WIFI_OPT_SUCCESS)));
    EXPECT_CALL(WifiApHalInterface::GetInstance(), AddBlockByMac(StrEq("DA:BB:CC:DD:EE:FF")))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    pApStartedState->GoInState();
}
TEST_F(ApStartedState_test, GoInState_FAILED1)
{
    std::vector<StationInfo> results;
    EXPECT_CALL(WifiSettings::GetInstance(), SetHotspotState(A<int>())).WillRepeatedly(Return(0));
    EXPECT_CALL(*pMockApMonitor, StartMonitor()).WillRepeatedly(Return());
    EXPECT_CALL(WifiApHalInterface::GetInstance(), StartAp()).WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    pApStartedState->GoInState();

    EXPECT_CALL(WifiApHalInterface::GetInstance(), StartAp()).WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_CALL(WifiSettings::GetInstance(), GetCountryCode(StrEq(""))).WillRepeatedly(Return(1));
    pApStartedState->GoInState();

    EXPECT_CALL(WifiSettings::GetInstance(), GetCountryCode(StrEq("")))
        .WillRepeatedly(DoAll(SetArgReferee<0>("CN"), Return(0)));
    EXPECT_CALL(WifiApHalInterface::GetInstance(), SetWifiCountryCode(StrEq("CN")))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    pApStartedState->GoInState();

    EXPECT_CALL(WifiApHalInterface::GetInstance(), SetWifiCountryCode(StrEq("CN")))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_CALL(WifiSettings::GetInstance(), GetHotspotConfig(A<HotspotConfig &>())).WillRepeatedly(Return(1));
    pApStartedState->GoInState();

    EXPECT_CALL(WifiSettings::GetInstance(), GetHotspotConfig(A<HotspotConfig &>()))
        .WillRepeatedly(DoAll(SetArgReferee<0>(apcfg), Return(0)));
    EXPECT_CALL(WifiApHalInterface::GetInstance(), GetFrequenciesByBand(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_CALL(*pMockApConfigUse, TransformFrequencyIntoChannel(_, _)).WillRepeatedly(Return());
    EXPECT_CALL(WifiSettings::GetInstance(), SetValidChannels(_)).WillRepeatedly(Return(1));
    pApStartedState->GoInState();

    EXPECT_CALL(WifiSettings::GetInstance(), SetValidChannels(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*pMockApConfigUse, CheckBandChannel(_, _)).WillRepeatedly(Return());
    EXPECT_CALL(WifiApHalInterface::GetInstance(), SetSoftApConfig(Eq(apcfg)))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    pApStartedState->GoInState();

    EXPECT_CALL(WifiApHalInterface::GetInstance(), SetSoftApConfig(Eq(apcfg)))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_CALL(*pMockApConfigUse, LogConfig(Eq(apcfg))).WillRepeatedly(Return());
    EXPECT_CALL(*pMockApStateMachine, StartDhcpServer()).WillRepeatedly(Return(false));
    pApStartedState->GoInState();

    EXPECT_CALL(WifiSettings::GetInstance(), GetBlockList(Eq(results)))
        .WillRepeatedly(DoAll(SetArgReferee<0>(valueList), Return(ErrCode::WIFI_OPT_FAILED)));
    pApStartedState->GoInState();

    EXPECT_CALL(WifiSettings::GetInstance(), GetBlockList(Eq(results)))
        .WillRepeatedly(DoAll(SetArgReferee<0>(valueList), Return(ErrCode::WIFI_OPT_SUCCESS)));
    EXPECT_CALL(WifiApHalInterface::GetInstance(), AddBlockByMac(StrEq("DA:BB:CC:DD:EE:FF")))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    pApStartedState->GoInState();

    EXPECT_CALL(WifiSettings::GetInstance(), GetHotspotConfig(A<HotspotConfig &>())).WillRepeatedly(Return(1));
    EXPECT_CALL(*pMockApStateMachine, StartDhcpServer()).WillRepeatedly(Return(true));
    EXPECT_CALL(*pMockApNatManager, EnableInterfaceNat(_, _, _)).WillRepeatedly(Return(false));
    pApStartedState->GoInState();
}
TEST_F(ApStartedState_test, GoOutState_SUCCESS)
{
    EXPECT_CALL(MockSystemInterface::GetInstance(), system(_)).WillRepeatedly(Return(true));

    EXPECT_CALL(MockNetworkInterface::GetInstance(), IsValidInterfaceName(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(MockNetworkInterface::GetInstance(), ClearAllIpAddress(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(WifiSettings::GetInstance(), SetHotspotState(A<int>())).WillRepeatedly(Return(0));
    EXPECT_CALL(*pMockApNatManager, EnableInterfaceNat(Eq(false), _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*pMockApStateMachine, StopDhcpServer()).WillRepeatedly(Return(true));
    EXPECT_CALL(WifiApHalInterface::GetInstance(), StopAp()).WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_CALL(WifiSettings::GetInstance(), ClearStationList()).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), ClearValidChannels()).WillRepeatedly(Return(0));
    EXPECT_CALL(*pMockApMonitor, StopMonitor()).WillRepeatedly(Return());
    pApStartedState->GoOutState();
}
TEST_F(ApStartedState_test, GoOutState_FAILED)
{
    EXPECT_CALL(MockSystemInterface::GetInstance(), system(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(WifiSettings::GetInstance(), SetHotspotState(A<int>())).WillRepeatedly(Return(0));
    EXPECT_CALL(*pMockApNatManager, EnableInterfaceNat(Eq(false), _, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(*pMockApStateMachine, StopDhcpServer()).WillRepeatedly(Return(false));
    EXPECT_CALL(WifiApHalInterface::GetInstance(), StopAp()).WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_CALL(WifiSettings::GetInstance(), ClearStationList()).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiSettings::GetInstance(), ClearValidChannels()).WillRepeatedly(Return(0));
    EXPECT_CALL(*pMockApMonitor, StopMonitor()).WillRepeatedly(Return());
    pApStartedState->GoOutState();
}
TEST_F(ApStartedState_test, ExecuteStateMsg_SUCCESS)
{
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_FAIL));
    EXPECT_TRUE(pApStartedState->ExecuteStateMsg(msg));

    EXPECT_CALL(WifiSettings::GetInstance(), GetStationList(_)).WillRepeatedly(Return(ErrCode::WIFI_OPT_FAILED));
    msg->ClearMessageBody();
    StationInfo staInfo;
    msg->SetMessageObj(staInfo);
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_STATION_JOIN));
    msg->AddStringMessageBody(staInfo.deviceName);
    msg->AddStringMessageBody(staInfo.bssid);
    msg->AddStringMessageBody(staInfo.ipAddr);
    EXPECT_TRUE(pApStartedState->ExecuteStateMsg(msg));

    msg->ClearMessageBody();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_STATION_LEAVE));
    msg->AddStringMessageBody(staInfo.deviceName);
    msg->AddStringMessageBody(staInfo.bssid);
    msg->AddStringMessageBody(staInfo.ipAddr);
    EXPECT_TRUE(pApStartedState->ExecuteStateMsg(msg));

    msg->ClearMessageBody();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_SET_HOTSPOT_CONFIG));
    msg->AddStringMessageBody(apcfg.GetSsid());
    msg->AddStringMessageBody(apcfg.GetPreSharedKey());
    msg->AddIntMessageBody(static_cast<int>(apcfg.GetSecurityType()));
    msg->AddIntMessageBody(static_cast<int>(apcfg.GetBand()));
    msg->AddIntMessageBody(apcfg.GetChannel());
    msg->AddIntMessageBody(apcfg.GetMaxConn());

    EXPECT_CALL(*pMockApConfigUse, LogConfig(Eq(apcfg))).WillRepeatedly(Return());
    EXPECT_CALL(WifiApHalInterface::GetInstance(), GetFrequenciesByBand(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_CALL(*pMockApConfigUse, TransformFrequencyIntoChannel(_, _)).WillRepeatedly(Return());
    EXPECT_CALL(WifiSettings::GetInstance(), SetValidChannels(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(WifiApHalInterface::GetInstance(), SetSoftApConfig(Eq(apcfg)))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_CALL(*pMockApConfigUse, CheckBandChannel(Eq(apcfg), _)).WillRepeatedly(Return());
    EXPECT_TRUE(pApStartedState->ExecuteStateMsg(msg));

    msg->ClearMessageBody();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_SET_HOTSPOT_CONFIG));
    msg->AddStringMessageBody(apcfg.GetSsid());
    msg->AddStringMessageBody(apcfg.GetPreSharedKey());
    msg->AddIntMessageBody(static_cast<int>(apcfg.GetSecurityType()));
    msg->AddIntMessageBody(static_cast<int>(apcfg.GetBand()));
    msg->AddIntMessageBody(apcfg.GetChannel());
    msg->AddIntMessageBody(apcfg.GetMaxConn());
    EXPECT_CALL(WifiApHalInterface::GetInstance(), SetSoftApConfig(Eq(apcfg)))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_FAILED));
    EXPECT_TRUE(pApStartedState->ExecuteStateMsg(msg));
}

TEST_F(ApStartedState_test, ExecuteStateMsg_SUCCESS2)
{
    msg->ClearMessageBody();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_UPDATE_HOTSPOTCONFIG_RESULT));
    msg->AddStringMessageBody(apcfg.GetSsid());
    msg->AddStringMessageBody(apcfg.GetPreSharedKey());
    msg->AddIntMessageBody(static_cast<int>(apcfg.GetSecurityType()));
    msg->AddIntMessageBody(static_cast<int>(apcfg.GetBand()));
    msg->AddIntMessageBody(apcfg.GetChannel());
    msg->AddIntMessageBody(apcfg.GetMaxConn());
    msg->SetParam1(1);
    EXPECT_CALL(WifiSettings::GetInstance(), SetHotspotConfig(Eq(apcfg))).WillRepeatedly(Return(1));
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_UPDATE_HOTSPOTCONFIG_RESULT));

    EXPECT_TRUE(pApStartedState->ExecuteStateMsg(msg));
    msg->SetParam1(0);
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_UPDATE_HOTSPOTCONFIG_RESULT));
    EXPECT_TRUE(pApStartedState->ExecuteStateMsg(msg));

    msg->ClearMessageBody();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_ADD_BLOCK_LIST));
    msg->AddStringMessageBody(apcfg.GetSsid());
    msg->AddStringMessageBody(apcfg.GetPreSharedKey());
    msg->AddIntMessageBody(static_cast<int>(apcfg.GetSecurityType()));
    msg->AddIntMessageBody(static_cast<int>(apcfg.GetBand()));
    msg->AddIntMessageBody(apcfg.GetChannel());
    msg->AddIntMessageBody(apcfg.GetMaxConn());
    EXPECT_CALL(WifiApHalInterface::GetInstance(), AddBlockByMac(Eq(staInfo.bssid)))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    msg->ClearMessageBody();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_ADD_BLOCK_LIST));
    msg->AddStringMessageBody(staInfo.deviceName);
    msg->AddStringMessageBody(staInfo.bssid);
    msg->AddStringMessageBody(staInfo.ipAddr);
    EXPECT_TRUE(pApStartedState->ExecuteStateMsg(msg));

    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_DEL_BLOCK_LIST));
    msg->AddStringMessageBody(staInfo.deviceName);
    msg->AddStringMessageBody(staInfo.bssid);
    msg->AddStringMessageBody(staInfo.ipAddr);
    EXPECT_CALL(WifiApHalInterface::GetInstance(), DelBlockByMac(Eq(staInfo.bssid)))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_TRUE(pApStartedState->ExecuteStateMsg(msg));
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_STOP_HOTSPOT));
    EXPECT_TRUE(pApStartedState->ExecuteStateMsg(msg));

    msg->ClearMessageBody();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_DISCONNECT_STATION));
    msg->AddStringMessageBody(staInfo.deviceName);
    msg->AddStringMessageBody(staInfo.bssid);
    msg->AddStringMessageBody(staInfo.ipAddr);
    EXPECT_CALL(WifiApHalInterface::GetInstance(), DisconnectStaByMac(Eq(staInfo.bssid)))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
    EXPECT_TRUE(pApStartedState->ExecuteStateMsg(msg));
}
TEST_F(ApStartedState_test, ExecuteStateMsg_FAILED)
{
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_START_HOTSPOT));
    EXPECT_FALSE(pApStartedState->ExecuteStateMsg(msg));

    msg = nullptr;
    EXPECT_FALSE(pApStartedState->ExecuteStateMsg(msg));
}
} // namespace Wifi
} // namespace OHOS