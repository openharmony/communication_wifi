/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include "mock_p2p_pendant.h"
#include "mock_wifi_p2p_hal_interface.h"
#include "wifi_hid2d_msg.h"
#include "wifi_p2p_msg.h"
#include "wifi_p2p_service.h"
#include "wifi_config_center.h"
#include "wifi_country_code_manager.h"

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
    static std::string g_errLog = "wifitest";
class WifiP2pServiceTest : public testing::Test {
public:
    WifiP2pServiceTest() : groupManager(), deviceManager(), svrManager()
    {}
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pMockP2pPendant.reset(new MockP2pPendant());
        pWifiP2pService.reset(
            new WifiP2pService(pMockP2pPendant->GetP2pStateMachine(), deviceManager, groupManager, svrManager));
    }
    virtual void TearDown()
    {
        EXPECT_CALL(WifiP2PHalInterface::GetInstance(), RegisterP2pCallback(testing::_));
        pWifiP2pService.reset();
        pMockP2pPendant.reset();
    }

public:
    std::unique_ptr<WifiP2pService> pWifiP2pService;
    std::unique_ptr<MockP2pPendant> pMockP2pPendant;
    WifiP2pGroupManager groupManager;
    WifiP2pDeviceManager deviceManager;
    WifiP2pServiceManager svrManager;
};
HWTEST_F(WifiP2pServiceTest, EnableP2p, TestSize.Level1)
{
    EXPECT_EQ(pWifiP2pService->EnableP2p(), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, DisableP2p, TestSize.Level1)
{
    EXPECT_EQ(pWifiP2pService->DisableP2p(), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, DiscoverDevices, TestSize.Level1)
{
    EXPECT_EQ(pWifiP2pService->DiscoverDevices(), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, StopDiscoverDevices, TestSize.Level1)
{
    EXPECT_EQ(pWifiP2pService->StopDiscoverDevices(), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, DiscoverServices, TestSize.Level1)
{
    EXPECT_EQ(pWifiP2pService->DiscoverServices(), ErrCode::WIFI_OPT_SUCCESS);
}
HWTEST_F(WifiP2pServiceTest, StopDiscoverServices, TestSize.Level1)
{
    EXPECT_EQ(pWifiP2pService->StopDiscoverServices(), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, PutLocalP2pService, TestSize.Level1)
{
    WifiP2pServiceInfo srvInfo;
    EXPECT_EQ(pWifiP2pService->PutLocalP2pService(srvInfo), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, DeleteLocalP2pService, TestSize.Level1)
{
    WifiP2pServiceInfo srvInfo;
    EXPECT_EQ(pWifiP2pService->DeleteLocalP2pService(srvInfo), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, RequestService, TestSize.Level1)
{
    WifiP2pDevice device;
    WifiP2pServiceRequest request;
    EXPECT_EQ(pWifiP2pService->RequestService(device, request), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, StartP2pListen, TestSize.Level1)
{
    int period = 0;
    int interval = 0;
    EXPECT_EQ(pWifiP2pService->StartP2pListen(period, interval), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, StopP2pListen, TestSize.Level1)
{
    EXPECT_EQ(pWifiP2pService->StopP2pListen(), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, CreateGroup, TestSize.Level1)
{
    WifiP2pConfig config;
    EXPECT_EQ(pWifiP2pService->CreateGroup(config), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, RemoveGroup, TestSize.Level1)
{
    EXPECT_EQ(pWifiP2pService->RemoveGroup(), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, DeleteGroup, TestSize.Level1)
{
    WifiP2pGroupInfo group;
    EXPECT_EQ(pWifiP2pService->DeleteGroup(group), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, P2pConnect, TestSize.Level1)
{
    WifiP2pConfig config;
    EXPECT_EQ(pWifiP2pService->P2pConnect(config), ErrCode::WIFI_OPT_SUCCESS);
    EXPECT_EQ(pWifiP2pService->P2pCancelConnect(), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, QueryP2pLinkedInfo, TestSize.Level1)
{
    WifiP2pLinkedInfo linkedInfo;
    EXPECT_EQ(pWifiP2pService->QueryP2pLinkedInfo(linkedInfo), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, GetCurrentGroup, TestSize.Level1)
{
    WifiP2pLinkedInfo p2pInfo;
    p2pInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
    WifiConfigCenter::GetInstance().SaveP2pInfo(p2pInfo);
    WifiP2pGroupInfo group;
    EXPECT_EQ(pWifiP2pService->GetCurrentGroup(group), ErrCode::WIFI_OPT_FAILED);
}

HWTEST_F(WifiP2pServiceTest, GetP2pEnableStatus, TestSize.Level1)
{
    int status;
    EXPECT_EQ(pWifiP2pService->GetP2pEnableStatus(status), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, GetP2pDiscoverStatus, TestSize.Level1)
{
    int status;
    EXPECT_EQ(pWifiP2pService->GetP2pDiscoverStatus(status), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, GetP2pConnectedStatus, TestSize.Level1)
{
    int status;
    EXPECT_EQ(pWifiP2pService->GetP2pConnectedStatus(status), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, QueryP2pDevices, TestSize.Level1)
{
    std::vector<WifiP2pDevice> devices;
    EXPECT_EQ(pWifiP2pService->QueryP2pDevices(devices), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, QueryP2pGroups, TestSize.Level1)
{
    std::vector<WifiP2pGroupInfo> groups;
    EXPECT_EQ(pWifiP2pService->QueryP2pGroups(groups), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, QueryP2pServices, TestSize.Level1)
{
    std::vector<WifiP2pServiceInfo> services;
    EXPECT_EQ(pWifiP2pService->QueryP2pServices(services), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, SetP2pDeviceName, TestSize.Level1)
{
    std::string deviceName("TestName");
    EXPECT_EQ(pWifiP2pService->SetP2pDeviceName(deviceName), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, SetP2pWfdInfo, TestSize.Level1)
{
    WifiP2pWfdInfo wfd;
    EXPECT_EQ(pWifiP2pService->SetP2pWfdInfo(wfd), ErrCode::WIFI_OPT_SUCCESS);
}

/**
 * @tc.name: Set upper scene test
 * @tc.desc: Set upper scene test function.
 * @tc.type: FUNC
 * @tc.require: issueI5LC5N
 */
HWTEST_F(WifiP2pServiceTest, SetUpperScene, TestSize.Level1)
{
    Hid2dUpperScene upperScene;
    upperScene.scene = 0; // 0: video, 1: audio, 2: file
    EXPECT_EQ(pWifiP2pService->Hid2dSetUpperScene("p2p0", upperScene), ErrCode::WIFI_OPT_SUCCESS);
    upperScene.scene = 1;
    EXPECT_EQ(pWifiP2pService->Hid2dSetUpperScene("p2p0", upperScene), ErrCode::WIFI_OPT_SUCCESS);
    upperScene.scene = 2;
    EXPECT_EQ(pWifiP2pService->Hid2dSetUpperScene("p2p0", upperScene), ErrCode::WIFI_OPT_SUCCESS);
}
/**
 * @tc.name: Hid2d shared link test
 * @tc.desc: Hid2d shared link test function.
 * @tc.type: FUNC
 * @tc.require: issueI5LC5N
 */
HWTEST_F(WifiP2pServiceTest, HiD2dSharedLinkTest, TestSize.Level1)
{
    int callingUid = 0;
    pWifiP2pService->IncreaseSharedLink(callingUid);
    pWifiP2pService->DecreaseSharedLink(callingUid);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}


HWTEST_F(WifiP2pServiceTest, GetCurrentGroupTest001, TestSize.Level1)
{
    WifiP2pLinkedInfo p2pInfo;
    p2pInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
    WifiConfigCenter::GetInstance().SaveP2pInfo(p2pInfo);
    WifiP2pGroupInfo group;
    EXPECT_EQ(pWifiP2pService->GetCurrentGroup(group), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, Hid2dConnectTest001, TestSize.Level1)
{
    Hid2dConnectConfig config;
    config.SetDhcpMode(DhcpMode::CONNECT_GO_NODHCP);
    EXPECT_EQ(pWifiP2pService->Hid2dConnect(config), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, Hid2dConnectTest002, TestSize.Level1)
{
    Hid2dConnectConfig config;
    config.SetDhcpMode(DhcpMode::CONNECT_AP_NODHCP);
    EXPECT_EQ(pWifiP2pService->Hid2dConnect(config), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, Hid2dConnectTest003, TestSize.Level1)
{
    Hid2dConnectConfig config;
    config.SetDhcpMode(DhcpMode::CONNECT_AP_DHCP);
    EXPECT_EQ(pWifiP2pService->Hid2dConnect(config), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, Hid2dRequestGcIpTest001, TestSize.Level1)
{
    std::string deviceName("TestName");
    std::string strIpAddr;

    WifiP2pLinkedInfo p2pInfo;
    p2pInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
    WifiConfigCenter::GetInstance().SaveP2pInfo(p2pInfo);
    WifiP2pGroupInfo group;
    EXPECT_EQ(pWifiP2pService->GetCurrentGroup(group), ErrCode::WIFI_OPT_FAILED);
    EXPECT_EQ(pWifiP2pService->Hid2dRequestGcIp(deviceName, strIpAddr), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, Hid2dRequestGcIpTest002, TestSize.Level1)
{
    std::string deviceName("TestName");
    std::string strIpAddr;

    WifiP2pLinkedInfo p2pInfo;
    p2pInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
    WifiConfigCenter::GetInstance().SaveP2pInfo(p2pInfo);
    WifiP2pGroupInfo group;
    EXPECT_EQ(pWifiP2pService->GetCurrentGroup(group), ErrCode::WIFI_OPT_SUCCESS);
    EXPECT_EQ(pWifiP2pService->Hid2dRequestGcIp(deviceName, strIpAddr), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, HandleBusinessSAExceptionTest001, TestSize.Level1)
{
    int systemAbilityId = 0;
    int callingUid = 0;
    pWifiP2pService->IncreaseSharedLink(callingUid);
    pWifiP2pService->HandleBusinessSAException(systemAbilityId);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

HWTEST_F(WifiP2pServiceTest, HandleBusinessSAExceptionTest003, TestSize.Level1)
{
    int systemAbilityId = 4700;
    int callingUid = 0;
    pWifiP2pService->IncreaseSharedLink(callingUid);
    EXPECT_EQ(pWifiP2pService->HandleBusinessSAException(systemAbilityId), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, QueryP2pLocalDeviceTest001, TestSize.Level1)
{
    WifiP2pDevice device;
    EXPECT_EQ(pWifiP2pService->QueryP2pLocalDevice(device), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, RegisterP2pServiceCallbacksTest001, TestSize.Level1)
{
    IP2pServiceCallbacks callback;
    EXPECT_EQ(pWifiP2pService->RegisterP2pServiceCallbacks(callback), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, UnRegisterP2pServiceCallbacksTest001, TestSize.Level1)
{
    IP2pServiceCallbacks callback;
    EXPECT_EQ(pWifiP2pService->UnRegisterP2pServiceCallbacks(callback), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, Hid2dCreateGroupTest001, TestSize.Level1)
{
    const int frequency = 1;
    FreqType type = FreqType::FREQUENCY_160M;
    EXPECT_EQ(pWifiP2pService->Hid2dCreateGroup(frequency, type), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, MonitorCfgChangeTest001, TestSize.Level1)
{
    EXPECT_EQ(pWifiP2pService->MonitorCfgChange(), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, DiscoverPeersTest001, TestSize.Level1)
{
    int32_t channelid = 0;
    EXPECT_EQ(pWifiP2pService->DiscoverPeers(channelid), ErrCode::WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiP2pServiceTest, DisableRandomMacTest001, TestSize.Level1)
{
    int setmode = 0;
    EXPECT_EQ(pWifiP2pService->DisableRandomMac(setmode), ErrCode::WIFI_OPT_SUCCESS);
}
}  // namespace Wifi
}  // namespace OHOS