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
#include "wifi_hal_crpc_server_test.h"
#include "wifi_log.h"
#include "wifi_hal_crpc_server.h"
#include "wifi_hal_crpc_base.h"
#include "wifi_hal_crpc_chip.h"
#include "wifi_hal_crpc_supplicant.h"
#include "wifi_hal_crpc_sta.h"
#include "wifi_hal_crpc_ap.h"
#include "wifi_hal_crpc_common.h"
#include "wifi_hal_crpc_p2p.h"
#include "wifi_hal_ap_interface.h"
#include "wifi_hal_sta_interface.h"
#include "mock_wpa_ctrl.h"
#include "wifi_hal_common_func.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
static std::string g_rpcSockPath = "./unix_sock_test.sock";
RpcServer *WifiHalCRpcServerTest::mServer = nullptr;
Context *WifiHalCRpcServerTest::mContext = nullptr;

static int StrcmpMathRight(const char *left, const char *right)
{
    return strncmp(left, right, strlen(right));
}

void WifiHalCRpcServerTest::SetUpTestCase()
{
    if (access(g_rpcSockPath.c_str(), 0) == 0) {
        unlink(g_rpcSockPath.c_str());
    }
    mServer = CreateRpcServer(g_rpcSockPath.c_str());
    mContext = CreateContext(CONTEXT_BUFFER_MIN_SIZE);
    if (mServer == nullptr || mContext == nullptr) {
        printf("Init rpc server failed or create context failed!");
        exit(-1);
    }
    SetRpcServerInited(mServer);
    MockInitGlobalCmd();
    MockInitStaSupportedCmd();
    MockInitApSupportedCmd();
}

void WifiHalCRpcServerTest::TearDownTestCase()
{
    if (mServer != nullptr) {
        ReleaseRpcServer(mServer);
        mServer = nullptr;
    }
    SetRpcServerInited(NULL);
    if (mContext != nullptr) {
        ReleaseContext(mContext);
        mContext = nullptr;
    }
}

void WifiHalCRpcServerTest::SetUp()
{
    InitRpcFunc();
    if (mContext != nullptr) {
        mContext->wBegin = mContext->wEnd = 0;
    }
}

void WifiHalCRpcServerTest::TearDown()
{
    ReleaseRpcFunc();
    if (mContext != nullptr) {
        mContext->wBegin = mContext->wEnd = 0;
    }
}

HWTEST_F(WifiHalCRpcServerTest, GetRpcFuncTest, TestSize.Level1)
{
    EXPECT_TRUE(GetRpcFunc("GetName") != nullptr);
    EXPECT_TRUE(GetRpcFunc("GetNameTest") == nullptr);
}

HWTEST_F(WifiHalCRpcServerTest, OnTransactTest, TestSize.Level1)
{
    char buff[] = "N\tIncorrectTypeInputMessage";
    mContext->oneProcess = buff;
    mContext->nPos = 2;
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(OnTransact(mServer, mContext) < 0);
    char buff2[] = "N\tUnsupportedCmd\t";
    mContext->oneProcess = buff2;
    mContext->nPos = 2;
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(OnTransact(mServer, mContext) == 0);
    EXPECT_TRUE(strstr(mContext->szWrite, "unsupported function") != nullptr);
    char buff3[] = "N\tSetCountryCode\t";
    mContext->oneProcess = buff3;
    mContext->nPos = 2;
    mContext->nSize = strlen(buff3);
    EXPECT_TRUE(OnTransact(mServer, mContext) == 0);
    EXPECT_TRUE(strstr(mContext->szWrite, "server deal failed!") != nullptr);
}

HWTEST_F(WifiHalCRpcServerTest, PushPopCallbackMsgTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *msg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    ASSERT_TRUE(msg != nullptr);
    msg->msg.scanStatus = 100;
    int event = WIFI_FAILURE_EVENT - 1;
    EXPECT_TRUE(PushBackCallbackMsg(event, msg) < 0);
    event = WIFI_HAL_MAX_EVENT;
    EXPECT_TRUE(PushBackCallbackMsg(event, msg) < 0);
    event = WIFI_FAILURE_EVENT;
    EXPECT_TRUE(PushBackCallbackMsg(event, msg) == 0);
    WifiHalEventCallbackMsg *msg1 = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    ASSERT_TRUE(msg1 != nullptr);
    msg1->msg.scanStatus = 101;
    EXPECT_TRUE(PushBackCallbackMsg(event, msg1) == 0);
    WifiHalEventCallbackMsg *msg2 = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    ASSERT_TRUE(msg2 != nullptr);
    msg2->msg.scanStatus = 102;
    EXPECT_TRUE(PushBackCallbackMsg(event, msg2) == 0);
    EXPECT_TRUE(PopBackCallbackMsg(WIFI_HAL_MAX_EVENT) < 0);
    EXPECT_TRUE(PopBackCallbackMsg(event) == 0);
    EXPECT_TRUE(FrontCallbackMsg(WIFI_HAL_MAX_EVENT) == nullptr);
    WifiHalEventCallbackMsg *p = FrontCallbackMsg(event);
    EXPECT_TRUE(p->msg.scanStatus == 100);
    EXPECT_TRUE(PopFrontCallbackMsg(WIFI_HAL_MAX_EVENT) < 0);
    EXPECT_TRUE(PopFrontCallbackMsg(event) == 0);
    p = FrontCallbackMsg(event);
    EXPECT_TRUE(p->msg.scanStatus == 101);
    EXPECT_TRUE(PopFrontCallbackMsg(event) == 0);
    p = FrontCallbackMsg(event);
    EXPECT_TRUE(p == nullptr);
    free(msg2);
}

HWTEST_F(WifiHalCRpcServerTest, OnCallbackTransactTest, TestSize.Level1)
{
    EXPECT_TRUE(OnCallbackTransact(nullptr, 0, nullptr) < 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, WIFI_FAILURE_EVENT, mContext) == 0);
    EXPECT_TRUE(EndCallbackTransact(nullptr, 0) < 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, WIFI_FAILURE_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealCommonCbkTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    cbmsg->msg.scanStatus = 100;
    EXPECT_TRUE(PushBackCallbackMsg(WIFI_SCAN_INFO_NOTIFY_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, WIFI_SCAN_INFO_NOTIFY_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite, "C\t107\t100\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, WIFI_SCAN_INFO_NOTIFY_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealIfaceCbkTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    cbmsg->msg.ifMsg.id = 0;
    cbmsg->msg.ifMsg.type = 100;
    StrSafeCopy(cbmsg->msg.ifMsg.ifname, sizeof(cbmsg->msg.ifMsg.ifname), "wlan0");
    EXPECT_TRUE(PushBackCallbackMsg(WIFI_ADD_IFACE_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, WIFI_ADD_IFACE_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite, "C\t103\t0\t100\twlan0\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, WIFI_ADD_IFACE_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealConnectionChangedCbkTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    cbmsg->msg.connMsg.status = 100;
    cbmsg->msg.connMsg.networkId = 1;
    StrSafeCopy(cbmsg->msg.connMsg.bssid, sizeof(cbmsg->msg.connMsg.bssid), "00:00:00:00:00:00");
    EXPECT_TRUE(PushBackCallbackMsg(WIFI_CONNECT_CHANGED_NOTIFY_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, WIFI_CONNECT_CHANGED_NOTIFY_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite, "C\t108\t100\t1\t00:00:00:00:00:00\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, WIFI_CONNECT_CHANGED_NOTIFY_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealP2pDeviceFoundCbkTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    StrSafeCopy(cbmsg->msg.deviceInfo.srcAddress, sizeof(cbmsg->msg.deviceInfo.srcAddress), "00:00:00:00:00:00");
    EXPECT_TRUE(PushBackCallbackMsg(P2P_DEVICE_FOUND_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, P2P_DEVICE_FOUND_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite, "C\t120\t0\t0\t0\t0\t00:00:00:00:00:00\t\t\t\t\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, P2P_DEVICE_FOUND_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealP2pNegoriationCbkLostTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    StrSafeCopy(cbmsg->msg.connMsg.bssid, sizeof(cbmsg->msg.connMsg.bssid), "00:00:00:00:00:00");
    EXPECT_TRUE(PushBackCallbackMsg(P2P_DEVICE_LOST_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, P2P_DEVICE_LOST_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite, "C\t121\t00:00:00:00:00:00\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, P2P_DEVICE_LOST_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealP2pNegoriationCbkTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    StrSafeCopy(cbmsg->msg.connMsg.bssid, sizeof(cbmsg->msg.connMsg.bssid), "00:00:00:00:00:00");
    EXPECT_TRUE(PushBackCallbackMsg(P2P_GO_NEGOTIATION_REQUEST_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, P2P_GO_NEGOTIATION_REQUEST_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite, "C\t122\t0\t00:00:00:00:00:00\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, P2P_GO_NEGOTIATION_REQUEST_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealP2pInviationCbkReceiveTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    StrSafeCopy(cbmsg->msg.invitaInfo.srcAddress, sizeof(cbmsg->msg.invitaInfo.srcAddress), "00:00:00:00:00:00");
    StrSafeCopy(cbmsg->msg.invitaInfo.bssid, sizeof(cbmsg->msg.invitaInfo.bssid), "00:00:00:00:00:00");
    EXPECT_TRUE(PushBackCallbackMsg(P2P_INVITATION_RECEIVED_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, P2P_INVITATION_RECEIVED_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite,
        "C\t125\t0\t0\t0\t00:00:00:00:00:00\t\t00:00:00:00:00:00\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, P2P_INVITATION_RECEIVED_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealP2pInviationCbkResultTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    StrSafeCopy(cbmsg->msg.invitaInfo.bssid, sizeof(cbmsg->msg.invitaInfo.bssid), "00:00:00:00:00:00");
    EXPECT_TRUE(PushBackCallbackMsg(P2P_INVITATION_RESULT_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, P2P_INVITATION_RESULT_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite, "C\t126\t0\t00:00:00:00:00:00\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, P2P_INVITATION_RESULT_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealP2pInviationCbkFailureTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    StrSafeCopy(cbmsg->msg.invitaInfo.bssid, sizeof(cbmsg->msg.invitaInfo.bssid), "00:00:00:00:00:00");
    EXPECT_TRUE(PushBackCallbackMsg(P2P_GROUP_FORMATION_FAILURE_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, P2P_GROUP_FORMATION_FAILURE_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite, "C\t128\t00:00:00:00:00:00\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, P2P_GROUP_FORMATION_FAILURE_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealP2pGroupInfoCbkStartTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    StrSafeCopy(cbmsg->msg.groupInfo.groupIfName, sizeof(cbmsg->msg.groupInfo.groupIfName), "p2p-dev-wlan0");
    StrSafeCopy(cbmsg->msg.groupInfo.ssid, sizeof(cbmsg->msg.groupInfo.ssid), "test_p2p");
    StrSafeCopy(
        cbmsg->msg.groupInfo.goDeviceAddress, sizeof(cbmsg->msg.groupInfo.goDeviceAddress), "00:00:00:00:00:00");
    EXPECT_TRUE(PushBackCallbackMsg(P2P_GROUP_STARTED_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, P2P_GROUP_STARTED_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite,
        "C\t129\t0\t0\t0\tp2p-dev-wlan0\ttest_p2p\t\t\t00:00:00:00:00:00\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, P2P_GROUP_STARTED_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealP2pGroupInfoCbkRemoveTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    StrSafeCopy(cbmsg->msg.groupInfo.groupIfName, sizeof(cbmsg->msg.groupInfo.groupIfName), "p2p-dev-wlan0");
    EXPECT_TRUE(PushBackCallbackMsg(P2P_GROUP_REMOVED_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, P2P_GROUP_REMOVED_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite, "C\t130\t0\tp2p-dev-wlan0\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, P2P_GROUP_REMOVED_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealP2pDeviceInfoCbkPbcTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    StrSafeCopy(cbmsg->msg.deviceInfo.srcAddress, sizeof(cbmsg->msg.deviceInfo.srcAddress), "00:00:00:00:00:00");
    EXPECT_TRUE(PushBackCallbackMsg(P2P_PROV_DISC_PBC_REQ_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, P2P_PROV_DISC_PBC_REQ_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite, "C\t131\t00:00:00:00:00:00\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, P2P_PROV_DISC_PBC_REQ_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealP2pDeviceInfoCbkPinTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    StrSafeCopy(cbmsg->msg.deviceInfo.srcAddress, sizeof(cbmsg->msg.deviceInfo.srcAddress), "00:00:00:00:00:00");
    StrSafeCopy(cbmsg->msg.deviceInfo.deviceName, sizeof(cbmsg->msg.deviceInfo.deviceName), "test_p2p");
    EXPECT_TRUE(PushBackCallbackMsg(P2P_PROV_DISC_SHOW_PIN_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, P2P_PROV_DISC_SHOW_PIN_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite, "C\t134\t00:00:00:00:00:00\ttest_p2p\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, P2P_PROV_DISC_SHOW_PIN_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealP2pDeviceInfoCbkConnectionTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    StrSafeCopy(
        cbmsg->msg.deviceInfo.p2pDeviceAddress, sizeof(cbmsg->msg.deviceInfo.p2pDeviceAddress), "00:00:00:00:00:00");
    EXPECT_TRUE(PushBackCallbackMsg(AP_STA_DISCONNECTED_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, AP_STA_DISCONNECTED_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite, "C\t138\t00:00:00:00:00:00\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, AP_STA_DISCONNECTED_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealP2pServerInfoCbkTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    StrSafeCopy(cbmsg->msg.serverInfo.srcAddress, sizeof(cbmsg->msg.serverInfo.srcAddress), "00:00:00:00:00:00");
    EXPECT_TRUE(PushBackCallbackMsg(P2P_SERV_DISC_RESP_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, P2P_SERV_DISC_RESP_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite, "C\t136\t0\t00:00:00:00:00:00\t0\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, P2P_SERV_DISC_RESP_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, DealP2pServerDiscReqCbkTest, TestSize.Level1)
{
    WifiHalEventCallbackMsg *cbmsg = (WifiHalEventCallbackMsg *)calloc(1, sizeof(WifiHalEventCallbackMsg));
    StrSafeCopy(cbmsg->msg.serDiscReqInfo.mac, sizeof(cbmsg->msg.serDiscReqInfo.mac), "00:00:00:00:00:00");
    EXPECT_TRUE(PushBackCallbackMsg(P2P_SERV_DISC_REQ_EVENT, cbmsg) == 0);
    EXPECT_TRUE(OnCallbackTransact(mServer, P2P_SERV_DISC_REQ_EVENT, mContext) == 0);
    EXPECT_TRUE(StrcmpMathRight(mContext->szWrite, "C\t140\t0\t0\t0\t00:00:00:00:00:00\t0\t$$$$$$") == 0);
    EXPECT_TRUE(EndCallbackTransact(mServer, P2P_SERV_DISC_REQ_EVENT) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetNameTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetName(nullptr, nullptr) < 0);
    char buff[] = "N\tGetName\tx\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tGetName\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcGetName(mServer, mContext) < 0);
    char buff2[] = "N\tGetName\t128\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tGetName\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcGetName(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetTypeTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetType(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcGetType(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcRegisterEventCallbackTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcRegisterEventCallback(nullptr, nullptr) < 0);
    char buff[] = "N\tRegisterEventCallback\tasdgfd\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tRegisterEventCallback\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcRegisterEventCallback(mServer, mContext) < 0);
    char buff2[] = "N\tRegisterEventCallback\t2\t101\tasdf\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tRegisterEventCallback\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcRegisterEventCallback(mServer, mContext) < 0);
    char buff3[] = "N\tRegisterEventCallback\t2\t101\t108\t";
    mContext->oneProcess = buff3;
    mContext->nPos = strlen("N\tRegisterEventCallback\t");
    mContext->nSize = strlen(buff3);
    EXPECT_TRUE(RpcRegisterEventCallback(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcUnRegisterEventCallbackTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcUnRegisterEventCallback(nullptr, nullptr) < 0);
    char buff[] = "N\tUnRegisterEventCallback\tasdgfd\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tUnRegisterEventCallback\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcUnRegisterEventCallback(mServer, mContext) < 0);
    char buff2[] = "N\tUnRegisterEventCallback\t2\t101\tasdf\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tUnRegisterEventCallback\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcUnRegisterEventCallback(mServer, mContext) < 0);
    char buff3[] = "N\tUnRegisterEventCallback\t2\t101\t108\t";
    mContext->oneProcess = buff3;
    mContext->nPos = strlen("N\tUnRegisterEventCallback\t");
    mContext->nSize = strlen(buff3);
    EXPECT_TRUE(RpcUnRegisterEventCallback(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcNotifyClearTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcNotifyClear(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcNotifyClear(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetWifiChipTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetWifiChip(nullptr, nullptr) < 0);
    char buff[] = "N\tGetWifiChip\tadsgfsd\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tGetWifiChip\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcGetWifiChip(mServer, mContext) < 0);
    char buff1[] = "N\tGetWifiChip\t8\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tGetWifiChip\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcGetWifiChip(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetWifiChipIdsTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetWifiChipIds(nullptr, nullptr) < 0);
    char buff[] = "N\tGetWifiChipIds\tx\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tGetWifiChipIds\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcGetWifiChipIds(mServer, mContext) < 0);
    char buff1[] = "N\tGetWifiChipIds\t8\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tGetWifiChipIds\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcGetWifiChipIds(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetChipIdTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetChipId(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcGetChipId(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcCreateIfaceTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcCreateIface(nullptr, nullptr) < 0);
    char buff[] = "N\tCreateIface\tfdshajkdsghk\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tCreateIface\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcCreateIface(mServer, mContext) < 0);
    char buff1[] = "N\tCreateIface\t8\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tCreateIface\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcCreateIface(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetIfaceTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetIface(nullptr, nullptr) < 0);
    char buff[] = "N\tGetIface\twlan0";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tGetIface\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcGetIface(mServer, mContext) < 0);
    char buff1[] = "N\tGetIface\twlan0\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tGetIface\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcGetIface(mServer, mContext) == 0);
    char buff2[] = "N\tGetIface\t01234567890123456789012345678901\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tGetIface\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcGetIface(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetIfaceNamesTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetIfaceNames(nullptr, nullptr) < 0);
    char buff[] = "N\tGetIfaceNames\tasdgf\tasdgf\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tGetIfaceNames\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcGetIfaceNames(mServer, mContext) < 0);
    char buff1[] = "N\tGetIfaceNames\t12\tasdgf\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tGetIfaceNames\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcGetIfaceNames(mServer, mContext) < 0);
    char buff2[] = "N\tGetIfaceNames\t12\t128\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tGetIfaceNames\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcGetIfaceNames(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcRemoveIfaceTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcRemoveIface(nullptr, nullptr) < 0);
    char buff[] = "N\tRemoveIface\twlan0";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tRemoveIface\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcRemoveIface(mServer, mContext) < 0);
    char buff1[] = "N\tRemoveIface\twlan0\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tRemoveIface\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcRemoveIface(mServer, mContext) == 0);
    char buff2[] = "N\tRemoveIface\t01234567890123456789012345678901\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tRemoveIface\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcRemoveIface(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetCapabilitiesTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetCapabilities(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcGetCapabilities(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetSupportedComboModesTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetSupportedComboModes(nullptr, nullptr) < 0);
    char buff[] = "N\tGetSupportedComboModes\tasdgds\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tGetSupportedComboModes\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcGetSupportedComboModes(mServer, mContext) < 0);
    char buff1[] = "N\tGetSupportedComboModes\t134\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tGetSupportedComboModes\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcGetSupportedComboModes(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcConfigComboModesTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcConfigComboModes(nullptr, nullptr) < 0);
    char buff[] = "N\tConfigComboModes\tasdgds\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tConfigComboModes\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcConfigComboModes(mServer, mContext) < 0);
    char buff1[] = "N\tConfigComboModes\t134\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tConfigComboModes\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcConfigComboModes(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetComboModesTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetComboModes(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcGetComboModes(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcRequestFirmwareDebugDumpTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcRequestFirmwareDebugDump(nullptr, nullptr) < 0);
    char buff[] = "N\tRequestFirmwareDebugDump\tasdgds\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tRequestFirmwareDebugDump\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcRequestFirmwareDebugDump(mServer, mContext) < 0);
    char buff1[] = "N\tRequestFirmwareDebugDump\t134\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tRequestFirmwareDebugDump\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcRequestFirmwareDebugDump(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcStartTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcStart(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcStart(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcStartSupplicantTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcStartSupplicant(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcStartSupplicant(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcStopSupplicantTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcStopSupplicant(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcStopSupplicant(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcStopTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcStop(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcStop(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcConnectSupplicantTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcConnectSupplicant(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcConnectSupplicant(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcDisconnectSupplicantTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcDisconnectSupplicant(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcDisconnectSupplicant(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcRequestToSupplicantTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcRequestToSupplicant(nullptr, nullptr) < 0);
    char buff[] = "N\tRequestToSupplicant\tasdf\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tRequestToSupplicant\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcRequestToSupplicant(mServer, mContext) < 0);
    char buff1[] = "N\tRequestToSupplicant\t4\t8c677c8d5a\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tRequestToSupplicant\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcRequestToSupplicant(mServer, mContext) < 0);
    char buff2[] = "N\tRequestToSupplicant\t4\t8c677c8a\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tRequestToSupplicant\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcRequestToSupplicant(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcSetPowerSaveTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcSetPowerSave(nullptr, nullptr) < 0);
    char buff[] = "N\tSetPowerSave\tfds\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tSetPowerSave\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcSetPowerSave(mServer, mContext) < 0);
    char buff1[] = "N\tSetPowerSave\t1\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tSetPowerSave\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcSetPowerSave(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcWpaSetCountryCodeTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcWpaSetCountryCode(nullptr, nullptr) < 0);
    char buff[] = "N\tWpaSetCountryCode\tCHINA\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tWpaSetCountryCode\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcWpaSetCountryCode(mServer, mContext) < 0);
    char buff1[] = "N\tWpaSetCountryCode\tCN\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tWpaSetCountryCode\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcWpaSetCountryCode(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcWpaGetCountryCodeTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcWpaGetCountryCode(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcWpaGetCountryCode(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcStartScanTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcStartScan(nullptr, nullptr) < 0);
    char buff[] = "N\tStartScan\tx\t10\tscan_ssid1\t10\tscan_ssid2\t2\t2427\t2442\t2\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tStartScan\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcStartScan(mServer, mContext) < 0);
    char buff1[] = "N\tStartScan\t2\t10\tscan_ssid1\t10\tscan_ssid2";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tStartScan\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcStartScan(mServer, mContext) < 0);
    char buff2[] = "N\tStartScan\t2\t10\tscan_ssid1\t10\tscan_ssid2\tx\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tStartScan\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcStartScan(mServer, mContext) < 0);
    char buff3[] = "N\tStartScan\t2\t10\tscan_ssid1\t10\tscan_ssid2\t2\t2427\tx\tx\t";
    mContext->oneProcess = buff3;
    mContext->nPos = strlen("N\tStartScan\t");
    mContext->nSize = strlen(buff3);
    EXPECT_TRUE(RpcStartScan(mServer, mContext) < 0);
    char buff4[] = "N\tStartScan\t2\t10\tscan_ssid1\t10\tscan_ssid2\t2\t2427\t2442\tx\t";
    mContext->oneProcess = buff4;
    mContext->nPos = strlen("N\tStartScan\t");
    mContext->nSize = strlen(buff4);
    EXPECT_TRUE(RpcStartScan(mServer, mContext) < 0);
    char buff5[] = "N\tStartScan\t2\t10\tscan_ssid1\t10\tscan_ssid2\t2\t2427\t2442\t2\t";
    mContext->oneProcess = buff5;
    mContext->nPos = strlen("N\tStartScan\t");
    mContext->nSize = strlen(buff5);
    EXPECT_TRUE(RpcStartScan(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetScanInfosTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetScanInfos(nullptr, nullptr) < 0);
    char buff[] = "N\tGetScanInfos\tx\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tGetScanInfos\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcGetScanInfos(mServer, mContext) < 0);
    char buff1[] = "N\tGetScanInfos\t12\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tGetScanInfos\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcGetScanInfos(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetNetworkListTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetNetworkList(nullptr, nullptr) < 0);
    char buff[] = "N\tGetNetworkList\tx\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tGetNetworkList\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcGetNetworkList(mServer, mContext) < 0);
    char buff1[] = "N\tGetNetworkList\t12\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tGetNetworkList\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcGetNetworkList(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcStartPnoScanTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcStartPnoScan(nullptr, nullptr) < 0);
    char buff[] = "N\tStartPnoScan\t1\tx\t1\t2\t3\tasd\t4\tasdf\t1\t5\tasdfg\t2\t5040\t5080\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tStartPnoScan\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcStartPnoScan(mServer, mContext) < 0);
    char buff1[] = "N\tStartPnoScan\t1\t2\t1\t2\t10\tscan_ssid1\t10\tscan_ssid2";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tStartPnoScan\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcStartPnoScan(mServer, mContext) < 0);
    char buff2[] = "N\tStartPnoScan\t1\t2\t1\t2\t10\tscan_ssid1\t10\tscan_ssid2\tx\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tStartPnoScan\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcStartPnoScan(mServer, mContext) < 0);
    char buff3[] = "N\tStartPnoScan\t1\t2\t1\t2\t10\tscan_ssid1\t10\tscan_ssid2\t2\t10\tsave_ssid1\t10\tsave_ssid2";
    mContext->oneProcess = buff3;
    mContext->nPos = strlen("N\tStartPnoScan\t");
    mContext->nSize = strlen(buff3);
    EXPECT_TRUE(RpcStartPnoScan(mServer, mContext) < 0);
    char buff4[] =
        "N\tStartPnoScan\t1\t2\t1\t2\t10\tscan_ssid1\t10\tscan_ssid2\t2\t10\tsave_ssid1\t10\tsave_ssid2\tx\t";
    mContext->oneProcess = buff4;
    mContext->nPos = strlen("N\tStartPnoScan\t");
    mContext->nSize = strlen(buff4);
    EXPECT_TRUE(RpcStartPnoScan(mServer, mContext) < 0);
    char buff5[] =
        "N\tStartPnoScan\t1\t2\t1\t2\t10\tscan_ssid1\t10\tscan_ssid2\t2\t10\tsave_ssid1\t10\tsave_ssid2\t2\t5040\tx\t";
    mContext->oneProcess = buff5;
    mContext->nPos = strlen("N\tStartPnoScan\t");
    mContext->nSize = strlen(buff5);
    EXPECT_TRUE(RpcStartPnoScan(mServer, mContext) < 0);
    char buff6[] =
    "N\tStartPnoScan\t1\t2\t1\t2\t10\tscan_ssid1\t10\tscan_ssid2\t2\t10\tsave_ssid1\t10\tsave_ssid2\t2\t5040\t5080\t";
    mContext->oneProcess = buff6;
    mContext->nPos = strlen("N\tStartPnoScan\t");
    mContext->nSize = strlen(buff6);
    EXPECT_TRUE(RpcStartPnoScan(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcStopPnoScanTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcStopPnoScan(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcStopPnoScan(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcConnectTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcConnect(nullptr, nullptr) < 0);
    char buff[] = "N\tConnect\tx\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tConnect\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcConnect(mServer, mContext) < 0);
    char buff1[] = "N\tConnect\t1\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tConnect\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcConnect(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcWpaAutoConnectTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcWpaAutoConnect(nullptr, nullptr) < 0);
    char buff[] = "N\tWpaAutoConnect\t0ad\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tWpaAutoConnect\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcWpaAutoConnect(mServer, mContext) < 0);
    char buff1[] = "N\tWpaAutoConnect\t1\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tWpaAutoConnect\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcWpaAutoConnect(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcReconnectTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcReconnect(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcReconnect(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcReassociateTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcReassociate(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcReassociate(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcDisconnectTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcDisconnect(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcDisconnect(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetStaCapabilitiesTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetStaCapabilities(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcGetStaCapabilities(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetDeviceMacAddressTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetDeviceMacAddress(nullptr, nullptr) < 0);
    char buff[] = "N\tGetDeviceMacAddress\tx\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tGetDeviceMacAddress\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcGetDeviceMacAddress(mServer, mContext) < 0);
    char buff1[] = "N\tGetDeviceMacAddress\t17\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tGetDeviceMacAddress\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcGetDeviceMacAddress(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetFrequenciesTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetFrequencies(nullptr, nullptr) < 0);
    char buff[] = "N\tGetFrequencies\t1\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tGetFrequencies\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcGetFrequencies(mServer, mContext) < 0);
    char buff1[] = "N\tGetFrequencies\t1\t128\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tGetFrequencies\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcGetFrequencies(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcSetAssocMacAddrTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcSetAssocMacAddr(nullptr, nullptr) < 0);
    char buff[] = "N\tSetAssocMacAddr\tx\t7d9c039dfeba46\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tSetAssocMacAddr\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcSetAssocMacAddr(mServer, mContext) < 0);
    char buff1[] = "N\tSetAssocMacAddr\t6\t7d9c039dfeba46\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tSetAssocMacAddr\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcSetAssocMacAddr(mServer, mContext) < 0);
    char buff2[] = "N\tSetAssocMacAddr\t7\t7d9c039dfeba46\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tSetAssocMacAddr\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcSetAssocMacAddr(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcSetScanningMacAddressTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcSetScanningMacAddress(nullptr, nullptr) < 0);
    char buff[] = "N\tSetScanningMacAddress\tx\t7d9c039dfeba46\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tSetScanningMacAddress\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcSetScanningMacAddress(mServer, mContext) < 0);
    char buff1[] = "N\tSetScanningMacAddress\t6\t7d9c039dfeba46\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tSetScanningMacAddress\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcSetScanningMacAddress(mServer, mContext) < 0);
    char buff2[] = "N\tSetScanningMacAddress\t7\t7d9c039dfeba46\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tSetScanningMacAddress\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcSetScanningMacAddress(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcDeauthLastRoamingBssidTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcDeauthLastRoamingBssid(nullptr, nullptr) < 0);
    char buff[] = "N\tDeauthLastRoamingBssid\tx\t7d9c039dfeba46\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tDeauthLastRoamingBssid\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcDeauthLastRoamingBssid(mServer, mContext) < 0);
    char buff1[] = "N\tDeauthLastRoamingBssid\t6\t7d9c039dfeba46\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tDeauthLastRoamingBssid\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcDeauthLastRoamingBssid(mServer, mContext) < 0);
    char buff2[] = "N\tDeauthLastRoamingBssid\t7\t7d9c039dfeba46\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tDeauthLastRoamingBssid\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcDeauthLastRoamingBssid(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetSupportFeatureTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetSupportFeature(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcGetSupportFeature(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcRunCmdTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcRunCmd(nullptr, nullptr) < 0);
    char buff[] = "N\tRunCmd\twlan0";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tRunCmd\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcRunCmd(mServer, mContext) < 0);
    char buff1[] = "N\tRunCmd\twlan0\tx\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tRunCmd\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcRunCmd(mServer, mContext) < 0);
    char buff2[] = "N\tRunCmd\twlan0\t1\tx\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tRunCmd\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcRunCmd(mServer, mContext) < 0);
    char buff3[] = "N\tRunCmd\twlan0\t1\t6\t7d9c039dfeba46\t";
    mContext->oneProcess = buff3;
    mContext->nPos = strlen("N\tRunCmd\t");
    mContext->nSize = strlen(buff3);
    EXPECT_TRUE(RpcRunCmd(mServer, mContext) < 0);
    char buff4[] = "N\tRunCmd\twlan0\t1\t7\t7d9c039dfeba46\t";
    mContext->oneProcess = buff4;
    mContext->nPos = strlen("N\tRunCmd\t");
    mContext->nSize = strlen(buff4);
    EXPECT_TRUE(RpcRunCmd(mServer, mContext) == 0);
    char buff5[] = "N\tRunCmd\t0123456789012345678901\t1\t7\t7d9c039dfeba46\t";
    mContext->oneProcess = buff5;
    mContext->nPos = strlen("N\tRunCmd\t");
    mContext->nSize = strlen(buff5);
    EXPECT_TRUE(RpcRunCmd(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcSetWifiTxPowerTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcSetWifiTxPower(nullptr, nullptr) < 0);
    char buff[] = "N\tSetWifiTxPower\t12";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tSetWifiTxPower\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcSetWifiTxPower(mServer, mContext) < 0);
    char buff1[] = "N\tSetWifiTxPower\t12\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tSetWifiTxPower\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcSetWifiTxPower(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcRemoveNetworkTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcRemoveNetwork(nullptr, nullptr) < 0);
    char buff[] = "N\tRemoveNetwork\t12";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tRemoveNetwork\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcRemoveNetwork(mServer, mContext) < 0);
    char buff1[] = "N\tRemoveNetwork\t12\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tRemoveNetwork\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcRemoveNetwork(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcAddNetworkTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcAddNetwork(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcAddNetwork(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcEnableNetworkTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcEnableNetwork(nullptr, nullptr) < 0);
    char buff[] = "N\tEnableNetwork\t12";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tEnableNetwork\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcEnableNetwork(mServer, mContext) < 0);
    char buff1[] = "N\tEnableNetwork\t12\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tEnableNetwork\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcEnableNetwork(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcDisableNetworkTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcDisableNetwork(nullptr, nullptr) < 0);
    char buff[] = "N\tDisableNetwork\t12";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tDisableNetwork\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcDisableNetwork(mServer, mContext) < 0);
    char buff1[] = "N\tDisableNetwork\t12\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tDisableNetwork\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcDisableNetwork(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcSetNetworkTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcSetNetwork(nullptr, nullptr) < 0);
    char buff[] = "N\tSetNetwork\t0\t1";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tSetNetwork\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcSetNetwork(mServer, mContext) < 0);
    char buff1[] = "N\tSetNetwork\t0\t1\t12\tafsdgljsd";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tSetNetwork\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcSetNetwork(mServer, mContext) == 0);
    char buff2[] = "N\tSetNetwork\t0\t1\t12\tafsdgljsd\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tSetNetwork\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcSetNetwork(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcWpaGetNetworkTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcWpaGetNetwork(nullptr, nullptr) < 0);
    char buff[] = "N\tWpaGetNetwork\t2\tssid";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tWpaGetNetwork\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcWpaGetNetwork(mServer, mContext) < 0);
    char buff1[] = "N\tWpaGetNetwork\t2\tssid\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tWpaGetNetwork\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcWpaGetNetwork(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcSaveNetworkConfigTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcSaveNetworkConfig(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcSaveNetworkConfig(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcStartWpsPbcModeTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcStartWpsPbcMode(nullptr, nullptr) < 0);
    char buff[] = "N\tStartWpsPbcMode\t1\t2\tadsgfkdsj";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tStartWpsPbcMode\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcStartWpsPbcMode(mServer, mContext) < 0);
    char buff1[] = "N\tStartWpsPbcMode\t1\t2\tadsgfkdsj\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tStartWpsPbcMode\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcStartWpsPbcMode(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcStartWpsPinModeTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcStartWpsPinMode(nullptr, nullptr) < 0);
    char buff[] = "N\tStartWpsPinMode\t1\t2\tadsgfkdsj";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tStartWpsPinMode\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcStartWpsPinMode(mServer, mContext) < 0);
    char buff1[] = "N\tStartWpsPinMode\t1\t2\tadsgfkdsj\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tStartWpsPinMode\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcStartWpsPinMode(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcStopWpsTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcStopWps(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcStopWps(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcWpaBlocklistClearTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcWpaBlocklistClear(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcWpaBlocklistClear(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetRoamingCapabilitiesTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetRoamingCapabilities(nullptr, nullptr) < 0);
    EXPECT_TRUE(RpcGetRoamingCapabilities(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcSetRoamConfigTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcSetRoamConfig(nullptr, nullptr) < 0);
    char buff[] = "N\tSetRoamConfig\tx\tfdsagdsa\tsafdgfds\t1\tvcxzcbvx\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tSetRoamConfig\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcSetRoamConfig(mServer, mContext) < 0);
    char buff1[] = "N\tSetRoamConfig\t2\tfdsagdsa\tsafdgfds";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tSetRoamConfig\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcSetRoamConfig(mServer, mContext) < 0);
    char buff2[] = "N\tSetRoamConfig\t2\tfdsagdsa\tsafdgfds\tx\tvcxzcbvx\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tSetRoamConfig\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcSetRoamConfig(mServer, mContext) < 0);
    char buff3[] = "N\tSetRoamConfig\t2\tfdsagdsa\tsafdgfds\t1\tvcxzcbvx";
    mContext->oneProcess = buff3;
    mContext->nPos = strlen("N\tSetRoamConfig\t");
    mContext->nSize = strlen(buff3);
    EXPECT_TRUE(RpcSetRoamConfig(mServer, mContext) < 0);
    char buff4[] = "N\tSetRoamConfig\t2\tfdsagdsa\tsafdgfds\t1\tvcxzcbvx\t";
    mContext->oneProcess = buff4;
    mContext->nPos = strlen("N\tSetRoamConfig\t");
    mContext->nSize = strlen(buff4);
    EXPECT_TRUE(RpcSetRoamConfig(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetConnectSignalInfoTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetConnectSignalInfo(nullptr, nullptr) < 0);
    char buff[] = "N\tGetConnectSignalInfo\tssid";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tGetConnectSignalInfo\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcGetConnectSignalInfo(mServer, mContext) < 0);
    char buff1[] = "N\tGetConnectSignalInfo\t00:00:00:00:00:00\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tGetConnectSignalInfo\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcGetConnectSignalInfo(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcStartSoftApTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcStartSoftAp(nullptr, nullptr) < 0);
    char buff[] = "N\tStartSoftAp\t0\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tStartSoftAp\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcStartSoftAp(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcStopSoftApTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcStopSoftAp(nullptr, nullptr) < 0);
    char buff[] = "N\tStopSoftAp\t0\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tStopSoftAp\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcStopSoftAp(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcSetHostapdConfigTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcSetHostapdConfig(nullptr, nullptr) < 0);
    char buff[] = "N\tSetHostapdConfig\ttests\t5\tadc123456\t9\t1\t0\t6\t20\t0\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tSetHostapdConfig\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcSetHostapdConfig(mServer, mContext) == 0);
    char buff1[] = "N\tSetHostapdConfig\ttests\t5\tadc123456\t9\t1\t0\t6\t20";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tSetHostapdConfig\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcSetHostapdConfig(mServer, mContext) < 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetStaInfosTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetStaInfos(nullptr, nullptr) < 0);
    char buff[] = "N\tGetStaInfos\t128";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tGetStaInfos\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcGetStaInfos(mServer, mContext) < 0);
    char buff1[] = "N\tGetStaInfos\t128\t0\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tGetStaInfos\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcGetStaInfos(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcSetCountryCodeTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcSetCountryCode(nullptr, nullptr) < 0);
    char buff[] = "N\tSetCountryCode\tCN";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tSetCountryCode\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcSetCountryCode(mServer, mContext) < 0);
    char buff1[] = "N\tSetCountryCode\tCN\t0\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tSetCountryCode\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcSetCountryCode(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcSetMacFilterTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcSetMacFilter(nullptr, nullptr) < 0);
    char buff[] = "N\tSetMacFilter\tx\t345697dbf921d3\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tSetMacFilter\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcSetMacFilter(mServer, mContext) < 0);
    char buff1[] = "N\tSetMacFilter\t6\t345697dbf921d3\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tSetMacFilter\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcSetMacFilter(mServer, mContext) < 0);
    char buff2[] = "N\tSetMacFilter\t7\t345697dbf921d3\t0\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tSetMacFilter\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcSetMacFilter(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcDelMacFilterTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcDelMacFilter(nullptr, nullptr) < 0);
    char buff[] = "N\tDelMacFilter\tx\t345697dbf921d3\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tDelMacFilter\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcDelMacFilter(mServer, mContext) < 0);
    char buff1[] = "N\tDelMacFilter\t6\t345697dbf921d3\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tDelMacFilter\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcDelMacFilter(mServer, mContext) < 0);
    char buff2[] = "N\tDelMacFilter\t7\t345697dbf921d3\t0\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tDelMacFilter\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcDelMacFilter(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcDisassociateStaTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcDisassociateSta(nullptr, nullptr) < 0);
    char buff[] = "N\tDisassociateSta\tx\t345697dbf921d3\t";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tDisassociateSta\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcDisassociateSta(mServer, mContext) < 0);
    char buff1[] = "N\tDisassociateSta\t6\t345697dbf921d3\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tDisassociateSta\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcDisassociateSta(mServer, mContext) < 0);
    char buff2[] = "N\tDisassociateSta\t7\t345697dbf921d3\t0\t";
    mContext->oneProcess = buff2;
    mContext->nPos = strlen("N\tDisassociateSta\t");
    mContext->nSize = strlen(buff2);
    EXPECT_TRUE(RpcDisassociateSta(mServer, mContext) == 0);
}

HWTEST_F(WifiHalCRpcServerTest, RpcGetValidFrequenciesForBandTest, TestSize.Level1)
{
    EXPECT_TRUE(RpcGetValidFrequenciesForBand(nullptr, nullptr) < 0);
    char buff[] = "N\tGetValidFrequenciesForBand\t1\t128";
    mContext->oneProcess = buff;
    mContext->nPos = strlen("N\tGetValidFrequenciesForBand\t");
    mContext->nSize = strlen(buff);
    EXPECT_TRUE(RpcGetValidFrequenciesForBand(mServer, mContext) < 0);
    char buff1[] = "N\tGetValidFrequenciesForBand\t1\t128\t0\t";
    mContext->oneProcess = buff1;
    mContext->nPos = strlen("N\tGetValidFrequenciesForBand\t");
    mContext->nSize = strlen(buff1);
    EXPECT_TRUE(RpcGetValidFrequenciesForBand(mServer, mContext) == 0);
}
}  // namespace Wifi
}  // namespace OHOS