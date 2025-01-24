/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "securec.h"
#include "wifi_hal_callback.h"
#include <log.h>

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Eq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
const int STATUS_MSG = 0;
const int NET_WORK = 5;
const int DISASSOC_STA_HAS_LEFT = 0;
static std::string g_errLog;
void MyLogCallback(const LogType type, const LogLevel level,
                   const unsigned int domain, const char *tag,
                   const char *msg)
{
    g_errLog = msg;
}

class WifiHalCallbackTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() 
    {
        LOG_SetCallback(MyLogCallback);
    }
    virtual void TearDown() {}
};

HWTEST_F(WifiHalCallbackTest, RpcP2pSetWpsSecondaryDeviceTypeTest, TestSize.Level1)
{
    int status = STATUS_MSG;
    WifiHalCbNotifyScanEnd(status);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, WifiHalCbNotifyConnectChangedTest, TestSize.Level1)
{
    int status = STATUS_MSG;
    int networkId = NET_WORK;
    char pos[] = "WIFI_REASON_LENGTH";
    WifiHalCbNotifyConnectChanged(status, networkId, NULL);
    WifiHalCbNotifyConnectChanged(status, networkId, pos);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, WifiHalCbNotifyDisConnectReasonTest, TestSize.Level1)
{
    int status = DISASSOC_STA_HAS_LEFT;
    char bssid[] = "02:42:ac:11:00:04";
    WifiHalCbNotifyDisConnectReason(status, NULL);
    WifiHalCbNotifyDisConnectReason(status, bssid);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, WifiHalCbNotifyBssidChangedTest, TestSize.Level1)
{
    char reasonPos[] = "WIFI_REASON_LENGTH";
    char bssidPos[] = "hello";
    WifiHalCbNotifyBssidChanged(nullptr, bssidPos);
    WifiHalCbNotifyBssidChanged(reasonPos, nullptr);
    WifiHalCbNotifyBssidChanged(reasonPos, bssidPos);
    char reason[] = "hello world";
    WifiHalCbNotifyBssidChanged(reason, bssidPos);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, WifiHalCbNotifyWpaStateChangeTest, TestSize.Level1)
{
    int status = STATUS_MSG;
    WifiHalCbNotifyWpaStateChange(status);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}


HWTEST_F(WifiHalCallbackTest, WifiHalCbNotifyWrongKeyTest, TestSize.Level1)
{
    int status = STATUS_MSG;
    WifiHalCbNotifyWrongKey(status);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}


HWTEST_F(WifiHalCallbackTest, WifiHalCbNotifyConnectionFullTest, TestSize.Level1)
{
    int status = STATUS_MSG;
    WifiHalCbNotifyConnectionFull(status);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, WifiHalCbNotifyConnectionRejectTest, TestSize.Level1)
{
    int status = STATUS_MSG;
    WifiHalCbNotifyConnectionReject(status);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, WifiHalCbNotifyWpsOverlapTest, TestSize.Level1)
{
    int event = STATUS_MSG;
    WifiHalCbNotifyWpsOverlap(event);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, WifiHalCbNotifyWpsTimeOutTest, TestSize.Level1)
{
    int event = STATUS_MSG;
    WifiHalCbNotifyWpsTimeOut(event);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}


HWTEST_F(WifiHalCallbackTest, WifiHalCbStaJoinTest, TestSize.Level1)
{
    int id = NET_WORK;
    char content[] = "AP-STA-CONNECTED";
    char contents[] = "AP-STA-DISCONNECTED";
    char contented[] = "WIFI_STA_LEAVE_EVENT";
    WifiHalCbStaJoin(nullptr, id);
    WifiHalCbStaJoin(content, id);
    WifiHalCbStaJoin(contents, id);
    WifiHalCbStaJoin(contented, id);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, WifiHalCbApStateTest, TestSize.Level1)
{
    int id = NET_WORK;
    char content[] = "AP-ENABLED";
    char contents[] = "AP-ENABLED";
    char contentd[] = "CTRL-EVENT-TERMINATING";
    char contented[] = "WIFI_STA_LEAVE_EVENT";
    WifiHalCbApState(nullptr, id);
    WifiHalCbApState(content, id);
    WifiHalCbApState(contents, id);
    WifiHalCbApState(contentd, id);
    WifiHalCbApState(contented, id);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, WifiP2pHalCbNotifyConnectSupplicantTest, TestSize.Level1)
{
    int event = STATUS_MSG;
    WifiP2pHalCbNotifyConnectSupplicant(event);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbDeviceFoundTest, TestSize.Level1)
{
    P2pDeviceInfo device;
    P2pHalCbDeviceFound(nullptr);
    P2pHalCbDeviceFound(&device);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbDeviceLostTest, TestSize.Level1)
{
    char p2pDeviceAddress[] = "00:00:00:00:00:00";
    P2pHalCbDeviceLost(nullptr);
    P2pHalCbDeviceLost(p2pDeviceAddress);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbGoNegotiationRequestTest, TestSize.Level1)
{
    char srcAddress[] = "00:00:00:00:00:00";
    short passwordId = NET_WORK;
    P2pHalCbGoNegotiationRequest(nullptr, passwordId);
    P2pHalCbGoNegotiationRequest(srcAddress, passwordId);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbGoNegotiationSuccessTest, TestSize.Level1)
{
    P2pHalCbGoNegotiationSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbGoNegotiationFailureTest, TestSize.Level1)
{
    int status = STATUS_MSG;
    P2pHalCbGoNegotiationFailure(status);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbInvitationReceivedTest, TestSize.Level1)
{
    P2pInvitationInfo info;
    P2pHalCbInvitationReceived(NULL);
    P2pHalCbInvitationReceived(&info);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbInvitationResultTest, TestSize.Level1)
{
    int status = STATUS_MSG;
    char bssid[] = "wifibssid";
    P2pHalCbInvitationResult(NULL, status);
    P2pHalCbInvitationResult(bssid, status);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbGroupFormationSuccessTest, TestSize.Level1)
{
    P2pHalCbGroupFormationSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbGroupFormationFailureTest, TestSize.Level1)
{
    char reason[] = "P2P_GROUP_FORMATION_FAILURE_EVENT";
    P2pHalCbGroupFormationFailure(NULL);
    P2pHalCbGroupFormationFailure(reason);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbGroupStartedTest, TestSize.Level1)
{
    P2pGroupInfo info;
    P2pHalCbGroupStarted(NULL);
    P2pHalCbGroupStarted(&info);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbGroupRemovedTest, TestSize.Level1)
{
    char groupIfName[] = "P2P_GROUP_REMOVED_EVENT";
    int isGo = NET_WORK;
    P2pHalCbGroupRemoved(NULL, isGo);
    P2pHalCbGroupRemoved(groupIfName, isGo);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbProvisionDiscoveryPbcRequestTest, TestSize.Level1)
{
    P2pHalCbProvisionDiscoveryPbcRequest(NULL);
    P2pHalCbProvisionDiscoveryPbcRequest("P2P_PROV_DISC_PBC_REQ_EVENT");
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbProvisionDiscoveryPbcResponseTest, TestSize.Level1)
{
    P2pHalCbProvisionDiscoveryPbcResponse(NULL);
    P2pHalCbProvisionDiscoveryPbcResponse("00:00:00:00:00:00");
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbProvisionDiscoveryEnterPinTest, TestSize.Level1)
{
    P2pHalCbProvisionDiscoveryEnterPin(NULL);
    P2pHalCbProvisionDiscoveryEnterPin("00:00:00:00:00:00");
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbProvisionDiscoveryShowPinTest, TestSize.Level1)
{
    char address[] = "00:00:00:00:00:00";
    char pin[] = "P2P_PROV_DISC_SHOW_PIN_EVEN";
    P2pHalCbProvisionDiscoveryShowPin(NULL, pin);
    P2pHalCbProvisionDiscoveryShowPin(address, NULL);
    P2pHalCbProvisionDiscoveryShowPin(address, pin);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbProvisionDiscoveryFailureTest, TestSize.Level1)
{
    P2pHalCbProvisionDiscoveryFailure();
    P2pHalCbFindStopped();
    P2pHalCbConnectSupplicantFailed();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbServiceDiscoveryResponseTest, TestSize.Level1)
{
    P2pServDiscRespInfo info;
    char buff[] = "\t1002callback";
    info.tlvs = buff;
    P2pHalCbServiceDiscoveryResponse(NULL);
    P2pHalCbServiceDiscoveryResponse(&info);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbStaConnectStateTest, TestSize.Level1)
{
    int state = STATUS_MSG;
    char p2pDeviceAddress[] = "wifibssid";
    char p2pGroupAddress[] = "wifiGroupAddr";
    P2pHalCbStaConnectState(NULL, NULL, state);
    P2pHalCbStaConnectState(p2pDeviceAddress, p2pGroupAddress, state);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbServDiscReqTest, TestSize.Level1)
{
    P2pServDiscReqInfo info;
    char buff[] = "\t1002request";
    info.tlvs = buff;
    P2pHalCbServDiscReq(NULL);
    P2pHalCbServDiscReq(&info);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(WifiHalCallbackTest, P2pHalCbP2pIfaceCreatedTest, TestSize.Level1)
{
    int state = STATUS_MSG;
    char ifName[] = "wifibssid";
    P2pHalCbP2pIfaceCreated(NULL, state);
    P2pHalCbP2pIfaceCreated(ifName, state);
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}
} // namespace Wifi
} // namespace OHOS

