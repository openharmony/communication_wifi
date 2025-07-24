/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <cstdio>
#include <gtest/gtest.h>
#include "wifi_hdi_wpa_callback.h"
#include "wifi_log.h"

using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
const std::string g_errLog = "wifitest";
constexpr int PD_STATUS_CODE_SHOW_PIN = 0;
constexpr int PD_STATUS_CODE_ENTER_PIN = 1;
constexpr int PD_STATUS_CODE_PBC_REQ = 2;
constexpr int PD_STATUS_CODE_PBC_RSP = 3;
constexpr int PD_STATUS_CODE_FAIL = 4;

class WifiHdiWpaCallbackTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(WifiHdiWpaCallbackTest, OnEventBssidChangedTest, TestSize.Level1)
{
    struct HdiWpaBssidChangedParam bssidChangedParam;
    bssidChangedParam.bssidLen = 17;

    int32_t result = OnEventBssidChanged(nullptr, &bssidChangedParam, "wlan0");
    EXPECT_EQ(result, 1);
    result = OnEventBssidChanged(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);

    bssidChangedParam.bssid = nullptr;
    bssidChangedParam.bssidLen = 0;
    result = OnEventBssidChanged(nullptr, &bssidChangedParam, "wlan0");
    EXPECT_EQ(result, 1);

    bssidChangedParam.reasonLen = 16;
    result = OnEventBssidChanged(nullptr, &bssidChangedParam, "wlan0");
    EXPECT_EQ(result, 1);
    bssidChangedParam.reasonLen = 0;
    result = OnEventBssidChanged(nullptr, &bssidChangedParam, "wlan0");
    EXPECT_EQ(result, 1);
    bssidChangedParam.reasonLen = 33;
    result = OnEventBssidChanged(nullptr, &bssidChangedParam, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventBssidChangedTest1, TestSize.Level1)
{
    struct HdiWpaBssidChangedParam bssidChangedParam;
    bssidChangedParam.bssidLen = 17;
    char reason[] = "wlan0";
    memcpy_s(bssidChangedParam.reason, sizeof(reason), reason, sizeof(reason));
    bssidChangedParam.reasonLen = 10;
    int32_t result = OnEventBssidChanged(nullptr, &bssidChangedParam, "wlan0");
    EXPECT_EQ(result, 1);

    bssidChangedParam.reasonLen = 36;
    result = OnEventBssidChanged(nullptr, &bssidChangedParam, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventTempDisabledTest, TestSize.Level1)
{
    struct HdiWpaTempDisabledParam tempDisabledParam;
    int32_t result = OnEventTempDisabled(nullptr, &tempDisabledParam, "wlan0");
    EXPECT_EQ(result, 0);
    result = OnEventTempDisabled(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventTempDisabledTest1, TestSize.Level1)
{
    struct HdiWpaTempDisabledParam tempDisabledParam;
    char ssid[] = "wlan0";
    memcpy_s(tempDisabledParam.ssid, sizeof(ssid), ssid, sizeof(ssid));
    int32_t result = OnEventTempDisabled(nullptr, &tempDisabledParam, "wlan0");
    EXPECT_EQ(result, 0);

    char reason[] = "wlan0";
    memcpy_s(tempDisabledParam.reason, sizeof(reason), reason, sizeof(reason));
    result = OnEventTempDisabled(nullptr, &tempDisabledParam, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventAssociateRejectTEST, TestSize.Level1)
{
    struct HdiWpaAssociateRejectParam associateRejectParam;
    associateRejectParam.statusCode = 1;
    int32_t result = OnEventAssociateReject(nullptr, &associateRejectParam, "wlan0");
    EXPECT_EQ(result, 0);
    result = OnEventAssociateReject(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventDeviceFoundTest, TestSize.Level1)
{
    struct HdiP2pDeviceInfoParam deviceInfoParam;
    deviceInfoParam.srcAddressLen = 17;
    deviceInfoParam.p2pDeviceAddressLen = 17;
    deviceInfoParam.configMethods = 1;
    deviceInfoParam.deviceCapabilities = 2;
    deviceInfoParam.groupCapabilities = 3;
    deviceInfoParam.wfdDeviceInfo = nullptr;
    deviceInfoParam.wfdLength = 0;

    int32_t result = OnEventDeviceFound(nullptr, &deviceInfoParam, "wlan0");
    EXPECT_EQ(result, 0);
    result = OnEventDeviceFound(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventGroupStartedTest, TestSize.Level1)
{
    struct HdiP2pGroupStartedParam groupStartedParam;
    groupStartedParam.isGo = 1;
    groupStartedParam.isPersistent = 1;
    groupStartedParam.frequency = 2412;
    groupStartedParam.goDeviceAddressLen = 17;

    int32_t result = OnEventGroupStarted(nullptr, &groupStartedParam, "wlan0");
    EXPECT_EQ(result, 0);
    result = OnEventGroupStarted(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventProvisionDiscoveryCompletedTest_01, TestSize.Level1)
{
    struct HdiP2pProvisionDiscoveryCompletedParam provisionDiscoveryCompletedParam;
    provisionDiscoveryCompletedParam.provDiscStatusCode = PD_STATUS_CODE_SHOW_PIN;
    provisionDiscoveryCompletedParam.p2pDeviceAddressLen = 17;

    int32_t result = OnEventProvisionDiscoveryCompleted(nullptr, &provisionDiscoveryCompletedParam, "wlan0");
    EXPECT_EQ(result, 0);
    result = OnEventProvisionDiscoveryCompleted(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventProvisionDiscoveryCompletedTest_02, TestSize.Level1)
{
    struct HdiP2pProvisionDiscoveryCompletedParam provisionDiscoveryCompletedParam;
    provisionDiscoveryCompletedParam.provDiscStatusCode = PD_STATUS_CODE_ENTER_PIN;
    provisionDiscoveryCompletedParam.p2pDeviceAddressLen = 17;

    int32_t result = OnEventProvisionDiscoveryCompleted(nullptr, &provisionDiscoveryCompletedParam, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventProvisionDiscoveryCompletedTest_03, TestSize.Level1)
{
    struct HdiP2pProvisionDiscoveryCompletedParam provisionDiscoveryCompletedParam;
    provisionDiscoveryCompletedParam.provDiscStatusCode = PD_STATUS_CODE_PBC_REQ;
    provisionDiscoveryCompletedParam.p2pDeviceAddressLen = 17;

    int32_t result = OnEventProvisionDiscoveryCompleted(nullptr, &provisionDiscoveryCompletedParam, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventProvisionDiscoveryCompletedTest_04, TestSize.Level1)
{
    struct HdiP2pProvisionDiscoveryCompletedParam provisionDiscoveryCompletedParam;
    provisionDiscoveryCompletedParam.provDiscStatusCode = PD_STATUS_CODE_PBC_RSP;
    provisionDiscoveryCompletedParam.p2pDeviceAddressLen = 17;

    int32_t result = OnEventProvisionDiscoveryCompleted(nullptr, &provisionDiscoveryCompletedParam, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventProvisionDiscoveryCompletedTest_05, TestSize.Level1)
{
    struct HdiP2pProvisionDiscoveryCompletedParam provisionDiscoveryCompletedParam;
    provisionDiscoveryCompletedParam.provDiscStatusCode = PD_STATUS_CODE_FAIL;

    int32_t result = OnEventProvisionDiscoveryCompleted(nullptr, &provisionDiscoveryCompletedParam, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventServDiscReq_01, TestSize.Level1)
{
    struct HdiP2pServDiscReqInfoParam servDiscReqInfoParam;
    servDiscReqInfoParam.freq = 2412;
    servDiscReqInfoParam.dialogToken = 1;
    servDiscReqInfoParam.updateIndic = 2;
    servDiscReqInfoParam.macLen = 6;
    servDiscReqInfoParam.mac = new uint8_t[servDiscReqInfoParam.macLen];
    memcpy_s(servDiscReqInfoParam.mac, servDiscReqInfoParam.macLen, "\x00\x11\x22\x33\x44\x55", 6);
    servDiscReqInfoParam.tlvsLen = 4;
    servDiscReqInfoParam.tlvs = new uint8_t[servDiscReqInfoParam.tlvsLen];
    memcpy_s(servDiscReqInfoParam.tlvs, servDiscReqInfoParam.tlvsLen, "x01x02x03x04", 4);

    int32_t result = OnEventServDiscReq(nullptr, &servDiscReqInfoParam, "wlan0");
    EXPECT_EQ(result, 0);
    result = OnEventServDiscReq(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);

    delete[] servDiscReqInfoParam.mac;
    delete[] servDiscReqInfoParam.tlvs;
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventStaConnectState_01, TestSize.Level1)
{
    struct HdiP2pStaConnectStateParam staConnectStateParam;
    staConnectStateParam.p2pDeviceAddressLen = 17;
    staConnectStateParam.state = 1;

    int32_t result = OnEventStaConnectState(nullptr, &staConnectStateParam, "wlan0");
    EXPECT_EQ(result, 0);
    result = OnEventStaConnectState(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventStaConnectState_02, TestSize.Level1)
{
    struct HdiP2pStaConnectStateParam staConnectStateParam;
    staConnectStateParam.p2pDeviceAddressLen = 17;
    staConnectStateParam.state = 0;

    int32_t result = OnEventStaConnectState(nullptr, &staConnectStateParam, "wlan0");
    EXPECT_EQ(result, 0);

    staConnectStateParam.state = 1;
    result = OnEventStaConnectState(nullptr, &staConnectStateParam, "wlan0");
    EXPECT_EQ(result, 0);

    result = OnEventStaConnectState(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventDisconnectedTest, TestSize.Level1)
{
    struct HdiWpaDisconnectParam disconectParam;
    disconectParam.bssidLen = 17;

    int32_t result = OnEventDisconnected(nullptr, &disconectParam, "wlan0");
    EXPECT_EQ(result, 1);
    result = OnEventDisconnected(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);

    disconectParam.bssid = nullptr;
    disconectParam.bssidLen = 0;
    result = OnEventDisconnected(nullptr, &disconectParam, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventStateChangedTest, TestSize.Level1)
{
    struct HdiWpaStateChangedParam statechangedParam;
    int32_t result = OnEventStateChanged(nullptr, &statechangedParam, "wlan0");
    EXPECT_EQ(result, 0);

    result = OnEventStateChanged(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventStaNotifyTest, TestSize.Level1)
{
    char *notifyParam;
    int32_t result = OnEventStaNotify(nullptr, notifyParam, "wlan0");
    EXPECT_EQ(result, 1);

    result = OnEventStaNotify(nullptr, notifyParam, "p2p");
    EXPECT_EQ(result, 1);

    result = OnEventStaNotify(nullptr, notifyParam, "Test");
    EXPECT_EQ(result, 1);

    result = OnEventStaNotify(nullptr, nullptr, "Test");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventWpsOverlapTest, TestSize.Level1)
{
    int32_t result = OnEventWpsOverlap(nullptr, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventWpsTimeoutTest, TestSize.Level1)
{
    int32_t result = OnEventWpsTimeout(nullptr, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventAuthTimeoutTest, TestSize.Level1)
{
    int32_t result = OnEventAuthTimeout(nullptr, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventScanResultTest, TestSize.Level1)
{
    struct HdiWpaRecvScanResultParam recvScanResultParam;
    int32_t result = OnEventScanResult(nullptr, &recvScanResultParam, "wlan0");
    EXPECT_EQ(result, 0);

    result = OnEventScanResult(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, onEventStaJoinTest, TestSize.Level1)
{
    struct HdiApCbParm apCbParm;
    int32_t result = onEventStaJoin(nullptr, &apCbParm, "wlan0");
    EXPECT_EQ(result, 1);

    result = onEventStaJoin(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);

    apCbParm.content = nullptr;
    result = onEventStaJoin(nullptr, &apCbParm, "wlan0");
    EXPECT_EQ(result, 1);

    const char *str = "AP-STA-CONNECTED";
    apCbParm.content = const_cast<char *>(str);
    result = onEventStaJoin(nullptr, &apCbParm, "wlan0");
    EXPECT_EQ(result, 0);

    const char *str2 = "AP-STA-DISCONNECTED";
    apCbParm.content = const_cast<char *>(str2);
    result = onEventStaJoin(nullptr, &apCbParm, "wlan0");
    EXPECT_EQ(result, 0);

    const char *str3 = "1234567890abcdf123456";
    apCbParm.content = const_cast<char *>(str3);
    result = onEventStaJoin(nullptr, &apCbParm, "wlan0");
    EXPECT_EQ(result, 1);

    const char *str4 = "Test";
    apCbParm.content = const_cast<char *>(str4);
    result = onEventStaJoin(nullptr, &apCbParm, "wlan0");
    EXPECT_EQ(result, 1);

    const char *str5 = "AP-STA-CONNECTED 11:22:**:**:**:330";
    apCbParm.content = const_cast<char *>(str5);
    result = onEventStaJoin(nullptr, &apCbParm, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, onEventApStateTest, TestSize.Level1)
{
    struct HdiApCbParm apCbParm;
    int32_t result = onEventApState(nullptr, &apCbParm, "wlan0");
    EXPECT_EQ(result, 1);

    result = onEventApState(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);

    apCbParm.content = nullptr;
    result = onEventApState(nullptr, &apCbParm, "wlan0");
    EXPECT_EQ(result, 1);

    const char *str = "AP-ENABLED";
    apCbParm.content = const_cast<char *>(str);
    result = onEventApState(nullptr, &apCbParm, "wlan0");
    EXPECT_EQ(result, 0);

    const char *str1 = "AP-DISABLED";
    apCbParm.content = const_cast<char *>(str1);
    result = onEventApState(nullptr, &apCbParm, "wlan0");
    EXPECT_EQ(result, 0);

    const char *str2 = "CTRL-EVENT-TERMINATING";
    apCbParm.content = const_cast<char *>(str2);
    result = onEventApState(nullptr, &apCbParm, "wlan0");
    EXPECT_EQ(result, 0);

    const char *str3 = "AP-STA-POSSIBLE-PSK-MISMATCH ";
    apCbParm.content = const_cast<char *>(str3);
    result = onEventApState(nullptr, &apCbParm, "wlan0");
    EXPECT_EQ(result, 0);

    const char *str4 = "Test";
    apCbParm.content = const_cast<char *>(str4);
    result = onEventApState(nullptr, &apCbParm, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventGoNegotiationRequestTest, TestSize.Level1)
{
    struct HdiP2pGoNegotiationRequestParam goNegotiationRequestParam;
    int32_t result = OnEventGoNegotiationRequest(nullptr, &goNegotiationRequestParam, "wlan0");
    EXPECT_EQ(result, 0);

    result = OnEventGoNegotiationRequest(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventGoNegotiationCompletedTest, TestSize.Level1)
{
    struct HdiP2pGoNegotiationCompletedParam goNegotiationCompletedParam;
    int32_t result = OnEventGoNegotiationCompleted(nullptr, &goNegotiationCompletedParam, "wlan0");
    EXPECT_EQ(result, 0);

    result = OnEventGoNegotiationCompleted(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventInvitationResultTest, TestSize.Level1)
{
    struct HdiP2pInvitationResultParam invitationResultParam;
    int32_t result = OnEventInvitationResult(nullptr, &invitationResultParam, "wlan0");
    EXPECT_EQ(result, 0);

    result = OnEventInvitationResult(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventGroupFormationSuccessTest, TestSize.Level1)
{
    int32_t result = OnEventGroupFormationSuccess(nullptr, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventGroupFormationFailureTest, TestSize.Level1)
{
    int32_t result = OnEventGroupFormationFailure(nullptr, "reason", "wlan0");
    EXPECT_EQ(result, 0);

    result = OnEventGroupFormationFailure(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventGroupInfoStartedTest, TestSize.Level1)
{
    struct HdiP2pGroupInfoStartedParam groupStartedParam;
    int32_t result = OnEventGroupInfoStarted(nullptr, &groupStartedParam, "wlan0");
    EXPECT_EQ(result, 0);

    result = OnEventGroupInfoStarted(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventGroupRemovedTest, TestSize.Level1)
{
    struct HdiP2pGroupRemovedParam groupRemovedParam;
    int32_t result = OnEventGroupRemoved(nullptr, &groupRemovedParam, "wlan0");
    EXPECT_EQ(result, 0);

    result = OnEventGroupRemoved(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventFindStoppedTest, TestSize.Level1)
{
    int32_t result = OnEventFindStopped(nullptr, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventServDiscRespTest, TestSize.Level1)
{
    struct HdiP2pServDiscRespParam servDiscRespParam;
    int32_t result = OnEventServDiscResp(nullptr, &servDiscRespParam, "wlan0");
    EXPECT_EQ(result, 0);

    result = OnEventServDiscResp(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);

    servDiscRespParam.tlvs = nullptr;
    result = OnEventServDiscResp(nullptr, &servDiscRespParam, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventIfaceCreatedTest, TestSize.Level1)
{
    struct HdiP2pIfaceCreatedParam ifaceCreatedParam;
    int32_t result = OnEventIfaceCreated(nullptr, &ifaceCreatedParam, "wlan0");
    EXPECT_EQ(result, 0);

    result = OnEventIfaceCreated(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventConnectedTest, TestSize.Level1)
{
    struct HdiWpaConnectParam connectParam;
    int32_t result = OnEventConnected(nullptr, &connectParam, "wlan0");
    EXPECT_EQ(result, 1);

    result = OnEventConnected(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);

    connectParam.bssidLen = 0;
    result = OnEventConnected(nullptr, &connectParam, "wlan0");
    EXPECT_EQ(result, 1);

    connectParam.bssidLen = 10;
    result = OnEventConnected(nullptr, &connectParam, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventDeviceLostTest, TestSize.Level1)
{
    struct HdiP2pDeviceLostParam deviceLostParam;
    int32_t result = OnEventDeviceLost(nullptr, &deviceLostParam, "wlan0");
    EXPECT_EQ(result, 0);

    result = OnEventDeviceLost(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventInvitationReceivedTest, TestSize.Level1)
{
    struct HdiP2pInvitationReceivedParam invitationReceivedParam;
    int32_t result = OnEventInvitationReceived(nullptr, &invitationReceivedParam, "wlan0");
    EXPECT_EQ(result, 0);

    result = OnEventInvitationReceived(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnNativeProcessDeathTest, TestSize.Level1)
{
    int status = 0;
    OnNativeProcessDeath(status);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}
} // namespace Wifi
} // namespace OHOS
