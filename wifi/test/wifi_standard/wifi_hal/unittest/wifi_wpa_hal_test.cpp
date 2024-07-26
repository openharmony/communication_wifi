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
#include "wifi_wpa_hal_test.h"
#include "wifi_log.h"

using namespace testing::ext;

extern WifiWpaInterface *g_wpaInterface;

namespace OHOS {
namespace Wifi {

class WifiWpaHalTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        g_wpaInterface = &wpaInterface;
    }
    virtual void TearDown()
    {}
    WifiWpaInterface wpaInterface;
};

HWTEST_F(WifiWpaHalTest, GetWifiWapGlobalInterfaceTest, TestSize.Level1)
{
    g_wpaInterface = GetWifiWapGlobalInterface();
    EXPECT_TRUE(g_wpaInterface != NULL);
}

HWTEST_F(WifiWpaHalTest, DealP2pFindInfoTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    DealP2pFindInfo(buf);
}

HWTEST_F(WifiWpaHalTest, DealP2pGoNegRequestTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    DealP2pGoNegRequest(buf);
}

HWTEST_F(WifiWpaHalTest, DealGroupStartInfoTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    DealGroupStartInfo(buf);
}

HWTEST_F(WifiWpaHalTest, DealServiceDiscRespEventTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    DealServiceDiscRespEvent(buf);
}

HWTEST_F(WifiWpaHalTest, DealP2pGroupRemoveTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    DealP2pGroupRemove(buf);
}

HWTEST_F(WifiWpaHalTest, DealP2pConnectChangedTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    int type = 0;
    DealP2pConnectChanged(buf, type);
}

HWTEST_F(WifiWpaHalTest, DealDeviceLostEventTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    DealDeviceLostEvent(buf);
}

HWTEST_F(WifiWpaHalTest, DealInvitationReceivedTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    int type = 0;
    DealInvitationReceived(buf, type);
}

HWTEST_F(WifiWpaHalTest, DealInvitationResultEventTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    DealInvitationResultEvent(buf);
}

HWTEST_F(WifiWpaHalTest, DealP2pGoNegotiationFailureTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    DealP2pGoNegotiationFailure(buf);
}

HWTEST_F(WifiWpaHalTest, DealP2pConnectFailedTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    DealP2pConnectFailed(buf);
}

HWTEST_F(WifiWpaHalTest, DealP2pChannelSwitchTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    DealP2pChannelSwitch(buf);
}

HWTEST_F(WifiWpaHalTest, DealGroupFormationFailureEventTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    DealGroupFormationFailureEvent(buf);
}

HWTEST_F(WifiWpaHalTest, DealProvDiscPbcReqEventTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    unsigned long length = 150;
    DealProvDiscPbcReqEvent(buf, length);
}

HWTEST_F(WifiWpaHalTest, DealProDiscPbcRespEventTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    unsigned long length = 150;
    DealProDiscPbcRespEvent(buf, length);
}

HWTEST_F(WifiWpaHalTest, DealProDiscEnterPinEventTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    unsigned long length = 150;
    DealProDiscEnterPinEvent(buf, length);
}

HWTEST_F(WifiWpaHalTest, DealProvDiscShowPinEventTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12:23:34:45:56:67";
    unsigned long length = 150;
    DealProvDiscShowPinEvent(buf, length);
}

HWTEST_F(WifiWpaHalTest, DealP2pServDiscReqEventTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "12" "34" "56";
    DealP2pServDiscReqEvent(buf);
}

HWTEST_F(WifiWpaHalTest, DealP2pInterfaceCreatedTest, TestSize.Level1)
{
    const int bufLen = 5;
    char buf[bufLen] = "GO";
    DealP2pInterfaceCreated(buf);
}

HWTEST_F(WifiWpaHalTest, DealP2pInterfaceCreatedTest_01, TestSize.Level1)
{
    const int bufLen = 5;
    char buf[bufLen] = "GC";
    DealP2pInterfaceCreated(buf);
}

HWTEST_F(WifiWpaHalTest, DealWpaP2pCallBackSubFunTest, TestSize.Level1)
{
    const int bufLen = 5;
    char buf[bufLen] = "GO";
    DealWpaP2pCallBackSubFun(buf);
}

HWTEST_F(WifiWpaHalTest, DealWpaP2pCallBackSubFunTest_01, TestSize.Level1)
{
    const int bufLen = 10;
    char buf[bufLen] = "string";
    DealWpaP2pCallBackSubFun(buf);
}

HWTEST_F(WifiWpaHalTest, WpaP2pCallBackFuncTest, TestSize.Level1)
{
    const int bufLen = 10;
    char buf[bufLen] = "GO";
    WpaP2pCallBackFunc(buf);
}

HWTEST_F(WifiWpaHalTest, ParseAuthRejectTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "status_code= 1488";
    ParseAuthReject(buf);
}

HWTEST_F(WifiWpaHalTest, ParseAssocRejectTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "status_code= %";
    ParseAssocReject(buf);
}

HWTEST_F(WifiWpaHalTest, WpaCallBackFuncTwoTest, TestSize.Level1)
{
    const int bufLen = 18;
    char buf[bufLen] = "status_code= 1488";
    WpaCallBackFuncTwo(buf);
}

HWTEST_F(WifiWpaHalTest, WpaCallBackFuncTest, TestSize.Level1)
{
    const int bufLen = 32;
    char buf[bufLen] = "CTRL-EVENT-CONNECTED ";
    WpaCallBackFunc(buf);
}

HWTEST_F(WifiWpaHalTest, WpaCallBackFuncTest_01, TestSize.Level1)
{
    const int bufLen = 32;
    char buf[bufLen] = "CTRL-EVENT-DISCONNECTED ";
    WpaCallBackFunc(buf);
}

HWTEST_F(WifiWpaHalTest, MyWpaCtrlPendingTest, TestSize.Level1)
{
    wpa_ctrl ctrl;
    ctrl.s = 17;
    int result = MyWpaCtrlPending(&ctrl);
    EXPECT_TRUE(result == 0 | result == 1);
}

HWTEST_F(WifiWpaHalTest, StopWpaSoftApTest, TestSize.Level1)
{
    ModuleInfo p;
    p.referenceCount = 2;
    StopWpaSoftAp(&p);
}

HWTEST_F(WifiWpaHalTest, RecoverWifiProcessTest, TestSize.Level1)
{
    void *arg = NULL;
    RecoverWifiProcess(arg);
}

HWTEST_F(WifiWpaHalTest, RecoverWifiThreadTest, TestSize.Level1)
{
    RecoverWifiThread();
}

HWTEST_F(WifiWpaHalTest, WpaReceiveCallbackTest, TestSize.Level1)
{
    void *arg = NULL;
    WpaReceiveCallback(arg);
}

HWTEST_F(WifiWpaHalTest, WpaCliWpaTerminateTest, TestSize.Level1)
{
    int result = WpaCliWpaTerminate();
    EXPECT_TRUE(result == -1);
}

}
}