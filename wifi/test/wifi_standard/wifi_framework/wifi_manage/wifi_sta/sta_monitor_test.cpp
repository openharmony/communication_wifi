/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "sta_monitor.h"
#include <gtest/gtest.h>
#include <string>
#include "sta_state_machine.h"
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("StaMonitorTest");

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
static std::string g_errLog;
void StaMonitorCallback(const LogType type,const LogLevel level,const unsigned int domain ,const char *tag,const char *msg)
{
    g_errLog = msg;
}
class StaMonitorTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        LOG_SetCallback(StaMonitorCallback);
        pStaMonitor = std::make_unique<StaMonitor>();
        pStaMonitor->pStaStateMachine = new StaStateMachine();
        InitStaMonitorSuccess();
    }
    virtual void TearDown()
    {
        pStaMonitor.reset();
    }

public:
    std::unique_ptr<StaMonitor> pStaMonitor;

    void InitStaMonitorSuccess();
    void InitStaMonitorFail();
    void UnInitStaMonitorSuccess();
    void UnInitStaMonitorFail();
    void OnConnectChangedCallBackSuccess1();
    void OnConnectChangedCallBackSuccess2();
    void OnConnectChangedCallBackSuccess3();
    void OnConnectChangedCallBackFail1();
    void OnConnectChangedCallBackFail2();
    void OnConnectChangedCallBackFail3();
    void OnWpaStateChangedCallBackSuccess();
    void OnWpaStateChangedCallBackFail1();
    void OnWpaStateChangedCallBackFail2();
    void OnWpaSsidWrongKeyCallBackSuccess();
    void OnWpaSsidWrongKeyCallBackFail();
    void OnWpsPbcOverlapCallBackSuccess();
    void OnWpsPbcOverlapCallBackFail1();
    void OnWpsPbcOverlapCallBackFail2();
    void OnWpsTimeOutCallBackSuccess();
    void OnWpsTimeOutCallBackFail1();
    void OnWpsTimeOutCallBackFail2();
    void OnBssidChangedCallBackSuccess();
    void OnBssidChangedCallBackFail();
    void OnBssidChangedCallBackFail1();
    void OnBssidChangedCallBackFail2();
    void OnWpaConnectionFullCallBackSuccess();
    void OnWpaConnectionFullCallBackFail();
    void OnWpaConnectionRejectCallBackSuccess();
    void OnWpaConnectionRejectCallBackFail();
    void OnWpaHilinkCallBackSuccess();
    void OnWpaStaNotifyCallBackSuccess();
    void OnWpaStaNotifyCallBackFail();
    void OnWpaStaNotifyCallBackFail1();
    void OnWpaStaNotifyCallBackFail2();
    void OnWpaCustomEapNotifyCallBackSuccess();
    void OnWpaCustomEapNotifyCallBackFail1();
    void OnWpaCustomEapNotifyCallBackFail2();
};

void StaMonitorTest::InitStaMonitorSuccess()
{
    EXPECT_TRUE(pStaMonitor->InitStaMonitor() == WIFI_OPT_SUCCESS);
}

void StaMonitorTest::InitStaMonitorFail()
{
    EXPECT_FALSE(pStaMonitor->InitStaMonitor() == WIFI_OPT_FAILED);
}

void StaMonitorTest::UnInitStaMonitorSuccess()
{
    EXPECT_TRUE(pStaMonitor->UnInitStaMonitor() == WIFI_OPT_SUCCESS);
}

void StaMonitorTest::UnInitStaMonitorFail()
{
    pStaMonitor->SetStateMachine(pStaMonitor->pStaStateMachine);
    pStaMonitor->SetStateMachine(nullptr);
    EXPECT_FALSE(pStaMonitor->UnInitStaMonitor() == WIFI_OPT_FAILED);
}

void StaMonitorTest::OnConnectChangedCallBackSuccess1()
{
    int status = HAL_WPA_CB_CONNECTED;
    int networkId = 1;
    std::string bssid = "01:23:45:67:89:AB";
    int locallyGenerated = 0;
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = ConnState::DISCONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .Times(AtLeast(0))
        .WillOnce(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    pStaMonitor->OnConnectChangedCallBack(status, networkId, bssid, locallyGenerated);
}

void StaMonitorTest::OnConnectChangedCallBackSuccess2()
{
    int status = HAL_WPA_CB_DISCONNECTED;
    int networkId = 1;
    std::string bssid = "01:23:45:67:89:AB";
    int locallyGenerated = 0;
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = ConnState::DISCONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .Times(AtLeast(0))
        .WillOnce(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    pStaMonitor->OnConnectChangedCallBack(status, networkId, bssid, locallyGenerated);
}

void StaMonitorTest::OnConnectChangedCallBackSuccess3()
{
    int status = 0;
    int networkId = 1;
    std::string bssid = "01:23:45:67:89:AB";
    int locallyGenerated = 0;
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = ConnState::DISCONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .Times(AtLeast(0))
        .WillOnce(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    pStaMonitor->OnConnectChangedCallBack(status, networkId, bssid, locallyGenerated);
}

void StaMonitorTest::OnConnectChangedCallBackFail1()
{
    int status = HAL_WPA_CB_CONNECTED;
    int networkId = 0;
    std::string bssid = "00:00:00:00:00:00";
    int locallyGenerated = 0;
    pStaMonitor->pStaStateMachine = nullptr;
    pStaMonitor->OnConnectChangedCallBack(status, networkId, bssid, locallyGenerated);
}

void StaMonitorTest::OnConnectChangedCallBackFail2()
{
    int status = HAL_WPA_CB_CONNECTED;
    int networkId = 0;
    std::string bssid = "00:00:00:00:00:00";
    int locallyGenerated = 0;
    pStaMonitor->OnConnectChangedCallBack(status, networkId, bssid, locallyGenerated);
}

void StaMonitorTest::OnConnectChangedCallBackFail3()
{
    int status = -1;
    int networkId = 0;
    std::string bssid = "00:00:00:00:00:00";
    int locallyGenerated = 0;
    pStaMonitor->OnConnectChangedCallBack(status, networkId, bssid, locallyGenerated);
}

void StaMonitorTest::OnWpaStateChangedCallBackSuccess()
{
    int status = 1;
    pStaMonitor->OnWpaStateChangedCallBack(status, "test");
}

void StaMonitorTest::OnWpaStateChangedCallBackFail1()
{
    int status = 1;
    pStaMonitor->pStaStateMachine = nullptr;
    pStaMonitor->OnWpaStateChangedCallBack(status, "test");
}

void StaMonitorTest::OnWpaSsidWrongKeyCallBackSuccess()
{
    pStaMonitor->OnWpaSsidWrongKeyCallBack("");
}

void StaMonitorTest::OnWpaSsidWrongKeyCallBackFail()
{
    pStaMonitor->pStaStateMachine = nullptr;
    pStaMonitor->OnWpaSsidWrongKeyCallBack("");
}

void StaMonitorTest::OnWpsPbcOverlapCallBackSuccess()
{
    int status = 1;
    pStaMonitor->OnWpsPbcOverlapCallBack(status);
}

void StaMonitorTest::OnWpsPbcOverlapCallBackFail1()
{
    int status = 1;
    pStaMonitor->pStaStateMachine = nullptr;
    pStaMonitor->OnWpsPbcOverlapCallBack(status);
}

void StaMonitorTest::OnWpsTimeOutCallBackSuccess()
{
    int status = 1;
    pStaMonitor->OnWpsTimeOutCallBack(status);
}

void StaMonitorTest::OnWpsTimeOutCallBackFail1()
{
    int status = 1;
    pStaMonitor->pStaStateMachine = nullptr;
    pStaMonitor->OnWpsTimeOutCallBack(status);
}

void StaMonitorTest::OnBssidChangedCallBackSuccess()
{
    std::string reason = "null";
    std::string bssid = "01:23:45:67:89:AB";
    pStaMonitor->OnBssidChangedCallBack(reason, bssid);
}

void StaMonitorTest::OnBssidChangedCallBackFail()
{
    std::string reason = "null";
    std::string bssid = "01:23:45:67:89:AB";
    pStaMonitor->pStaStateMachine = nullptr;
    pStaMonitor->OnBssidChangedCallBack(reason, bssid);
}

void StaMonitorTest::OnBssidChangedCallBackFail1()
{
    std::string reason = "null";
    std::string bssid = "01:23:45:67:89:AB";
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = ConnState::DISCONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .Times(AtLeast(0))
        .WillOnce(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    pStaMonitor->OnBssidChangedCallBack(reason, bssid);
}

void StaMonitorTest::OnBssidChangedCallBackFail2()
{
    std::string reason = "null";
    std::string bssid = "01:23:45:67:89:AB";
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = ConnState::CONNECTED;
    linkedInfo.bssid = "01:23:45:67:89:AB";
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .Times(AtLeast(0))
        .WillOnce(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    pStaMonitor->OnBssidChangedCallBack(reason, bssid);
}

void StaMonitorTest::OnWpaConnectionFullCallBackSuccess()
{
    int status = 1;
    pStaMonitor->OnWpaConnectionFullCallBack(status);
}

void StaMonitorTest::OnWpaConnectionFullCallBackFail()
{
    int status = 1;
    pStaMonitor->pStaStateMachine = nullptr;
    pStaMonitor->OnWpaConnectionFullCallBack(status);
}

void StaMonitorTest::OnWpaConnectionRejectCallBackSuccess()
{
    AssocRejectInfo assocRejectInfo;
    assocRejectInfo.statusCode = 1;
    pStaMonitor->OnWpaConnectionRejectCallBack(assocRejectInfo);
}

void StaMonitorTest::OnWpaConnectionRejectCallBackFail()
{
    AssocRejectInfo assocRejectInfo;
    assocRejectInfo.statusCode = 1;
    pStaMonitor->pStaStateMachine = nullptr;
    pStaMonitor->OnWpaConnectionRejectCallBack(assocRejectInfo);
}

void StaMonitorTest::OnWpaHilinkCallBackSuccess()
{
    std::string bssid = "01:23:45:67:89:AB";
    pStaMonitor->OnWpaHilinkCallBack(bssid);
}

void StaMonitorTest::OnWpaStaNotifyCallBackSuccess()
{
    std::string notifyParam = "01:23:45:67:89:AB";
    pStaMonitor->OnWpaStaNotifyCallBack(notifyParam);
}

void StaMonitorTest::OnWpaStaNotifyCallBackFail()
{
    std::string notifyParam;
    pStaMonitor->OnWpaStaNotifyCallBack(notifyParam);
}

void StaMonitorTest::OnWpaStaNotifyCallBackFail1()
{
    std::string notifyParam = "01";
    pStaMonitor->OnWpaStaNotifyCallBack(notifyParam);
}

void StaMonitorTest::OnWpaStaNotifyCallBackFail2()
{
    std::string notifyParam = "01:";
    pStaMonitor->OnWpaStaNotifyCallBack(notifyParam);
}

void StaMonitorTest::OnWpaCustomEapNotifyCallBackSuccess()
{
    std::string notifyParam = "06:55:1:13:10:AlwAxA0AFgMBALkBAAC1AwOfjdAqQ/Z==";
    pStaMonitor->OnWpaStaNotifyCallBack(notifyParam);
}

void StaMonitorTest::OnWpaCustomEapNotifyCallBackFail1()
{
    std::string notifyParam = "06:55:1:13:10";
    pStaMonitor->OnWpaStaNotifyCallBack(notifyParam);
}

void StaMonitorTest::OnWpaCustomEapNotifyCallBackFail2()
{
    std::string notifyParam = "06:55:1:13:A:AlwAxA0AFgMBALkBAAC1AwOfjdAqQ/Z==";
    pStaMonitor->OnWpaStaNotifyCallBack(notifyParam);
}

HWTEST_F(StaMonitorTest, InitStaMonitorSuccess, TestSize.Level1)
{
    InitStaMonitorSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, InitStaMonitorFail, TestSize.Level1)
{
    InitStaMonitorFail();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, UnInitStaMonitorSuccess, TestSize.Level1)
{
    UnInitStaMonitorSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, UnInitStaMonitorFail, TestSize.Level1)
{
    UnInitStaMonitorFail();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnConnectChangedCallBackFail1, TestSize.Level1)
{
    OnConnectChangedCallBackFail1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnConnectChangedCallBackFail2, TestSize.Level1)
{
    OnConnectChangedCallBackFail2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnConnectChangedCallBackSuccess1, TestSize.Level1)
{
    OnConnectChangedCallBackSuccess1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnConnectChangedCallBackSuccess2, TestSize.Level1)
{
    OnConnectChangedCallBackSuccess2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnConnectChangedCallBackSuccess3, TestSize.Level1)
{
    OnConnectChangedCallBackSuccess3();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaStateChangedCallBackSuccess, TestSize.Level1)
{
    OnWpaStateChangedCallBackSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaStateChangedCallBackFail1, TestSize.Level1)
{
    OnWpaStateChangedCallBackFail1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaSsidWrongKeyCallBackSuccess, TestSize.Level1)
{
    OnWpaSsidWrongKeyCallBackSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaSsidWrongKeyCallBackFail, TestSize.Level1)
{
    OnWpaSsidWrongKeyCallBackFail();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpsPbcOverlapCallBackSuccess, TestSize.Level1)
{
    OnWpsPbcOverlapCallBackSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpsPbcOverlapCallBackFail1, TestSize.Level1)
{
    OnWpsPbcOverlapCallBackFail1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpsTimeOutCallBackSuccess, TestSize.Level1)
{
    OnWpsTimeOutCallBackSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpsTimeOutCallBackFail1, TestSize.Level1)
{
    OnWpsTimeOutCallBackFail1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnBssidChangedCallBackSuccess, TestSize.Level1)
{
    OnBssidChangedCallBackSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnBssidChangedCallBackFail, TestSize.Level1)
{
    OnBssidChangedCallBackFail();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnBssidChangedCallBackFail1, TestSize.Level1)
{
    OnBssidChangedCallBackFail1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnBssidChangedCallBackFail2, TestSize.Level1)
{
    OnBssidChangedCallBackFail2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaConnectionFullCallBackSuccess, TestSize.Level1)
{
    OnWpaConnectionFullCallBackSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaConnectionFullCallBackFail, TestSize.Level1)
{
    OnWpaConnectionFullCallBackFail();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaConnectionRejectCallBackSuccess, TestSize.Level1)
{
    OnWpaConnectionRejectCallBackSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaConnectionRejectCallBackFail, TestSize.Level1)
{
    OnWpaConnectionRejectCallBackFail();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaHilinkCallBackSuccess, TestSize.Level1)
{
    OnWpaHilinkCallBackSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaStaNotifyCallBackSuccess, TestSize.Level1)
{
    OnWpaStaNotifyCallBackSuccess();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaStaNotifyCallBackFail, TestSize.Level1)
{
    OnWpaStaNotifyCallBackFail();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaStaNotifyCallBackFail1, TestSize.Level1)
{
    OnWpaStaNotifyCallBackFail1();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaStaNotifyCallBackFail2, TestSize.Level1)
{
    OnWpaStaNotifyCallBackFail2();
    EXPECT_FALSE(g_errLog.find("callback")!=std::string::npos);
}

#ifdef EXTENSIBLE_AUTHENTICATION
HWTEST_F(StaMonitorTest, OnWpaCustomEapNotifyCallBackFail1, TestSize.Level1)
{
    WIFI_LOGI("OnWpaCustomEapNotifyCallBackFail1 enter!");
    OnWpaCustomEapNotifyCallBackFail1();
    EXPECT_FALSE(g_errLog.find("callback") != std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaCustomEapNotifyCallBackFail2, TestSize.Level1)
{
    WIFI_LOGI("OnWpaCustomEapNotifyCallBackFail2 enter!");
    OnWpaCustomEapNotifyCallBackFail2();
    EXPECT_FALSE(g_errLog.find("callback") != std::string::npos);
}

HWTEST_F(StaMonitorTest, OnWpaCustomEapNotifyCallBackSuccess, TestSize.Level1)
{
    WIFI_LOGI("OnWpaCustomEapNotifyCallBackSuccess enter!");
    OnWpaCustomEapNotifyCallBackSuccess();
    EXPECT_FALSE(g_errLog.find("callback") == std::string::npos);
}
#endif

} // WIFI
} // OHOS