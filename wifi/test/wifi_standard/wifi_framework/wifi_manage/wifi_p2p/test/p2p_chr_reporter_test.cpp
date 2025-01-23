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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "p2p_chr_reporter.h"

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class P2pChrReporterTest : public testing::Test {
public:
    static void SetUpTestCase() {}

    static void TearDownTestCase() {}

    virtual void SetUp()
    {
        P2pChrReporter::GetInstance().ResetState();
    }

    virtual void TearDown()
    {
        P2pChrReporter::GetInstance().ResetState();
    }

    void UpdateErrorMessage(int state, int errCode, int minorCode)
    {
        P2pChrReporter::GetInstance().UpdateErrorMessage(state, errCode, minorCode);
    }

    void ReportP2pConnectFailed(int state, int errCode, int minorCode)
    {
        P2pChrReporter::GetInstance().ReportP2pConnectFailed(state, errCode, minorCode);
    }

    void ReportP2pAbnormalDisconnect(int state, int errCode, int minorCode)
    {
        P2pChrReporter::GetInstance().ReportP2pAbnormalDisconnect(state, errCode, minorCode);
    }

    uint16_t GetP2pSpecificError(int state, int errCode)
    {
        return P2pChrReporter::GetInstance().GetP2pSpecificError(state, errCode);
    }

    bool IsNormalErrCode(int errCode)
    {
        return P2pChrReporter::GetInstance().IsNormalErrCode(errCode);
    }

    void OnP2pChrErrCodeReport(int errCode)
    {
        P2pChrReporter::GetInstance().OnP2pChrErrCodeReport(errCode);
    }

    int GetWpsSuccess()
    {
        return P2pChrReporter::GetInstance().wpsSuccess_;
    }

    int GetDeviceRole()
    {
        return P2pChrReporter::GetInstance().role_;
    }
};

HWTEST_F(P2pChrReporterTest, ReportErrCodeBeforeGroupFormationSucc, TestSize.Level1)
{
    int state = P2P_INVITATION;
    int errCode = P2pChrReporter::P2P_STATUS_SUCCESS;
    int minorCode = P2P_CHR_DEFAULT_REASON_CODE;
    P2pChrReporter::GetInstance().ReportErrCodeBeforeGroupFormationSucc(state, errCode, minorCode);
    EXPECT_EQ(GetWpsSuccess(), true);
    errCode = P2P_CHR_DEFAULT_REASON_CODE;
    P2pChrReporter::GetInstance().ReportErrCodeBeforeGroupFormationSucc(state, errCode, minorCode);
    state = GROUP_OWNER_NEGOTIATION;
    P2pChrReporter::GetInstance().ReportErrCodeBeforeGroupFormationSucc(state, errCode, minorCode);
}

HWTEST_F(P2pChrReporterTest, SetWpsSuccess, TestSize.Level1)
{
    P2pChrReporter::GetInstance().SetWpsSuccess(true);
    EXPECT_EQ(GetWpsSuccess(), true);
}

HWTEST_F(P2pChrReporterTest, SetDeviceRole, TestSize.Level1)
{
    P2pChrReporter::GetInstance().SetDeviceRole(GROUP_OWNER);
    EXPECT_EQ(GetDeviceRole(), GROUP_OWNER);
}

HWTEST_F(P2pChrReporterTest, ProcessChrEvent, TestSize.Level1)
{
    std::string notifyParam = "1_0_0_0";
    P2pChrReporter::GetInstance().ProcessChrEvent(notifyParam);
    notifyParam = "2_0_0_0";
    P2pChrReporter::GetInstance().ProcessChrEvent(notifyParam);
    EXPECT_TRUE(IsNormalErrCode(P2P_CHR_DEFAULT_REASON_CODE));
}

HWTEST_F(P2pChrReporterTest, ReportP2pInterfaceStateChange, TestSize.Level1)
{
    int state = P2P_INVITATION;
    int errCode = P2pChrReporter::P2P_STATUS_SUCCESS;
    int minorCode = P2P_CHR_DEFAULT_REASON_CODE;
    P2pChrReporter::GetInstance().SetWpsSuccess(true);
    EXPECT_EQ(GetWpsSuccess(), true);
    P2pChrReporter::GetInstance().ReportP2pInterfaceStateChange(state, errCode, minorCode);
    errCode = P2pChrReporter::DR_TO_SWITCH_MGMT;
    P2pChrReporter::GetInstance().ReportP2pInterfaceStateChange(state, errCode, minorCode);
    errCode = P2P_CHR_DEFAULT_REASON_CODE;
    P2pChrReporter::GetInstance().ReportP2pInterfaceStateChange(state, errCode, minorCode);
}

HWTEST_F(P2pChrReporterTest, UploadP2pChrErrEvent, TestSize.Level1)
{
    P2pChrReporter::GetInstance().SetWpsSuccess(false);
    EXPECT_EQ(GetWpsSuccess(), false);
    P2pChrReporter::GetInstance().UploadP2pChrErrEvent();
    P2pChrReporter::GetInstance().SetWpsSuccess(true);
    EXPECT_EQ(GetWpsSuccess(), true);
    P2pChrReporter::GetInstance().UploadP2pChrErrEvent();
}

HWTEST_F(P2pChrReporterTest, UpdateErrorMessage, TestSize.Level1)
{
    int state = P2P_INVITATION;
    int errCode = P2pChrReporter::P2P_STATUS_SUCCESS;
    int minorCode = P2P_CHR_DEFAULT_REASON_CODE;
    UpdateErrorMessage(state, errCode, minorCode);
    state = P2P_INTERFACE_STATE_DISCONNECTED;
    UpdateErrorMessage(state, errCode, minorCode);
    errCode = P2P_CHR_DEFAULT_REASON_CODE;
    UpdateErrorMessage(state, errCode, minorCode);
    EXPECT_TRUE(IsNormalErrCode(errCode));
}

HWTEST_F(P2pChrReporterTest, ReportP2pConnectFailed, TestSize.Level1)
{
    int state = P2P_INVITATION;
    int errCode = P2pChrReporter::P2P_STATUS_SUCCESS;
    int minorCode = P2P_CHR_DEFAULT_REASON_CODE;
    ReportP2pConnectFailed(state, errCode, minorCode);
    EXPECT_TRUE(IsNormalErrCode(errCode));
}

HWTEST_F(P2pChrReporterTest, ReportP2pAbnormalDisconnect, TestSize.Level1)
{
    int state = P2P_INVITATION;
    int errCode = P2pChrReporter::P2P_STATUS_SUCCESS;
    int minorCode = P2P_CHR_DEFAULT_REASON_CODE;
    ReportP2pAbnormalDisconnect(state, errCode, minorCode);
    EXPECT_TRUE(IsNormalErrCode(errCode));
}

HWTEST_F(P2pChrReporterTest, GetP2pSpecificError, TestSize.Level1)
{
    P2pChrReporter::GetInstance().SetDeviceRole(UNKNOWN_ROLE);
    EXPECT_EQ(GetP2pSpecificError(DEVICE_DISCOVERY, P2pChrReporter::P2P_STATUS_SUCCESS), 0);
}

HWTEST_F(P2pChrReporterTest, IsNormalErrCode, TestSize.Level1)
{
    EXPECT_TRUE(IsNormalErrCode(P2P_CHR_DEFAULT_REASON_CODE));
    EXPECT_FALSE(IsNormalErrCode(P2pChrReporter::DR_TO_SWITCH_MGMT));
}

HWTEST_F(P2pChrReporterTest, OnP2pChrErrCodeReport, TestSize.Level1)
{
    int errCode = P2pChrReporter::P2P_STATUS_SUCCESS;
    OnP2pChrErrCodeReport(errCode);
    EXPECT_TRUE(IsNormalErrCode(errCode));
}
}  // namespace Wifi
}  // namespace OHOS