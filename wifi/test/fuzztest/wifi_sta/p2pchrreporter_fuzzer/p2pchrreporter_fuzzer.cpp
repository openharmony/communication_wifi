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

#include "p2pchrreporter_fuzzer.h"
#include "wifi_fuzz_common_func.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include "p2p_chr_reporter.h"
#include "wifi_p2p_msg.h"
#include "wifi_internal_msg.h"
#include "p2p_define.h"

namespace OHOS {
namespace Wifi {
constexpr int U32_AT_SIZE_ZERO = 4;
constexpr int THREE = 3;
constexpr int EIGHTEEN = 18;
constexpr int NUM_BYTES = 1;

FuzzedDataProvider *FDP = nullptr;

void P2pChrReporterProcessChrEventTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    std::string notifyParam = FDP->ConsumeBytesAsString(NUM_BYTES);
    reporter.ProcessChrEvent(notifyParam);
    std::string validParam = std::to_string(FDP->ConsumeIntegral<int>() % THREE + 1) + "_" +
        std::to_string(FDP->ConsumeIntegral<int>() % EIGHTEEN) + "_" +
        std::to_string(FDP->ConsumeIntegral<int>()) + "_" +
        std::to_string(FDP->ConsumeIntegral<int>());
    reporter.ProcessChrEvent(validParam);
}

void P2pChrReporterReportErrCodeBeforeGroupFormationSuccTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    int state = FDP->ConsumeIntegral<int>() % EIGHTEEN;
    int errCode = FDP->ConsumeIntegral<int>();
    int minorCode = FDP->ConsumeIntegral<int>();
    reporter.ReportErrCodeBeforeGroupFormationSucc(state, errCode, minorCode);
}

void P2pChrReporterReportP2pInterfaceStateChangeTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    int state = FDP->ConsumeIntegral<int>() % EIGHTEEN;
    int errCode = FDP->ConsumeIntegral<int>();
    int minorCode = FDP->ConsumeIntegral<int>();
    reporter.ReportP2pInterfaceStateChange(state, errCode, minorCode);
}

void P2pChrReporterUpdateErrorMessageTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    int state = FDP->ConsumeIntegral<int>() % EIGHTEEN;
    int errCode = FDP->ConsumeIntegral<int>();
    int minorCode = FDP->ConsumeIntegral<int>();
    reporter.UpdateErrorMessage(state, errCode, minorCode);
}

void P2pChrReporterUploadP2pChrErrEventTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    reporter.UploadP2pChrErrEvent();
}

void P2pChrReporterResetStateTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    reporter.ResetState();
}

void P2pChrReporterReportP2pConnectFailedTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    int state = FDP->ConsumeIntegral<int>() % EIGHTEEN;
    int errCode = FDP->ConsumeIntegral<int>();
    int minorCode = FDP->ConsumeIntegral<int>();
    reporter.ReportP2pConnectFailed(state, errCode, minorCode);
}

void P2pChrReporterReportP2pAbnormalDisconnectTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    int state = FDP->ConsumeIntegral<int>() % EIGHTEEN;
    int errCode = FDP->ConsumeIntegral<int>();
    int minorCode = FDP->ConsumeIntegral<int>();
    reporter.ReportP2pAbnormalDisconnect(state, errCode, minorCode);
}

void P2pChrReporterGetP2pSpecificErrorTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    int state = FDP->ConsumeIntegral<int>();
    int errCode = FDP->ConsumeIntegral<int>();
    reporter.GetP2pSpecificError(state, errCode);
}

void P2pChrReporterSetWpsSuccessTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    bool success = FDP->ConsumeBool();
    reporter.SetWpsSuccess(success);
}

void P2pChrReporterSetDeviceRoleTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    int roleInt = FDP->ConsumeIntegral<int>() % THREE;
    DeviceRole role = static_cast<DeviceRole>(roleInt);
    reporter.SetDeviceRole(role);
}

void P2pChrReporterIsNormalErrCodeTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    int errCode = FDP->ConsumeIntegral<int>();
    reporter.IsNormalErrCode(errCode);
}

void P2pChrReporterOnP2pChrErrCodeReportTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    int errCode = FDP->ConsumeIntegral<int>();
    reporter.OnP2pChrErrCodeReport(errCode);
}

void P2pChrReporterHandleP2pHid2dConnTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    reporter.HandleP2pHid2dConn();
}

void P2pChrReporterHandleP2pNormalConnTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    reporter.HandleP2pNormalConn();
}

void P2pChrReporterUpdateConnectedInfoTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    WifiP2pGroupInfo group;
    int frequency = FDP->ConsumeIntegral<int>();
    group.SetFrequency(frequency);
    reporter.UpdateConnectedInfo(group);
}

void P2pChrReporterCombinedTest()
{
    P2pChrReporter &reporter = P2pChrReporter::GetInstance();
    reporter.ResetState();
    bool success = FDP->ConsumeBool();
    reporter.SetWpsSuccess(success);
    int roleInt = FDP->ConsumeIntegral<int>() % THREE;
    DeviceRole role = static_cast<DeviceRole>(roleInt);
    reporter.SetDeviceRole(role);
    int state = FDP->ConsumeIntegral<int>() % EIGHTEEN;
    int errCode = FDP->ConsumeIntegral<int>();
    int minorCode = FDP->ConsumeIntegral<int>();
    reporter.ReportErrCodeBeforeGroupFormationSucc(state, errCode, minorCode);
    reporter.ReportP2pInterfaceStateChange(state, errCode, minorCode);
    reporter.UpdateErrorMessage(state, errCode, minorCode);
    reporter.UploadP2pChrErrEvent();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::Wifi::FDP = &fdp;
    OHOS::Wifi::P2pChrReporterProcessChrEventTest();
    OHOS::Wifi::P2pChrReporterReportErrCodeBeforeGroupFormationSuccTest();
    OHOS::Wifi::P2pChrReporterReportP2pInterfaceStateChangeTest();
    OHOS::Wifi::P2pChrReporterUpdateErrorMessageTest();
    OHOS::Wifi::P2pChrReporterUploadP2pChrErrEventTest();
    OHOS::Wifi::P2pChrReporterResetStateTest();
    OHOS::Wifi::P2pChrReporterReportP2pConnectFailedTest();
    OHOS::Wifi::P2pChrReporterReportP2pAbnormalDisconnectTest();
    OHOS::Wifi::P2pChrReporterGetP2pSpecificErrorTest();
    OHOS::Wifi::P2pChrReporterSetWpsSuccessTest();
    OHOS::Wifi::P2pChrReporterSetDeviceRoleTest();
    OHOS::Wifi::P2pChrReporterIsNormalErrCodeTest();
    OHOS::Wifi::P2pChrReporterOnP2pChrErrCodeReportTest();
    OHOS::Wifi::P2pChrReporterHandleP2pHid2dConnTest();
    OHOS::Wifi::P2pChrReporterHandleP2pNormalConnTest();
    OHOS::Wifi::P2pChrReporterUpdateConnectedInfoTest();
    OHOS::Wifi::P2pChrReporterCombinedTest();
    return 0;
}
}
}
