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

#include "scan_state_machine.h"
#include "wifi_error_no.h"
#include "wifi_logger.h"
#include "wifi_channel_helper.h"
#include "wifi_config_center.h"
#include "wifi_sta_hal_interface.h"
#include "wifi_common_util.h"
#include "wifi_common_event_helper.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_SCAN_LABEL("ScanStateMachine");
std::shared_mutex ScanStateMachine::lock;

constexpr int SCAN_INFO_VALIDITY = 1 * 1000 * 1000;
constexpr int MILLISECOND_TO_MICROSECOND = 1000;

ScanStateMachine::ScanStateMachine(int instId)
    : StateMachine("ScanStateMachine"),
      quitFlag(false),
      initState(nullptr),
      hardwareReadyState(nullptr),
      commonScanState(nullptr),
      commonScanUnworkedState(nullptr),
      commonScanningState(nullptr),
      pnoScanState(nullptr),
      pnoScanHardwareState(nullptr),
      commonScanAfterPnoState(nullptr),
      pnoScanSoftwareState(nullptr),
      pnoSwScanFreeState(nullptr),
      pnoSwScanningState(nullptr),
      runningFullScanFlag(false),
      supportHwPnoFlag(true),
      pnoConfigStoredFlag(false),
      runningHwPnoFlag(false),
      remainWaitResultTimer(false),
      runningSwPnoFlag(false),
      lastScanStartTime(0),
      m_instId(instId)
{}

ScanStateMachine::~ScanStateMachine()
{
    WIFI_LOGI("Enter ~ScanStateMachine.\n");

    /* Stop the thread. Otherwise, a problem occurs */
    StopHandlerThread();

    if (initState != nullptr) {
        delete initState;
        initState = nullptr;
    }

    if (hardwareReadyState != nullptr) {
        delete hardwareReadyState;
        hardwareReadyState = nullptr;
    }

    if (commonScanState != nullptr) {
        delete commonScanState;
        commonScanState = nullptr;
    }

    if (commonScanUnworkedState != nullptr) {
        delete commonScanUnworkedState;
        commonScanUnworkedState = nullptr;
    }

    if (commonScanningState != nullptr) {
        delete commonScanningState;
        commonScanningState = nullptr;
    }

    if (pnoScanState != nullptr) {
        delete pnoScanState;
        pnoScanState = nullptr;
    }

    if (pnoScanHardwareState != nullptr) {
        delete pnoScanHardwareState;
        pnoScanHardwareState = nullptr;
    }
    StopPnoScanHardware();

    if (commonScanAfterPnoState != nullptr) {
        delete commonScanAfterPnoState;
        commonScanAfterPnoState = nullptr;
    }

    if (pnoScanSoftwareState != nullptr) {
        delete pnoScanSoftwareState;
        pnoScanSoftwareState = nullptr;
    }

    if (pnoSwScanFreeState != nullptr) {
        delete pnoSwScanFreeState;
        pnoSwScanFreeState = nullptr;
    }

    if (pnoSwScanningState != nullptr) {
        delete pnoSwScanningState;
        pnoSwScanningState = nullptr;
    }
}

bool ScanStateMachine::InitScanStateMachine()
{
    WIFI_LOGI("Enter InitScanStateMachine.\n");

    /* init supportHwPnoFlag value */
    supportHwPnoFlag = WifiSettings::GetInstance().GetSupportHwPnoFlag(m_instId);

    if (!InitialStateMachine("ScanStateMachine")) {
        WIFI_LOGE("Initial StateMachine failed.\n");
        return false;
    }

    if (InitCommonScanState() != true) {
        return false;
    }

    if (InitPnoScanState() != true) {
        return false;
    }

    BuildScanStateTree();
    SetFirstState(initState);
    StartStateMachine();
    return true;
}

bool ScanStateMachine::EnrollScanStatusListener(ScanStatusReportHandler handler)
{
    WIFI_LOGI("Enter EnrollScanStatusListener.\n");

    if (!handler) {
        WIFI_LOGE("handler is null.\n");
        return false;
    }

    scanStatusReportHandler = handler;
    return true;
}

ScanStateMachine::InitState::InitState(ScanStateMachine *paraScanStateMachine) : State("InitState")
{
    pScanStateMachine = paraScanStateMachine;
}

ScanStateMachine::InitState::~InitState()
{}

void ScanStateMachine::InitState::GoInState()
{
    WIFI_LOGI("Enter InitState::GoInState.\n");
    {
        std::unique_lock<std::shared_mutex> guard(lock);
        pScanStateMachine->runningScans.clear();
        pScanStateMachine->waitingScans.clear();
    }

    if (pScanStateMachine->quitFlag) {
        WIFI_LOGI("Notify finish ScanStateMachine.\n");
        pScanStateMachine->ReportStatusChange(SCAN_FINISHED_STATUS);
    }
    return;
}

void ScanStateMachine::InitState::GoOutState()
{
    WIFI_LOGI("Enter InitState::GoOutState.\n");
    return;
}

bool ScanStateMachine::InitState::ExecuteStateMsg(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case CMD_SCAN_PREPARE:
            LoadDriver();
            return true;

        case CMD_SCAN_FINISH:
            UnLoadDriver();
            return true;

        case CMD_DISABLE_SCAN:
            DisableScan();
            return true;

        case CMD_START_COMMON_SCAN:
            pScanStateMachine->ReportCommonScanFailed(msg->GetParam1());
            return true;

        case CMD_START_PNO_SCAN:
            pScanStateMachine->ReportStatusChange(PNO_SCAN_FAILED);
            return true;

        case CMD_STOP_PNO_SCAN:
            pScanStateMachine->ClearPnoScanConfig();
            pScanStateMachine->StopPnoScanHardware();
            return true;

        case CMD_STOP_COMMON_SCAN:
        case SCAN_RESULT_EVENT:
        case PNO_SCAN_RESULT_EVENT:
        case SCAN_FAILED_EVENT:
            return true;

        case SYSTEM_SCAN_TIMER:
        case DISCONNECTED_SCAN_TIMER:
        case RESTART_PNO_SCAN_TIMER:
        case RESTART_SYSTEM_SCAN_TIMER:
        case SYSTEM_SINGLE_SCAN_TIMER:
            pScanStateMachine->ReportScanInnerEvent((ScanInnerEventType)msg->GetMessageName());
            return true;
        case SCAN_UPDATE_COUNTRY_CODE:
            HandleUpdateCountryCode(msg);
            return true;
        default:
            return false;
    }
}
void ScanStateMachine::InitState::HandleUpdateCountryCode(InternalMessagePtr msg)
{
    std::string wifiCountryCode = msg->GetStringFromMessage();
    if (wifiCountryCode.empty()) {
        return;
    }
    WifiErrorNo result = WifiStaHalInterface::GetInstance().SetWifiCountryCode(
        WifiConfigCenter::GetInstance().GetStaIfaceName(), wifiCountryCode);
    if (result == WifiErrorNo::WIFI_HAL_OPT_OK) {
        WIFI_LOGI("update wifi country code sucess, wifiCountryCode=%{public}s", wifiCountryCode.c_str());
        WifiChannelHelper::GetInstance().UpdateValidChannels(
            WifiConfigCenter::GetInstance().GetStaIfaceName(), pScanStateMachine->m_instId);
        return;
    }
    WIFI_LOGE("update wifi country code fail, wifiCountryCode=%{public}s, ret=%{public}d",
        wifiCountryCode.c_str(), result);
}

ScanStateMachine::HardwareReady::HardwareReady(ScanStateMachine *paraScanStateMachine) : State("HardwareReady")
{
    pScanStateMachine = paraScanStateMachine;
}

ScanStateMachine::HardwareReady::~HardwareReady()
{}

void ScanStateMachine::HardwareReady::GoInState()
{
    WIFI_LOGI("Enter HardwareReady::GoInState.\n");
    return;
}

void ScanStateMachine::HardwareReady::GoOutState()
{
    WIFI_LOGI("Enter HardwareReady::GoOutState.\n");
    return;
}

bool ScanStateMachine::HardwareReady::ExecuteStateMsg(InternalMessagePtr msg)
{
    WIFI_LOGI("HardwareReady::ExecuteStateMsg.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case CMD_START_COMMON_SCAN:
            pScanStateMachine->CommonScanRequestProcess(msg);
            return true;

        case CMD_START_PNO_SCAN:
            pScanStateMachine->PnoScanRequestProcess(msg);
            return true;

        default:
            return false;
    }
}

ScanStateMachine::CommonScan::CommonScan(ScanStateMachine *paraScanStateMachine) : State("CommonScan")
{
    pScanStateMachine = paraScanStateMachine;
}

ScanStateMachine::CommonScan::~CommonScan()
{}

void ScanStateMachine::CommonScan::GoInState()
{
    WIFI_LOGI("Enter CommonScan::GoInState.\n");
    return;
}

void ScanStateMachine::CommonScan::GoOutState()
{
    WIFI_LOGI("Enter CommonScan::GoOutState.\n");
    pScanStateMachine->ReportCommonScanFailedAndClear(false);
    return;
}

bool ScanStateMachine::CommonScan::ExecuteStateMsg(InternalMessagePtr msg)
{
    WIFI_LOGI("CommonScan::ExecuteStateMsg.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case CMD_STOP_COMMON_SCAN:
            pScanStateMachine->RemoveCommonScanRequest(msg->GetParam1());
            return true;

        default:
            return false;
    }
}

ScanStateMachine::CommonScanUnworked::CommonScanUnworked(ScanStateMachine *paraScanStateMachine)
    : State("CommonScanUnworked")
{
    pScanStateMachine = paraScanStateMachine;
}

ScanStateMachine::CommonScanUnworked::~CommonScanUnworked()
{}

void ScanStateMachine::CommonScanUnworked::GoInState()
{
    WIFI_LOGI("Enter CommonScanUnworked::GoInState.\n");
    pScanStateMachine->StartNewCommonScan();
    return;
}

void ScanStateMachine::CommonScanUnworked::GoOutState()
{
    WIFI_LOGI("Enter CommonScanUnworked::GoOutState.\n");
    return;
}

bool ScanStateMachine::CommonScanUnworked::ExecuteStateMsg(InternalMessagePtr msg)
{
    WIFI_LOGD("CommonScanUnworked::ExecuteStateMsg.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case CMD_START_COMMON_SCAN:
            pScanStateMachine->CommonScanRequestProcess(msg);
            return true;

        case CMD_START_PNO_SCAN:
        case CMD_RESTART_PNO_SCAN:
            pScanStateMachine->PnoScanRequestProcess(msg);
            return true;

        default:
            return false;
    }
}

ScanStateMachine::CommonScanning::CommonScanning(ScanStateMachine *paraScanStateMachine) : State("CommonScanning")
{
    pScanStateMachine = paraScanStateMachine;
}

ScanStateMachine::CommonScanning::~CommonScanning()
{}

void ScanStateMachine::CommonScanning::GoInState()
{
    WIFI_LOGI("Enter CommonScanning::GoInState.\n");
    return;
}

void ScanStateMachine::CommonScanning::GoOutState()
{
    WIFI_LOGI("Enter CommonScanning::GoOutState.\n");
    pScanStateMachine->ClearRunningScanSettings();
    pScanStateMachine->ReportCommonScanFailedAndClear(true);
    pScanStateMachine->StopTimer(int(WAIT_SCAN_RESULT_TIMER));
    return;
}

/**
 * @Description  Function for processing messages when common scanning is in progress.
 * @param msg - Internal message class, which is used to send messages to the state machine.[in]
 * @return success: true, failed: false
 */
bool ScanStateMachine::CommonScanning::ExecuteStateMsg(InternalMessagePtr msg)
{
    WIFI_LOGI("Enter CommonScanning::ExecuteStateMsg.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case CMD_START_COMMON_SCAN:
            pScanStateMachine->CommonScanWhenRunning(msg);
            return true;

        case SCAN_RESULT_EVENT:
            pScanStateMachine->CommonScanInfoProcess();
            pScanStateMachine->SwitchState(pScanStateMachine->commonScanUnworkedState);
            return true;

        case SCAN_FAILED_EVENT:
            WIFI_LOGE("scan failed.");
            pScanStateMachine->ReportCommonScanFailedAndClear(true);
            pScanStateMachine->SwitchState(pScanStateMachine->commonScanUnworkedState);
            return true;

        case WAIT_SCAN_RESULT_TIMER:
            WIFI_LOGE("get scan result time out.");
            pScanStateMachine->ReportCommonScanFailedAndClear(true);
            pScanStateMachine->SwitchState(pScanStateMachine->commonScanUnworkedState);
            return true;

        /*
         * Receive a PNO scanning request and wait until the scanning is complete and
         * enter the idle state
         */
        case CMD_START_PNO_SCAN:
        case CMD_RESTART_PNO_SCAN:
            pScanStateMachine->DelayMessage(msg);
            return true;

        default:
            return false;
    }
}

ScanStateMachine::PnoScan::PnoScan(ScanStateMachine *paraScanStateMachine) : State("PnoScan")
{
    pScanStateMachine = paraScanStateMachine;
}

ScanStateMachine::PnoScan::~PnoScan()
{}

void ScanStateMachine::PnoScan::GoInState()
{
    WIFI_LOGI("Enter PnoScan::GoInState.\n");
    return;
}

void ScanStateMachine::PnoScan::GoOutState()
{
    WIFI_LOGI("Enter PnoScan::GoOutState.\n");
    pScanStateMachine->StopPnoScanHardware();
    return;
}

bool ScanStateMachine::PnoScan::ExecuteStateMsg(InternalMessagePtr msg)
{
    WIFI_LOGI("PnoScan::ExecuteStateMsg.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null.\n");
    }
    return false;
}

ScanStateMachine::PnoScanHardware::PnoScanHardware(ScanStateMachine *paraScanStateMachine) : State("PnoScanHardware")
{
    pScanStateMachine = paraScanStateMachine;
    return;
}

ScanStateMachine::PnoScanHardware::~PnoScanHardware()
{}

void ScanStateMachine::PnoScanHardware::GoInState()
{
    WIFI_LOGI("Enter PnoScanHardware::GoInState.\n");
    if (!pScanStateMachine->StartPnoScanHardware()) {
        WIFI_LOGE("StartPnoScanHardware failed.");
        return;
    }
}

void ScanStateMachine::PnoScanHardware::GoOutState()
{
    WIFI_LOGI("Enter PnoScanHardware::GoOutState.\n");
}

bool ScanStateMachine::PnoScanHardware::ExecuteStateMsg(InternalMessagePtr msg)
{
    WIFI_LOGD("PnoScanHardware::ExecuteStateMsg.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case CMD_START_PNO_SCAN:
            pScanStateMachine->PnoScanHardwareProcess(msg);
            return true;

        case CMD_STOP_PNO_SCAN:
            pScanStateMachine->ClearPnoScanConfig();
            pScanStateMachine->StopPnoScanHardware();
            return true;

        case CMD_RESTART_PNO_SCAN:
            pScanStateMachine->StopPnoScanHardware();
            pScanStateMachine->PnoScanHardwareProcess(msg);
            return true;

        case PNO_SCAN_RESULT_EVENT:
        case SCAN_RESULT_EVENT:
            pScanStateMachine->HwPnoScanInfoProcess();
            return true;

        case CMD_START_COMMON_SCAN:
            pScanStateMachine->DelayMessage(msg);
            pScanStateMachine->SwitchState(pScanStateMachine->hardwareReadyState);
            return true;

        default:
            return false;
    }
}

ScanStateMachine::CommonScanAfterPno::CommonScanAfterPno(ScanStateMachine *paraScanStateMachine)
    : State("CommonScanAfterPno")
{
    pScanStateMachine = paraScanStateMachine;
}

ScanStateMachine::CommonScanAfterPno::~CommonScanAfterPno()
{}

void ScanStateMachine::CommonScanAfterPno::GoInState()
{
    WIFI_LOGI("Enter CommonScanAfterPno::GoInState.\n");
    pScanStateMachine->CommonScanAfterPnoProcess();
}

void ScanStateMachine::CommonScanAfterPno::GoOutState()
{
    WIFI_LOGI("Enter CommonScanAfterPno::GoOutState.\n");
    if (!pScanStateMachine->remainWaitResultTimer) {
        pScanStateMachine->StopTimer(static_cast<int>(WAIT_SCAN_RESULT_TIMER));
    }
    pScanStateMachine->remainWaitResultTimer = false;
}

bool ScanStateMachine::CommonScanAfterPno::ExecuteStateMsg(InternalMessagePtr msg)
{
    WIFI_LOGI("CommonScanAfterPno::ExecuteStateMsg.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case SCAN_RESULT_EVENT:
            pScanStateMachine->CommonScanAfterPnoResult();
            pScanStateMachine->SwitchState(pScanStateMachine->pnoScanHardwareState);
            return true;

        case SCAN_FAILED_EVENT:
        case WAIT_SCAN_RESULT_TIMER:
            pScanStateMachine->SwitchState(pScanStateMachine->pnoScanHardwareState);
            return true;

        case CMD_START_PNO_SCAN:
        case PNO_SCAN_RESULT_EVENT:
            WIFI_LOGE("Ignore the message.\n");
            return true;

        /*
         * After receiving the scanning start message,
         * wait until the current scanning is complete and process the message after
         * the status is changed
         */
        case CMD_START_COMMON_SCAN:
            pScanStateMachine->DelayMessage(msg);
            pScanStateMachine->SwitchState(pScanStateMachine->commonScanningState);
            pScanStateMachine->remainWaitResultTimer = true;
            return true;

        case CMD_RESTART_PNO_SCAN:
            pScanStateMachine->UpdatePnoScanRequest(msg);
            return true;

        default:
            return false;
    }
}

ScanStateMachine::PnoScanSoftware::PnoScanSoftware(ScanStateMachine *paraScanStateMachine) : State("PnoScanSoftware")
{
    pScanStateMachine = paraScanStateMachine;
}

ScanStateMachine::PnoScanSoftware::~PnoScanSoftware()
{}

void ScanStateMachine::PnoScanSoftware::GoInState()
{
    WIFI_LOGI("Enter PnoScanSoftware::GoInState.\n");
    WIFI_LOGI("Start scan first!");

    if (!pScanStateMachine->StartNewSoftwareScan()) {
        WIFI_LOGE("failed to start new softwareScan");
    }
}

void ScanStateMachine::PnoScanSoftware::GoOutState()
{
    WIFI_LOGI("Enter PnoScanSoftware::GoOutState.\n");
    pScanStateMachine->StopTimer(static_cast<int>(SOFTWARE_PNO_SCAN_TIMER));
}

bool ScanStateMachine::PnoScanSoftware::ExecuteStateMsg(InternalMessagePtr msg)
{
    WIFI_LOGI("Enter PnoScanSoftware::ExecuteStateMsg.\n");

    if (msg == nullptr) {
        WIFI_LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case CMD_STOP_PNO_SCAN:
            pScanStateMachine->ClearPnoScanConfig();
            pScanStateMachine->StopPnoScanSoftware();
            return true;
        default:
            return false;
    }
}

ScanStateMachine::PnoSwScanFree::PnoSwScanFree(ScanStateMachine *paraScanStateMachine) : State("PnoSwScanFree")
{
    pScanStateMachine = paraScanStateMachine;
}

ScanStateMachine::PnoSwScanFree::~PnoSwScanFree()
{}

void ScanStateMachine::PnoSwScanFree::GoInState()
{
    WIFI_LOGI("Enter PnoSwScanFree::GoInState.\n");
}

void ScanStateMachine::PnoSwScanFree::GoOutState()
{
    WIFI_LOGI("Enter PnoSwScanFree::GoOutState.\n");
}

bool ScanStateMachine::PnoSwScanFree::ExecuteStateMsg(InternalMessagePtr msg)
{
    WIFI_LOGI("Enter PnoSwScanFree::ExecuteStateMsg.\n");

    if (msg == nullptr) {
        WIFI_LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case CMD_START_PNO_SCAN:
            pScanStateMachine->PnoScanSoftwareProcess(msg);
            return true;
        case CMD_RESTART_PNO_SCAN:
            pScanStateMachine->StopPnoScanSoftware();
            pScanStateMachine->PnoScanSoftwareProcess(msg);
            return true;
        case CMD_START_COMMON_SCAN:
            pScanStateMachine->DelayMessage(msg);
            pScanStateMachine->SwitchState(pScanStateMachine->hardwareReadyState);
            return true;
        case SOFTWARE_PNO_SCAN_TIMER:
            WIFI_LOGI(
                "softwarePno scanscanInterval is %{public}d.\n", pScanStateMachine->runningPnoScanConfig.scanInterval);

            if (!pScanStateMachine->RepeatStartCommonScan()) {
                WIFI_LOGE("Failed to start scan");
            }
            pScanStateMachine->StartTimer(static_cast<int>(SOFTWARE_PNO_SCAN_TIMER),
                (pScanStateMachine->runningPnoScanConfig.scanInterval) * SECOND_TO_MILLI_SECOND);

            return true;
        default:
            return false;
    }
}

ScanStateMachine::PnoSwScanning::PnoSwScanning(ScanStateMachine *paraScanStateMachine) : State("PnoSwScanning")
{
    pScanStateMachine = paraScanStateMachine;
}

ScanStateMachine::PnoSwScanning::~PnoSwScanning()
{}

void ScanStateMachine::PnoSwScanning::GoInState()
{
    WIFI_LOGI("Enter PnoSwScanning::GoInState.\n");
}

void ScanStateMachine::PnoSwScanning::GoOutState()
{
    WIFI_LOGI("Enter PnoSwScanning::GoOutState.\n");
    pScanStateMachine->StopTimer(static_cast<int>(WAIT_SCAN_RESULT_TIMER));
}

bool ScanStateMachine::PnoSwScanning::ExecuteStateMsg(InternalMessagePtr msg)
{
    WIFI_LOGI("Enter PnoSwScanning::ExecuteStateMsg.\n");
    if (msg == nullptr) {
        WIFI_LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case SCAN_RESULT_EVENT:
            pScanStateMachine->SoftwareScanInfoProcess();
            pScanStateMachine->SwitchState(pScanStateMachine->pnoSwScanFreeState);
            return true;

        case SCAN_FAILED_EVENT:
            WIFI_LOGE("scan failed");
            pScanStateMachine->SwitchState(pScanStateMachine->pnoSwScanFreeState);
            return true;

        case WAIT_SCAN_RESULT_TIMER:
            WIFI_LOGE("get scan result timed out");
            pScanStateMachine->SwitchState(pScanStateMachine->pnoSwScanFreeState);
            return true;

        case CMD_START_PNO_SCAN:
            WIFI_LOGE("The SwPnoScan is in progress and cannot be performed repeatedly.");
            pScanStateMachine->PnoScanFailedProcess();
            return true;
        case CMD_RESTART_PNO_SCAN:
        case CMD_START_COMMON_SCAN:
            pScanStateMachine->DelayMessage(msg);
            return true;

        case SOFTWARE_PNO_SCAN_TIMER:
            WIFI_LOGI("Scanning is in progress. Please wait for the scan result.");
            pScanStateMachine->DelayMessage(msg);
            return true;

        default:
            return false;
    }
}

void ScanStateMachine::CommonScanRequestProcess(InternalMessagePtr interMessage)
{
    WIFI_LOGI("CommonScanRequestProcess.\n");

    int requestIndex = 0;
    InterScanConfig scanConfig;
    if (!GetCommonScanRequestInfo(interMessage, requestIndex, scanConfig)) {
        ReportCommonScanFailed(requestIndex);
        return;
    }
    if (!VerifyScanStyle(scanConfig.scanStyle)) {
        WIFI_LOGE("invalid scan type");
        return;
    }
    {
        std::unique_lock<std::shared_mutex> guard(lock);
        waitingScans.insert(std::pair<int, InterScanConfig>(requestIndex, scanConfig));
    }
    StartNewCommonScan();
}

bool ScanStateMachine::GetCommonScanRequestInfo(
    InternalMessagePtr interMessage, int &requestIndex, InterScanConfig &scanConfig)
{
    WIFI_LOGI("Enter GetRequestMsgInfo.\n");

    if (interMessage == nullptr) {
        WIFI_LOGE("interMessage is null.");
        return false;
    }

    requestIndex = interMessage->GetParam1();
    if (!GetCommonScanConfig(interMessage, scanConfig)) {
        WIFI_LOGE("GetCommonScanConfig failed.");
        return false;
    }
    return true;
}

bool ScanStateMachine::GetCommonScanConfig(InternalMessagePtr interMessage, InterScanConfig &scanConfig)
{
    WIFI_LOGI("Enter GetCommonScanConfig.\n");

    if (interMessage == nullptr) {
        WIFI_LOGE("interMessage is null.");
        return false;
    }

    /* Obtaining the Hidden Network List */
    int hiddenSize = interMessage->GetIntFromMessage();
    for (int i = 0; i < hiddenSize; i++) {
        std::string hiddenSsid = interMessage->GetStringFromMessage();
        if (hiddenSsid.empty()) {
            WIFI_LOGE("Message body is error.");
            continue;
        }
        scanConfig.hiddenNetworkSsid.push_back(hiddenSsid);
    }

    /* Obtains the frequency list */
    int freqSize = interMessage->GetIntFromMessage();
    for (int i = 0; i < freqSize; i++) {
        int freq = interMessage->GetIntFromMessage();
        if (freq == 0) {
            WIFI_LOGE("Message body is error.");
            continue;
        }
        scanConfig.scanFreqs.push_back(freq);
    }

    scanConfig.fullScanFlag = (bool)interMessage->GetIntFromMessage();
    scanConfig.backScanPeriod = interMessage->GetIntFromMessage();
    scanConfig.bssidsNumPerScan = interMessage->GetIntFromMessage();
    scanConfig.maxScansCache = interMessage->GetIntFromMessage();
    scanConfig.maxBackScanPeriod = interMessage->GetIntFromMessage();
    scanConfig.scanStyle = interMessage->GetIntFromMessage();
    return true;
}

void ScanStateMachine::StartNewCommonScan()
{
    WIFI_LOGI("Enter StartNewCommonScan.\n");

    {
        std::shared_lock<std::shared_mutex> guard(lock);
        if (waitingScans.size() == 0) {
            ContinuePnoScanProcess();
            return;
        }
        ClearRunningScanSettings();
        bool hasFullScan = false;
        /* Traverse the request list and combine parameters */
        std::map<int, InterScanConfig>::iterator configIter = waitingScans.begin();
        for (; configIter != waitingScans.end(); ++configIter) {
            runningScanSettings.scanStyle = MergeScanStyle(runningScanSettings.scanStyle, configIter->second.scanStyle);
            std::vector<std::string>::iterator hiddenIter = configIter->second.hiddenNetworkSsid.begin();
            /* Remove duplicate hidden list */
            for (; hiddenIter != configIter->second.hiddenNetworkSsid.end(); ++hiddenIter) {
                if (std::find(runningScanSettings.hiddenNetworkSsid.begin(),
                    runningScanSettings.hiddenNetworkSsid.end(),
                    *hiddenIter) != runningScanSettings.hiddenNetworkSsid.end()) {
                    continue;
                }
                runningScanSettings.hiddenNetworkSsid.push_back(*hiddenIter);
            }

            if (!hasFullScan) {
                /* When scanFreqs is empty, it means that scan all frequenties */
                if (configIter->second.scanFreqs.empty()) {
                    runningScanSettings.scanFreqs.clear();
                    runningFullScanFlag = true;
                    hasFullScan = true;
                } else {
                    std::vector<int>::iterator freqIter = configIter->second.scanFreqs.begin();
                    /* Repetitions are eliminated */
                    for (; freqIter != configIter->second.scanFreqs.end(); ++freqIter) {
                        if (std::find(runningScanSettings.scanFreqs.begin(),
                            runningScanSettings.scanFreqs.end(),
                            *freqIter) != runningScanSettings.scanFreqs.end()) {
                            continue;
                        }
                        runningScanSettings.scanFreqs.push_back(*freqIter);
                    }
                }
            }
        }
    }

    if (!StartSingleCommonScan(runningScanSettings)) {
        ReportCommonScanFailedAndClear(false);
        ContinuePnoScanProcess();
        return;
    }

    std::unique_lock<std::shared_mutex> guard(lock);
    runningScans.swap(waitingScans);
    waitingScans.clear();
    SwitchState(commonScanningState);
    WIFI_LOGI("StartNewCommonScan success.\n");
}

void ScanStateMachine::ClearRunningScanSettings()
{
    runningScanSettings.hiddenNetworkSsid.clear();
    runningScanSettings.scanFreqs.clear();
    runningFullScanFlag = false;
    return;
}

bool ScanStateMachine::StartSingleCommonScan(WifiHalScanParam &scanParam)
{
    WIFI_LOGI("Enter StartSingleCommonScan.\n");

    for (auto freqIter = scanParam.scanFreqs.begin(); freqIter != scanParam.scanFreqs.end(); ++freqIter) {
        WIFI_LOGI("freq is %{public}d.\n", *freqIter);
    }

    for (auto hiddenIter = scanParam.hiddenNetworkSsid.begin(); hiddenIter != scanParam.hiddenNetworkSsid.end();
         ++hiddenIter) {
        WIFI_LOGI("hidden ssid is %{public}s.\n", SsidAnonymize(*hiddenIter).c_str());
    }

    WIFI_LOGI("Begin call Scan.\n");
    WifiCommonEventHelper::PublishScanStartEvent(COMMON_SCAN_START, "");
    WifiErrorNo ret = WifiStaHalInterface::GetInstance().Scan(
        WifiConfigCenter::GetInstance().GetStaIfaceName(), scanParam);
    if ((ret != WIFI_HAL_OPT_OK) && (ret != WIFI_HAL_OPT_SCAN_BUSY)) {
        WIFI_LOGE("GetInstance().scan failed.");
        return false;
    }
    WIFI_LOGI("End call Scan.\n");

    /*
     * Start the timer. If no result is returned for a long time, the scanning
     * fails
     */
    StartTimer(static_cast<int>(WAIT_SCAN_RESULT_TIMER), MAX_WAIT_SCAN_RESULT_TIME);
    lastScanStartTime = GetElapsedMicrosecondsSinceBoot();
    return true;
}

void ScanStateMachine::CommonScanWhenRunning(InternalMessagePtr interMessage)
{
    WIFI_LOGI("Enter CommonScanWhenRunning.\n");

    int requestIndex = MAX_SCAN_CONFIG_STORE_INDEX;
    InterScanConfig scanConfig;
    if (!GetCommonScanRequestInfo(interMessage, requestIndex, scanConfig)) {
        ReportCommonScanFailed(requestIndex);
        return;
    }

    if (ActiveCoverNewScan(scanConfig)) {
        std::unique_lock<std::shared_mutex> guard(lock);
        runningScans.insert(std::pair<int, InterScanConfig>(requestIndex, scanConfig));
    } else {
        std::unique_lock<std::shared_mutex> guard(lock);
        waitingScans.insert(std::pair<int, InterScanConfig>(requestIndex, scanConfig));
    }
}

bool ScanStateMachine::ActiveCoverNewScan(InterScanConfig &interScanConfig)
{
    WIFI_LOGI("Enter ActiveCoverNewScan.\n");

    if (!ActiveScanStyle(interScanConfig.scanStyle)) {
        return false;
    }

    /*
     * Determine if the frequency of new requests is included in the ongoing scan
     * settings
     */
    if (!runningFullScanFlag) {
        /* When scanFreqs is empty, it means that scan all frequenties */
        if (interScanConfig.scanFreqs.size() == 0) {
            return false;
        }

        for (auto freqIter = interScanConfig.scanFreqs.begin(); freqIter != interScanConfig.scanFreqs.end();
             ++freqIter) {
            if (std::find(runningScanSettings.scanFreqs.begin(), runningScanSettings.scanFreqs.end(), *freqIter) ==
                runningScanSettings.scanFreqs.end()) {
                return false;
            }
        }
    }

    /*
     * Determines whether the newly requested hidden network list is included in
     * the ongoing scan settings
     */
    if ((runningScanSettings.hiddenNetworkSsid.size() == 0) && (interScanConfig.hiddenNetworkSsid.size() != 0)) {
        return false;
    }

    for (auto hiddenIter = interScanConfig.hiddenNetworkSsid.begin();
         hiddenIter != interScanConfig.hiddenNetworkSsid.end();
         ++hiddenIter) {
        if (std::find(runningScanSettings.hiddenNetworkSsid.begin(),
            runningScanSettings.hiddenNetworkSsid.end(),
            *hiddenIter) == runningScanSettings.hiddenNetworkSsid.end()) {
            return false;
        }
    }
    return true;
}

void ScanStateMachine::FilterScanResultRecord::RecordFilteredScanResult(const InterScanInfo &interScanInfo)
{
    std::string keyMgmt;
    interScanInfo.GetDeviceMgmt(keyMgmt);
    WifiDeviceConfig wifiDeviceConfig;
    if (WifiSettings::GetInstance().GetDeviceConfig(interScanInfo.ssid, keyMgmt, wifiDeviceConfig) != 0) {
        return;
    }
    auto iter = filteredMsgs.find(interScanInfo.ssid);
    if (iter == filteredMsgs.end()) {
        filteredMsgs.insert({interScanInfo.ssid, GetScanInfoMsg(interScanInfo)});
    } else {
        iter->second << "|" << GetScanInfoMsg(interScanInfo).str();
    }
}

std::stringstream ScanStateMachine::FilterScanResultRecord::GetScanInfoMsg(const InterScanInfo &interScanInfo)
{
    std::stringstream filterSavedScanInfo;
    filterSavedScanInfo << MacAnonymize(interScanInfo.bssid) << "_" << interScanInfo.timestamp;
    return filterSavedScanInfo;
}

std::string ScanStateMachine::FilterScanResultRecord::GetFilteredScanResultMsg()
{
    std::stringstream filterSavedScanInfo;
    for (auto &filteredMsg : filteredMsgs) {
        if (filterSavedScanInfo.rdbuf() ->in_avail() != 0) {
            filterSavedScanInfo << ",";
        }
        filterSavedScanInfo << "\"" << SsidAnonymize(filteredMsg.first) << "\"" <<
            " : \"" << filteredMsg.second.str() << "\"";
    }
    return filterSavedScanInfo.str();
}

void ScanStateMachine::FilterScanResult(std::vector<InterScanInfo> &scanInfoList)
{
    std::string connectedBssid = WifiConfigCenter::GetInstance().GetConnectedBssid(m_instId);
    auto validScanInfosEnd = scanInfoList.begin();
    int numFilteredScanResults = 0;
    const int64_t scanInfoValidSinceTime = lastScanStartTime - SCAN_INFO_VALIDITY;
    FilterScanResultRecord records;
    for (auto &scanInfo : scanInfoList) {
        if (scanInfo.timestamp <= scanInfoValidSinceTime && connectedBssid != scanInfo.bssid) {
            records.RecordFilteredScanResult(scanInfo);
            numFilteredScanResults++;
            continue;
        }
        if (scanInfo.timestamp <= lastScanStartTime) {
            if (connectedBssid == scanInfo.bssid) {
                scanInfo.timestamp = GetElapsedMicrosecondsSinceBoot();
            } else {
                scanInfo.timestamp += 1 * MILLISECOND_TO_MICROSECOND;
            }
        }
        // move valid scanInfo to the end of valid scanInfos;
        *validScanInfosEnd = std::move(scanInfo);
        validScanInfosEnd++;
    }
    scanInfoList.erase(validScanInfosEnd, scanInfoList.end());
    WIFI_LOGI("scanInfoValidSinceTime: %{public}s, total number of valid scan results: %{public}zd, filtered invalid "
              "scan results total num: %{public}d, filtered savedNetworks: [%{public}s]",
              std::to_string(scanInfoValidSinceTime).c_str(),
              scanInfoList.size(),
              numFilteredScanResults,
              records.GetFilteredScanResultMsg().c_str());
}

void ScanStateMachine::CommonScanInfoProcess()
{
    WIFI_LOGI("Enter CommonScanInfoProcess.\n");

    ScanStatusReport scanStatusReport;
    if (!GetScanInfos(scanStatusReport.scanInfoList)) {
        WIFI_LOGE("GetScanInfos failed.");
        ReportCommonScanFailedAndClear(true);
        return;
    }
    FilterScanResult(scanStatusReport.scanInfoList);
    GetRunningIndexList(scanStatusReport.requestIndexList);

    scanStatusReport.status = COMMON_SCAN_SUCCESS;
    if (scanStatusReportHandler) {
        scanStatusReportHandler(scanStatusReport);
    }
    std::unique_lock<std::shared_mutex> guard(lock);
    runningScans.clear();
}

void ScanStateMachine::SetWifiMode(InterScanInfo &scanInfo)
{
    if (scanInfo.isHeInfoExist) {
        scanInfo.wifiMode = WIFI_802_11AX;
    } else if (scanInfo.band != SCAN_24GHZ_BAND && scanInfo.isVhtInfoExist) {
        scanInfo.wifiMode = WIFI_802_11AC;
    } else if (scanInfo.isHtInfoExist) {
        scanInfo.wifiMode = WIFI_802_11N;
    } else if (scanInfo.isErpExist) {
        scanInfo.wifiMode = WIFI_802_11G;
    } else if (scanInfo.band == SCAN_24GHZ_BAND) {
        if (scanInfo.maxRates < MAX_RATES_24G) {
            scanInfo.wifiMode = WIFI_802_11B;
        } else {
            scanInfo.wifiMode = WIFI_802_11G;
        }
    } else {
        scanInfo.wifiMode = WIFI_802_11A;
    }
    return;
}

void ScanStateMachine::ParseSecurityType(InterScanInfo &scanInfo)
{
    scanInfo.securityType = WifiSecurity::OPEN;
    if (scanInfo.capabilities.find("PSK+SAE") != std::string::npos) {
        scanInfo.securityType = WifiSecurity::PSK_SAE;
        return;
    }
    if (scanInfo.capabilities.find("WAPI-PSK") != std::string::npos) {
        scanInfo.securityType = WifiSecurity::WAPI_PSK;
        return;
    }
    if (scanInfo.capabilities.find("PSK") != std::string::npos) {
        scanInfo.securityType = WifiSecurity::PSK;
        return;
    }
    if (scanInfo.capabilities.find("WEP") != std::string::npos) {
        scanInfo.securityType = WifiSecurity::WEP;
        return;
    }
    if (scanInfo.capabilities.find("EAP-SUITE-B-192") != std::string::npos) {
        scanInfo.securityType = WifiSecurity::EAP_SUITE_B;
        return;
    }
    if (scanInfo.capabilities.find("EAP") != std::string::npos) {
        scanInfo.securityType = WifiSecurity::EAP;
        return;
    }
    if (scanInfo.capabilities.find("SAE") != std::string::npos) {
        scanInfo.securityType = WifiSecurity::SAE;
        return;
    }
    if (scanInfo.capabilities.find("OWE-TRANS-OPEN") != std::string::npos) {
        scanInfo.securityType = WifiSecurity::OPEN;
        return;
    }
    if (scanInfo.capabilities.find("OWE") != std::string::npos) {
        scanInfo.securityType = WifiSecurity::OWE;
        return;
    }
    if (scanInfo.capabilities.find("CERT") != std::string::npos) {
        scanInfo.securityType = WifiSecurity::WAPI_CERT;
        return;
    }
}

void ScanStateMachine::GetSecurityTypeAndBand(std::vector<InterScanInfo> &scanInfos)
{
    WIFI_LOGI("Enter GetSecurityTypeAndBand.\n");

    for (auto &scanInfo : scanInfos) {
        if (scanInfo.frequency < SCAN_24GHZ_MAX_FREQUENCY) {
            scanInfo.band = SCAN_24GHZ_BAND;
        } else if (scanInfo.frequency > SCAN_5GHZ_MIN_FREQUENCY) {
            scanInfo.band = SCAN_5GHZ_BAND;
        } else {
            WIFI_LOGE("invalid frequency value: %{public}d", scanInfo.frequency);
            scanInfo.band = 0;
        }

        SetWifiMode(scanInfo);
        ParseSecurityType(scanInfo);
    }

    return;
}

void ScanStateMachine::ReportStatusChange(ScanStatus status)
{
    WIFI_LOGI("Enter ReportStatusChange.\n");

    ScanStatusReport scanStatusReport;
    scanStatusReport.status = status;
    if (scanStatusReportHandler) {
        scanStatusReportHandler(scanStatusReport);
    }
}

void ScanStateMachine::ReportScanInnerEvent(ScanInnerEventType innerEvent)
{
    WIFI_LOGI("Enter ReportScanInnerEvent, event is %{public}d.\n", innerEvent);

    ScanStatusReport scanStatusReport;
    scanStatusReport.status = SCAN_INNER_EVENT;
    scanStatusReport.innerEvent = innerEvent;
    if (scanStatusReportHandler) {
        scanStatusReportHandler(scanStatusReport);
    }
}

void ScanStateMachine::ReportCommonScanFailed(int requestIndex)
{
    WIFI_LOGI("Enter ReportCommonScanFailed.\n");

    if (requestIndex == MAX_SCAN_CONFIG_STORE_INDEX) {
        return;
    }

    ScanStatusReport scanStatusReport;
    scanStatusReport.status = COMMON_SCAN_FAILED;
    scanStatusReport.requestIndexList.push_back(requestIndex);
    if (scanStatusReportHandler) {
        scanStatusReportHandler(scanStatusReport);
    }
}

void ScanStateMachine::ReportCommonScanFailedAndClear(bool runningFlag)
{
    WIFI_LOGI("Enter ReportCommonScanFailedAndClear.\n");

    ScanStatusReport scanStatusReport;
    if (runningFlag) {
        GetRunningIndexList(scanStatusReport.requestIndexList);
        std::unique_lock<std::shared_mutex> guard(lock);
        runningScans.clear();
    } else {
        GetWaitingIndexList(scanStatusReport.requestIndexList);
        std::unique_lock<std::shared_mutex> guard(lock);
        waitingScans.clear();
    }

    if (scanStatusReport.requestIndexList.size() == 0) {
        return;
    }

    scanStatusReport.status = COMMON_SCAN_FAILED;
    if (scanStatusReportHandler) {
        scanStatusReportHandler(scanStatusReport);
    }
}

void ScanStateMachine::GetRunningIndexList(std::vector<int> &runningIndexList)
{
    std::shared_lock<std::shared_mutex> guard(lock);
    std::map<int, InterScanConfig>::iterator iter = runningScans.begin();
    for (; iter != runningScans.end(); ++iter) {
        runningIndexList.push_back(iter->first);
    }
}

void ScanStateMachine::GetWaitingIndexList(std::vector<int> &waitingIndexList)
{
    std::shared_lock<std::shared_mutex> guard(lock);
    std::map<int, InterScanConfig>::iterator iter = waitingScans.begin();
    for (; iter != waitingScans.end(); ++iter) {
        waitingIndexList.push_back(iter->first);
    }
}

bool ScanStateMachine::VerifyScanStyle(int scanStyle)
{
    return (
        scanStyle == SCAN_TYPE_LOW_SPAN || scanStyle == SCAN_TYPE_LOW_POWER || scanStyle == SCAN_TYPE_HIGH_ACCURACY);
}

bool ScanStateMachine::ActiveScanStyle(int scanStyle)
{
    switch (runningScanSettings.scanStyle) {
        case SCAN_TYPE_LOW_SPAN:
        case SCAN_TYPE_LOW_POWER:
            return scanStyle != SCAN_TYPE_HIGH_ACCURACY;
        case SCAN_TYPE_HIGH_ACCURACY:
            return true;
        default:
            WIFI_LOGE("invalid scan style.");
            return false;
    }
}

int ScanStateMachine::MergeScanStyle(int currentScanStyle, int newScanStyle)
{
    switch (currentScanStyle) {
        case SCAN_TYPE_LOW_SPAN:
        case SCAN_TYPE_LOW_POWER:
            return newScanStyle;
        case SCAN_TYPE_HIGH_ACCURACY:
            return currentScanStyle;
        default:
            WIFI_LOGE("invalid scan style.");
            return newScanStyle;
    }
}

void ScanStateMachine::RemoveCommonScanRequest(int requestIndex)
{
    WIFI_LOGI("Enter RemoveCommonScanRequest.\n");
    std::unique_lock<std::shared_mutex> guard(lock);
    if (runningScans.count(requestIndex) == 1) {
        runningScans.erase(requestIndex);
    }

    if (waitingScans.count(requestIndex) == 1) {
        waitingScans.erase(requestIndex);
    }
}

void ScanStateMachine::PnoScanRequestProcess(InternalMessagePtr interMessage)
{
    WIFI_LOGI("ScanStateMachine::PnoScanRequestProcess.\n");

    if (!GetPnoScanRequestInfo(interMessage)) {
        WIFI_LOGE("GetPnoScanRequestInfo failed.\n");
        return;
    }

    if (supportHwPnoFlag) {
        SwitchState(pnoScanHardwareState);
    } else {
        SwitchState(pnoScanSoftwareState);
    }
}

void ScanStateMachine::ContinuePnoScanProcess()
{
    WIFI_LOGI("ScanStateMachine::ContinuePnoScanProcess.\n");

    if (!pnoConfigStoredFlag) {
        return;
    }

    if (supportHwPnoFlag) {
        SwitchState(pnoScanHardwareState);
    } else {
        SwitchState(pnoScanSoftwareState);
    }

    return;
}

void ScanStateMachine::PnoScanHardwareProcess(InternalMessagePtr interMessage)
{
    WIFI_LOGI("ScanStateMachine::PnoScanHardwareProcess.\n");
    if (runningHwPnoFlag) {
        WIFI_LOGE("Hardware Pno scan is running.");
        return;
    }

    if (!GetPnoScanRequestInfo(interMessage)) {
        WIFI_LOGE("GetPnoScanRequestInfo failed.");
        return;
    }

    if (!StartPnoScanHardware()) {
        WIFI_LOGE("StartPnoScanHardware failed.");
        return;
    }
}

bool ScanStateMachine::StartPnoScanHardware()
{
    WIFI_LOGI("ScanStateMachine::StartPnoScanHardware.\n");
    if (runningHwPnoFlag) {
        WIFI_LOGE("Hardware Pno scan is running.");
        return true;
    }

    if (!pnoConfigStoredFlag) {
        WIFI_LOGE("Pno config has not stored.");
        return true;
    }

    /* Invoke the IDL interface to start PNO scanning */
    WifiHalPnoScanParam pnoScanParam;
    pnoScanParam.scanInterval = runningPnoScanConfig.scanInterval;
    pnoScanParam.minRssi2Dot4Ghz = runningPnoScanConfig.minRssi2Dot4Ghz;
    pnoScanParam.minRssi5Ghz = runningPnoScanConfig.minRssi5Ghz;
    pnoScanParam.hiddenSsid.assign(
        runningPnoScanConfig.hiddenNetworkSsid.begin(), runningPnoScanConfig.hiddenNetworkSsid.end());
    pnoScanParam.savedSsid.assign(
        runningPnoScanConfig.savedNetworkSsid.begin(), runningPnoScanConfig.savedNetworkSsid.end());
    pnoScanParam.scanFreqs.assign(runningPnoScanConfig.freqs.begin(), runningPnoScanConfig.freqs.end());
    WIFI_LOGI("pnoScanParam.scanInterval is %{public}d.\n", pnoScanParam.scanInterval);
    WifiCommonEventHelper::PublishScanStartEvent(PNO_SCAN_START, "");
    WifiErrorNo ret = WifiStaHalInterface::GetInstance().StartPnoScan(
        WifiConfigCenter::GetInstance().GetStaIfaceName(), pnoScanParam);
    if ((ret != WIFI_HAL_OPT_OK) && (ret != WIFI_HAL_OPT_SCAN_BUSY)) {
        WIFI_LOGE("WifiStaHalInterface::GetInstance().StartPnoScan failed.");
        PnoScanFailedProcess();
        return false;
    }
    runningHwPnoFlag = true;
    return true;
}

void ScanStateMachine::StopPnoScanHardware()
{
    WIFI_LOGI("ScanStateMachine::StopPnoScanHardware.\n");

    if (!supportHwPnoFlag) {
        return;
    }
    if (!runningHwPnoFlag) {
        WIFI_LOGE("Hardware Pno scan is not running.");
    }

    /* Invoke the IDL interface to stop PNO scanning */
    if (WifiStaHalInterface::GetInstance().StopPnoScan(
        WifiConfigCenter::GetInstance().GetStaIfaceName()) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("WifiStaHalInterface::GetInstance().StopPnoScan failed.");
    }

    runningHwPnoFlag = false;
}

void ScanStateMachine::UpdatePnoScanRequest(InternalMessagePtr interMessage)
{
    WIFI_LOGI("Enter UpdatePnoScanRequest.\n");

    if (!GetPnoScanRequestInfo(interMessage)) {
        WIFI_LOGE("GetPnoScanRequestInfo failed.");
        return;
    }
}

bool ScanStateMachine::GetPnoScanRequestInfo(InternalMessagePtr interMessage)
{
    WIFI_LOGI("Enter GetPnoScanRequestInfo.\n");

    if (interMessage == nullptr) {
        WIFI_LOGE("interMessage is null.");
        PnoScanFailedProcess();
        return false;
    }

    ClearPnoScanConfig();
    if (!GetPnoScanConfig(interMessage, runningPnoScanConfig)) {
        WIFI_LOGE("GetPnoScanConfig failed.");
        PnoScanFailedProcess();
        return false;
    }

    if (!GetCommonScanConfig(interMessage, runningScanConfigForPno)) {
        WIFI_LOGE("GetCommonScanConfig failed.");
        PnoScanFailedProcess();
        return false;
    }

    if ((runningScanConfigForPno.hiddenNetworkSsid.size() == 0) &&
        (runningPnoScanConfig.hiddenNetworkSsid.size() != 0)) {
        runningScanConfigForPno.hiddenNetworkSsid.assign(
            runningPnoScanConfig.hiddenNetworkSsid.begin(), runningPnoScanConfig.hiddenNetworkSsid.end());
    }

    pnoConfigStoredFlag = true;
    return true;
}

bool ScanStateMachine::GetPnoScanConfig(InternalMessagePtr interMessage, PnoScanConfig &pnoScanConfig)
{
    WIFI_LOGI("Enter GetPnoScanConfig.\n");

    if (interMessage == nullptr) {
        WIFI_LOGE("interMessage is null.");
        return false;
    }

    pnoScanConfig.scanInterval = interMessage->GetIntFromMessage();
    pnoScanConfig.minRssi2Dot4Ghz = interMessage->GetIntFromMessage();
    pnoScanConfig.minRssi5Ghz = interMessage->GetIntFromMessage();

    /* Obtaining the Hidden Network List */
    int hiddenSize = interMessage->GetIntFromMessage();
    for (int i = 0; i < hiddenSize; i++) {
        std::string hiddenSsid = interMessage->GetStringFromMessage();
        if (hiddenSsid.empty()) {
            WIFI_LOGE("Message body is error.");
            return false;
        }
        pnoScanConfig.hiddenNetworkSsid.push_back(hiddenSsid);
    }

    /* Obtains the saved network list. */
    int iSavedSize = interMessage->GetIntFromMessage();
    for (int i = 0; i < iSavedSize; i++) {
        std::string savedSizeStr = interMessage->GetStringFromMessage();
        if (savedSizeStr.empty()) {
            WIFI_LOGE("Message body is error.");
            return false;
        }
        pnoScanConfig.savedNetworkSsid.push_back(savedSizeStr);
    }

    int freqsSize = interMessage->GetIntFromMessage();
    for (int i = 0; i < freqsSize; i++) {
        int freqs = interMessage->GetIntFromMessage();
        if (freqs == 0) {
            WIFI_LOGE("Message body is error.");
            return false;
        }
        pnoScanConfig.freqs.push_back(freqs);
    }
    return true;
}

void ScanStateMachine::HwPnoScanInfoProcess()
{
    WIFI_LOGI("Enter HwPnoScanInfoProcess.\n");

    if (!runningHwPnoFlag) {
        WIFI_LOGE("Hardware pno scan is not running.");
        return;
    }

    std::vector<InterScanInfo> scanInfos;
    if (!GetScanInfos(scanInfos)) {
        WIFI_LOGE("GetScanInfos failed.");
        return;
    }

    if (NeedCommonScanAfterPno(scanInfos)) {
        SwitchState(commonScanAfterPnoState);
        return;
    }

    ReportPnoScanInfos(scanInfos);
    return;
}

void ScanStateMachine::ReportPnoScanInfos(std::vector<InterScanInfo> &scanInfos)
{
    WIFI_LOGI("Enter ReportPnoScanInfos.\n");

    ScanStatusReport scanStatusReport;
    scanStatusReport.status = PNO_SCAN_INFO;
    scanStatusReport.scanInfoList.assign(scanInfos.begin(), scanInfos.end());
    if (scanStatusReportHandler) {
        scanStatusReportHandler(scanStatusReport);
    }
    return;
}

bool ScanStateMachine::NeedCommonScanAfterPno(std::vector<InterScanInfo> &scanInfos)
{
    WIFI_LOGI("Enter NeedCommonScanAfterPno.\n");
    if (scanInfos.size() > 0) {
        WIFI_LOGI("Enter UpdateNetworkScoreCache.[%{public}s]\n", MacAnonymize(scanInfos[0].bssid).c_str());
    }
    return false;
}

void ScanStateMachine::CommonScanAfterPnoProcess()
{
    WIFI_LOGI("Enter CommonScanAfterPnoProcess.\n");

    StopPnoScanHardware();
    WifiHalScanParam scanParam;
    scanParam.hiddenNetworkSsid.assign(
        runningScanConfigForPno.hiddenNetworkSsid.begin(), runningScanConfigForPno.hiddenNetworkSsid.end());
    scanParam.scanFreqs.assign(runningScanConfigForPno.scanFreqs.begin(), runningScanConfigForPno.scanFreqs.end());
    if (!StartSingleCommonScan(scanParam)) {
        WIFI_LOGE("StartSingleCommonScan failed.\n");
        SwitchState(pnoScanHardwareState);
        return;
    }
}

void ScanStateMachine::CommonScanAfterPnoResult()
{
    WIFI_LOGI("Enter CommonScanAfterPnoResult.\n");

    std::vector<InterScanInfo> scanInfos;
    if (!GetScanInfos(scanInfos)) {
        WIFI_LOGE("GetScanInfos failed.");
        return;
    }

    ReportPnoScanInfos(scanInfos);
}

void ScanStateMachine::PnoScanFailedProcess()
{
    WIFI_LOGI("Enter PnoScanFailedProcess.\n");

    runningHwPnoFlag = false;
    runningSwPnoFlag = false;
    ClearPnoScanConfig();
    ReportStatusChange(PNO_SCAN_FAILED);
}

void ScanStateMachine::ClearPnoScanConfig()
{
    pnoConfigStoredFlag = false;
    runningPnoScanConfig.scanInterval = 0;
    runningPnoScanConfig.minRssi2Dot4Ghz = 0;
    runningPnoScanConfig.minRssi5Ghz = 0;
    runningPnoScanConfig.hiddenNetworkSsid.clear();
    runningPnoScanConfig.savedNetworkSsid.clear();
    runningPnoScanConfig.freqs.clear();

    runningScanConfigForPno.fullScanFlag = 0;
    runningScanConfigForPno.backScanPeriod = 0;
    runningScanConfigForPno.bssidsNumPerScan = 0;
    runningScanConfigForPno.maxScansCache = 0;
    runningScanConfigForPno.maxBackScanPeriod = 0;
    runningScanConfigForPno.hiddenNetworkSsid.clear();
    runningScanConfigForPno.scanFreqs.clear();

    return;
}

bool ScanStateMachine::GetScanInfos(std::vector<InterScanInfo> &scanInfos)
{
    WIFI_LOGI("Enter GetScanInfos.\n");

    WIFI_LOGI("Begin: QueryScanInfos.");
    if (WifiStaHalInterface::GetInstance().QueryScanInfos(
        WifiConfigCenter::GetInstance().GetStaIfaceName(), scanInfos) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("WifiStaHalInterface::GetInstance().GetScanInfos failed.");
        return false;
    }
    WIFI_LOGI("End: QueryScanInfos.");
    GetSecurityTypeAndBand(scanInfos);
    return true;
}

bool ScanStateMachine::StartNewSoftwareScan()
{
    WIFI_LOGI("Enter StartNewSoftwareScan.\n");

    if (!RepeatStartCommonScan()) {
        WIFI_LOGE("failed to start common single scan");
        return false;
    }
    StartTimer(int(SOFTWARE_PNO_SCAN_TIMER), (runningPnoScanConfig.scanInterval) * SECOND_TO_MILLI_SECOND);
    return true;
}

bool ScanStateMachine::RepeatStartCommonScan()
{
    WIFI_LOGI("Enter RepeatStartCommonScan.\n");

    if (!pnoConfigStoredFlag) {
        WIFI_LOGE("Pno config has not stored.");
        return false;
    }

    WifiHalScanParam scanParam;
    scanParam.scanFreqs.assign(runningScanConfigForPno.scanFreqs.begin(), runningScanConfigForPno.scanFreqs.end());
    scanParam.hiddenNetworkSsid.assign(
        runningScanConfigForPno.hiddenNetworkSsid.begin(), runningScanConfigForPno.hiddenNetworkSsid.end());

    if (!StartSingleCommonScan(scanParam)) {
        PnoScanFailedProcess();
        return false;
    }

    runningSwPnoFlag = true;
    SwitchState(pnoSwScanningState);
    return true;
}

void ScanStateMachine::StopPnoScanSoftware()
{
    WIFI_LOGI("ScanStateMachine::StopPnoScanSoftware.\n");

    if (!runningSwPnoFlag) {
        WIFI_LOGE("Software Pno scan is not running.");
        return;
    }

    StopTimer(int(WAIT_SCAN_RESULT_TIMER));
    /* Stop the PNO software scanning timer. */
    StopTimer(int(SOFTWARE_PNO_SCAN_TIMER));
    runningSwPnoFlag = false;
    return;
}

void ScanStateMachine::PnoScanSoftwareProcess(InternalMessagePtr interMessage)
{
    WIFI_LOGI("ScanStateMachine::PnoScanSoftwareProcess.\n");

    if (runningSwPnoFlag) {
        WIFI_LOGE("Software Pno scan is running.");
        return;
    }

    if (!GetPnoScanRequestInfo(interMessage)) {
        WIFI_LOGE("GetPnoScanRequestInfo failed.");
        return;
    }

    if (!StartNewSoftwareScan()) {
        WIFI_LOGE("StartPnoScanSoftware failed.");
        return;
    }
}

void ScanStateMachine::SoftwareScanInfoProcess()
{
    WIFI_LOGI("Enter SoftwareScanInfoProcess.\n");

    std::vector<InterScanInfo> scanInfos;
    if (!GetScanInfos(scanInfos)) {
        WIFI_LOGE("GetScanInfos failed.");
    }

    ReportPnoScanInfos(scanInfos);
}

bool ScanStateMachine::InitCommonScanState()
{
    WIFI_LOGI("Enter InitCommonScanState.\n");

    initState = new (std::nothrow) InitState(this);
    if (initState == nullptr) {
        WIFI_LOGE("Alloc initState failed.\n");
        return false;
    }

    hardwareReadyState = new (std::nothrow) HardwareReady(this);
    if (hardwareReadyState == nullptr) {
        WIFI_LOGE("Alloc hardwareReadyState failed.\n");
        return false;
    }

    commonScanState = new (std::nothrow) CommonScan(this);
    if (commonScanState == nullptr) {
        WIFI_LOGE("Alloc commonScanState failed.\n");
        return false;
    }

    commonScanUnworkedState = new (std::nothrow) CommonScanUnworked(this);
    if (commonScanUnworkedState == nullptr) {
        WIFI_LOGE("Alloc commonScanUnworkedState failed.\n");
        return false;
    }

    commonScanningState = new (std::nothrow) CommonScanning(this);
    if (commonScanningState == nullptr) {
        WIFI_LOGE("Alloc commonScanningState failed.\n");
        return false;
    }
    return true;
}

bool ScanStateMachine::InitPnoScanState()
{
    WIFI_LOGI("Enter InitPnoScanState.\n");

    pnoScanState = new (std::nothrow) PnoScan(this);
    if (pnoScanState == nullptr) {
        WIFI_LOGE("Alloc pnoScanState failed.\n");
        return false;
    }

    pnoScanHardwareState = new (std::nothrow) PnoScanHardware(this);
    if (pnoScanHardwareState == nullptr) {
        WIFI_LOGE("Alloc pnoScanHardwareState failed.\n");
        return false;
    }

    commonScanAfterPnoState = new (std::nothrow) CommonScanAfterPno(this);
    if (commonScanAfterPnoState == nullptr) {
        WIFI_LOGE("Alloc commonScanAfterPnoState failed.\n");
        return false;
    }

    pnoScanSoftwareState = new (std::nothrow) PnoScanSoftware(this);
    if (pnoScanSoftwareState == nullptr) {
        WIFI_LOGE("Alloc pnoScanSoftwareState failed.\n");
        return false;
    }

    pnoSwScanFreeState = new (std::nothrow) PnoSwScanFree(this);
    if (pnoSwScanFreeState == nullptr) {
        WIFI_LOGE("Alloc pnoSwScanFreeState failed.\n");
        return false;
    }

    pnoSwScanningState = new (std::nothrow) PnoSwScanning(this);
    if (pnoSwScanningState == nullptr) {
        WIFI_LOGE("Alloc pnoSwScanningState failed.\n");
        return false;
    }
    return true;
}

void ScanStateMachine::BuildScanStateTree()
{
    WIFI_LOGI("Enter BuildScanStateTree.\n");

    StatePlus(initState, nullptr);
    StatePlus(hardwareReadyState, initState);
    StatePlus(commonScanState, hardwareReadyState);
    StatePlus(commonScanUnworkedState, commonScanState);
    StatePlus(commonScanningState, commonScanState);
    StatePlus(pnoScanState, hardwareReadyState);
    StatePlus(pnoScanHardwareState, pnoScanState);
    StatePlus(commonScanAfterPnoState, pnoScanHardwareState);
    StatePlus(pnoScanSoftwareState, pnoScanState);
    StatePlus(pnoSwScanFreeState, pnoScanSoftwareState);
    StatePlus(pnoSwScanningState, pnoScanSoftwareState);
}

void ScanStateMachine::InitState::LoadDriver()
{
    WIFI_LOGI("Enter LoadDriver.\n");
    pScanStateMachine->SwitchState(pScanStateMachine->hardwareReadyState);
    pScanStateMachine->ReportStatusChange(SCAN_STARTED_STATUS);
    WIFI_LOGI("Start Scan Service Success.\n");
}

void ScanStateMachine::InitState::UnLoadDriver()
{
    WIFI_LOGI("Enter UnLoadDriver.\n");
    pScanStateMachine->SwitchState(pScanStateMachine->initState);
    pScanStateMachine->quitFlag = true;
    WIFI_LOGI("Stop Scan Service Success.\n");
}

void ScanStateMachine::InitState::DisableScan()
{
    WIFI_LOGI("Enter DisableScan.\n");
    pScanStateMachine->SwitchState(pScanStateMachine->initState);
    WIFI_LOGI("Disable Scan Success.\n");
}
}  // namespace Wifi
}  // namespace OHOS