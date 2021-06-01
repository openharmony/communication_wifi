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
#include "scan_state_machine.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_SCAN_STATE_MACHINE"

namespace OHOS {
namespace Wifi {
ScanStateMachine::ScanStateMachine()
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
      runningSwPnoFlag(false)
{}

ScanStateMachine::~ScanStateMachine()
{
    LOGI("Enter ScanStateMachine::~ScanStateMachine.\n");

    /* Stop the thread. Otherwise, a problem occurs */
    StopHandlerThread();

    if (initState != nullptr) {
        delete initState;
    }

    if (hardwareReadyState != nullptr) {
        delete hardwareReadyState;
    }

    if (commonScanState != nullptr) {
        delete commonScanState;
    }

    if (commonScanUnworkedState != nullptr) {
        delete commonScanUnworkedState;
    }

    if (commonScanningState != nullptr) {
        delete commonScanningState;
    }

    if (pnoScanState != nullptr) {
        delete pnoScanState;
    }

    if (pnoScanHardwareState != nullptr) {
        delete pnoScanHardwareState;
    }
    StopPnoScanHardware();

    if (commonScanAfterPnoState != nullptr) {
        delete commonScanAfterPnoState;
    }

    if (pnoScanSoftwareState != nullptr) {
        delete pnoScanSoftwareState;
    }

    if (pnoSwScanFreeState != nullptr) {
        delete pnoSwScanFreeState;
    }

    if (pnoSwScanningState != nullptr) {
        delete pnoSwScanningState;
    }
}

bool ScanStateMachine::InitScanStateMachine()
{
    LOGI("Enter InitScanStateMachine.\n");

    /* init supportHwPnoFlag value */
    supportHwPnoFlag = WifiSettings::GetInstance().GetSupportHwPnoFlag();

    if (!InitialStateMachine()) {
        LOGE("Initial StateMachine failed.\n");
        return false;
    }

    if (InitCommonScanState() != true) {
        return false;
    };

    if (InitPnoScanState() != true) {
        return false;
    };

    BuildScanStateTree();
    SetInitialState(initState);
    Start();
    return true;
}

bool ScanStateMachine::EnrollScanStatusListener(ScanStatusReportHandler handler)
{
    LOGI("Enter ScanStateMachine::EnrollScanStatusListener.\n");

    if (!handler) {
        LOGE("handler is null.\n");
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

void ScanStateMachine::InitState::Enter()
{
    LOGI("Enter ScanStateMachine::InitState::Enter.\n");
    pScanStateMachine->runningScans.clear();
    pScanStateMachine->waitingScans.clear();

    if (pScanStateMachine->quitFlag) {
        LOGI("Notify finish ScanStateMachine.\n");
        pScanStateMachine->ReportStatusChange(SCAN_FINISHED_STATUS);
    }
    return;
}

void ScanStateMachine::InitState::Exit()
{
    LOGI("Enter ScanStateMachine::InitState::Exit.\n");
    return;
}

bool ScanStateMachine::InitState::ProcessMessage(InternalMessage *msg)
{
    LOGI("Enter ScanStateMachine::InitState::ProcessMessage.\n");
    if (msg == nullptr) {
        LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case CMD_SCAN_PREPARE:
            LoadDriver();
            return true;

        case CMD_SCAN_FINISH:
            UnLoadDriver();
            return true;

        case CMD_START_COMMON_SCAN:
            pScanStateMachine->ReportCommonScanFailed(msg->GetArg1());
            return true;

        case CMD_START_PNO_SCAN:
            pScanStateMachine->ReportStatusChange(PNO_SCAN_FAILED);
            return true;

        case CMD_STOP_PNO_SCAN:
            pScanStateMachine->ClearPnoScanConfig();
            pScanStateMachine->StopPnoScanHardware();
            return true;

        case HARDWARE_LOAD_EVENT:
            pScanStateMachine->TransitionTo(pScanStateMachine->hardwareReadyState);
            pScanStateMachine->ReportStatusChange(SCAN_STARTED_STATUS);
            return true;

        case HARDWARE_UNLOAD_EVENT:
            pScanStateMachine->TransitionTo(pScanStateMachine->initState);
            pScanStateMachine->quitFlag = true;
            return true;

        case CMD_STOP_COMMON_SCAN:
        case SCAN_RESULT_EVENT:
        case PNO_SCAN_RESULT_EVENT:
        case SCAN_FAILED_EVENT:
            LOGE("ignored scan results event.\n");
            return true;

        case SYSTEM_SCAN_TIMER:
        case DISCONNECTED_SCAN_TIMER:
        case RESTART_PNO_SCAN_TIMER:
            pScanStateMachine->ReportScanInnerEvent((ScanInnerEventType)msg->GetMessageName());
            return true;

        default:
            return false;
    }
}

ScanStateMachine::HardwareReady::HardwareReady(ScanStateMachine *paraScanStateMachine) : State("HardwareReady")
{
    pScanStateMachine = paraScanStateMachine;
}

ScanStateMachine::HardwareReady::~HardwareReady()
{}

void ScanStateMachine::HardwareReady::Enter()
{
    LOGI("Enter ScanStateMachine::HardwareReady::Enter.\n");
    return;
}

void ScanStateMachine::HardwareReady::Exit()
{
    LOGI("Enter ScanStateMachine::HardwareReady::Exit.\n");
    return;
}

bool ScanStateMachine::HardwareReady::ProcessMessage(InternalMessage *msg)
{
    LOGI("ScanStateMachine::HardwareReady::ProcessMessage.\n");
    if (msg == nullptr) {
        LOGE("msg is null.\n");
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

void ScanStateMachine::CommonScan::Enter()
{
    LOGI("Enter ScanStateMachine::CommonScan::Enter.\n");
    return;
}

void ScanStateMachine::CommonScan::Exit()
{
    LOGI("Enter ScanStateMachine::CommonScan::Exit.\n");
    pScanStateMachine->ReportCommonScanFailedAndClear(false);
    return;
}

bool ScanStateMachine::CommonScan::ProcessMessage(InternalMessage *msg)
{
    LOGI("ScanStateMachine::CommonScan::ProcessMessage.\n");
    if (msg == nullptr) {
        LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case CMD_STOP_COMMON_SCAN:
            pScanStateMachine->RemoveCommonScanRequest(msg->GetArg1());
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

void ScanStateMachine::CommonScanUnworked::Enter()
{
    LOGI("Enter ScanStateMachine::CommonScanUnworked::Enter.\n");
    pScanStateMachine->StartNewCommonScan();
    return;
}

void ScanStateMachine::CommonScanUnworked::Exit()
{
    LOGI("Enter ScanStateMachine::CommonScanUnworked::Exit.\n");
    return;
}

bool ScanStateMachine::CommonScanUnworked::ProcessMessage(InternalMessage *msg)
{
    LOGI("ScanStateMachine::CommonScanUnworked::ProcessMessage.\n");
    if (msg == nullptr) {
        LOGE("msg is null.\n");
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

void ScanStateMachine::CommonScanning::Enter()
{
    LOGI("Enter ScanStateMachine::CommonScanning::Enter.\n");
    return;
}

void ScanStateMachine::CommonScanning::Exit()
{
    LOGI("Enter ScanStateMachine::CommonScanning::Exit.\n");
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
bool ScanStateMachine::CommonScanning::ProcessMessage(InternalMessage *msg)
{
    LOGI("Enter ScanStateMachine::CommonScanning::ProcessMessage.\n");
    if (msg == nullptr) {
        LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case CMD_START_COMMON_SCAN:
            pScanStateMachine->CommonScanWhenRunning(msg);
            return true;

        case SCAN_RESULT_EVENT:
            pScanStateMachine->CommonScanResultProcess();
            pScanStateMachine->TransitionTo(pScanStateMachine->commonScanUnworkedState);
            return true;

        case SCAN_FAILED_EVENT:
            LOGE("scan failed.");
            pScanStateMachine->ReportCommonScanFailedAndClear(true);
            pScanStateMachine->TransitionTo(pScanStateMachine->commonScanUnworkedState);
            return true;

        case WAIT_SCAN_RESULT_TIMER:
            LOGE("get scan result time out.");
            pScanStateMachine->ReportCommonScanFailedAndClear(true);
            pScanStateMachine->TransitionTo(pScanStateMachine->commonScanUnworkedState);
            return true;

        /*
         * Receive a PNO scanning request and wait until the scanning is complete and
         * enter the idle state
         */
        case CMD_START_PNO_SCAN:
        case CMD_RESTART_PNO_SCAN:
            pScanStateMachine->DeferMessage(msg);
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

void ScanStateMachine::PnoScan::Enter()
{
    LOGI("Enter ScanStateMachine::PnoScan::Enter.\n");
    return;
}

void ScanStateMachine::PnoScan::Exit()
{
    LOGI("Enter ScanStateMachine::PnoScan::Exit.\n");
    pScanStateMachine->StopPnoScanHardware();
    return;
}

bool ScanStateMachine::PnoScan::ProcessMessage(InternalMessage *msg)
{
    LOGI("ScanStateMachine::PnoScan::ProcessMessage.\n");
    if (msg == nullptr) {
        LOGE("msg is null.\n");
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

void ScanStateMachine::PnoScanHardware::Enter()
{
    LOGI("Enter ScanStateMachine::PnoScanHardware::Enter.\n");
    if (!pScanStateMachine->StartPnoScanHardware()) {
        LOGE("StartPnoScanHardware failed.");
        return;
    }
    return;
}

void ScanStateMachine::PnoScanHardware::Exit()
{
    LOGI("Enter ScanStateMachine::PnoScanHardware::Exit.\n");
    return;
}

bool ScanStateMachine::PnoScanHardware::ProcessMessage(InternalMessage *msg)
{
    LOGI("ScanStateMachine::PnoScanHardware::ProcessMessage.\n");
    if (msg == nullptr) {
        LOGE("msg is null.\n");
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
            pScanStateMachine->HwPnoScanResultProcess();
            return true;

        case CMD_START_COMMON_SCAN:
            pScanStateMachine->DeferMessage(msg);
            pScanStateMachine->TransitionTo(pScanStateMachine->hardwareReadyState);
            return true;

        default:
            return false;
    }
}

ScanStateMachine::CommonScanAfterPno::CommonScanAfterPno(ScanStateMachine *paraScanStateMachine)
    : State("CommonScanAfterPno")
{
    pScanStateMachine = paraScanStateMachine;
    return;
}

ScanStateMachine::CommonScanAfterPno::~CommonScanAfterPno()
{}

void ScanStateMachine::CommonScanAfterPno::Enter()
{
    LOGI("Enter ScanStateMachine::CommonScanAfterPno::Enter.\n");
    pScanStateMachine->CommonScanAfterPnoProcess();
    return;
}

void ScanStateMachine::CommonScanAfterPno::Exit()
{
    LOGI("Enter ScanStateMachine::CommonScanAfterPno::Exit.\n");
    if (!pScanStateMachine->remainWaitResultTimer) {
        pScanStateMachine->StopTimer(static_cast<int>(WAIT_SCAN_RESULT_TIMER));
    }
    pScanStateMachine->remainWaitResultTimer = false;

    return;
}

bool ScanStateMachine::CommonScanAfterPno::ProcessMessage(InternalMessage *msg)
{
    LOGI("ScanStateMachine::CommonScanAfterPno::ProcessMessage.\n");
    if (msg == nullptr) {
        LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case SCAN_RESULT_EVENT:
            pScanStateMachine->CommonScanAfterPnoResult();
            pScanStateMachine->TransitionTo(pScanStateMachine->pnoScanHardwareState);
            return true;

        case SCAN_FAILED_EVENT:
        case WAIT_SCAN_RESULT_TIMER:
            pScanStateMachine->TransitionTo(pScanStateMachine->pnoScanHardwareState);
            return true;

        case CMD_START_PNO_SCAN:
        case PNO_SCAN_RESULT_EVENT:
            LOGE("Ignore the message.\n");
            return true;

        /*
         * After receiving the scanning start message,
         * wait until the current scanning is complete and process the message after
         * the status is changed
         */
        case CMD_START_COMMON_SCAN:
            pScanStateMachine->DeferMessage(msg);
            pScanStateMachine->TransitionTo(pScanStateMachine->commonScanningState);
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

void ScanStateMachine::PnoScanSoftware::Enter()
{
    LOGI("Enter ScanStateMachine::PnoScanSoftware::Enter.\n");
    LOGI("Start scan first!");

    if (!pScanStateMachine->StartNewSoftwareScan()) {
        LOGE("failed to start new softwareScan");
    }
    return;
}

void ScanStateMachine::PnoScanSoftware::Exit()
{
    LOGI("Enter ScanStateMachine::PnoScanSoftware::Exit.\n");
    pScanStateMachine->StopTimer(static_cast<int>(SOFTWARE_PNO_SCAN_TIMER));
    return;
}

bool ScanStateMachine::PnoScanSoftware::ProcessMessage(InternalMessage *msg)
{
    LOGI("Enter ScanStateMachine::PnoScanSoftware::ProcessMessage.\n");

    if (msg == nullptr) {
        LOGE("msg is null.\n");
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

void ScanStateMachine::PnoSwScanFree::Enter()
{
    LOGI("Enter ScanStateMachine::PnoSwScanFree::Enter.\n");
    return;
}

void ScanStateMachine::PnoSwScanFree::Exit()
{
    LOGI("Enter ScanStateMachine::PnoSwScanFree::Exit.\n");
    return;
}

bool ScanStateMachine::PnoSwScanFree::ProcessMessage(InternalMessage *msg)
{
    LOGI("Enter ScanStateMachine::PnoSwScanFree::ProcessMessage.\n");

    if (msg == nullptr) {
        LOGE("msg is null.\n");
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
            pScanStateMachine->DeferMessage(msg);
            pScanStateMachine->TransitionTo(pScanStateMachine->hardwareReadyState);
            return true;
        case SOFTWARE_PNO_SCAN_TIMER:
            LOGI("softwarePno scanscanInterval is %{public}d.\n", pScanStateMachine->runningPnoScanConfig.scanInterval);

            if (!pScanStateMachine->RepeatStartCommonScan()) {
                LOGE("Failed to start scan");
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

void ScanStateMachine::PnoSwScanning::Enter()
{
    LOGI("Enter ScanStateMachine::PnoSwScanning::Enter.\n");
    return;
}

void ScanStateMachine::PnoSwScanning::Exit()
{
    LOGI("Enter ScanStateMachine::PnoSwScanning::Exit.\n");
    pScanStateMachine->StopTimer(static_cast<int>(WAIT_SCAN_RESULT_TIMER));
    return;
}

bool ScanStateMachine::PnoSwScanning::ProcessMessage(InternalMessage *msg)
{
    LOGI("Enter ScanStateMachine::PnoSwScanning::ProcessMessage.\n");
    if (msg == nullptr) {
        LOGE("msg is null.\n");
        return true;
    }

    switch (msg->GetMessageName()) {
        case SCAN_RESULT_EVENT:
            pScanStateMachine->SoftwareScanResultProcess();
            pScanStateMachine->TransitionTo(pScanStateMachine->pnoSwScanFreeState);
            return true;

        case SCAN_FAILED_EVENT:
            LOGE("scan failed");
            pScanStateMachine->TransitionTo(pScanStateMachine->pnoSwScanFreeState);
            return true;

        case WAIT_SCAN_RESULT_TIMER:
            LOGE("get scan result timed out");
            pScanStateMachine->TransitionTo(pScanStateMachine->pnoSwScanFreeState);
            return true;

        case CMD_START_PNO_SCAN:
            LOGE("The SwPnoScan is in progress and cannot be performed repeatedly.");
            pScanStateMachine->PnoScanFailedProcess();
            return true;
        case CMD_RESTART_PNO_SCAN:
        case CMD_START_COMMON_SCAN:
            pScanStateMachine->DeferMessage(msg);
            return true;

        case SOFTWARE_PNO_SCAN_TIMER:
            LOGI("Scanning is in progress. Please wait for the scan result.");
            pScanStateMachine->DeferMessage(msg);
            return true;

        default:
            return false;
    }
}

void ScanStateMachine::CommonScanRequestProcess(InternalMessage *interMessage)
{
    LOGI("ScanStateMachine::CommonScanRequestProcess.\n");

    int requestIndex = 0;
    InterScanConfig scanConfig;
    if (!GetCommonScanRequestInfo(interMessage, requestIndex, scanConfig)) {
        ReportCommonScanFailed(requestIndex);
        return;
    }
    if (!VerifyScanStyle(scanConfig.scanStyle)) {
        LOGE("invalid scan type");
        return;
    }
    waitingScans.insert(std::pair<int, InterScanConfig>(requestIndex, scanConfig));
    StartNewCommonScan();

    return;
}

bool ScanStateMachine::GetCommonScanRequestInfo(
    InternalMessage *interMessage, int &requestIndex, InterScanConfig &scanConfig)
{
    LOGI("Enter ScanStateMachine::GetRequestMsgInfo.\n");

    if (interMessage == nullptr) {
        LOGE("interMessage is null.");
        return false;
    }

    requestIndex = interMessage->GetArg1();
    if (!GetCommonScanConfig(interMessage, scanConfig)) {
        LOGE("GetCommonScanConfig failed.");
        return false;
    }

    return true;
}

bool ScanStateMachine::GetCommonScanConfig(InternalMessage *interMessage, InterScanConfig &scanConfig)
{
    LOGI("Enter ScanStateMachine::GetCommonScanConfig.\n");

    if (interMessage == nullptr) {
        LOGE("interMessage is null.");
        return false;
    }

    /* Obtaining the Hidden Network List */
    int hiddenSize = interMessage->GetIntFromMessage();
    for (int i = 0; i < hiddenSize; i++) {
        std::string hiddenSsid = interMessage->GetStringFromMessage();
        if (hiddenSsid.empty()) {
            LOGE("Message body is error.");
            return false;
        }
        scanConfig.hiddenNetworkSsid.push_back(hiddenSsid);
    }

    /* Obtains the frequency list */
    int freqSize = interMessage->GetIntFromMessage();
    for (int i = 0; i < freqSize; i++) {
        int freq = interMessage->GetIntFromMessage();
        if (freq == 0) {
            LOGE("Message body is error.");
            return false;
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
    LOGI("Enter ScanStateMachine::StartNewCommonScan.\n");

    if (waitingScans.size() == 0) {
        ContinuePnoScanProcess();
        return;
    }

    ClearRunningScanSettings();
    bool hasFullScan = false;
    /* Traverse the request list and combine parameters */
    std::map<int, InterScanConfig>::iterator configIter = waitingScans.begin();
    for (; configIter != waitingScans.end(); configIter++) {
        runningScanSettings.scanStyle = MergeScanStyle(runningScanSettings.scanStyle, configIter->second.scanStyle);

        std::vector<std::string>::iterator hiddenIter = configIter->second.hiddenNetworkSsid.begin();
        /* Remove duplicate hidden list */
        for (; hiddenIter != configIter->second.hiddenNetworkSsid.end(); hiddenIter++) {
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
                for (; freqIter != configIter->second.scanFreqs.end(); freqIter++) {
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

    if (!StartSingleCommonScan(runningScanSettings)) {
        ReportCommonScanFailedAndClear(false);
        ContinuePnoScanProcess();
        return;
    }

    runningScans.swap(waitingScans);
    waitingScans.clear();
    TransitionTo(commonScanningState);
    LOGI("StartNewCommonScan success.\n");

    return;
}

void ScanStateMachine::ClearRunningScanSettings()
{
    runningScanSettings.hiddenNetworkSsid.clear();
    runningScanSettings.scanFreqs.clear();
    runningFullScanFlag = false;
    return;
}

bool ScanStateMachine::StartSingleCommonScan(WifiScanParam &scanParam)
{
    LOGI("Enter ScanStateMachine::StartSingleCommonScan.\n");

    for (auto freqIter = scanParam.scanFreqs.begin(); freqIter != scanParam.scanFreqs.end(); freqIter++) {
        LOGI("freq is %{public}d.\n", *freqIter);
    }

    for (auto hiddenIter = scanParam.hiddenNetworkSsid.begin(); hiddenIter != scanParam.hiddenNetworkSsid.end();
         hiddenIter++) {
        LOGI("hidden ssid is %{public}s.\n", hiddenIter->c_str());
    }

    LOGI("Begin call Scan.\n");
    WifiErrorNo ret = WifiStaHalInterface::GetInstance().Scan(scanParam);
    if ((ret != WIFI_IDL_OPT_OK) && (ret != WIFI_IDL_OPT_SCAN_BUSY)) {
        LOGE("WifiStaHalInterface::GetInstance().scan failed.");
        return false;
    }
    LOGI("End call Scan.\n");

    /*
     * Start the timer. If no result is returned for a long time, the scanning
     * fails
     */
    StartTimer(static_cast<int>(WAIT_SCAN_RESULT_TIMER), MAX_WAIT_SCAN_RESULT_TIME);

    return true;
}

void ScanStateMachine::CommonScanWhenRunning(InternalMessage *interMessage)
{
    LOGI("Enter ScanStateMachine::CommonScanWhenRunning.\n");

    int requestIndex = MAX_SCAN_CONFIG_STORE_INDEX;
    InterScanConfig scanConfig;
    if (!GetCommonScanRequestInfo(interMessage, requestIndex, scanConfig)) {
        ReportCommonScanFailed(requestIndex);
        return;
    }

    if (ActiveCoverNewScan(scanConfig)) {
        runningScans.insert(std::pair<int, InterScanConfig>(requestIndex, scanConfig));
    } else {
        waitingScans.insert(std::pair<int, InterScanConfig>(requestIndex, scanConfig));
    }

    return;
}

bool ScanStateMachine::ActiveCoverNewScan(InterScanConfig &interScanConfig)
{
    LOGI("Enter ScanStateMachine::ActiveCoverNewScan.\n");

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
             freqIter++) {
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
         hiddenIter++) {
        if (std::find(runningScanSettings.hiddenNetworkSsid.begin(),
            runningScanSettings.hiddenNetworkSsid.end(),
            *hiddenIter) == runningScanSettings.hiddenNetworkSsid.end()) {
            return false;
        }
    }

    return true;
}

void ScanStateMachine::CommonScanResultProcess()
{
    LOGI("Enter ScanStateMachine::CommonScanResultProcess.\n");

    ScanStatusReport scanStatusReport;
    if (!GetScanResults(scanStatusReport.scanResultList)) {
        LOGE("GetScanResults failed.");
        ReportCommonScanFailedAndClear(true);
        return;
    }
    GetRunningIndexList(scanStatusReport.requestIndexList);

    scanStatusReport.status = COMMON_SCAN_SUCCESS;
    if (scanStatusReportHandler) {
        scanStatusReportHandler(scanStatusReport);
    }
    runningScans.clear();

    return;
}

void ScanStateMachine::ConvertScanResults(
    std::vector<WifiScanResult> &wifiScanResults, std::vector<InterScanResult> &scanResults)
{
    LOGI("Enter ScanStateMachine::ConvertScanResults.\n");

    std::vector<WifiScanResult>::iterator iter = wifiScanResults.begin();
    for (; iter != wifiScanResults.end(); iter++) {
        InterScanResult singleResult;
        singleResult.bssid = iter->bssid;
        singleResult.ssid = iter->ssid;
        singleResult.capabilities = iter->capability;
        singleResult.frequency = iter->frequency;
        singleResult.level = iter->signalLevel;
        singleResult.timestamp = iter->timestamp;

        scanResults.push_back(singleResult);
    }

    return;
}

void ScanStateMachine::OnQuitting()
{
    LOGI("Enter ScanStateMachine::OnQuitting.\n");
    return;
}
void ScanStateMachine::OnHalting()
{
    LOGI("ScanStateMachine::OnQuitting.\n");
    return;
}

void ScanStateMachine::ReportStatusChange(ScanStatus status)
{
    LOGI("Enter ScanStateMachine::ReportStatusChange.\n");

    ScanStatusReport scanStatusReport;
    scanStatusReport.status = status;
    if (scanStatusReportHandler) {
        scanStatusReportHandler(scanStatusReport);
    }

    return;
}

void ScanStateMachine::ReportScanInnerEvent(ScanInnerEventType innerEvent)
{
    LOGI("Enter ScanStateMachine::ReportScanInnerEvent, event is %{public}d.\n", innerEvent);

    ScanStatusReport scanStatusReport;
    scanStatusReport.status = SCAN_INNER_EVENT;
    scanStatusReport.innerEvent = innerEvent;
    if (scanStatusReportHandler) {
        scanStatusReportHandler(scanStatusReport);
    }

    return;
}

void ScanStateMachine::ReportCommonScanFailed(int requestIndex)
{
    LOGI("Enter ScanStateMachine::ReportCommonScanFailed.\n");

    if (requestIndex == MAX_SCAN_CONFIG_STORE_INDEX) {
        return;
    }

    ScanStatusReport scanStatusReport;
    scanStatusReport.status = COMMON_SCAN_FAILED;
    scanStatusReport.requestIndexList.push_back(requestIndex);
    if (scanStatusReportHandler) {
        scanStatusReportHandler(scanStatusReport);
    }

    return;
}

void ScanStateMachine::ReportCommonScanFailedAndClear(bool runningFlag)
{
    LOGI("Enter ScanStateMachine::ReportCommonScanFailedAndClear.\n");

    ScanStatusReport scanStatusReport;
    if (runningFlag) {
        GetRunningIndexList(scanStatusReport.requestIndexList);
        runningScans.clear();
    } else {
        GetWaitingIndexList(scanStatusReport.requestIndexList);
        waitingScans.clear();
    }

    if (scanStatusReport.requestIndexList.size() == 0) {
        return;
    }

    scanStatusReport.status = COMMON_SCAN_FAILED;
    if (scanStatusReportHandler) {
        scanStatusReportHandler(scanStatusReport);
    }

    return;
}

void ScanStateMachine::GetRunningIndexList(std::vector<int> &runningIndexList)
{
    std::map<int, InterScanConfig>::iterator iter = runningScans.begin();
    for (; iter != runningScans.end(); iter++) {
        runningIndexList.push_back(iter->first);
    }

    return;
}

void ScanStateMachine::GetWaitingIndexList(std::vector<int> &waitingIndexList)
{
    std::map<int, InterScanConfig>::iterator iter = waitingScans.begin();
    for (; iter != waitingScans.end(); iter++) {
        waitingIndexList.push_back(iter->first);
    }

    return;
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
            LOGE("invalid scan style.");
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
            LOGE("invalid scan style.");
            return newScanStyle;
    }
}

void ScanStateMachine::RemoveCommonScanRequest(int requestIndex)
{
    LOGI("Enter ScanStateMachine::RemoveCommonScanRequest.\n");

    if (runningScans.count(requestIndex) == 1) {
        runningScans.erase(requestIndex);
    }

    if (waitingScans.count(requestIndex) == 1) {
        waitingScans.erase(requestIndex);
    }

    return;
}

void ScanStateMachine::PnoScanRequestProcess(InternalMessage *interMessage)
{
    LOGI("ScanStateMachine::PnoScanRequestProcess.\n");

    if (!GetPnoScanRequestInfo(interMessage)) {
        LOGE("GetPnoScanRequestInfo failed.\n");
        return;
    }

    if (supportHwPnoFlag) {
        TransitionTo(pnoScanHardwareState);
    } else {
        TransitionTo(pnoScanSoftwareState);
    }

    return;
}

void ScanStateMachine::ContinuePnoScanProcess()
{
    LOGI("ScanStateMachine::ContinuePnoScanProcess.\n");

    if (!pnoConfigStoredFlag) {
        return;
    }

    if (supportHwPnoFlag) {
        TransitionTo(pnoScanHardwareState);
    } else {
        TransitionTo(pnoScanSoftwareState);
    }

    return;
}

void ScanStateMachine::PnoScanHardwareProcess(InternalMessage *interMessage)
{
    LOGI("ScanStateMachine::PnoScanHardwareProcess.\n");
    if (runningHwPnoFlag) {
        LOGE("Hardware Pno scan is running.");
        return;
    }

    if (!GetPnoScanRequestInfo(interMessage)) {
        LOGE("GetPnoScanRequestInfo failed.");
        return;
    }

    if (!StartPnoScanHardware()) {
        LOGE("StartPnoScanHardware failed.");
        return;
    }

    return;
}

bool ScanStateMachine::StartPnoScanHardware()
{
    LOGI("ScanStateMachine::StartPnoScanHardware.\n");
    if (runningHwPnoFlag) {
        LOGE("Hardware Pno scan is running.");
        return true;
    }

    if (!pnoConfigStoredFlag) {
        LOGE("Pno config has not stored.");
        return true;
    }

    /* Invoke the IDL interface to start PNO scanning */
    WifiPnoScanParam pnoScanParam;
    pnoScanParam.scanInterval = runningPnoScanConfig.scanInterval;
    pnoScanParam.minRssi2Dot4Ghz = runningPnoScanConfig.minRssi2Dot4Ghz;
    pnoScanParam.minRssi5Ghz = runningPnoScanConfig.minRssi5Ghz;
    pnoScanParam.hiddenSsid.assign(
        runningPnoScanConfig.hiddenNetworkSsid.begin(), runningPnoScanConfig.hiddenNetworkSsid.end());
    pnoScanParam.savedSsid.assign(
        runningPnoScanConfig.savedNetworkSsid.begin(), runningPnoScanConfig.savedNetworkSsid.end());
    pnoScanParam.scanFreqs.assign(runningPnoScanConfig.freqs.begin(), runningPnoScanConfig.freqs.end());
    LOGI("pnoScanParam.scanInterval is %{public}d.\n", pnoScanParam.scanInterval);
    WifiErrorNo ret = WifiStaHalInterface::GetInstance().StartPnoScan(pnoScanParam);
    if ((ret != WIFI_IDL_OPT_OK) && (ret != WIFI_IDL_OPT_SCAN_BUSY)) {
        LOGE("WifiStaHalInterface::GetInstance().StartPnoScan failed.");
        PnoScanFailedProcess();
        return false;
    }
    runningHwPnoFlag = true;

    return true;
}

void ScanStateMachine::StopPnoScanHardware()
{
    LOGI("ScanStateMachine::StopPnoScanHardware.\n");

    if (!supportHwPnoFlag) {
        return;
    }
    if (!runningHwPnoFlag) {
        LOGE("Hardware Pno scan is not running.");
    }

    /* Invoke the IDL interface to stop PNO scanning */
    if (WifiStaHalInterface::GetInstance().StopPnoScan() != WIFI_IDL_OPT_OK) {
        LOGE("WifiStaHalInterface::GetInstance().StopPnoScan failed.");
    }

    runningHwPnoFlag = false;
    return;
}

void ScanStateMachine::UpdatePnoScanRequest(InternalMessage *interMessage)
{
    LOGI("Enter ScanStateMachine::UpdatePnoScanRequest.\n");

    if (!GetPnoScanRequestInfo(interMessage)) {
        LOGE("GetPnoScanRequestInfo failed.");
        return;
    }

    return;
}

bool ScanStateMachine::GetPnoScanRequestInfo(InternalMessage *interMessage)
{
    LOGI("Enter ScanStateMachine::GetPnoScanRequestInfo.\n");

    if (interMessage == nullptr) {
        LOGE("interMessage is null.");
        PnoScanFailedProcess();
        return false;
    }

    ClearPnoScanConfig();
    if (!GetPnoScanConfig(interMessage, runningPnoScanConfig)) {
        LOGE("GetPnoScanConfig failed.");
        PnoScanFailedProcess();
        return false;
    }

    if (!GetCommonScanConfig(interMessage, runningScanConfigForPno)) {
        LOGE("GetCommonScanConfig failed.");
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

bool ScanStateMachine::GetPnoScanConfig(InternalMessage *interMessage, PnoScanConfig &pnoScanConfig)
{
    LOGI("Enter ScanStateMachine::GetPnoScanConfig.\n");

    if (interMessage == nullptr) {
        LOGE("interMessage is null.");
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
            LOGE("Message body is error.");
            return false;
        }
        pnoScanConfig.hiddenNetworkSsid.push_back(hiddenSsid);
    }

    /* Obtains the saved network list. */
    int iSavedSize = interMessage->GetIntFromMessage();
    for (int i = 0; i < iSavedSize; i++) {
        std::string savedSizeStr = interMessage->GetStringFromMessage();
        if (savedSizeStr.empty()) {
            LOGE("Message body is error.");
            return false;
        }
        pnoScanConfig.savedNetworkSsid.push_back(savedSizeStr);
    }

    int freqsSize = interMessage->GetIntFromMessage();
    for (int i = 0; i < freqsSize; i++) {
        int freqs = interMessage->GetIntFromMessage();
        if (freqs == 0) {
            LOGE("Message body is error.");
            return false;
        }
        pnoScanConfig.freqs.push_back(freqs);
    }

    return true;
}

void ScanStateMachine::HwPnoScanResultProcess()
{
    LOGI("Enter ScanStateMachine::HwPnoScanResultProcess.\n");

    if (!runningHwPnoFlag) {
        LOGE("Hardware pno scan is not running.");
        return;
    }

    std::vector<InterScanResult> scanResults;
    if (!GetScanResults(scanResults)) {
        LOGE("GetScanResults failed.");
        return;
    }

    if (NeedCommonScanAfterPno(scanResults)) {
        TransitionTo(commonScanAfterPnoState);
        return;
    }

    ReportPnoScanResults(scanResults);
    return;
}

void ScanStateMachine::ReportPnoScanResults(std::vector<InterScanResult> &scanResults)
{
    LOGI("Enter ScanStateMachine::ReportPnoScanResults.\n");

    ScanStatusReport scanStatusReport;
    scanStatusReport.status = PNO_SCAN_RESULT;
    scanStatusReport.scanResultList.assign(scanResults.begin(), scanResults.end());
    if (scanStatusReportHandler) {
        scanStatusReportHandler(scanStatusReport);
    }
    return;
}

bool ScanStateMachine::NeedCommonScanAfterPno(std::vector<InterScanResult> &scanResults)
{
    LOGI("Enter ScanStateMachine::NeedCommonScanAfterPno.\n");
    if (scanResults.size() > 0) {
        LOGI("Enter UpdateNetworkScoreCache.[%{public}s]\n", scanResults[0].bssid.c_str());
    }
    return false;
}

void ScanStateMachine::CommonScanAfterPnoProcess()
{
    LOGI("Enter ScanStateMachine::CommonScanAfterPnoProcess.\n");

    StopPnoScanHardware();
    WifiScanParam scanParam;
    scanParam.hiddenNetworkSsid.assign(
        runningScanConfigForPno.hiddenNetworkSsid.begin(), runningScanConfigForPno.hiddenNetworkSsid.end());
    scanParam.scanFreqs.assign(runningScanConfigForPno.scanFreqs.begin(), runningScanConfigForPno.scanFreqs.end());
    if (!StartSingleCommonScan(scanParam)) {
        LOGE("StartSingleCommonScan failed.\n");
        TransitionTo(pnoScanHardwareState);
        return;
    }

    return;
}

void ScanStateMachine::CommonScanAfterPnoResult()
{
    LOGI("Enter ScanStateMachine::CommonScanAfterPnoResult.\n");

    std::vector<InterScanResult> scanResults;
    if (!GetScanResults(scanResults)) {
        LOGE("GetScanResults failed.");
        return;
    }

    ReportPnoScanResults(scanResults);
    return;
}

void ScanStateMachine::PnoScanFailedProcess()
{
    LOGI("Enter ScanStateMachine::PnoScanFailedProcess.\n");

    runningHwPnoFlag = false;
    runningSwPnoFlag = false;
    ClearPnoScanConfig();
    ReportStatusChange(PNO_SCAN_FAILED);

    return;
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

bool ScanStateMachine::GetScanResults(std::vector<InterScanResult> &scanResults)
{
    LOGI("Enter ScanStateMachine::GetScanResults.\n");

    std::vector<WifiScanResult> wifiScanResults;
    LOGI("Begin: QueryScanResults.");
    if (WifiStaHalInterface::GetInstance().QueryScanResults(wifiScanResults) != WIFI_IDL_OPT_OK) {
        LOGE("WifiStaHalInterface::GetInstance().QueryScanResults failed.");
        return false;
    }
    LOGI("End: QueryScanResults.");

    ConvertScanResults(wifiScanResults, scanResults);
    return true;
}

bool ScanStateMachine::StartNewSoftwareScan()
{
    LOGI("Enter ScanStateMachine::StartNewSoftwareScan.\n");

    if (!RepeatStartCommonScan()) {
        LOGE("failed to start common single scan");
        return false;
    }
    StartTimer(int(SOFTWARE_PNO_SCAN_TIMER), (runningPnoScanConfig.scanInterval) * SECOND_TO_MILLI_SECOND);

    return true;
}

bool ScanStateMachine::RepeatStartCommonScan()
{
    LOGI("Enter ScanStateMachine::RepeatStartCommonScan.\n");

    if (!pnoConfigStoredFlag) {
        LOGE("Pno config has not stored.");
        return false;
    }

    WifiScanParam scanParam;
    scanParam.scanFreqs.assign(runningScanConfigForPno.scanFreqs.begin(), runningScanConfigForPno.scanFreqs.end());
    scanParam.hiddenNetworkSsid.assign(
        runningScanConfigForPno.hiddenNetworkSsid.begin(), runningScanConfigForPno.hiddenNetworkSsid.end());

    if (!StartSingleCommonScan(scanParam)) {
        PnoScanFailedProcess();
        return false;
    }

    runningSwPnoFlag = true;
    TransitionTo(pnoSwScanningState);

    return true;
}

void ScanStateMachine::StopPnoScanSoftware()
{
    LOGI("ScanStateMachine::StopPnoScanSoftware.\n");

    if (!runningSwPnoFlag) {
        LOGE("Software Pno scan is not running.");
        return;
    }

    StopTimer(int(WAIT_SCAN_RESULT_TIMER));
    /* Stop the PNO software scanning timer. */
    StopTimer(int(SOFTWARE_PNO_SCAN_TIMER));

    runningSwPnoFlag = false;
    return;
}

void ScanStateMachine::PnoScanSoftwareProcess(InternalMessage *interMessage)
{
    LOGI("ScanStateMachine::PnoScanSoftwareProcess.\n");

    if (runningSwPnoFlag) {
        LOGE("Software Pno scan is running.");
        return;
    }

    if (!GetPnoScanRequestInfo(interMessage)) {
        LOGE("GetPnoScanRequestInfo failed.");
        return;
    }

    if (!StartNewSoftwareScan()) {
        LOGE("StartPnoScanSoftware failed.");
        return;
    }

    return;
}

void ScanStateMachine::SoftwareScanResultProcess()
{
    LOGI("Enter ScanStateMachine::SoftwareScanResultProcess.\n");

    std::vector<InterScanResult> scanResults;
    if (!GetScanResults(scanResults)) {
        LOGE("GetScanResults failed.");
    }

    ReportPnoScanResults(scanResults);
    return;
}

bool ScanStateMachine::InitCommonScanState()
{
    LOGI("Enter ScanStateMachine::InitCommonScanState.\n");

    initState = new (std::nothrow) InitState(this);
    if (initState == nullptr) {
        LOGE("Alloc initState failed.\n");
        return false;
    }

    hardwareReadyState = new (std::nothrow) HardwareReady(this);
    if (hardwareReadyState == nullptr) {
        LOGE("Alloc hardwareReadyState failed.\n");
        return false;
    }

    commonScanState = new (std::nothrow) CommonScan(this);
    if (commonScanState == nullptr) {
        LOGE("Alloc commonScanState failed.\n");
        return false;
    }

    commonScanUnworkedState = new (std::nothrow) CommonScanUnworked(this);
    if (commonScanUnworkedState == nullptr) {
        LOGE("Alloc commonScanUnworkedState failed.\n");
        return false;
    }

    commonScanningState = new (std::nothrow) CommonScanning(this);
    if (commonScanningState == nullptr) {
        LOGE("Alloc commonScanningState failed.\n");
        return false;
    }

    return true;
}

bool ScanStateMachine::InitPnoScanState()
{
    LOGI("Enter ScanStateMachine::InitPnoScanState.\n");

    pnoScanState = new (std::nothrow) PnoScan(this);
    if (pnoScanState == nullptr) {
        LOGE("Alloc pnoScanState failed.\n");
        return false;
    }

    pnoScanHardwareState = new (std::nothrow) PnoScanHardware(this);
    if (pnoScanHardwareState == nullptr) {
        LOGE("Alloc pnoScanHardwareState failed.\n");
        return false;
    }

    commonScanAfterPnoState = new (std::nothrow) CommonScanAfterPno(this);
    if (commonScanAfterPnoState == nullptr) {
        LOGE("Alloc commonScanAfterPnoState failed.\n");
        return false;
    }

    pnoScanSoftwareState = new (std::nothrow) PnoScanSoftware(this);
    if (pnoScanSoftwareState == nullptr) {
        LOGE("Alloc pnoScanSoftwareState failed.\n");
        return false;
    }

    pnoSwScanFreeState = new (std::nothrow) PnoSwScanFree(this);
    if (pnoSwScanFreeState == nullptr) {
        LOGE("Alloc pnoSwScanFreeState failed.\n");
        return false;
    }

    pnoSwScanningState = new (std::nothrow) PnoSwScanning(this);
    if (pnoSwScanningState == nullptr) {
        LOGE("Alloc pnoSwScanningState failed.\n");
        return false;
    }

    return true;
}

void ScanStateMachine::BuildScanStateTree()
{
    LOGI("Enter ScanStateMachine::BuildScanStateTree.\n");

    AddState(initState, nullptr);
    AddState(hardwareReadyState, initState);
    AddState(commonScanState, hardwareReadyState);
    AddState(commonScanUnworkedState, commonScanState);
    AddState(commonScanningState, commonScanState);
    AddState(pnoScanState, hardwareReadyState);
    AddState(pnoScanHardwareState, pnoScanState);
    AddState(commonScanAfterPnoState, pnoScanHardwareState);
    AddState(pnoScanSoftwareState, pnoScanState);
    AddState(pnoSwScanFreeState, pnoScanSoftwareState);
    AddState(pnoSwScanningState, pnoScanSoftwareState);
}

void ScanStateMachine::InitState::LoadDriver()
{
    LOGI("Enter ScanStateMachine::LoadDriver.\n");
    pScanStateMachine->TransitionTo(pScanStateMachine->hardwareReadyState);
    pScanStateMachine->ReportStatusChange(SCAN_STARTED_STATUS);
    LOGI("Start Scan Service Success.\n");
}

void ScanStateMachine::InitState::UnLoadDriver()
{
    LOGI("Enter ScanStateMachine::UnLoadDriver.\n");
    pScanStateMachine->TransitionTo(pScanStateMachine->initState);
    pScanStateMachine->quitFlag = true;
    LOGI("Stop Scan Service Success.\n");
}
}  // namespace Wifi
}  // namespace OHOS