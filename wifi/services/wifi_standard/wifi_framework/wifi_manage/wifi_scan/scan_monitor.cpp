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
#include "scan_monitor.h"
#include "wifi_logger.h"
#include "wifi_supplicant_hal_interface.h"

DEFINE_WIFILOG_SCAN_LABEL("ScanMonitor");

namespace OHOS {
namespace Wifi {
ScanMonitor::ScanMonitor(int instId) : pScanStateMachine(nullptr), m_instId(instId)
{}

ScanMonitor::~ScanMonitor()
{}

bool ScanMonitor::InitScanMonitor()
{
    WIFI_LOGI("Enter ScanMonitor::InitScanMonitor.");

    SupplicantEventCallback eventCallback;
    eventCallback.onScanNotify = [this](int result) { this->ReceiveScanEventFromIdl(result); };
    if (WifiSupplicantHalInterface::GetInstance().RegisterSupplicantEventCallback(eventCallback) != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("RegisterSupplicantEventCallback failed.");
        return false;
    }

    return true;
}

void ScanMonitor::UnInitScanMonitor()
{
    WIFI_LOGI("Enter ScanMonitor::UnInitScanMonitor.");
    if (WifiSupplicantHalInterface::GetInstance().UnRegisterSupplicantEventCallback() != WIFI_HAL_OPT_OK) {
        WIFI_LOGE("UnRegisterSupplicantEventCallback failed.");
    }
    return;
}

void ScanMonitor::SetScanStateMachine(ScanStateMachine *paraScanStateMachine)
{
    pScanStateMachine = paraScanStateMachine;
    return;
}

void ScanMonitor::ReceiveScanEventFromIdl(int result)
{
    WIFI_LOGI("Enter ScanMonitor::ReceiveScanEventFromIdl, result is %{public}d.", result);
    ProcessReceiveScanEvent(result);
    return;
}

void ScanMonitor::ProcessReceiveScanEvent(int result)
{
    WIFI_LOGI("Enter ScanMonitor::ProcessReceiveScanEvent, result is %{public}d.\n", result);

    switch (result) {
        case HAL_SINGLE_SCAN_OVER_OK: {
            SendScanInfoEvent();
            break;
        }
        case HAL_SINGLE_SCAN_FAILED: {
            SendScanFailedEvent();
            break;
        }
        case HAL_PNO_SCAN_OVER_OK: {
            SendPnoScanInfoEvent();
            break;
        }
        default: {
            WIFI_LOGE("result is error.\n");
            break;
        }
    }

    return;
}

void ScanMonitor::SendScanInfoEvent()
{
    if (pScanStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }
    pScanStateMachine->SendMessage(static_cast<int>(SCAN_RESULT_EVENT));
    return;
}

void ScanMonitor::SendPnoScanInfoEvent()
{
    if (pScanStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }
    pScanStateMachine->SendMessage(static_cast<int>(PNO_SCAN_RESULT_EVENT));
    return;
}

void ScanMonitor::SendScanFailedEvent()
{
    if (pScanStateMachine == nullptr) {
        WIFI_LOGE("The statemachine pointer is null.");
        return;
    }
    pScanStateMachine->SendMessage(static_cast<int>(SCAN_FAILED_EVENT));
    return;
}
}  // namespace Wifi
}  // namespace OHOS
