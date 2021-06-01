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

#undef LOG_TAG
#define LOG_TAG "OHWIFI_SCAN_MONITOR"

namespace OHOS {
namespace Wifi {
ScanMonitor::ScanMonitor() : pScanStateMachine(nullptr)
{}

ScanMonitor::~ScanMonitor()
{
    (void)WifiSupplicantHalInterface::GetInstance().UnRigisterSupplicantEventCallback();
}

bool ScanMonitor::InitScanMonitor()
{
    LOGI("Enter ScanMonitor::InitScanMonitor.\n");

    SupplicantEventCallback eventCallback;
    eventCallback.onScanNotify = &(ScanMonitor::ReceiveScanEventFromIdl);
    eventCallback.pInstance = (void *)this;
    if (WifiSupplicantHalInterface::GetInstance().RigisterSupplicantEventCallback(eventCallback) != WIFI_IDL_OPT_OK) {
        LOGE("RigisterSupplicantEventCallback failed.\n");
        return false;
    }

    return true;
}

void ScanMonitor::SetScanStateMachine(ScanStateMachine *paraScanStateMachine)
{
    pScanStateMachine = paraScanStateMachine;
    return;
}

void ScanMonitor::ReceiveScanEventFromIdl(int result, void *pInstance)
{
    LOGI("Enter ScanMonitor::ReceiveScanEventFromIdl, result is %{public}d.\n", result);
    if (pInstance == nullptr) {
        LOGE("pInstance is null.\n");
        return;
    }

    auto pScanMonitor = (ScanMonitor *)pInstance;
    pScanMonitor->ProcessReceiveScanEvent(result);
    return;
}

void ScanMonitor::ProcessReceiveScanEvent(int result)
{
    LOGI("Enter ScanMonitor::ProcessReceiveScanEvent, result is %{public}d.\n", result);

    switch (result) {
        case SINGLE_SCAN_OVER_OK: {
            SendScanResultEvent();
            break;
        }
        case SINGLE_SCAN_FAILED: {
            SendScanFailedEvent();
            break;
        }
        case PNO_SCAN_OVER_OK: {
            SendPnoScanResultEvent();
            break;
        }
        default: {
            LOGE("result is error.\n");
            break;
        }
    }

    return;
}

void ScanMonitor::SendScanResultEvent()
{
    pScanStateMachine->SendMessage(static_cast<int>(SCAN_RESULT_EVENT));
    return;
}

void ScanMonitor::SendPnoScanResultEvent()
{
    pScanStateMachine->SendMessage(static_cast<int>(PNO_SCAN_RESULT_EVENT));
    return;
}

void ScanMonitor::SendScanFailedEvent()
{
    pScanStateMachine->SendMessage(static_cast<int>(SCAN_FAILED_EVENT));
    return;
}
}  // namespace Wifi
}  // namespace OHOS