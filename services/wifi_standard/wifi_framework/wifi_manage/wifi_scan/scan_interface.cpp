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
#include "scan_interface.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_SCAN_INTERFACE"

namespace OHOS {
namespace Wifi {
ScanInterface::ScanInterface() : pScanService(nullptr)
{}

ScanInterface::~ScanInterface()
{
    LOGI("Enter ScanInterface::~ScanInterface.");
    if (pScanService != nullptr) {
        delete pScanService;
        pScanService = nullptr;
    }
}

int ScanInterface::Init(WifiMessageQueue<WifiResponseMsgInfo> *mqUp)
{
    LOGI("Enter ScanInterface::Init.");

    if (mqUp == nullptr) {
        LOGE("mqUp is null.");
        return -1;
    }

    pScanService = new (std::nothrow) ScanService();
    if (pScanService == nullptr) {
        LOGE("New ScanService failed.");
        return -1;
    }

    if (!(pScanService->InitScanService(mqUp))) {
        LOGE("InitScanService failed.");
        delete pScanService;
        pScanService = nullptr;
        return -1;
    }

    return 0;
}

int ScanInterface::UnInit()
{
    LOGI("Enter ScanInterface::UnInit.");
    if (pScanService != nullptr) {
        pScanService->UnInitScanService();
    }
    return 0;
}

int ScanInterface::PushMsg(WifiRequestMsgInfo *requestMsg)
{
    LOGI("Enter ScanInterface::PushMsg");

    if (requestMsg == nullptr) {
        LOGE("requestMsg is null.");
        return -1;
    }

    HandleRequestMsg(requestMsg);
    return 0;
}

void ScanInterface::HandleRequestMsg(const WifiRequestMsgInfo *requestMsg)
{
    LOGI("Enter ScanInterface::HandleRequestMsg");
    if (requestMsg == nullptr) {
        LOGE("requestMsg is null.");
        return;
    }

    switch (requestMsg->msgCode) {
        case SCAN_REQ:
            DealScanMsg();
            break;

        case SCAN_PARAM_REQ:
            DealScanParamMsg(requestMsg);
            break;

        case SCAN_RECONNECT_REQ:
            DealScanReconnectMsg();
            break;

        case SCREEN_CHANGE_NOTICE:
            DealScreenChangeMsg(requestMsg);
            break;

        case SCAN_NOTIFY_STA_CONN_REQ:
            DealStaNotifyScanMsg(requestMsg);
            break;

        case FRONT_BACK_STATUS_CHANGE_NOTICE:
            DealAppModeChangeMsg(requestMsg);
            break;

        case CUSTOM_STATUS_CHANGE_NOTICE:
            DealCustomSceneChangeMsg(requestMsg);
            break;

        case SCAN_CONTROL_REQ:
            pScanService->ClearScanControlValue();
            pScanService->SystemScanProcess(true);
            break;

        default:
            LOGE("requestMsg->msgCode is error.");
            break;
    }
}

void ScanInterface::DealScanMsg()
{
    LOGI("Enter ScanInterface::DealScanMsg");

    if (!(pScanService->Scan(true))) {
        LOGE("pScanService->Scan failed.");
    }
    return;
}

void ScanInterface::DealScanParamMsg(const WifiRequestMsgInfo *requestMsg)
{
    LOGI("Enter ScanInterface::DealScanParamMsg");
    if (requestMsg == nullptr) {
        LOGE("requestMsg is null.");
        return;
    }

    if (!(pScanService->Scan(requestMsg->params.wifiScanParams))) {
        LOGE("pScanService->Scan failed.");
    }
    return;
}

void ScanInterface::DealScanReconnectMsg()
{
    LOGI("Enter ScanInterface::DealScanReconnectMsg");

    if (!(pScanService->Scan(false))) {
        LOGE("pScanService->Scan failed.");
    }
    return;
}

void ScanInterface::DealScreenChangeMsg(const WifiRequestMsgInfo *requestMsg)
{
    LOGI("Enter ScanInterface::DealScreenChangeMsg");
    if (requestMsg == nullptr) {
        LOGE("requestMsg is invalid.");
        return;
    }

    if (requestMsg->params.wifiMockState.type != MODE_STATE_SCREEN) {
        LOGE("requestMsg->params->wifiMockState is invalid.");
        return;
    }
    bool screenOn = true;
    if (requestMsg->params.wifiMockState.state == STATE_CLOSE) {
        screenOn = false;
    }
    pScanService->HandleScreenStatusChanged(screenOn);
    return;
}

void ScanInterface::DealStaNotifyScanMsg(const WifiRequestMsgInfo *requestMsg)
{
    LOGI("Enter ScanInterface::DealStaNotifyScanMsg");
    if (requestMsg == nullptr) {
        LOGE("requestMsg is null.");
        return;
    }

    pScanService->HandleStaStatusChanged(requestMsg->params.argInt);
    pScanService->SetStaCurrentTime();
    return;
}

void ScanInterface::DealAppModeChangeMsg(const WifiRequestMsgInfo *requestMsg)
{
    LOGI("Enter ScanInterface::DealAppModeChangeMsg");
    if (requestMsg == nullptr) {
        LOGE("requestMsg is null.");
        return;
    }

    if (requestMsg->params.wifiMockState.type != MODE_STATE_APP_RUN) {
        LOGE("requestMsg->params->wifiMockState is invalid.");
        return;
    }
    pScanService->SetOperateAppMode(requestMsg->params.wifiMockState.state);
    return;
}

void ScanInterface::DealCustomSceneChangeMsg(const WifiRequestMsgInfo *requestMsg)
{
    LOGI("Enter ScanInterface::DealCustomSceneChangeMsg");
    if (requestMsg == nullptr) {
        LOGE("requestMsg is null.");
        return;
    }

    if (requestMsg->params.wifiMockState.type < MODE_STATE_POWER_SAVING) {
        LOGE("requestMsg->params->wifiMockState is invalid.");
        return;
    }
    time_t now = time(0);
    if (requestMsg->params.wifiMockState.state == STATE_OPEN) {
        pScanService->SetCustomScene(requestMsg->params.wifiMockState.type, now);
    }
    if (requestMsg->params.wifiMockState.state == STATE_CLOSE) {
        pScanService->SystemScanProcess(true);
    }
    return;
}

DECLARE_INIT_SERVICE(ScanInterface);
}  // namespace Wifi
}  // namespace OHOS