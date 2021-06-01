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
#include "sta_interface.h"
#include "wifi_log.h"
#include "define.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_STA_INTERFACE"

namespace OHOS {
namespace Wifi {
StaInterface::StaInterface() : pStaService(nullptr)
{}

StaInterface::~StaInterface()
{
    LOGI("StaInterface::~StaInterface");
    if (pStaService != nullptr) {
        delete pStaService;
    }
}

int StaInterface::Init(WifiMessageQueue<WifiResponseMsgInfo> *mqUp)
{
    LOGD("Enter StaInterface::Init.\n");
    if (mqUp == nullptr) {
        LOGE("mqUp is null.\n");
        return -1;
    }

    pStaService = new (std::nothrow) StaService();
    if (pStaService == nullptr) {
        LOGE("New StaService failed.\n");
        return -1;
    }

    if (pStaService->InitStaService(mqUp) != WIFI_OPT_SUCCESS) {
        LOGE("InitStaService failed.\n");
        delete pStaService;
        pStaService = nullptr;
        return -1;
    }

    if (pStaService->EnableWifi() != WIFI_OPT_SUCCESS) {
        LOGE("EnableWifi failed.\n");
        UnInit();
        return -1;
    }
    InitStaHandleMap();
    return 0;
}

int StaInterface::InitStaHandleMap()
{
    staHandleFuncMap[WifiInternalMsgCode::STA_CONNECT_REQ] = &StaInterface::WifiStaCmdConnectReq;
    staHandleFuncMap[WIFI_SVR_CMD_RECONNECT] = &StaInterface::WifiStaCmdReconnectReq;
    staHandleFuncMap[WifiInternalMsgCode::STA_REASSOCIATE_REQ] = &StaInterface::WifiStaCmdReassociateReq;
    staHandleFuncMap[WifiInternalMsgCode::STA_DISCONNECT_REQ] = &StaInterface::WifiStaCmdDisconnectReq;
    staHandleFuncMap[WifiInternalMsgCode::STA_REMOVE_DEVICE_REQ] = &StaInterface::WifiStaCmdRemoveDeviceReq;
    staHandleFuncMap[WifiInternalMsgCode::STA_START_WPS_REQ] = &StaInterface::WifiStaCmdStartWpsReq;
    staHandleFuncMap[WifiInternalMsgCode::STA_CANCEL_WPS_REQ] = &StaInterface::WifiStaCmdCancelWpsReq;
    staHandleFuncMap[WifiInternalMsgCode::STA_CONNECT_MANAGE_REQ] = &StaInterface::WifiStaCmdConnectManagerReq;
    staHandleFuncMap[WifiInternalMsgCode::STA_SET_COUNTRY_CODE] = &StaInterface::WifiStaCmdSetCountryCodeReq;
    return 0;
}

int StaInterface::UnInit()
{
    LOGD("Enter StaInterface::UnInit.\n");
    int ret = 0;
    if (pStaService->DisableWifi() != WIFI_OPT_SUCCESS) {
        LOGD("DisableWifi failed.\n");
        return -1;
    }

    return ret;
}

int StaInterface::PushMsg(WifiRequestMsgInfo *requestMsg)
{
    LOGD("Enter StaInterface::PushMsg\n");
    if (requestMsg == nullptr) {
        LOGE("requestMsg is null.\n");
        return -1;
    }

    for (auto iter = staHandleFuncMap.begin(); iter != staHandleFuncMap.end(); ++iter) {
        if (iter->first == requestMsg->msgCode) {
            (this->*(iter->second))(requestMsg);
            break;
        }
    }

    return 0;
}

void StaInterface::WifiStaCmdConnectReq(const WifiRequestMsgInfo *requestMsg)
{
    LOGD("Enter StaInterface::WifiStaCmdConnectReq.\n");

    if (requestMsg->params.argInt >= 0) {
        pStaService->ConnectTo(requestMsg->params.argInt);
    } else {
        pStaService->ConnectTo(requestMsg->params.deviceConfig);
    }
}

void StaInterface::WifiStaCmdReconnectReq(const WifiRequestMsgInfo *requestMsg)
{
    if (requestMsg == nullptr) {
        LOGE("requestMsg is null\n");
    }
    LOGD("Enter StaInterface::WifiStaCmdReconnectReq.\n");
    pStaService->ReConnect();
}

void StaInterface::WifiStaCmdReassociateReq(const WifiRequestMsgInfo *requestMsg)
{
    if (requestMsg == nullptr) {
        LOGE("requestMsg is null\n");
    }
    LOGD("Enter StaInterface::WifiStaCmdReassociateReq.\n");
    pStaService->ReAssociate();
}

void StaInterface::WifiStaCmdDisconnectReq(const WifiRequestMsgInfo *requestMsg)
{
    if (requestMsg == nullptr) {
        LOGE("requestMsg is null\n");
    }
    LOGD("Enter StaInterface::WifiStaCmdDisconnectReq.\n");
    pStaService->Disconnect();
}

void StaInterface::WifiStaCmdRemoveDeviceReq(const WifiRequestMsgInfo *requestMsg)
{
    if (requestMsg == nullptr) {
        LOGE("requestMsg is null\n");
        return;
    }
    LOGD("Enter StaInterface::WifiStaCmdRemoveDeviceReq.\n");
    pStaService->RemoveDeviceConfig(requestMsg->params.argInt);
}

void StaInterface::WifiStaCmdStartWpsReq(const WifiRequestMsgInfo *requestMsg)
{
    if (requestMsg == nullptr) {
        LOGE("requestMsg is null\n");
        return;
    }
    LOGD("Enter StaInterface::WifiStaCmdStartWpsReq.\n");
    pStaService->StartWps(requestMsg->params.wpsConfig);
}

void StaInterface::WifiStaCmdCancelWpsReq(const WifiRequestMsgInfo *requestMsg)
{
    if (requestMsg == nullptr) {
        LOGE("requestMsg is null\n");
    }
    LOGD("Enter StaInterface::WifiStaCmdCancelWpsReq.\n");
    pStaService->CancelWps();
}

void StaInterface::WifiStaCmdConnectManagerReq(const WifiRequestMsgInfo *requestMsg)
{
    LOGI("Connection management information transferred successfully.\n");
    pStaService->SyncLinkInfo(requestMsg->params.scanResults);
    pStaService->ConnectivityManager(requestMsg->params.scanResults);
}

void StaInterface::WifiStaCmdSetCountryCodeReq(const WifiRequestMsgInfo *requestMsg)
{
    if (requestMsg == nullptr) {
        LOGE("requestMsg is null\n");
    }
    LOGD("Enter StaInterface::WifiStaCmdSetCountryCodeReq.\n");
    pStaService->SetCountryCode();
}

DECLARE_INIT_SERVICE(StaInterface);
}  // namespace Wifi
}  // namespace OHOS
