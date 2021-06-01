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

#ifndef OHOS_WIFI_SCAN_INTERFACE_H
#define OHOS_WIFI_SCAN_INTERFACE_H

#include "base_service.h"
#include "scan_service.h"

namespace OHOS {
namespace Wifi {
class ScanInterface : BaseService {
public:
    ScanInterface();
    ~ScanInterface();

    /**
     * @Description  Scan service initialization function.
     *
     * @param mqUp - message queue,which is used to return results.[in]
     * @return success: 0, failed: -1
     */
    int Init(WifiMessageQueue<WifiResponseMsgInfo> *mqUp);
    /**
     * @Description  Receives the function information of the Scan service and
     *               distributes and processes the information.
     *
     * @param requestMsg - request message[in]
     * @return success: 0, failed: -1
     */
    int PushMsg(WifiRequestMsgInfo *msg);
    /**
     *
     * @Description  Stopping the Scan Service
     * @return success: 0, failed: -1
     */
    int UnInit();

private:
    /**
     * @Description  Receives the function information of the Scan service and
     *               distributes and processes the information.
     *
     * @param requestMsg - request message[in]
     */
    void HandleRequestMsg(const WifiRequestMsgInfo *requestMsg);
    /**
     * @Description Processes interface service SCAN_REQ messages.
     *
     */
    void DealScanMsg();
    /**
     * @Description Processes interface service SCAN_PARAM_REQ messages.
     *
     * @param requestMsg request message[in]
     */
    void DealScanParamMsg(const WifiRequestMsgInfo *requestMsg);
    /**
     * @Description Processes interface service SCAN_RECONNECT_REQ messages.
     *
     */
    void DealScanReconnectMsg();
    /**
     * @Description Processes interface service SCREEN_CHANGE_NOTICE messages.
     *
     * @param requestMsg request message[in]
     */
    void DealScreenChangeMsg(const WifiRequestMsgInfo *requestMsg);
    /**
     * @Description Processes interface service SCAN_NOTIFY_STA_CONN_REQ messages.
     *
     * @param requestMsg request message[in]
     */
    void DealStaNotifyScanMsg(const WifiRequestMsgInfo *requestMsg);
    /**
     * @Description Processes interface service FRONT_BACK_STATUS_CHANGE_NOTICE messages.
     *
     * @param requestMsg request message[in]
     */
    void DealAppModeChangeMsg(const WifiRequestMsgInfo *requestMsg);
    /**
     * @Description Processes interface service CUSTOM_STATUS_CHANGE_NOTICE messages.
     *
     * @param requestMsg request message[in]
     */
    void DealCustomSceneChangeMsg(const WifiRequestMsgInfo *requestMsg);

private:
    ScanService *pScanService;
};
}  // namespace Wifi
}  // namespace OHOS

#endif