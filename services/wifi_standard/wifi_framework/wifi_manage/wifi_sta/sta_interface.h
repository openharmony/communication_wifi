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

#ifndef OHOS_WIFI_STA_INTERFACE_H
#define OHOS_WIFI_STA_INTERFACE_H

#include "base_service.h"
#include "sta_service.h"

namespace OHOS {
namespace Wifi {
class StaInterface : BaseService {
public:
    StaInterface();
    ~StaInterface() override;
    using staHandleFunc = void (StaInterface::*)(const WifiRequestMsgInfo *requestMsg);
    using StaHandleFuncMap = std::map<int, staHandleFunc>;
    /**
     * @Description：The initialization function of Sta
     *
     * @param mqUp - The uplink Messagequeue used to return results
     * @Return: 0 - success   -1 - failed
     */
    int Init(WifiMessageQueue<WifiResponseMsgInfo> *mqUp) override;
    /**
     * @Description：Receive Message from Sta and then process distributively.
     *
     * @param requestMsg - Request Message
     * @Return: 0 - success  -1 - failed
     */
    int PushMsg(WifiRequestMsgInfo *msg) override;
    /**
     * @Description：Stop function of Sta.
     *
     * @Return: 0 - success  -1 - failed
     */
    int UnInit(void) override;

private:
    /**
     * @Description: Initialize StaHandleMap.
     *
     * @Return: 0 - success  -1 - failed
     */
    int InitStaHandleMap();
    /**
     * @Description: Start connection process when receive the connecting request.
     *
     * @param requestMsg - request message
     */
    void WifiStaCmdConnectReq(const WifiRequestMsgInfo *requestMsg);
    /**
     * @Description: Start reconnection process when receive the reconnecting request.
     *
     * @param requestMsg - request message
     */
    void WifiStaCmdReconnectReq(const WifiRequestMsgInfo *requestMsg);
    /**
     * @Description: Start reassociation process when receive the reassociating request.
     *
     * @param requestMsg - request message
     */
    void WifiStaCmdReassociateReq(const WifiRequestMsgInfo *requestMsg);
    /**
     * @Description: Start disconnection process when receive the disconnecting request.
     *
     * @param requestMsg - request message
     */
    void WifiStaCmdDisconnectReq(const WifiRequestMsgInfo *requestMsg);
    /**
     * @Description: Start the process of removing device configuration
                     when receive the request of removing device configuration.
     *
     * @param requestMsg - request message
     */
    void WifiStaCmdRemoveDeviceReq(const WifiRequestMsgInfo *requestMsg);
    /**
     * @Description: Start Wps connection process when receive the wps connecting request.
     *
     * @param requestMsg - request message
     */
    void WifiStaCmdStartWpsReq(const WifiRequestMsgInfo *requestMsg);
    /**
     * @Description: Start Wps connection process when receive the wps connecting request.
     *
     * @param requestMsg - request message
     */
    void WifiStaCmdCancelWpsReq(const WifiRequestMsgInfo *requestMsg);
    /**
     * @Description: Start the process of ConnectivityManager when
                     receive the opening ConnectivityManager request.
     *
     * @param requestMsg - request message
     */
    void WifiStaCmdConnectManagerReq(const WifiRequestMsgInfo *requestMsg);
    /**
     * @Description: Start the process of setting countrycode when receive setting countrycode request.
     *
     * @param requestMsg - request message
     */
    void WifiStaCmdSetCountryCodeReq(const WifiRequestMsgInfo *requestMsg);

private:
    StaHandleFuncMap staHandleFuncMap;
    StaService *pStaService;
};
}  // namespace Wifi
}  // namespace OHOS
#endif