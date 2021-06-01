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

#ifndef OHOS_WIFI_SERVICE_H
#define OHOS_WIFI_SERVICE_H

#include "wifi_internal_msg.h"
#include "sta_connectivity_manager.h"
#include "sta_monitor.h"
#include "sta_state_machine.h"

namespace OHOS {
namespace Wifi {
class StaService {
public:
    StaService();
    ~StaService();
    /**
     * @Description  Initialize StaService module.
     *
     * @param pMsgQueueUp - the uplink Message queue used to return results.(in)
     * @Return success: WIFI_OPT_SUCCESS  failed: WIFI_OPT_FAILED
     */
    ErrCode InitStaService(WifiMessageQueue<WifiResponseMsgInfo> *pMsgQueueUp);
    /**
     * @Description  Notify the results code to Interface Service.
     *
     * @param msgCode - operating results code.(in)
     */
    void NotifyResult(int msgCode) const;
    /**
     * @Description  Enable wifi
     *
     * @Output: Return operating results to Interface Service after enable wifi
               successfully through NotifyResult function instead of returning
               result immediately.
     * @Return success: WIFI_OPT_SUCCESS  failed: WIFI_OPT_FAILED
     */
    ErrCode EnableWifi() const;
    /**
     * @Description  Disable wifi
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through NotifyResult function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  failed: WIFI_OPT_FAILED
     */
    ErrCode DisableWifi() const;
    /**
     * @Description  Connect to a new network
     *
     * @param config - the configuration of network which is going to connect.(in)
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through NotifyResult function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  failed: WIFI_OPT_FAILED
     */
    ErrCode ConnectTo(const WifiDeviceConfig &config) const;
    /**
     * @Description  Connecting to a specified network.
     *
     * @param networkId - interior saved network index.(in)
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through NotifyResult function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  failed: WIFI_OPT_FAILED
     */
    ErrCode ConnectTo(int networkId) const;
    /**
     * @Description  Reconnect to currently active network.
     *
     * @Return success: WIFI_OPT_SUCCESS  failed: WIFI_OPT_FAILED
     */
    ErrCode ReConnect() const;
    /**
     * @Description  ReAssociate network
     *
     * @Return success: WIFI_OPT_SUCCESS  failed: WIFI_OPT_FAILED
     */
    ErrCode ReAssociate() const;
    /**
     * @Description  Remove network
     *
     * @param networkId -The NetworkId is going to be removed.(in)
     * @Return success: WIFI_OPT_SUCCESS  failed: WIFI_OPT_FAILED
     */
    ErrCode RemoveDeviceConfig(int networkId) const;
    /**
     * @Description  Disconnect to the network
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through NotifyResult function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  failed: WIFI_OPT_FAILED
     */
    ErrCode Disconnect() const;
    /**
     * @Description  Start WPS Connection
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through NotifyResult function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  failed: WIFI_OPT_FAILED
     */
    ErrCode StartWps(const WpsConfig &config) const;
    /**
     * @Description  Close WPS Connection
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through NotifyResult function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  failed: WIFI_OPT_FAILED
     */
    ErrCode CancelWps() const;
    /**
     * @Description  Set country code
     *
     * @Return success: WIFI_OPT_SUCCESS  failed: WIFI_OPT_FAILED
     */
    ErrCode SetCountryCode() const;
    /**
     * @Description  ConnectivityManager process scan results.
     *
     * @Output: Return operating results to Interface Service after enable wifi
                successfully through NotifyResult function instead of returning
                result immediately.
     * @Return success: WIFI_OPT_SUCCESS  failed: WIFI_OPT_FAILED
     */
    ErrCode ConnectivityManager(const std::vector<WifiScanInfo> &scanResults);
    ErrCode SyncLinkInfo(const std::vector<WifiScanInfo> &scanResults);

private:
    StaStateMachine *pStaStateMachine;
    StaMonitor *pStaMonitor;
    WifiMessageQueue<WifiResponseMsgInfo> *msgQueueUp;
    StaConnectivityManager *pStaConnectivityManager;
};
}  // namespace Wifi
}  // namespace OHOS
#endif