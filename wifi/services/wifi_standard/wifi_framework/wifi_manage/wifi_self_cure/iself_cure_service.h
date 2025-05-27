/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_SELF_CURE_SERVICE_H
#define OHOS_WIFI_SELF_CURE_SERVICE_H

#include "wifi_errcode.h"
#include "wifi_msg.h"
#include "self_cure_service_callback.h"
#include "self_cure_msg.h"
#include "sta_service_callback.h"

namespace OHOS {
namespace Wifi {
class ISelfCureService {
public:
    virtual ~ISelfCureService() = default;
    /**
     * @Description  self cure service initialization function.
     *
     * @return ErrCode - success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode InitSelfCureService() = 0;

    /**
     * @Description Get register sta callback
     *
     * @return StaServiceCallback - sta callback
     */
    virtual StaServiceCallback GetStaCallback() const = 0;

    /**
     * @Description Notify Internet Failure Detected
     *
     * @return ErrCode - success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode NotifyInternetFailureDetected(int forceNoHttpCheck) = 0;

    /**
     * @Description Notify P2p connect state changed to selfcure
     *
     * @param info - p2p connect state
     * @return ErrCode - success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode NotifyP2pConnectStateChanged(const WifiP2pLinkedInfo &info) = 0;

    /**
     * @Description Is SelfCure On Going
     *
     * @return bool - true: selfcure is ongoing, false: selfcure is not ongoing
     */
    virtual bool IsSelfCureOnGoing() = 0;

    /**
     * @Description Is SelfCure Connecting
     *
     * @return bool - true: selfcure is Connecting, false: selfcure is not Connecting
     */
    virtual bool IsSelfCureL2Connecting() = 0;

    /**
     * @Description stop selfcure when user disconnect
     *
     * @param status - the situation while user disconnect
     * @return ErrCode - success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode StopSelfCureWifi(int32_t status) = 0;

    /**
     * @Description Check if Selfcure state,
     *
     * @param event - event type
     * @return result - true: no need broadcast state change,  false: broadcast state normally
     */
    virtual bool CheckSelfCureWifiResult(int event) = 0;

    /**
     * @Description stop selfcure when user disconnect
     *
     * @return bool - true: have done selfcure or no need to do, false: selfcure not finish
     */
    virtual bool IsWifiSelfcureDone() = 0;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
