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

#ifndef OHOS_WIFI_SELF_CURE_INTERFACE_H
#define OHOS_WIFI_SELF_CURE_INTERFACE_H

#include "iself_cure_service.h"
#include "wifi_errcode.h"
#include "define.h"
#include "self_cure_common.h"
#include "ip2p_service_callbacks.h"
#include "sta_service_callback.h"

namespace OHOS {
namespace Wifi {
class SelfCureService;
class SelfCureInterface : public ISelfCureService {
    FRIEND_GTEST(SelfCureInterface);
public:
    explicit SelfCureInterface(int instId = 0);
    ~SelfCureInterface() override;

    /**
     * @Description  self cure service initialization function.
     *
     * @return success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode InitSelfCureService() override;

    /**
     * @Description Get register sta callback
     *
     * @return StaServiceCallback - sta callback
     */
    virtual StaServiceCallback GetStaCallback() const override;

    /**
     * @Description Notify Internet Failure Detected
     *
     * @return ErrCode - success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
    */
    virtual ErrCode NotifyInternetFailureDetected(int forceNoHttpCheck) override;

    /**
     * @Description Notify P2p connect state changed to selfcure
     *
     * @param info - p2p connect state
     * @return ErrCode - success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode NotifyP2pConnectStateChanged(const WifiP2pLinkedInfo &info) override;

    /**
    * @Description  init callback function.
    *
    * @return ErrCode - success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
    */
    virtual ErrCode InitCallback();

    /**
     * @Description deal sta connection change
     *
     * @param state - OperateResState
     * @param info -  const WifiLinkedInfo
     */
    void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId = 0);

    /**
     * @Description rssi level changed
     *
     * @param rssi
     */
    void DealRssiLevelChanged(int rssi, int instId = 0);

    /**
     * @Description deal dhcp offer report
     *
     * @param info -  IpInfo
     */
    void DealDhcpOfferReport(const IpInfo &ipInfo, int instId = 0);

    /**
     * @Description Is SelfCure On Going
     *
     * @return bool - true: selfcure is ongoing, false: selfcure is not ongoing
    */
    bool IsSelfCureOnGoing() override;

    /**
     * @Description Is SelfCure Connecting
     *
     * @return bool - true: selfcure is Connecting, false: selfcure is not Connecting
    */
    bool IsSelfCureL2Connecting() override;

    /**
     * @Description stop selfcure when user disconnect
     *
     * @param status - the situation while user disconnect
     * @return ErrCode - success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode StopSelfCureWifi(int32_t status) override;

    /**
     * @Description Check if Selfcure state,
     *
     * @param event - event type
     * @return result - true: no need broadcast state change,  false: broadcast state normally
     */
    bool CheckSelfCureWifiResult(int event) override;

    /**
     * @Description stop selfcure when user disconnect
     *
     * @return bool - true: have done selfcure or no need to do, false: selfcure not finish
     */
    bool IsWifiSelfcureDone() override;

    /**
     * @Description Notify IPv6 connection failure detected
     *
     * @return ErrCode - success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    ErrCode NotifyIpv6FailureDetected() override;
 
    /**
     * @Description Notify that tx/rx is good but network is actually not
     * working
     *
     * @param isTxRxGoodButNoInternet - true if tx/rx good but no internet
     */
    void NotifyTxRxGoodButNoInternet(bool isTxRxGoodButNoInternet) override;
private:
    std::mutex mutex;
    std::vector<SelfCureServiceCallback> mSelfCureCallback;
    SelfCureService *pSelfCureService;
    StaServiceCallback mStaCallback;
    int m_instId;
};
}  // namespace Wifi
}  // namespace OHOS
#endif