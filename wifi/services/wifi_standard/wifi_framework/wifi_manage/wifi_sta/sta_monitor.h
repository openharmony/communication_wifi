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
#ifndef OHOS_STA_MONITOR_H
#define OHOS_STA_MONITOR_H

#include "sta_state_machine.h"
#include "wifi_event_callback.h"

namespace OHOS {
namespace Wifi {
class StaMonitor {
    FRIEND_GTEST(StaMonitor);
public:
    /**
     * @Description : Construct a new Sta Monitor object.
     *
     */
    explicit StaMonitor(int instId = 0);

    /**
     * @Description Destroy the Sta Monitor object.
     *
     */
    virtual ~StaMonitor();

    /**
     * @Description : Initialize the sta monitor.
     *
     */
    ErrCode InitStaMonitor();

    /**
     * @Description : Uninitialize the sta monitor.
     *
     */
    ErrCode UnInitStaMonitor() const;

    /**
     * @Description : Generating a Sta State Machine Instance.
     *
     * @param paraStaStateMachine - a Sta State Machine Instance [in]
     */
    void SetStateMachine(StaStateMachine *paraStaStateMachine);

    /**
     * @Description : Callback of the connection state change event.
     *
     * @param status : status codes [in]
     * @param code - network id  or disconnect reason[in]
     * @param bssid - bssid of the network [in]
     */
    void OnConnectChangedCallBack(int status, int code, const std::string &bssid, int locallyGenerated);

    /**
     * @Description : Callback of the hilink trigger boardcast and wps.
     *
     * @param bssid - bssid of the network [in]
     */
    void OnWpaHilinkCallBack(const std::string &bssid);

    /**
     * @Description : Callback of the connection state change event.
     *
     * @param reason : reason for bssid change [in]
     * @param bssid: bssid of the network [in]
     */
    void OnBssidChangedCallBack(const std::string &reason, const std::string &bssid);

    /**
     * @Description : Callback of the wpa state change event.
     *
     * @param status - status codes [in]
     * @param ssid - ssid of the network [in]
     */
    void OnWpaStateChangedCallBack(int status, const std::string &ssid);

    /**
     * @Description : Callback of the Wpa ssid wrong key event.
     *
     * @param bssid: bssid of the network [in]
     */
    void OnWpaSsidWrongKeyCallBack(const std::string &bssid);

    /**
     * @Description : Callback of the Connection Full event.
     *
     * @param status - status codes [in]
     */
    void OnWpaConnectionFullCallBack(int status);

    /**
     * @Description : Callback of the Connection Refused event.
     *
     * @param assocRejectInfo - assoc reject info [in]
     */
    void OnWpaConnectionRejectCallBack(const AssocRejectInfo &assocRejectInfo);

    /**
     * @Description : Callback of the WPS_OVERLAP event.
     *
     * @param status - status codes [in]
     */
    void OnWpsPbcOverlapCallBack(int status);

    /**
     * @Description : Callback of the WPS_TIMEOUT event.
     *
     * @param status - status codes [in]
     */
    void OnWpsTimeOutCallBack(int status);

    /**
     * @Description : Callback of the AUTH TIMEOUT event.
     */
    void OnWpaAuthTimeOutCallBack();

    /**
     * @Description : Callback of the SIM/AKA/AKA' authentication event.
     *
     * @param notifyParam - authentication information [in]
     */
    void OnWpaEapSimAuthCallBack(const std::string &notifyParam);

    /**
     * @Description : Callback of the STA event.
     *
     * @param notifyParam - authentication information [in]
     */
    void OnWpaStaNotifyCallBack(const std::string &notifyParam);

    /**
     * @Description : Callback of the Csa channel switch
     *
     * @param notifyParam - authentication information [in]
     */
    void OnWpaCsaChannelSwitchNotifyCallBack(const std::string &notifyParam);

    /**
     * @Description : Callback of the Mlo Work State
     *
     * @param notifyParam - mlo state and reason code [in]
     */
    void OnWpaMloStateNotifyCallBack(const std::string &notifyParam);

    void OnWpaCustomEapNotifyCallBack(const std::string &notifyParam);

private:
    StaStateMachine *pStaStateMachine;
    int m_instId;
};
}  // namespace Wifi
}  // namespace OHOS
#endif