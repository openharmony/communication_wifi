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
    * @Description  Register self cure callback function.
    *
    * @param callbacks - Callback function pointer storage structure
    * @return ErrCode - success: WIFI_OPT_SUCCESS  fail: WIFI_OPT_FAILED
    */
    virtual ErrCode RegisterSelfCureServiceCallback(const SelfCureServiceCallback &callbacks) override;

    /**
     * @Description Get register sta callback
     *
     * @return StaServiceCallback - sta callback
     */
    virtual StaServiceCallback GetStaCallback() override;

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
     * @Description deal p2p connection change
     *
     * @param info -  const WifiP2pLinkedInfo
     */
    void DealP2pConnChanged(const WifiP2pLinkedInfo &info);

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