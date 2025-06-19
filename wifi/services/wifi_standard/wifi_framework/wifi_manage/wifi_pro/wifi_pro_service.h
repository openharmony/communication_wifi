/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_PRO_SERVICE_H
#define OHOS_WIFI_PRO_SERVICE_H

#include "define.h"
#include "wifi_log.h"
#include "wifi_errcode.h"
#include "wifi_internal_msg.h"
#include "wifi_pro_state_machine.h"
#ifdef FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT
#include "wifi_intelligence_state_machine.h"
#include "telephony_observer.h"
#endif

namespace OHOS {
namespace Wifi {
#ifdef FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT
class CellularStateObserver : public Telephony::TelephonyObserver {
public:
    CellularStateObserver() = default;
    ~CellularStateObserver() = default;
    void OnCellInfoUpdated(int32_t slotId, const std::vector<sptr<Telephony::CellInformation>> &vec) override;
};
#endif
class WifiProService {
    FRIEND_GTEST(WifiProService);
public:
    explicit WifiProService(int32_t instId = 0);
    ~WifiProService();
    static WifiProService &GetInstance();
    ErrCode InitWifiProService();
    void HandleStaConnChanged(OperateResState state, const WifiLinkedInfo &linkedInfo);
    void HandleRssiLevelChanged(int32_t rssi);
    void HandleScanResult(const std::vector<InterScanInfo> &scanInfos);
    void HandleWifiHalSignalInfoChange(const WifiSignalPollInfo &wifiSignalPollInfo);
    void HandleQoeReport(const NetworkLagType &networkLagType, const NetworkLagInfo &networkLagInfo);
#ifdef FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT
    void OnScreenStateChanged(int32_t screenState);
    void OnCellInfoUpdated();
    void OnWifiStateOpen(int32_t state);
    void OnWifiStateClose(int32_t state);
#endif
private:
#ifdef FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT
    sptr<CellularStateObserver> cellularStateObserver_ { nullptr };
    std::shared_ptr<WifiIntelligenceStateMachine> pWifiIntelligenceStateMachine_ { nullptr };
    void RegisterCellularStateObserver();
    void UnRegisterCellularStateObserver();
    int32_t simCount_ { 0 };
#endif
    std::shared_ptr<WifiProStateMachine> pWifiProStateMachine_ { nullptr };
    int32_t instId_ { 0 };
    void NotifyWifi2WifiFailed(OperateResState state);
    void NotifyWifiConnectStateChanged(OperateResState state, const WifiLinkedInfo &linkedInfo);
    void NotifyCheckWifiInternetResult(OperateResState state);
};

}  // namespace Wifi
}  // namespace OHOS
#endif