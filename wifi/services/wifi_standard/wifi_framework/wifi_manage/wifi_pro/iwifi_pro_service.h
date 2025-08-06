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

#ifndef OHOS_WIFI_IWIFI_PRO_SERVICE_H
#define OHOS_WIFI_IWIFI_PRO_SERVICE_H

#include "wifi_errcode.h"
#include "wifi_msg.h"
#include "sta_service_callback.h"

namespace OHOS {
namespace Wifi {
class IWifiProService {
public:
    virtual ~IWifiProService() = default;
    /**
     * @Description  wifiPro service initialization function.
     *
     * @return ErrCode - success: WIFI_OPT_SUCCESS, failed: WIFI_OPT_FAILED
     */
    virtual ErrCode InitWifiProService() = 0;

    /**
     * @Description Get register sta callback
     *
     * @return StaServiceCallback - sta callback
     */
    virtual StaServiceCallback GetStaCallback() const = 0;

    /**
     * @Description deal scan results
     *
     * @return results - scan results
     */
    virtual void DealScanResult(const std::vector<InterScanInfo> &results) = 0;
 
    /**
     * @Description deal wifi channel qoe
     */
    virtual void DealQoeReport(const NetworkLagType &networkLagType, const NetworkLagInfo &networkLagInfo) = 0;

#ifdef FEATURE_AUTOOPEN_SPEC_LOC_SUPPORT
    /**
     * @Description receive screen state change event
     *
     * @param screenState - screen state
     */
    virtual void OnScreenStateChanged(int32_t screenState) = 0;

    /**
     * @Description receive cell info updated
     *
     */
    virtual void OnCellInfoUpdated() = 0;

    /**
     * @Description receive wifi open result
     *
     * @param state - wifi open state
     */
    virtual void OnWifiStateOpen(int32_t state) = 0;

    /**
     * @Description receive wifi close result
     *
     * @param state - wifi close state
     */
    virtual void OnWifiStateClose(int32_t state) = 0;

    /**
     * @Description receive device config change
     *
     * @param status - device config change type, update/remove
     * @param config - changed config
     * @param isRemoveAll - is remove all device config 1:remove all 0:not remove all
     */
    virtual void OnWifiDeviceConfigChange(int32_t status, const WifiDeviceConfig &config, bool isRemoveAll) = 0;
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif
