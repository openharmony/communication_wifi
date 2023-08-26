/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_SCAN_H
#define OHOS_WIFI_SCAN_H

#include "wifi_errcode.h"
#include "wifi_scan_msg.h"
#include "i_wifi_scan_callback.h"

namespace OHOS {
namespace Wifi {
class WifiScan {
public:
    static std::unique_ptr<WifiScan> CreateWifiScan(int system_ability_id);
    static std::unique_ptr<WifiScan> GetInstance(int system_ability_id);

    virtual ~WifiScan()
    {}

    /**
     * @Description Set the Scan Control Info object
     *
     * @param info - ScanControlInfo object
     * @return ErrCode - operation result
     */
    virtual ErrCode SetScanControlInfo(const ScanControlInfo &info) = 0;

    /**
     * @Description Start scan Wifi
     *
     * @param compatible - indicates whether compatibility is maintained
     * @return ErrCode - operation result
     */
    virtual ErrCode Scan(bool compatible = true) = 0;

    /**
     * @Description Obtain the scanning result
     *
     * @param result - Get result vector of WifiScanInfo
     * @param compatible - indicates whether compatibility is maintained
     * @return ErrCode - operation result
     */
    virtual ErrCode GetScanInfoList(std::vector<WifiScanInfo> &result, bool compatible = true) = 0;

    /**
     * @Description Start scan with specified params
     *
     * @param params - WifiScanParams object
     * @return ErrCode - operation result
     */
    virtual ErrCode AdvanceScan(const WifiScanParams &params) = 0;

#ifdef OHOS_ARCH_LITE
    virtual ErrCode RegisterCallBack(const std::shared_ptr<IWifiScanCallback> &callback,
        const std::vector<std::string> &event) = 0;
#else
    virtual ErrCode RegisterCallBack(const sptr<IWifiScanCallback> &callback,
        const std::vector<std::string> &event) = 0;
#endif

    /**
     * @Description Get supported features
     *
     * @param features - return supported features
     * @return ErrCode - operation result
     */
    virtual ErrCode GetSupportedFeatures(long &features) = 0;

    /**
     * @Description Check if supported input feature
     *
     * @param feature - input feature
     * @return bool - true if supported, false if unsupported
     */
    virtual bool IsFeatureSupported(long feature) = 0;

    /**
     * @Description SetScanOnlyAvailable.
     *
     * @return ErrCode - operation result
     */
    virtual ErrCode SetScanOnlyAvailable(bool bScanOnlyAvailable) = 0;

    /**
     * @Description GetScanOnly Whether Available.
     *
     * @return ErrCode - operation result
     */
    virtual ErrCode GetScanOnlyAvailable(bool &bScanOnlyAvailable) = 0;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
