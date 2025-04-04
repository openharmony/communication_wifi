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

#ifndef OHOS_WIFI_SCAN_IMPL
#define OHOS_WIFI_SCAN_IMPL

#include "wifi_scan.h"
#include "wifi_scan_proxy.h"

namespace OHOS {
namespace Wifi {
class WifiScanImpl : public Wifi::WifiScan {
public:
    WifiScanImpl();
    virtual ~WifiScanImpl();
    bool Init(int systemAbilityId, int instId);

    /**
     * @Description Set the Scan Control Info object
     *
     * @param info - ScanControlInfo object
     * @return ErrCode - operation result
     */
    virtual ErrCode SetScanControlInfo(const ScanControlInfo &info) override;

    /**
     * @Description Start scan Wifi
     *
     * @param compatible - indicates whether compatibility is maintained
     * @return ErrCode - operation result
     */
    virtual ErrCode Scan(bool compatible) override;

    /**
     * @Description Obtain the scanning result
     *
     * @param result - Get result venctor of WifiScanInfo
     * @param compatible - indicates whether compatibility is maintained
     * @return ErrCode - operation result
     */
    virtual ErrCode GetScanInfoList(std::vector<WifiScanInfo> &result, bool compatible) override;

#ifdef OHOS_ARCH_LITE
    virtual ErrCode RegisterCallBack(const std::shared_ptr<IWifiScanCallback> &callback,
        const std::vector<std::string> &event) override;
#else
    virtual ErrCode RegisterCallBack(const sptr<IWifiScanCallback> &callback,
        const std::vector<std::string> &event) override;
#endif

    /**
     * @Description Get supported features
     *
     * @param features - return supported features
     * @return ErrCode - operation result
     */
    ErrCode GetSupportedFeatures(long &features) override;

    /**
     * @Description Check if supported input feature
     *
     * @param feature - input feature
     * @return true - supported
     * @return false - unsupported
     */
    bool IsFeatureSupported(long feature) override;

    /**
     * @Description Check whether the ScanAlways mode is enabled
     *
     * @param bOpen - true / false
     * @return ErrCode - operation result
     */
    ErrCode IsWifiClosedScan(bool &bOpen);

    /**
     * @Description Start scan with specified params
     *
     * @param params - WifiScanParams object
     * @return ErrCode - operation result
     */
    ErrCode AdvanceScan(const WifiScanParams &params) override;

    /**
     * @Description Check whether service is died.
     *
     * @return bool - true: service is died, false: service is not died.
     */
    bool IsRemoteDied(void);
    /**
     * @Description SetScanOnlyAvailable.
     *
     * @return ErrCode - operation result
     */
    ErrCode SetScanOnlyAvailable(bool bScanOnlyAvailable) override;
    /**
     * @Description GetScanOnlyAvailable.
     *
     * @return ErrCode - operation result
     */
    ErrCode GetScanOnlyAvailable(bool &bScanOnlyAvailable) override;

    /**
     * @Description Start pno scan
     *
     * @param isStartAction - true:start pno scan; false:stop pno scan
     * @param periodMs - pno scan interval
     * @param suspendReason - pno scan suspent reason
     * @return ErrCode - operation result
     */
    ErrCode StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason) override;

private:
    bool GetWifiScanProxy();
    std::atomic<int> systemAbilityId_;
    int instId_;
    std::mutex mutex_;
#ifdef OHOS_ARCH_LITE
    IWifiScan *client_;
#else
    sptr<OHOS::Wifi::IWifiScan> client_;
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif
