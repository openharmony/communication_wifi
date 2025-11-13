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

#ifndef WIFI_SCAN_PROXY
#define WIFI_SCAN_PROXY

#ifdef OHOS_ARCH_LITE
#include <vector>
#include "iproxy_client.h"
#include "i_wifi_scan.h"
#include "i_wifi_scan_callback.h"
#include "refbase.h"
#include "wifi_errcode.h"
#include "wifi_scan_msg.h"
#endif

namespace OHOS {
namespace Wifi {
#ifdef OHOS_ARCH_LITE
class WifiScanProxy : public IWifiScan {
public:static WifiScanProxy *GetInstance(void);
    static void ReleaseInstance(void);
    explicit WifiScanProxy(void);
    ErrCode Init(void);
    virtual ~WifiScanProxy();

    /**
     * @Description Start scan Wifi
     *
     * @param compatible - indicates whether compatibility is maintained
     * @return ErrCode - operation result
     */
    virtual ErrCode Scan(bool compatible) override;

    /**
     * @Description Set the Scan Control Info object
     *
     * @param info - ScanControlInfo object
     * @return ErrCode - operation result
     */
    virtual ErrCode SetScanControlInfo(const tagScanControlInfo &info) override;

    /**
     * @Description Start scan with specified params
     *
     * @param params - WifiScanParams object
     * @return ErrCode - operation result
     */
    virtual ErrCode AdvanceScan(const WifiScanParams &params) override;

    /**
     * @Description Check whether the ScanAlways mode is enabled
     *
     * @param bOpen - true / false
     * @return ErrCode - operation result
     */
    virtual ErrCode IsWifiClosedScan(bool &bOpen) override;

    /**
     * @Description Obtain the scanning result
     *
     * @param result - Get result venctor of WifiScanInfo
     * @param compatible - indicates whether compatibility is maintained
     * @return ErrCode - operation result
     */
    virtual ErrCode GetScanInfoList(std::vector<WifiScanInfo> &result, bool compatible) override;

    virtual ErrCode RegisterCallBack(const std::shared_ptr<IWifiScanCallback> &callback,
        const std::vector<std::string> &event) override;

    /**
     * @Description Get supported features
     *
     * @param features - return supported features
     * @return ErrCode - operation result
     */
    ErrCode GetSupportedFeatures(long &features) override;

    /**
     * @Description Check whether service is died.
     *
     * @return bool - true: service is died, false: service is not died.
     */
    bool IsRemoteDied(void) override;

    /**
     * @Description SetScanOnlyAvailable.
     *
     * @return ErrCode - operation result
     */
    ErrCode SetScanOnlyAvailable(bool bScanOnlyAvailable) override;

    /**
     * @Description GetScanAlways Whether Available.
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
    void OnRemoteDied(void);
private:
    static WifiScanProxy *g_instance;
    IClientProxy *remote_ = nullptr;
    SvcIdentity svcIdentity_ = { 0 };
    bool remoteDied_;
};
#endif
}  // namespace Wifi
}  // namespace OHOS
#endif
