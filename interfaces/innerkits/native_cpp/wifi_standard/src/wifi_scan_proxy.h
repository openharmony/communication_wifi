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
#include "iproxy_client.h"
#else
#include <iremote_proxy.h>
#endif
#include "i_wifi_scan.h"
#include "wifi_errcode.h"
#include "wifi_scan_msg.h"

namespace OHOS {
namespace Wifi {
#ifdef OHOS_ARCH_LITE
class WifiScanProxy : public IWifiScan {
public:static WifiScanProxy *GetInstance(void);
    static void ReleaseInstance(void);
    explicit WifiScanProxy(void);
    ErrCode Init(void);
#else
class WifiScanProxy : public IRemoteProxy<IWifiScan>, public IRemoteObject::DeathRecipient {
public:
    explicit WifiScanProxy(const sptr<IRemoteObject> &remote);
#endif
    virtual ~WifiScanProxy();

    /**
     * @Description Start scan Wifi
     *
     * @return ErrCode - operation result
     */
    virtual ErrCode Scan() override;

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
     * @return ErrCode - operation result
     */
    virtual ErrCode GetScanInfoList(std::vector<WifiScanInfo> &result) override;

#ifdef OHOS_ARCH_LITE
    virtual ErrCode RegisterCallBack(const std::shared_ptr<IWifiScanCallback> &callback) override;
#else
    virtual ErrCode RegisterCallBack(const sptr<IWifiScanCallback> &callback) override;
#endif

    /**
     * @Description Get supported features
     *
     * @param features - return supported features
     * @return ErrCode - operation result
     */
    ErrCode GetSupportedFeatures(long &features) override;

#ifdef OHOS_ARCH_LITE
    void OnRemoteDied(void);
private:
    static WifiScanProxy *g_instance;
    IClientProxy *remote_ = nullptr;
    SvcIdentity svcIdentity_ = { 0 };
    bool remoteDied_;
#else
    void OnRemoteDied(const wptr<IRemoteObject>& remoteObject) override;
private:
    static BrokerDelegator<WifiScanProxy> g_delegator;
    bool mRemoteDied;
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif
