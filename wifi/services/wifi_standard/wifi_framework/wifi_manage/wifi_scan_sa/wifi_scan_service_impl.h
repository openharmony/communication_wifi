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

#ifndef OHOS_WIFI_SCAN_SERVICE_H
#define OHOS_WIFI_SCAN_SERVICE_H

#ifdef OHOS_ARCH_LITE
#include "wifi_scan_stub_lite.h"
#else
#include "system_ability.h"
#include "wifi_scan_stub.h"
#include "iremote_object.h"
#endif

namespace OHOS {
namespace Wifi {
#ifdef OHOS_ARCH_LITE
enum ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
#endif

class WifiScanServiceImpl : public WifiScanStub {
public:
    WifiScanServiceImpl();
#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<WifiScanServiceImpl> GetInstance();
    void OnStart();
    void OnStop();
#else
    explicit WifiScanServiceImpl(int instId);
#endif
    virtual ~WifiScanServiceImpl();

    ErrCode SetScanControlInfo(const ScanControlInfo &info) override;
    ErrCode Scan(bool compatible) override;
    ErrCode PermissionVerification();
    ErrCode AdvanceScan(const WifiScanParams &params) override;
    ErrCode IsWifiClosedScan(bool &bOpen) override;
    ErrCode GetScanInfoList(std::vector<WifiScanInfo> &result, bool compatible) override;
    ErrCode SetScanOnlyAvailable(bool bScanOnlyAvailable) override;
    ErrCode GetScanOnlyAvailable(bool &bScanOnlyAvailable) override;
    ErrCode StartWifiPnoScan(bool isStartAction, int periodMs, int suspendReason) override;
#ifdef OHOS_ARCH_LITE
    ErrCode RegisterCallBack(const std::shared_ptr<IWifiScanCallback> &callback,
        const std::vector<std::string> &event) override;
#else
    ErrCode RegisterCallBack(const sptr<IWifiScanCallback> &callback, const std::vector<std::string> &event) override;
#endif
    ErrCode GetSupportedFeatures(long &features) override;
    bool IsRemoteDied(void) override;
    static void SaBasicDump(std::string& result);

private:
    bool Init();
    bool IsScanServiceRunning();
#ifndef OHOS_ARCH_LITE
    void UpdateScanMode();
#endif

private:
#ifdef OHOS_ARCH_LITE
    static std::mutex g_instanceLock;
    static std::shared_ptr<WifiScanServiceImpl> g_instance;
    ServiceRunningState mState;
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif
