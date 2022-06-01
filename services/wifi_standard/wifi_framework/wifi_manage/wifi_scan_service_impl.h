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
enum ServiceRunningState {
    STATE_NOT_START,
    STATE_RUNNING
};

#ifdef OHOS_ARCH_LITE
class WifiScanServiceImpl : public WifiScanStub {
#else
class WifiScanServiceImpl : public SystemAbility, public WifiScanStub {
    DECLARE_SYSTEM_ABILITY(WifiScanServiceImpl);
#endif

public:
    WifiScanServiceImpl();
    virtual ~WifiScanServiceImpl();

#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<WifiScanServiceImpl> GetInstance();

    void OnStart();
    void OnStop();
#else
    static sptr<WifiScanServiceImpl> GetInstance();

    void OnStart() override;
    void OnStop() override;
#endif

    ErrCode SetScanControlInfo(const ScanControlInfo &info) override;
    ErrCode Scan() override;
    ErrCode AdvanceScan(const WifiScanParams &params) override;
    ErrCode IsWifiClosedScan(bool &bOpen) override;
    ErrCode GetScanInfoList(std::vector<WifiScanInfo> &result) override;
#ifdef OHOS_ARCH_LITE
    ErrCode RegisterCallBack(const std::shared_ptr<IWifiScanCallback> &callback) override;
#else
    ErrCode RegisterCallBack(const sptr<IWifiScanCallback> &callback) override;
#endif
    ErrCode GetSupportedFeatures(long &features) override;

private:
    bool Init();
    bool IsScanServiceRunning();

private:
#ifdef OHOS_ARCH_LITE
    static std::shared_ptr<WifiScanServiceImpl> g_instance;
#else
    static sptr<WifiScanServiceImpl> g_instance;
#endif
    static std::mutex g_instanceLock;
    bool mPublishFlag = false;
    ServiceRunningState mState;
};
}  // namespace Wifi
}  // namespace OHOS
#endif