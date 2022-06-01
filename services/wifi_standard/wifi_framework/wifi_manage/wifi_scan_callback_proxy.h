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
#ifndef OHOS_I_WIFI_SCAN_CALLBACK_PROXY_H
#define OHOS_I_WIFI_SCAN_CALLBACK_PROXY_H

#include "i_wifi_scan_callback.h"
#ifdef OHOS_ARCH_LITE
#include "serializer.h"
#else
#include "iremote_proxy.h"
#endif

namespace OHOS {
namespace Wifi {
#ifdef OHOS_ARCH_LITE
class WifiScanCallbackProxy : public IWifiScanCallback {
public:
    explicit WifiScanCallbackProxy(SvcIdentity *sid);
#else
class WifiScanCallbackProxy : public IRemoteProxy<IWifiScanCallback> {
public:
    explicit WifiScanCallbackProxy(const sptr<IRemoteObject> &impl);
#endif

    virtual ~WifiScanCallbackProxy();

    void OnWifiScanStateChanged(int state) override;

private:
#ifdef OHOS_ARCH_LITE
    SvcIdentity *sid_;
    static const int DEFAULT_IPC_SIZE = 256;
#else
    static inline BrokerDelegator<WifiScanCallbackProxy> g_delegator;
#endif
};
}  // namespace Wifi
}  // namespace OHOS
#endif
