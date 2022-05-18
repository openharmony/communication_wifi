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
#ifndef OHOS_I_WIFI_SCAN_CALLBACK_STUB_H
#define OHOS_I_WIFI_SCAN_CALLBACK_STUB_H

#ifdef OHOS_ARCH_LITE
#include "serializer.h"
#else
#include "iremote_stub.h"
#endif
#include "i_wifi_scan_callback.h"

namespace OHOS {
namespace Wifi {
#ifdef OHOS_ARCH_LITE
class WifiScanCallbackStub : public IWifiScanCallback {
#else
class WifiScanCallbackStub : public IRemoteStub<IWifiScanCallback> {
#endif
public:
    WifiScanCallbackStub();
    virtual ~WifiScanCallbackStub();
#ifdef OHOS_ARCH_LITE
    int OnRemoteRequest(uint32_t code, IpcIo *data);
#else
    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
#endif
    void OnWifiScanStateChanged(int state) override;
#ifdef OHOS_ARCH_LITE
    void RegisterCallBack(const std::shared_ptr<IWifiScanCallback> &userCallback);
#else
    void RegisterCallBack(const sptr<IWifiScanCallback> &userCallback);
#endif
    bool IsRemoteDied() const;
    void SetRemoteDied(bool val);

private:
#ifdef OHOS_ARCH_LITE
    int RemoteOnWifiScanStateChanged(uint32_t code, IpcIo *data);
    std::shared_ptr<IWifiScanCallback> userCallback_;
#else
    int RemoteOnWifiScanStateChanged(uint32_t code, MessageParcel &data, MessageParcel &reply);
    sptr<IWifiScanCallback> userCallback_;
#endif

    bool mRemoteDied;
};
}  // namespace Wifi
}  // namespace OHOS
#endif