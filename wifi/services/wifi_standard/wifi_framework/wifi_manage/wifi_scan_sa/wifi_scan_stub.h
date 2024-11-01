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

#ifndef OHOS_WIFI_SCAN_STUB_H
#define OHOS_WIFI_SCAN_STUB_H

#include <map>
#include "iremote_stub.h"
#include "i_wifi_scan.h"

namespace OHOS {
namespace Wifi {
class WifiScanStub : public IRemoteStub<IWifiScan> {
public:
    using handleFunc = std::function<int
        (uint32_t, MessageParcel &, MessageParcel &, MessageOption &)>;
    using HandleFuncMap = std::map<int, handleFunc>;
    WifiScanStub();
    explicit WifiScanStub(int instId);
    virtual ~WifiScanStub() override;

    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    bool IsSingleCallback() const;
    void SetSingleCallback(const bool isSingleCallback);

private:
    void InitHandleMap();
    int OnSetScanControlInfo(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnScan(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnScanByParams(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnIsWifiClosedScan(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnGetScanInfoList(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnRegisterCallBack(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnGetSupportedFeatures(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnSetScanOnlyAvailable(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnGetScanOnlyAvailable(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int OnStartWifiPnoScan(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    void SendScanInfo(int32_t contentSize, std::vector<WifiScanInfo> &result, MessageParcel &reply);
    std::mutex deathRecipientMutex;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
    HandleFuncMap handleFuncMap;
    bool mSingleCallback;

protected:
    int m_instId{0};
};
}  // namespace Wifi
}  // namespace OHOS
#endif
