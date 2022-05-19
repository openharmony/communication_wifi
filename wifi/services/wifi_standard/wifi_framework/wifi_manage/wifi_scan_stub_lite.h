/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_SCAN_STUB_LITE_H
#define OHOS_WIFI_SCAN_STUB_LITE_H

#include <map>
#include "i_wifi_scan.h"
#include "i_wifi_scan_callback.h"
#include "serializer.h"

namespace OHOS {
namespace Wifi {
class WifiScanStub : public IWifiScan {
public:
    WifiScanStub();
    virtual ~WifiScanStub() override;

    virtual int OnRemoteRequest(uint32_t code, IpcIo *req, IpcIo *reply);

protected:
    std::shared_ptr<IWifiScanCallback> GetCallback() const;

private:
    int OnSetScanControlInfo(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnScan(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnScanByParams(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnIsWifiClosedScan(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnGetScanInfoList(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnRegisterCallBack(uint32_t code, IpcIo *req, IpcIo *reply);
    int OnGetSupportedFeatures(uint32_t code, IpcIo *req, IpcIo *reply);

    std::shared_ptr<IWifiScanCallback> callback_;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
