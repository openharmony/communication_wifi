/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_DEVICE_MGR_SERVICE_H
#define OHOS_WIFI_DEVICE_MGR_SERVICE_H

#ifndef OHOS_ARCH_LITE
#include <map>
#include "iremote_stub.h"
#include "message_parcel.h"
#include "message_option.h"
#include "i_wifi_device_mgr.h"

namespace OHOS {
namespace Wifi {
class WifiDeviceMgrStub : public IRemoteStub<IWifiDeviceMgr> {
public:
    using FuncHandle = int (WifiDeviceMgrStub::*)(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    using FuncHandleMap = std::map<int, FuncHandle>;

    WifiDeviceMgrStub();
    virtual ~WifiDeviceMgrStub();
    virtual int OnRemoteRequest(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option) override;
    int GetWifiRemoteInner(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option);
    static FuncHandleMap funcHandleMap_;
};
}  // namespace Wifi
}  // namespace OHOS
#endif
#endif