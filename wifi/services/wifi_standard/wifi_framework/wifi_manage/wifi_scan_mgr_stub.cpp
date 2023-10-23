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

#include "wifi_scan_mgr_stub.h"
#include "wifi_logger.h"
#include "wifi_errcode.h"
#include "wifi_manager_service_ipc_interface_code.h"
DEFINE_WIFILOG_HOTSPOT_LABEL("WifiScanMgrStub");

namespace OHOS {
namespace Wifi {
WifiScanMgrStub::FuncHandleMap WifiScanMgrStub::funcHandleMap_ = {
    {static_cast<uint32_t>(ScanInterfaceCode::WIFI_MGR_GET_SCAN_SERVICE),
        &WifiScanMgrStub::GetWifiRemoteInner},
};

WifiScanMgrStub::WifiScanMgrStub()
{}

WifiScanMgrStub::~WifiScanMgrStub()
{}

int WifiScanMgrStub::GetWifiRemoteInner(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int instId = data.ReadInt32();
    sptr<IRemoteObject> obj = GetWifiRemote(instId);
    int ret = reply.WriteRemoteObject(obj);
    return ret;
}

int WifiScanMgrStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        WIFI_LOGE("device stub token verification error: %{public}d", code);
        return WIFI_OPT_FAILED;
    }
    FuncHandleMap::iterator iter = funcHandleMap_.find(code);
    if (iter == funcHandleMap_.end()) {
        WIFI_LOGE("not find function to deal, code %{public}u", code);
        reply.WriteInt32(0);
        reply.WriteInt32(WIFI_OPT_NOT_SUPPORTED);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    } else {
        return (this->*(iter->second))(code, data, reply, option);
    }
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS