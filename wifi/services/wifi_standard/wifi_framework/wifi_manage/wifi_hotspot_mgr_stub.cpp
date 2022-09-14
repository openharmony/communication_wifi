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

#include "wifi_hotspot_mgr_stub.h"
#include "wifi_logger.h"
#include "wifi_errcode.h"
DEFINE_WIFILOG_HOTSPOT_LABEL("WifiHotspotMgrStub");

namespace OHOS {
namespace Wifi {
WifiHotspotMgrStub::FuncHandleMap WifiHotspotMgrStub::funcHandleMap_ = {
    {WIFI_MGR_GET_HOTSPOT_SERVICE, &WifiHotspotMgrStub::GetWifiRemoteInner},
};

WifiHotspotMgrStub::WifiHotspotMgrStub()
{}

WifiHotspotMgrStub::~WifiHotspotMgrStub()
{}

int WifiHotspotMgrStub::GetWifiRemoteInner(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    int id = data.ReadInt32();
    sptr<IRemoteObject> obj = GetWifiRemote(id);
    int ret = reply.WriteRemoteObject(obj);
    return ret;
}

int WifiHotspotMgrStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        WIFI_LOGE("Hotspot stub token verification error: %{public}d", code);
        return WIFI_OPT_FAILED;
    }
    FuncHandleMap::iterator iter = funcHandleMap_.find(code);
    if (iter == funcHandleMap_.end()) {
        WIFI_LOGE("not find function to deal, code %{public}u", code);
        return WIFI_OPT_NOT_SUPPORTED;
    } else {
        return (this->*(iter->second))(code, data, reply, option);
    }
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS
