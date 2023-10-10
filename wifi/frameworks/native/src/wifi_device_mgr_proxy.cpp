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

#include "wifi_device_mgr_proxy.h"
#include "ipc_types.h"
#include "message_option.h"
#include "message_parcel.h"
#include "wifi_logger.h"
#include "wifi_manager_service_ipc_interface_code.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiDeviceMgrProxy");
namespace OHOS {
namespace Wifi {
sptr<IRemoteObject> WifiDeviceMgrProxy::GetWifiRemote(int instId)
{
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return nullptr;
    }
    data.WriteInt32(instId);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_MGR_GET_DEVICE_SERVICE), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Get remote object instId %{public}d failed,error code is %{public}d", instId, error);
        return nullptr;
    }

    return reply.ReadRemoteObject();
}
}  // namespace Wifi
}  // namespace OHOS