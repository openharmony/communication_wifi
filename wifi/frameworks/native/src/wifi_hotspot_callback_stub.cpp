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

#include "wifi_hotspot_callback_stub.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_hisysevent.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_errcode.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiHotspotCallbackStub");
namespace OHOS {
namespace Wifi {
WifiHotspotCallbackStub::WifiHotspotCallbackStub() : userCallback_(nullptr), mRemoteDied(false)
{}

WifiHotspotCallbackStub::~WifiHotspotCallbackStub()
{}

int WifiHotspotCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("WifiHotspotCallbackStub::OnRemoteRequest!");
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        WIFI_LOGE("Hotspot callback stub token verification error: %{public}d", code);
        return WIFI_OPT_FAILED;
    }

    int exception = data.ReadInt32();
    if (exception) {
        return -1;
    }
    int ret = -1;
    switch (code) {
        case static_cast<uint32_t>(HotspotInterfaceCode::WIFI_CBK_CMD_HOTSPOT_STATE_CHANGE): {
            ret = RemoteOnHotspotStateChanged(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(HotspotInterfaceCode::WIFI_CBK_CMD_HOTSPOT_STATE_JOIN): {
            ret = RemoteOnHotspotStaJoin(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(HotspotInterfaceCode::WIFI_CBK_CMD_HOTSPOT_STATE_LEAVE): {
            ret = RemoteOnHotspotStaLeave(code, data, reply);
            break;
        }
        default: {
            ret = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
        }
    }
    return ret;
}

int WifiHotspotCallbackStub::RemoteOnHotspotStateChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int state = data.ReadInt32();
    OnHotspotStateChanged(state);
    return 0;
}

int WifiHotspotCallbackStub::RemoteOnHotspotStaJoin(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    const char *readStr = nullptr;
    StationInfo info;
    readStr = data.ReadCString();
    info.deviceName = (readStr != nullptr) ? readStr : "";
    readStr = data.ReadCString();
    info.bssid = (readStr != nullptr) ? readStr : "";
    info.bssidType = data.ReadInt32();
    readStr = data.ReadCString();
    info.ipAddr = (readStr != nullptr) ? readStr : "";
    OnHotspotStaJoin(info);
    return 0;
}

int WifiHotspotCallbackStub::RemoteOnHotspotStaLeave(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    const char *readStr = nullptr;
    StationInfo info;
    readStr = data.ReadCString();
    info.deviceName = (readStr != nullptr) ? readStr : "";
    readStr = data.ReadCString();
    info.bssid = (readStr != nullptr) ? readStr : "";
    info.bssidType = data.ReadInt32();
    readStr = data.ReadCString();
    info.ipAddr = (readStr != nullptr) ? readStr : "";
    OnHotspotStaLeave(info);
    return 0;
}

void WifiHotspotCallbackStub::RegisterCallBack(const sptr<IWifiHotspotCallback> &callBack)
{
    if (callBack == nullptr) {
        WIFI_LOGD("RegisterCallBack:callBack is nullptr!");
        return;
    }
    userCallback_ = callBack;
}

void WifiHotspotCallbackStub::OnHotspotStateChanged(int state)
{
    WIFI_LOGI("WifiHotspotCallbackStub::OnHotspotStateChanged, state:%{public}d.", state);
    if (userCallback_) {
        userCallback_->OnHotspotStateChanged(state);
    }
    WriteWifiEventReceivedHiSysEvent(HISYS_HOTSPOT_STATE_CHANGE, state);
}

void WifiHotspotCallbackStub::OnHotspotStaJoin(const StationInfo &info)
{
    WIFI_LOGI("WifiHotspotCallbackStub::OnHotspotStaJoin");
    if (userCallback_) {
        userCallback_->OnHotspotStaJoin(info);
    }
    WriteWifiEventReceivedHiSysEvent(HISYS_HOTSPOT_STA_JOIN, HISYS_EVENT_DEFAULT_VALUE);
}

void WifiHotspotCallbackStub::OnHotspotStaLeave(const StationInfo &info)
{
    WIFI_LOGI("WifiHotspotCallbackStub::OnHotspotStaLeave");
    if (userCallback_) {
        userCallback_->OnHotspotStaLeave(info);
    }
    WriteWifiEventReceivedHiSysEvent(HISYS_HOTSPOT_STA_LEAVE, HISYS_EVENT_DEFAULT_VALUE);
}

bool WifiHotspotCallbackStub::IsRemoteDied() const
{
    return mRemoteDied;
}

void WifiHotspotCallbackStub::SetRemoteDied(bool val)
{
    mRemoteDied = val;
}
}  // namespace Wifi
}  // namespace OHOS