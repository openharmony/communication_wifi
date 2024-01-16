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

#include "wifi_device_callback_proxy.h"
#include "wifi_logger.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"

DEFINE_WIFILOG_LABEL("WifiDeviceCallBackProxy");

namespace OHOS {
namespace Wifi {
WifiDeviceCallBackProxy::WifiDeviceCallBackProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IWifiDeviceCallBack>(impl)
{}

void WifiDeviceCallBackProxy::OnWifiStateChanged(int state)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnWifiStateChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(state);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_STATE_CHANGE), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_CBK_CMD_STATE_CHANGE), error);
        return;
    }
    return;
}

void WifiDeviceCallBackProxy::OnWifiConnectionChanged(int state, const WifiLinkedInfo &info)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnWifiConnectionChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(state);
    data.WriteInt32(info.networkId);
    data.WriteString(info.ssid);
    data.WriteString(info.bssid);
    data.WriteInt32(info.rssi);
    data.WriteInt32(info.band);
    data.WriteInt32(info.frequency);
    data.WriteInt32(info.linkSpeed);
    data.WriteString(info.macAddress);
    data.WriteInt32(info.ipAddress);
    data.WriteInt32((int)info.connState);
    data.WriteBool(info.ifHiddenSSID);
    data.WriteInt32(info.rxLinkSpeed);
    data.WriteInt32(info.txLinkSpeed);
    data.WriteInt32(info.chload);
    data.WriteInt32(info.snr);
    data.WriteInt32(info.isDataRestricted);
    data.WriteString(info.portalUrl);
    data.WriteInt32((int)info.supplicantState);
    data.WriteInt32((int)info.detailedState);
    data.WriteBool(info.isAncoConnected);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_CONNECTION_CHANGE), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_CBK_CMD_CONNECTION_CHANGE), error);
        return;
    }
    return;
}

void WifiDeviceCallBackProxy::OnWifiRssiChanged(int rssi)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnWifiRssiChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(rssi);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_RSSI_CHANGE), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_CBK_CMD_RSSI_CHANGE), error);
        return;
    }
    return;
}

void WifiDeviceCallBackProxy::OnWifiWpsStateChanged(int state, const std::string &pinCode)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnWifiWpsStateChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(state);
    data.WriteCString(pinCode.c_str());
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_WPS_STATE_CHANGE), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_CBK_CMD_WPS_STATE_CHANGE), error);
        return;
    }
    return;
}

void WifiDeviceCallBackProxy::OnStreamChanged(int direction)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnStreamChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(direction);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_STREAM_DIRECTION), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_CBK_CMD_STREAM_DIRECTION), error);
        return;
    }
    return;
}

void WifiDeviceCallBackProxy::OnDeviceConfigChanged(ConfigChange value)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnDeviceConfigChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32((int)value);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_DEVICE_CONFIG_CHANGE), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_CBK_CMD_DEVICE_CONFIG_CHANGE), error);
        return;
    }
    return;
}
}  // namespace Wifi
}  // namespace OHOS