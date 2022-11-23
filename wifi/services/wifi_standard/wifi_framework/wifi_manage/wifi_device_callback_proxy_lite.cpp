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

#include "wifi_device_callback_proxy.h"
#include "define.h"
#include "ipc_skeleton.h"
#include "rpc_errno.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiDeviceCallBackProxy");

namespace OHOS {
namespace Wifi {

WifiDeviceCallBackProxy::WifiDeviceCallBackProxy(SvcIdentity *sid) : sid_(*sid)
{}

WifiDeviceCallBackProxy::~WifiDeviceCallBackProxy()
{
    ReleaseSvc(sid_);
}

void WifiDeviceCallBackProxy::OnWifiStateChanged(int state)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnWifiStateChanged");
    IpcIo data;
    uint8_t buff[DEFAULT_IPC_SIZE];
    IpcIoInit(&data, buff, DEFAULT_IPC_SIZE, 0);
    if (!WriteInterfaceToken(&data, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    (void)WriteInt32(&data, 0);
    (void)WriteInt32(&data, state);

    IpcIo reply;
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int ret = SendRequest(sid_, WIFI_CBK_CMD_STATE_CHANGE, &data, &reply, option, nullptr);
    if (ret != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_CBK_CMD_STATE_CHANGE, ret);
    }
}

void WifiDeviceCallBackProxy::OnWifiConnectionChanged(int state, const WifiLinkedInfo &info)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnWifiConnectionChanged");
    IpcIo data;
    constexpr int IPC_DATA_SIZE = 1024;
    uint8_t buff[IPC_DATA_SIZE];
    IpcIoInit(&data, buff, IPC_DATA_SIZE, 0);
    if (!WriteInterfaceToken(&data, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    (void)WriteInt32(&data, 0);
    (void)WriteInt32(&data, state);
    (void)WriteInt32(&data, info.networkId);
    (void)WriteString(&data, info.ssid.c_str());
    (void)WriteString(&data, info.bssid.c_str());
    (void)WriteInt32(&data, info.rssi);
    (void)WriteInt32(&data, info.band);
    (void)WriteInt32(&data, info.frequency);
    (void)WriteInt32(&data, info.linkSpeed);
    (void)WriteString(&data, info.macAddress.c_str());
    (void)WriteUint32(&data, info.ipAddress);
    (void)WriteInt32(&data, (int)info.connState);
    (void)WriteBool(&data, info.ifHiddenSSID);
    (void)WriteInt32(&data, info.rxLinkSpeed);
    (void)WriteInt32(&data, info.txLinkSpeed);
    (void)WriteInt32(&data, info.chload);
    (void)WriteInt32(&data, info.snr);
    (void)WriteInt32(&data, info.isDataRestricted);
    (void)WriteString(&data, info.portalUrl.c_str());
    (void)WriteInt32(&data, (int)info.supplicantState);
    (void)WriteInt32(&data, (int)info.detailedState);

    IpcIo reply;
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int ret = SendRequest(sid_, WIFI_CBK_CMD_CONNECTION_CHANGE, &data, &reply, option, nullptr);
    if (ret != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_CBK_CMD_CONNECTION_CHANGE, ret);
    }
}

void WifiDeviceCallBackProxy::OnWifiRssiChanged(int rssi)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnWifiRssiChanged");
    IpcIo data;
    uint8_t buff[DEFAULT_IPC_SIZE];
    IpcIoInit(&data, buff, DEFAULT_IPC_SIZE, 0);
    if (!WriteInterfaceToken(&data, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    (void)WriteInt32(&data, 0);
    (void)WriteInt32(&data, rssi);

    IpcIo reply;
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int ret = SendRequest(sid_, WIFI_CBK_CMD_RSSI_CHANGE, &data, &reply, option, nullptr);
    if (ret != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_CBK_CMD_RSSI_CHANGE, ret);
    }
}

void WifiDeviceCallBackProxy::OnWifiWpsStateChanged(int state, const std::string &pinCode)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnWifiWpsStateChanged");
    IpcIo data;
    uint8_t buff[DEFAULT_IPC_SIZE];
    IpcIoInit(&data, buff, DEFAULT_IPC_SIZE, 0);
    if (!WriteInterfaceToken(&data, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    (void)WriteInt32(&data, 0);
    (void)WriteInt32(&data, state);
    (void)WriteString(&data, pinCode.c_str());

    IpcIo reply;
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int ret = SendRequest(sid_, WIFI_CBK_CMD_WPS_STATE_CHANGE, &data, &reply, option, nullptr);
    if (ret != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_CBK_CMD_WPS_STATE_CHANGE, ret);
    }
}

void WifiDeviceCallBackProxy::OnStreamChanged(int direction)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnStreamChanged");
    IpcIo data;
    uint8_t buff[DEFAULT_IPC_SIZE];
    IpcIoInit(&data, buff, DEFAULT_IPC_SIZE, 0);
    if (!WriteInterfaceToken(&data, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    (void)WriteInt32(&data, 0);
    (void)WriteInt32(&data, direction);

    IpcIo reply;
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int ret = SendRequest(sid_, WIFI_CBK_CMD_STREAM_DIRECTION, &data, &reply, option, nullptr);
    if (ret != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_CBK_CMD_STREAM_DIRECTION, ret);
    }
}

void WifiDeviceCallBackProxy::OnDeviceConfigChanged(ConfigChange state)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnDeviceConfigChanged");
    IpcIo data;
    uint8_t buff[DEFAULT_IPC_SIZE];
    IpcIoInit(&data, buff, DEFAULT_IPC_SIZE, 0);
    if (!WriteInterfaceToken(&data, DECLARE_INTERFACE_DESCRIPTOR_L1, DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH)) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    (void)WriteInt32(&data, 0);
    (void)WriteInt32(&data, static_cast<int>(state));

    IpcIo reply;
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = TF_OP_ASYNC;
    int ret = SendRequest(sid_, WIFI_CBK_CMD_DEVICE_CONFIG_CHANGE, &data, &reply, option, nullptr);
    if (ret != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_CBK_CMD_DEVICE_CONFIG_CHANGE, ret);
    }
}
}  // namespace Wifi
}  // namespace OHOS
