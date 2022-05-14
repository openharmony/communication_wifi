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
#include "liteipc_adapter.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiDeviceCallBackProxy");

namespace OHOS {
namespace Wifi {
WifiDeviceCallBackProxy::WifiDeviceCallBackProxy(SvcIdentity *sid) : sid_(sid)
{}

WifiDeviceCallBackProxy::~WifiDeviceCallBackProxy()
{
    if (sid_ != nullptr) {
#ifdef __LINUX__
        BinderRelease(sid_->ipcContext, sid_->handle);
#endif
        free(sid_);
        sid_ = nullptr;
    }
}

void WifiDeviceCallBackProxy::OnWifiStateChanged(int state)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnWifiStateChanged");
    IpcIo data;
    uint8_t buff[DEFAULT_IPC_SIZE];
    IpcIoInit(&data, buff, DEFAULT_IPC_SIZE, 0);
    IpcIoPushInt32(&data, 0);
    IpcIoPushInt32(&data, state);
    int ret = Transact(nullptr, *sid_, WIFI_CBK_CMD_STATE_CHANGE, &data, nullptr, LITEIPC_FLAG_ONEWAY, nullptr);
    if (ret != LITEIPC_OK) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_CBK_CMD_STATE_CHANGE, ret);
    }
}

void WifiDeviceCallBackProxy::OnWifiConnectionChanged(int state, const WifiLinkedInfo &info)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnWifiConnectionChanged");
    constexpr int IPC_DATA_SIZE = 1024;
    IpcIo data;
    uint8_t buff[IPC_DATA_SIZE];
    IpcIoInit(&data, buff, IPC_DATA_SIZE, 0);
    IpcIoPushInt32(&data, 0);
    IpcIoPushInt32(&data, state);
    IpcIoPushInt32(&data, info.networkId);
    IpcIoPushString(&data, info.ssid.c_str());
    IpcIoPushString(&data, info.bssid.c_str());
    IpcIoPushInt32(&data, info.rssi);
    IpcIoPushInt32(&data, info.band);
    IpcIoPushInt32(&data, info.frequency);
    IpcIoPushInt32(&data, info.linkSpeed);
    IpcIoPushString(&data, info.macAddress.c_str());
    IpcIoPushInt32(&data, info.ipAddress);
    IpcIoPushInt32(&data, (int)info.connState);
    IpcIoPushBool(&data, info.ifHiddenSSID);
    IpcIoPushString(&data, info.rxLinkSpeed.c_str());
    IpcIoPushString(&data, info.txLinkSpeed.c_str());
    IpcIoPushInt32(&data, info.chload);
    IpcIoPushInt32(&data, info.snr);
    IpcIoPushInt32(&data, (int)info.supplicantState);
    IpcIoPushInt32(&data, (int)info.detailedState);
    int ret = Transact(nullptr, *sid_, WIFI_CBK_CMD_CONNECTION_CHANGE, &data, nullptr, LITEIPC_FLAG_ONEWAY, nullptr);
    if (ret != LITEIPC_OK) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_CBK_CMD_CONNECTION_CHANGE, ret);
    }
}

void WifiDeviceCallBackProxy::OnWifiRssiChanged(int rssi)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnWifiRssiChanged");
    IpcIo data;
    uint8_t buff[DEFAULT_IPC_SIZE];
    IpcIoInit(&data, buff, DEFAULT_IPC_SIZE, 0);
    IpcIoPushInt32(&data, 0);
    IpcIoPushInt32(&data, rssi);
    int ret = Transact(nullptr, *sid_, WIFI_CBK_CMD_RSSI_CHANGE, &data, nullptr, LITEIPC_FLAG_ONEWAY, nullptr);
    if (ret != LITEIPC_OK) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_CBK_CMD_RSSI_CHANGE, ret);
    }
}

void WifiDeviceCallBackProxy::OnWifiWpsStateChanged(int state, const std::string &pinCode)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnWifiWpsStateChanged");
    IpcIo data;
    uint8_t buff[DEFAULT_IPC_SIZE];
    IpcIoInit(&data, buff, DEFAULT_IPC_SIZE, 0);
    IpcIoPushInt32(&data, 0);
    IpcIoPushInt32(&data, state);
    IpcIoPushString(&data, pinCode.c_str());
    int ret = Transact(nullptr, *sid_, WIFI_CBK_CMD_WPS_STATE_CHANGE, &data, nullptr, LITEIPC_FLAG_ONEWAY, nullptr);
    if (ret != LITEIPC_OK) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_CBK_CMD_WPS_STATE_CHANGE, ret);
    }
}

void WifiDeviceCallBackProxy::OnStreamChanged(int direction)
{
    WIFI_LOGD("WifiDeviceCallBackProxy::OnStreamChanged");
    IpcIo data;
    uint8_t buff[DEFAULT_IPC_SIZE];
    IpcIoInit(&data, buff, DEFAULT_IPC_SIZE, 0);
    IpcIoPushInt32(&data, 0);
    IpcIoPushInt32(&data, direction);
    int ret = Transact(nullptr, *sid_, WIFI_CBK_CMD_STREAM_DIRECTION, &data, nullptr, LITEIPC_FLAG_ONEWAY, nullptr);
    if (ret != LITEIPC_OK) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_CBK_CMD_STREAM_DIRECTION, ret);
    }
}
}  // namespace Wifi
}  // namespace OHOS
