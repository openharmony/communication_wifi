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
#include "wifi_device_callback_stub.h"
#include "define.h"
#include "wifi_hisysevent.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_errcode.h"

DEFINE_WIFILOG_LABEL("WifiDeviceCallBackStub");
namespace OHOS {
namespace Wifi {
WifiDeviceCallBackStub::WifiDeviceCallBackStub() : callback_(nullptr), mRemoteDied(false)
{}

WifiDeviceCallBackStub::~WifiDeviceCallBackStub()
{}

int WifiDeviceCallBackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGI("WifiDeviceCallBackStub::OnRemoteRequest, code:%{public}u!", code);
    if (mRemoteDied) {
        WIFI_LOGE("Failed to `%{public}s`,Remote service is died!", __func__);
        return -1;
    }

    if (data.ReadInterfaceToken() != GetDescriptor()) {
        WIFI_LOGE("Sta callback stub token verification error: %{public}d", code);
        return WIFI_OPT_FAILED;
    }

    int exception = data.ReadInt32();
    if (exception) {
        WIFI_LOGE("WifiDeviceCallBackStub::OnRemoteRequest, got exception: %{public}d!", exception);
        return WIFI_OPT_FAILED;
    }
    int ret = -1;
    switch (code) {
        case WIFI_CBK_CMD_STATE_CHANGE: {
            ret = RemoteOnWifiStateChanged(code, data, reply);
            break;
        }
        case WIFI_CBK_CMD_CONNECTION_CHANGE: {
            ret = RemoteOnWifiConnectionChanged(code, data, reply);
            break;
        }
        case WIFI_CBK_CMD_RSSI_CHANGE: {
            ret = RemoteOnWifiRssiChanged(code, data, reply);
            break;
        }
        case WIFI_CBK_CMD_WPS_STATE_CHANGE: {
            ret = RemoteOnWifiWpsStateChanged(code, data, reply);
            break;
        }
        case WIFI_CBK_CMD_STREAM_DIRECTION: {
            ret = RemoteOnStreamChanged(code, data, reply);
            break;
        }
        case WIFI_CBK_CMD_DEVICE_CONFIG_CHANGE: {
            ret = RemoteOnDeviceConfigChanged(code, data, reply);
            break;
        }
        default: {
            ret = IPCObjectStub::OnRemoteRequest(code, data, reply, option);
            break;
        }
    }
    return ret;
}

void WifiDeviceCallBackStub::RegisterUserCallBack(const sptr<IWifiDeviceCallBack> &callBack)
{
    if (callBack == nullptr) {
        WIFI_LOGE("RegisterUserCallBack:callBack is nullptr!");
        return;
    }
    callback_ = callBack;
}

bool WifiDeviceCallBackStub::IsRemoteDied() const
{
    return mRemoteDied;
}

void WifiDeviceCallBackStub::SetRemoteDied(bool val)
{
    mRemoteDied = val;
}

void WifiDeviceCallBackStub::OnWifiStateChanged(int state)
{
    WIFI_LOGI("WifiDeviceCallBackStub::OnWifiStateChanged, state:%{public}d!", state);

    if (callback_) {
        callback_->OnWifiStateChanged(state);
    }
    WriteWifiEventReceivedHiSysEvent(HISYS_STA_POWER_STATE_CHANGE, state);
}

void WifiDeviceCallBackStub::OnWifiConnectionChanged(int state, const WifiLinkedInfo &info)
{
    WIFI_LOGI("WifiDeviceCallBackStub::OnWifiConnectionChanged, state:%{public}d!", state);
    if (callback_) {
        callback_->OnWifiConnectionChanged(state, info);
    }
    WriteWifiEventReceivedHiSysEvent(HISYS_STA_CONN_STATE_CHANGE, state);
}

void WifiDeviceCallBackStub::OnWifiRssiChanged(int rssi)
{
    WIFI_LOGI("WifiDeviceCallBackStub::OnWifiRssiChanged, rssi:%{public}d!", rssi);
    if (callback_) {
        callback_->OnWifiRssiChanged(rssi);
    }
    WriteWifiEventReceivedHiSysEvent(HISYS_STA_RSSI_STATE_CHANGE, rssi);
}

void WifiDeviceCallBackStub::OnWifiWpsStateChanged(int state, const std::string &pinCode)
{
    WIFI_LOGI("WifiDeviceCallBackStub::OnWifiWpsStateChanged, state:%{public}d!", state);
    if (callback_) {
        callback_->OnWifiWpsStateChanged(state, pinCode);
    }
}

void WifiDeviceCallBackStub::OnStreamChanged(int direction)
{
    WIFI_LOGI("WifiDeviceCallBackStub::OnStreamChanged, direction:%{public}d!", direction);
    if (callback_) {
        callback_->OnStreamChanged(direction);
    }
}

void WifiDeviceCallBackStub::OnDeviceConfigChanged(ConfigChange value)
{
    WIFI_LOGI("WifiDeviceCallBackStub::OnDeviceConfigChanged, value:%{public}d!", value);
    if (callback_) {
        callback_->OnDeviceConfigChanged(value);
    }
}

int WifiDeviceCallBackStub::RemoteOnWifiStateChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int state = data.ReadInt32();
    OnWifiStateChanged(state);
    reply.WriteInt32(0); /* Reply 0 to indicate that no exception occurs. */
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnWifiConnectionChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int state = data.ReadInt32();
    WifiLinkedInfo info;
    info.networkId = data.ReadInt32();
    info.ssid = data.ReadString();
    info.bssid = data.ReadString();
    info.rssi = data.ReadInt32();
    info.band = data.ReadInt32();
    info.frequency = data.ReadInt32();
    info.linkSpeed = data.ReadInt32();
    info.macAddress = data.ReadString();
    info.ipAddress = data.ReadInt32();
    int tmpConnState = data.ReadInt32();
    if (tmpConnState >= 0 && tmpConnState <= int(ConnState::UNKNOWN)) {
        info.connState = ConnState(tmpConnState);
    } else {
        info.connState = ConnState::UNKNOWN;
    }
    info.ifHiddenSSID = data.ReadBool();
    info.rxLinkSpeed = data.ReadInt32();
    info.txLinkSpeed = data.ReadInt32();
    info.chload = data.ReadInt32();
    info.snr = data.ReadInt32();
    info.isDataRestricted = data.ReadInt32();
    info.portalUrl = data.ReadString();
    int tmpState = data.ReadInt32();
    if (tmpState >= 0 && tmpState <= int(SupplicantState::INVALID)) {
        info.supplicantState = SupplicantState(tmpState);
    } else {
        info.supplicantState = SupplicantState::INVALID;
    }

    int tmpDetailState = data.ReadInt32();
    if (tmpDetailState >= 0 && tmpDetailState <= int(DetailedState::INVALID)) {
        info.detailedState = DetailedState(tmpDetailState);
    } else {
        info.detailedState = DetailedState::INVALID;
    }
    OnWifiConnectionChanged(state, info);
    reply.WriteInt32(0); /* Reply 0 to indicate that no exception occurs. */
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnWifiRssiChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int rssi = data.ReadInt32();
    OnWifiRssiChanged(rssi);
    reply.WriteInt32(0); /* Reply 0 to indicate that no exception occurs. */
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnWifiWpsStateChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    const char *readStr = nullptr;
    int state = data.ReadInt32();
    readStr = data.ReadCString();
    std::string pinCode = (readStr != nullptr) ? readStr : "";
    OnWifiWpsStateChanged(state, pinCode);
    reply.WriteInt32(0); /* Reply 0 to indicate that no exception occurs. */
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnStreamChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int direction = data.ReadInt32();
    OnStreamChanged(direction);
    reply.WriteInt32(0); /* Reply 0 to indicate that no exception occurs. */
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnDeviceConfigChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int value = data.ReadInt32();
    OnDeviceConfigChanged(ConfigChange(value));
    reply.WriteInt32(0); /* Reply 0 to indicate that no exception occurs. */
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS