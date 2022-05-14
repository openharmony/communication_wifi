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
#include "wifi_device_callback_stub_lite.h"
#include "define.h"
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

int WifiDeviceCallBackStub::OnRemoteRequest(uint32_t code, IpcIo *data)
{
    int ret = WIFI_OPT_FAILED;
    WIFI_LOGD("OnRemoteRequest code:%{public}u!", code);
    if (mRemoteDied || data == nullptr) {
        WIFI_LOGD("Failed to %{public}s,mRemoteDied:%{public}d data:%{public}d!",
            __func__, mRemoteDied, data == nullptr);
        return ret;
    }

    int exception = IpcIoPopInt32(data);
    if (exception) {
        WIFI_LOGE("WifiDeviceCallBackStub::OnRemoteRequest, got exception: %{public}d!", exception);
        return ret;
    }
    switch (code) {
        case WIFI_CBK_CMD_STATE_CHANGE: {
            ret = RemoteOnWifiStateChanged(code, data);
            break;
        }
        case WIFI_CBK_CMD_CONNECTION_CHANGE: {
            ret = RemoteOnWifiConnectionChanged(code, data);
            break;
        }
        case WIFI_CBK_CMD_RSSI_CHANGE: {
            ret = RemoteOnWifiRssiChanged(code, data);
            break;
        }
        case WIFI_CBK_CMD_WPS_STATE_CHANGE: {
            ret = RemoteOnWifiWpsStateChanged(code, data);
            break;
        }
        case WIFI_CBK_CMD_STREAM_DIRECTION: {
            ret = RemoteOnStreamChanged(code, data);
            break;
        }
        default: {
            ret = WIFI_OPT_FAILED;
        }
    }
    return ret;
}

void WifiDeviceCallBackStub::RegisterUserCallBack(const std::shared_ptr<IWifiDeviceCallBack> &callBack)
{
    if (callBack == nullptr) {
        WIFI_LOGD("RegisterUserCallBack:callBack is nullptr!");
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
    WIFI_LOGD("WifiDeviceCallBackStub::OnWifiStateChanged");

    if (callback_) {
        callback_->OnWifiStateChanged(state);
    }
}

void WifiDeviceCallBackStub::OnWifiConnectionChanged(int state, const WifiLinkedInfo &info)
{
    WIFI_LOGD("WifiDeviceCallBackStub::OnWifiConnectionChanged");
    if (callback_) {
        callback_->OnWifiConnectionChanged(state, info);
    }
}

void WifiDeviceCallBackStub::OnWifiRssiChanged(int rssi)
{
    WIFI_LOGD("WifiDeviceCallBackStub::OnWifiRssiChanged");
    if (callback_) {
        callback_->OnWifiRssiChanged(rssi);
    }
}

void WifiDeviceCallBackStub::OnWifiWpsStateChanged(int state, const std::string &pinCode)
{
    WIFI_LOGD("WifiDeviceCallBackStub::OnWifiWpsStateChanged");
    if (callback_) {
        callback_->OnWifiWpsStateChanged(state, pinCode);
    }
}

void WifiDeviceCallBackStub::OnStreamChanged(int direction)
{
    WIFI_LOGD("WifiDeviceCallBackStub::OnStreamChanged");
    if (callback_) {
        callback_->OnStreamChanged(direction);
    }
}

int WifiDeviceCallBackStub::RemoteOnWifiStateChanged(uint32_t code, IpcIo *data)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int state = IpcIoPopInt32(data);
    OnWifiStateChanged(state);
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnWifiConnectionChanged(uint32_t code, IpcIo *data)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    size_t readLen;
    int state = IpcIoPopInt32(data);
    WifiLinkedInfo info;
    info.networkId = IpcIoPopInt32(data);
    info.ssid = (char *)IpcIoPopString(data, &readLen);
    info.bssid = (char *)IpcIoPopString(data, &readLen);
    info.rssi = IpcIoPopInt32(data);
    info.band = IpcIoPopInt32(data);
    info.frequency = IpcIoPopInt32(data);
    info.linkSpeed = IpcIoPopInt32(data);
    info.macAddress = (char *)IpcIoPopString(data, &readLen);
    info.ipAddress = IpcIoPopInt32(data);
    int tmpConnState = IpcIoPopInt32(data);
    if (tmpConnState >= 0 && tmpConnState <= int(ConnState::FAILED)) {
        info.connState = ConnState(tmpConnState);
    } else {
        info.connState = ConnState::FAILED;
    }
    info.ifHiddenSSID = IpcIoPopBool(data);
    info.rxLinkSpeed = (char *)IpcIoPopString(data, &readLen);
    info.txLinkSpeed = (char *)IpcIoPopString(data, &readLen);
    info.chload = IpcIoPopInt32(data);
    info.snr = IpcIoPopInt32(data);
    int tmpState = IpcIoPopInt32(data);
    if (tmpState >= 0 && tmpState <= int(SupplicantState::INVALID)) {
        info.supplicantState = SupplicantState(tmpState);
    } else {
        info.supplicantState = SupplicantState::INVALID;
    }

    int tmpDetailState = IpcIoPopInt32(data);
    if (tmpDetailState >= 0 && tmpDetailState <= int(DetailedState::INVALID)) {
        info.detailedState = DetailedState(tmpDetailState);
    } else {
        info.detailedState = DetailedState::INVALID;
    }
    OnWifiConnectionChanged(state, info);
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnWifiRssiChanged(uint32_t code, IpcIo *data)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int rssi = IpcIoPopInt32(data);
    OnWifiRssiChanged(rssi);
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnWifiWpsStateChanged(uint32_t code, IpcIo *data)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    size_t readLen;
    int state = IpcIoPopInt32(data);
    std::string pinCode = (char *)IpcIoPopString(data, &readLen);
    OnWifiWpsStateChanged(state, pinCode);
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnStreamChanged(uint32_t code, IpcIo *data)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int direction = IpcIoPopInt32(data);
    OnStreamChanged(direction);
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS
