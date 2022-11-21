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

int WifiDeviceCallBackStub::OnRemoteInterfaceToken(uint32_t code, IpcIo *data)
{
    size_t length;
    uint16_t* interfaceRead = nullptr;
    interfaceRead = ReadInterfaceToken(data, &length);
    for (size_t i = 0; i < length; i++) {
        if (i >= DECLARE_INTERFACE_DESCRIPTOR_L1_LENGTH || interfaceRead[i] != DECLARE_INTERFACE_DESCRIPTOR_L1[i]) {
            WIFI_LOGE("Sta stub token verification error: %{public}d", code);
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

int WifiDeviceCallBackStub::OnRemoteRequest(uint32_t code, IpcIo *data)
{
    int ret = WIFI_OPT_FAILED;
    WIFI_LOGD("OnRemoteRequest code:%{public}u!", code);
    if (mRemoteDied || data == nullptr) {
        WIFI_LOGE("Failed to %{public}s,mRemoteDied:%{public}d data:%{public}d!",
            __func__, mRemoteDied, data == nullptr);
        return ret;
    }

    if (OnRemoteInterfaceToken(code, data) == WIFI_OPT_FAILED) {
        return WIFI_OPT_FAILED;
    }
    int exception = WIFI_OPT_FAILED;
    (void)ReadInt32(data, &exception);
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
        case WIFI_CBK_CMD_DEVICE_CONFIG_CHANGE: {
            ret = RemoteOnDeviceConfigChanged(code, data);
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

void WifiDeviceCallBackStub::OnDeviceConfigChanged(ConfigChange state)
{
    WIFI_LOGD("WifiDeviceCallBackStub::OnDeviceConfigChanged");
    if (callback_) {
        callback_->OnDeviceConfigChanged(state);
    }
}

int WifiDeviceCallBackStub::RemoteOnWifiStateChanged(uint32_t code, IpcIo *data)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int state = 0;
    (void)ReadInt32(data, &state);
    OnWifiStateChanged(state);
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnWifiConnectionChanged(uint32_t code, IpcIo *data)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    size_t readLen;
    int state = 0;
    (void)ReadInt32(data, &state);
    WifiLinkedInfo info;
    (void)ReadInt32(data, &info.networkId);
    info.ssid = (char *)ReadString(data, &readLen);
    info.bssid = (char *)ReadString(data, &readLen);
    (void)ReadInt32(data, &info.rssi);
    (void)ReadInt32(data, &info.band);
    (void)ReadInt32(data, &info.frequency);
    (void)ReadInt32(data, &info.linkSpeed);
    info.macAddress = (char *)ReadString(data, &readLen);
    (void)ReadUint32(data, &info.ipAddress);
    int tmpConnState = 0;
    (void)ReadInt32(data, &tmpConnState);
    if (tmpConnState >= 0 && tmpConnState <= int(ConnState::UNKNOWN)) {
        info.connState = ConnState(tmpConnState);
    } else {
        info.connState = ConnState::UNKNOWN;
    }
    (void)ReadBool(data, &info.ifHiddenSSID);
    (void)ReadInt32(data, &info.rxLinkSpeed);
    (void)ReadInt32(data, &info.txLinkSpeed);
    (void)ReadInt32(data, &info.chload);
    (void)ReadInt32(data, &info.snr);
    (void)ReadInt32(data, &info.isDataRestricted);
    info.portalUrl = (char *)ReadString(data, &readLen);
    int tmpState = 0;
    (void)ReadInt32(data, &tmpState);
    if (tmpState >= 0 && tmpState <= int(SupplicantState::INVALID)) {
        info.supplicantState = SupplicantState(tmpState);
    } else {
        info.supplicantState = SupplicantState::INVALID;
    }

    int tmpDetailState = 0;
    (void)ReadInt32(data, &tmpDetailState);
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
    int rssi = 0;
    (void)ReadInt32(data, &rssi);
    OnWifiRssiChanged(rssi);
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnWifiWpsStateChanged(uint32_t code, IpcIo *data)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    size_t readLen;
    int state = 0;
    (void)ReadInt32(data, &state);
    std::string pinCode = (char *)ReadString(data, &readLen);
    OnWifiWpsStateChanged(state, pinCode);
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnStreamChanged(uint32_t code, IpcIo *data)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int direction = 0;
    (void)ReadInt32(data, &direction);
    OnStreamChanged(direction);
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnDeviceConfigChanged(uint32_t code, IpcIo *data)
{
    WIFI_LOGD("run %{public}s code %{public}u", __func__, code);
    int state = 0;
    (void)ReadInt32(data, &state);
    OnDeviceConfigChanged(ConfigChange(state));
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS
