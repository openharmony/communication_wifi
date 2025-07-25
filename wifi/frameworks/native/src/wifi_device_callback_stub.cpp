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
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_hisysevent.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_errcode.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_LABEL("WifiDeviceCallBackStub");
namespace OHOS {
namespace Wifi {
static const int CALLBACK_LIMIT = 1000;
WifiDeviceCallBackStub::WifiDeviceCallBackStub() : callbackMap_ {}, mRemoteDied(false)
{}

WifiDeviceCallBackStub::~WifiDeviceCallBackStub()
{}

int WifiDeviceCallBackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("OnRemoteRequest, code:%{public}u!", code);

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
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_STATE_CHANGE): {
            ret = RemoteOnWifiStateChanged(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_CONNECTION_CHANGE): {
            ret = RemoteOnWifiConnectionChanged(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_RSSI_CHANGE): {
            ret = RemoteOnWifiRssiChanged(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_WPS_STATE_CHANGE): {
            ret = RemoteOnWifiWpsStateChanged(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_STREAM_DIRECTION): {
            ret = RemoteOnStreamChanged(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_CBK_CMD_DEVICE_CONFIG_CHANGE): {
            ret = RemoteOnDeviceConfigChanged(code, data, reply);
            break;
        }
        case static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CANDIDATE_CONNECT_APPROVAL): {
            ret = RemoteOnCandidateApprovalStatusChanged(code, data, reply);
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

    if (callbackMap_.size() >= CALLBACK_LIMIT &&
        callbackMap_.find(callBack->name) == callbackMap_.end()) {
        WIFI_LOGE("RegisterUserCallBack:callBack %{public}s reaches number limit!", callBack->name.c_str());
        return;
    }
    callbackMap_[callBack->name] = callBack;
}

bool WifiDeviceCallBackStub::IsRemoteDied() const
{
    return mRemoteDied;
}

void WifiDeviceCallBackStub::SetRemoteDied(bool val)
{
    WIFI_LOGI("SetRemoteDied, state:%{public}d!", val);
    mRemoteDied = val;
}
void WifiDeviceCallBackStub::SetWifiState(int val)
{
    mState_ = val;
}

int WifiDeviceCallBackStub::GetWifiState()
{
    return mState_;
}

NO_SANITIZE("cfi") void WifiDeviceCallBackStub::OnWifiStateChanged(int state)
{
    WIFI_LOGI("OnWifiStateChanged, state:%{public}d!", state);
    if (state == static_cast<int>(WifiState::ENABLED)) {
        mState_ = true;
    } else {
        mState_ = false;
    }

    for (auto& pair : callbackMap_) {
        if (pair.second) {
            pair.second->OnWifiStateChanged(state);
        }
    }
    WriteWifiEventReceivedHiSysEvent(HISYS_STA_POWER_STATE_CHANGE, state);
}

NO_SANITIZE("cfi") void WifiDeviceCallBackStub::OnWifiConnectionChanged(int state, const WifiLinkedInfo &info)
{
    WIFI_LOGI("OnWifiConnectionChanged, state:%{public}d!", state);
    for (auto& pair : callbackMap_) {
        if (pair.second) {
            pair.second->OnWifiConnectionChanged(state, info);
        }
    }
    WriteWifiEventReceivedHiSysEvent(HISYS_STA_CONN_STATE_CHANGE, state);
}

NO_SANITIZE("cfi") void WifiDeviceCallBackStub::OnWifiRssiChanged(int rssi)
{
    WIFI_LOGI("OnWifiRssiChanged, rssi:%{public}d!", rssi);
    for (auto& pair : callbackMap_) {
        if (pair.second) {
            pair.second->OnWifiRssiChanged(rssi);
        }
    }
    WriteWifiEventReceivedHiSysEvent(HISYS_STA_RSSI_STATE_CHANGE, rssi);
}

NO_SANITIZE("cfi") void WifiDeviceCallBackStub::OnWifiWpsStateChanged(int state, const std::string &pinCode)
{
    WIFI_LOGI("OnWifiWpsStateChanged, state:%{public}d!", state);
    for (auto& pair : callbackMap_) {
        if (pair.second) {
            pair.second->OnWifiWpsStateChanged(state, pinCode);
        }
    }
}

NO_SANITIZE("cfi") void WifiDeviceCallBackStub::OnStreamChanged(int direction)
{
    WIFI_LOGD("OnStreamChanged, direction:%{public}d!", direction);
    for (auto& pair : callbackMap_) {
        if (pair.second) {
            pair.second->OnStreamChanged(direction);
        }
    }
}

NO_SANITIZE("cfi") void WifiDeviceCallBackStub::OnDeviceConfigChanged(ConfigChange value)
{
    WIFI_LOGI("OnDeviceConfigChanged, value:%{public}d!", value);
    for (auto& pair : callbackMap_) {
        if (pair.second) {
            pair.second->OnDeviceConfigChanged(value);
        }
    }
}

NO_SANITIZE("cfi") void WifiDeviceCallBackStub::OnCandidateApprovalStatusChanged(CandidateApprovalStatus status)
{
    WIFI_LOGI("OnCandidateApprovalStatusChanged, status:%{public}d!", static_cast<int>(status));
    for (auto& pair : callbackMap_) {
        if (pair.second) {
            pair.second->OnCandidateApprovalStatusChanged(status);
        }
    }
}

int WifiDeviceCallBackStub::RemoteOnWifiStateChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int state = data.ReadInt32();
    OnWifiStateChanged(state);
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
    info.ipAddress = static_cast<unsigned int>(data.ReadInt32());
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
    info.isAncoConnected = data.ReadBool();
    OnWifiConnectionChanged(state, info);
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnWifiRssiChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int rssi = data.ReadInt32();
    OnWifiRssiChanged(rssi);
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
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnStreamChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int direction = data.ReadInt32();
    OnStreamChanged(direction);
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnDeviceConfigChanged(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int value = data.ReadInt32();
    OnDeviceConfigChanged(ConfigChange(value));
    return 0;
}

int WifiDeviceCallBackStub::RemoteOnCandidateApprovalStatusChanged(uint32_t code, MessageParcel &data,
    MessageParcel &reply)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int status = data.ReadInt32();
    OnCandidateApprovalStatusChanged(CandidateApprovalStatus(status));
    return 0;
}
}  // namespace Wifi
}  // namespace OHOS