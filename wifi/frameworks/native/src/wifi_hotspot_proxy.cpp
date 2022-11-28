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

#include "wifi_hotspot_proxy.h"
#include "string_ex.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "wifi_hisysevent.h"
#include "wifi_hotspot_callback_stub.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiHotspotProxy");
namespace OHOS {
namespace Wifi {
static sptr<WifiHotspotCallbackStub> g_wifiHotspotCallbackStub =
    sptr<WifiHotspotCallbackStub>(new (std::nothrow) WifiHotspotCallbackStub());

WifiHotspotProxy::WifiHotspotProxy(const sptr<IRemoteObject> &impl)
    : IRemoteProxy<IWifiHotspot>(impl), mRemoteDied(false), remote_(nullptr), deathRecipient_(nullptr)
{
    if (impl) {
        if (!impl->IsProxyObject()) {
            WIFI_LOGW("not proxy object!");
            return;
        }
        deathRecipient_ = new (std::nothrow) WifiDeathRecipient(*this);
        if (deathRecipient_ == nullptr) {
            WIFI_LOGW("deathRecipient_ is nullptr!");
        }
        if (!impl->AddDeathRecipient(deathRecipient_)) {
            WIFI_LOGW("AddDeathRecipient failed!");
            return;
        }
        remote_ = impl;
        WIFI_LOGI("AddDeathRecipient success! deathRecipient_: %{private}p", static_cast<void*>(deathRecipient_));
    }
}

WifiHotspotProxy::~WifiHotspotProxy()
{
    WIFI_LOGI("enter ~WifiHotspotProxy!");
    RemoveDeathRecipient();
}

void WifiHotspotProxy::RemoveDeathRecipient(void)
{
    WIFI_LOGI("enter RemoveDeathRecipient, deathRecipient_: %{private}p!", static_cast<void*>(deathRecipient_));
    std::lock_guard<std::mutex> lock(mutex_);
    if (remote_ == nullptr) {
        WIFI_LOGI("remote_ is nullptr!");
        return;
    }
    if (deathRecipient_ == nullptr) {
        WIFI_LOGI("deathRecipient_ is nullptr!");
        return;
    }
    remote_->RemoveDeathRecipient(deathRecipient_);
    remote_ = nullptr;
}

ErrCode WifiHotspotProxy::IsHotspotActive(bool &isActive)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_IS_HOTSPOT_ACTIVE, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_IS_HOTSPOT_ACTIVE);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ErrCode(ret) != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }
    isActive = ((reply.ReadInt32() == 1) ? true : false);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotProxy::IsHotspotDualBandSupported(bool &isSupported)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_IS_HOTSPOT_DUAL_BAND_SUPPORTED, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_IS_HOTSPOT_DUAL_BAND_SUPPORTED);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ErrCode(ret) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("reply failed: %d", ret);
        return ErrCode(ret);
    }
    isSupported = ((reply.ReadInt32() == 1) ? true : false);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotProxy::GetHotspotState(int &state)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GETAPSTATE_WIFI, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_GETAPSTATE_WIFI);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ErrCode(ret) != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }
    state = reply.ReadInt32();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotProxy::GetHotspotConfig(HotspotConfig &result)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    const char *readStr = nullptr;
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_HOTSPOT_CONFIG, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_GET_HOTSPOT_CONFIG);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ErrCode(ret) != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }

    readStr = reply.ReadCString();
    result.SetSsid((readStr != nullptr) ? readStr : "");
    result.SetSecurityType(static_cast<KeyMgmt>(reply.ReadInt32()));
    result.SetBand(static_cast<BandType>(reply.ReadInt32()));
    result.SetChannel(reply.ReadInt32());
    readStr = reply.ReadCString();
    result.SetPreSharedKey((readStr != nullptr) ? readStr : "");
    result.SetMaxConn(reply.ReadInt32());

    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotProxy::SetHotspotConfig(const HotspotConfig &config)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteCString(config.GetSsid().c_str());
    data.WriteInt32(static_cast<int>(config.GetSecurityType()));
    data.WriteInt32(static_cast<int>(config.GetBand()));
    data.WriteInt32(config.GetChannel());
    data.WriteCString(config.GetPreSharedKey().c_str());
    data.WriteInt32(config.GetMaxConn());
    int error = Remote()->SendRequest(WIFI_SVR_CMD_SETAPCONFIG_WIFI, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_SETAPCONFIG_WIFI);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiHotspotProxy::GetStationList(std::vector<StationInfo> &result)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    const char *readStr = nullptr;
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_STATION_LIST, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_GET_STATION_LIST);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ErrCode(ret) != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }
    constexpr int MAX_SIZE = 512;
    int size = reply.ReadInt32();
    if (size > MAX_SIZE) {
        WIFI_LOGE("Station list size error: %{public}d", size);
        return WIFI_OPT_FAILED;
    }
    for (int i = 0; i < size; i++) {
        StationInfo info;
        readStr = reply.ReadCString();
        info.deviceName = (readStr != nullptr) ? readStr : "";
        readStr = reply.ReadCString();
        info.bssid = (readStr != nullptr) ? readStr : "";
        readStr = reply.ReadCString();
        info.ipAddr = (readStr != nullptr) ? readStr : "";
        result.emplace_back(info);
    }

    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotProxy::DisassociateSta(const StationInfo &info)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteCString(info.deviceName.c_str());
    data.WriteCString(info.bssid.c_str());
    data.WriteCString(info.ipAddr.c_str());
    int error = Remote()->SendRequest(WIFI_SVR_CMD_DISCONNECT_STA, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_DISCONNECT_STA);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return ErrCode(exception);
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiHotspotProxy::EnableHotspot(const ServiceType type)
{
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32(static_cast<int>(type));
    int error = Remote()->SendRequest(WIFI_SVR_CMD_ENABLE_WIFI_AP, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_ENABLE_WIFI_AP);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    WriteWifiStateHiSysEvent(HISYS_SERVICE_TYPE_AP, WifiOperType::ENABLE);
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiHotspotProxy::DisableHotspot(const ServiceType type)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32(static_cast<int>(type));
    int error = Remote()->SendRequest(WIFI_SVR_CMD_DISABLE_WIFI_AP, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_DISABLE_WIFI_AP);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    WriteWifiStateHiSysEvent(HISYS_SERVICE_TYPE_AP, WifiOperType::DISABLE);
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiHotspotProxy::GetBlockLists(std::vector<StationInfo> &infos)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    const char *readStr = nullptr;
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_BLOCK_LISTS, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_GET_BLOCK_LISTS);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int err = reply.ReadInt32();
    if (err != WIFI_OPT_SUCCESS) {
        return ErrCode(err);
    }

    constexpr int MAX_SIZE = 512;
    int size = reply.ReadInt32();
    if (size > MAX_SIZE) {
        WIFI_LOGE("Get block size error: %{public}d", size);
        return WIFI_OPT_FAILED;
    }

    for (int i = 0; i < size; i++) {
        StationInfo info;
        readStr = reply.ReadCString();
        info.deviceName = (readStr != nullptr) ? readStr : "";
        readStr = reply.ReadCString();
        info.bssid = (readStr != nullptr) ? readStr : "";
        readStr = reply.ReadCString();
        info.ipAddr = (readStr != nullptr) ? readStr : "";
        infos.push_back(info);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotProxy::AddBlockList(const StationInfo &info)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteCString(info.deviceName.c_str());
    data.WriteCString(info.bssid.c_str());
    data.WriteCString(info.ipAddr.c_str());
    int error = Remote()->SendRequest(WIFI_SVR_CMD_ADD_BLOCK_LIST, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_ADD_BLOCK_LIST);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiHotspotProxy::DelBlockList(const StationInfo &info)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteCString(info.deviceName.c_str());
    data.WriteCString(info.bssid.c_str());
    data.WriteCString(info.ipAddr.c_str());
    int error = Remote()->SendRequest(WIFI_SVR_CMD_DEL_BLOCK_LIST, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_DEL_BLOCK_LIST);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiHotspotProxy::GetValidBands(std::vector<BandType> &bands)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_VALID_BANDS, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_GET_VALID_BANDS);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int err = reply.ReadInt32();
    if (err != WIFI_OPT_SUCCESS) {
        return ErrCode(err);
    }

    constexpr int MAX_BAND_SIZE = 512;
    int count = reply.ReadInt32();
    if (count > MAX_BAND_SIZE) {
        WIFI_LOGE("Band size error: %{public}d", count);
        return WIFI_OPT_FAILED;
    }
    for (int i = 0; i < count; i++) {
        int val = reply.ReadInt32();
        bands.push_back(BandType(val));
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotProxy::GetValidChannels(BandType band, std::vector<int32_t> &validchannels)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32((int)band);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_VALID_CHANNELS, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_GET_VALID_CHANNELS);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int err = reply.ReadInt32();
    if (err != WIFI_OPT_SUCCESS) {
        return ErrCode(err);
    }

    constexpr int MAX_CHANNELS_SIZE = 512;
    int count = reply.ReadInt32();
    if (count > MAX_CHANNELS_SIZE) {
        WIFI_LOGE("Channel size error: %{public}d", count);
        return WIFI_OPT_FAILED;
    }
    for (int i = 0; i < count; i++) {
        int val = reply.ReadInt32();
        validchannels.push_back(val);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotProxy::RegisterCallBack(const sptr<IWifiHotspotCallback> &callback)
{
    WIFI_LOGD("WifiHotspotProxy::RegisterCallBack!");
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    g_wifiHotspotCallbackStub->RegisterCallBack(callback);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    if (!data.WriteRemoteObject(g_wifiHotspotCallbackStub->AsObject())) {
        WIFI_LOGE("WifiHotspotProxy::RegisterCallBack WriteDate fail, write callback.");
        return WIFI_OPT_FAILED;
    }

    int error = Remote()->SendRequest(WIFI_SVR_CMD_REGISTER_HOTSPOT_CALLBACK, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("WifiHotspotProxy::RegisterCallBack failed, error code is %{public}d ", error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    return ErrCode(ret);
}

ErrCode WifiHotspotProxy::GetSupportedFeatures(long &features)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_SUPPORTED_FEATURES, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_SUPPORTED_FEATURES, error);
        return ErrCode(error);
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }

    features = reply.ReadInt64();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotProxy::GetSupportedPowerModel(std::set<PowerModel>& setPowerModelList)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_SUPPORTED_POWER_MODEL, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_GET_SUPPORTED_POWER_MODEL);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int err = reply.ReadInt32();
    if (err != WIFI_OPT_SUCCESS) {
        return ErrCode(err);
    }

    constexpr int MAX_SIZE = 32;
    int size = reply.ReadInt32();
    if (size > MAX_SIZE) {
        WIFI_LOGE("size error: %{public}d", size);
        return WIFI_OPT_FAILED;
    }
    for (int i = 0; i < size; i++) {
        int val = reply.ReadInt32();
        setPowerModelList.insert(PowerModel(val));
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotProxy::GetPowerModel(PowerModel& model)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_POWER_MODEL, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_GET_POWER_MODEL);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int err = reply.ReadInt32();
    if (err != WIFI_OPT_SUCCESS) {
        return ErrCode(err);
    }
    model = PowerModel(reply.ReadInt32());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiHotspotProxy::SetPowerModel(const PowerModel& model)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32(static_cast<int>(model));
    int error = Remote()->SendRequest(WIFI_SVR_CMD_SET_POWER_MODEL, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_SET_POWER_MODEL);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

void WifiHotspotProxy::OnRemoteDied(const wptr<IRemoteObject>& remoteObject)
{
    WIFI_LOGW("Remote service is died!");
    mRemoteDied = true;
    RemoveDeathRecipient();
    if (g_wifiHotspotCallbackStub != nullptr) {
        g_wifiHotspotCallbackStub->SetRemoteDied(true);
    }
}

bool WifiHotspotProxy::IsRemoteDied(void)
{
    if (mRemoteDied) {
        WIFI_LOGW("IsRemoteDied! remote is died now!");
    }
    return mRemoteDied;
}
}  // namespace Wifi
}  // namespace OHOS