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

#include "wifi_device_proxy.h"
#include "define.h"
#include "wifi_common_util.h"
#include "wifi_device_callback_stub.h"
#include "wifi_hisysevent.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiDeviceProxy");

namespace OHOS {
namespace Wifi {
static sptr<WifiDeviceCallBackStub> g_deviceCallBackStub =
    sptr<WifiDeviceCallBackStub>(new (std::nothrow) WifiDeviceCallBackStub());

WifiDeviceProxy::WifiDeviceProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IWifiDevice>(impl),
    remote_(nullptr), mRemoteDied(false), deathRecipient_(nullptr)
{
    std::lock_guard<std::mutex> lock(mutex_);
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

WifiDeviceProxy::~WifiDeviceProxy()
{
    WIFI_LOGI("enter ~WifiDeviceProxy!");
    RemoveDeathRecipient();
}

void WifiDeviceProxy::RemoveDeathRecipient(void)
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

ErrCode WifiDeviceProxy::EnableWifi()
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
    int error = Remote()->SendRequest(WIFI_SVR_CMD_ENABLE_WIFI, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_ENABLE_WIFI, error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    WriteWifiStateHiSysEvent(HISYS_SERVICE_TYPE_STA, WifiOperType::ENABLE);
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::DisableWifi()
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_DISABLE_WIFI, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_DISABLE_WIFI, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    WriteWifiStateHiSysEvent(HISYS_SERVICE_TYPE_STA, WifiOperType::DISABLE);
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::InitWifiProtect(const WifiProtectType &protectType, const std::string &protectName)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32((int)protectType);
    data.WriteCString(protectName.c_str());
    int error = Remote()->SendRequest(WIFI_SVR_CMD_INIT_WIFI_PROTECT, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_INIT_WIFI_PROTECT, error);
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

    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::GetWifiProtectRef(const WifiProtectMode &protectMode, const std::string &protectName)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32((int)protectMode);
    data.WriteCString(protectName.c_str());
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_WIFI_PROTECT, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_WIFI_PROTECT, error);
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

    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::PutWifiProtectRef(const std::string &protectName)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteCString(protectName.c_str());
    int error = Remote()->SendRequest(WIFI_SVR_CMD_PUT_WIFI_PROTECT, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_PUT_WIFI_PROTECT, error);
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

    return WIFI_OPT_SUCCESS;
}

void WifiDeviceProxy::WriteIpAddress(MessageParcel &data, const WifiIpAddress &address)
{
    data.WriteInt32(address.family);
    data.WriteInt32(address.addressIpv4);
    int size = address.addressIpv6.size();
    data.WriteInt32(size);
    for (int i = 0; i < size; i++) {
        data.WriteInt8(address.addressIpv6[i]);
    }
    return;
}

void WifiDeviceProxy::WriteDeviceConfig(const WifiDeviceConfig &config, MessageParcel &data)
{
    data.WriteInt32(config.networkId);
    data.WriteInt32(config.status);
    data.WriteString(config.bssid);
    data.WriteString(config.ssid);
    data.WriteInt32(config.band);
    data.WriteInt32(config.channel);
    data.WriteInt32(config.frequency);
    data.WriteInt32(config.level);
    data.WriteBool(config.isPasspoint);
    data.WriteBool(config.isEphemeral);
    data.WriteString(config.preSharedKey);
    data.WriteString(config.keyMgmt);
    for (int i = 0; i < WEPKEYS_SIZE; i++) {
        data.WriteString(config.wepKeys[i]);
    }
    data.WriteInt32(config.wepTxKeyIndex);
    data.WriteInt32(config.priority);
    data.WriteBool(config.hiddenSSID);
    data.WriteInt32((int)config.wifiIpConfig.assignMethod);
    WriteIpAddress(data, config.wifiIpConfig.staticIpAddress.ipAddress.address);
    data.WriteInt32(config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength);
    data.WriteInt32(config.wifiIpConfig.staticIpAddress.ipAddress.flags);
    data.WriteInt32(config.wifiIpConfig.staticIpAddress.ipAddress.scope);
    WriteIpAddress(data, config.wifiIpConfig.staticIpAddress.gateway);
    WriteIpAddress(data, config.wifiIpConfig.staticIpAddress.dnsServer1);
    WriteIpAddress(data, config.wifiIpConfig.staticIpAddress.dnsServer2);
    data.WriteString(config.wifiIpConfig.staticIpAddress.domains);
    data.WriteString(config.wifiEapConfig.eap);
    data.WriteString(config.wifiEapConfig.identity);
    data.WriteString(config.wifiEapConfig.password);
    data.WriteString(config.wifiEapConfig.clientCert);
    data.WriteString(config.wifiEapConfig.privateKey);
    data.WriteUInt8Vector(config.wifiEapConfig.certEntry);
    data.WriteString(config.wifiEapConfig.certPassword);
    data.WriteInt32(static_cast<int>(config.wifiEapConfig.phase2Method));
    data.WriteInt32((int)config.wifiProxyconfig.configureMethod);
    data.WriteString(config.wifiProxyconfig.autoProxyConfig.pacWebAddress);
    data.WriteString(config.wifiProxyconfig.manualProxyConfig.serverHostName);
    data.WriteInt32(config.wifiProxyconfig.manualProxyConfig.serverPort);
    data.WriteString(config.wifiProxyconfig.manualProxyConfig.exclusionObjectList);
    data.WriteInt32((int)config.wifiPrivacySetting);
}

ErrCode WifiDeviceProxy::RemoveCandidateConfig(const WifiDeviceConfig &config)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    /* Write a flag: 1-remove config by networkId, 2-remove config by WifiDeviceConfig */
    data.WriteInt32(2);
    WriteDeviceConfig(config, data);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_REMOVE_CANDIDATE_CONFIG, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error=%{public}d", WIFI_SVR_CMD_REMOVE_CANDIDATE_CONFIG, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }

    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::RemoveCandidateConfig(int networkId)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    /* Write a flag: 1-remove config by networkId, 2-remove config by WifiDeviceConfig */
    data.WriteInt32(1);
    data.WriteInt32(networkId);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_REMOVE_CANDIDATE_CONFIG, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error=%{public}d", WIFI_SVR_CMD_REMOVE_CANDIDATE_CONFIG, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::AddDeviceConfig(const WifiDeviceConfig &config, int &result, bool isCandidate)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    /* true-candidate config, false-normal config */
    data.WriteBool(isCandidate);
    WriteDeviceConfig(config, data);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_ADD_DEVICE_CONFIG, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_ADD_DEVICE_CONFIG, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }
    result = reply.ReadInt32();

    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::UpdateDeviceConfig(const WifiDeviceConfig &config, int &result)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }

    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    WriteDeviceConfig(config, data);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }
    result = reply.ReadInt32();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::RemoveDevice(int networkId)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32(networkId);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::RemoveAllDevice()
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
    int error = Remote()->SendRequest(WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG, error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

void WifiDeviceProxy::ReadIpAddress(MessageParcel &reply, WifiIpAddress &address)
{
    constexpr int MAX_SIZE = 256;
    address.family = reply.ReadInt32();
    address.addressIpv4 = reply.ReadInt32();
    int size = reply.ReadInt32();
    if (size > MAX_SIZE) {
        WIFI_LOGE("Read IP address size error: %{public}d", size);
        return;
    }
    for (int i = 0; i < size; i++) {
        address.addressIpv6.push_back(reply.ReadInt8());
    }
    return;
}

void WifiDeviceProxy::ParseDeviceConfigs(MessageParcel &reply, std::vector<WifiDeviceConfig> &result)
{
    constexpr int MAX_DEVICE_CONFIG_SIZE = 1024;
    int retSize = reply.ReadInt32();
    if (retSize > MAX_DEVICE_CONFIG_SIZE) {
        WIFI_LOGE("Parse device config size error: %{public}d", retSize);
        return;
    }
    for (int i = 0; i < retSize; ++i) {
        WifiDeviceConfig config;
        config.networkId = reply.ReadInt32();
        config.status = reply.ReadInt32();
        config.bssid = reply.ReadString();
        config.ssid = reply.ReadString();
        config.band = reply.ReadInt32();
        config.channel = reply.ReadInt32();
        config.frequency = reply.ReadInt32();
        config.level = reply.ReadInt32();
        config.isPasspoint = reply.ReadBool();
        config.isEphemeral = reply.ReadBool();
        config.preSharedKey = reply.ReadString();
        config.keyMgmt = reply.ReadString();
        for (int j = 0; j < WEPKEYS_SIZE; j++) {
            config.wepKeys[j] = reply.ReadString();
        }
        config.wepTxKeyIndex = reply.ReadInt32();
        config.priority = reply.ReadInt32();
        config.hiddenSSID = reply.ReadBool();
        config.wifiIpConfig.assignMethod = AssignIpMethod(reply.ReadInt32());
        ReadIpAddress(reply, config.wifiIpConfig.staticIpAddress.ipAddress.address);
        config.wifiIpConfig.staticIpAddress.ipAddress.prefixLength = reply.ReadInt32();
        config.wifiIpConfig.staticIpAddress.ipAddress.flags = reply.ReadInt32();
        config.wifiIpConfig.staticIpAddress.ipAddress.scope = reply.ReadInt32();
        ReadIpAddress(reply, config.wifiIpConfig.staticIpAddress.gateway);
        ReadIpAddress(reply, config.wifiIpConfig.staticIpAddress.dnsServer1);
        ReadIpAddress(reply, config.wifiIpConfig.staticIpAddress.dnsServer2);
        config.wifiIpConfig.staticIpAddress.domains = reply.ReadString();
        config.wifiEapConfig.eap = reply.ReadString();
        config.wifiEapConfig.identity = reply.ReadString();
        config.wifiEapConfig.password = reply.ReadString();
        config.wifiEapConfig.clientCert = reply.ReadString();
        config.wifiEapConfig.privateKey= reply.ReadString();
        config.wifiEapConfig.phase2Method = Phase2Method(reply.ReadInt32());
        config.wifiProxyconfig.configureMethod = ConfigureProxyMethod(reply.ReadInt32());
        config.wifiProxyconfig.autoProxyConfig.pacWebAddress = reply.ReadString();
        config.wifiProxyconfig.manualProxyConfig.serverHostName = reply.ReadString();
        config.wifiProxyconfig.manualProxyConfig.serverPort = reply.ReadInt32();
        config.wifiProxyconfig.manualProxyConfig.exclusionObjectList = reply.ReadString();
        config.wifiPrivacySetting = WifiPrivacyConfig(reply.ReadInt32());
        config.uid = reply.ReadInt32();

        result.emplace_back(config);
    }
}

ErrCode WifiDeviceProxy::GetDeviceConfigs(std::vector<WifiDeviceConfig> &result, bool isCandidate)
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
    /* true-candidate config, false-normal config */
    data.WriteBool(isCandidate);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_DEVICE_CONFIGS, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_DEVICE_CONFIGS, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }

    ParseDeviceConfigs(reply, result);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::EnableDeviceConfig(int networkId, bool attemptEnable)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32(networkId);
    data.WriteInt32(attemptEnable);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_ENABLE_DEVICE, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_ENABLE_DEVICE, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::DisableDeviceConfig(int networkId)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32(networkId);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_DISABLE_DEVICE, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_DISABLE_DEVICE, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::ConnectToNetwork(int networkId, bool isCandidate)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    /* true-candidate config, false-normal config */
    data.WriteBool(isCandidate);
    data.WriteInt32(networkId);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_CONNECT_TO, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_CONNECT_TO, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    WriteWifiConnectionHiSysEvent(WifiConnectionType::CONNECT, GetBundleName());
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::ConnectToDevice(const WifiDeviceConfig &config)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    WriteDeviceConfig(config, data);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_CONNECT2_TO, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_CONNECT2_TO, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    WriteWifiConnectionHiSysEvent(WifiConnectionType::CONNECT, GetBundleName());
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::IsConnected(bool &isConnected)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_IS_WIFI_CONNECTED, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_IS_WIFI_CONNECTED, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }
    isConnected = reply.ReadBool();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::ReConnect()
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_RECONNECT, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_RECONNECT, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    WriteWifiConnectionHiSysEvent(WifiConnectionType::CONNECT, GetBundleName());
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::ReAssociate(void)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_REASSOCIATE, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_REASSOCIATE, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    WriteWifiConnectionHiSysEvent(WifiConnectionType::CONNECT, GetBundleName());
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::Disconnect(void)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_DISCONNECT, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_DISCONNECT, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    WriteWifiConnectionHiSysEvent(WifiConnectionType::DISCONNECT, GetBundleName());
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::StartWps(const WpsConfig &config)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32(static_cast<int>(config.setup));
    data.WriteCString(config.pin.c_str());
    data.WriteCString(config.bssid.c_str());
    int error = Remote()->SendRequest(WIFI_SVR_CMD_START_WPS, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_START_WPS, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::CancelWps(void)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_CANCEL_WPS, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_CANCEL_WPS, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::IsWifiActive(bool &bActive)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_IS_WIFI_ACTIVE, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_IS_WIFI_ACTIVE, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }

    bActive = reply.ReadBool();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::GetWifiState(int &state)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_WIFI_STATE, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_WIFI_STATE, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }

    state = reply.ReadInt32();
    return WIFI_OPT_SUCCESS;
}

void WifiDeviceProxy::ReadLinkedInfo(MessageParcel &reply, WifiLinkedInfo &info)
{
    info.networkId = reply.ReadInt32();
    info.ssid = reply.ReadString();
    info.bssid = reply.ReadString();
    info.rssi = reply.ReadInt32();
    info.band = reply.ReadInt32();
    info.frequency = reply.ReadInt32();
    info.linkSpeed = reply.ReadInt32();
    info.macAddress = reply.ReadString();
    info.macType = reply.ReadInt32();
    info.ipAddress = reply.ReadInt32();
    int tmpConnState = reply.ReadInt32();
    if ((tmpConnState >= 0) && (tmpConnState <= (int)ConnState::UNKNOWN)) {
        info.connState = ConnState(tmpConnState);
    } else {
        info.connState = ConnState::UNKNOWN;
    }
    info.ifHiddenSSID = reply.ReadBool();
    info.rxLinkSpeed = reply.ReadInt32();
    info.txLinkSpeed = reply.ReadInt32();
    info.chload = reply.ReadInt32();
    info.snr = reply.ReadInt32();
    info.isDataRestricted = reply.ReadInt32();
    info.portalUrl = reply.ReadString();

    int tmpState = reply.ReadInt32();
    if ((tmpState >= 0) && (tmpState <= (int)SupplicantState::INVALID)) {
        info.supplicantState = (SupplicantState)tmpState;
    } else {
        info.supplicantState = SupplicantState::INVALID;
    }

    int tmpDetailState = reply.ReadInt32();
    if ((tmpDetailState >= 0) && (tmpDetailState <= (int)DetailedState::INVALID)) {
        info.detailedState = (DetailedState)tmpDetailState;
    } else {
        info.detailedState = DetailedState::INVALID;
    }
}

ErrCode WifiDeviceProxy::GetLinkedInfo(WifiLinkedInfo &info)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_LINKED_INFO, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_LINKED_INFO, error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }

    ReadLinkedInfo(reply, info);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::GetIpInfo(IpInfo &info)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_DHCP_INFO, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_DHCP_INFO, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }

    info.ipAddress = reply.ReadInt32();
    info.gateway = reply.ReadInt32();
    info.netmask = reply.ReadInt32();
    info.primaryDns = reply.ReadInt32();
    info.secondDns = reply.ReadInt32();
    info.serverIp = reply.ReadInt32();
    info.leaseDuration = reply.ReadInt32();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::SetCountryCode(const std::string &countryCode)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteString(countryCode);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_SET_COUNTRY_CODE, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_SET_COUNTRY_CODE, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::GetCountryCode(std::string &countryCode)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_COUNTRY_CODE, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_COUNTRY_CODE, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }
    countryCode = reply.ReadString();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::RegisterCallBack(const sptr<IWifiDeviceCallBack> &callback)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageParcel data, reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);

    if (g_deviceCallBackStub == nullptr) {
        WIFI_LOGE("g_deviceCallBackStub is nullptr");
        return WIFI_OPT_FAILED;
    }
    g_deviceCallBackStub->RegisterUserCallBack(callback);

    if (!data.WriteRemoteObject(g_deviceCallBackStub->AsObject())) {
        WIFI_LOGE("WifiDeviceProxy::RegisterCallBack WriteRemoteObject failed!");
        return WIFI_OPT_FAILED;
    }

    int pid = GetCallingPid();
    data.WriteInt32(pid);
    WIFI_LOGD("%{public}s, calling uid: %{public}d, pid: %{public}d", __func__, GetCallingUid(), pid);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed, code is %{public}d", WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::GetSignalLevel(const int &rssi, const int &band, int &level)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32(rssi);
    data.WriteInt32(band);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_SIGNAL_LEVEL, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_GET_SIGNAL_LEVEL, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }

    level = reply.ReadInt32();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::GetSupportedFeatures(long &features)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
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
        return WIFI_OPT_FAILED;
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

ErrCode WifiDeviceProxy::GetDeviceMacAddress(std::string &result)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
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
    int error = Remote()->SendRequest(WIFI_SVR_CMD_GET_DERVICE_MAC_ADD, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed", WIFI_SVR_CMD_GET_DERVICE_MAC_ADD);
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
    result = (readStr != nullptr) ? readStr : "";
    return WIFI_OPT_SUCCESS;
}

bool WifiDeviceProxy::SetLowLatencyMode(bool enabled)
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
    data.WriteBool(enabled);
    int error = Remote()->SendRequest(WIFI_SVR_CMD_SET_LOW_LATENCY_MODE, data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d", WIFI_SVR_CMD_SET_LOW_LATENCY_MODE, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return reply.ReadBool();
}

void WifiDeviceProxy::OnRemoteDied(const wptr<IRemoteObject> &remoteObject)
{
    WIFI_LOGW("Remote service is died! remoteObject: %{private}p", &remoteObject);
    mRemoteDied = true;
    RemoveDeathRecipient();
    if (g_deviceCallBackStub == nullptr) {
        WIFI_LOGE("g_deviceCallBackStub is nullptr");
        return;
    }
    if (g_deviceCallBackStub != nullptr) {
        g_deviceCallBackStub->SetRemoteDied(true);
    }
}

bool WifiDeviceProxy::IsRemoteDied(void)
{
    if (mRemoteDied) {
        WIFI_LOGW("IsRemoteDied! remote is died now!");
    }
    return mRemoteDied;
}
}  // namespace Wifi
}  // namespace OHOS
