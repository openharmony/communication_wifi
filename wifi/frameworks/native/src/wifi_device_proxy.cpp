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
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_common_util.h"
#include "wifi_device_callback_stub.h"
#include "wifi_hisysevent.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiDeviceProxy");

namespace OHOS {
namespace Wifi {

constexpr int MAX_SIZE = 256;
constexpr int MAX_MDM_RESTRICTED_SIZE = 200;
int g_bigDataRecvLen = 0;

static sptr<WifiDeviceCallBackStub> g_deviceCallBackStub =
    sptr<WifiDeviceCallBackStub>(new (std::nothrow) WifiDeviceCallBackStub());
static sptr<WifiInternalCallback> g_InternalCallback =
    sptr<WifiInternalCallback>(new (std::nothrow) WifiInternalCallback());

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
        WIFI_LOGD("AddDeathRecipient success! ");
        InitWifiState();
    }
}

WifiDeviceProxy::~WifiDeviceProxy()
{
    WIFI_LOGD("enter ~WifiDeviceProxy!");
    RemoveDeathRecipient();
}

void WifiDeviceProxy::InitWifiState()
{
    auto callBack = sptr<WifiInternalCallback>(new WifiInternalCallback());
    callBack->wifiStateChangeCallback = [=](int state) {
        this->OnWifiStateChanged(state);
    };
    const std::vector<std::string> event = {EVENT_STA_POWER_STATE_CHANGE};
    RegisterCallBack(callBack, event);

    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_ACTIVE), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_ACTIVE), error);
        return;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        return;
    }

    bool bActive = reply.ReadBool();
    g_deviceCallBackStub->SetWifiState(bActive);
    return;
}

void WifiDeviceProxy::RemoveDeathRecipient(void)
{
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), error);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_PROTECT), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_PROTECT), error);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_PUT_WIFI_PROTECT), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_PUT_WIFI_PROTECT), error);
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

ErrCode WifiDeviceProxy::IsHeldWifiProtectRef(
    const std::string &protectName, bool &isHoldProtect)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_HELD_WIFI_PROTECT), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_HELD_WIFI_PROTECT), error);
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

    isHoldProtect = reply.ReadBool();
    WIFI_LOGD("%{public}s result %{public}d", __func__, isHoldProtect);
    return WIFI_OPT_SUCCESS;
}

void WifiDeviceProxy::WriteWifiRestrictedInfo(const WifiRestrictedInfo &info, MessageParcel &data)
{
    data.WriteString(info.ssid);
    data.WriteString(info.bssid);
    data.WriteInt32(info.uid);
    data.WriteInt32(static_cast<int32_t>(info.wifiRestrictedType));
}

void WifiDeviceProxy::WriteIpAddress(MessageParcel &data, const WifiIpAddress &address)
{
    data.WriteInt32(address.family);
    data.WriteInt32(address.addressIpv4);
    int size = static_cast<int>(address.addressIpv6.size());
    data.WriteInt32(size);
    for (int i = 0; i < size; i++) {
        data.WriteInt8(address.addressIpv6[i]);
    }
    return;
}

void WifiDeviceProxy::WriteEapConfig(MessageParcel &data, const WifiEapConfig &wifiEapConfig)
{
    data.WriteString(wifiEapConfig.eap);
    data.WriteInt32(static_cast<int>(wifiEapConfig.phase2Method));
    data.WriteString(wifiEapConfig.identity);
    data.WriteString(wifiEapConfig.anonymousIdentity);
    data.WriteString(wifiEapConfig.password);

    data.WriteString(wifiEapConfig.caCertPath);
    data.WriteString(wifiEapConfig.caCertAlias);
    data.WriteUInt8Vector(wifiEapConfig.certEntry);

    data.WriteString(wifiEapConfig.clientCert);
    data.WriteString(std::string(wifiEapConfig.certPassword));
    data.WriteString(wifiEapConfig.privateKey);

    data.WriteString(wifiEapConfig.altSubjectMatch);
    data.WriteString(wifiEapConfig.domainSuffixMatch);
    data.WriteString(wifiEapConfig.realm);
    data.WriteString(wifiEapConfig.plmn);
    data.WriteInt32(wifiEapConfig.eapSubId);
}

void WifiDeviceProxy::WriteDeviceConfig(const WifiDeviceConfig &config, MessageParcel &data)
{
    data.WriteInt32(config.networkId);
    data.WriteString(config.bssid);
    data.WriteInt32(config.bssidType);
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
    WriteEapConfig(data, config.wifiEapConfig);
    data.WriteInt32((int)config.wifiProxyconfig.configureMethod);
    data.WriteString(config.wifiProxyconfig.autoProxyConfig.pacWebAddress);
    data.WriteString(config.wifiProxyconfig.manualProxyConfig.serverHostName);
    data.WriteInt32(config.wifiProxyconfig.manualProxyConfig.serverPort);
    data.WriteString(config.wifiProxyconfig.manualProxyConfig.exclusionObjectList);
    data.WriteInt32((int)config.wifiPrivacySetting);
    data.WriteString(config.callProcessName);
    data.WriteString(config.ancoCallProcessName);
    data.WriteInt32(config.uid);
    data.WriteInt32(config.wifiWapiConfig.wapiPskType);
    data.WriteString(config.wifiWapiConfig.wapiAsCertData);
    data.WriteString(config.wifiWapiConfig.wapiUserCertData);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_CANDIDATE_CONFIG),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error=%{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_CANDIDATE_CONFIG), error);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_CANDIDATE_CONFIG),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error=%{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_CANDIDATE_CONFIG), error);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ADD_DEVICE_CONFIG),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_ADD_DEVICE_CONFIG), error);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG), error);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::SetWifiRestrictedList(const std::vector<WifiRestrictedInfo> &wifiRestrictedInfoList)
{
    WIFI_LOGI("wifi_device_proxy:: SetWifiRestrictedList");
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
    int size = static_cast<int>(wifiRestrictedInfoList.size());
    if (size > MAX_MDM_RESTRICTED_SIZE) {
        WIFI_LOGE("SetWifiRestrictedList size error: %{public}d", size);
        return WIFI_OPT_MDM_OUT_MAX_NUM;
    }
    data.WriteInt32(size);
    for (int i = 0; i < size; i++) {
        WriteWifiRestrictedInfo(wifiRestrictedInfoList[i], data);
    }
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_WIFI_ACCESS_LIST),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_WIFI_ACCESS_LIST), error);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG), error);
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
    address.family = reply.ReadInt32();
    address.addressIpv4 = static_cast<uint32_t>(reply.ReadInt32());
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

void WifiDeviceProxy::BigDataReadIpAddress(WifiIpAddress &address, std::vector<std::string> &tokens)
{
    address.family = CheckDataLegal(tokens[g_bigDataRecvLen++]);
    address.addressIpv4 = static_cast<size_t>(CheckDataLegal(tokens[g_bigDataRecvLen++]));
    int size = CheckDataLegal(tokens[g_bigDataRecvLen++]);
    if (size > MAX_SIZE) {
        WIFI_LOGE("Read IP address size error: %{public}d", size);
        return;
    }
    for (int i = 0; i < size; i++) {
        address.addressIpv6.push_back(CheckDataLegal(tokens[g_bigDataRecvLen++]));
    }
    return;
}

void WifiDeviceProxy::ReadEapConfig(MessageParcel &reply, WifiEapConfig &wifiEapConfig)
{
    wifiEapConfig.eap = reply.ReadString();
    wifiEapConfig.phase2Method = Phase2Method(reply.ReadInt32());
    wifiEapConfig.identity = reply.ReadString();
    wifiEapConfig.anonymousIdentity = reply.ReadString();
    wifiEapConfig.password = reply.ReadString();
    wifiEapConfig.caCertPath = reply.ReadString();
    wifiEapConfig.caCertAlias = reply.ReadString();
    reply.ReadUInt8Vector(&wifiEapConfig.certEntry);
    wifiEapConfig.clientCert = reply.ReadString();
    if (strcpy_s(wifiEapConfig.certPassword, sizeof(wifiEapConfig.certPassword),
        reply.ReadString().c_str()) != EOK) {
        WIFI_LOGE("%{public}s: failed to copy", __func__);
    }
    wifiEapConfig.privateKey = reply.ReadString();
    wifiEapConfig.altSubjectMatch = reply.ReadString();
    wifiEapConfig.domainSuffixMatch = reply.ReadString();
    wifiEapConfig.realm = reply.ReadString();
    wifiEapConfig.plmn = reply.ReadString();
    wifiEapConfig.eapSubId = reply.ReadInt32();
}

void WifiDeviceProxy::BigDataReadEapConfig(WifiEapConfig &wifiEapConfig, std::vector<std::string> &tokens)
{
    wifiEapConfig.eap = HexToString(tokens[g_bigDataRecvLen++]);
    wifiEapConfig.phase2Method = Phase2Method(CheckDataLegal(tokens[g_bigDataRecvLen++]));
    wifiEapConfig.identity = HexToString(tokens[g_bigDataRecvLen++]);
    wifiEapConfig.anonymousIdentity = HexToString(tokens[g_bigDataRecvLen++]);
    wifiEapConfig.password = HexToString(tokens[g_bigDataRecvLen++]);
    wifiEapConfig.caCertPath = HexToString(tokens[g_bigDataRecvLen++]);
    wifiEapConfig.caCertAlias = HexToString(tokens[g_bigDataRecvLen++]);
    wifiEapConfig.clientCert = HexToString(tokens[g_bigDataRecvLen++]);
    wifiEapConfig.privateKey = HexToString(tokens[g_bigDataRecvLen++]);
    wifiEapConfig.altSubjectMatch = HexToString(tokens[g_bigDataRecvLen++]);
    wifiEapConfig.domainSuffixMatch = HexToString(tokens[g_bigDataRecvLen++]);
    wifiEapConfig.realm = HexToString(tokens[g_bigDataRecvLen++]);
    wifiEapConfig.plmn = HexToString(tokens[g_bigDataRecvLen++]);
    wifiEapConfig.eapSubId = CheckDataLegal(tokens[g_bigDataRecvLen++]);
}

std::vector<std::string> splitString(std::string str, char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    size_t pos = 0;
    while ((pos = str.find(delimiter)) != std::string::npos) {
        token = str.substr(0, pos);
        tokens.push_back(token);
        str.erase(0, pos + 1);
    }
    tokens.push_back(str);
    return tokens;
}

void WifiDeviceProxy::ParseDeviceConfigs(MessageParcel &reply, std::vector<WifiDeviceConfig> &result)
{
    WIFI_LOGI("ParseDeviceConfigs");
    constexpr int MAX_DEVICE_CONFIG_SIZE = 1024;
    std::vector<uint32_t> allSize;
    reply.ReadUInt32Vector(&allSize);
    uint32_t retSize = allSize.size();
    if (retSize > MAX_DEVICE_CONFIG_SIZE || retSize == 0) {
        WIFI_LOGE("Parse device config size error: %{public}d", retSize);
        return;
    }
    sptr<Ashmem> ashmem = reply.ReadAshmem();
    if (ashmem == nullptr || !ashmem->MapReadAndWriteAshmem()) {
        WIFI_LOGE("ParseDeviceConfigs ReadAshmem error");
        return;
    }
    int offset = 0;
    for (uint32_t i = 0; i < retSize; i++) {
        auto origin = ashmem->ReadFromAshmem(allSize[i], offset);
        if (origin == nullptr) {
            offset += static_cast<int>(allSize[i]);
            continue;
        }
        MessageParcel inParcel;
        inParcel.WriteBuffer(reinterpret_cast<const char*>(origin), allSize[i]);
        WifiDeviceConfig config;
        ReadDeviceConfig(inParcel, config);
        offset += static_cast<int>(allSize[i]);
        result.emplace_back(config);
    }
    ashmem->UnmapAshmem();
    ashmem->CloseAshmem();
    return;
}

void WifiDeviceProxy::WifiDeviceProxy::ParseMultiLinkedInfo(MessageParcel &reply, std::vector<WifiLinkedInfo> &result)
{
    std::vector<uint32_t> allSize;
    reply.ReadUInt32Vector(&allSize);
    uint32_t retSize = static_cast<uint32_t>(allSize.size());
    if (retSize > WIFI_MAX_MLO_LINK_NUM || retSize == 0) {
        WIFI_LOGE("Parse multi linked info size error: %{public}d", retSize);
        return;
    }
    sptr<Ashmem> ashmem = reply.ReadAshmem();
    if (ashmem == nullptr || !ashmem->MapReadAndWriteAshmem()) {
        WIFI_LOGE("ParseMultiLinkedInfo ReadAshmem error");
        return;
    }
    int offset = 0;
    for (uint32_t i = 0; i < retSize; i++) {
        auto origin = ashmem->ReadFromAshmem(allSize[i], offset);
        if (origin == nullptr) {
            offset += static_cast<int>(allSize[i]);
            continue;
        }
        MessageParcel inParcel;
        inParcel.WriteBuffer(reinterpret_cast<const char*>(origin), allSize[i]);
        WifiLinkedInfo info;
        ReadLinkedInfo(inParcel, info);
        offset += static_cast<int>(allSize[i]);
        result.emplace_back(info);
    }
    ashmem->UnmapAshmem();
    ashmem->CloseAshmem();
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIGS),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIGS), error);
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

ErrCode WifiDeviceProxy::SetTxPower(int power)
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
    data.WriteInt32(power);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_TX_POWER), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_TX_POWER), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_DEVICE), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_DEVICE), error);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_DEVICE), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_DEVICE), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::AllowAutoConnect(int32_t networkId, bool isAllowed)
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
    data.WriteBool(isAllowed);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ALLOW_AUTO_CONNECT), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_ALLOW_AUTO_CONNECT), error);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT_TO), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT_TO), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT2_TO), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT2_TO), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::StartRoamToNetwork(const int networkId, const std::string bssid, const bool isCandidate)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to %{public}s,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("%{public}s write interface token error.", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32(networkId);
    data.WriteString(bssid);
    data.WriteInt32(isCandidate);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_ROAM_TO_NETWORK), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("StartRoamToNetwork %{public}d failed, error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_ROAM_TO_NETWORK), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        WIFI_LOGE("StartRoamToNetwork Reply Read failed, exception:%{public}d", exception);
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("StartRoamToNetwork Reply Read failed, ret:%{public}d", ret);
        return ErrCode(ret);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::StartConnectToUserSelectNetwork(const int networkId,
    const std::string bssid, const bool isCandidate)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to StartConnectToUserSelectNetwork, remote service is died!");
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token has error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32(networkId);
    data.WriteString(bssid);
    data.WriteInt32(isCandidate);
    int error = Remote()->SendRequest(static_cast<uint32_t>(
        DevInterfaceCode::WIFI_SVR_CMD_START_CONNECT_TO_USER_SELECT_NETWORK), data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("StartConnectToUserSelectNetwork %{public}d failed, error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_ROAM_TO_NETWORK), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        WIFI_LOGE("StartConnectToUserSelectNetwork Reply Read failed, exception:%{public}d", exception);
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("StartConnectToUserSelectNetwork Reply Read failed, ret:%{public}d", ret);
        return ErrCode(ret);
    }
    return WIFI_OPT_SUCCESS;
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_CONNECTED), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_CONNECTED), error);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_RECONNECT), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_RECONNECT), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REASSOCIATE), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REASSOCIATE), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISCONNECT), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISCONNECT), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_WPS), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_WPS), error);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CANCEL_WPS), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_CANCEL_WPS), error);
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
    if (g_deviceCallBackStub->GetWifiState() != DEFAULT_VALUES) {
        bActive = g_deviceCallBackStub->GetWifiState();
        return WIFI_OPT_SUCCESS;
    }
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_ACTIVE), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_ACTIVE), error);
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
    g_deviceCallBackStub->SetWifiState(bActive);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_STATE), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_STATE), error);
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
    info.ipAddress = static_cast<uint32_t>(reply.ReadInt32());
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
    info.wifiStandard = reply.ReadInt32();
    info.maxSupportedRxLinkSpeed = reply.ReadInt32();
    info.maxSupportedTxLinkSpeed = reply.ReadInt32();
    int tmpChanWidth = reply.ReadInt32();
    if ((tmpChanWidth >= 0) && (tmpChanWidth <= (int)WifiChannelWidth::WIDTH_INVALID)) {
        info.channelWidth = (WifiChannelWidth)tmpChanWidth;
    } else {
        info.channelWidth = WifiChannelWidth::WIDTH_INVALID;
    }
    info.isAncoConnected = reply.ReadBool();
    info.supportedWifiCategory = static_cast<WifiCategory>(reply.ReadInt32());
    info.isHiLinkNetwork = reply.ReadInt32();
    info.lastRxPackets = reply.ReadInt32();
    info.lastTxPackets = reply.ReadInt32();
    info.wifiLinkType = static_cast<WifiLinkType>(reply.ReadInt32());
    info.linkId = reply.ReadInt32();
}

void WifiDeviceProxy::ReadWifiSignalPollInfo(MessageParcel &reply, std::vector<WifiSignalPollInfo> &wifiSignalPollInfos)
{
    int arrayLength = reply.ReadInt32();
    for (int index = 0; index < arrayLength; index++) {
        WifiSignalPollInfo signInfo;
        signInfo.signal = reply.ReadInt32();
        signInfo.txrate = reply.ReadInt32();
        signInfo.rxrate = reply.ReadInt32();
        signInfo.noise = reply.ReadInt32();
        signInfo.txPackets = reply.ReadInt32();
        signInfo.rxPackets = reply.ReadInt32();
        signInfo.snr = reply.ReadInt32();
        signInfo.chload = reply.ReadInt32();
        signInfo.ulDelay = reply.ReadInt32();
        signInfo.txBytes = reply.ReadUint32();
        signInfo.rxBytes = reply.ReadUint32();
        signInfo.txFailed = reply.ReadInt32();
        signInfo.chloadSelf = reply.ReadInt32();
        signInfo.timeStamp = reply.ReadInt64();
        wifiSignalPollInfos.push_back(signInfo);
    }
}

ErrCode WifiDeviceProxy::GetDisconnectedReason(DisconnectedReason &reason)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DISCONNECTED_REASON),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DISCONNECTED_REASON), error);
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
    int tempReason = reply.ReadInt32();
    if (tempReason >= 0 && tempReason < static_cast<int>(DisconnectedReason::DISC_REASON_MAX_VALUE)) {
        reason = (DisconnectedReason)tempReason;
    } else {
        reason = DisconnectedReason::DISC_REASON_DEFAULT;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::IsMeteredHotspot(bool &bMeteredHotspot)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_METERED_HOTSPOT),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_METERED_HOTSPOT), error);
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

    bMeteredHotspot = reply.ReadBool();
    return WIFI_OPT_SUCCESS;
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_LINKED_INFO), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_LINKED_INFO), error);
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

ErrCode WifiDeviceProxy::GetSignalPollInfoArray(std::vector<WifiSignalPollInfo> &wifiSignalPollInfos, int length)
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
    data.WriteInt32(length);
    
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNALPOLL_INFO_ARRAY),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNALPOLL_INFO_ARRAY), error);
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
    ReadWifiSignalPollInfo(reply, wifiSignalPollInfos);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_INFO), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_INFO), error);
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

    info.ipAddress = static_cast<uint32_t>(reply.ReadInt32());
    info.gateway = static_cast<uint32_t>(reply.ReadInt32());
    info.netmask = static_cast<uint32_t>(reply.ReadInt32());
    info.primaryDns = static_cast<uint32_t>(reply.ReadInt32());
    info.secondDns = static_cast<uint32_t>(reply.ReadInt32());
    info.serverIp = static_cast<uint32_t>(reply.ReadInt32());
    info.leaseDuration = static_cast<uint32_t>(reply.ReadInt32());
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::GetIpv6Info(IpV6Info &info)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_IPV6INFO),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_IPV6INFO), error);
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
    info.linkIpV6Address = reply.ReadString();
    info.globalIpV6Address = reply.ReadString();
    info.randGlobalIpV6Address = reply.ReadString();
    info.uniqueLocalAddress1 = reply.ReadString();
    info.uniqueLocalAddress2 = reply.ReadString();
    info.gateway = reply.ReadString();
    info.netmask = reply.ReadString();
    info.primaryDns = reply.ReadString();
    info.secondDns = reply.ReadString();
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_COUNTRY_CODE), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_COUNTRY_CODE), error);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_COUNTRY_CODE), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_COUNTRY_CODE), error);
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

ErrCode WifiDeviceProxy::RegisterCallBack(const sptr<IWifiDeviceCallBack> &callback,
    const std::vector<std::string> &event)
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

    std::vector<std::string> trace;
    std::copy(event.begin(), event.end(), std::back_inserter(trace));
    auto it = std::find(trace.begin(), trace.end(), EVENT_STA_POWER_STATE_CHANGE);
    if (it == trace.end()) {
        trace.push_back(EVENT_STA_POWER_STATE_CHANGE);
    }

    if (!data.WriteRemoteObject(g_deviceCallBackStub->AsObject())) {
        WIFI_LOGE("WifiDeviceProxy::RegisterCallBack WriteRemoteObject failed!");
        return WIFI_OPT_FAILED;
    }

    int pid = GetCallingPid();
    data.WriteInt32(pid);
    int tokenId = GetCallingTokenId();
    data.WriteInt32(tokenId);
    int eventNum = static_cast<int>(trace.size());
    data.WriteInt32(eventNum);
    if (eventNum > 0) {
        for (auto &eventName : trace) {
            data.WriteString(eventName);
        }
    }
    WIFI_LOGD("%{public}s, calling uid: %{public}d, pid: %{public}d, tokenId: %{private}d",
        __func__, GetCallingUid(), pid, tokenId);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed, code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT), error);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNAL_LEVEL), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNAL_LEVEL), error);
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES), error);
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

ErrCode WifiDeviceProxy::IsFeatureSupported(long feature, bool &isSupported)
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
    data.WriteInt64(feature);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_FEATURE_SUPPORTED),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_FEATURE_SUPPORTED), error);
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

    isSupported = reply.ReadInt32();
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DERVICE_MAC_ADD),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DERVICE_MAC_ADD));
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_LATENCY_MODE), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_LATENCY_MODE), error);
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

ErrCode WifiDeviceProxy::IsBandTypeSupported(int bandType, bool &supported)
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
    data.WriteInt32(bandType);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_BANDTYPE_SUPPORTED),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("IsBandTypeSupported (%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_BANDTYPE_SUPPORTED), error);
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
    supported = reply.ReadInt32();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::Get5GHzChannelList(std::vector<int> &result)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    constexpr int MAX_CHANNEL_SIZE = 36;
    MessageOption option;
    MessageParcel data, reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNELLIST), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Get5GHzChannelList(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNELLIST), error);
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
    int retSize = reply.ReadInt32();
    if (retSize > MAX_CHANNEL_SIZE) {
        WIFI_LOGE("Get5GHzChannelList fail, size error: %{public}d", retSize);
        return WIFI_OPT_FAILED;
    }
    for (int i = 0; i < retSize; ++i) {
        result.emplace_back(reply.ReadInt32());
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::SetAppFrozen(std::set<int> pidList, bool isFrozen)
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
    int size = static_cast<int>(pidList.size() < MAX_PID_LIST_SIZE ? pidList.size() : MAX_PID_LIST_SIZE);
    int count = 0;
    data.WriteInt32(size);
    for (std::set<int>::iterator it = pidList.begin(); it != pidList.end() && count < size; it++, count++) {
        data.WriteInt32(*it);
    }
    data.WriteBool(isFrozen);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_FROZEN_APP), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("SetAppFrozen(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_FROZEN_APP), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::ResetAllFrozenApp()
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_RESET_ALL_FROZEN_APP), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Get5GHzChannelList(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_RESET_ALL_FROZEN_APP), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::DisableAutoJoin(const std::string &conditionName)
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
    data.WriteString(conditionName);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_AUTO_JOIN), data,
                                      reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("DisableAutoJoin (%{public}d) failed,error code is %{public}d",
                  static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_AUTO_JOIN), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::EnableAutoJoin(const std::string &conditionName)
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
    data.WriteString(conditionName);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_AUTO_JOIN), data,
                                      reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("EnableAutoJoin(%{public}d) failed,error code is %{public}d",
                  static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_AUTO_JOIN), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::RegisterAutoJoinCondition(const std::string &conditionName,
                                                   const std::function<bool()> &autoJoinCondition)
{
    return WIFI_OPT_FAILED;
}

ErrCode WifiDeviceProxy::DeregisterAutoJoinCondition(const std::string &conditionName)
{
    return WIFI_OPT_FAILED;
}

ErrCode WifiDeviceProxy::RegisterFilterBuilder(const FilterTag &filterTag,
                                               const std::string &filterName,
                                               const FilterBuilder &filterBuilder)
{
    return WIFI_OPT_FAILED;
}

ErrCode WifiDeviceProxy::DeregisterFilterBuilder(const FilterTag &filterTag, const std::string &filterName)
{
    return WIFI_OPT_FAILED;
}

ErrCode WifiDeviceProxy::RegisterCommonBuilder(const TagType &tagType, const std::string &tagName,
                                               const CommonBuilder &commonBuilder)
{
    return WIFI_OPT_FAILED;
}

ErrCode WifiDeviceProxy::DeregisterCommonBuilder(const TagType &tagType, const std::string &tagName)
{
    return WIFI_OPT_FAILED;
}

ErrCode WifiDeviceProxy::StartPortalCertification()
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_PORTAL_CERTIF), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("StartPortalCertification(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_PORTAL_CERTIF), error);
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

ErrCode WifiDeviceProxy::GetChangeDeviceConfig(ConfigChange &value, WifiDeviceConfig &config)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIG_CHANGE),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("GetChangeDeviceConfig (%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIG_CHANGE), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    value = (ConfigChange)reply.ReadInt32();
    config.networkId = reply.ReadInt32();
    config.ssid = reply.ReadString();
    config.bssid = reply.ReadString();
    config.callProcessName = reply.ReadString();
    config.ancoCallProcessName = reply.ReadString();
    config.keyMgmt = reply.ReadString();
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::FactoryReset()
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`, remote service is died.", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error, func:%{public}s", __func__);
        return WIFI_OPT_FAILED;
    }

    data.WriteInt32(0);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_SET_FACTORY_RESET), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("FactoryReset(%{public}d) failed, error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_SET_FACTORY_RESET), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        WIFI_LOGE("Reply Read failed, exception:%{public}d", exception);
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Reply Read failed, ret:%{public}d", ret);
        return ErrCode(ret);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::ReceiveNetworkControlInfo(const WifiNetworkControlInfo& networkControlInfo)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to %{public}s,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token has error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }

    data.WriteInt32(0);
    data.WriteInt32(networkControlInfo.uid);
    data.WriteInt32(networkControlInfo.pid);
    data.WriteString(networkControlInfo.bundleName);
    data.WriteInt32(networkControlInfo.state);
    data.WriteInt32(networkControlInfo.sceneId);
    data.WriteInt32(networkControlInfo.rtt);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_NET_CONTROL_INFO), data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("ReceiveNetworkControlInfo(%{public}d) failed, error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_NET_CONTROL_INFO), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        WIFI_LOGE("ReceiveNetworkControlInfo Reply Read failed, exception:%{public}d", exception);
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("ReceiveNetworkControlInfo Reply Read failed, ret:%{public}d", ret);
        return ErrCode(ret);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::LimitSpeed(const int controlId, const int limitMode)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to %{public}s,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token has error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    data.WriteInt32(controlId);
    data.WriteInt32(limitMode);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_LIMIT_SPEED), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("LimitSpeed(%{public}d) failed, error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_LIMIT_SPEED), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        WIFI_LOGE("LimitSpeed Reply Read failed, exception:%{public}d", exception);
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("LimitSpeed Reply Read failed, ret:%{public}d", ret);
        return ErrCode(ret);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::SetLowTxPower(const WifiLowPowerParam wifiLowPowerParam)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to %{public}s,remote service is died!", __func__);
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
    data.WriteString(wifiLowPowerParam.ifName);
    data.WriteInt32(wifiLowPowerParam.scene);
    data.WriteInt32(wifiLowPowerParam.rssiThreshold);
    data.WriteString(wifiLowPowerParam.peerMacaddr);
    data.WriteString(wifiLowPowerParam.powerParam);
    data.WriteInt32(wifiLowPowerParam.powerParamLen);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_TX_POWER), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("SetLowTxPower(%{public}d) failed, error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_TX_POWER), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        WIFI_LOGE("SetLowTxPower Reply Read failed, exception:%{public}d", exception);
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("SetLowTxPower Reply Read failed, ret:%{public}d", ret);
        return ErrCode(ret);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::EnableHiLinkHandshake(bool uiFlag, std::string &bssid, WifiDeviceConfig &deviceConfig)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to `%{public}s`, remote service is died.", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageParcel data, reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error, func:%{public}s", __func__);
        return WIFI_OPT_FAILED;
    }

    data.WriteInt32(0);
    data.WriteBool(uiFlag);
    data.WriteString(bssid);
    WriteDeviceConfig(deviceConfig, data);

    //Wirte device config
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_HILINK_CONNECT), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("EnableHiLinkHandshake(%{public}d) failed, error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_HILINK_CONNECT), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        WIFI_LOGE("Reply Read failed, exception:%{public}d", exception);
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Reply Read failed, ret:%{public}d", ret);
        return ErrCode(ret);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::SetSatelliteState(const int state)
{
    if (mRemoteDied) {
        WIFI_LOGE("failed to %{public}s,remote service is died!", __func__);
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
    data.WriteInt32(state);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_SATELLITE_STATE), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("SetSatelliteState(%{public}d) failed, error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_SATELLITE_STATE), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        WIFI_LOGE("SetSatelliteState Reply Read failed, exception:%{public}d", exception);
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("SetSatelliteState Reply Read failed, ret:%{public}d", ret);
        return ErrCode(ret);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::EnableSemiWifi()
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_SEMI_WIFI), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_SEMI_WIFI), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiDeviceProxy::GetWifiDetailState(WifiDetailState &state)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_DETAIL_STATE), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_DETAIL_STATE), error);
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

    int tempState = reply.ReadInt32();
    if (tempState >= 0 && tempState <= static_cast<int>(WifiDetailState::STATE_SEMI_ACTIVE)) {
        state = static_cast<WifiDetailState>(tempState);
    } else {
        state = WifiDetailState::STATE_UNKNOWN;
    }
    return WIFI_OPT_SUCCESS;
}

void WifiDeviceProxy::ReadDeviceConfig(MessageParcel &reply, WifiDeviceConfig &config)
{
    config.networkId = reply.ReadInt32();
    config.bssid = reply.ReadString();
    config.bssidType = reply.ReadInt32();
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
    ReadEapConfig(reply, config.wifiEapConfig);
    config.wifiProxyconfig.configureMethod = ConfigureProxyMethod(reply.ReadInt32());
    config.wifiProxyconfig.autoProxyConfig.pacWebAddress = reply.ReadString();
    config.wifiProxyconfig.manualProxyConfig.serverHostName = reply.ReadString();
    config.wifiProxyconfig.manualProxyConfig.serverPort = reply.ReadInt32();
    config.wifiProxyconfig.manualProxyConfig.exclusionObjectList = reply.ReadString();
    config.wifiPrivacySetting = WifiPrivacyConfig(reply.ReadInt32());
    config.uid = reply.ReadInt32();
    config.callProcessName = reply.ReadString();
    config.ancoCallProcessName = reply.ReadString();
    config.wifiWapiConfig.wapiPskType = reply.ReadInt32();
    config.networkSelectionStatus.status = WifiDeviceConfigStatus(reply.ReadInt32());
    config.networkSelectionStatus.networkSelectionDisableReason = DisabledReason(reply.ReadInt32());
    config.networkSelectionStatus.seenInLastQualifiedNetworkSelection = reply.ReadBool();
    config.isPortal = reply.ReadBool();
    config.noInternetAccess = reply.ReadBool();
    config.isAllowAutoConnect = reply.ReadBool();
}

ErrCode WifiDeviceProxy::GetDeviceConfig(const int &networkId, WifiDeviceConfig &config)
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
    data.WriteInt32(networkId);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIG),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIG), error);
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

    ReadDeviceConfig(reply, config);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::SetDpiMarkRule(const std::string &ifaceName, int uid, int protocol, int enable)
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
    data.WriteCString(ifaceName.c_str());
    data.WriteInt32(uid);
    data.WriteInt32(protocol);
    data.WriteInt32(enable);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_DPI_MARK_RULE),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_DPI_MARK_RULE), error);
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

ErrCode WifiDeviceProxy::UpdateNetworkLagInfo(const NetworkLagType networkLagType, const NetworkLagInfo &networkLagInfo)
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
    data.WriteInt32(static_cast<int32_t>(networkLagType));
    data.WriteInt32(static_cast<int32_t>(networkLagInfo.uid));
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_NETWORK_LAG_INFO), data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_NETWORK_LAG_INFO),
            error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

void WifiDeviceProxy::ReadSignalInfoForVoWiFi(MessageParcel &reply, VoWifiSignalInfo &signalInfo)
{
    signalInfo.rssi = reply.ReadInt32();
    signalInfo.noise = reply.ReadInt32();
    signalInfo.bler = reply.ReadInt32();
    signalInfo.deltaTxPacketCounter = reply.ReadInt32();
    signalInfo.accessType = reply.ReadInt32();
    signalInfo.reverse = reply.ReadInt32();
    signalInfo.txGood = reply.ReadInt64();
    signalInfo.txBad = reply.ReadInt64();
    signalInfo.macAddress = reply.ReadString();
}

ErrCode WifiDeviceProxy::FetchWifiSignalInfoForVoWiFi(VoWifiSignalInfo &signalInfo)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_FETCH_SIGNALINFO_VOWIFI),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_FETCH_SIGNALINFO_VOWIFI), error);
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
 
    ReadSignalInfoForVoWiFi(reply, signalInfo);
    return WIFI_OPT_SUCCESS;
}
 
ErrCode WifiDeviceProxy::IsSupportVoWifiDetect(bool &isSupported)
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
    data.WriteInt32(isSupported);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_SUPPORT_VOWIFI_DETECT),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_SUPPORT_VOWIFI_DETECT), error);
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
    isSupported = reply.ReadInt32();
    return WIFI_OPT_SUCCESS;
}
 
ErrCode WifiDeviceProxy::SetVoWifiDetectMode(WifiDetectConfInfo info)
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
    data.WriteInt32(info.wifiDetectMode);
    data.WriteInt32(info.threshold);
    data.WriteInt32(info.envalueCount);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_VOWIFI_DETECT_MODE),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_VOWIFI_DETECT_MODE), error);
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
 
ErrCode WifiDeviceProxy::GetVoWifiDetectMode(WifiDetectConfInfo &info)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_VOWIFI_DETECT_MODE),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_VOWIFI_DETECT_MODE), error);
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
    info.wifiDetectMode = reply.ReadInt32();
    info.threshold = reply.ReadInt32();
    info.envalueCount = reply.ReadInt32();
    return WIFI_OPT_SUCCESS;
}
 
ErrCode WifiDeviceProxy::SetVoWifiDetectPeriod(int period)
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
    data.WriteInt32(period);
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_VOWIFI_DETECT_PERIOD),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_VOWIFI_DETECT_PERIOD), error);
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
 
ErrCode WifiDeviceProxy::GetVoWifiDetectPeriod(int &period)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_VOWIFI_DETECT_PERIOD),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_VOWIFI_DETECT_PERIOD), error);
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
    period = reply.ReadInt32();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiDeviceProxy::GetMultiLinkedInfo(std::vector<WifiLinkedInfo> &multiLinkedInfo)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_MULTI_LINKED_INFO), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_LINKED_INFO), error);
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

    ParseMultiLinkedInfo(reply, multiLinkedInfo);
    return WIFI_OPT_SUCCESS;
}

void WifiDeviceProxy::OnWifiStateChanged(int state)
{
    WIFI_LOGI("WifiDeviceProxy::OnWifiStateChanged, state %{public}d", state);
    if (state == static_cast<int>(WifiState::ENABLED)) {
        g_deviceCallBackStub->SetWifiState(true);
    } else {
        g_deviceCallBackStub->SetWifiState(false);
    }
}
}  // namespace Wifi
}  // namespace OHOS
