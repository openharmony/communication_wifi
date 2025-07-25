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
#include "wifi_p2p_proxy.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_logger.h"
#include "wifi_p2p_callback_stub.h"
#include "wifi_common_util.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_P2P_LABEL("WifiP2pProxy");

static sptr<WifiP2pCallbackStub> g_wifiP2pCallbackStub =
    sptr<WifiP2pCallbackStub>(new (std::nothrow) WifiP2pCallbackStub());

WifiP2pProxy::WifiP2pProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IWifiP2p>(impl),
    mRemoteDied(false), remote_(nullptr), deathRecipient_(nullptr)
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
        WIFI_LOGI("AddDeathRecipient success! deathRecipient_");
    }
}

WifiP2pProxy::~WifiP2pProxy()
{
    WIFI_LOGI("enter ~WifiP2pProxy!");
    RemoveDeathRecipient();
}

void WifiP2pProxy::RemoveDeathRecipient(void)
{
    WIFI_LOGI("enter RemoveDeathRecipient, deathRecipient_!");
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

ErrCode WifiP2pProxy::EnableP2p(void)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_ENABLE), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_ENABLE), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::DisableP2p(void)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISABLE), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISABLE), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::DiscoverDevices(void)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISCOVER_DEVICES), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISCOVER_DEVICES), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::StopDiscoverDevices(void)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_DISCOVER_DEVICES),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_DISCOVER_DEVICES), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::DiscoverServices(void)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISCOVER_SERVICES), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISCOVER_SERVICES), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::StopDiscoverServices(void)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_DISCOVER_SERVICES),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_DISCOVER_SERVICES), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::RequestService(const WifiP2pDevice &device, const WifiP2pServiceRequest &request)
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
    WriteWifiP2pServiceRequest(data, device, request);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REQUEST_SERVICES), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REQUEST_SERVICES), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::PutLocalP2pService(const WifiP2pServiceInfo &srvInfo)
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
    WriteWifiP2pServiceInfo(data, srvInfo);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_PUT_LOCAL_SERVICES),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_PUT_LOCAL_SERVICES), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::DeleteLocalP2pService(const WifiP2pServiceInfo &srvInfo)
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
    WriteWifiP2pServiceInfo(data, srvInfo);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DELETE_LOCAL_SERVICES),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DELETE_LOCAL_SERVICES), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::StartP2pListen(int period, int interval)
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
    data.WriteInt32(period);
    data.WriteInt32(interval);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_START_LISTEN), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_START_LISTEN), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::StopP2pListen(void)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_LISTEN), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_LISTEN), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::CreateGroup(const WifiP2pConfig &config)
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
    WriteWifiP2pConfigData(data, config);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CREATE_GROUP), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CREATE_GROUP), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::RemoveGroup()
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REMOVE_GROUP), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REMOVE_GROUP), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::RemoveGroupClient(const GcInfo &info)
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
    data.WriteString(info.ip);
    data.WriteString(info.mac);
    data.WriteString(info.host);

    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REMOVE_GROUP_CLIENT),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            P2PInterfaceCode::WIFI_SVR_CMD_P2P_REMOVE_GROUP_CLIENT, error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::DeleteGroup(const WifiP2pGroupInfo &group)
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
    WriteWifiP2pGroupData(data, group);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DELETE_GROUP), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DELETE_GROUP), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

void WifiP2pProxy::ReadWifiP2pServiceInfo(MessageParcel &reply, WifiP2pServiceInfo &info) const
{
    const char *readStr = nullptr;
    readStr = reply.ReadCString();
    info.SetServiceName((readStr != nullptr) ? readStr : "");
    readStr = reply.ReadCString();
    info.SetDeviceAddress((readStr != nullptr) ? readStr : "");
    info.SetServicerProtocolType(static_cast<P2pServicerProtocolType>(reply.ReadInt32()));
    std::vector<std::string> queryList;

    constexpr int MAX_SIZE = 512;
    int size = reply.ReadInt32();
    if (size > MAX_SIZE) {
        WIFI_LOGE("P2p service size error: %{public}d", size);
        return;
    }
    for (int i = 0; i < size; i++) {
        readStr = reply.ReadCString();
        std::string str = (readStr != nullptr) ? readStr : "";
        queryList.push_back(str);
    }
    info.SetQueryList(queryList);
    return;
}

void WifiP2pProxy::WriteWifiP2pServiceInfo(MessageParcel &data, const WifiP2pServiceInfo &info) const
{
    data.WriteCString(info.GetServiceName().c_str());
    data.WriteCString(info.GetDeviceAddress().c_str());
    data.WriteInt32(static_cast<int>(info.GetServicerProtocolType()));
    std::vector<std::string> queryList = info.GetQueryList();
    data.WriteInt32(queryList.size());
    for (std::size_t i = 0; i < queryList.size(); i++) {
        data.WriteCString(queryList[i].c_str());
    }
    return;
}

void WifiP2pProxy::WriteWifiP2pServiceRequest(
    MessageParcel &data, const WifiP2pDevice &device, const WifiP2pServiceRequest &request) const
{
    WriteWifiP2pDeviceData(data, device);
    data.WriteInt32(static_cast<int>(request.GetProtocolType()));
    data.WriteInt32(request.GetTransactionId());
    std::vector<unsigned char> query = request.GetQuery();
    data.WriteInt32(query.size());
    for (std::size_t i = 0; i < query.size(); i++) {
        data.WriteInt8(query[i]);
    }
    return;
}

void WifiP2pProxy::WriteWifiP2pDeviceData(MessageParcel &data, const WifiP2pDevice &device) const
{
    data.WriteString(device.GetDeviceName());
    data.WriteString(device.GetDeviceAddress());
    data.WriteInt32(device.GetDeviceAddressType());
    data.WriteString(device.GetPrimaryDeviceType());
    data.WriteString(device.GetSecondaryDeviceType());
    data.WriteInt32(static_cast<int>(device.GetP2pDeviceStatus()));
    data.WriteBool(device.GetWfdInfo().GetWfdEnabled());
    data.WriteInt32(device.GetWfdInfo().GetDeviceInfo());
    data.WriteInt32(device.GetWfdInfo().GetCtrlPort());
    data.WriteInt32(device.GetWfdInfo().GetMaxThroughput());
    data.WriteInt32(device.GetWpsConfigMethod());
    data.WriteInt32(device.GetDeviceCapabilitys());
    data.WriteInt32(device.GetGroupCapabilitys());
}

void WifiP2pProxy::ReadWifiP2pDeviceData(MessageParcel &reply, WifiP2pDevice &device) const
{
    device.SetDeviceName(reply.ReadString());
    device.SetDeviceAddress(reply.ReadString());
    device.SetRandomDeviceAddress(reply.ReadString());
    device.SetDeviceAddressType(reply.ReadInt32());
    device.SetPrimaryDeviceType(reply.ReadString());
    device.SetSecondaryDeviceType(reply.ReadString());
    device.SetP2pDeviceStatus(static_cast<P2pDeviceStatus>(reply.ReadInt32()));
    WifiP2pWfdInfo wfdInfo;
    wfdInfo.SetWfdEnabled(reply.ReadBool());
    wfdInfo.SetDeviceInfo(reply.ReadInt32());
    wfdInfo.SetCtrlPort(reply.ReadInt32());
    wfdInfo.SetMaxThroughput(reply.ReadInt32());
    device.SetWfdInfo(wfdInfo);
    device.SetWpsConfigMethod(reply.ReadInt32());
    device.SetDeviceCapabilitys(reply.ReadInt32());
    device.SetGroupCapabilitys(reply.ReadInt32());
    device.SetGroupAddress(reply.ReadString());
}

void WifiP2pProxy::WriteWifiP2pGroupData(MessageParcel &data, const WifiP2pGroupInfo &info) const
{
    data.WriteBool(info.IsGroupOwner());
    WriteWifiP2pDeviceData(data, info.GetOwner());
    data.WriteString(info.GetPassphrase());
    data.WriteString(info.GetInterface());
    data.WriteString(info.GetGroupName());
    data.WriteInt32(info.GetFrequency());
    data.WriteBool(info.IsPersistent());
    data.WriteInt32(static_cast<int>(info.GetP2pGroupStatus()));
    data.WriteInt32(info.GetNetworkId());
    data.WriteString(info.GetGoIpAddress());
    std::vector<WifiP2pDevice> deviceVec;
    deviceVec = info.GetClientDevices();
    data.WriteInt32(deviceVec.size());
    for (auto it = deviceVec.begin(); it != deviceVec.end(); ++it) {
        WriteWifiP2pDeviceData(data, *it);
    }
}

void WifiP2pProxy::ReadWifiP2pGroupData(MessageParcel &reply, WifiP2pGroupInfo &info) const
{
    info.SetIsGroupOwner(reply.ReadBool());
    WifiP2pDevice device;
    ReadWifiP2pDeviceData(reply, device);
    info.SetOwner(device);
    info.SetPassphrase(reply.ReadString());
    info.SetInterface(reply.ReadString());
    info.SetGroupName(reply.ReadString());
    info.SetFrequency(reply.ReadInt32());
    info.SetIsPersistent(reply.ReadBool());
    info.SetP2pGroupStatus(static_cast<P2pGroupStatus>(reply.ReadInt32()));
    info.SetNetworkId(reply.ReadInt32());
    info.SetGoIpAddress(reply.ReadString());
    info.SetGcIpAddress(reply.ReadString());

    constexpr int MAX_SIZE = 512;
    int size = reply.ReadInt32();
    if (size > MAX_SIZE) {
        WIFI_LOGE("Group info device size error: %{public}d", size);
        return;
    }
    for (auto it = 0; it < size; ++it) {
        WifiP2pDevice cliDev;
        ReadWifiP2pDeviceData(reply, cliDev);
        info.AddClientDevice(cliDev);
    }
}

void WifiP2pProxy::WriteWifiP2pConfigData(MessageParcel &data, const WifiP2pConfig &config) const
{
    data.WriteString(config.GetDeviceAddress());
    data.WriteInt32(config.GetDeviceAddressType());
    data.WriteString(config.GetPassphrase());
    data.WriteString(config.GetGroupName());
    data.WriteInt32(static_cast<int>(config.GetGoBand()));
    data.WriteInt32(config.GetNetId());
    data.WriteInt32(config.GetGroupOwnerIntent());
    data.WriteInt32(config.GetFreq());
}

ErrCode WifiP2pProxy::P2pConnect(const WifiP2pConfig &config)
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
    WriteWifiP2pConfigData(data, config);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CONNECT), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CONNECT), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::P2pCancelConnect()
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CANCEL_CONNECT), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CANCEL_CONNECT), error);
        return WIFI_OPT_FAILED;
    }

    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::QueryP2pLinkedInfo(WifiP2pLinkedInfo &linkedInfo)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_INFO), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_INFO), error);
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
    linkedInfo.SetConnectState(static_cast<P2pConnectedState>(reply.ReadInt32()));
    linkedInfo.SetIsGroupOwner(reply.ReadBool());
    std::string groupOwnerAddr = reply.ReadString();
    linkedInfo.SetIsGroupOwnerAddress(groupOwnerAddr);

    int size = reply.ReadInt32();
    for (int i = 0; i < size; i++) {
        linkedInfo.AddClientInfoList(reply.ReadString(), reply.ReadString(), reply.ReadString());
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::GetCurrentGroup(WifiP2pGroupInfo &group)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_CURRENT_GROUP), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_CURRENT_GROUP), error);
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
    ReadWifiP2pGroupData(reply, group);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::GetP2pEnableStatus(int &status)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_ENABLE_STATUS), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_ENABLE_STATUS), error);
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
    status = reply.ReadInt32();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::GetP2pDiscoverStatus(int &status)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_DISCOVER_STATUS),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_DISCOVER_STATUS), error);
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
    status = reply.ReadInt32();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::GetP2pConnectedStatus(int &status)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_CONNECTED_STATUS),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_CONNECTED_STATUS), error);
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
    status = reply.ReadInt32();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::QueryP2pDevices(std::vector<WifiP2pDevice> &devices)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_DEVICES), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_DEVICES), error);
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
        WIFI_LOGE("Get p2p devices size error: %{public}d", size);
        return WIFI_OPT_FAILED;
    }
    for (int i = 0; i < size; ++i) {
        WifiP2pDevice config;
        ReadWifiP2pDeviceData(reply, config);
        devices.emplace_back(config);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::QueryP2pLocalDevice(WifiP2pDevice &device)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_LOCAL_DEVICE),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_LOCAL_DEVICE), error);
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
    ReadWifiP2pDeviceData(reply, device);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::QueryP2pGroups(std::vector<WifiP2pGroupInfo> &groups)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_GROUPS), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_GROUPS), error);
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
        WIFI_LOGE("Get p2p group size error: %{public}d", size);
        return WIFI_OPT_FAILED;
    }
    for (int i = 0; i < size; ++i) {
        WifiP2pGroupInfo group;
        ReadWifiP2pGroupData(reply, group);
        groups.emplace_back(group);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::QueryP2pServices(std::vector<WifiP2pServiceInfo> &services)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_SERVICES), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_SERVICES), error);
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
        WIFI_LOGE("Get p2p service size error: %{public}d", size);
        return WIFI_OPT_FAILED;
    }
    for (int i = 0; i < size; ++i) {
        WifiP2pServiceInfo info;
        ReadWifiP2pServiceInfo(reply, info);
        services.emplace_back(info);
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::SetP2pDeviceName(const std::string &deviceName)
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
    data.WriteString(deviceName);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_SET_DEVICE_NAME), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_SET_DEVICE_NAME), error);
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
    return WIFI_OPT_SUCCESS;
}
ErrCode WifiP2pProxy::SetP2pWfdInfo(const WifiP2pWfdInfo &wfdInfo)
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
    data.WriteBool(wfdInfo.GetWfdEnabled());
    data.WriteInt32(wfdInfo.GetDeviceInfo());
    data.WriteInt32(wfdInfo.GetCtrlPort());
    data.WriteInt32(wfdInfo.GetMaxThroughput());
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_SET_WFD_INFO), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_SET_WFD_INFO), error);
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
    return WIFI_OPT_SUCCESS;
}


ErrCode WifiP2pProxy::RegisterCallBack(const sptr<IWifiP2pCallback> &callback, const std::vector<std::string> &event)
{
    if (mRemoteDied) {
        WIFI_LOGW("failed to `%{public}s`,remote service is died!", __func__);
        return WIFI_OPT_FAILED;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (g_wifiP2pCallbackStub == nullptr) {
        WIFI_LOGE("g_wifiP2pCallbackStub is nullptr");
        return WIFI_OPT_FAILED;
    }
    g_wifiP2pCallbackStub->RegisterCallBack(callback);
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return WIFI_OPT_FAILED;
    }
    data.WriteInt32(0);
    if (!data.WriteRemoteObject(g_wifiP2pCallbackStub->AsObject())) {
        WIFI_LOGE("RegisterCallBack WriteRemoteObject failed!");
        return WIFI_OPT_FAILED;
    }
    int pid = GetCallingPid();
    data.WriteInt32(pid);
    int tokenId = GetCallingTokenId();
    data.WriteInt32(tokenId);
    int eventNum = static_cast<int>(event.size());
    data.WriteInt32(eventNum);
    if (eventNum > 0) {
        for (auto &eventName : event) {
            data.WriteString(eventName);
        }
    }
    WIFI_LOGD("%{public}s, calling uid: %{public}d, pid: %{public}d, tokenId: %{private}d",
        __func__, GetCallingUid(), pid, tokenId);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REGISTER_CALLBACK), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("RegisterCallBack failed, error code is %{public}d", error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    WIFI_LOGD("RegisterCallBack is finished: result=%{public}d", ret);
    return ErrCode(ret);
}

ErrCode WifiP2pProxy::GetSupportedFeatures(long &features)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES), error);
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

ErrCode WifiP2pProxy::Hid2dRequestGcIp(const std::string& gcMac, std::string& ipAddr)
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
    data.WriteCString(gcMac.c_str());
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_APPLY_IP), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_APPLY_IP), error);
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
    const char *ipAddress = reply.ReadCString();
    ipAddr = (ipAddress != nullptr) ? ipAddress : "";
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::Hid2dSharedlinkIncrease()
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
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_SHARED_LINK_INCREASE), data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_SHARED_LINK_INCREASE), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::Hid2dSharedlinkDecrease()
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
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_SHARED_LINK_DECREASE), data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_SHARED_LINK_DECREASE), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::Hid2dCreateGroup(const int frequency, FreqType type)
{
    WIFI_LOGI("Request hid2d create group");

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
    data.WriteInt32(frequency);
    data.WriteInt32(static_cast<int>(type));
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CREATE_GROUP),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CREATE_GROUP), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::Hid2dRemoveGcGroup(const std::string& gcIfName)
{
    WIFI_LOGI("Request hid2d remove group");

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
    data.WriteCString(gcIfName.c_str());
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_REMOVE_GC_GROUP),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_REMOVE_GC_GROUP), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::Hid2dConnect(const Hid2dConnectConfig& config)
{
    WIFI_LOGI("Request hid2d connect");

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
    data.WriteCString(config.GetBssid().c_str());
    data.WriteCString(config.GetPreSharedKey().c_str());
    data.WriteInt32(config.GetFrequency());
    data.WriteInt32(static_cast<int>(config.GetDhcpMode()));
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CONNECT), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CONNECT), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::Hid2dConfigIPAddr(const std::string& ifName, const IpAddrInfo& ipInfo)
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
    data.WriteCString(ifName.c_str());
    data.WriteCString(ipInfo.ip.c_str());
    data.WriteCString(ipInfo.gateway.c_str());
    data.WriteCString(ipInfo.netmask.c_str());
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CONFIG_IP), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CONFIG_IP), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::Hid2dReleaseIPAddr(const std::string& ifName)
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
    data.WriteCString(ifName.c_str());
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_RELEASE_IP), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_RELEASE_IP), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::Hid2dGetRecommendChannel(const RecommendChannelRequest& request,
    RecommendChannelResponse& response)
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
    data.WriteCString(request.remoteIfName.c_str());
    data.WriteInt32(request.remoteIfMode);
    data.WriteCString(request.localIfName.c_str());
    data.WriteInt32(request.localIfMode);
    data.WriteInt32(request.prefBand);
    data.WriteInt32(static_cast<int>(request.prefBandwidth));
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_P2P_RECOMMENDED_CHANNEL),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_P2P_RECOMMENDED_CHANNEL), error);
        return ErrCode(error);
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    int ret = reply.ReadInt32();
    if (ErrCode(ret) != WIFI_OPT_SUCCESS) {
        return ErrCode(ret);
    }
    response.status = RecommendStatus(reply.ReadInt32());
    response.index = reply.ReadInt32();
    response.centerFreq = reply.ReadInt32();
    response.centerFreq1 = reply.ReadInt32();
    response.centerFreq2 = reply.ReadInt32();
    response.bandwidth = reply.ReadInt32();
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::Hid2dGetChannelListFor5G(std::vector<int>& vecChannelList)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNEL_LIST), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGW("Set Attr(%{public}d) failed",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNEL_LIST));
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
    int listSize = reply.ReadInt32();
    if (listSize > MAX_SIZE) {
        WIFI_LOGE("Get channel list for 5G size error: %{public}d", listSize);
        return WIFI_OPT_FAILED;
    }
    for (int i = 0; i < listSize; ++i) {
        vecChannelList.emplace_back(reply.ReadInt32());
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::Hid2dGetSelfWifiCfgInfo(SelfCfgType cfgType,
    char cfgData[CFG_DATA_MAX_BYTES], int* getDatValidLen)
{
    if (getDatValidLen == nullptr) {
        WIFI_LOGE("getDatValidLen is nullptr!");
        return WIFI_OPT_FAILED;
    }

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
    data.WriteInt32(static_cast<int>(cfgType));
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_SELF_WIFI_CFG), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGW("Set Attr(%{public}d) failed",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_SELF_WIFI_CFG));
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

    *getDatValidLen = reply.ReadInt32();
    if (*getDatValidLen > 0) {
        const char *dataBuffer = (const char *)reply.ReadBuffer(*getDatValidLen);
        if (dataBuffer == nullptr) {
            WIFI_LOGE("`%{public}s` inner communication error!", __func__);
            return WIFI_OPT_FAILED;
        }
        if (memcpy_s(cfgData, CFG_DATA_MAX_BYTES, dataBuffer, *getDatValidLen) != EOK) {
            WIFI_LOGE("`%{public}s` memcpy_s failed!", __func__);
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::Hid2dSetPeerWifiCfgInfo(PeerCfgType cfgType,
    char cfgData[CFG_DATA_MAX_BYTES], int setDataValidLen)
{
    if (setDataValidLen <= 0) {
        WIFI_LOGE("`%{public}s` parameter is error!", __func__);
        return WIFI_OPT_INVALID_PARAM;
    }
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
    data.WriteInt32(static_cast<int>(cfgType));
    data.WriteInt32(setDataValidLen);
    data.WriteBuffer(cfgData, setDataValidLen);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_SET_PEER_WIFI_CFG), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGW("Set Attr(%{public}d) failed",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_SET_PEER_WIFI_CFG));
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
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::Hid2dSetUpperScene(const std::string& ifName, const Hid2dUpperScene& scene)
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
    data.WriteCString(ifName.c_str());
    data.WriteCString(scene.mac.c_str());
    data.WriteUint32(scene.scene);
    data.WriteInt32(scene.fps);
    data.WriteUint32(scene.bw);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_SET_UPPER_SCENE), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGW("Set Attr(%{public}d) failed", static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_SET_UPPER_SCENE));
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::DiscoverPeers(int32_t channelid)
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
    data.WriteInt32(channelid);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISCOVER_PEERS),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISCOVER_PEERS), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::DisableRandomMac(int setmode)
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
    data.WriteInt32(setmode);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISABLE_RANDOM_MAC),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISABLE_RANDOM_MAC), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::CheckCanUseP2p()
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CHECK_CAN_USE_P2P),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CHECK_CAN_USE_P2P), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

void WifiP2pProxy::OnRemoteDied(const wptr<IRemoteObject>& remoteObject)
{
    WIFI_LOGE("Remote service is died!");
    mRemoteDied = true;
    if (g_wifiP2pCallbackStub == nullptr) {
        WIFI_LOGE("g_wifiP2pCallbackStub is nullptr");
        return;
    }
    g_wifiP2pCallbackStub->SetRemoteDied(true);
}

bool WifiP2pProxy::IsRemoteDied(void)
{
    if (mRemoteDied) {
        WIFI_LOGW("IsRemoteDied! remote is died now!");
    }
    return mRemoteDied;
}

ErrCode WifiP2pProxy::Hid2dIsWideBandwidthSupported(bool &isSupport)
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
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_WIDE_SUPPORTED),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_WIDE_SUPPORTED), error);
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
    isSupport = (reply.ReadInt32() == 1);
    return WIFI_OPT_SUCCESS;
}

ErrCode WifiP2pProxy::SetMiracastSinkConfig(const std::string& config)
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
    data.WriteString(config);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_SET_MIRACAST_SINK_CONFIG), data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_SET_MIRACAST_SINK_CONFIG), error);
        return WIFI_OPT_FAILED;
    }
    int exception = reply.ReadInt32();
    if (exception) {
        return WIFI_OPT_FAILED;
    }
    return ErrCode(reply.ReadInt32());
}

ErrCode WifiP2pProxy::GetSupportedChanForBand(std::vector<int> &channels, int band)
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
    data.WriteInt32(band);
    int error = Remote()->SendRequest(
        static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_SUPPORT_CHANN_FOR_BAND), data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_SUPPORT_CHANN_FOR_BAND), error);
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
    constexpr int MAX_SIZE = 40;
    int listSize = reply.ReadInt32();
    if (listSize > MAX_SIZE) {
        WIFI_LOGE("Get channel list size error: %{public}d", listSize);
        return WIFI_OPT_FAILED;
    }
    for (int i = 0; i < listSize; i++) {
        channels.emplace_back(reply.ReadInt32());
    }
    return WIFI_OPT_SUCCESS;
}
}  // namespace Wifi
}  // namespace OHOS
