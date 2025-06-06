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

#include "wifi_p2p_callback_proxy.h"
#include "wifi_logger.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_internal_event_dispatcher.h"

DEFINE_WIFILOG_P2P_LABEL("WifiP2pCallbackProxy");

namespace OHOS {
namespace Wifi {
WifiP2pCallbackProxy::WifiP2pCallbackProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IWifiP2pCallback>(impl)
{}

WifiP2pCallbackProxy::~WifiP2pCallbackProxy()
{}

void WifiP2pCallbackProxy::OnP2pStateChanged(int state)
{
    WIFI_LOGD("WifiP2pCallbackProxy::OnP2pStateChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(state);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_P2P_STATE_CHANGE), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_CBK_CMD_P2P_STATE_CHANGE), error);
        return;
    }
    return;
}

void WifiP2pCallbackProxy::OnP2pPersistentGroupsChanged(void)
{
    WIFI_LOGD("WifiP2pCallbackProxy::OnP2pPersistentGroupsChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_PERSISTENT_GROUPS_CHANGE),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_CBK_CMD_PERSISTENT_GROUPS_CHANGE), error);
        return;
    }
    return;
}

void WifiP2pCallbackProxy::WriteWifiP2pDeviceData(MessageParcel &data, const WifiP2pDevice &device)
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
    data.WriteInt32(static_cast<int>(device.GetChrErrCode()));
}

void WifiP2pCallbackProxy::OnP2pThisDeviceChanged(const WifiP2pDevice &device)
{
    WIFI_LOGD("WifiP2pCallbackProxy::OnP2pThisDeviceChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    WriteWifiP2pDeviceData(data, device);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_THIS_DEVICE_CHANGE), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_CBK_CMD_THIS_DEVICE_CHANGE), error);
        return;
    }
    return;
}

void WifiP2pCallbackProxy::OnP2pPeersChanged(const std::vector<WifiP2pDevice> &devices)
{
    WIFI_LOGD("WifiP2pCallbackProxy::OnP2pPeersChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    int size = static_cast<int>(devices.size());
    data.WriteInt32(size);
    for (int i = 0; i < size; ++i) {
        WriteWifiP2pDeviceData(data, devices[i]);
    }
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_PEER_CHANGE), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_CBK_CMD_PEER_CHANGE), error);
        return;
    }
    return;
}

void WifiP2pCallbackProxy::OnP2pPrivatePeersChanged(const std::string &priWfdInfo)
{
    WIFI_LOGD("WifiP2pCallbackProxy::OnP2pPrivatePeersChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteString(priWfdInfo);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_PRIVATE_PEER_CHANGE),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_CBK_CMD_PRIVATE_PEER_CHANGE), error);
        return;
    }
    return;
}

void WifiP2pCallbackProxy::OnP2pServicesChanged(const std::vector<WifiP2pServiceInfo> &srvInfo)
{
    WIFI_LOGD("WifiP2pCallbackProxy::OnP2pServicesChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    int size = static_cast<int>(srvInfo.size());
    data.WriteInt32(size);
    for (int i = 0; i < size; ++i) {
        data.WriteCString(srvInfo[i].GetServiceName().c_str());
        data.WriteCString(srvInfo[i].GetDeviceAddress().c_str());
        data.WriteInt32(static_cast<int>(srvInfo[i].GetServicerProtocolType()));
        std::vector<std::string> queryList = srvInfo[i].GetQueryList();
        data.WriteInt32(queryList.size());
        for (auto it = queryList.begin(); it != queryList.end(); it++) {
            data.WriteCString((*it).c_str());
        }
    }
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_SERVICE_CHANGE), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_CBK_CMD_SERVICE_CHANGE), error);
        return;
    }
    return;
}

void WifiP2pCallbackProxy::OnP2pConnectionChanged(const WifiP2pLinkedInfo &info)
{
    WIFI_LOGD("WifiP2pCallbackProxy::OnP2pConnectionChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(static_cast<int>(info.GetConnectState()));
    data.WriteBool(info.IsGroupOwner());
    data.WriteCString(info.GetGroupOwnerAddress().c_str());
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_CONNECT_CHANGE), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_CBK_CMD_CONNECT_CHANGE), error);
        return;
    }
    return;
}

void WifiP2pCallbackProxy::OnP2pDiscoveryChanged(bool isChange)
{
    WIFI_LOGD("WifiP2pCallbackProxy::OnP2pDiscoveryChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteBool(isChange);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_DISCOVERY_CHANGE), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_CBK_CMD_DISCOVERY_CHANGE), error);
        return;
    }
    return;
}

void WifiP2pCallbackProxy::OnP2pActionResult(P2pActionCallback action, ErrCode code)
{
    WIFI_LOGD("WifiP2pCallbackProxy::OnP2pActionResult");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(static_cast<int>(action));
    data.WriteInt32(static_cast<int>(code));
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_P2P_ACTION_RESULT), data,
        reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_CBK_CMD_P2P_ACTION_RESULT), error);
        return;
    }
    return;
}

void WifiP2pCallbackProxy::OnConfigChanged(CfgType type, char* cfgData, int dataLen)
{
    WIFI_LOGD("WifiP2pCallbackProxy::OnConfigChanged");
    MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(static_cast<int>(type));
    data.WriteInt32(dataLen);
    data.WriteBuffer(cfgData, dataLen);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_CFG_CHANGE), data, reply,
        option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code is %{public}d",
            static_cast<int32_t>(P2PInterfaceCode::WIFI_CBK_CMD_CFG_CHANGE), error);
        return;
    }
    return;
}

void WifiP2pCallbackProxy::OnP2pGcJoinGroup(const OHOS::Wifi::GcInfo &info)
{
    WIFI_LOGD("WifiP2pCallbackProxy::OnP2pGcJoinGroup");
	MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteString(info.mac);
    data.WriteString(info.ip);
    data.WriteString(info.host);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_P2P_GC_JOIN_GROUP),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code %{public}d",
            P2PInterfaceCode::WIFI_CBK_CMD_P2P_GC_JOIN_GROUP, error);
        return;
    }
    return;
}

void WifiP2pCallbackProxy::OnP2pGcLeaveGroup(const OHOS::Wifi::GcInfo &info)
{
    WIFI_LOGD("WifiP2pCallbackProxy::OnP2pGcLeaveGroup");
	MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteString(info.mac);
    data.WriteString(info.ip);
    data.WriteString(info.host);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_P2P_GC_LEAVE_GROUP),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code %{public}d",
            P2PInterfaceCode::WIFI_CBK_CMD_P2P_GC_LEAVE_GROUP, error);
        return;
    }
    return;
}

void WifiP2pCallbackProxy::OnP2pChrErrCodeReport(const int errCode)
{
    WIFI_LOGD("WifiP2pCallbackProxy::OnP2pChrErrCodeReport");
	MessageOption option = {MessageOption::TF_ASYNC};
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        WIFI_LOGE("Write interface token error: %{public}s", __func__);
        return;
    }
    data.WriteInt32(0);
    data.WriteInt32(errCode);
    int error = Remote()->SendRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_CBK_CMD_CHR_ERRCODE_REPORT),
        data, reply, option);
    if (error != ERR_NONE) {
        WIFI_LOGE("Set Attr(%{public}d) failed,error code %{public}d",
            P2PInterfaceCode::WIFI_CBK_CMD_CHR_ERRCODE_REPORT, error);
        return;
    }
    return;
}
}  // namespace Wifi
}  // namespace OHOS
