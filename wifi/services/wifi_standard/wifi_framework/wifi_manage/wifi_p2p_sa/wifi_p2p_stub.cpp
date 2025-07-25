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
#include "wifi_p2p_stub.h"
#include "wifi_logger.h"
#include "wifi_errcode.h"
#include "wifi_internal_event_dispatcher.h"
#include "wifi_p2p_callback_proxy.h"
#include "wifi_p2p_death_recipient.h"
#include "wifi_common_def.h"
#include "wifi_manager_service_ipc_interface_code.h"

DEFINE_WIFILOG_P2P_LABEL("WifiP2pStub");

namespace OHOS {
namespace Wifi {
WifiP2pStub::WifiP2pStub() : mSingleCallback(false)
{
    InitHandleMap();
    deathRecipient_ = nullptr;
}

WifiP2pStub::~WifiP2pStub()
{
    deathRecipient_ = nullptr;
}

void WifiP2pStub::InitHandleMapEx()
{
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REGISTER_CALLBACK)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnRegisterCallBack(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetSupportedFeatures(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_SET_DEVICE_NAME)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnSetP2pDeviceName(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_SET_WFD_INFO)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnSetP2pWfdInfo(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_APPLY_IP)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnHid2dRequestGcIp(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_SHARED_LINK_INCREASE)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnHid2dSharedlinkIncrease(code, data, reply, option);
        };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_SHARED_LINK_DECREASE)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnHid2dSharedlinkDecrease(code, data, reply, option);
        };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CREATE_GROUP)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnHid2dCreateGroup(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_REMOVE_GC_GROUP)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnHid2dRemoveGcGroup(code, data, reply, option);
        };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CONNECT)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnHid2dConnect(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CONFIG_IP)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnHid2dConfigIPAddr(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_RELEASE_IP)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnHid2dReleaseIPAddr(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_P2P_RECOMMENDED_CHANNEL)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnHid2dGetRecommendChannel(code, data, reply, option);
        };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNEL_LIST)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnHid2dGetChannelListFor5G(code, data, reply, option); };
    InitHandleMapExPart3();
}

void WifiP2pStub::InitHandleMapExPart3()
{
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_SELF_WIFI_CFG)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnHid2dGetSelfWifiCfgInfo(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_SET_PEER_WIFI_CFG)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnHid2dSetPeerWifiCfgInfo(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_LOCAL_DEVICE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnQueryP2pLocalDevice(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_SET_UPPER_SCENE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnHid2dSetUpperScene(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISCOVER_PEERS)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnDiscoverPeers(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISABLE_RANDOM_MAC)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnDisableRandomMac(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CHECK_CAN_USE_P2P)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnCheckCanUseP2p(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_WIDE_SUPPORTED)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnHid2dIsWideBandwidthSupported(code, data, reply, option);
        };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_SET_MIRACAST_SINK_CONFIG)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnSetMiracastSinkConfig(code, data, reply, option);
        };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_SUPPORT_CHANN_FOR_BAND)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnGetSupportChanForBand(code, data, reply, option);
        };
}

void WifiP2pStub::InitHandleMap()
{
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_ENABLE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply, MessageOption &option) { OnEnableP2p(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISABLE)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply, MessageOption &option) { OnDisableP2p(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISCOVER_DEVICES)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnDiscoverDevices(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_DISCOVER_DEVICES)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnStopDiscoverDevices(code, data, reply, option);
        };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISCOVER_SERVICES)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnDiscoverServices(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_DISCOVER_SERVICES)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnStopDiscoverServices(code, data, reply, option);
        };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REQUEST_SERVICES)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnRequestService(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_PUT_LOCAL_SERVICES)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnPutLocalP2pService(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DELETE_LOCAL_SERVICES)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnDeleteLocalP2pService(code, data, reply, option);
        };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_START_LISTEN)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnStartP2pListen(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_LISTEN)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnStopP2pListen(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CREATE_GROUP)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply, MessageOption &option) { OnCreateGroup(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REMOVE_GROUP)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply, MessageOption &option) { OnRemoveGroup(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REMOVE_GROUP_CLIENT)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnRemoveGroupClient(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DELETE_GROUP)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply, MessageOption &option) { OnDeleteGroup(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CONNECT)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply, MessageOption &option) { OnP2pConnect(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CANCEL_CONNECT)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnP2pCancelConnect(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_INFO)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnQueryP2pLinkedInfo(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_CURRENT_GROUP)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetCurrentGroup(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_ENABLE_STATUS)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetP2pEnableStatus(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_DISCOVER_STATUS)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnGetP2pDiscoverStatus(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_CONNECTED_STATUS)] =
        [this](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            OnGetP2pConnectedStatus(code, data, reply, option);
        };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_DEVICES)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnQueryP2pDevices(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_GROUPS)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnQueryP2pGroups(code, data, reply, option); };
    handleFuncMap[static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_SERVICES)] = [this](uint32_t code,
        MessageParcel &data, MessageParcel &reply,
        MessageOption &option) { OnQueryP2pServices(code, data, reply, option); };
    InitHandleMapEx();
    return;
}

int WifiP2pStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        WIFI_LOGE("P2p stub token verification error: %{public}d", code);
        return WIFI_OPT_FAILED;
    }

    HandleFuncMap::iterator iter = handleFuncMap.find(code);
    if (iter == handleFuncMap.end()) {
        WIFI_LOGD("not find function to deal, code %{public}u", code);
        reply.WriteInt32(0);
        reply.WriteInt32(WIFI_OPT_NOT_SUPPORTED);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    } else {
        int exception = data.ReadInt32();
        if (exception) {
            return WIFI_OPT_FAILED;
        }
        (iter->second)(code, data, reply, option);
    }
    return 0;
}

void WifiP2pStub::OnEnableP2p(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = EnableP2p();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnDisableP2p(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = DisableP2p();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnDiscoverDevices(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = DiscoverDevices();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnStopDiscoverDevices(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = StopDiscoverDevices();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnDiscoverServices(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = DiscoverServices();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnStopDiscoverServices(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = StopDiscoverServices();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnRequestService(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiP2pDevice device;
    WifiP2pServiceRequest request;
    if (!ReadWifiP2pServiceRequest(data, device, request)) {
        reply.WriteInt32(0);
        reply.WriteInt32(WIFI_OPT_INVALID_PARAM);
        return;
    }
    ErrCode ret = RequestService(device, request);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnPutLocalP2pService(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiP2pServiceInfo config;
    if (!ReadWifiP2pServiceInfo(data, config)) {
        reply.WriteInt32(0);
        reply.WriteInt32(WIFI_OPT_INVALID_PARAM);
        return;
    }
    ErrCode ret = PutLocalP2pService(config);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnDeleteLocalP2pService(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiP2pServiceInfo config;
    if (!ReadWifiP2pServiceInfo(data, config)) {
        reply.WriteInt32(0);
        reply.WriteInt32(WIFI_OPT_INVALID_PARAM);
        return;
    }
    ErrCode ret = DeleteLocalP2pService(config);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnStartP2pListen(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int period = data.ReadInt32();
    int interval = data.ReadInt32();
    ErrCode ret = StartP2pListen(period, interval);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnStopP2pListen(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = StopP2pListen();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnCreateGroup(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiP2pConfig config;
    ReadWifiP2pConfigData(data, config);
    ErrCode ret = CreateGroup(config);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnRemoveGroup(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = RemoveGroup();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnRemoveGroupClient(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    GcInfo info;
    info.ip = data.ReadString();
    info.mac = data.ReadString();
    info.host = data.ReadString();
    ErrCode ret = RemoveGroupClient(info);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnDeleteGroup(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiP2pGroupInfo config;
    if (!ReadWifiP2pGroupData(data, config)) {
        reply.WriteInt32(0);
        reply.WriteInt32(WIFI_OPT_INVALID_PARAM);
        return;
    }
    ErrCode ret = DeleteGroup(config);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnP2pConnect(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiP2pConfig config;
    ReadWifiP2pConfigData(data, config);

    ErrCode ret = P2pConnect(config);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnP2pCancelConnect(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = P2pCancelConnect();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnQueryP2pLinkedInfo(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiP2pLinkedInfo config;
    ErrCode ret = QueryP2pLinkedInfo(config);

    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(static_cast<int>(config.GetConnectState()));
        reply.WriteBool(config.IsGroupOwner());
        reply.WriteString(config.GetGroupOwnerAddress());
        std::vector<GcInfo> gcInfos = config.GetClientInfoList();
        int size = static_cast<int>(gcInfos.size());
        reply.WriteInt32(size);
        for (int i = 0; i < size; i++) {
            reply.WriteString(gcInfos[i].mac);
            reply.WriteString(gcInfos[i].ip);
            reply.WriteString(gcInfos[i].host);
        }
    }
    return;
}

void WifiP2pStub::OnGetCurrentGroup(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiP2pGroupInfo config;
    ErrCode ret = GetCurrentGroup(config);

    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        WriteWifiP2pGroupData(reply, config, false);
    }
    return;
}

void WifiP2pStub::OnGetP2pEnableStatus(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int status = 0;
    ErrCode ret = GetP2pEnableStatus(status);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(status);
    }
    return;
}

void WifiP2pStub::OnGetP2pDiscoverStatus(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int status = 0;
    ErrCode ret = GetP2pDiscoverStatus(status);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(status);
    }
    return;
}

void WifiP2pStub::OnGetP2pConnectedStatus(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int status = 0;
    ErrCode ret = GetP2pConnectedStatus(status);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(status);
    }
    return;
}

void WifiP2pStub::OnQueryP2pDevices(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::vector<WifiP2pDevice> devices;
    ErrCode ret = QueryP2pDevices(devices);

    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        int size = static_cast<int>(devices.size());
        reply.WriteInt32(size);
        for (int i = 0; i < size; ++i) {
            WriteWifiP2pDeviceData(reply, devices[i]);
        }
    }
    return;
}

void WifiP2pStub::OnQueryP2pLocalDevice(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGI("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiP2pDevice device;
    ErrCode ret = QueryP2pLocalDevice(device);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        WriteWifiP2pDeviceData(reply, device);
    }
    return;
}

void WifiP2pStub::OnQueryP2pGroups(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::vector<WifiP2pGroupInfo> groups;
    ErrCode ret = QueryP2pGroups(groups);

    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    if (ret == WIFI_OPT_SUCCESS) {
        int size = static_cast<int>(groups.size());
        reply.WriteInt32(size);
        for (int i = 0; i < size; ++i) {
            WriteWifiP2pGroupData(reply, groups[i], true);
        }
    }
    return;
}

void WifiP2pStub::OnQueryP2pServices(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::vector<WifiP2pServiceInfo> services;
    ErrCode ret = QueryP2pServices(services);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    if (ret == WIFI_OPT_SUCCESS) {
        int size = static_cast<int>(services.size());
        reply.WriteInt32(size);
        for (int i = 0; i < size; ++i) {
            WriteWifiP2pServiceInfo(reply, services[i]);
        }
    }
    return;
}

void WifiP2pStub::OnDiscoverPeers(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int channelid = data.ReadInt32();
    ErrCode ret = DiscoverPeers(channelid);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnDisableRandomMac(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int setmode = data.ReadInt32();
    ErrCode ret = DisableRandomMac(setmode);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnCheckCanUseP2p(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = CheckCanUseP2p();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

bool WifiP2pStub::ReadWifiP2pServiceInfo(MessageParcel &data, WifiP2pServiceInfo &info)
{
    const char *readStr = nullptr;
    constexpr int MAX_QUERY_SIZE = 256;
    readStr = data.ReadCString();
    info.SetServiceName((readStr != nullptr) ? readStr : "");
    readStr = data.ReadCString();
    info.SetDeviceAddress((readStr != nullptr) ? readStr : "");
    info.SetServicerProtocolType(static_cast<P2pServicerProtocolType>(data.ReadInt32()));
    std::vector<std::string> queryList;
    int size = data.ReadInt32();
    if (size > MAX_QUERY_SIZE) {
        return false;
    }
    for (int i = 0; i < size; i++) {
        readStr = data.ReadCString();
        std::string str = (readStr != nullptr) ? readStr : "";
        queryList.push_back(str);
    }
    info.SetQueryList(queryList);
    return true;
}

bool WifiP2pStub::ReadWifiP2pServiceRequest(MessageParcel &data, WifiP2pDevice &device, WifiP2pServiceRequest &request)
{
    constexpr int MAX_QUERY_SIZE = 256;
    ReadWifiP2pDeviceData(data, device);
    request.SetProtocolType(static_cast<P2pServicerProtocolType>(data.ReadInt32()));
    request.SetTransactionId(data.ReadInt32());
    int size = data.ReadInt32();
    if (size > MAX_QUERY_SIZE) {
        return false;
    }
    std::vector<unsigned char> query;
    for (int i = 0; i < size; i++) {
        unsigned char chr = data.ReadInt8();
        query.push_back(chr);
    }
    request.SetQuery(query);
    return true;
}

void WifiP2pStub::WriteWifiP2pServiceInfo(MessageParcel &reply, const WifiP2pServiceInfo &info)
{
    reply.WriteCString(info.GetServiceName().c_str());
    reply.WriteCString(info.GetDeviceAddress().c_str());
    reply.WriteInt32(static_cast<int>(info.GetServicerProtocolType()));
    reply.WriteInt32(info.GetQueryList().size());
    std::vector<std::string> queryList = info.GetQueryList();
    for (auto it = queryList.begin(); it != queryList.end(); it++) {
        reply.WriteCString((*it).c_str());
    }
    return;
}

void WifiP2pStub::ReadWifiP2pDeviceData(MessageParcel &data, WifiP2pDevice &device)
{
    device.SetDeviceName(data.ReadString());
    device.SetDeviceAddress(data.ReadString());
    device.SetDeviceAddressType(data.ReadInt32());
    device.SetPrimaryDeviceType(data.ReadString());
    device.SetSecondaryDeviceType(data.ReadString());
    device.SetP2pDeviceStatus(static_cast<P2pDeviceStatus>(data.ReadInt32()));
    WifiP2pWfdInfo wfdInfo;
    wfdInfo.SetWfdEnabled(data.ReadBool());
    wfdInfo.SetDeviceInfo(data.ReadInt32());
    wfdInfo.SetCtrlPort(data.ReadInt32());
    wfdInfo.SetMaxThroughput(data.ReadInt32());
    device.SetWfdInfo(wfdInfo);
    device.SetWpsConfigMethod(data.ReadInt32());
    device.SetDeviceCapabilitys(data.ReadInt32());
    device.SetGroupCapabilitys(data.ReadInt32());
}

void WifiP2pStub::WriteWifiP2pDeviceData(MessageParcel &reply, const WifiP2pDevice &device)
{
    reply.WriteString(device.GetDeviceName());
    reply.WriteString(device.GetDeviceAddress());
    reply.WriteString(device.GetRandomDeviceAddress());
    reply.WriteInt32(device.GetDeviceAddressType());
    reply.WriteString(device.GetPrimaryDeviceType());
    reply.WriteString(device.GetSecondaryDeviceType());
    reply.WriteInt32(static_cast<int>(device.GetP2pDeviceStatus()));
    reply.WriteBool(device.GetWfdInfo().GetWfdEnabled());
    reply.WriteInt32(device.GetWfdInfo().GetDeviceInfo());
    reply.WriteInt32(device.GetWfdInfo().GetCtrlPort());
    reply.WriteInt32(device.GetWfdInfo().GetMaxThroughput());
    reply.WriteInt32(device.GetWpsConfigMethod());
    reply.WriteInt32(device.GetDeviceCapabilitys());
    reply.WriteInt32(device.GetGroupCapabilitys());
    reply.WriteString(device.GetGroupAddress());
}

bool WifiP2pStub::ReadWifiP2pGroupData(MessageParcel &data, WifiP2pGroupInfo &info)
{
    constexpr int MAX_DEV_SIZE = 256;
    info.SetIsGroupOwner(data.ReadBool());
    WifiP2pDevice device;
    ReadWifiP2pDeviceData(data, device);
    info.SetOwner(device);
    info.SetPassphrase(data.ReadString());
    info.SetInterface(data.ReadString());
    info.SetGroupName(data.ReadString());
    info.SetFrequency(data.ReadInt32());
    info.SetIsPersistent(data.ReadBool());
    info.SetP2pGroupStatus(static_cast<P2pGroupStatus>(data.ReadInt32()));
    info.SetNetworkId(data.ReadInt32());
    info.SetGoIpAddress(data.ReadString());
    int size = data.ReadInt32();
    if (size > MAX_DEV_SIZE) {
        return false;
    }
    for (auto it = 0; it < size; ++it) {
        WifiP2pDevice cliDev;
        ReadWifiP2pDeviceData(data, cliDev);
        info.AddClientDevice(cliDev);
    }
    return true;
}

void WifiP2pStub::WriteWifiP2pGroupData(MessageParcel &reply, const WifiP2pGroupInfo &info, bool isPersistent)
{
    reply.WriteBool(info.IsGroupOwner());
    WriteWifiP2pDeviceData(reply, info.GetOwner());
    reply.WriteString(info.GetPassphrase());
    reply.WriteString(info.GetInterface());
    reply.WriteString(info.GetGroupName());
    reply.WriteInt32(info.GetFrequency());
    reply.WriteBool(info.IsPersistent());
    reply.WriteInt32(static_cast<int>(info.GetP2pGroupStatus()));
    reply.WriteInt32(info.GetNetworkId());
    reply.WriteString(info.GetGoIpAddress());
    reply.WriteString(info.GetGcIpAddress());
    std::vector<WifiP2pDevice> deviceVec;
    if (isPersistent) {
        deviceVec = info.GetPersistentDevices();
    } else {
        deviceVec = info.GetClientDevices();
    }
    reply.WriteInt32(deviceVec.size());
    for (auto it = deviceVec.begin(); it != deviceVec.end(); ++it) {
        WriteWifiP2pDeviceData(reply, *it);
    }
}

void WifiP2pStub::ReadWifiP2pConfigData(MessageParcel &data, WifiP2pConfig &config)
{
    config.SetDeviceAddress(data.ReadString());
    config.SetDeviceAddressType(data.ReadInt32());
    config.SetPassphrase(data.ReadString());
    config.SetGroupName(data.ReadString());
    config.SetGoBand(static_cast<GroupOwnerBand>(data.ReadInt32()));
    config.SetNetId(data.ReadInt32());
    config.SetGroupOwnerIntent(data.ReadInt32());
    config.SetFreq(data.ReadInt32());
}

void WifiP2pStub::OnRegisterCallBack(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    do {
        sptr<IRemoteObject> remote = data.ReadRemoteObject();
        if (remote == nullptr) {
            WIFI_LOGE("Failed to readRemoteObject!");
            break;
        }

        sptr<IWifiP2pCallback> callback_ = iface_cast<IWifiP2pCallback>(remote);
        if (callback_ == nullptr) {
            callback_ = sptr<WifiP2pCallbackProxy>::MakeSptr(remote);
            WIFI_LOGI("create new `WifiP2pCallbackProxy`!");
        }

        int pid = data.ReadInt32();
        int tokenId = data.ReadInt32();
        int eventNum = data.ReadInt32();
        std::vector<std::string> event;
        if (eventNum > 0 && eventNum <= MAX_READ_EVENT_SIZE) {
            for (int i = 0; i < eventNum; ++i) {
                event.emplace_back(data.ReadString());
            }
        }
        WIFI_LOGD("%{public}s, get pid: %{public}d, tokenId: %{private}d", __func__, pid, tokenId);

        if (mSingleCallback) {
            ret = RegisterCallBack(callback_, event);
        } else {
            std::unique_lock<std::mutex> lock(deathRecipientMutex);
            if (deathRecipient_ == nullptr) {
                deathRecipient_ = sptr<WifiP2pDeathRecipient>::MakeSptr();
            }
            // Add death recipient to remote object if this is the first time to register callback.
            if ((remote->IsProxyObject()) &&
                !WifiInternalEventDispatcher::GetInstance().HasP2pRemote(remote)) {
                remote->AddDeathRecipient(deathRecipient_);
            }

            if (callback_ != nullptr) {
                for (const auto &eventName : event) {
                    ret = WifiInternalEventDispatcher::GetInstance().AddP2pCallback(remote, callback_, pid,
                        eventName, tokenId);
                }
            }
        }
        MonitorCfgChange();
    } while (0);

    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnGetSupportedFeatures(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    long features = 0;
    int ret = GetSupportedFeatures(features);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt64(features);
    }

    return;
}

void WifiP2pStub::OnSetP2pDeviceName(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    ErrCode ret = WIFI_OPT_FAILED;
    std::string deviceName = data.ReadString();
    ret = SetP2pDeviceName(deviceName);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);

    return;
}

void WifiP2pStub::OnSetP2pWfdInfo(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    WifiP2pWfdInfo wfdInfo;
    wfdInfo.SetWfdEnabled(data.ReadBool());
    wfdInfo.SetDeviceInfo(data.ReadInt32());
    wfdInfo.SetCtrlPort(data.ReadInt32());
    wfdInfo.SetMaxThroughput(data.ReadInt32());

    int ret = SetP2pWfdInfo(wfdInfo);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    return;
}

void WifiP2pStub::OnHid2dRequestGcIp(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());

    ErrCode ret = WIFI_OPT_FAILED;
    const char *readStr = data.ReadCString();
    std::string ipAddr;
    if (readStr == nullptr) {
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        std::string gcMac = readStr;
        ret = Hid2dRequestGcIp(gcMac, ipAddr);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteCString(ipAddr.c_str());
    }
}

void WifiP2pStub::OnHid2dSharedlinkIncrease(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());

    int ret = Hid2dSharedlinkIncrease();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
}

void WifiP2pStub::OnHid2dSharedlinkDecrease(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    int ret = Hid2dSharedlinkDecrease();
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
}

void WifiP2pStub::OnHid2dCreateGroup(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());

    int frequency = data.ReadInt32();
    int type = data.ReadInt32();
    int ret = Hid2dCreateGroup(frequency, FreqType(type));
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
}

void WifiP2pStub::OnHid2dRemoveGcGroup(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());

    ErrCode ret = WIFI_OPT_FAILED;
    const char *readStr = data.ReadCString();
    if (readStr == nullptr) {
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        std::string gcIfName = readStr;
        ret = Hid2dRemoveGcGroup(gcIfName);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
}

void WifiP2pStub::OnHid2dConnect(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());

    ErrCode ret = WIFI_OPT_FAILED;
    Hid2dConnectConfig config;
    const char *ssidRead = data.ReadCString();
    const char *bssidRead = data.ReadCString();
    const char *preSharedKeyRead = data.ReadCString();
    if (ssidRead == nullptr || bssidRead == nullptr || preSharedKeyRead == nullptr) {
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        config.SetSsid(ssidRead);
        config.SetBssid(bssidRead);
        config.SetPreSharedKey(preSharedKeyRead);
        config.SetFrequency(data.ReadInt32());
        config.SetDhcpMode(DhcpMode(data.ReadInt32()));

        ret = Hid2dConnect(config);
    }

    reply.WriteInt32(0);
    reply.WriteInt32(ret);
}

void WifiP2pStub::OnHid2dConfigIPAddr(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());

    ErrCode ret = WIFI_OPT_FAILED;
    IpAddrInfo ipInfo;
    const char *ifNameRead = data.ReadCString();
    const char *ipRead = data.ReadCString();
    const char *gatewayRead = data.ReadCString();
    const char *netmaskRead = data.ReadCString();
    if (ifNameRead == nullptr || ipRead == nullptr || gatewayRead == nullptr || netmaskRead == nullptr) {
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        std::string ifName = ifNameRead;
        ipInfo.ip = ipRead;
        ipInfo.gateway = gatewayRead;
        ipInfo.netmask = netmaskRead;
        ret = Hid2dConfigIPAddr(ifName, ipInfo);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
}

void WifiP2pStub::OnHid2dReleaseIPAddr(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());

    ErrCode ret = WIFI_OPT_FAILED;
    const char *ifNameRead = data.ReadCString();
    if (ifNameRead == nullptr) {
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        std::string ifName = ifNameRead;
        ret = Hid2dReleaseIPAddr(ifName);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
}

void WifiP2pStub::OnHid2dGetRecommendChannel(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    const char *readStr = nullptr;
    RecommendChannelRequest request;
    RecommendChannelResponse response;
    readStr = data.ReadCString();
    request.remoteIfName = (readStr != nullptr) ? readStr : "";
    request.remoteIfMode = data.ReadInt32();
    readStr = data.ReadCString();
    request.localIfName = (readStr != nullptr) ? readStr : "";
    request.localIfMode = data.ReadInt32();
    request.prefBand = data.ReadInt32();
    request.prefBandwidth = PreferBandwidth(data.ReadInt32());
    ErrCode ret = Hid2dGetRecommendChannel(request, response);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(static_cast<int>(response.status));
        reply.WriteInt32(response.index);
        reply.WriteInt32(response.centerFreq);
        reply.WriteInt32(response.centerFreq1);
        reply.WriteInt32(response.centerFreq2);
        reply.WriteInt32(response.bandwidth);
    }
}

void WifiP2pStub::OnHid2dGetChannelListFor5G(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());

    std::vector<int> vecChannelList;
    ErrCode ret = Hid2dGetChannelListFor5G(vecChannelList);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32((int)vecChannelList.size());
        for (auto& channel : vecChannelList) {
            reply.WriteInt32(channel);
        }
    }
}

void WifiP2pStub::OnHid2dGetSelfWifiCfgInfo(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());

    int cfgType = data.ReadInt32();
    int len = 0;
    char cfgData[CFG_DATA_MAX_BYTES];
    if (memset_s(cfgData, CFG_DATA_MAX_BYTES, 0, CFG_DATA_MAX_BYTES) != EOK) {
        WIFI_LOGE("`%{public}s` memset_s failed!", __func__);
    }
    ErrCode ret = Hid2dGetSelfWifiCfgInfo(SelfCfgType(cfgType), cfgData, &len);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    reply.WriteInt32(len);
    if (ret == WIFI_OPT_SUCCESS && len > 0) {
        reply.WriteBuffer(cfgData, len);
    }
}

void WifiP2pStub::OnHid2dSetPeerWifiCfgInfo(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());

    char cfgData[CFG_DATA_MAX_BYTES];
    if (memset_s(cfgData, CFG_DATA_MAX_BYTES, 0, CFG_DATA_MAX_BYTES) != EOK) {
        WIFI_LOGE("`%{public}s` memset_s failed!", __func__);
    }
    int cfgType = data.ReadInt32();
    int len = data.ReadInt32();
    const char *dataBuffer = (const char *)data.ReadBuffer(len);
    if (memcpy_s(cfgData, CFG_DATA_MAX_BYTES, dataBuffer, len) != EOK) {
        WIFI_LOGE("`%{public}s` memcpy_s failed!", __func__);
        reply.WriteInt32(0);
        reply.WriteInt32(WIFI_OPT_FAILED);
        return;
    }
    ErrCode ret = Hid2dSetPeerWifiCfgInfo(PeerCfgType(cfgType), cfgData, len);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
}

void WifiP2pStub::OnHid2dSetUpperScene(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());

    ErrCode ret = WIFI_OPT_FAILED;
    Hid2dUpperScene scene;
    const char *ifNameRead = data.ReadCString();
    const char *macRead = data.ReadCString();
    if (ifNameRead == nullptr || macRead == nullptr) {
        ret = WIFI_OPT_INVALID_PARAM;
    } else {
        std::string ifName = ifNameRead;
        scene.mac = macRead;
        scene.scene = data.ReadUint32();
        scene.fps = data.ReadInt32();
        scene.bw = data.ReadUint32();
        struct timespec times = {0, 0};
        clock_gettime(CLOCK_MONOTONIC, &times);
        if (scene.scene == 0) {
            scene.setTime = 0;
        } else {
            scene.setTime =
                static_cast<int64_t>(times.tv_sec) * SECOND_TO_MILLI_SECOND + times.tv_nsec / SECOND_TO_MICRO_SECOND;
        }
        ret = Hid2dSetUpperScene(ifName, scene);
    }
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
}

bool WifiP2pStub::IsSingleCallback() const
{
    return mSingleCallback;
}

void WifiP2pStub::SetSingleCallback(const bool isSingleCallback)
{
    mSingleCallback = true;
}

void WifiP2pStub::OnHid2dIsWideBandwidthSupported(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    bool isSupport = false;
    ErrCode ret = Hid2dIsWideBandwidthSupported(isSupport);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(isSupport ? 1 : 0);
    }
}

void WifiP2pStub::OnSetMiracastSinkConfig(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::string config = data.ReadString();
    ErrCode ret = SetMiracastSinkConfig(config);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
}

void WifiP2pStub::OnGetSupportChanForBand(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    WIFI_LOGD("run %{public}s code %{public}u, datasize %{public}zu", __func__, code, data.GetRawDataSize());
    std::vector<int> channels;
    int band = data.ReadInt32();
    ErrCode ret = GetSupportedChanForBand(channels, band);
    reply.WriteInt32(0);
    reply.WriteInt32(ret);
    if (ret == WIFI_OPT_SUCCESS) {
        reply.WriteInt32(static_cast<int>(channels.size()));
        for (auto& channel : channels) {
            reply.WriteInt32(channel);
        }
    }
}
}  // namespace Wifi
}  // namespace OHOS
