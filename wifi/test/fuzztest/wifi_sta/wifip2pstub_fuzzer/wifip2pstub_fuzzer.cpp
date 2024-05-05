/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "wifip2pstub_fuzzer.h"
#include "wifi_fuzz_common_func.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "wifi_p2p_stub.h"
#include "message_parcel.h"
#include "securec.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_p2p_service_impl.h"
#include "wifi_log.h"
#include "wifi_config_center.h"
#include "wifi_settings.h"
#include "wifi_common_def.h"

namespace OHOS {
namespace Wifi {
constexpr size_t U32_AT_SIZE_ZERO = 4;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiP2pService";
static bool g_isInsted = false;
static std::mutex g_instanceLock;
static sptr<WifiP2pServiceImpl> pWifiP2pServiceImpl = nullptr;

bool Init()
{
    if (!g_isInsted) {
        pWifiP2pServiceImpl = WifiP2pServiceImpl::GetInstance();
        if (!pWifiP2pServiceImpl) {
            LOGE("Init failed pWifiP2pServiceImpl is nullptr!");
            return false;
        }
        if (WifiConfigCenter::GetInstance().GetP2pMidState() != WifiOprMidState::RUNNING) {
            LOGE("Init setmidstate!");
            WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::RUNNING);
        }
        g_isInsted = true;
    }
    return true;
}

bool OnRemoteRequest(uint32_t code, MessageParcel &data)
{
    std::unique_lock<std::mutex> autoLock(g_instanceLock);
    if (!g_isInsted) {
        if (!Init()) {
            LOGE("OnRemoteRequest Init failed!");
            return false;
        }
    }
    MessageParcel reply;
    MessageOption option;
    int32_t ret = pWifiP2pServiceImpl->OnRemoteRequest(code, data, reply, option);
    return ret;
}

void OnDiscoverDevicesFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISCOVER_DEVICES), datas);
}


void OnStopDiscoverDevicesFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_DISCOVER_DEVICES), datas);
}


void OnDiscoverServicesFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISCOVER_SERVICES), datas);
}


void OnStopDiscoverServicesFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_DISCOVER_SERVICES), datas);
}

void OnRequestServiceFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REQUEST_SERVICES), datas);
}

void OnPutLocalP2pServiceFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_PUT_LOCAL_SERVICES), datas);
}

void OnDeleteLocalP2pServiceFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DELETE_LOCAL_SERVICES), datas);
}

void OnStartP2pListenFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_START_LISTEN), datas);
}

void OnStopP2pListenFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_LISTEN), datas);
}

void OnCreateGroupFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CREATE_GROUP), datas);
}

void OnRemoveGroupFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REMOVE_GROUP), datas);
}

void OnDeleteGroupFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DELETE_GROUP), datas);
}

void OnP2pConnectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CONNECT), datas);
}

void OnP2pCancelConnectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CANCEL_CONNECT), datas);
}

void OnQueryP2pLinkedInfoFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_INFO), datas);
}

void OnGetCurrentGroupFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_CURRENT_GROUP), datas);
}

void OnGetP2pEnableStatusFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_ENABLE_STATUS), datas);
}

void OnGetP2pDiscoverStatusFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_DISCOVER_STATUS), datas);
}

void OnGetP2pConnectedStatusFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_CONNECTED_STATUS), datas);
}

void OnQueryP2pDevicesFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_DEVICES), datas);
}

void OnQueryP2pGroupsFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_GROUPS), datas);
}

void OnQueryP2pServicesFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_SERVICES), datas);
}

void OnRegisterCallBackFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REGISTER_CALLBACK), datas);
}

void OnSetP2pDeviceNameFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_SET_DEVICE_NAME), datas);
}

void OnSetP2pWfdInfoFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_SET_WFD_INFO), datas);
}

void OnHid2dRequestGcIpFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_APPLY_IP), datas);
}

void OnHid2dSharedlinkIncreaseFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_SHARED_LINK_INCREASE), datas);
}

void OnHid2dSharedlinkDecreaseFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_SHARED_LINK_DECREASE), datas);
}


void OnHid2dCreateGroupFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CREATE_GROUP), datas);
}

void OnHid2dRemoveGcGroupFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_REMOVE_GC_GROUP), datas);
}
void OnHid2dConnectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CONNECT), datas);
}

void OnHid2dConfigIPAddrFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CONFIG_IP), datas);
}

void OnHid2dReleaseIPAddrFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_RELEASE_IP), datas);
}

void OnHid2dGetRecommendChannelFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_P2P_RECOMMENDED_CHANNEL), datas);
}

void OnHid2dGetChannelListFor5GFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNEL_LIST), datas);
}

void OnHid2dGetSelfWifiCfgInfoFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_SELF_WIFI_CFG), datas);
}

void OnHid2dSetPeerWifiCfgInfoFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_SET_PEER_WIFI_CFG), datas);
}
void OnQueryP2pLocalDeviceFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_LOCAL_DEVICE), datas);
}

void OnHid2dSetUpperSceneFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_SET_UPPER_SCENE), datas);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    OHOS::Wifi::OnDiscoverDevicesFuzzTest(data, size);
    OHOS::Wifi::OnStopDiscoverDevicesFuzzTest(data, size);
    OHOS::Wifi::OnDiscoverServicesFuzzTest(data, size);
    OHOS::Wifi::OnStopDiscoverServicesFuzzTest(data, size);
    OHOS::Wifi::OnRequestServiceFuzzTest(data, size);
    OHOS::Wifi::OnPutLocalP2pServiceFuzzTest(data, size);
    OHOS::Wifi::OnDeleteLocalP2pServiceFuzzTest(data, size);
    OHOS::Wifi::OnStartP2pListenFuzzTest(data, size);
    OHOS::Wifi::OnStopP2pListenFuzzTest(data, size);
    OHOS::Wifi::OnCreateGroupFuzzTest(data, size);
    OHOS::Wifi::OnRemoveGroupFuzzTest(data, size);
    OHOS::Wifi::OnDeleteGroupFuzzTest(data, size);
    OHOS::Wifi::OnP2pConnectFuzzTest(data, size);
    OHOS::Wifi::OnP2pCancelConnectFuzzTest(data, size);
    OHOS::Wifi::OnQueryP2pLinkedInfoFuzzTest(data, size);
    OHOS::Wifi::OnGetCurrentGroupFuzzTest(data, size);
    OHOS::Wifi::OnGetP2pEnableStatusFuzzTest(data, size);
    OHOS::Wifi::OnGetP2pDiscoverStatusFuzzTest(data, size);
    OHOS::Wifi::OnGetP2pConnectedStatusFuzzTest(data, size);
    OHOS::Wifi::OnQueryP2pDevicesFuzzTest(data, size);
    OHOS::Wifi::OnQueryP2pGroupsFuzzTest(data, size);
    OHOS::Wifi::OnQueryP2pServicesFuzzTest(data, size);
    OHOS::Wifi::OnRegisterCallBackFuzzTest(data, size);
    OHOS::Wifi::OnSetP2pDeviceNameFuzzTest(data, size);
    OHOS::Wifi::OnSetP2pWfdInfoFuzzTest(data, size);
    OHOS::Wifi::OnHid2dRequestGcIpFuzzTest(data, size);
    OHOS::Wifi::OnHid2dSharedlinkIncreaseFuzzTest(data, size);
    OHOS::Wifi::OnHid2dSharedlinkDecreaseFuzzTest(data, size);
    OHOS::Wifi::OnHid2dCreateGroupFuzzTest(data, size);
    OHOS::Wifi::OnHid2dRemoveGcGroupFuzzTest(data, size);
    OHOS::Wifi::OnHid2dConnectFuzzTest(data, size);
    OHOS::Wifi::OnHid2dConfigIPAddrFuzzTest(data, size);
    OHOS::Wifi::OnHid2dReleaseIPAddrFuzzTest(data, size);
    OHOS::Wifi::OnHid2dGetRecommendChannelFuzzTest(data, size);
    OHOS::Wifi::OnHid2dGetChannelListFor5GFuzzTest(data, size);
    OHOS::Wifi::OnHid2dGetSelfWifiCfgInfoFuzzTest(data, size);
    OHOS::Wifi::OnHid2dSetPeerWifiCfgInfoFuzzTest(data, size);
    OHOS::Wifi::OnQueryP2pLocalDeviceFuzzTest(data, size);
    OHOS::Wifi::OnHid2dSetUpperSceneFuzzTest(data, size);
    return 0;
}
}
}
