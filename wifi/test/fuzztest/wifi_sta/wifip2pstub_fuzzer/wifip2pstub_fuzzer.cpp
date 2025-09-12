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
#include <fuzzer/FuzzedDataProvider.h>
#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "wifi_device_stub.h"
#include "wifi_device_service_impl.h"
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
#include "wifi_manager.h"
#include "wifi_net_agent.h"

namespace OHOS {
namespace Wifi {
FuzzedDataProvider *FDP = nullptr;
const int32_t NUM_BYTES = 1;
constexpr size_t U32_AT_SIZE_ZERO = 4;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiP2pService";
const std::u16string FORMMGR_INTERFACE_TOKEN_DEVICE = u"ohos.wifi.IWifiDeviceService";
static bool g_isInsted = false;
static std::mutex g_instanceLock;
std::shared_ptr<WifiDeviceStub> pWifiDeviceStub = std::make_shared<WifiDeviceServiceImpl>();
sptr<WifiP2pStub> pWifiP2pServiceImpl = WifiP2pServiceImpl::GetInstance();
bool Init()
{
    if (!g_isInsted) {
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
    pWifiP2pServiceImpl->OnRemoteRequest(code, data, reply, option);
    return true;
}

void OnDiscoverDevicesFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISCOVER_DEVICES), datas);
}


void OnStopDiscoverDevicesFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_DISCOVER_DEVICES), datas);
}


void OnDiscoverServicesFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISCOVER_SERVICES), datas);
}


void OnStopDiscoverServicesFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_DISCOVER_SERVICES), datas);
}

void OnRequestServiceFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REQUEST_SERVICES), datas);
}

void OnPutLocalP2pServiceFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_PUT_LOCAL_SERVICES), datas);
}

void OnDeleteLocalP2pServiceFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DELETE_LOCAL_SERVICES), datas);
}

void OnStartP2pListenFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());;
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_START_LISTEN), datas);
}

void OnStopP2pListenFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_STOP_LISTEN), datas);
}

void OnCreateGroupFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CREATE_GROUP), datas);
}

void OnRemoveGroupFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REMOVE_GROUP), datas);
}

void OnRemoveGroupClientFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REMOVE_GROUP_CLIENT), datas);
}

void OnDeleteGroupFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DELETE_GROUP), datas);
}

void OnP2pConnectFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CONNECT), datas);
}

void OnP2pCancelConnectFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CANCEL_CONNECT), datas);
}

void OnQueryP2pLinkedInfoFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_INFO), datas);
}

void OnGetCurrentGroupFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_CURRENT_GROUP), datas);
}

void OnGetP2pEnableStatusFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_ENABLE_STATUS), datas);
}

void OnGetP2pDiscoverStatusFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_DISCOVER_STATUS), datas);
}

void OnGetP2pConnectedStatusFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_CONNECTED_STATUS), datas);
}

void OnQueryP2pDevicesFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_DEVICES), datas);
}

void OnQueryP2pGroupsFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_GROUPS), datas);
}

void OnQueryP2pServicesFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_SERVICES), datas);
}

void OnRegisterCallBackFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_REGISTER_CALLBACK), datas);
}

void OnSetP2pDeviceNameFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_SET_DEVICE_NAME), datas);
}

void OnSetP2pWfdInfoFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_SET_WFD_INFO), datas);
}

void OnHid2dRequestGcIpFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_APPLY_IP), datas);
}

void OnHid2dSharedlinkIncreaseFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_SHARED_LINK_INCREASE), datas);
}

void OnHid2dSharedlinkDecreaseFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_SHARED_LINK_DECREASE), datas);
}


void OnHid2dCreateGroupFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CREATE_GROUP), datas);
}

void OnHid2dRemoveGcGroupFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_REMOVE_GC_GROUP), datas);
}
void OnHid2dConnectFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CONNECT), datas);
}

void OnHid2dConfigIPAddrFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_CONFIG_IP), datas);
}

void OnHid2dReleaseIPAddrFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_RELEASE_IP), datas);
}

void OnHid2dGetRecommendChannelFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_P2P_RECOMMENDED_CHANNEL), datas);
}

void OnHid2dGetChannelListFor5GFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNEL_LIST), datas);
}

void OnHid2dGetSelfWifiCfgInfoFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_GET_SELF_WIFI_CFG), datas);
}

void OnHid2dSetPeerWifiCfgInfoFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_SET_PEER_WIFI_CFG), datas);
}
void OnQueryP2pLocalDeviceFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_QUERY_LOCAL_DEVICE), datas);
}

void OnHid2dSetUpperSceneFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_SET_UPPER_SCENE), datas);
}

void DoSomethingInterestingWithMyAPIS()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_ENABLE), datas);
}

void DoSomethingInterestingWithMyAPI()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISABLE), datas);
}

void OnEnableWifiFuzzTest()
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI),
        datas, reply, option);
}

void OnDisableWifiFuzzTest()
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI),
        datas, reply, option);
}

void OnDiscoverPeersFuzzTest()
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISCOVER_PEERS),
        datas, reply, option);
}

void OnDisableRandomMacFuzzTest()
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISABLE_RANDOM_MAC),
        datas, reply, option);
}

void OnCheckCanUseP2pFuzzTest()
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_CHECK_CAN_USE_P2P),
        datas, reply, option);
}

void Hid2dIsWideBandwidthSupportedFuzzTest()
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_HID2D_WIDE_SUPPORTED),
        datas, reply, option);
}

void WifiP2pServiceImplFuzzTest()
{
    WifiP2pServiceInfo srvInfo;
    std::string serviceName = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string mDeviceAddress = FDP->ConsumeBytesAsString(NUM_BYTES);
    srvInfo.SetServiceName(serviceName);
    srvInfo.SetDeviceAddress(mDeviceAddress);

    WifiP2pDevice device;
    std::string deviceName = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string networkName = FDP->ConsumeBytesAsString(NUM_BYTES);
    mDeviceAddress = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string primaryDeviceType = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string secondaryDeviceType = FDP->ConsumeBytesAsString(NUM_BYTES);
    unsigned int supportWpsConfigMethods = FDP->ConsumeIntegral<unsigned int>();
    int deviceCapabilitys = FDP->ConsumeIntegral<int>();
    int groupCapabilitys = FDP->ConsumeIntegral<int>();
    device.SetDeviceName(deviceName);
    device.SetNetworkName(networkName);
    device.SetDeviceAddress(mDeviceAddress);
    device.SetPrimaryDeviceType(primaryDeviceType);
    device.SetSecondaryDeviceType(secondaryDeviceType);
    device.SetWpsConfigMethod(supportWpsConfigMethods);
    device.SetDeviceCapabilitys(deviceCapabilitys);
    device.SetGroupCapabilitys(groupCapabilitys);
    WifiP2pGroupInfo group;
    std::string passphrase = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string interface = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string groupName = FDP->ConsumeBytesAsString(NUM_BYTES);
    int frequency = FDP->ConsumeIntegral<int>();
    group.SetPassphrase(passphrase);
    group.SetInterface(interface);
    group.SetGroupName(groupName);
    group.SetFrequency(frequency);
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES), datas);
    pWifiP2pServiceImpl->WriteWifiP2pServiceInfo(datas, srvInfo);
    pWifiP2pServiceImpl->WriteWifiP2pDeviceData(datas, device);
    pWifiP2pServiceImpl->WriteWifiP2pGroupData(datas, group, false);
    pWifiP2pServiceImpl->WriteWifiP2pServiceInfo(datas, srvInfo);
}

void OnGetSupportChanForBandTest()
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(
        static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_GET_SUPPORT_CHANN_FOR_BAND),
        datas, reply, option);
}

void OnSetP2pHighPerfTest()
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(
        static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_SET_P2P_HIGH_PERF_MODE),
        datas, reply, option);
}

void WifiP2pStubFuzzTest()
{
    OHOS::Wifi::OnDiscoverDevicesFuzzTest();
    OHOS::Wifi::OnDiscoverPeersFuzzTest();
    OHOS::Wifi::OnDisableRandomMacFuzzTest();
    OHOS::Wifi::OnCheckCanUseP2pFuzzTest();
    OHOS::Wifi::OnStopDiscoverDevicesFuzzTest();
    OHOS::Wifi::OnDiscoverServicesFuzzTest();
    OHOS::Wifi::OnStopDiscoverServicesFuzzTest();
    OHOS::Wifi::OnRequestServiceFuzzTest();
    OHOS::Wifi::OnPutLocalP2pServiceFuzzTest();
    OHOS::Wifi::OnDeleteLocalP2pServiceFuzzTest();
    OHOS::Wifi::OnStartP2pListenFuzzTest();
    OHOS::Wifi::OnStopP2pListenFuzzTest();
    OHOS::Wifi::OnCreateGroupFuzzTest();
    OHOS::Wifi::OnRemoveGroupFuzzTest();
    OHOS::Wifi::OnDeleteGroupFuzzTest();
    OHOS::Wifi::OnP2pConnectFuzzTest();
    OHOS::Wifi::OnP2pCancelConnectFuzzTest();
    OHOS::Wifi::OnQueryP2pLinkedInfoFuzzTest();
    OHOS::Wifi::OnGetCurrentGroupFuzzTest();
    OHOS::Wifi::OnGetP2pEnableStatusFuzzTest();
    OHOS::Wifi::OnGetP2pDiscoverStatusFuzzTest();
    OHOS::Wifi::OnGetP2pConnectedStatusFuzzTest();
    OHOS::Wifi::OnQueryP2pDevicesFuzzTest();
    OHOS::Wifi::OnQueryP2pGroupsFuzzTest();
    OHOS::Wifi::OnQueryP2pServicesFuzzTest();
    OHOS::Wifi::OnRegisterCallBackFuzzTest();
    OHOS::Wifi::OnSetP2pDeviceNameFuzzTest();
    OHOS::Wifi::OnSetP2pWfdInfoFuzzTest();
    OHOS::Wifi::OnHid2dRequestGcIpFuzzTest();
    OHOS::Wifi::OnHid2dSharedlinkIncreaseFuzzTest();
    OHOS::Wifi::OnHid2dSharedlinkDecreaseFuzzTest();
    OHOS::Wifi::OnHid2dCreateGroupFuzzTest();
    OHOS::Wifi::OnHid2dRemoveGcGroupFuzzTest();
    OHOS::Wifi::OnHid2dConnectFuzzTest();
    OHOS::Wifi::OnHid2dConfigIPAddrFuzzTest();
    OHOS::Wifi::OnHid2dReleaseIPAddrFuzzTest();
    OHOS::Wifi::OnHid2dGetRecommendChannelFuzzTest();
    OHOS::Wifi::OnHid2dGetChannelListFor5GFuzzTest();
    OHOS::Wifi::OnHid2dGetSelfWifiCfgInfoFuzzTest();
    OHOS::Wifi::OnHid2dSetPeerWifiCfgInfoFuzzTest();
    OHOS::Wifi::OnQueryP2pLocalDeviceFuzzTest();
    OHOS::Wifi::OnHid2dSetUpperSceneFuzzTest();
    OHOS::Wifi::DoSomethingInterestingWithMyAPI();
    OHOS::Wifi::WifiP2pServiceImplFuzzTest();
    OHOS::Wifi::Hid2dIsWideBandwidthSupportedFuzzTest();
    OHOS::Wifi::OnRemoveGroupClientFuzzTest();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    Init();
    FuzzedDataProvider fdp(data, size);
    OHOS::Wifi::FDP = &fdp;
    OHOS::Wifi::WifiP2pStubFuzzTest();
    sleep(U32_AT_SIZE_ZERO);
    return 0;
}
}
}
