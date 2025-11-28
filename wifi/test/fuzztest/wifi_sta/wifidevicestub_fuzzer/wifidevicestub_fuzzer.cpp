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

#include "wifidevicestub_fuzzer.h"
#include "wifi_fuzz_common_func.h"
#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "wifi_device_stub.h"
#include "wifi_device_mgr_stub.h"
#include "message_parcel.h"
#include "securec.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_device_service_impl.h"
#include "wifi_device_mgr_service_impl.h"
#include "wifi_log.h"
#include <mutex>
#include "wifi_config_center.h"
#include "wifi_settings.h"
#include "wifi_common_def.h"
#include "wifi_manager.h"
#include "wifi_net_agent.h"

namespace OHOS {
namespace Wifi {
FuzzedDataProvider *FDP = nullptr;
const int32_t NUM_BYTES = 1;
constexpr int FIVE = 5;
constexpr int NINE = 9;
const size_t MAX_INPUT_SIZE = 1024;
static bool g_isInsted = false;
static std::mutex g_instanceLock;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiDeviceService";
const std::u16string FORMMGR_INTERFACE_TOKEN_DEVICE_EX = u"ohos.wifi.IWifiDeviceMgr";
std::shared_ptr<WifiDeviceServiceImpl> pWifiDeviceServiceImpl = std::make_shared<WifiDeviceServiceImpl>();
std::shared_ptr<WifiDeviceStub> pWifiDeviceStub = std::make_shared<WifiDeviceServiceImpl>();
sptr<WifiDeviceMgrStub> pWifiDeviceMgrStub = WifiDeviceMgrServiceImpl::GetInstance();

class IWifiDeviceCallBackMock : public IWifiDeviceCallBack {
public:
    IWifiDeviceCallBackMock()
    {
        LOGE("IWifiDeviceCallBackMock");
    }

    ~IWifiDeviceCallBackMock()
    {
        LOGE("~IWifiDeviceCallBackMock");
    }

public:
    void OnWifiStateChanged(int state) override
    {
        LOGE("OnWifiStateChanged test");
    }

    void OnWifiConnectionChanged(int state, const WifiLinkedInfo &info) override
    {
        LOGE("OnWifiConnectionChanged test");
    }

    void OnWifiRssiChanged(int rssi) override
    {
        LOGE("OnWifiRssiChanged test");
    }

    void OnWifiWpsStateChanged(int state, const std::string &pinCode) override
    {
        LOGE("OnWifiWpsStateChanged test");
    }

    void OnStreamChanged(int direction) override
    {
        LOGE("OnStreamChanged test");
    }

    void OnDeviceConfigChanged(ConfigChange value) override
    {
        LOGE("OnDeviceConfigChanged test");
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

bool Init()
{
    if (!g_isInsted) {
        if (WifiConfigCenter::GetInstance().GetWifiMidState(0) != WifiOprMidState::RUNNING) {
            WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::RUNNING, 0);
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
    pWifiDeviceStub->OnRemoteRequest(code, data, reply, option);
    return true;
}

void OnInitWifiProtectFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

void OnGetWifiProtectRefFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_PROTECT), datas);
}

void OnPutWifiProtectRefFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_PUT_WIFI_PROTECT), datas);
}

void OnIsHeldWifiProtectRefFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_HELD_WIFI_PROTECT), datas);
}

void OnAddDeviceConfigFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ADD_DEVICE_CONFIG), datas);
}

void OnSetWifiRestrictedListFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_WIFI_ACCESS_LIST), datas);
}

void OnUpdateDeviceConfigFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG), datas);
}

void OnRemoveDeviceFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG), datas);
}

void OnRemoveAllDeviceFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG), datas);
}

void OnGetDeviceConfigsFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIGS), datas);
}

void OnEnableDeviceConfigFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_DEVICE), datas);
}

void OnDisableDeviceConfigFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_DEVICE), datas);
}

void OnAllowAutoConnectFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ALLOW_AUTO_CONNECT), datas);
}

void OnConnectToFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT_TO), datas);
}

void OnConnect2ToFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT2_TO), datas);
}

void OnReConnectFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_RECONNECT), datas);
}

void OnReAssociateFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REASSOCIATE), datas);
}

void OnDisconnectFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISCONNECT), datas);
}

void OnStartWpsFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_WPS), datas);
}

void OnCancelWpsFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CANCEL_WPS), datas);
}

void OnIsWifiActiveFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_ACTIVE), datas);
}

void OnGetWifiStateFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_STATE), datas);
}

void OnGetLinkedInfoFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_LINKED_INFO), datas);
}

void OnIsMeteredHotspotFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_METERED_HOTSPOT), datas);
}

void OnGetIpInfoFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_INFO), datas);
}

void OnSetCountryCodeFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_COUNTRY_CODE), datas);
}

void OnGetCountryCodeFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_COUNTRY_CODE), datas);
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT), datas);
}

void OnGetSignalLevelFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNAL_LEVEL), datas);
}

void OnGetIpV6InfoFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_IPV6INFO), datas);
}

void OnGetDeviceMacAddFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DERVICE_MAC_ADD), datas);
}

void OnIsWifiConnectedFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_CONNECTED), datas);
}

void OnSetLowLatencyModeFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_LATENCY_MODE), datas);
}

void OnRemoveCandidateConfigFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_CANDIDATE_CONFIG), datas);
}

void OnIsBandTypeSupportedFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_BANDTYPE_SUPPORTED), datas);
}

void OnGet5GHzChannelListFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNELLIST), datas);
}

void OnGetDisconnectedReasonFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DISCONNECTED_REASON), datas);
}

void OnSetFrozenAppFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_FROZEN_APP), datas);
}

void OnResetAllFrozenAppFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_RESET_ALL_FROZEN_APP), datas);
}

void OnDisableAutoJoinFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_AUTO_JOIN), datas);
}

void OnEnableAutoJoinFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_AUTO_JOIN), datas);
}

void OnStartPortalCertificationFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_PORTAL_CERTIF), datas);
}

void OnGetChangeDeviceConfigFuzzTest()
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        return;
    }

    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    if (FDP->remaining_bytes() < 0) {
        return;
    }

    size_t readSize = std::min(static_cast<size_t>(FDP->remaining_bytes()),MAX_INPUT_SIZE);
    
    std::string tmpBuffer;
    if (readSize > 0) {
        tmpBuffer = FDP->ConsumeBytesAsString(readSize);
    }

    datas.WriteInt32(tmpInt);
    if (!tmpBuffer.empty()) {
        datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    }

    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIG_CHANGE), datas);
}

void OnLimitSpeedFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_LIMIT_SPEED), datas);
}

void OnEnableHiLinkHandshakeFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_HILINK_CONNECT), datas);
}

void OnStartWifiDetectionFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_WIFI_DETECTION), datas);
}

void OnGetMultiLinkedInfoFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_MULTI_LINKED_INFO), datas);
}

void OnSetSatelliteStateFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_SATELLITE_STATE), datas);
}

void OnFactoryResetFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_SET_FACTORY_RESET), datas);
}

void OnEnableWifiFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI), datas);
}

void OnDisableWifiFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI), datas);
}

void OnGetSupportedFeaturesFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES), datas);
}

void OnEnableSemiWifiFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_SEMI_WIFI), datas);
}

void OnGetWifiDetailStateFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_DETAIL_STATE), datas);
}

void OnSetTxPowerFuzzTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_TX_POWER), datas);
}

void OnSetLowTxPowerTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_TX_POWER), datas);
}

void OnSetDpiMarkRuleTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_DPI_MARK_RULE), datas);
}

void DoSomethingDeviceMgrStubTest()
{
    int32_t fd = FDP->ConsumeIntegral<int32_t>();
    std::vector<std::u16string> args;
    std::string networkName = "backup";
    std::string name = "restore";
    uint32_t code = static_cast<uint32_t>(DevInterfaceCode::WIFI_MGR_GET_DEVICE_SERVICE);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE_EX);
    int32_t tmpInt = FDP->ConsumeIntegral<int32_t>();
    std::string tmpBuffer = FDP->ConsumeBytesAsString(NUM_BYTES);
    datas.WriteInt32(tmpInt);
    datas.WriteBuffer(tmpBuffer.c_str(), tmpBuffer.size());
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    WifiDeviceMgrServiceImpl mWifiDeviceMgrServiceImpl;
    pWifiDeviceMgrStub->OnRemoteRequest(code, datas, reply, option);
    mWifiDeviceMgrServiceImpl.OnExtension(networkName, datas, reply);
    mWifiDeviceMgrServiceImpl.OnExtension(name, datas, reply);
    mWifiDeviceMgrServiceImpl.Dump(fd, args);
    mWifiDeviceMgrServiceImpl.OnSvcCmd(fd, args);
}

bool WifiFuzzTest()
{
    return true;
}

void WifiDeviceServiceImplTest()
{
    int networkId = FDP->ConsumeIntegral<int>();
    int uid = FDP->ConsumeIntegral<int>();
    std::string networkName = FDP->ConsumeBytesAsString(NUM_BYTES);
    FilterTag filterTag = static_cast<FilterTag>(FDP->ConsumeIntegral<uint8_t>() % FIVE);
    bool attemptEnable = FDP->ConsumeBool();
    WifiDeviceServiceImpl mWifiDeviceServiceImpl;
    MessageParcel datas;
    WifiDeviceConfig config;
    config.ssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.eap = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.clientCert = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.privateKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.certEntry.push_back(FDP->ConsumeIntegral<uint8_t>());
    config.wifiEapConfig.encryptedData = FDP->ConsumeBytesAsString(NUM_BYTES);

    mWifiDeviceServiceImpl.DeregisterAutoJoinCondition(networkName);
    mWifiDeviceServiceImpl.DeregisterFilterBuilder(filterTag, networkName);
    mWifiDeviceServiceImpl.RegisterAutoJoinCondition(networkName, WifiFuzzTest);
    mWifiDeviceServiceImpl.HilinkGetMacAddress(config, config.ssid);
    mWifiDeviceServiceImpl.SaBasicDump(config.ssid);
    mWifiDeviceServiceImpl.IsScanServiceRunning();
    mWifiDeviceServiceImpl.StartRoamToNetwork(networkId, networkName, attemptEnable);
    mWifiDeviceServiceImpl.IsWifiBrokerProcess(uid);
    mWifiDeviceServiceImpl.CheckConfigPwd(config);
    mWifiDeviceServiceImpl.CheckConfigEap(config);
    pWifiDeviceStub->WriteEapConfig(datas, config.wifiEapConfig);
    pWifiDeviceStub->WriteWifiDeviceConfig(datas, config);
}

void CheckConfigEapTest()
{
    WifiDeviceConfig config;
    config.ssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.eap = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.clientCert = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.privateKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.certEntry.push_back(FDP->ConsumeIntegral<uint8_t>());
    config.wifiEapConfig.encryptedData = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string keyMgmtWapiPsk = "WPA-PSK";
    config.keyMgmt = keyMgmtWapiPsk;
    pWifiDeviceServiceImpl->CheckConfigEap(config);
    config.keyMgmt.clear();
    std::string eapMethodPeap = "PEAP";
    config.wifiEapConfig.eap = EAP_METHOD_PEAP;
    pWifiDeviceServiceImpl->CheckConfigEap(config);
    config.keyMgmt = FDP->ConsumeBytesAsString(NUM_BYTES);
    pWifiDeviceServiceImpl->CheckConfigEap(config);
}

void CheckConfigWapiTest()
{
    WifiDeviceConfig config;
    config.ssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.eap = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.clientCert = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.privateKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.certEntry.push_back(FDP->ConsumeIntegral<uint8_t>());
    config.wifiEapConfig.encryptedData = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string keyMgmtwapiPsk = "WAPI-PSK";
    config.keyMgmt = keyMgmtwapiPsk;
    pWifiDeviceServiceImpl->CheckConfigWapi(config);
    config.keyMgmt.clear();
    config.keyMgmt = FDP->ConsumeBytesAsString(NUM_BYTES);
    pWifiDeviceServiceImpl->CheckConfigWapi(config);
}

void CheckConfigPwdTest()
{
    WifiDeviceConfig config;
    std::string ssidLength = "name";
    config.ssid = ssidLength;
    config.bssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.eap = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.clientCert = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.privateKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.certEntry.push_back(FDP->ConsumeIntegral<uint8_t>());
    config.wifiEapConfig.encryptedData = FDP->ConsumeBytesAsString(NUM_BYTES);
    pWifiDeviceServiceImpl->CheckConfigPwd(config);
}

void InitWifiBrokerProcessInfoTest()
{
    WifiDeviceConfig config;
    config.ssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.eap = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.clientCert = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.privateKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.certEntry.push_back(FDP->ConsumeIntegral<uint8_t>());
    config.wifiEapConfig.encryptedData = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string ancoServiceBroker = "anco_service_broker";
    config.callProcessName = ancoServiceBroker;
    pWifiDeviceServiceImpl->InitWifiBrokerProcessInfo(config);
}

void SetWifiConnectedModeTest()
{
    pWifiDeviceServiceImpl->SetWifiConnectedMode();
}

void RemoveCandidateConfigFuzzTest()
{
    WifiDeviceConfig config;
    config.ssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.eap = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.clientCert = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.privateKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.certEntry.push_back(FDP->ConsumeIntegral<uint8_t>());
    config.wifiEapConfig.encryptedData = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.callProcessName = FDP->ConsumeBytesAsString(NUM_BYTES);
    pWifiDeviceServiceImpl->RemoveCandidateConfig(config);
}

void RemoveCandidateConfigTest()
{
    int networkId = FDP->ConsumeIntegral<int>();
    pWifiDeviceServiceImpl->RemoveCandidateConfig(networkId);
}

void AddDeviceConfigTest()
{
    WifiDeviceConfig config;
    int result = 0;
    bool isCandidate = FDP->ConsumeBool();
    config.ssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.eap = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.clientCert = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.privateKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.certEntry.push_back(FDP->ConsumeIntegral<uint8_t>());
    config.wifiEapConfig.encryptedData = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.callProcessName = FDP->ConsumeBytesAsString(NUM_BYTES);
    pWifiDeviceServiceImpl->AddDeviceConfig(config, result, isCandidate);
}

void ConnectToNetworkTest()
{
    int networkId = FDP->ConsumeIntegral<int>();
    bool isCandidate = FDP->ConsumeBool();
    pWifiDeviceServiceImpl->ConnectToNetwork(networkId, isCandidate);
}

void ConnectToDeviceTest()
{
    WifiDeviceConfig config;
    config.ssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.eap = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.clientCert = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.privateKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.certEntry.push_back(FDP->ConsumeIntegral<uint8_t>());
    config.wifiEapConfig.encryptedData = FDP->ConsumeBytesAsString(NUM_BYTES);
    pWifiDeviceServiceImpl->ConnectToDevice(config);
}

void SaBasicDumpTest()
{
    WifiLinkedInfo info;
    info.connState = static_cast<ConnState>(FDP->ConsumeIntegral<uint8_t>() % NINE);
    WifiConfigCenter::GetInstance().SaveLinkedInfo(info, 0);
    std::string result;
    pWifiDeviceServiceImpl->SaBasicDump(result);
}

void IsRemoteDiedTest()
{
    pWifiDeviceServiceImpl->IsRemoteDied();
}

void IsBandTypeSupportedTest()
{
    int bandType = FDP->ConsumeIntegral<int>();
    bool supported = FDP->ConsumeBool();
    pWifiDeviceServiceImpl->IsBandTypeSupported(bandType, supported);
}

void RegisterCallBackTest()
{
    std::vector<std::string> event;
    sptr<IWifiDeviceCallBack> callBack = new (std::nothrow) IWifiDeviceCallBackMock();
    pWifiDeviceServiceImpl->RegisterCallBack(callBack, event);
    pWifiDeviceServiceImpl->RegisterCallBack(nullptr, event);
}

void CheckCanEnableWifiTest()
{
    pWifiDeviceServiceImpl->CheckCanEnableWifi();
}

void HilinkGetMacAddressTest()
{
    WifiDeviceConfig config;
    config.ssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.eap = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.clientCert = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.privateKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.certEntry.push_back(FDP->ConsumeIntegral<uint8_t>());
    config.wifiEapConfig.encryptedData = FDP->ConsumeBytesAsString(NUM_BYTES);
    std::string currentMac = FDP->ConsumeBytesAsString(NUM_BYTES);
    pWifiDeviceServiceImpl->HilinkGetMacAddress(config, currentMac);
}

void EnableHiLinkHandshakeTest()
{
    WifiDeviceConfig config;
    config.ssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.bssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.preSharedKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.keyMgmt = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.eap = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.clientCert = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.privateKey = FDP->ConsumeBytesAsString(NUM_BYTES);
    config.wifiEapConfig.certEntry.push_back(FDP->ConsumeIntegral<uint8_t>());
    config.wifiEapConfig.encryptedData = FDP->ConsumeBytesAsString(NUM_BYTES);
    bool uiFlag = FDP->ConsumeBool();
    std::string bssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    pWifiDeviceServiceImpl->EnableHiLinkHandshake(uiFlag, bssid, config);
}

void StartWifiDetectionTest()
{
    pWifiDeviceServiceImpl->StartWifiDetection();
}

void RegisterFilterBuilderTest()
{
    FilterTag filterTag = static_cast<FilterTag>(FDP->ConsumeIntegral<uint8_t>() % FIVE);
    std::string bssid = FDP->ConsumeBytesAsString(NUM_BYTES);
    FilterBuilder filterBuilder = [](auto &compositeWifiFilter) {};
    pWifiDeviceServiceImpl->RegisterFilterBuilder(filterTag, bssid, filterBuilder);
}

void OnGetDeviceConfigTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIG), datas);
}

void OnIsFeatureSupportedTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_FEATURE_SUPPORTED), datas);
}

void OnUpdateNetworkLagInfoTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_NETWORK_LAG_INFO), datas);
}

void OnReceiveNetworkControlInfoTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_NET_CONTROL_INFO), datas);
}

void OnFetchWifiSignalInfoForVoWiFiTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_FETCH_SIGNALINFO_VOWIFI), datas);
}

void OnIsSupportVoWifiDetectTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_SUPPORT_VOWIFI_DETECT), datas);
}

void OnSetVoWifiDetectModeTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_VOWIFI_DETECT_MODE), datas);
}

void OnGetVoWifiDetectModeTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_VOWIFI_DETECT_MODE), datas);
}

void OnSetVoWifiDetectPeriodTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_VOWIFI_DETECT_PERIOD), datas);
}

void OnGetVoWifiDetectPeriodTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_VOWIFI_DETECT_PERIOD), datas);
}

void OnGetSignalPollInfoArrayTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNALPOLL_INFO_ARRAY), datas);
}

void OnIsRandomMacDisabledTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_RANDOMMAC_DISABLED), datas);
}

void OnSetRandomMacDisabledTest()
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_RANDOMMAC_DISABLED), datas);
}

void WifiDeviceFuzzTest()
{
    OHOS::Wifi::OnInitWifiProtectFuzzTest();
    OHOS::Wifi::OnGetWifiProtectRefFuzzTest();
    OHOS::Wifi::OnPutWifiProtectRefFuzzTest();
    OHOS::Wifi::OnIsHeldWifiProtectRefFuzzTest();
    OHOS::Wifi::OnSetWifiRestrictedListFuzzTest();
    OHOS::Wifi::OnAddDeviceConfigFuzzTest();
    OHOS::Wifi::OnUpdateDeviceConfigFuzzTest();
    OHOS::Wifi::OnRemoveDeviceFuzzTest();
    OHOS::Wifi::OnRemoveAllDeviceFuzzTest();
    OHOS::Wifi::OnGetDeviceConfigsFuzzTest();
    OHOS::Wifi::OnEnableDeviceConfigFuzzTest();
    OHOS::Wifi::OnDisableDeviceConfigFuzzTest();
    OHOS::Wifi::OnAllowAutoConnectFuzzTest();
    OHOS::Wifi::OnConnectToFuzzTest();
    OHOS::Wifi::OnConnect2ToFuzzTest();
    OHOS::Wifi::OnReConnectFuzzTest();
    OHOS::Wifi::OnReAssociateFuzzTest();
    OHOS::Wifi::OnDisconnectFuzzTest();
    OHOS::Wifi::OnStartWpsFuzzTest();
    OHOS::Wifi::OnCancelWpsFuzzTest();
    OHOS::Wifi::OnIsWifiActiveFuzzTest();
    OHOS::Wifi::OnGetWifiStateFuzzTest();
    OHOS::Wifi::OnIsMeteredHotspotFuzzTest();
    OHOS::Wifi::OnGetLinkedInfoFuzzTest();
    OHOS::Wifi::OnGetIpInfoFuzzTest();
    OHOS::Wifi::OnGetCountryCodeFuzzTest();
    OHOS::Wifi::OnRegisterCallBackFuzzTest();
    OHOS::Wifi::OnGetSignalLevelFuzzTest();
    OHOS::Wifi::OnGetIpV6InfoFuzzTest();
    OHOS::Wifi::OnGetDeviceMacAddFuzzTest();
    OHOS::Wifi::OnIsWifiConnectedFuzzTest();
    OHOS::Wifi::OnSetLowLatencyModeFuzzTest();
    OHOS::Wifi::OnRemoveCandidateConfigFuzzTest();
    OHOS::Wifi::OnIsBandTypeSupportedFuzzTest();
    OHOS::Wifi::OnGet5GHzChannelListFuzzTest();
    OHOS::Wifi::OnGetDisconnectedReasonFuzzTest();
    OHOS::Wifi::OnSetFrozenAppFuzzTest();
    OHOS::Wifi::OnResetAllFrozenAppFuzzTest();
    OHOS::Wifi::OnDisableAutoJoinFuzzTest();
    OHOS::Wifi::OnEnableAutoJoinFuzzTest();
    OHOS::Wifi::OnStartPortalCertificationFuzzTest();
    OHOS::Wifi::OnGetChangeDeviceConfigFuzzTest();
    OHOS::Wifi::OnLimitSpeedFuzzTest();
    OHOS::Wifi::OnEnableHiLinkHandshakeFuzzTest();
    OHOS::Wifi::OnGetWifiDetailStateFuzzTest();
}

void WifiDeviceFuzzTestPart2()
{
    OHOS::Wifi::OnSetTxPowerFuzzTest();
    OHOS::Wifi::OnStartWifiDetectionFuzzTest();
    OHOS::Wifi::OnGetMultiLinkedInfoFuzzTest();
    OHOS::Wifi::OnSetSatelliteStateFuzzTest();
    OHOS::Wifi::OnGetSupportedFeaturesFuzzTest();
    OHOS::Wifi::OnSetLowTxPowerTest();
    OHOS::Wifi::DoSomethingDeviceMgrStubTest();
    OHOS::Wifi::WifiDeviceServiceImplTest();
    OHOS::Wifi::CheckConfigEapTest();
    OHOS::Wifi::CheckConfigWapiTest();
    OHOS::Wifi::CheckConfigPwdTest();
    OHOS::Wifi::InitWifiBrokerProcessInfoTest();
    OHOS::Wifi::SetWifiConnectedModeTest();
    OHOS::Wifi::RemoveCandidateConfigFuzzTest();
    OHOS::Wifi::RemoveCandidateConfigTest();
    OHOS::Wifi::AddDeviceConfigTest();
    OHOS::Wifi::ConnectToNetworkTest();
    OHOS::Wifi::ConnectToDeviceTest();
    OHOS::Wifi::SaBasicDumpTest();
    OHOS::Wifi::IsRemoteDiedTest();
    OHOS::Wifi::IsBandTypeSupportedTest();
    OHOS::Wifi::RegisterCallBackTest();
    OHOS::Wifi::CheckCanEnableWifiTest();
    OHOS::Wifi::HilinkGetMacAddressTest();
    OHOS::Wifi::EnableHiLinkHandshakeTest();
    OHOS::Wifi::StartWifiDetectionTest();
    OHOS::Wifi::RegisterFilterBuilderTest();
    OHOS::Wifi::OnSetDpiMarkRuleTest();
    OHOS::Wifi::OnGetDeviceConfigTest();
    OHOS::Wifi::OnIsFeatureSupportedTest();
    OHOS::Wifi::OnUpdateNetworkLagInfoTest();
    OHOS::Wifi::OnReceiveNetworkControlInfoTest();
    OHOS::Wifi::OnFetchWifiSignalInfoForVoWiFiTest();
    OHOS::Wifi::OnIsSupportVoWifiDetectTest();
    OHOS::Wifi::OnSetVoWifiDetectModeTest();
    OHOS::Wifi::OnGetVoWifiDetectModeTest();
    OHOS::Wifi::OnSetVoWifiDetectPeriodTest();
    OHOS::Wifi::OnGetVoWifiDetectPeriodTest();
    OHOS::Wifi::OnGetSignalPollInfoArrayTest();
    OHOS::Wifi::OnIsRandomMacDisabledTest();
    OHOS::Wifi::OnSetRandomMacDisabledTest();
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Wifi::FDP = &fdp;
    OHOS::Wifi::WifiDeviceFuzzTest();
    OHOS::Wifi::WifiDeviceFuzzTestPart2();
    return 0;
}
}
}
