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
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr int TWO = 2;
constexpr int FIVE = 5;
constexpr int NINE = 9;
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

void OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

void OnGetWifiProtectRefFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_PROTECT), datas);
}

void OnPutWifiProtectRefFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_PUT_WIFI_PROTECT), datas);
}

void OnIsHeldWifiProtectRefFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_HELD_WIFI_PROTECT), datas);
}

void OnAddDeviceConfigFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ADD_DEVICE_CONFIG), datas);
}

void OnUpdateDeviceConfigFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG), datas);
}

void OnRemoveDeviceFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG), datas);
}

void OnRemoveAllDeviceFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG), datas);
}

void OnGetDeviceConfigsFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIGS), datas);
}

void OnEnableDeviceConfigFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_DEVICE), datas);
}

void OnDisableDeviceConfigFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_DEVICE), datas);
}

void OnConnectToFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT_TO), datas);
}

void OnConnect2ToFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CONNECT2_TO), datas);
}

void OnReConnectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_RECONNECT), datas);
}

void OnReAssociateFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REASSOCIATE), datas);
}

void OnDisconnectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISCONNECT), datas);
}

void OnStartWpsFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_WPS), datas);
}

void OnCancelWpsFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_CANCEL_WPS), datas);
}

void OnIsWifiActiveFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_ACTIVE), datas);
}

void OnGetWifiStateFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_STATE), datas);
}

void OnGetLinkedInfoFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_LINKED_INFO), datas);
}

void OnIsMeteredHotspotFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_METERED_HOTSPOT), datas);
}

void OnGetIpInfoFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_INFO), datas);
}

void OnSetCountryCodeFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_COUNTRY_CODE), datas);
}

void OnGetCountryCodeFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_COUNTRY_CODE), datas);
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
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REGISTER_CALLBACK_CLIENT), datas);
}

void OnGetSignalLevelFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SIGNAL_LEVEL), datas);
}

void OnGetIpV6InfoFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DHCP_IPV6INFO), datas);
}

void OnGetDeviceMacAddFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DERVICE_MAC_ADD), datas);
}

void OnIsWifiConnectedFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_WIFI_CONNECTED), datas);
}

void OnSetLowLatencyModeFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_LATENCY_MODE), datas);
}

void OnRemoveCandidateConfigFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_CANDIDATE_CONFIG), datas);
}

void OnIsBandTypeSupportedFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_BANDTYPE_SUPPORTED), datas);
}

void OnGet5GHzChannelListFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_5G_CHANNELLIST), datas);
}

void OnGetDisconnectedReasonFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DISCONNECTED_REASON), datas);
}

void OnSetFrozenAppFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_FROZEN_APP), datas);
}

void OnResetAllFrozenAppFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_RESET_ALL_FROZEN_APP), datas);
}

void OnDisableAutoJoinFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_AUTO_JOIN), datas);
}

void OnEnableAutoJoinFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_AUTO_JOIN), datas);
}

void OnStartPortalCertificationFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_PORTAL_CERTIF), datas);
}

void OnGetChangeDeviceConfigFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIG_CHANGE), datas);
}

void OnLimitSpeedFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_LIMIT_SPEED), datas);
}

void OnEnableHiLinkHandshakeFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_HILINK_CONNECT), datas);
}

void OnSetSatelliteStateFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_SATELLITE_STATE), datas);
}

void OnFactoryResetFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_SET_FACTORY_RESET), datas);
}

void OnEnableWifiFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI), datas);
}

void OnDisableWifiFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI), datas);
}

void OnGetSupportedFeaturesFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES), datas);
}

void OnEnableSemiWifiFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_SEMI_WIFI), datas);
}

void OnGetWifiDetailStateFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_DETAIL_STATE), datas);
}

void OnSetTxPowerFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_TX_POWER), datas);
}

void OnSetLowTxPowerTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_LOW_TX_POWER), datas);
}

void OnSetDpiMarkRuleTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_DPI_MARK_RULE), datas);
}

void DoSomethingDeviceMgrStubTest(const uint8_t* data, size_t size)
{
    std::string networkName = "backup";
    std::string name = "restore";
    uint32_t code = static_cast<uint32_t>(DevInterfaceCode::WIFI_MGR_GET_DEVICE_SERVICE);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE_EX);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    WifiDeviceMgrServiceImpl mWifiDeviceMgrServiceImpl;
    pWifiDeviceMgrStub->OnRemoteRequest(code, datas, reply, option);
    mWifiDeviceMgrServiceImpl.OnExtension(networkName, datas, reply);
    mWifiDeviceMgrServiceImpl.OnExtension(name, datas, reply);
}

bool WifiFuzzTest()
{
    return true;
}

void WifiDeviceServiceImplTest(const uint8_t* data, size_t size)
{
    int index = 0;
    int networkId = static_cast<int>(data[index++]);
    int uid = static_cast<int>(data[index++]);
    std::string networkName = std::string(reinterpret_cast<const char*>(data), size);
    FilterTag filterTag = static_cast<FilterTag>(static_cast<int>(data[0]) % FIVE);
    bool attemptEnable = (static_cast<int>(data[0]) % TWO) ? true : false;
    WifiDeviceServiceImpl mWifiDeviceServiceImpl;
    MessageParcel datas;
    WifiDeviceConfig config;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.eap = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.clientCert = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.privateKey = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.certEntry.push_back(static_cast<uint8_t>(data[index++]));
    config.wifiEapConfig.encryptedData = std::string(reinterpret_cast<const char*>(data), size);

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

void CheckConfigEapTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    int index = 0;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.eap = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.clientCert = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.privateKey = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.certEntry.push_back(static_cast<uint8_t>(data[index++]));
    config.wifiEapConfig.encryptedData = std::string(reinterpret_cast<const char*>(data), size);
    std::string keyMgmtWapiPsk = "WPA-PSK";
    config.keyMgmt = keyMgmtWapiPsk;
    pWifiDeviceServiceImpl->CheckConfigEap(config);
    config.keyMgmt.clear();
    std::string eapMethodPeap = "PEAP";
    config.wifiEapConfig.eap = EAP_METHOD_PEAP;
    pWifiDeviceServiceImpl->CheckConfigEap(config);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    pWifiDeviceServiceImpl->CheckConfigEap(config);
}

void CheckConfigWapiTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    int index = 0;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.eap = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.clientCert = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.privateKey = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.certEntry.push_back(static_cast<uint8_t>(data[index++]));
    config.wifiEapConfig.encryptedData = std::string(reinterpret_cast<const char*>(data), size);
    std::string keyMgmtwapiPsk = "WAPI-PSK";
    config.keyMgmt = keyMgmtwapiPsk;
    pWifiDeviceServiceImpl->CheckConfigWapi(config);
    config.keyMgmt.clear();
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    pWifiDeviceServiceImpl->CheckConfigWapi(config);
}

void CheckConfigPwdTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    int index = 0;
    std::string ssidLength = "name";
    config.ssid = ssidLength;
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.eap = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.clientCert = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.privateKey = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.certEntry.push_back(static_cast<uint8_t>(data[index++]));
    config.wifiEapConfig.encryptedData = std::string(reinterpret_cast<const char*>(data), size);
    pWifiDeviceServiceImpl->CheckConfigPwd(config);
}

void InitWifiBrokerProcessInfoTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    int index = 0;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.eap = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.clientCert = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.privateKey = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.certEntry.push_back(static_cast<uint8_t>(data[index++]));
    config.wifiEapConfig.encryptedData = std::string(reinterpret_cast<const char*>(data), size);
    std::string ancoServiceBroker = "anco_service_broker";
    config.callProcessName = ancoServiceBroker;
    pWifiDeviceServiceImpl->InitWifiBrokerProcessInfo(config);
}

void SetWifiConnectedModeTest(const uint8_t* data, size_t size)
{
    pWifiDeviceServiceImpl->SetWifiConnectedMode();
}

void RemoveCandidateConfigFuzzTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    int index = 0;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.eap = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.clientCert = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.privateKey = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.certEntry.push_back(static_cast<uint8_t>(data[index++]));
    config.wifiEapConfig.encryptedData = std::string(reinterpret_cast<const char*>(data), size);
    config.callProcessName = std::string(reinterpret_cast<const char*>(data), size);
    pWifiDeviceServiceImpl->RemoveCandidateConfig(config);
}

void RemoveCandidateConfigTest(const uint8_t* data, size_t size)
{
    int index = 0;
    int networkId = static_cast<int>(data[index++]);
    pWifiDeviceServiceImpl->RemoveCandidateConfig(networkId);
}

void AddDeviceConfigTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    int result = 0;
    int index = 0;
    bool isCandidate = (static_cast<int>(data[0]) % TWO) ? true : false;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.eap = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.clientCert = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.privateKey = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.certEntry.push_back(static_cast<uint8_t>(data[index++]));
    config.wifiEapConfig.encryptedData = std::string(reinterpret_cast<const char*>(data), size);
    config.callProcessName = std::string(reinterpret_cast<const char*>(data), size);
    pWifiDeviceServiceImpl->AddDeviceConfig(config, result, isCandidate);
}

void ConnectToNetworkTest(const uint8_t* data, size_t size)
{
    int index = 0;
    int networkId = static_cast<int>(data[index++]);
    bool isCandidate = (static_cast<int>(data[0]) % TWO) ? true : false;
    pWifiDeviceServiceImpl->ConnectToNetwork(networkId, isCandidate);
}

void ConnectToDeviceTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    int index = 0;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.eap = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.clientCert = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.privateKey = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.certEntry.push_back(static_cast<uint8_t>(data[index++]));
    config.wifiEapConfig.encryptedData = std::string(reinterpret_cast<const char*>(data), size);
    pWifiDeviceServiceImpl->ConnectToDevice(config);
}

void SaBasicDumpTest(const uint8_t* data, size_t size)
{
    WifiLinkedInfo info;
    info.connState = static_cast<ConnState>(static_cast<int>(data[0]) % NINE);
    WifiConfigCenter::GetInstance().SaveLinkedInfo(info, 0);
    std::string result;
    pWifiDeviceServiceImpl->SaBasicDump(result);
}

void IsRemoteDiedTest(const uint8_t* data, size_t size)
{
    pWifiDeviceServiceImpl->IsRemoteDied();
}

void IsBandTypeSupportedTest(const uint8_t* data, size_t size)
{
    int bandType = static_cast<int>(data[0]);
    bool supported = (static_cast<int>(data[0]) % TWO) ? true : false;
    pWifiDeviceServiceImpl->IsBandTypeSupported(bandType, supported);
}

void RegisterCallBackTest(const uint8_t* data, size_t size)
{
    std::vector<std::string> event;
    sptr<IWifiDeviceCallBack> callBack = new (std::nothrow) IWifiDeviceCallBackMock();
    pWifiDeviceServiceImpl->RegisterCallBack(callBack, event);
    pWifiDeviceServiceImpl->RegisterCallBack(nullptr, event);
}

void CheckCanEnableWifiTest(const uint8_t* data, size_t size)
{
    pWifiDeviceServiceImpl->CheckCanEnableWifi();
}

void HilinkGetMacAddressTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    int index = 0;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.eap = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.clientCert = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.privateKey = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.certEntry.push_back(static_cast<uint8_t>(data[index++]));
    config.wifiEapConfig.encryptedData = std::string(reinterpret_cast<const char*>(data), size);
    std::string currentMac = std::string(reinterpret_cast<const char*>(data), size);
    pWifiDeviceServiceImpl->HilinkGetMacAddress(config, currentMac);
}

void EnableHiLinkHandshakeTest(const uint8_t* data, size_t size)
{
    WifiDeviceConfig config;
    int index = 0;
    config.ssid = std::string(reinterpret_cast<const char*>(data), size);
    config.bssid = std::string(reinterpret_cast<const char*>(data), size);
    config.preSharedKey = std::string(reinterpret_cast<const char*>(data), size);
    config.keyMgmt = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.eap = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.clientCert = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.privateKey = std::string(reinterpret_cast<const char*>(data), size);
    config.wifiEapConfig.certEntry.push_back(static_cast<uint8_t>(data[index++]));
    config.wifiEapConfig.encryptedData = std::string(reinterpret_cast<const char*>(data), size);
    bool uiFlag = (static_cast<int>(data[0]) % TWO) ? true : false;
    std::string bssid = std::string(reinterpret_cast<const char*>(data), size);
    pWifiDeviceServiceImpl->EnableHiLinkHandshake(uiFlag, bssid, config);
}

void RegisterFilterBuilderTest(const uint8_t* data, size_t size)
{
    FilterTag filterTag = static_cast<FilterTag>(static_cast<int>(data[0]) % FIVE);
    std::string bssid = std::string(reinterpret_cast<const char*>(data), size);
    FilterBuilder filterBuilder = [](auto &compositeWifiFilter) {};
    pWifiDeviceServiceImpl->RegisterFilterBuilder(filterTag, bssid, filterBuilder);
}

void OnGetDeviceConfigTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIG), datas);
}

void OnIsFeatureSupportedTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_FEATURE_SUPPORTED), datas);
}

void OnUpdateNetworkLagInfoTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_NETWORK_LAG_INFO), datas);
}

void OnReceiveNetworkControlInfoTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_NET_CONTROL_INFO), datas);
}

void OnFetchWifiSignalInfoForVoWiFiTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_FETCH_SIGNALINFO_VOWIFI), datas);
}

void OnIsSupportVoWifiDetectTest(const uint8_t* data, size_t size)
{
    StopMonitor();
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_SUPPORT_VOWIFI_DETECT), datas);
}

void OnSetVoWifiDetectModeTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_VOWIFI_DETECT_MODE), datas);
}

void OnSetVoWifiDetectPeriodTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_VOWIFI_DETECT_PERIOD), datas);
}

void OnGetVoWifiDetectPeriodTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_VOWIFI_DETECT_PERIOD), datas);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    OHOS::Wifi::OnInitWifiProtectFuzzTest(data, size);
    OHOS::Wifi::OnGetWifiProtectRefFuzzTest(data, size);
    OHOS::Wifi::OnPutWifiProtectRefFuzzTest(data, size);
    OHOS::Wifi::OnIsHeldWifiProtectRefFuzzTest(data, size);
    OHOS::Wifi::OnAddDeviceConfigFuzzTest(data, size);
    OHOS::Wifi::OnUpdateDeviceConfigFuzzTest(data, size);
    OHOS::Wifi::OnRemoveDeviceFuzzTest(data, size);
    OHOS::Wifi::OnRemoveAllDeviceFuzzTest(data, size);
    OHOS::Wifi::OnGetDeviceConfigsFuzzTest(data, size);
    OHOS::Wifi::OnEnableDeviceConfigFuzzTest(data, size);
    OHOS::Wifi::OnDisableDeviceConfigFuzzTest(data, size);
    OHOS::Wifi::OnConnectToFuzzTest(data, size);
    OHOS::Wifi::OnConnect2ToFuzzTest(data, size);
    OHOS::Wifi::OnReConnectFuzzTest(data, size);
    OHOS::Wifi::OnReAssociateFuzzTest(data, size);
    OHOS::Wifi::OnDisconnectFuzzTest(data, size);
    OHOS::Wifi::OnStartWpsFuzzTest(data, size);
    OHOS::Wifi::OnCancelWpsFuzzTest(data, size);
    OHOS::Wifi::OnIsWifiActiveFuzzTest(data, size);
    OHOS::Wifi::OnGetWifiStateFuzzTest(data, size);
    OHOS::Wifi::OnIsMeteredHotspotFuzzTest(data, size);
    OHOS::Wifi::OnGetLinkedInfoFuzzTest(data, size);
    OHOS::Wifi::OnGetIpInfoFuzzTest(data, size);
    OHOS::Wifi::OnGetCountryCodeFuzzTest(data, size);
    OHOS::Wifi::OnRegisterCallBackFuzzTest(data, size);
    OHOS::Wifi::OnGetSignalLevelFuzzTest(data, size);
    OHOS::Wifi::OnGetIpV6InfoFuzzTest(data, size);
    OHOS::Wifi::OnGetDeviceMacAddFuzzTest(data, size);
    OHOS::Wifi::OnIsWifiConnectedFuzzTest(data, size);
    OHOS::Wifi::OnSetLowLatencyModeFuzzTest(data, size);
    OHOS::Wifi::OnRemoveCandidateConfigFuzzTest(data, size);
    OHOS::Wifi::OnIsBandTypeSupportedFuzzTest(data, size);
    OHOS::Wifi::OnGet5GHzChannelListFuzzTest(data, size);
    OHOS::Wifi::OnGetDisconnectedReasonFuzzTest(data, size);
    OHOS::Wifi::OnSetFrozenAppFuzzTest(data, size);
    OHOS::Wifi::OnResetAllFrozenAppFuzzTest(data, size);
    OHOS::Wifi::OnDisableAutoJoinFuzzTest(data, size);
    OHOS::Wifi::OnEnableAutoJoinFuzzTest(data, size);
    OHOS::Wifi::OnStartPortalCertificationFuzzTest(data, size);
    OHOS::Wifi::OnGetChangeDeviceConfigFuzzTest(data, size);
    OHOS::Wifi::OnLimitSpeedFuzzTest(data, size);
    OHOS::Wifi::OnEnableHiLinkHandshakeFuzzTest(data, size);
    OHOS::Wifi::OnGetWifiDetailStateFuzzTest(data, size);
    OHOS::Wifi::OnSetTxPowerFuzzTest(data, size);
    OHOS::Wifi::OnSetSatelliteStateFuzzTest(data, size);
    OHOS::Wifi::OnGetSupportedFeaturesFuzzTest(data, size);
    OHOS::Wifi::OnSetLowTxPowerTest(data, size);
    OHOS::Wifi::DoSomethingDeviceMgrStubTest(data, size);
    OHOS::Wifi::WifiDeviceServiceImplTest(data, size);
    OHOS::Wifi::CheckConfigEapTest(data, size);
    OHOS::Wifi::CheckConfigWapiTest(data, size);
    OHOS::Wifi::CheckConfigPwdTest(data, size);
    OHOS::Wifi::InitWifiBrokerProcessInfoTest(data, size);
    OHOS::Wifi::SetWifiConnectedModeTest(data, size);
    OHOS::Wifi::RemoveCandidateConfigFuzzTest(data, size);
    OHOS::Wifi::RemoveCandidateConfigTest(data, size);
    OHOS::Wifi::AddDeviceConfigTest(data, size);
    OHOS::Wifi::ConnectToNetworkTest(data, size);
    OHOS::Wifi::ConnectToDeviceTest(data, size);
    OHOS::Wifi::SaBasicDumpTest(data, size);
    OHOS::Wifi::IsRemoteDiedTest(data, size);
    OHOS::Wifi::IsBandTypeSupportedTest(data, size);
    OHOS::Wifi::RegisterCallBackTest(data, size);
    OHOS::Wifi::CheckCanEnableWifiTest(data, size);
    OHOS::Wifi::HilinkGetMacAddressTest(data, size);
    OHOS::Wifi::EnableHiLinkHandshakeTest(data, size);
    OHOS::Wifi::RegisterFilterBuilderTest(data, size);
    OHOS::Wifi::OnSetDpiMarkRuleTest(data, size);
    OHOS::Wifi::OnGetDeviceConfigTest(data, size);
    OHOS::Wifi::OnIsFeatureSupportedTest(data, size);
    OHOS::Wifi::OnUpdateNetworkLagInfoTest(data, size);
    OHOS::Wifi::OnReceiveNetworkControlInfoTest(data, size);
    OHOS::Wifi::OnFetchWifiSignalInfoForVoWiFiTest(data, size);
    OHOS::Wifi::OnIsSupportVoWifiDetectTest(data, size);
    OHOS::Wifi::OnSetVoWifiDetectModeTest(data, size);
    OHOS::Wifi::OnSetVoWifiDetectPeriodTest(data, size);
    OHOS::Wifi::OnGetVoWifiDetectPeriodTest(data, size);
    sleep(4);
    return 0;
}
}
}
