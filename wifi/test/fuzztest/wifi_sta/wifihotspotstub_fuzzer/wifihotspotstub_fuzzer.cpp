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

#include "wifihotspotstub_fuzzer.h"
#include "wifi_fuzz_common_func.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "wifi_hotspot_stub.h"
#include "wifi_device_stub.h"
#include "wifi_device_service_impl.h"
#include "message_parcel.h"
#include "securec.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_hotspot_service_impl.h"
#include "wifi_hotspot_mgr_stub.h"
#include "wifi_hotspot_mgr_service_impl.h"
#include "wifi_log.h"
#include <mutex>
#include "wifi_config_center.h"
#include "wifi_settings.h"
#include "wifi_common_def.h"
#include "wifi_manager.h"
namespace OHOS {
namespace Wifi {
constexpr size_t U32_AT_SIZE_ZERO = 4;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiHotspotService";
const std::u16string FORMMGR_INTERFACE_TOKEN_DEVICE = u"ohos.wifi.IWifiDeviceService";
static bool g_isInsted = false;
static std::mutex g_instanceLock;
std::shared_ptr<WifiDeviceStub> pWifiDeviceStub = std::make_shared<WifiDeviceServiceImpl>();
std::shared_ptr<WifiHotspotStub> pWifiHotspotServiceImpl = std::make_shared<WifiHotspotServiceImpl>();
void MyExit()
{
    WifiManager::GetInstance().GetWifiStaManager()->StopUnloadStaSaTimer();
    WifiManager::GetInstance().GetWifiScanManager()->StopUnloadScanSaTimer();
    WifiManager::GetInstance().GetWifiHotspotManager()->StopUnloadApSaTimer();
    WifiManager::GetInstance().GetWifiP2pManager()->StopUnloadP2PSaTimer();
    WifiAppStateAware::GetInstance().appChangeEventHandler.reset();
    WifiNetAgent::GetInstance().netAgentEventHandler.reset();
    WifiSettings::GetInstance().mWifiEncryptionThread.reset();
    WifiManager::GetInstance().Exit();
    sleep(5);
    printf("exiting\n");
}

bool Init()
{
    if (!g_isInsted) {
        if (WifiManager::GetInstance().Init() < 0) {
            LOGE("WifiManager init failed!");
            return false;
        }
        atexit(MyExit);
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
    pWifiHotspotServiceImpl->OnRemoteRequest(code, data, reply, option);
    return true;
}

void OnIsHotspotActiveFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_IS_HOTSPOT_ACTIVE), datas);
}

void OnGetApStateWifiFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GETAPSTATE_WIFI), datas);
}

void OnGetHotspotConfigFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_HOTSPOT_CONFIG), datas);
}

void OnSetApConfigWifiFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_SETAPCONFIG_WIFI), datas);
}

void OnGetStationListFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_STATION_LIST), datas);
}

void OnAddBlockListFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_ADD_BLOCK_LIST), datas);
}

void OnDelBlockListFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_DEL_BLOCK_LIST), datas);
}

void OnGetBlockListsFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_BLOCK_LISTS), datas);
}

void OnGetValidBandsFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_VALID_BANDS), datas);
}

void OnDisassociateStaFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_DISCONNECT_STA), datas);
}

void OnGetValidChannelsFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_VALID_CHANNELS), datas);
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
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_REGISTER_HOTSPOT_CALLBACK), datas);
}

void OnGetSupportedPowerModelFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_POWER_MODEL), datas);
}

void OnGetPowerModelFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_POWER_MODEL), datas);
}

void OnSetPowerModelFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_SET_POWER_MODEL), datas);
}

void OnIsHotspotDualBandSupportedFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_IS_HOTSPOT_DUAL_BAND_SUPPORTED), datas);
}

void OnSetApIdleTimeoutFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_SETTIMEOUT_AP), datas);
}

void OnGetApIfaceNameFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_IFACE_NAME), datas);
}

void OnEnableWifiApTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI_AP), datas);
}

void OnDisableWifiApTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI_AP), datas);
}

void OnEnableWifiFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI),
        datas, reply, option);
}

void OnDisableWifiFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI),
        datas, reply, option);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    Init();
    OHOS::Wifi::OnEnableWifiFuzzTest(data, size);
    OHOS::Wifi::OnEnableWifiApTest(data, size);
    OHOS::Wifi::OnIsHotspotActiveFuzzTest(data, size);
    OHOS::Wifi::OnGetApStateWifiFuzzTest(data, size);
    OHOS::Wifi::OnGetHotspotConfigFuzzTest(data, size);
    OHOS::Wifi::OnSetApConfigWifiFuzzTest(data, size);
    OHOS::Wifi::OnGetStationListFuzzTest(data, size);
    OHOS::Wifi::OnAddBlockListFuzzTest(data, size);
    OHOS::Wifi::OnDelBlockListFuzzTest(data, size);
    OHOS::Wifi::OnGetBlockListsFuzzTest(data, size);
    OHOS::Wifi::OnDisassociateStaFuzzTest(data, size);
    OHOS::Wifi::OnGetValidBandsFuzzTest(data, size);
    OHOS::Wifi::OnGetValidChannelsFuzzTest(data, size);
    OHOS::Wifi::OnRegisterCallBackFuzzTest(data, size);
    OHOS::Wifi::OnGetSupportedPowerModelFuzzTest(data, size);
    OHOS::Wifi::OnGetPowerModelFuzzTest(data, size);
    OHOS::Wifi::OnSetPowerModelFuzzTest(data, size);
    OHOS::Wifi::OnIsHotspotDualBandSupportedFuzzTest(data, size);
    OHOS::Wifi::OnSetApIdleTimeoutFuzzTest(data, size);
    OHOS::Wifi::OnGetApIfaceNameFuzzTest(data, size);
    OHOS::Wifi::OnDisableWifiApTest(data, size);
    OHOS::Wifi::OnDisableWifiFuzzTest(data, size);
    sleep(4);
    return 0;
}
}
}
