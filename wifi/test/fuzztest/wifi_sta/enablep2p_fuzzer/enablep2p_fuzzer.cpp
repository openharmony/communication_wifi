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

#include "enablep2p_fuzzer.h"
#include "wifi_fuzz_common_func.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "wifi_p2p_stub.h"
#include "wifi_device_stub.h"
#include "wifi_hotspot_stub.h"
#include "wifi_scan_stub.h"
#include "message_parcel.h"
#include "securec.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_p2p_service_impl.h"
#include "wifi_device_service_impl.h"
#include "wifi_hotspot_service_impl.h"
#include "wifi_scan_service_impl.h"
#include "wifi_log.h"
#include "wifi_config_center.h"
#include "wifi_settings.h"
#include "wifi_common_def.h"

namespace OHOS {
namespace Wifi {
constexpr size_t MAP_SCAN_NUMS = 20;
constexpr size_t MAP_P2P_NUMS = 50;
constexpr size_t MAP_HOTSPOT_NUMS = 30;
constexpr size_t MAP_DEVICE_NUMS = 60;
constexpr size_t U32_AT_SIZE_ZERO = 4;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiP2pService";
const std::u16string FORMMGR_INTERFACE_TOKEN_DEVICE = u"ohos.wifi.IWifiDeviceService";
const std::u16string FORMMGR_INTERFACE_TOKEN_HOSPOT = u"ohos.wifi.IWifiHotspotService";
const std::u16string FORMMGR_INTERFACE_TOKEN_SCAN = u"ohos.wifi.IWifiScan";
std::shared_ptr<WifiDeviceStub> pWifiDeviceStub = std::make_shared<WifiDeviceServiceImpl>();
std::shared_ptr<WifiHotspotStub> pWifiHotspotStub = std::make_shared<WifiHotspotServiceImpl>();
sptr<WifiP2pStub> pWifiP2pStub = WifiP2pServiceImpl::GetInstance();
std::shared_ptr<WifiScanStub> pWifiScanStub = std::make_shared<WifiScanServiceImpl>();

bool DoSomethingScanStubTest(const uint8_t* data, size_t size)
{
    uint32_t code = U32_AT(data) % MAP_SCAN_NUMS + static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_FULL_SCAN);
    LOGI("wifiscanstub_fuzzer code(0x%{public}x) size(%{public}zu)", code, size); // code[0x1004, 0x101E]
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_SCAN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiScanStub->OnRemoteRequest(code, datas, reply, option);
    return true;
}

bool DoSomethingP2pStubTets(const uint8_t* data, size_t size)
{
    uint32_t code = U32_AT(data) % MAP_P2P_NUMS + static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_ENABLE);
    LOGI("wifip2pstub_fuzzer code(0x%{public}x) size(%{public}zu)", code, size);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiP2pStub->OnRemoteRequest(code, datas, reply, option);
    return true;
}


bool DoSomethingHotSpotStubTest(const uint8_t* data, size_t size)
{
    uint32_t code = U32_AT(data) % MAP_HOTSPOT_NUMS +
        static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI_AP);
    LOGI("wifihotspotstub_fuzzer code(0x%{public}x) size(%{public}zu)", code, size);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_HOSPOT);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiHotspotStub->OnRemoteRequest(code, datas, reply, option);
    return true;
}

bool DoSomethingDeviceStubTest(const uint8_t* data, size_t size)
{
    uint32_t code = U32_AT(data) % MAP_DEVICE_NUMS + static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI);
    LOGI("wifidevicestub_fuzzer code(0x%{public}x) size(%{public}zu)", code, size); // code[0x1001,0x1031]
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(code, datas, reply, option);
    return true;
}

bool IsFeatureSupportedTest(const uint8_t* data, size_t size)
{
    LOGI("IsFeatureSupportedTest");
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_FEATURE_SUPPORTED),
        datas, reply, option);
    return true;
}

bool OnEnableSemiWifiTest(const uint8_t* data, size_t size)
{
    LOGI("OnEnableSemiWifiTest"); // code[0x1001,0x1031]
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_SEMI_WIFI),
        datas, reply, option);
    return true;
}

bool OnStartRoamToNetworkTest(const uint8_t* data, size_t size)
{
    LOGI("OnStartRoamToNetworkTest"); // code[0x1001,0x1031]
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_ROAM_TO_NETWORK),
        datas, reply, option);
    return true;
}

bool OnStartConnectToUserSelectNetworkTest(const uint8_t* data, size_t size)
{
    LOGI("OnStartConnectToUserSelectNetworkTest"); // code[0x1001,0x1031]
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(
    static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_START_CONNECT_TO_USER_SELECT_NETWORK), datas, reply, option);
    return true;
}


bool OnSetScanOnlyAvailableTest(const uint8_t* data, size_t size)
{
    LOGI("OnSetScanOnlyAvailableTest"); // code[0x1004, 0x101E]
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_SCAN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiScanStub->OnRemoteRequest(static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_SET_WIFI_SCAN_ONLY),
        datas, reply, option);
    return true;
}

void OnEnableLocalOnlyHotspotFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiScanStub->OnRemoteRequest(static_cast<uint32_t>(
        HotspotInterfaceCode::WIFI_SVR_CMD_ENABLE_LOCAL_ONLY_HOTSPOT), datas, reply, option);
}
 
void OnDisableLocalOnlyHotspotFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiScanStub->OnRemoteRequest(static_cast<uint32_t>(
        HotspotInterfaceCode::WIFI_SVR_CMD_DISABLE_LOCAL_ONLY_HOTSPOT), datas, reply, option);
}
 
void OnGetHotspotModeFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiScanStub->OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_GET_HOTSPOT_MODE),
        datas, reply, option);
}
 
void OnGetLocaoOnlyHotspotConfigFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiScanStub->OnRemoteRequest(static_cast<uint32_t>(
        HotspotInterfaceCode::WIFI_SVR_CMD_GET_LOCAL_ONLY_HOTSPOT_CONFIG), datas, reply, option);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    OHOS::Wifi::DoSomethingScanStubTest(data, size);
    OHOS::Wifi::DoSomethingP2pStubTets(data, size);
    OHOS::Wifi::DoSomethingHotSpotStubTest(data, size);
    OHOS::Wifi::DoSomethingDeviceStubTest(data, size);
    OHOS::Wifi::OnEnableSemiWifiTest(data, size);
    OHOS::Wifi::OnStartRoamToNetworkTest(data, size);
    OHOS::Wifi::OnStartConnectToUserSelectNetworkTest(data, size);
    OHOS::Wifi::OnSetScanOnlyAvailableTest(data, size);
    OHOS::Wifi::IsFeatureSupportedTest(data, size);
    OHOS::Wifi::OnEnableLocalOnlyHotspotFuzzTest(data, size);
    OHOS::Wifi::OnDisableLocalOnlyHotspotFuzzTest(data, size);
    OHOS::Wifi::OnGetHotspotModeFuzzTest(data, size);
    OHOS::Wifi::OnGetLocaoOnlyHotspotConfigFuzzTest(data, size);
    return 0;
}
}
}
