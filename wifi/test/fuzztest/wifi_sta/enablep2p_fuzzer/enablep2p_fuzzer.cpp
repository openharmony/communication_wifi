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
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiP2pService";
const std::u16string FORMMGR_INTERFACE_TOKEN_DEVICE = u"ohos.wifi.IWifiDeviceService";
const std::u16string FORMMGR_INTERFACE_TOKEN_HOSPOT = u"ohos.wifi.IWifiHotspotService";
const std::u16string FORMMGR_INTERFACE_TOKEN_SCAN = u"ohos.wifi.IWifiScan";
std::shared_ptr<WifiDeviceStub> pWifiDeviceStub = std::make_shared<WifiDeviceServiceImpl>();
std::shared_ptr<WifiHotspotStub> pWifiHotspotStub = std::make_shared<WifiHotspotServiceImpl>();
sptr<WifiP2pStub> pWifiP2pStub = WifiP2pServiceImpl::GetInstance();
std::shared_ptr<WifiScanStub> pWifiScanStub = std::make_shared<WifiScanServiceImpl>();

bool OnSetScanOnlyAvailableTest(const uint8_t* data, size_t size)
{
    uint32_t code = static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_SET_WIFI_SCAN_ONLY);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_SCAN);
    datas.WriteInt32(0);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiScanStub->OnRemoteRequest(code, datas, reply, option);
    return true;
}

bool OnGetScanOnlyAvailableTest(const uint8_t* data, size_t size)
{
    uint32_t code = static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_GET_WIFI_SCAN_ONLY);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_SCAN);
    datas.WriteInt32(0);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiScanStub->OnRemoteRequest(code, datas, reply, option);
    return true;
}

void OnEnableWifiApTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_HOSPOT);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    MessageParcel reply;
    MessageOption option;
    pWifiHotspotStub->OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI_AP),
        datas, reply, option);
}

void OnDisableWifiApTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_HOSPOT);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    MessageParcel reply;
    MessageOption option;
    pWifiHotspotStub->OnRemoteRequest(static_cast<uint32_t>(HotspotInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI_AP),
        datas, reply, option);
}

bool OnFactoryResetFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_SET_FACTORY_RESET),
        datas, reply, option);
    return true;
}

bool OnEnableWifiFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI),
        datas, reply, option);
    return true;
}

bool OnDisableWifiFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_WIFI),
        datas, reply, option);
    return true;
}

bool OnGetSupportedFeaturesFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES),
        datas, reply, option);
    return true;
}

bool OnSetCountryCodeFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_DEVICE);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_SET_COUNTRY_CODE),
        datas, reply, option);
    return true;
}

void DoSomethingInterestingWithMyAPIS(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiP2pStub->OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_ENABLE),
        datas, reply, option);
}

void DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    LOGI("enablep2p_fuzzer enter");
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiP2pStub->OnRemoteRequest(static_cast<uint32_t>(P2PInterfaceCode::WIFI_SVR_CMD_P2P_DISABLE),
        datas, reply, option);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    OHOS::Wifi::OnSetScanOnlyAvailableTest(data, size);
    OHOS::Wifi::OnGetScanOnlyAvailableTest(data, size);
    OHOS::Wifi::OnEnableWifiApTest(data, size);
    OHOS::Wifi::OnDisableWifiApTest(data, size);
    OHOS::Wifi::OnFactoryResetFuzzTest(data, size);
    OHOS::Wifi::OnEnableWifiFuzzTest(data, size);
    OHOS::Wifi::OnDisableWifiFuzzTest(data, size);
    OHOS::Wifi::OnGetSupportedFeaturesFuzzTest(data, size);
    OHOS::Wifi::OnSetCountryCodeFuzzTest(data, size);
    OHOS::Wifi::OnSetScanOnlyAvailableTest(data, size);
    OHOS::Wifi::OnSetScanOnlyAvailableTest(data, size);
    OHOS::Wifi::OnSetScanOnlyAvailableTest(data, size);
    OHOS::Wifi::OnSetScanOnlyAvailableTest(data, size);
    OHOS::Wifi::DoSomethingInterestingWithMyAPIS(data, size);
    OHOS::Wifi::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
}
}
