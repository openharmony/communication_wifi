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

namespace OHOS {
namespace Wifi {
constexpr size_t U32_AT_SIZE_ZERO = 4;
static bool g_isInsted = false;
static std::mutex g_instanceLock;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiDeviceService";
static sptr<WifiDeviceMgrServiceImpl> pWifiDeviceMgrServiceImpl = nullptr;
static sptr<WifiDeviceServiceImpl> pWifiDeviceServiceImpl = nullptr;

bool Init ()
{
    if (!g_isInsted) {
        pWifiDeviceMgrServiceImpl = WifiDeviceMgrServiceImpl::GetInstance();
        if(!pWifiDeviceMgrServiceImpl) {
            LOGE("Init failed pWifiDeviceMgrServiceImpl is nullptr!");
            return false;
        }
        pWifiDeviceMgrServiceImpl->OnStart();
        sptr<IRemoteObject> remote = pWifiDeviceMgrServiceImpl->GetWifiRemote(0);
        if (!remote) {
            LOGE("Init failed remote is nullptr!");
            return false;
        }
        pWifiDeviceServiceImpl = iface_cast<WifiDeviceServiceImpl>(remote);
        if (!pWifiDeviceServiceImpl) {
            LOGE("Init failed pWifiDeviceServiceImpl is nullptr!");
            return false;
        }
        if (WifiConfigCenter::GetInstance().GetWifiMidState(0) != WifiOprMidState::RUNNING) {
            LOGE("Init setmidstate!");
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
        if (!init()) {
            LOGE("OnRemoteRequest Init failed!");
            return false;
        }
    }
    MessageParcel reply;
    MessageOption option;
    pWifiDeviceServiceImpl->OnRemoteRequest(code, data, reply, option);
}


bool OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

bool OnGetWifiProtectRef(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_WIFI_PROTECT), datas);
}

bool OnPutWifiProtectRef(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_PUT_WIFI_PROTECT), datas);
}

bool OnIsHeldWifiProtectRef(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_IS_HELD_WIFI_PROTECT), datas);
}

bool OnAddDeviceConfig(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ADD_DEVICE_CONFIG), datas);
}

bool OnUpdateDeviceConfig(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_UPDATE_DEVICE_CONFIG), datas);
}

bool OnRemoveDevice(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_DEVICE_CONFIG), datas);
}

bool OnRemoveAllDevice(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_REMOVE_ALL_DEVICE_CONFIG), datas);
}

bool OnGetDeviceConfigs(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_DEVICE_CONFIGS), datas);
}

bool OnEnableDeviceConfig(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_DEVICE), datas);
}

bool OnDisableDeviceConfig(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_DISABLE_DEVICE), datas);
}

bool OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

bool OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

bool OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

bool OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

bool OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

bool OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

bool OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

bool OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

bool OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

bool OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

bool OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

bool OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

bool OnInitWifiProtectFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        rerurn false;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_INIT_WIFI_PROTECT), datas);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    sleep(1);
    OHOS::Wifi::DoSomethingInterestingWithMyAPI(data, size);
    OHOS::Wifi::DoSomethingInterestingWithMyAPIEx(data, size);
    return 0;
}
}
}