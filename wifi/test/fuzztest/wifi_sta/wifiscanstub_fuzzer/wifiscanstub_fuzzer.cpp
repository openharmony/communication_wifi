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

#include "wifiscanstub_fuzzer.h"
#include "wifi_fuzz_common_func.h"

#include <cstddef>
#include <cstdint>
#include <unistd.h>
#include "wifi_scan_stub.h"
#include "wifi_scan_mgr_stub.h"
#include "message_parcel.h"
#include "securec.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_scan_service_impl.h"
#include "wifi_scan_mgr_service_impl.h"
#include "wifi_log.h"
#include <mutex>
#include "wifi_config_center.h"
#include "wifi_settings.h"
#include "wifi_common_def.h"

namespace OHOS {
namespace Wifi {
constexpr size_t U32_AT_SIZE_ZERO = 4;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiScan";
static bool g_isInsted = false;
static std::mutex g_instanceLock;
static sptr<WifiScanMgrServiceImpl> pWifiScanMgrServiceImpl = nullptr;
static sptr<WifiScanServiceImpl> pWifiScanServiceImpl = nullptr;

bool Init()
{
    if (!g_isInsted) {
        pWifiScanMgrServiceImpl = WifiScanMgrServiceImpl::GetInstance();
        if (!pWifiScanMgrServiceImpl) {
            LOGE("Init failed pWifiScanMgrServiceImpl is nullptr!");
            return false;
        }
        pWifiScanMgrServiceImpl->OnStart();
        sptr<IRemoteObject> remote = pWifiScanMgrServiceImpl->GetWifiRemote(0);
        if (!remote) {
            LOGE("Init failed remote is nullptr!");
            return false;
        }
        pWifiScanServiceImpl = iface_cast<WifiScanServiceImpl>(remote);
        if (!pWifiScanServiceImpl) {
            LOGE("Init failed pWifiScanServiceImpl is nullptr!");
            return false;
        }
        if (WifiConfigCenter::GetInstance().GetScanMidState(0) != WifiOprMidState::RUNNING) {
            LOGE("Init setmidstate!");
            WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::RUNNING, 0);
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
    int32_t ret = pWifiScanServiceImpl->OnRemoteRequest(code, data, reply, option);
    return ret;
}

void OnSetScanControlInfoFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_SET_SCAN_CONTROL_INFO), datas);
}

void OnScanByParamsFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_SPECIFIED_PARAMS_SCAN), datas);
}

void OnIsWifiClosedScanFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_IS_SCAN_ALWAYS_ACTIVE), datas);
}

void OnGetScanInfoListFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_GET_SCAN_INFO_LIST), datas);
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
    OnRemoteRequest(static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_REGISTER_SCAN_CALLBACK), datas);
}

void OnStartWifiPnoScanFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_START_PNO_SCAN), datas);
}

void OnScanFuzzTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN)) {
        LOGE("WriteInterfaceToken failed!");
        return;
    }
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    OnRemoteRequest(static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_FULL_SCAN), datas);
}


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    OHOS::Wifi::OnSetScanControlInfoFuzzTest(data, size);
    OHOS::Wifi::OnScanFuzzTest(data, size);
    OHOS::Wifi::OnScanByParamsFuzzTest(data, size);
    OHOS::Wifi::OnIsWifiClosedScanFuzzTest(data, size);
    OHOS::Wifi::OnGetScanInfoListFuzzTest(data, size);
    OHOS::Wifi::OnRegisterCallBackFuzzTest(data, size);
    OHOS::Wifi::OnStartWifiPnoScanFuzzTest(data, size);
    return 0;
}
}
}
