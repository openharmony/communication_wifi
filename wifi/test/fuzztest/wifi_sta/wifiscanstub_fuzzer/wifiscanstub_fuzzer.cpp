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

namespace OHOS {
namespace Wifi {
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr size_t MAP_SCAN_NUMS = 31;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiScan";
const std::u16string FORMMGR_INTERFACE_TOKEN_EX = u"ohos.wifi.IWifiScanMgr";
sptr<WifiScanMgrStub> pWifiScanMgrStub = WifiScanMgrServiceImpl::GetInstance();
std::shared_ptr<WifiScanStub> pWifiScanStub = std::make_shared<WifiScanServiceImpl>();

bool DoSomethingInterestingWithMyAPIEx(const uint8_t* data, size_t size)
{
    uint32_t code = static_cast<uint32_t>(ScanInterfaceCode::WIFI_MGR_GET_SCAN_SERVICE);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN_EX);
    datas.WriteInt32(0);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiScanMgrStub->OnRemoteRequest(code, datas, reply, option);
    return true;
}

void OnGetSupportedFeaturesTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiScanStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES),
        datas, reply, option);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    uint32_t code = U32_AT(data) % MAP_SCAN_NUMS + static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_FULL_SCAN);
    LOGI("wifiscanstub_fuzzer code(0x%{public}x) size(%{public}zu)", code, size); // code[0x1004, 0x101E]
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiScanStub->OnRemoteRequest(code, datas, reply, option);
    OnGetSupportedFeaturesTest(data, size);
    return true;
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
