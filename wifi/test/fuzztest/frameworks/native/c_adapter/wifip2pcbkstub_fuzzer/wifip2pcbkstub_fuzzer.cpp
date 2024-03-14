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

#include "wifip2pcbkstub_fuzzer.h"
#include "wifi_fuzz_common_func.h"
#include "wifi_p2p_callback_stub.h"

#include <cstddef>
#include <cstdint>

#include "message_parcel.h"
#include "securec.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"

namespace OHOS {
namespace Wifi {
constexpr size_t U32_AT_SIZE_ZERO = 4;
constexpr size_t MAP_SCAN_NUMS = 10;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiDeviceCallBack";
std::shared_ptr<WifiP2pCallbackStub> pWifiP2pCallStub = std::make_shared<WifiP2pCallbackStub>();

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    uint32_t code = U32_AT(data) % MAP_SCAN_NUMS + static_cast<uint32_t>
    (P2PInterfaceCode::WIFI_CBK_CMD_P2P_STATE_CHANGE);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    pWifiP2pCallStub->OnRemoteRequest(code, datas, reply, option);
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size <= OHOS::Wifi::U32_AT_SIZE_ZERO)) {
        return 0;
    }
    OHOS::Wifi::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
}
}
