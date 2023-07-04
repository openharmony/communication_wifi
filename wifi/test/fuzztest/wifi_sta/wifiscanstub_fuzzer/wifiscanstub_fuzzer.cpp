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

#include <cstddef>
#include <cstdint>

#include "wifi_scan_stub.h"
#include "message_parcel.h"
#include "securec.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_log.h"

namespace OHOS {
namespace Wifi {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_ZERO_SIZE = 0;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiScan";

class WifiScanStubTest : public WifiScanStub {
public:
    WifiScanStubTest() = default;
    virtual ~WifiScanStubTest() = default;

    ErrCode SetScanControlInfo(const ScanControlInfo &info) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode Scan() override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode AdvanceScan(const WifiScanParams &params) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode IsWifiClosedScan(bool &bOpen) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode GetScanInfoList(std::vector<WifiScanInfo> &result) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode RegisterCallBack(const sptr<IWifiScanCallback> &callback, const std::vector<std::string> &event) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode GetSupportedFeatures(long &features) override
    {
        return WIFI_OPT_SUCCESS;
    }
    bool IsRemoteDied(void) override
    {
        return WIFI_OPT_SUCCESS;
    }
};

std::shared_ptr<WifiScanStub> pWifiScanStub = std::make_shared<WifiScanStubTest>();
void RemoteRequestSetScanControlInfo(const char* data, size_t size) // 1 WIFI_SVR_CMD_SET_SCAN_CONTROL_INFO
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    int result = pWifiScanStub->OnRemoteRequest(
        static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_SET_SCAN_CONTROL_INFO), datas, reply, option);
    LOGI("wifiscanstub_fuzzer OnRemoteRequest(0x%{public}x %{public}d)",
        static_cast<int32_t>(ScanInterfaceCode::WIFI_SVR_CMD_SET_SCAN_CONTROL_INFO), result);
}

void RemoteRequestFullScan(const char* data, size_t size) // 2 WIFI_SVR_CMD_FULL_SCAN
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    int result = pWifiScanStub->OnRemoteRequest(
        static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_FULL_SCAN), datas, reply, option);
    LOGI("wifiscanstub_fuzzer OnRemoteRequest(0x%{public}x %{public}d)",
        static_cast<int32_t>(ScanInterfaceCode::WIFI_SVR_CMD_FULL_SCAN), result);
}

void RemoteRequestSpecifiedParamsScan(const char* data, size_t size) // 3 WIFI_SVR_CMD_SPECIFIED_PARAMS_SCAN
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    int result = pWifiScanStub->OnRemoteRequest(
        static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_SPECIFIED_PARAMS_SCAN), datas, reply, option);
    LOGI("wifiscanstub_fuzzer OnRemoteRequest(0x%{public}x %{public}d)",
        static_cast<int32_t>(ScanInterfaceCode::WIFI_SVR_CMD_SPECIFIED_PARAMS_SCAN), result);
}

void RemoteRequestIsScanAlwaysActive(const char* data, size_t size) // 4 WIFI_SVR_CMD_IS_SCAN_ALWAYS_ACTIVE
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    int result = pWifiScanStub->OnRemoteRequest(
        static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_IS_SCAN_ALWAYS_ACTIVE), datas, reply, option);
    LOGI("wifiscanstub_fuzzer OnRemoteRequest(0x%{public}x %{public}d)",
        static_cast<int32_t>(ScanInterfaceCode::WIFI_SVR_CMD_IS_SCAN_ALWAYS_ACTIVE), result);
}

void RemoteRequestGetScanInfoList(const char* data, size_t size) // 5 WIFI_SVR_CMD_GET_SCAN_INFO_LIST
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    int result = pWifiScanStub->OnRemoteRequest(
        static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_GET_SCAN_INFO_LIST), datas, reply, option);
    LOGI("wifiscanstub_fuzzer OnRemoteRequest(0x%{public}x %{public}d)",
        static_cast<int32_t>(ScanInterfaceCode::WIFI_SVR_CMD_GET_SCAN_INFO_LIST), result);
}

void RemoteRequestRegisterCallBack(const char* data, size_t size) // 6 WIFI_SVR_CMD_REGISTER_SCAN_CALLBACK
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    int result = pWifiScanStub->OnRemoteRequest(
        static_cast<uint32_t>(ScanInterfaceCode::WIFI_SVR_CMD_REGISTER_SCAN_CALLBACK), datas, reply, option);
    LOGI("wifiscanstub_fuzzer OnRemoteRequest(0x%{public}x %{public}d)",
        static_cast<int32_t>(ScanInterfaceCode::WIFI_SVR_CMD_REGISTER_SCAN_CALLBACK), result);
}

void RemoteRequestGetSupportedFeatures(const char* data, size_t size) // 7 WIFI_SVR_CMD_GET_SUPPORTED_FEATURES
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    int result =
        pWifiScanStub->OnRemoteRequest(static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES),
        datas, reply, option);
    LOGI("wifiscanstub_fuzzer OnRemoteRequest(0x%{public}x %{public}d)",
        static_cast<int32_t>(DevInterfaceCode::WIFI_SVR_CMD_GET_SUPPORTED_FEATURES), result);
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    RemoteRequestSetScanControlInfo(data, size);
    RemoteRequestFullScan(data, size);
    RemoteRequestSpecifiedParamsScan(data, size);
    RemoteRequestIsScanAlwaysActive(data, size);
    RemoteRequestGetScanInfoList(data, size);
    RemoteRequestRegisterCallBack(data, size);
    RemoteRequestGetSupportedFeatures(data, size);
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        LOGE("LLVMFuzzerTestOneInput data is null, size:%{public}zu", size);
        return 0;
    }

    if (size <= U32_ZERO_SIZE || size > OHOS::Wifi::FOO_MAX_LEN) {
        LOGE("LLVMFuzzerTestOneInput size invalid parameter, size:%{public}zu", size);
        return 0;
    }
    OHOS::Wifi::DoSomethingInterestingWithMyAPI((const char*)data, size);
    return 0;
}
}
}
