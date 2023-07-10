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

#include "wifi_device_stub.h"
#include "message_parcel.h"
#include "securec.h"
#include "define.h"
#include "wifi_manager_service_ipc_interface_code.h"
#include "wifi_log.h"

namespace OHOS {
namespace Wifi {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MAP_DEVICE_NUMS = 50;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiDeviceService";

class WifiDeviceStubFuzzTest : public WifiDeviceStub {
public:
    WifiDeviceStubFuzzTest() = default;
    virtual ~WifiDeviceStubFuzzTest() = default;

    ErrCode EnableWifi() override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode DisableWifi() override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode InitWifiProtect(const WifiProtectType &protectType, const std::string &protectName) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode GetWifiProtectRef(const WifiProtectMode &protectMode, const std::string &protectName) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode PutWifiProtectRef(const std::string &protectName) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode RemoveCandidateConfig(int networkId) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode RemoveCandidateConfig(const WifiDeviceConfig &config) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode AddDeviceConfig(const WifiDeviceConfig &config, int &result, bool isCandidate) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode UpdateDeviceConfig(const WifiDeviceConfig &config, int &result) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode RemoveDevice(int networkId) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode RemoveAllDevice() override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode GetDeviceConfigs(std::vector<WifiDeviceConfig> &result, bool isCandidate) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode EnableDeviceConfig(int networkId, bool attemptEnable) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode DisableDeviceConfig(int networkId) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode ConnectToNetwork(int networkId, bool isCandidate) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode ConnectToDevice(const WifiDeviceConfig &config) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode IsConnected(bool &isConnected) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode ReConnect() override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode ReAssociate(void) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode Disconnect(void) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode StartWps(const WpsConfig &config) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode CancelWps(void) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode IsWifiActive(bool &bActive) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode GetWifiState(int &state) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode GetLinkedInfo(WifiLinkedInfo &info) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode GetDisconnectedReason(DisconnectedReason &reason) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode GetIpInfo(IpInfo &info) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode SetCountryCode(const std::string &countryCode) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode GetCountryCode(std::string &countryCode) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode RegisterCallBack(const sptr<IWifiDeviceCallBack> &callback, const std::vector<std::string> &event) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode GetSignalLevel(const int &rssi, const int &band, int &level) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode GetSupportedFeatures(long &features) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode GetDeviceMacAddress(std::string &result) override
    {
        return WIFI_OPT_SUCCESS;
    }
    bool SetLowLatencyMode(bool enabled) override
    {
        return WIFI_OPT_SUCCESS;
    }
    bool IsRemoteDied(void) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode IsBandTypeSupported(int bandType, bool &supported) override
    {
        return WIFI_OPT_SUCCESS;
    }
    ErrCode Get5GHzChannelList(std::vector<int> &result) override
    {
        return WIFI_OPT_SUCCESS;
    }
};

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    uint32_t code = U32_AT(data) % MAP_DEVICE_NUMS + static_cast<uint32_t>(DevInterfaceCode::WIFI_SVR_CMD_ENABLE_WIFI);
    LOGI("wifidevicestub_fuzzer code(0x%{public}x)", code); // code[0x1001,0x1031]
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<WifiDeviceStub> pWifiDeviceStub = std::make_shared<WifiDeviceStubFuzzTest>();
    pWifiDeviceStub->OnRemoteRequest(code, datas, reply, option);
    return true;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::Wifi::U32_AT_SIZE) {
        return 0;
    }

    /* Validate the length of size */
    if (size == 0 || size > OHOS::Wifi::FOO_MAX_LEN) {
        return 0;
    }

    OHOS::Wifi::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
}
}
