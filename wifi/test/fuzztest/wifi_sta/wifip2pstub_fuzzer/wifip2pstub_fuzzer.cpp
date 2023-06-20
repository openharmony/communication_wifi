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

#include "wifip2pstub_fuzzer.h"
#include "wifi_fuzz_common_func.h"

#include <cstddef>
#include <cstdint>

#include "wifi_p2p_stub.h"
#include "message_parcel.h"
#include "securec.h"
#include "define.h"

namespace OHOS {
namespace Wifi {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MAP_P2P_NUMS = 41;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.wifi.IWifiP2pService";

class WifiP2pStubFuzzTest : public WifiP2pStub {
public:
    WifiP2pStubTest() = default;
    virtual ~WifiP2pStubTest() = default;
    ErrCode MonitorCfgChange() override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode EnableP2p() override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode DisableP2p() override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode DiscoverDevices() override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode StopDiscoverDevices() override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode DiscoverServices() override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode StopDiscoverServices() override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode RequestService(const WifiP2pDevice &device, const WifiP2pServiceRequest &request) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode PutLocalP2pService(const WifiP2pServiceInfo &srvInfo) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode DeleteLocalP2pService(const WifiP2pServiceInfo &srvInfo) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode StartP2pListen(int period, int interval) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode StopP2pListen() override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode CreateGroup(const WifiP2pConfig &config) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode RemoveGroup() override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode DeleteGroup(const WifiP2pGroupInfo &group) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode P2pConnect(const WifiP2pConfig &config) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode P2pCancelConnect() override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode QueryP2pLinkedInfo(WifiP2pLinkedInfo& linkedInfo) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode GetCurrentGroup(WifiP2pGroupInfo &group) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode GetP2pEnableStatus(int &status) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode GetP2pDiscoverStatus(int &status) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode GetP2pConnectedStatus(int &status) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode QueryP2pDevices(std::vector<WifiP2pDevice> &devices) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode QueryP2pLocalDevice(WifiP2pDevice &device) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode QueryP2pGroups(std::vector<WifiP2pGroupInfo> &groups) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode QueryP2pServices(std::vector<WifiP2pServiceInfo> &services) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode RegisterCallBack(const sptr<IWifiP2pCallback> &callback, const std::vector<std::string> &event) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode GetSupportedFeatures(long &features) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode SetP2pDeviceName(const std::string &deviceName) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode SetP2pWfdInfo(const WifiP2pWfdInfo &wfdInfo) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode Hid2dRequestGcIp(const std::string& gcMac, std::string& ipAddr) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode Hid2dSharedlinkIncrease() override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode Hid2dSharedlinkDecrease() override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode Hid2dCreateGroup(const int frequency, FreqType type) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode Hid2dConnect(const Hid2dConnectConfig& config) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode Hid2dConfigIPAddr(const std::string& ifName, const IpAddrInfo& ipInfo) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode Hid2dReleaseIPAddr(const std::string& ifName) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode Hid2dGetRecommendChannel(const RecommendChannelRequest& request,
        RecommendChannelResponse& response) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode Hid2dRemoveGcGroup(const std::string& gcIfName) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode Hid2dGetChannelListFor5G(std::vector<int>& vecChannelList) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode  Hid2dGetSelfWifiCfgInfo(SelfCfgType cfgType,
        char cfgData[CFG_DATA_MAX_BYTES], int* getDatValidLen) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode Hid2dSetPeerWifiCfgInfo(PeerCfgType cfgType,
        char cfgData[CFG_DATA_MAX_BYTES], int setDataValidLen) override
    {
        return WIFI_OPT_SUCCESS;
    }

    ErrCode Hid2dSetUpperScene(const std::string& ifName, const Hid2dUpperScene& scene) override
    {
        return WIFI_OPT_SUCCESS;
    }

    bool IsRemoteDied() override
    {
        return WIFI_OPT_SUCCESS;
    }
};

void OnGetSupportedFeaturesTest(const uint8_t* data, size_t size)
{
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<WifiP2pStub> pWifiP2pStub = std::make_shared<WifiP2pStubFuzzTest>();
    pWifiP2pStub->OnRemoteRequest(WIFI_SVR_CMD_GET_SUPPORTED_FEATURES, datas, reply, option);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    uint32_t code = U32_AT(data) % MAP_P2P_NUMS + WIFI_SVR_CMD_P2P_ENABLE;
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<WifiP2pStub> pWifiP2pStub = std::make_shared<WifiP2pStubFuzzTest>();
    OnGetSupportedFeaturesTest(data, size);
    pWifiP2pStub->OnRemoteRequest(code, datas, reply, option);
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
