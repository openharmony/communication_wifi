/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "securec.h"
#include "wifichid2d_fuzzer.h"
#include "c_adapter/inc/wifi_c_utils.h"
#include "kits/c/wifi_hid2d.h"
#include <fuzzer/FuzzedDataProvider.h>

namespace OHOS {
namespace Wifi {
    bool WifiCHid2dFuzzerTest(const uint8_t* data, size_t size)
    {
        Hid2dRequestGcIpTest(data, size);
        Hid2dSharedlinkIncreaseTest();
        Hid2dSharedlinkDecreaseTest();
        Hid2dIsWideBandwidthSupportedTest();
        Hid2dCreateGroupTest(data, size);
        Hid2dRemoveGcGroupTest(data, size);
        Hid2dConnectTest(data, size);
        Hid2dConfigIPAddrTest(data, size);
        Hid2dReleaseIPAddrTest(data, size);
        Hid2dGetRecommendChannelTest(data, size);
        Hid2dGetSelfWifiCfgInfoTest(data, size);
        Hid2dSetUpperSceneTest(data, size);
        return true;
    }
}  // namespace Wifi
}  // namespace OHOS

void Hid2dRequestGcIpTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);

    std::vector<uint8_t> gcMac = FDP.ConsumeBytes<uint8_t>(MACLEN);
    if (gcMac.size() != MACLEN) {
        return;
    }
    
    std::vector<uint32_t> ipAddr;
    for (size_t i = 0; i < IPLEN; i++) {
        ipAddr.push_back(FDP.ConsumeIntegral<uint32_t>());
    }
    
    (void)Hid2dRequestGcIp(gcMac.data(), ipAddr.data());
}

void Hid2dSharedlinkIncreaseTest(void)
{
    (void)Hid2dSharedlinkIncrease();
}

void Hid2dSharedlinkDecreaseTest(void)
{
    (void)Hid2dSharedlinkDecrease();
}

void Hid2dIsWideBandwidthSupportedTest(void)
{
    (void)Hid2dIsWideBandwidthSupported();
}

void Hid2dCreateGroupTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    int frequency = 0;
    FreqType type = FREQUENCY_DEFAULT;
    if (size > 0) {
        frequency = FDP.ConsumeIntegral<int>();
    }
    (void)Hid2dCreateGroup(frequency, type);
}

void Hid2dRemoveGcGroupTest(const uint8_t* data, size_t size)
{
    char gcIfName[IF_NAME_LEN] = {0};
    if (size >= IF_NAME_LEN) {
        if (memcpy_s(gcIfName, IF_NAME_LEN, data, IF_NAME_LEN - 1) != EOK) {
            return;
        }
    }
    (void)Hid2dRemoveGcGroup(gcIfName);
}

void Hid2dConnectTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    Hid2dConnectConfig cppConfig;
    if (size >= sizeof(Hid2dConnectConfig)) {
        if (memcpy_s(cppConfig.ssid, MAX_SSID_LEN, data, MAX_SSID_LEN - 1) != EOK) {
            return;
        }

        if (memcpy_s(cppConfig.bssid, MAC_LEN, data, MAC_LEN) != EOK) {
            return;
        }

        if (memcpy_s(cppConfig.preSharedKey, MAX_KEY_LEN, data, MAX_KEY_LEN - 1) != EOK) {
            return;
        }
        cppConfig.frequency = FDP.ConsumeIntegral<int>();
    }
    (void)Hid2dConnect(&cppConfig);
}

void Hid2dConfigIPAddrTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    char ifName[IF_NAME_LEN] = {0};
    IpAddrInfo ipAddrInfo;
    if (size >= IF_NAME_LEN) {
        if (memcpy_s(ifName, IF_NAME_LEN, data, IF_NAME_LEN - 1) != EOK) {
            return;
        }
    }

    if (size >= sizeof(IpAddrInfo)) {
        for (int i = 0; i < IPV4_ARRAY_LEN; i++) {
            ipAddrInfo.ip[i] = FDP.ConsumeIntegral<int>();
            ipAddrInfo.gateway[i] = FDP.ConsumeIntegral<int>();
            ipAddrInfo.netmask[i] = FDP.ConsumeIntegral<int>();
        }
    }
    (void)Hid2dConfigIPAddr(ifName, &ipAddrInfo);
}

void Hid2dReleaseIPAddrTest(const uint8_t* data, size_t size)
{
    char ifName[IF_NAME_LEN] = {0};
    if (size >= IF_NAME_LEN) {
        if (memcpy_s(ifName, IF_NAME_LEN, data, IF_NAME_LEN - 1) != EOK) {
            return;
        }
    }
    (void)Hid2dReleaseIPAddr(ifName);
}

void Hid2dGetRecommendChannelTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    RecommendChannelRequest request;
    RecommendChannelResponse response;
    int index = 0;

    if (size >= sizeof(RecommendChannelRequest)) {
        request.remoteIfMode = FDP.ConsumeIntegral<int>();
        request.localIfMode = FDP.ConsumeIntegral<int>();
        request.prefBand = FDP.ConsumeIntegral<int>();

        if (memcpy_s(request.remoteIfName, IF_NAME_LEN, data, IF_NAME_LEN - 1) != EOK) {
            return;
        }

        if (memcpy_s(request.localIfName, IF_NAME_LEN, data + IF_NAME_LEN, IF_NAME_LEN - 1) != EOK) {
            return;
        }
    }
    index = 0;
    if (size >= sizeof(RecommendChannelResponse)) {
        response.index = FDP.ConsumeIntegral<int>();
        response.centerFreq = FDP.ConsumeIntegral<int>();
        response.centerFreq1 = FDP.ConsumeIntegral<int>();
        response.centerFreq2 = FDP.ConsumeIntegral<int>();
        response.bandwidth = FDP.ConsumeIntegral<int>();
    }
    (void)Hid2dGetRecommendChannel(&request, &response);
}

void Hid2dGetSelfWifiCfgInfoTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    int getDatValidLen = 0;
    char cfgData[DATA_MAX_BYTES] = {0};
    SelfCfgType cfgType = TYPE_OF_GET_SELF_CONFIG;
    if (size >= DATA_MAX_BYTES) {
        getDatValidLen = FDP.ConsumeIntegral<int>();
        if (memcpy_s(cfgData, DATA_MAX_BYTES, data, DATA_MAX_BYTES - 1) != EOK) {
            return;
        }
    }
    (void)Hid2dGetSelfWifiCfgInfo(cfgType, cfgData, &getDatValidLen);
}

void Hid2dSetPeerWifiCfgInfoTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    int setDataValidLen = FDP.ConsumeIntegral<int>();
    char cfgData[DATA_MAX_BYTES] = {0};
    PeerCfgType cfgType = TYPE_OF_SET_PEER_CONFIG;
    if (size >= DATA_MAX_BYTES) {
        if (memcpy_s(cfgData, DATA_MAX_BYTES, data, DATA_MAX_BYTES -1) != EOK) {
            return;
        }
    }
    (void)Hid2dSetPeerWifiCfgInfo(cfgType, cfgData, setDataValidLen);
}

void Hid2dSetUpperSceneTest(const uint8_t* data, size_t size)
{
    FuzzedDataProvider FDP(data, size);
    char ifName[IF_NAME_LEN] = {0};
    Hid2dUpperScene scene;

    if (size >= IF_NAME_LEN) {
        if (memcpy_s(ifName, IF_NAME_LEN, data, IF_NAME_LEN - 1) != EOK) {
            return;
        }
    }

    if (size >= sizeof(Hid2dUpperScene)) {
        if (memcpy_s(scene.mac, MAC_LEN, data, MAC_LEN) != EOK) {
            return;
        }
        scene.scene = FDP.ConsumeIntegral<unsigned int>();
        scene.fps = FDP.ConsumeIntegral<int>();
        scene.bw = FDP.ConsumeIntegral<unsigned int>();
    }
    (void)Hid2dSetUpperScene(ifName, &scene);
}

void Hid2dSetGroupType(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    GroupLiveType type = GROUPKEEPALIVE;
    (void)Hid2dSetGroupType(type);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Wifi::WifiCHid2dFuzzerTest(data, size);
    return 0;
}

