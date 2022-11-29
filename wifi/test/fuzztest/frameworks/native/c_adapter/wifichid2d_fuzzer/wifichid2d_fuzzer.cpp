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
#include "../../../../../../frameworks/native/c_adapter/inc/wifi_c_utils.h"
#include "../../../../../../interfaces/kits/c/wifi_hid2d.h"

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
        Hid2dSetPeerWifiCfgInfoTest(data, size);
        Hid2dSetUpperSceneTest(data, size);
        return true;
    }
}  // namespace Wifi
}  // namespace OHOS

void Hid2dRequestGcIpTest(const uint8_t* data, size_t size)
{
    unsigned char gcMac[MACLEN] = {0};
    unsigned int ipAddr[IPLEN] = {0};
    if (size >= MACLEN) {
        if (memcpy_s(gcMac, MACLEN, data, MACLEN) != EOK) {
            return;
        }

        for (int i = 0; i < IPLEN; i++) {
            ipAddr[i] = static_cast<int>(data[i]);
        }
    }
    (void)Hid2dRequestGcIp(gcMac, ipAddr);
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
    int frequency = 0;
    FreqType type = FREQUENCY_DEFAULT;
    if (size > 0) {
        frequency = static_cast<int>(data[0]);
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
        cppConfig.frequency = static_cast<int>(data[0]);
    }
    (void)Hid2dConnect(&cppConfig);
}

void Hid2dConfigIPAddrTest(const uint8_t* data, size_t size)
{
    char ifName[IF_NAME_LEN] = {0};
    IpAddrInfo ipAddrInfo;
    if (size >= IF_NAME_LEN) {
        if (memcpy_s(ifName, IF_NAME_LEN, data, IF_NAME_LEN - 1) != EOK) {
            return;
        }
    }

    if (size >= sizeof(IpAddrInfo)) {
        int index = 0;
        for (int i = 0; i < IPV4_ARRAY_LEN; i++) {
            ipAddrInfo.ip[i] = static_cast<int>(data[index++]);
            ipAddrInfo.gateway[i] = static_cast<int>(data[index++]);
            ipAddrInfo.netmask[i] = static_cast<int>(data[index++]);
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
    RecommendChannelRequest request;
    RecommendChannelResponse response;
    int index = 0;

    if (size >= sizeof(RecommendChannelRequest)) {
        request.remoteIfMode = static_cast<int>(data[index++]);
        request.localIfMode = static_cast<int>(data[index++]);
        request.prefBand = static_cast<int>(data[index++]);

        if (memcpy_s(request.remoteIfName, IF_NAME_LEN, data, IF_NAME_LEN - 1) != EOK) {
            return;
        }

        if (memcpy_s(request.localIfName, IF_NAME_LEN, data + IF_NAME_LEN, IF_NAME_LEN - 1) != EOK) {
            return;
        }
    }
    index = 0;
    if (size >= sizeof(RecommendChannelResponse)) {
        response.index = static_cast<int>(data[index++]);
        response.centerFreq = static_cast<int>(data[index++]);
        response.centerFreq1 = static_cast<int>(data[index++]);
        response.centerFreq2 = static_cast<int>(data[index++]);
        response.bandwidth = static_cast<int>(data[index++]);
    }
    (void)Hid2dGetRecommendChannel(&request, &response);
}

void Hid2dGetSelfWifiCfgInfoTest(const uint8_t* data, size_t size)
{
    int getDatValidLen = 0;
    char cfgData[DATA_MAX_BYTES] = {0};
    SelfCfgType cfgType = TYPE_OF_GET_SELF_CONFIG;
    if (size >= DATA_MAX_BYTES) {
        getDatValidLen = static_cast<int>(data[0]);
        if (memcpy_s(cfgData, DATA_MAX_BYTES, data, DATA_MAX_BYTES - 1) != EOK) {
            return;
        }
    }
    (void)Hid2dGetSelfWifiCfgInfo(cfgType, cfgData, &getDatValidLen);
}

void Hid2dSetPeerWifiCfgInfoTest(const uint8_t* data, size_t size)
{
    int setDataValidLen = static_cast<int>(data[0]);
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
        int index = 0;
        scene.scene = static_cast<unsigned int>(data[index++]);
        scene.fps = static_cast<int>(data[index++]);
        scene.bw = static_cast<unsigned int>(data[index++]);
    }
    (void)Hid2dSetUpperScene(ifName, &scene);
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Wifi::WifiCHid2dFuzzerTest(data, size);
    return 0;
}

