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

#include "wifichid2d_fuzzer.h"
#include "wifi_device.h"
#include "../../../../interfaces/kits/c/wifi_hid2d.h"
#include "securec.h"

namespace OHOS {
namespace Wifi {
    bool WifiCHid2dFuzzerTest(const uint8_t* data, size_t size)
    {
        Hid2dRequestGcIpTest(data, size);
        /*
        Hid2dSharedlinkIncreaseTest();
        Hid2dSharedlinkDecreaseTest();
        Hid2dCreateGroupTest(data, size);
        Hid2dRemoveGcGroupTest(data, size);
        Hid2dConnectTest(data, size);
        Hid2dConfigIPAddrTest(data, size);
        Hid2dReleaseIPAddrTest(data, size);
        Hid2dGetRecommendChannelTest(data, size);
        Hid2dGetChannelListFor5GTest(data, size);
        Hid2dGetSelfWifiCfgInfoTest(data, size);
        Hid2dSetPeerWifiCfgInfoTest(data, size);
        Hid2dIsWideBandwidthSupportedTest();
        Hid2dSetUpperSceneTest(data, size);
        */
        return true;
    }

/*
    void Hid2dSharedlinkIncreaseTest(void)
    {
        (void)Hid2dSharedlinkIncrease();
    }

    void Hid2dSharedlinkDecreaseTest(void)
    {
        (void)Hid2dSharedlinkDecreaseTest();
    }

    void Hid2dCreateGroupTest(const uint8_t* data, size_t size)
    {
        unsigned int index = 0;
        WifiErrorCode Hid2dCreateGroup(const int frequency, FreqType type)
        int frequency = static_cast<int> (data[index++]);
        FreqType type = FREQUENCY_DEFAULT;
        if (data[index++] > VALUE) {
            type = FREQUENCY_160M;
        }
        (void)Hid2dCreateGroup(frequency, type);
    }

    void Hid2dRemoveGcGroupTest(const uint8_t* data, size_t size)
    {
        char gcIfName[NAMELEN] = {0};
        if (size >= NAMELEN) {
            if (memcpy_s(gcIfName, NAMELEN, data, NAMELEN) != EOK) {
                gcIfName[MACLEN] = {0};
            }
        }
        (void)Hid2dRemoveGcGroup(gcIfName);
    }

    void Hid2dConnectTest(const uint8_t* data, size_t size)
    {
        string ssid = std::string(reinterpret_cast<const char*>(data), size);
        string bssid = std::string(reinterpret_cast<const char*>(data), size);
        string preSharedKey = std::string(reinterpret_cast<const char*>(data), size);

        OHOS::Wifi::Hid2dConnectConfig* cppConfig;
        cppConfig->SetSsid(ssid);
        cppConfig->SetBssid(bssid);
        cppConfig->SetPreSharedKey(preSharedKey);
        (void)Hid2dConnect(cppConfig);
    }

    void Hid2dConfigIPAddrTest(const uint8_t* data, size_t size)
    {
        unsigned int ip[IPV4_ARRAY_LEN];
        unsigned int gateway[IPV4_ARRAY_LEN];
        unsigned int netmask[IPV4_ARRAY_LEN];
        char ifName[NAMELEN] = {0};
        if (memcpy_s(ifName, NAMELEN, data, size) != EOK) {
            ifName[MACLEN] = {0};
        }
        
        OHOS::Wifi::IpAddrInfo* ipAddrInfo;
        ipAddrInfo->ip = OHOS::Wifi::IpArrayToStr(ip);
        ipAddrInfo->gateway = OHOS::Wifi::IpArrayToStr(gateway);
        ipAddrInfo->netmask = OHOS::Wifi::IpArrayToStr(netmask);

        (void)Hid2dConfigIPAddr(ifName, ipAddrInfo);
    }
    
    void Hid2dReleaseIPAddrTest(const uint8_t* data, size_t size)
    {
        char ifName[NAMELEN] = {0};
        if (memcpy_s(ifName, NAMELEN, data, size) != EOK) {
            ifName[MACLEN] = {0};
        }
        (void)Hid2dReleaseIPAddr(ifName);
    }

    void Hid2dGetRecommendChannelTest(const uint8_t* data, size_t size)
    {
        RecommendChannelResponse *request = nullptr;
        RecommendChannelResponse *response = nullptr;
        int index = 0;

        request->index = static_cast<int> (data[index++]);
        request->centerFreq = static_cast<int> (data[index++]);
        request->centerFreq1 = static_cast<int> (data[index++]);
        request->centerFreq2 = static_cast<int> (data[index++]);
        response->index = static_cast<int> (data[index++]);
        response->centerFreq = static_cast<int> (data[index++]);
        response->centerFreq1 = static_cast<int> (data[index++]);
        response->centerFreq2 = static_cast<int> (data[index++]);        

        (void)Hid2dGetRecommendChannel(nullptr, nullptr);
    }

    void Hid2dGetChannelListFor5GTest(const uint8_t* data, size_t size)
    {
        int *chanList = reinterpret_cast<int*>(data);
        (void)Hid2dGetChannelListFor5G(chanList, size);
    }

    void Hid2dGetSelfWifiCfgInfoTest(const uint8_t* data, size_t size)
    {
        int* getDatValidLen = nullptr;
        SelfCfgType cfgType = TYPE_OF_GET_SELF_CONFIG;
        char cfgData[DATA_MAX_BYTES] = {0};

        if (memcpy_s(cfgData, DATA_MAX_BYTES, data, size) != EOK) {
            cfgData[DATA_MAX_BYTES] = {0};
        }
        (void)Hid2dGetSelfWifiCfgInfo(cfgType, cfgData, getDatValidLen)
    }

    void Hid2dSetPeerWifiCfgInfoTest(const uint8_t* data, size_t size)
    {
        PeerCfgType cfgType = TYPE_OF_SET_PEER_CONFIG;
        int setDataValidLen = static_cast<int> (data[0]);
        char cfgData[DATA_MAX_BYTES] = {0};

        if (memcpy_s(cfgData, DATA_MAX_BYTES, data, size) != EOK) {
            cfgData[DATA_MAX_BYTES] = {0};
        }
        
        (void)Hid2dSetPeerWifiCfgInfo(cfgType, cfgData, setDataValidLen);
    }

    void Hid2dIsWideBandwidthSupportedTest(void)
    {
        (void)Hid2dIsWideBandwidthSupported();
    }

    void Hid2dSetUpperSceneTest(const uint8_t* data, size_t size)
    {
        char ifName[NAMELEN] = {0};
        int index = 0;
        Hid2dUpperScene* scene;

        scene->mac = std::string(reinterpret_cast<const char*>(data), size);
        scene->scene = static_cast<unsigned int> (data[index++]);
        scene->fps = static_cast<int> (data[index++]);
        scene->bw = static_cast<unsigned int> (data[index++]);
        if (memcpy_s(ifName, NAMELEN, data, size) != EOK) {
            ifName[MACLEN] = {0};
        }

        (void)Hid2dSetUpperScene(ifName, scene);
    }
*/
}  // namespace Wifi
}  // namespace OHOS
    void Hid2dRequestGcIpTest(const uint8_t* data, size_t size)
    {
        unsigned char gcMac[MACLEN] = {0};
        unsigned int ipAddr[IPLEN] = {0};
        if (size >= MACLEN) {
            if (memcpy_s(gcMac, MACLEN, data, MACLEN) != EOK) {
                gcMac[MACLEN] = {0}
            }

            for (int i = 0; i < IPLEN; i++) {
                ipAddr[i] = static_cast<int> (data[i]);
            }
        }
        (void)Hid2dRequestGcIp(gcMac, ipAddr);
    }
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::Wifi::WifiCHid2dFuzzerTest(data, size);
    return 0;
}

