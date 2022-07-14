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

#include "arp_checker.h"
#include <arpa/inet.h>
#include <chrono>
#include <net/if_arp.h>

#include "securec.h"
#include "wifi_log.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "ohwifi_arp_checker"

namespace OHOS {
namespace Wifi {
constexpr int MAX_LENGTH = 1500;

ArpChecker::ArpChecker(std::string& ifname, std::string& hwAddr, std::string& ipAddr)
{
    uint8_t mac[ETH_ALEN + sizeof(uint32_t)];
    if (sscanf_s(hwAddr.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
        &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != ETH_ALEN) {
        LOGE("invalid hwAddr:%{public}s", hwAddr.c_str());
        if (memset_s(mac, sizeof(mac), 0, sizeof(mac)) != EOK) {
            LOGE("ArpChecker memset fail");
        }
    }
    rawSocket_.CreateSocket(ifname.c_str(), ETH_P_ARP);
    inet_aton(ipAddr.c_str(), &localIpAddr_);
    if (memcpy_s(localHwAddr_, ETH_ALEN, mac, ETH_ALEN) != EOK) {
        LOGE("ArpChecker memcpy fail");
    }
    if (memset_s(l2Broadcast_, ETH_ALEN, 0xFF, ETH_ALEN) != EOK) {
        LOGE("ArpChecker memset fail");
    }
}

ArpChecker::~ArpChecker()
{
    rawSocket_.Close();
}

bool ArpChecker::DoArp(int& timeoutMillis, std::string& targetIp, bool& isFillSenderIp)
{
    struct in_addr destIp;
    struct ArpPacket arpPacket;

    inet_aton(targetIp.c_str(), &destIp);
    arpPacket.ar_hrd = htons(ARPHRD_ETHER);
    arpPacket.ar_pro = htons(ETH_P_IP);
    arpPacket.ar_hln = ETH_ALEN;
    arpPacket.ar_pln = IPV4_ALEN;
    arpPacket.ar_op = htons(ARPOP_REQUEST);
    if (memcpy_s(arpPacket.ar_sha, ETH_ALEN, localHwAddr_, ETH_ALEN) != EOK) {
        LOGE("DoArp memcpy fail");
    }
    if (isFillSenderIp) {
        if (memcpy_s(arpPacket.ar_spa, IPV4_ALEN, &localIpAddr_, sizeof(localIpAddr_)) != EOK) {
            LOGE("DoArp memcpy fail");
        }
    } else {
        if (memset_s(arpPacket.ar_spa, IPV4_ALEN, 0, IPV4_ALEN) != EOK) {
            LOGE("DoArp memset fail");
        }
    }
    if (memset_s(arpPacket.ar_tha, ETH_ALEN, 0, ETH_ALEN) != EOK) {
        LOGE("DoArp memset fail");
    }
    if (memcpy_s(arpPacket.ar_tpa, IPV4_ALEN, &destIp, sizeof(destIp)) != EOK) {
        LOGE("DoArp memcpy fail");
    }

    if (rawSocket_.Send(reinterpret_cast<uint8_t *>(&arpPacket), sizeof(arpPacket), l2Broadcast_) != 0) {
        LOGE("send arp fail");
        return false;
    }

    int readLen = 0;
    uint64_t elapsed = 0;
    int leftMillis = timeoutMillis;
    uint8_t recvBuff[MAX_LENGTH];
    std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
    while (leftMillis > 0) {
        readLen = rawSocket_.Recv(recvBuff, sizeof(recvBuff), leftMillis);
        if (readLen >= static_cast<int>(sizeof(struct ArpPacket))) {
            struct ArpPacket *respPacket = reinterpret_cast<struct ArpPacket*>(recvBuff);
            if (ntohs(respPacket->ar_hrd) == ARPHRD_ETHER &&
                ntohs(respPacket->ar_pro) == ETH_P_IP &&
                respPacket->ar_hln == ETH_ALEN &&
                respPacket->ar_pln == IPV4_ALEN &&
                ntohs(respPacket->ar_op) == ARPOP_REPLY &&
                memcmp(respPacket->ar_sha, localHwAddr_, ETH_ALEN) != 0 &&
                memcmp(respPacket->ar_spa, &destIp, IPV4_ALEN) == 0) {
                LOGE("doArp() return true");
                return true;
            }
        }
        std::chrono::steady_clock::time_point current = std::chrono::steady_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current - startTime).count();
        leftMillis -= static_cast<int>(elapsed);
    }
    LOGE("doArp() return false");
    return false;
}
}
}
