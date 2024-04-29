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

ArpChecker::ArpChecker()
{
}

ArpChecker::~ArpChecker()
{
    Stop();
}

void ArpChecker::Start(std::string& ifname, std::string& hwAddr, std::string& ipAddr, std::string& gateway)
{
    if (socketCreated) {
        Stop();
    }
    uint8_t mac[ETH_ALEN + sizeof(uint32_t)];
    if (sscanf_s(hwAddr.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
        &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != ETH_ALEN) {
        LOGE("invalid hwAddr:%{private}s", hwAddr.c_str());
        if (memset_s(mac, sizeof(mac), 0, sizeof(mac)) != EOK) {
            LOGE("ArpChecker memset fail");
        }
    }
    if (rawSocket_.CreateSocket(ifname.c_str(), ETH_P_ARP) != 0) {
        LOGE("ArpChecker CreateSocket failed");
        socketCreated = false;
        return;
    }
    inet_aton(ipAddr.c_str(), &localIpAddr);
    if (memcpy_s(localMacAddr, ETH_ALEN, mac, ETH_ALEN) != EOK) {
        LOGE("ArpChecker memcpy fail");
    }
    if (memset_s(l2Broadcast, ETH_ALEN, 0xFF, ETH_ALEN) != EOK) {
        LOGE("ArpChecker memset fail");
    }
    inet_aton(gateway.c_str(), &gatewayIpAddr);
    socketCreated = true;
}

void ArpChecker::Stop()
{
    if (!socketCreated) {
        return;
    }
    rawSocket_.Close();
    socketCreated = false;
}

bool ArpChecker::DoArpCheck(int timeoutMillis, bool isFillSenderIp)
{
    uint64_t timeCost;
    return DoArpCheck(timeoutMillis, isFillSenderIp, timeCost);
}
bool ArpChecker::DoArpCheck(int timeoutMillis, bool isFillSenderIp, uint64_t &timeCost)
{
    LOGI("Enter DoArpCheck");
    if (!socketCreated) {
        LOGE("ArpChecker DoArpCheck failed, socket not created");
        return false;
    }
    struct ArpPacket arpPacket;

    arpPacket.ar_hrd = htons(ARPHRD_ETHER);
    arpPacket.ar_pro = htons(ETH_P_IP);
    arpPacket.ar_hln = ETH_ALEN;
    arpPacket.ar_pln = IPV4_ALEN;
    arpPacket.ar_op = htons(ARPOP_REQUEST);
    if (memcpy_s(arpPacket.ar_sha, ETH_ALEN, localMacAddr, ETH_ALEN) != EOK) {
        LOGE("DoArpCheck memcpy fail");
    }
    if (isFillSenderIp) {
        if (memcpy_s(arpPacket.ar_spa, IPV4_ALEN, &localIpAddr, sizeof(localIpAddr)) != EOK) {
            LOGE("DoArpCheck memcpy fail");
        }
    } else {
        if (memset_s(arpPacket.ar_spa, IPV4_ALEN, 0, IPV4_ALEN) != EOK) {
            LOGE("DoArpCheck memset fail");
        }
    }
    if (memset_s(arpPacket.ar_tha, ETH_ALEN, 0, ETH_ALEN) != EOK) {
        LOGE("DoArpCheck memset fail");
    }
    if (memcpy_s(arpPacket.ar_tpa, IPV4_ALEN, &gatewayIpAddr, sizeof(gatewayIpAddr)) != EOK) {
        LOGE("DoArpCheck memcpy fail");
    }
    if (rawSocket_.Send(reinterpret_cast<uint8_t *>(&arpPacket), sizeof(arpPacket), l2Broadcast) != 0) {
        LOGE("send arp fail");
        return false;
    }

    timeCost = 0;
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
                memcmp(respPacket->ar_sha, localMacAddr, ETH_ALEN) != 0 &&
                memcmp(respPacket->ar_spa, &gatewayIpAddr, IPV4_ALEN) == 0) {
                std::chrono::steady_clock::time_point current = std::chrono::steady_clock::now();
                timeCost = std::chrono::duration_cast<std::chrono::milliseconds>(current - startTime).count();
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
