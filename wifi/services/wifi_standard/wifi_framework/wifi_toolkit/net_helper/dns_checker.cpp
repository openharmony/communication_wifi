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

#include "dns_checker.h"
#include <arpa/inet.h>
#include <chrono>
#include <poll.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <unistd.h>

#include "securec.h"
#include "wifi_log.h"
#include "wifi_settings.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "ohwifi_dns_checker"

namespace OHOS {
namespace Wifi {

const int DNS_SERVER_PORT = 53;
const int DNS_ADDRESS_TYPE = 1;

struct DNS_HEADER {
    unsigned short id;
    unsigned char rd : 1;
    unsigned char tc : 1;
    unsigned char aa : 1;
    unsigned char opCode : 4;
    unsigned char qr : 1;

    unsigned char rCode : 4;
    unsigned char cd : 1;
    unsigned char ad : 1;
    unsigned char z : 1;
    unsigned char ra : 1;

    unsigned short qCount;
    unsigned short ansCount;
    unsigned short authCount;
    unsigned short addCount;
};

struct QUESTION {
    unsigned short qtype;
    unsigned short qclass;
};

DnsChecker::DnsChecker() : dnsSocket(0), socketCreated(false), isRunning(true)
{}

DnsChecker::~DnsChecker()
{
    Stop();
}

void DnsChecker::Start(std::string priDns, std::string secondDns)
{
    if (socketCreated) {
        Stop();
    }
    isRunning = true;
    dnsSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (dnsSocket < 0) {
        LOGE("DnsChecker:socket error : %{public}d", errno);
        dnsSocket = 0;
        return;
    }
    std::string ifaceName = WifiSettings::GetInstance().GetStaIfaceName();
    struct ifreq ifaceReq;
    if (strncpy_s(ifaceReq.ifr_name, sizeof(ifaceReq.ifr_name), ifaceName.c_str(), ifaceName.size()) != EOK) {
        LOGE("DnsChecker copy ifaceReq failed.");
        close(dnsSocket);
        dnsSocket = 0;
        return;
    }
    if (setsockopt(dnsSocket, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifaceReq, sizeof(ifaceReq)) == -1) {
        LOGE("DnsChecker start SO_BINDTODEVICE error:%{public}d.", errno);
        close(dnsSocket);
        dnsSocket = 0;
        return;
    }
    socketCreated = true;
    primaryDnsAddress = priDns;
    secondDnsAddress = secondDns;
}

void DnsChecker::Stop()
{
    if (!socketCreated) {
        return;
    }
    close(dnsSocket);
    dnsSocket = 0;
    socketCreated = false;
}

void DnsChecker::formatHostAdress(char* hostAddress, const char* host)
{
    if (!hostAddress || !host) {
        return;
    }
    int lock = 0;
    int len = strlen(host);
    for (int i = 0; i < len; i++) {
        if (host[i] == '.') {
            *hostAddress++ = i - lock;
            for (; lock < i; lock++) {
                *hostAddress++ = host[lock];
            }
            lock++;
        }
    }
    *hostAddress++ = '\0';
}
void DnsChecker::StopDnsCheck()
{
    isRunning = false;
}

bool DnsChecker::DoDnsCheck(std::string url, int timeoutMillis)
{
    LOGI("DoDnsCheck Enter.");
    int len1 = (int)url.find("/generate_204");
    int len =  len1 - strlen("http://");
    std::string host = url.substr(strlen("http://"), len);
    host = host + ".";
    LOGD("DoDnsCheck url=%{public}s", host.c_str());
    if (!isRunning) {
        return false;
    }
    bool dnsValid = checkDnsValid(host, primaryDnsAddress, timeoutMillis) ||
        checkDnsValid(host, secondDnsAddress, timeoutMillis);
    if (!dnsValid) {
        LOGE("all dns can not work.");
    }
    return dnsValid;
}

int DnsChecker::recvDnsData(char* buff, int size, int timeout)
{
    if (dnsSocket < 0) {
        LOGE("invalid socket fd");
        return 0;
    }

    pollfd fds[1];
    fds[0].fd = dnsSocket;
    fds[0].events = POLLIN;
    if (poll(fds, 1, timeout) <= 0) {
        return 0;
    }

    int nBytes;
    do {
        nBytes = read(dnsSocket, buff, size);
        if (nBytes < 0) {
            LOGE("recvfrom failed %{public}d", errno);
            return false;
        }
    } while (nBytes == -1 && isRunning);

    return nBytes < 0 ? 0 : nBytes;
}

bool DnsChecker::checkDnsValid(std::string host, std::string dnsAddress, int timeoutMillis)
{
    if (!socketCreated && !isRunning) {
        LOGE("DnsChecker checkDnsValid failed, socket not created");
        return false;
    }
    if (dnsAddress.empty()) {
        LOGE("DnsChecker dnsAddress is empty!");
        return false;
    }
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_SERVER_PORT);
    dest.sin_addr.s_addr = inet_addr(dnsAddress.c_str());
    char buff[2048] = {0};
    struct DNS_HEADER *dns = (struct DNS_HEADER*)&buff;
    dns->id = (unsigned short)htons(getpid());
    dns->rd = 1;
    dns->qCount = htons(1);
    char* hostAddress = (char*)&buff[sizeof(struct DNS_HEADER)];
    formatHostAdress(hostAddress, host.c_str());
    struct QUESTION *qinfo = (struct QUESTION *)&buff[sizeof(struct DNS_HEADER) +
        (strlen((const char*)hostAddress) + 1)];
    qinfo->qtype = htons(DNS_ADDRESS_TYPE);
    qinfo->qclass = htons(1);
    int len = (int)(sizeof(struct DNS_HEADER) + (strlen((const char*)hostAddress) + 1) + sizeof(QUESTION));
    if (sendto(dnsSocket, buff, len, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        LOGE("send dns data failed.");
        return false;
    }
    uint64_t elapsed = 0;
    int leftMillis = timeoutMillis;
    std::chrono::steady_clock::time_point startTime = std::chrono::steady_clock::now();
    while (leftMillis > 0 && isRunning) {
        int readLen = recvDnsData(buff, sizeof(buff), leftMillis);
        if (readLen >= static_cast<int>(sizeof(struct DNS_HEADER))) {
            dns = (struct DNS_HEADER*)buff;
            LOGI("dns recv ansCount:%{public}d", dns->ansCount);
            return dns->ansCount > 0;
        }
        std::chrono::steady_clock::time_point current = std::chrono::steady_clock::now();
        elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current - startTime).count();
        leftMillis -= static_cast<int>(elapsed);
    }
    return false;
}
}
}
