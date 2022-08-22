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

#include "raw_socket.h"
#include <arpa/inet.h>
#include <cstdio>
#include <cerrno>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "securec.h"
#include "wifi_log.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "ohwifi_raw_socket"

namespace OHOS {
namespace Wifi {
constexpr int OPT_SUCC = 0;
constexpr int OPT_FAIL = -1;

RawSocket::RawSocket() : socketFd_(-1), ifaceIndex_(0), protocol_(0)
{
}

RawSocket::~RawSocket()
{
    Close();
}

bool RawSocket::SetNonBlock(int fd)
{
    int ret = fcntl(fd, F_GETFL);
    if (ret < 0) {
        return false;
    }

    uint32_t flags = (static_cast<uint32_t>(ret) | O_NONBLOCK);
    return fcntl(fd, F_SETFL, flags);
}

int RawSocket::CreateSocket(const char *iface, uint16_t protocol)
{
    if (iface == nullptr) {
        LOGW("iface is null");
        return OPT_FAIL;
    }

    unsigned int ifaceIndex = if_nametoindex(iface);
    if (ifaceIndex == 0) {
        LOGE("get iface index fail: %{public}s", iface);
        return OPT_FAIL;
    }

    int socketFd = socket(PF_PACKET, SOCK_DGRAM, htons(protocol));
    if (socketFd < 0) {
        LOGE("create socket fail");
        return OPT_FAIL;
    }

    if (SetNonBlock(socketFd)) {
        LOGE("set non block fail");
        (void)close(socketFd);
        return OPT_FAIL;
    }

    struct sockaddr_ll rawAddr;
    rawAddr.sll_ifindex = ifaceIndex;
    rawAddr.sll_protocol = htons(protocol);
    rawAddr.sll_family = AF_PACKET;

    int ret = bind(socketFd, reinterpret_cast<struct sockaddr *>(&rawAddr), sizeof(rawAddr));
    if (ret != 0) {
        LOGE("bind fail");
        (void)close(socketFd);
        return OPT_FAIL;
    }
    socketFd_ = socketFd;
    ifaceIndex_ = ifaceIndex;
    protocol_ = protocol;
    return OPT_SUCC;
}

int RawSocket::Send(uint8_t *buff, int count, uint8_t *destHwaddr)
{
    if (buff == nullptr || destHwaddr == nullptr) {
        LOGE("buff or dest hwaddr is null");
        return OPT_FAIL;
    }

    if (socketFd_ < 0 || ifaceIndex_ == 0) {
        LOGE("invalid socket fd");
        return OPT_FAIL;
    }

    struct sockaddr_ll rawAddr;
    (void)memset_s(&rawAddr, sizeof(rawAddr), 0, sizeof(rawAddr));
    rawAddr.sll_ifindex = ifaceIndex_;
    rawAddr.sll_protocol = htons(protocol_);
    rawAddr.sll_family = AF_PACKET;
    if (memcpy_s(rawAddr.sll_addr, sizeof(rawAddr.sll_addr), destHwaddr, ETH_ALEN) != EOK) {
        LOGE("Send: memcpy fail");
        return OPT_FAIL;
    }

    int ret;
    do {
        ret = sendto(socketFd_, buff, count, 0, reinterpret_cast<struct sockaddr *>(&rawAddr), sizeof(rawAddr));
        if (ret == -1) {
            LOGE("Send: sendto fail");
            if (errno != EINTR) {
                break;
            }
        }
    } while (ret == -1);
    return ret > 0 ? OPT_SUCC : OPT_FAIL;
}

int RawSocket::Recv(uint8_t *buff, int count, int timeoutMillis)
{
    if (socketFd_ < 0) {
        LOGE("invalid socket fd");
        return 0;
    }

    pollfd fds[1];
    fds[0].fd = socketFd_;
    fds[0].events = POLLIN;
    if (poll(fds, 1, timeoutMillis) <= 0) {
        return 0;
    }

    int nBytes;
    do {
        nBytes = read(socketFd_, buff, count);
        if (nBytes == -1) {
            if (errno != EINTR) {
                break;
            }
        }
    } while (nBytes == -1);

    return nBytes < 0 ? 0 : nBytes;
}

int RawSocket::Close(void)
{
    int ret = OPT_FAIL;

    if (socketFd_ >= 0) {
        ret = close(socketFd_);
    }
    socketFd_ = -1;
    ifaceIndex_ = 0;
    protocol_ = 0;
    return OPT_FAIL;
}
}
}
