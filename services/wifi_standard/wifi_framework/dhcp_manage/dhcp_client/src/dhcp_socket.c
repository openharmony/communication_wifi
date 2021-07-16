/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "dhcp_socket.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "securec.h"
#include "dhcp_client.h"

#undef LOG_TAG
#define LOG_TAG "WifiDhcpSocket"


static uint16_t CheckSum(u_int16_t *addr, int count)
{
    /* Compute Internet Checksum for "count" bytes beginning at location "addr". */
    register int32_t sum = 0;
    u_int16_t *source = addr;

    while (count > 1)  {
        /*  This is the inner loop */
        sum += *source++;
        count -= DHCP_UINT16_BYTES;
    }

    /*  Add left-over byte, if any */
    if (count > 0) {
        /* Make sure that the left-over byte is added correctly both with little and big endian hosts */
        u_int16_t tmp;
        *(unsigned char *)(&tmp) = *(unsigned char *)source;
        sum += tmp;
    }

    /*  Fold 32-bit sum to 16 bits */
    while (sum >> DHCP_UINT16_BITS) {
        sum = (sum & 0xffff) + (sum >> DHCP_UINT16_BITS);
    }

    return ~sum;
}

/* Raw socket can receive data frames or data packets from the local network interface. */
int CreateRawSocket(int *rawFd)
{
    int sockFd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (sockFd == -1) {
        LOGE("CreateRawSocket() failed, socket error:%{public}s.\n", strerror(errno));
        return SOCKET_OPT_FAILED;
    }
    *rawFd = sockFd;
    return SOCKET_OPT_SUCCESS;
}

int BindRawSocket(const int rawFd, const int ifaceIndex, const uint8_t *ifaceAddr)
{
    if (rawFd < 0) {
        LOGE("BindRawSocket() failed, rawFd:%{public}d error!\n", rawFd);
        return SOCKET_OPT_FAILED;
    }

    struct sockaddr_ll rawAddr;
    if (memset_s(&rawAddr, sizeof(rawAddr), 0, sizeof(rawAddr)) != EOK) {
        LOGE("BindRawSocket() failed, memset_s rawAddr error!\n");
        close(rawFd);
        return SOCKET_OPT_FAILED;
    }
    rawAddr.sll_ifindex = ifaceIndex;
    rawAddr.sll_protocol = htons(ETH_P_IP);
    rawAddr.sll_family = AF_PACKET;
    if (ifaceAddr != NULL) {
        rawAddr.sll_halen = MAC_ADDR_LEN;
        if (memcpy_s(rawAddr.sll_addr, sizeof(rawAddr.sll_addr), ifaceAddr, MAC_ADDR_LEN) != EOK) {
            LOGE("BindRawSocket() failed, memcpy_s rawAddr.sll_addr error!\n");
            close(rawFd);
            return SOCKET_OPT_FAILED;
        }
    }
    int nRet = bind(rawFd, (struct sockaddr *)&rawAddr, sizeof(rawAddr));
    if (nRet == -1) {
        LOGE("BindRawSocket() index:%{public}d failed, bind error:%{public}s.\n", ifaceIndex, strerror(errno));
        close(rawFd);
        return SOCKET_OPT_FAILED;
    }

    return SOCKET_OPT_SUCCESS;
}

/* Kernel socket can receive data frames or data packets from the local network interface, ip and port. */
int CreateKernelSocket(int *sockFd)
{
    int nFd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (nFd == -1) {
        LOGE("CreateKernelSocket() failed, socket error:%{public}s.\n", strerror(errno));
        return SOCKET_OPT_FAILED;
    }
    *sockFd = nFd;
    return SOCKET_OPT_SUCCESS;
}

int BindKernelSocket(const int sockFd, const char *ifaceName, const uint32_t sockIp, const int sockPort, bool bCast)
{
    if (sockFd < 0) {
        LOGE("BindKernelSocket() failed, sockFd:%{public}d error!\n", sockFd);
        return SOCKET_OPT_FAILED;
    }

    /* Bind the specified interface. */
    if (ifaceName != NULL) {
        struct ifreq ifaceReq;
        if (strncpy_s(ifaceReq.ifr_name, sizeof(ifaceReq.ifr_name), ifaceName, IFNAMSIZ) != EOK) {
            close(sockFd);
            return SOCKET_OPT_FAILED;
        }
        if (setsockopt(sockFd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifaceReq, sizeof(ifaceReq)) == -1) {
            LOGE("BindKernelSocket() %{public}s SO_BINDTODEVICE error:%{public}s.\n", ifaceName, strerror(errno));
            close(sockFd);
            return SOCKET_OPT_FAILED;
        }
    }

    /* Set the broadcast feature of the data sent by the socket. */
    if (bCast) {
        if (setsockopt(sockFd, SOL_SOCKET, SO_BROADCAST, (const char *)&bCast, sizeof(bool)) == -1) {
            LOGE("BindKernelSocket() sockFd:%{public}d SO_BROADCAST error:%{public}s.\n", sockFd, strerror(errno));
            close(sockFd);
            return SOCKET_OPT_FAILED;
        }
    }

    /* Allow multiple sockets to use the same port number. */
    bool bReuseaddr = true;
    if (setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, (const char *)&bReuseaddr, sizeof(bool)) == -1) {
        LOGE("BindKernelSocket() sockFd:%{public}d SO_REUSEADDR error:%{public}s.\n", sockFd, strerror(errno));
        close(sockFd);
        return SOCKET_OPT_FAILED;
    }

    struct sockaddr_in kernelAddr;
    if (memset_s(&kernelAddr, sizeof(kernelAddr), 0, sizeof(kernelAddr)) != EOK) {
        close(sockFd);
        return SOCKET_OPT_FAILED;
    }
    kernelAddr.sin_addr.s_addr = sockIp;
    kernelAddr.sin_port = htons(sockPort);
    kernelAddr.sin_family = AF_INET;
    int nRet = bind(sockFd, (struct sockaddr *)&kernelAddr, sizeof(kernelAddr));
    if (nRet == -1) {
        LOGE("BindKernelSocket() sockFd:%{public}d failed, bind error:%{public}s.\n", sockFd, strerror(errno));
        close(sockFd);
        return SOCKET_OPT_FAILED;
    }

    return SOCKET_OPT_SUCCESS;
}

int SendToDhcpPacket(
    const struct DhcpPacket *sendPacket, uint32_t srcIp, uint32_t destIp, int destIndex, const uint8_t *destHwaddr)
{
    int nFd = -1;
    if (CreateRawSocket(&nFd) != SOCKET_OPT_SUCCESS) {
        return SOCKET_OPT_FAILED;
    }

    struct sockaddr_ll rawAddr;
    rawAddr.sll_ifindex = destIndex;
    rawAddr.sll_protocol = htons(ETH_P_IP);
    rawAddr.sll_family = AF_PACKET;
    rawAddr.sll_halen = MAC_ADDR_LEN;
    if (memcpy_s(rawAddr.sll_addr, sizeof(rawAddr.sll_addr), destHwaddr, MAC_ADDR_LEN) != EOK) {
        close(nFd);
        return SOCKET_OPT_FAILED;
    }
    if (bind(nFd, (struct sockaddr *)&rawAddr, sizeof(rawAddr)) == -1) {
        LOGE("SendToDhcpPacket() index:%{public}d failed, bind error:%{public}s.\n", destIndex, strerror(errno));
        close(nFd);
        return SOCKET_OPT_FAILED;
    }

    /* Filling the structure information. */
    struct UdpDhcpPacket udpPackets;
    if (memset_s(&udpPackets, sizeof(udpPackets), 0, sizeof(udpPackets)) != EOK) {
        close(nFd);
        return SOCKET_OPT_FAILED;
    }
    udpPackets.udp.source = htons(BOOTP_CLIENT);
    udpPackets.udp.dest = htons(BOOTP_SERVER);
    udpPackets.udp.len = htons(sizeof(udpPackets.udp) + sizeof(struct DhcpPacket));
    udpPackets.ip.tot_len = udpPackets.udp.len;
    udpPackets.ip.protocol = IPPROTO_UDP;
    udpPackets.ip.saddr = srcIp;
    udpPackets.ip.daddr = destIp;
    if (memcpy_s(&(udpPackets.data), sizeof(struct DhcpPacket), sendPacket, sizeof(struct DhcpPacket)) != EOK) {
        close(nFd);
        return SOCKET_OPT_FAILED;
    }
    udpPackets.udp.check = CheckSum((u_int16_t *)&udpPackets, sizeof(struct UdpDhcpPacket));
    udpPackets.ip.ihl = sizeof(udpPackets.ip) >> DHCP_UINT16_BYTES;
    udpPackets.ip.version = IPVERSION;
    udpPackets.ip.tot_len = htons(sizeof(struct UdpDhcpPacket));
    udpPackets.ip.ttl = IPDEFTTL;
    udpPackets.ip.check = CheckSum((u_int16_t *)&(udpPackets.ip), sizeof(udpPackets.ip));

    ssize_t nBytes = sendto(nFd, &udpPackets, sizeof(udpPackets), 0, (struct sockaddr *)&rawAddr, sizeof(rawAddr));
    if (nBytes <= 0) {
        LOGE("SendToDhcpPacket() fd:%{public}d failed, sendto error:%{public}s.\n", nFd, strerror(errno));
    } else {
        LOGI("SendToDhcpPacket() fd:%{public}d, index:%{public}d, bytes:%{public}d.\n", nFd, destIndex, (int)nBytes);
    }
    close(nFd);
    return (nBytes <= 0) ? SOCKET_OPT_FAILED : SOCKET_OPT_SUCCESS;
}

int SendDhcpPacket(struct DhcpPacket *sendPacket, uint32_t srcIp, uint32_t destIp)
{
    int nFd = -1;
    if ((CreateKernelSocket(&nFd) != SOCKET_OPT_SUCCESS) ||
        (BindKernelSocket(nFd, NULL, srcIp, BOOTP_CLIENT, false) != SOCKET_OPT_SUCCESS)) {
        LOGE("SendDhcpPacket() fd:%{public}d,srcIp:%{public}u failed!\n", nFd, srcIp);
        return SOCKET_OPT_FAILED;
    }

    struct sockaddr_in kernelAddr;
    if (memset_s(&kernelAddr, sizeof(kernelAddr), 0, sizeof(kernelAddr)) != EOK) {
        close(nFd);
        return SOCKET_OPT_FAILED;
    }
    kernelAddr.sin_addr.s_addr = destIp;
    kernelAddr.sin_port = htons(BOOTP_SERVER);
    kernelAddr.sin_family = AF_INET;
    int nRet = connect(nFd, (struct sockaddr *)&kernelAddr, sizeof(kernelAddr));
    if (nRet == -1) {
        LOGE("SendDhcpPacket() nFd:%{public}d failed, connect error:%{public}s.\n", nFd, strerror(errno));
        close(nFd);
        return SOCKET_OPT_FAILED;
    }

    ssize_t nBytes = write(nFd, sendPacket, sizeof(struct DhcpPacket));
    if (nBytes <= 0) {
        LOGE("SendDhcpPacket() fd:%{public}d failed, write error:%{public}s.\n", nFd, strerror(errno));
    } else {
        LOGI("SendDhcpPacket() fd:%{public}d, srcIp:%{public}u, bytes:%{public}d.\n", nFd, srcIp, (int)nBytes);
    }
    close(nFd);
    return (nBytes <= 0) ? SOCKET_OPT_FAILED : SOCKET_OPT_SUCCESS;
}

int CheckReadBytes(const int count, const int totLen)
{
    if (count < 0) {
        LOGE("CheckReadBytes() couldn't read on raw listening socket, count:%{public}d, error:%{public}s!\n",
            count, strerror(errno));
        /* The specified network interface service may be down. */
        sleep(NUMBER_ONE);
        return SOCKET_OPT_ERROR;
    }

    int nCommonSize = sizeof(struct iphdr) + sizeof(struct udphdr);
    if (count < nCommonSize) {
        LOGE("CheckReadBytes() read size:%{public}d less than common size:%{public}d!\n", count, nCommonSize);
        return SOCKET_OPT_FAILED;
    }

    if (count < totLen) {
        LOGE("CheckReadBytes() count:%{public}d less than totLen:%{public}d, packet is Truncated!\n", count, totLen);
        return SOCKET_OPT_FAILED;
    }

    LOGI("CheckReadBytes() count:%{public}d, tot:%{public}d, common:%{public}d.\n", count, totLen, nCommonSize);
    return SOCKET_OPT_SUCCESS;
}

int CheckUdpPacket(struct UdpDhcpPacket *packet, const int totLen)
{
    if (packet == NULL) {
        LOGE("CheckUdpPacket() failed, packet == NULL!\n");
        return SOCKET_OPT_FAILED;
    }

    if (totLen > (int)sizeof(struct UdpDhcpPacket)) {
        LOGE("CheckUdpPacket() totLen:%{public}d more than %{public}d!\n", totLen, (int)sizeof(struct UdpDhcpPacket));
        return SOCKET_OPT_FAILED;
    }

    if ((packet->ip.protocol != IPPROTO_UDP) || (packet->ip.version != IPVERSION)) {
        LOGE("CheckUdpPacket() failed, packet->ip.protocol:%{public}d or version:%{public}u error!\n",
            packet->ip.protocol, packet->ip.version);
        return SOCKET_OPT_FAILED;
    }

    uint32_t uIhl = (uint32_t)(sizeof(packet->ip) >> DHCP_UINT16_BYTES);
    if (packet->ip.ihl != uIhl) {
        LOGE("CheckUdpPacket() failed, packet->ip.ihl:%{public}u error, uIhl:%{public}u!\n", packet->ip.ihl, uIhl);
        return SOCKET_OPT_FAILED;
    }

    if (packet->udp.dest != htons(BOOTP_CLIENT)) {
        LOGE("CheckUdpPacket() failed, packet->udp.dest:%{public}d error, htons:%{public}d!\n",
            packet->udp.dest, htons(BOOTP_CLIENT));
        return SOCKET_OPT_FAILED;
    }

    uint16_t uLen = (uint16_t)(totLen - (int)sizeof(packet->ip));
    if (ntohs(packet->udp.len) != uLen) {
        LOGE("CheckUdpPacket() failed, packet->udp.len:%{public}d error, uLen:%{public}d!\n", packet->udp.len, uLen);
        return SOCKET_OPT_FAILED;
    }
    LOGI("CheckUdpPacket() success, totLen:%{public}d.\n", totLen);
    return SOCKET_OPT_SUCCESS;
}

int CheckPacketIpSum(struct UdpDhcpPacket *udpPacket, const int bytes)
{
    if (udpPacket == NULL) {
        return SOCKET_OPT_FAILED;
    }

    if (CheckUdpPacket(udpPacket, bytes) != SOCKET_OPT_SUCCESS) {
        usleep(SLEEP_TIME_500_MS);
        return SOCKET_OPT_FAILED;
    }

    /* Check packet ip sum. */
    u_int16_t check = udpPacket->ip.check;
    udpPacket->ip.check = 0;
    uint16_t uCheckSum = CheckSum((u_int16_t *)&(udpPacket->ip), sizeof(udpPacket->ip));
    if (check != uCheckSum) {
        LOGE("CheckPacketIpSum() failed, ip.check:%{public}d, uCheckSum:%{public}d!\n", check, uCheckSum);
        return SOCKET_OPT_ERROR;
    }
    LOGI("CheckPacketIpSum() success, bytes:%{public}d.\n", bytes);
    return SOCKET_OPT_SUCCESS;
}

int CheckPacketUdpSum(struct UdpDhcpPacket *udpPacket, const int bytes)
{
    if (udpPacket == NULL) {
        LOGE("CheckPacketUdpSum() failed, udpPacket == NULL!\n");
        return SOCKET_OPT_FAILED;
    }

    /* Check packet udp sum. */
    u_int16_t check = udpPacket->udp.check;
    udpPacket->udp.check = 0;
    u_int32_t source = udpPacket->ip.saddr;
    u_int32_t dest = udpPacket->ip.daddr;
    if (memset_s(&udpPacket->ip, sizeof(udpPacket->ip), 0, sizeof(udpPacket->ip)) != EOK) {
        LOGE("CheckPacketUdpSum() failed, memset_s ERROR!\n");
        return SOCKET_OPT_FAILED;
    }
    udpPacket->ip.protocol = IPPROTO_UDP;
    udpPacket->ip.saddr = source;
    udpPacket->ip.daddr = dest;
    udpPacket->ip.tot_len = udpPacket->udp.len;
    uint16_t uCheckSum = CheckSum((u_int16_t *)udpPacket, bytes);
    if (check && (check != uCheckSum)) {
        LOGE("CheckPacketUdpSum() failed, udp.check:%{public}d, uCheckSum:%{public}d!\n", check, uCheckSum);
        return SOCKET_OPT_FAILED;
    }
    LOGI("CheckPacketUdpSum() success, bytes:%{public}d.\n", bytes);
    return SOCKET_OPT_SUCCESS;
}

int GetDhcpRawPacket(struct DhcpPacket *getPacket, int fd)
{
    if (getPacket == NULL) {
        return SOCKET_OPT_FAILED;
    }

    /* Get and check udp dhcp packet bytes. */
    struct UdpDhcpPacket packet;
    if (memset_s(&packet, sizeof(struct UdpDhcpPacket), 0, sizeof(struct UdpDhcpPacket)) != EOK) {
        return SOCKET_OPT_FAILED;
    }
    int nBytes = read(fd, &packet, sizeof(struct UdpDhcpPacket));
    int nRet = CheckReadBytes(nBytes, (int)ntohs(packet.ip.tot_len));
    if (nRet != SOCKET_OPT_SUCCESS) {
        usleep(SLEEP_TIME_200_MS);
        return nRet;
    }

    /* Check udp dhcp packet sum. */
    nBytes = (int)ntohs(packet.ip.tot_len);
    if (((nRet = CheckPacketIpSum(&packet, nBytes)) != SOCKET_OPT_SUCCESS) ||
        ((nRet = CheckPacketUdpSum(&packet, nBytes)) != SOCKET_OPT_SUCCESS)) {
        return nRet;
    }

    int nDhcpPacket = nBytes - (int)(sizeof(packet.ip) + sizeof(packet.udp));
    if (memcpy_s(getPacket, sizeof(struct DhcpPacket), &(packet.data), nDhcpPacket) != EOK) {
        LOGE("GetDhcpRawPacket() memcpy_s packet.data failed!\n");
        return SOCKET_OPT_FAILED;
    }
    if (ntohl(getPacket->cookie) != MAGIC_COOKIE) {
        LOGE("GetDhcpRawPacket() cook:%{public}x error, COOK:%{public}x!\n", ntohl(getPacket->cookie), MAGIC_COOKIE);
        return SOCKET_OPT_FAILED;
    }
    return nDhcpPacket;
}

int GetDhcpPacket(struct DhcpPacket *getPacket, int fd)
{
    if (getPacket == NULL) {
        return SOCKET_OPT_FAILED;
    }

    int bytes;
    if (memset_s(getPacket, sizeof(struct DhcpPacket), 0, sizeof(struct DhcpPacket)) != EOK) {
        return SOCKET_OPT_FAILED;
    }
    if ((bytes = read(fd, getPacket, sizeof(struct DhcpPacket))) < 0) {
        LOGE("GetDhcpPacket() couldn't read on kernel listening socket, error:%{public}s!\n", strerror(errno));
        return SOCKET_OPT_ERROR;
    }

    if (ntohl(getPacket->cookie) != MAGIC_COOKIE) {
        LOGE("GetDhcpPacket() cook:%{public}x error, COOK:%{public}x!\n", ntohl(getPacket->cookie), MAGIC_COOKIE);
        return SOCKET_OPT_FAILED;
    }
    return bytes;
}
