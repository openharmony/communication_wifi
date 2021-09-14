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
#include "network_interface.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <net/if.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <typeinfo>
#include <unistd.h>
#include <fcntl.h>

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>

#include "securec.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiNetworkInterface");

namespace OHOS {
namespace Wifi {
const int INET_IP_V4_ADDR_LEN = 4;
const int INET_IP_V6_ADDR_LEN = 16;
const int INT_BIT = 32;
bool NetworkInterface::IsValidInterfaceName(const std::string &interfaceName)
{
    size_t len = interfaceName.length();
    if (len == 0 || len > IF_NAMESIZE) {
        return false;
    }

    if (!isalnum(interfaceName[0])) {
        return false;
    }

    for (size_t i = 1; i < len; i++) {
        char ch = interfaceName[i];
        if (!isalnum(ch) && (ch != '_' && ch != '-' && ch != ':')) {
            return false;
        }
    }

    return true;
}


void NetworkInterface::Dump(const std::string &interfaceName)
{
    WIFI_LOGI("InterfaceName  [%s]", interfaceName.c_str());

    std::vector<Ipv4Address> vecIPv4;
    std::vector<Ipv6Address> vecIPv6;

    bool ret = FetchInterfaceConfig(interfaceName, vecIPv4, vecIPv6);
    if (!ret) {
        WIFI_LOGI("Fetch Interface [%s] failed.", interfaceName.c_str());
    }

    WIFI_LOGI("\tIPv4  size   [%zu]", vecIPv4.size());
    for (const auto &item : vecIPv4) {
        item.Dump();
    }

    WIFI_LOGI("\tIPv6  size   [%zu]", vecIPv6.size());
    for (const auto &item : vecIPv6) {
        item.Dump();
    }
}

bool NetworkInterface::FetchInterfaceConfig(
    const std::string &interfaceName, std::vector<Ipv4Address> &vecIPv4, std::vector<Ipv6Address> &vecIPv6)
{
    if (!FetchIpAddress(interfaceName, vecIPv4, vecIPv6)) {
        WIFI_LOGE("interface [%{public}s] Fetch IP address failed.", interfaceName.c_str());
        return false;
    }
    return true;
}

bool NetworkInterface::GetIpv4Address(const std::string &interfaceName, std::vector<Ipv4Address> &vecIPv4)
{
    std::vector<Ipv6Address> vecIPv6;
    if (!FetchIpAddress(interfaceName, vecIPv4, vecIPv6)) {
        WIFI_LOGE("interface [%{public}s] Fetch IP address failed.", interfaceName.c_str());
        return false;
    }
    /*
     * The ipv4 address is not set for the network interface. In this case, the
     * ipv4 address is not updated.
     */
    return !(vecIPv4.empty());
}

bool NetworkInterface::GetAllIpv6Address(const std::string &interfaceName, std::vector<Ipv6Address> &vecIPv6)
{
    std::vector<Ipv4Address> vecIPv4;
    if (!FetchIpAddress(interfaceName, vecIPv4, vecIPv6)) {
        WIFI_LOGE("interface [%{public}s] Fetch IP address failed.", interfaceName.c_str());
        return false;
    }
    return true;
}

bool NetworkInterface::IsExistAddressForInterface(const std::string &interfaceName, const BaseAddress &address)
{
    std::vector<Ipv4Address> vecIPv4;
    std::vector<Ipv6Address> vecIPv6;
    if (!FetchIpAddress(interfaceName, vecIPv4, vecIPv6)) {
        WIFI_LOGE("interface [%{public}s] Fetch IP address failed.", interfaceName.c_str());
        return false;
    }

    for (const auto &iter : vecIPv4) {
        if (iter == address) {
            return true;
        }
    }

    for (const auto &iter : vecIPv6) {
        if (iter == address) {
            return true;
        }
    }

    return false;
}

bool NetworkInterface::AddIpAddress(const std::string &interfaceName, const BaseAddress &ipAddress)
{
    if (!ipAddress.IsValid()) {
        WIFI_LOGE("Add IP address [%{public}s] is not valid.", ipAddress.GetAddressWithString().c_str());
        return false;
    }

    /* Avoid repeated add. */
    if (IsExistAddressForInterface(interfaceName, ipAddress)) {
        WIFI_LOGI("In interface [%{public}s], the address [%s] is exist.",
            interfaceName.c_str(),
            ipAddress.GetAddressWithString().c_str());
        return true;
    }

    if (!IpAddressChange(interfaceName, ipAddress, true)) {
        WIFI_LOGE("Interface [%{public}s] add address [%s] failed.",
            interfaceName.c_str(),
            ipAddress.GetAddressWithString().c_str());
        return false;
    }
    return true;
}

bool NetworkInterface::DelIpAddress(const std::string &interfaceName, const BaseAddress &ipAddress)
{
    if (!ipAddress.IsValid()) {
        WIFI_LOGE("Del IP address [%s] is not valid.", ipAddress.GetAddressWithString().c_str());
        return false;
    }

    if (!IsExistAddressForInterface(interfaceName, ipAddress)) {
        WIFI_LOGI("In interface [%{public}s], the address [%s] is not exist.",
            interfaceName.c_str(),
            ipAddress.GetAddressWithString().c_str());
        return true;
    }
    if (!IpAddressChange(interfaceName, ipAddress, false)) {
        WIFI_LOGE("Interface [%{public}s] del address [%s] failed.",
            interfaceName.c_str(),
            ipAddress.GetAddressWithString().c_str());
        return false;
    }
    return true;
}

bool NetworkInterface::ClearAllIpAddress(const std::string &interfaceName)
{
    std::vector<Ipv4Address> vecIPv4;
    std::vector<Ipv6Address> vecIPv6;
    bool ret = true;
    if (!FetchIpAddress(interfaceName, vecIPv4, vecIPv6)) {
        return false;
    }
    for (auto ip4 : vecIPv4) {
        ret &= DelIpAddress(interfaceName, ip4);
    }
    for (auto ip6 : vecIPv6) {
        ret &= DelIpAddress(interfaceName, ip6);
    }
    if (!ret) {
        WIFI_LOGW("Some ip del failed.");
    }
    return true;
}

bool NetworkInterface::SaveIpAddress(
    const struct ifaddrs &ifa, std::vector<Ipv4Address> &vecIPv4, std::vector<Ipv6Address> &vecIPv6)
{
    int ret = 0;
    char host[NI_MAXHOST] = {0}; /* IP address storage */
    char mask[NI_MAXHOST] = {0}; /* mask storage */
    int family = ifa.ifa_addr->sa_family;
    /* For an AF_INET* interface address, display the address */
    if (family == AF_INET || family == AF_INET6) {
        ret = getnameinfo(ifa.ifa_addr,
            (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
            host,
            NI_MAXHOST,
            nullptr,
            0,
            NI_NUMERICHOST);
        if (ret != 0) {
            WIFI_LOGE("getnameinfo() failed: %{public}s\n", gai_strerror(ret));
            return false;
        }
        ret = getnameinfo(ifa.ifa_netmask,
            (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
            mask,
            NI_MAXHOST,
            nullptr,
            0,
            NI_NUMERICHOST);
        if (ret != 0) {
            WIFI_LOGE("getnameinfo() failed: %{public}s\n", gai_strerror(ret));
            return false;
        }
        /* For an IPv6 address, the suffix %wlan0 exists. */
        char *sepNum = strchr(host, '%');
        if (sepNum != nullptr) {
            *sepNum = '\0';
        }
        if (family == AF_INET) {
            vecIPv4.push_back(Ipv4Address::Create(host, mask));
        } else if (family == AF_INET6) {
            vecIPv6.push_back(Ipv6Address::Create(host, mask));
        }
    }
    return true;
}

bool NetworkInterface::FetchIpAddress(
    const std::string &interfaceName, std::vector<Ipv4Address> &vecipv4, std::vector<Ipv6Address> &vecIPv6)
{
    struct ifaddrs *ifaddr = nullptr;
    struct ifaddrs *ifa = nullptr;
    bool ret = false;
    int n = 0;

    if (getifaddrs(&ifaddr) == -1) {
        WIFI_LOGE("getifaddrs: %{public}s", strerror(errno));
        return false;
    }

    for (ifa = ifaddr, n = 0; ifa != nullptr; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == nullptr) {
            continue;
        }
        /*
         * Display interface name and family (including symbolic
         * form of the latter for the common families)
         */
        if (strncmp(interfaceName.c_str(), ifa->ifa_name, IF_NAMESIZE) != 0 && !interfaceName.empty()) {
            continue;
        }
        ret |= SaveIpAddress(*ifa, vecipv4, vecIPv6);
    }

    freeifaddrs(ifaddr);
    return ret;
}

/* msg packet */
struct nlmsg {
    struct nlmsghdr nlmsg;
    struct ifaddrmsg ifamsg;
    char attrbuf[NLMSG_ALIGN(sizeof(struct rtattr)) + NLMSG_ALIGN(INET_IP_V6_ADDR_LEN) +
                 NLMSG_ALIGN(sizeof(struct rtattr)) + NLMSG_ALIGN(INET_IP_V4_ADDR_LEN)];
};

static bool SendNetlinkMsg(nlmsg msg)
{
    int sockfd = socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (sockfd < 0) {
        WIFI_LOGE("create socket failed to connet netlink");
        return false;
    }

    if (send(sockfd, &msg, msg.nlmsg.nlmsg_len, 0) < 0) {
        close(sockfd);
        WIFI_LOGE("socket send failed");
        return false;
    }

    char buf[NLMSG_ALIGN(sizeof(struct nlmsgerr)) + sizeof(msg)];
    int reclen = recv(sockfd, buf, sizeof(buf), 0);
    close(sockfd);
    if (reclen < 0) {
        WIFI_LOGE("failed to get results");
        return false;
    }

    struct nlmsghdr *recnlmsg = (struct nlmsghdr *)buf;
    int errnum = ((struct nlmsgerr *)NLMSG_DATA(recnlmsg))->error;
    if (!NLMSG_OK(recnlmsg, (unsigned)reclen) || recnlmsg->nlmsg_type != NLMSG_ERROR || errnum != 0) {
        WIFI_LOGE("Failed to set ip.err:%d", errnum);
        return false;
    }
    return true;
}

bool NetworkInterface::IpAddressChange(
    const std::string &interface, const BaseAddress &ipAddress, bool action, bool dad)
{
    if (!ipAddress.IsValid()) {
        WIFI_LOGE("bad input parameter to change ip.");
        return false;
    }

    int ifcindex = if_nametoindex(interface.c_str());
    if (ifcindex < 0) {
        WIFI_LOGE("bad interface to change ip.");
        return false;
    }

    int addrLen;
    in6_addr addr6;
    in_addr addr;
    void *addrSin;
    if (ipAddress.GetFamilyType() == BaseAddress::FamilyType::FAMILY_INET6) {
        addrLen = INET_IP_V6_ADDR_LEN;
        addr6 = static_cast<const Ipv6Address &>(ipAddress).GetIn6Addr();
        addrSin = &addr6;
    } else {
        addrLen = INET_IP_V4_ADDR_LEN;
        addr = static_cast<const Ipv4Address &>(ipAddress).GetAddressWithInet();
        addrSin = &addr;
    }
    int prelen = ipAddress.GetAddressPrefixLength();
    nlmsg msg;
    int ret = memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    if (ret != 0) {
        WIFI_LOGE("The msg of memset_s failed.");
        return false;
    }

    /* Netlink message header. */
    msg.nlmsg.nlmsg_len = NLMSG_LENGTH(sizeof(msg.ifamsg));
    msg.nlmsg.nlmsg_type = action ? RTM_NEWADDR : RTM_DELADDR;
    msg.nlmsg.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg.nlmsg.nlmsg_pid = getpid();

    /* Interface address message header. */
    msg.ifamsg.ifa_family = (addrLen == INET_IP_V6_ADDR_LEN) ? AF_INET6 : AF_INET;
    msg.ifamsg.ifa_flags = dad ? 0 : IFA_F_NODAD;
    msg.ifamsg.ifa_prefixlen = prelen;
    msg.ifamsg.ifa_index = ifcindex;

    /* Routing attribute. */
    struct rtattr *attr = (struct rtattr *)(((char *)&msg) + NLMSG_ALIGN(msg.nlmsg.nlmsg_len));
    attr->rta_type = IFA_LOCAL;
    attr->rta_len = RTA_LENGTH(addrLen);
    msg.nlmsg.nlmsg_len = NLMSG_ALIGN(msg.nlmsg.nlmsg_len) + RTA_LENGTH(addrLen);
    ret = memcpy_s(RTA_DATA(attr), sizeof(attr), addrSin, addrLen);
    if (ret != 0) {
        WIFI_LOGE("The attr of memcpy_s failed at INET_IP_V6_ADDR_LEN.");
        return false;
    }

    if (addrLen == INET_IP_V4_ADDR_LEN && action) { /* For IPV4 IFA_BROADCAST */
        attr = (struct rtattr *)(((char *)&msg) + NLMSG_ALIGN(msg.nlmsg.nlmsg_len));
        attr->rta_type = IFA_BROADCAST;
        attr->rta_len = RTA_LENGTH(addrLen);
        msg.nlmsg.nlmsg_len = NLMSG_ALIGN(msg.nlmsg.nlmsg_len) + RTA_LENGTH(addrLen);
        ((struct in_addr *)addrSin)->s_addr |= htonl((1 << (INT_BIT - prelen)) - 1);
        ret = memcpy_s(RTA_DATA(attr), sizeof(attr), addrSin, addrLen);
        if (ret != 0) {
            WIFI_LOGE("The attr of memcpy_s failed at INET_IP_V4_ADDR_LEN.");
            return false;
        }
    }
    return SendNetlinkMsg(msg);
}

bool NetworkInterface::WriteDataToFile(const std::string &fileName, const std::string &content)
{
    int fd = open(fileName.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        WIFI_LOGE("open %{public}s fail, error: %s", fileName.c_str(), strerror(errno));
        return false;
    }

    if (static_cast<size_t>(write(fd, content.c_str(), content.length())) != content.length()) {
        WIFI_LOGE("write content [%s] to file [%{public}s] failed. error: %s.",
            content.c_str(),
            fileName.c_str(),
            strerror(errno));
        close(fd);
        return false;
    }
    close(fd);
    return true;
}
}  // namespace Wifi
} // namespace OHOS
