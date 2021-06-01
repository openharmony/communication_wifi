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
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <typeinfo>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include "securec.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_UTIL_NetworkInterface"

namespace OHOS {
namespace Wifi {
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

bool NetworkInterface::IsInterfaceUp(const std::string &interfaceName)
{
    struct ifreq ifr;
    if (strncpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), interfaceName.c_str(), interfaceName.length()) != EOK) {
        return false;
    }
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return false;
    }
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
        LOGE("Failed to obtain the Interface [%s] status. ", interfaceName.c_str());
    }
    close(fd);
    return (ifr.ifr_flags & IFF_UP) > 0;
}

void NetworkInterface::Dump(const std::string &interfaceName)
{
    LOGI("InterfaceName [%s]", interfaceName.c_str());

    Ipv4Address ipv4 = Ipv4Address::INVALID_INET_ADDRESS;
    std::vector<Ipv6Address> vecIPv6;

    bool ret = FetchInterfaceConfig(interfaceName, ipv4, vecIPv6);
    if (!ret) {
        LOGI("Fetch Interface [%s] failed.", interfaceName.c_str());
    }

    ipv4.Dump();

    LOGI("\tIPv6  size   [%d]", vecIPv6.size());
    for (const auto &item : vecIPv6) {
        item.Dump();
    }
}

bool NetworkInterface::FetchInterfaceConfig(
    const std::string &interfaceName,
    Ipv4Address &ipv4,
    std::vector<Ipv6Address> &vecIPv6)
{
    if (!FetchIpAddress(interfaceName, ipv4, vecIPv6)) {
        LOGE("interface [%s] Fetch IP address failed.", interfaceName.c_str());
        return false;
    }
    return true;
}

bool NetworkInterface::GetIpv4Address(const std::string &interfaceName, Ipv4Address &ipv4)
{
    ipv4 = Ipv4Address::INVALID_INET_ADDRESS;
    std::vector<Ipv6Address> vecIPv6;
    if (!FetchIpAddress(interfaceName, ipv4, vecIPv6)) {
        LOGE("interface [%s] Fetch IP address failed.", interfaceName.c_str());
        return false;
    }
    /*
     * The ipv4 address is not set for the network interface. In this case, the
     * ipv4 address is not updated.
     */
    return !(ipv4 == Ipv4Address::INVALID_INET_ADDRESS);
}

bool NetworkInterface::GetAllIpv6Address(const std::string &interfaceName, std::vector<Ipv6Address> &vecIPv6)
{
    Ipv4Address ipv4 = Ipv4Address::INVALID_INET_ADDRESS;
    if (!FetchIpAddress(interfaceName, ipv4, vecIPv6)) {
        LOGE("interface [%s] Fetch IP address failed.", interfaceName.c_str());
        return false;
    }
    return true;
}

bool NetworkInterface::IsExistAddressForInterface(const std::string &interfaceName, const BaseAddress &address)
{
    Ipv4Address ipv4 = Ipv4Address::INVALID_INET_ADDRESS;
    std::vector<Ipv6Address> vecIPv6;
    if (!FetchIpAddress(interfaceName, ipv4, vecIPv6)) {
        LOGE("interface [%s] Fetch IP address failed.", interfaceName.c_str());
        return false;
    }

    if (address == static_cast<const BaseAddress &>(ipv4)) {
        return true;
    }

    for (const auto iter : vecIPv6) {
        if (iter == address) {
            return true;
        }
    }

    return false;
}

bool NetworkInterface::AddIpAddress(const std::string &interfaceName, const BaseAddress &ipAddress)
{
    if (!ipAddress.IsValid()) {
        LOGE("Add IP address [%s] is not valid.", ipAddress.GetAddressWithString().c_str());
        return false;
    }

    /* Avoid repeated add. */
    if (IsExistAddressForInterface(interfaceName, ipAddress)) {
        LOGI("In interface [%s], the address [%s] is exist.",
            interfaceName.c_str(),
            ipAddress.GetAddressWithString().c_str());
        return true;
    }

    return true;
}

bool NetworkInterface::DelIpAddress(const std::string &interfaceName, const BaseAddress &ipAddress)
{
    if (!ipAddress.IsValid()) {
        LOGE("Del IP address [%s] is not valid.", ipAddress.GetAddressWithString().c_str());
        return false;
    }

    if (!IsExistAddressForInterface(interfaceName, ipAddress)) {
        LOGI("In interface [%s], the address [%s] is not exist.",
            interfaceName.c_str(),
            ipAddress.GetAddressWithString().c_str());
        return true;
    }

    return true;
}

bool NetworkInterface::ClearAllIpAddress(const std::string &interfaceName)
{
    Ipv4Address ipv4 = Ipv4Address::INVALID_INET_ADDRESS;
    std::vector<Ipv6Address> vecIPv6;
    bool ret = true;
    if (!FetchIpAddress(interfaceName, ipv4, vecIPv6)) {
        return false;
    }
    ret = DelIpAddress(interfaceName, ipv4);
    for (auto ip6 : vecIPv6) {
        ret &= DelIpAddress(interfaceName, ip6);
    }
    if (!ret) {
        LOGW("Some ip del failed.");
    }
    return true;
}

bool NetworkInterface::SaveIpAddress(
    const struct ifaddrs &ifa,
    Ipv4Address &ipv4,
    std::vector<Ipv6Address> &vecIPv6)
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
            LOGE("getnameinfo() failed: %{public}s\n", gai_strerror(ret));
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
            LOGE("getnameinfo() failed: %{public}s\n", gai_strerror(ret));
            return false;
        }
        /* For an IPv6 address, the suffix %wlan0 exists. */
        char *sepNum = strchr(host, '%');
        if (sepNum != nullptr) {
            *sepNum = '\0';
        }
        if (family == AF_INET) {
            ipv4 = Ipv4Address::Create(host, mask);
        } else if (family == AF_INET6) {
            vecIPv6.push_back(Ipv6Address::Create(host, mask));
        }
    }
    return true;
}

bool NetworkInterface::FetchIpAddress(
    const std::string &interfaceName,
    Ipv4Address &ipv4,
    std::vector<Ipv6Address> &vecIPv6)
{
    struct ifaddrs *ifaddr = nullptr;
    struct ifaddrs *ifa = nullptr;
    bool ret = false;
    int n = 0;

    if (getifaddrs(&ifaddr) == -1) {
        LOGE("getifaddrs: %{public}s", strerror(errno));
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
        if (strncmp(interfaceName.c_str(), ifa->ifa_name, IF_NAMESIZE) != 0) {
            continue;
        }
        ret = SaveIpAddress(*ifa, ipv4, vecIPv6);
    }

    freeifaddrs(ifaddr);
    return ret;
}
}  // namespace Wifi
}  // namespace OHOS