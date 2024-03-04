/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "dhcpd_interface.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include "network_interface.h"
#include "wifi_global_func.h"
#include "wifi_logger.h"
#include "securec.h"
#ifndef OHOS_ARCH_LITE
#include "ipc_skeleton.h"
#endif

DEFINE_WIFILOG_DHCP_LABEL("WifiDhcpdInterface");

namespace OHOS {
namespace Wifi {
const int EU_I64_ADDR_LEN = 64;
const int GENE_V6_ADDR_LEN = 64; /* Generally, the prefix length cannot exceed 64 characters. */
const int IP_V6_ADDR_LEN = 128;
const std::string IP_V4_MASK("255.255.255.0");
const std::string IP_V4_DEFAULT("192.168.62.1");
static bool g_startDhcpServerFlag = false;

DhcpdInterface::DhcpdInterface()
    : mBindIpv4(Ipv4Address::invalidInetAddress), mBindIpv6(Ipv6Address::INVALID_INET6_ADDRESS)
{}

DhcpdInterface::~DhcpdInterface()
{
    g_startDhcpServerFlag = false;
}

bool DhcpdInterface::RegisterDhcpCallBack(const std::string &ifaceName, ServerCallBack &event)
{
    if (RegisterDhcpServerCallBack(ifaceName.c_str(), &event) != 0) {
        WIFI_LOGE("Register dhcp server callBack failed!");
        return false;
    }
    return true;
}

bool DhcpdInterface::StartDhcpServerFromInterface(const std::string &ifaceName, Ipv4Address &ipv4, Ipv6Address &ipv6,
    const std::string &ipAddress, bool isIpV4, const int32_t &leaseTime)
{
    g_startDhcpServerFlag = true;
    std::vector<Ipv4Address> vecIpv4Addr;
    std::vector<Ipv6Address> vecIpv6Addr;
    if (!NetworkInterface::FetchApOrP2pIpAddress(ifaceName, vecIpv4Addr, vecIpv6Addr)) {
        WIFI_LOGW("Get ipaddress failed!");
    }

    // set ap interface to bind an ip address
    if (!AssignIpAddr(mBindIpv4, mBindIpv6, vecIpv4Addr, vecIpv6Addr, ipAddress, isIpV4)) {
        WIFI_LOGE("Assign ip address for interface failed!");
        return false;
    }
    ipv4 = mBindIpv4;
    ipv6 = mBindIpv6;
    if (!ApplyIpAddress(ifaceName, mBindIpv4, mBindIpv6)) {
        WIFI_LOGE("bind interface address failed!");
        return false;
    }

    if (!SetDhcpIpRange(ifaceName)) {
        WIFI_LOGE("Set dhcp range ip address failed!");
        return false;
    }
    if (!UpdateDefaultConfigFile(leaseTime)) {
        WIFI_LOGE("UpdateDefaultConfigFile failed!");
        return false;
    }
    if (StartDhcpServer(ifaceName.c_str()) != 0) {
        WIFI_LOGE("Start dhcp server failed!");
        return false;
    }

    return true;
}

bool DhcpdInterface::SetDhcpIpRange(const std::string &ifaceName)
{
    if (!mBindIpv4.IsValid()) { /* currently, we just support ipv4 */
        WIFI_LOGE("current interface does not bind ipv4!");
        return false;
    }
    std::string ipAddr = mBindIpv4.GetAddressWithString();
    CallAdapterSetRange(ipAddr, ifaceName);
    return true;
}

bool DhcpdInterface::UpdateDefaultConfigFile(const int32_t &leaseTime)
{
    std::string time = std::to_string(leaseTime);
    int result = UpdateLeasesTime(time.c_str());
    WIFI_LOGI("UpdateDefaultConfigFile leaseTime:%{public}d result:%{public}d", leaseTime, result);
    return (result == 0) ? true : false;
}

bool DhcpdInterface::GetConnectedStationInfo(const std::string &ifaceName, std::map<std::string, StationInfo> &result)
{
    DhcpStationInfo *staInfos = NULL;
    int staNumber = 10;
    int staSize = 0;
    staInfos = (struct DhcpStationInfo*)malloc(sizeof(DhcpStationInfo) * staNumber);
    GetConnectedStaInfo(ifaceName, staNumber, staInfos, &staSize);
    for (int i = 0; i < staSize; i++) {
        StationInfo info;
        info.deviceName = staInfos[i].deviceName;
        info.bssid = staInfos[i].macAddr;
        info.bssidType = REAL_DEVICE_ADDRESS;
        info.ipAddr = staInfos[i].ipAddr;
        result.insert(std::make_pair(info.bssid, info));
    }
    free(staInfos);
    return true;
}

bool DhcpdInterface::StopDhcp(const std::string &ifaceName)
{
    WIFI_LOGI("StopDhcp ifaceName:%{public}s, flag:%{public}d", ifaceName.c_str(), g_startDhcpServerFlag);
    if (ifaceName.empty() || g_startDhcpServerFlag == false) {
        WIFI_LOGE("StopDhcp return!");
        return false;
    }
    g_startDhcpServerFlag = false;
    std::string rangeName;
    std::string tagName = ifaceName;
    transform(tagName.begin(), tagName.end(), tagName.begin(), ::tolower);
    if (tagName.find("p2p") != std::string::npos) {
        rangeName = "p2p";
    } else {
        rangeName = ifaceName;
    }

    WIFI_LOGI("StopDhcp ifaceName:%{public}s, rangeName:%{public}s", ifaceName.c_str(), rangeName.c_str());
    if (RemoveAllDhcpRange(rangeName.c_str()) != 0) {
        WIFI_LOGW("failed to remove [%{public}s] dhcp range.", rangeName.c_str());
    }
    if (StopDhcpServer(ifaceName.c_str()) != 0) {
        WIFI_LOGE("Dhcp server stop failed or already stopped!");
        return false;
    }
    if (!NetworkInterface::ClearAllIpAddress(ifaceName)) {
        WIFI_LOGW("Clear interface binding ip address failed!");
    }
    return true;
}

bool DhcpdInterface::ApplyIpAddress(const std::string &ifaceName, const Ipv4Address &ipv4, const Ipv6Address &ipv6)
{
    bool ret = NetworkInterface::AddIpAddress(ifaceName, ipv4);
    if (ipv6.IsValid()) {
        ret |= NetworkInterface::AddIpAddress(ifaceName, ipv6);
    }
    return ret;
}

bool DhcpdInterface::AssignIpAddr(Ipv4Address &ipv4, Ipv6Address &ipv6, const std::vector<Ipv4Address> &vecIpv4Addr,
    const std::vector<Ipv6Address> &vecIpv6Addr, const std::string &ipAddress, bool isIpV4)
{
    if (isIpV4) {
        ipv4 = AssignIpAddrV4(vecIpv4Addr, IP_V4_MASK, ipAddress);
        if (ipv4 == Ipv4Address::invalidInetAddress) {
            WIFI_LOGE("Failed to allocate the IP address.");
            return false;
        }
    } else {
        Ipv6Address apShareIp(Ipv6Address::INVALID_INET6_ADDRESS);
        for (auto iter = vecIpv6Addr.begin(); iter != vecIpv6Addr.end(); ++iter) {
            if (Ipv6Address::IsAddrLocallink(iter->GetIn6Addr()) || !iter->IsValid()) {
                continue;
            }
            apShareIp = *iter;
            break;
        }
        Ipv6Address prefixIp = (apShareIp.GetAddressPrefixLength() > (IP_V6_ADDR_LEN - EU_I64_ADDR_LEN))
                                   ? AssignIpAddrV6(vecIpv6Addr)
                                   : apShareIp;
        if (!prefixIp.IsValid()) {
            WIFI_LOGE("Failed to allocate the IP address.");
            return false;
        }

        ipv6 = Ipv6Address::Create(prefixIp.GetAddressWithString(), prefixIp.GetAddressPrefixLength(), 0);
    }
    return true;
}

bool DhcpdInterface::CompareSubNet(
    const std::vector<Ipv4Address> &vecIpAddr, const struct in_addr &input, const struct in_addr &mask) const
{
    /* Check whether the network ID is the same as the IP address in vecIpAddr. */
    for (auto address : vecIpAddr) {
        struct in_addr tmpAddr = {INADDR_ANY};
        if (inet_aton(address.GetAddressWithString().c_str(), &tmpAddr) == 0) {
            WIFI_LOGE("convert ipaddress %{private}s failed!", address.GetAddressWithString().c_str());
            return true;
        }
        if (CALC_SUBNET(tmpAddr.s_addr, mask.s_addr) == input.s_addr) {
            return true;
        }
    }
    return false;
}

Ipv4Address DhcpdInterface::AssignIpAddrV4(const std::vector<Ipv4Address> &vecIpAddr, const std::string &mask,
    const std::string &ipAddress) const
{
    struct in_addr maskAddr = {INADDR_ANY};
    if (inet_aton(mask.c_str(), &maskAddr) == 0) {
        WIFI_LOGE("convert mask to ipaddress failed![%s].", mask.c_str());
        return Ipv4Address::invalidInetAddress;
    }
    struct in_addr initAddr = {INADDR_ANY};
    std::string destIpAddress = ipAddress.empty() ? IP_V4_DEFAULT : ipAddress;
    if (inet_aton(destIpAddress.c_str(), &initAddr) == 0) {
        WIFI_LOGE("convert default ipaddress failed![%s].", destIpAddress.c_str());
        return Ipv4Address::invalidInetAddress;
    }
    struct in_addr tmpAddr = {INADDR_ANY};
    while (true) {
        tmpAddr.s_addr = CALC_SUBNET(initAddr.s_addr, maskAddr.s_addr);
        if (!CompareSubNet(vecIpAddr, tmpAddr, maskAddr)) {
            return Ipv4Address::Create(initAddr, maskAddr);
        }
        /* For conflict, try to change the new network. */
        uint32_t cSubnet = ntohl(htonl(IN_CLASSC_NET & IN_CLASSB_HOST) & tmpAddr.s_addr) >> IN_CLASSC_NSHIFT;
        cSubnet++;
        if (cSubnet == 0xFF) {
            WIFI_LOGE("No available IPv4 address is found.\n");
            return Ipv4Address::invalidInetAddress;
        } else {
            tmpAddr.s_addr = (tmpAddr.s_addr & htonl(IN_CLASSB_NET)) | htonl(cSubnet << IN_CLASSC_NSHIFT);
            initAddr.s_addr = tmpAddr.s_addr | (initAddr.s_addr & htonl(IN_CLASSC_HOST));
        }
    }
    return Ipv4Address::invalidInetAddress;
}

Ipv6Address DhcpdInterface::AssignIpAddrV6(const std::vector<Ipv6Address> &vecIpAddr)
{
    struct in6_addr prefix = IN6ADDR_ANY_INIT;
    std::random_device rd;
    int loopNum = 10;
    while (loopNum > 0) {
        bool bFlag = true;
        prefix.s6_addr[0] = 0xFD;
        for (int i = 1; i < (GENE_V6_ADDR_LEN / CHAR_BIT); i++) {
            prefix.s6_addr[i] = std::abs((int)rd()) % CHAR_MAX;
        }
        for (auto address : vecIpAddr) {
            struct in6_addr tmpAddr = IN6ADDR_ANY_INIT;
            if (inet_pton(AF_INET6, address.GetAddressWithString().c_str(), &tmpAddr) <= 0) {
                WIFI_LOGI("IpAddr:bad ip:%s and inet_pton error.", address.GetAddressWithString().c_str());
                continue;
            }
            if (memcmp(&tmpAddr, &prefix, sizeof(in6_addr)) == 0) {
                bFlag = false;
                WIFI_LOGI("same IP: %x and %x.", tmpAddr.s6_addr32[0], tmpAddr.s6_addr32[1]);
                break;
            }
        }
        if (bFlag) {
            char retStr[256] = {0};
            if (inet_ntop(AF_INET6, &prefix, retStr, sizeof(retStr)) != nullptr) {
                return Ipv6Address::Create(std::string(retStr), GENE_V6_ADDR_LEN, 0);
            } else {
                WIFI_LOGE("inet_ntop convert ipv6 address failed!");
                return Ipv6Address::INVALID_INET6_ADDRESS;
            }
        }
        loopNum--;
    }
    WIFI_LOGE("Fatal error,can not generate valid ULA addr!");
    return Ipv6Address::INVALID_INET6_ADDRESS;
}

bool DhcpdInterface::CallAdapterSetRange(std::string &ipAddr, const std::string &ifaceName)
{
    std::string::size_type pos = ipAddr.rfind(".");
    if (pos == std::string::npos) {
        return false;
    }
    std::string ipHead = ipAddr.substr(0, pos);
    std::string subnet = "255.255.255.0";
    std::string p2p = "p2p";

    DhcpRange range;
    if (strcpy_s(range.strStartip, INET_ADDRSTRLEN, (ipHead + ".3").c_str()) != EOK
        || strcpy_s(range.strEndip, INET_ADDRSTRLEN, (ipHead + ".254").c_str()) != EOK
        || strcpy_s(range.strSubnet, INET_ADDRSTRLEN, subnet.c_str()) != EOK) {
        return false;
    }
    range.iptype = 0;
    std::string tagName = ifaceName;
    transform(tagName.begin(), tagName.end(), tagName.begin(), ::tolower);
    if (tagName.find("p2p") != std::string::npos) {
        if (strcpy_s(range.strTagName, DHCP_MAX_FILE_BYTES, "p2p") != EOK) {
            return false;
        }
        if (PutDhcpRange(range.strTagName, &range) != 0) {
            return false;
        }
        if (SetDhcpName(ifaceName.c_str(), range.strTagName) != 0) {
            return false;
        }
    } else {
        if (strcpy_s(range.strTagName, INET_ADDRSTRLEN, ifaceName.c_str()) != EOK) {
            return false;
        }
        if (SetDhcpRange(ifaceName.c_str(), &range) != 0) {
            return false;
        }
    }
    return true;
}

bool DhcpdInterface::GetConnectedStaInfo(const std::string &ifaceName, int staNumber, DhcpStationInfo *staInfos,
    int *staSize)
{
    if (staInfos == nullptr || staSize == nullptr) {
        WIFI_LOGI("GetConnectedStaInfo param is null!\n");
        return false;
    }
#ifndef OHOS_ARCH_LITE
    std::string identity = IPCSkeleton::ResetCallingIdentity();
#endif
    int result = GetDhcpClientInfos(ifaceName.c_str(), staNumber, staInfos, staSize);
#ifndef OHOS_ARCH_LITE
    IPCSkeleton::SetCallingIdentity(identity);
#endif
    if (result != 0) {
        return false;
    }
    if (staInfos == NULL) {
        return false;
    }
    return true;
}
}  // namespace Wifi
}  // namespace OHOS