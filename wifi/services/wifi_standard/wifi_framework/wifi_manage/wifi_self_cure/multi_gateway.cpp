/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <securec.h>

#include "multi_gateway.h"
#include "singleton.h"
#include "wifi_logger.h"
#include "wifi_config_center.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("MultiGateway");

constexpr int32_t DEFAULT_ARP_TIMEOUT_MS = 1000;
constexpr uint32_t MULTI_GATEWAY_NUM = 2;
constexpr int32_t MAC_ADDRESS_LENGTH = 6;
constexpr int32_t MAC_INDEX_0 = 0;
constexpr int32_t MAC_INDEX_1 = 1;
constexpr int32_t MAC_INDEX_2 = 2;
constexpr int32_t MAC_INDEX_3 = 3;
constexpr int32_t MAC_INDEX_4 = 4;
constexpr int32_t MAC_INDEX_5 = 5;

MultiGateway::MultiGateway() : m_currentIdx(0)
{
    WIFI_LOGI("MultiGateway()");
}

MultiGateway::~MultiGateway()
{
    WIFI_LOGI("~MultiGateway()");
}

MultiGateway& MultiGateway::GetInstance()
{
    static MultiGateway instance;
    return instance;
}

void MultiGateway::GetGatewayAddr(int32_t instId)
{
    std::string macAddress;
    WifiConfigCenter::GetInstance().GetMacAddress(macAddress, instId);
    IpInfo ipInfo;
    WifiConfigCenter::GetInstance().GetIpInfo(ipInfo, instId);
    std::string ipAddress = IpTools::ConvertIpv4Address(ipInfo.ipAddress);
    std::string ifName = WifiConfigCenter::GetInstance().GetStaIfaceName();
    if (ipInfo.gateway == 0) {
        WIFI_LOGE("gateway is null");
        return;
    }
    m_gwIpAddr = IpTools::ConvertIpv4Address(ipInfo.gateway);

    ArpChecker arpChecker;
    m_currentIdx = 0;
    arpChecker.Start(ifName, macAddress, ipAddress, m_gwIpAddr);
    arpChecker.GetGwMacAddrList(DEFAULT_ARP_TIMEOUT_MS, true, m_gwMacLists);
    WIFI_LOGI("get gateway num is %{public}lu", static_cast<unsigned long>(m_gwMacLists.size()));
}

bool MultiGateway::IsMultiGateway()
{
    return m_gwMacLists.size() >= MULTI_GATEWAY_NUM;
}

int32_t MultiGateway::GetGatewayNum()
{
    return m_gwMacLists.size();
}

std::string MultiGateway::GetGatewayIp()
{
    return m_gwIpAddr;
}

void MultiGateway::GetNextGatewayMac(std::string& mac)
{
    WIFI_LOGE("GetNextGatewayMac m_currentIdx: %{public}u", m_currentIdx);
    if (m_currentIdx >= m_gwMacLists.size()) {
        WIFI_LOGE("m_currentIdx is overflow, m_currentIdx: %{public}u, size: %{public}lu",
            m_currentIdx,  static_cast<unsigned long>(m_gwMacLists.size()));
        return;
    }
    mac = m_gwMacLists[m_currentIdx];
    m_currentIdx++;
}

int32_t MultiGateway::SetStaticArp(const std::string& iface, const std::string& ipAddr, const std::string& macAddr)
{
    WIFI_LOGI("SetStaticArp enter");
    struct arpreq req;
    struct sockaddr_in *sin = nullptr;

    if (iface.empty() || ipAddr.empty() || macAddr.empty()) {
        WIFI_LOGE("SetStaticArp arg is invalid");
        return -1;
    }

    if (memset_s(&req, sizeof(struct arpreq), 0, sizeof(struct arpreq)) != EOK) {
        WIFI_LOGE("DelStaticArp memset_s err");
        return -1;
    }
    sin = reinterpret_cast<struct sockaddr_in *>(&req.arp_pa);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inet_addr(ipAddr.c_str());
    if (strncpy_s(req.arp_dev, sizeof(req.arp_dev), iface.c_str(), iface.size()) != EOK) {
        WIFI_LOGE("strncpy_s req err");
        return -1;
    }

    req.arp_flags = ATF_PERM | ATF_COM;
    if (GetMacAddr(reinterpret_cast<char *>(req.arp_ha.sa_data), macAddr.c_str()) < 0) {
        WIFI_LOGE("SetStaticArp GetMacAddr error");
        return -1;
    }
    return DoArpItem(SIOCSARP, &req);
}

int32_t MultiGateway::DelStaticArp(const std::string& iface, const std::string& ipAddr)
{
    WIFI_LOGI("DelStaticArp enter");
    struct arpreq req;
    if (iface.empty() || ipAddr.empty()) {
        WIFI_LOGE("DelStaticArp arg is invalid");
        return -1;
    }

    if (memset_s(&req, sizeof(struct arpreq), 0, sizeof(struct arpreq)) != EOK) {
        WIFI_LOGE("DelStaticArp memset_s err");
        return -1;
    }
    struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(&req.arp_pa);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inet_addr(ipAddr.c_str());
    if (strncpy_s(req.arp_dev, sizeof(req.arp_dev), iface.c_str(), iface.size()) != EOK) {
        WIFI_LOGE("strncpy_s req err");
        return -1;
    }
    return DoArpItem(SIOCDARP, &req);
}

int32_t MultiGateway::DoArpItem(int32_t cmd, struct arpreq *req)
{
    if (req == nullptr) {
        WIFI_LOGE("DoArpItem req is nullptr");
        return -1;
    }

    int32_t sockFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFd < 0) {
        WIFI_LOGE("DoArpItem socket creat error");
        return -1;
    }

    int32_t ret = ioctl(sockFd, cmd, req);
    if (ret < 0) {
        WIFI_LOGE("DoArpItem ioctl error");
    }
    close(sockFd);
    return ret;
}

int32_t MultiGateway::GetMacAddr(char *buff, const char *macAddr)
{
    unsigned int addr[MAC_ADDRESS_LENGTH] = {0};
    if (buff == nullptr || macAddr == nullptr) {
        WIFI_LOGE("buff or macAddr is nullptr");
        return -1;
    }

    if (sscanf_s(macAddr, "%x:%x:%x:%x:%x:%x", &addr[MAC_INDEX_0], &addr[MAC_INDEX_1], &addr[MAC_INDEX_2],
        &addr[MAC_INDEX_3], &addr[MAC_INDEX_4], &addr[MAC_INDEX_5]) < MAC_ADDRESS_LENGTH) {
        WIFI_LOGE("sscanf_s macAddr err");
        return -1;
    }

    for (int32_t i = 0; i < MAC_ADDRESS_LENGTH; i++) {
        buff[i] = addr[i];
    }
    return 0;
}
} // namespace Wifi
} // namespace OHOS
