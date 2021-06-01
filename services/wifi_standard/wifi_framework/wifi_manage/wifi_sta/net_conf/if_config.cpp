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

#include <unistd.h>
#include <error.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <iostream>
#include <vector>
#include "securec.h"
#include "if_config.h"
#include "ip_tools.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_STA_IF_CONFIG"

namespace OHOS {
namespace Wifi {
const std::string SYSTEM_COMMAND_IP = "/system/bin/ip";
const std::string SYSTEM_COMMAND_NDC = "/system/bin/ndc";
const std::string IFNAME = "wlan0";
const int SYSTEM_COMMAND_ERR_1 = -1;
const int SYSTEM_COMMAND_ERR_2 = 127;
const int IPV6_SUFFIX_LEN = 3;
std::unique_ptr<IfConfig> IfConfig::g_ifConfig;

IfConfig &IfConfig::GetInstance()
{
    if (g_ifConfig.get() == nullptr) {
        g_ifConfig = std::make_unique<IfConfig>();
    }
    return *g_ifConfig;
}

IfConfig::IfConfig()
{}

IfConfig::~IfConfig()
{}

/**
 * @Description : Execute script commands
 * @Return success:true failed:false
 */
bool IfConfig::ExecCommand(const std::vector<std::string> &vecCommandArg) const
{
    std::string command;
    for (auto iter : vecCommandArg) {
        command += iter;
        command += " ";
    }
    LOGI("exec cmd: [%s]", command.c_str());
    int ret = system(command.c_str());
    if (ret == SYSTEM_COMMAND_ERR_1 || ret == SYSTEM_COMMAND_ERR_2) {
        LOGE("exec failed. cmd: %s, error:%{public}s", command.c_str(), strerror(errno));
        return false;
    }

    return true;
}

/**
 * @Description : Set the network card address, routing, DNS
 * @Return success:0 failed:-1
 */
int IfConfig::SetIfAddr(const DhcpResult &dhcpResult) const
{
    int ret = -1;
    // 2 is the ip_type num
    for (int i = 0; i < 2; i++) {
        if (dhcpResult[i].isOptSuc) {
            ret = 0;

            SetNetDns(IFNAME, dhcpResult[i].dns, dhcpResult[i].dns2);

            FlushIpAddr(IFNAME, dhcpResult[i].iptype);

            AddIpAddr(IFNAME, dhcpResult[i].ip, dhcpResult[i].subnet, dhcpResult[i].iptype);

            AddIfRoute(IFNAME, dhcpResult[i].ip, dhcpResult[i].subnet, dhcpResult[i].gateWay, dhcpResult[i].iptype);
        }
    }

    if (ret == 0) {
        LOGI("set addr succeed!");
    }
    return ret;
}

/**
 * @Description : Set DNS
 * @Return None
 */
void IfConfig::SetNetDns(std::string ifName, std::string dns1, std::string dns2) const
{
    std::vector<std::string> ipRouteCmd;
    ipRouteCmd.clear();
    ipRouteCmd.push_back(SYSTEM_COMMAND_NDC);
    ipRouteCmd.push_back("resolver");
    ipRouteCmd.push_back("setnetdns");
    ipRouteCmd.push_back(ifName);
    ipRouteCmd.push_back("");
    ipRouteCmd.push_back(dns1);
    ipRouteCmd.push_back(dns2);
    ExecCommand(ipRouteCmd);

    return;
}

/**
 * @Description : Flush the IpAddr
 * @Return None
 */
void IfConfig::FlushIpAddr(std::string ifName, int ipType) const
{
    std::vector<std::string> ipRouteCmd;
    ipRouteCmd.clear();
    ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
    if (ipType == static_cast<int>(StaIpType::IPTYPE_IPV4)) {
        ipRouteCmd.push_back("-4");
    } else {
        ipRouteCmd.push_back("-6");
    }
    ipRouteCmd.push_back("addr");
    ipRouteCmd.push_back("flush");
    ipRouteCmd.push_back("label");
    ipRouteCmd.push_back(ifName);
    ExecCommand(ipRouteCmd);

    // clear wlan0 route
    if (ipType == static_cast<int>(StaIpType::IPTYPE_IPV4)) {
        ipRouteCmd.clear();
        ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
        ipRouteCmd.push_back("route");
        ipRouteCmd.push_back("flush");
        ipRouteCmd.push_back("dev");
        ipRouteCmd.push_back(ifName);
        ExecCommand(ipRouteCmd);
    } else {
        ipRouteCmd.clear();
        ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
        ipRouteCmd.push_back("-6");
        ipRouteCmd.push_back("route");
        ipRouteCmd.push_back("flush");
        ipRouteCmd.push_back("dev");
        ipRouteCmd.push_back(ifName);
        ExecCommand(ipRouteCmd);
    }

    // flush route cache
    ipRouteCmd.clear();
    ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
    ipRouteCmd.push_back("route");
    ipRouteCmd.push_back("flush");
    ipRouteCmd.push_back("cache");
    ExecCommand(ipRouteCmd);

    return;
}

/**
 * @Description : Add the IpAddr
 * @Return None
 */
void IfConfig::AddIpAddr(std::string ifName, std::string ipAddr, std::string mask, int ipType) const
{
    if (ipType == static_cast<int>(StaIpType::IPTYPE_IPV4)) {
        struct ifreq ifr;
        if (memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK ||
            strcpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), ifName.c_str()) != EOK) {
            LOGE("set ifr info failed!");
            return;
        }

        struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
        sin->sin_family = AF_INET;

        // ipAddr
        if (inet_aton(ipAddr.c_str(), &(sin->sin_addr)) < 0) {
            LOGE("inet_aton   error\n");
            return;
        }

        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) {
            LOGE("socket error\n");
            return;
        }

        if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
            LOGE("ioctl   SIOCSIFADDR   error\n");
            close(fd);
            return;
        }

        // netMask
        if (inet_aton(mask.c_str(), &(sin->sin_addr)) < 0) {
            LOGE("inet_pton   error\n");
            close(fd);
            return;
        }

        if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0) {
            LOGE("ioctl SIOCSIFNETMASK error");
            close(fd);
            return;
        }
        close(fd);
    } else {
        std::vector<std::string> ipRouteCmd;
        ipRouteCmd.clear();
        ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
        ipRouteCmd.push_back("-6");
        ipRouteCmd.push_back("addr");
        ipRouteCmd.push_back("add");
        ipRouteCmd.push_back(ipAddr);
        ipRouteCmd.push_back("dev");
        ipRouteCmd.push_back(ifName);
        ExecCommand(ipRouteCmd);
    }

    return;
}

/**
 * @Description : Add Route
 * @Return None
 */
void IfConfig::AddIfRoute(
    std::string ifName, std::string ipAddr, std::string mask, std::string gateWay, int ipType) const
{
    if (ipType == static_cast<int>(StaIpType::IPTYPE_IPV4)) {
        AddIpv4Route(ifName, ipAddr, mask, gateWay);
    } else {
        AddIpv6Route(ifName, ipAddr, mask, gateWay);
    }
    return;
}

/**
 * @Description : set Ipv4 Route
 * @Return None
 */
void IfConfig::AddIpv4Route(std::string ifName, std::string ipAddr, std::string mask, std::string gateWay) const
{
    std::vector<std::string> ipRouteCmd;
    ipRouteCmd.clear();
    ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
    ipRouteCmd.push_back("rule add fwmark");
    ipRouteCmd.push_back("0x0/0xffff");
    ipRouteCmd.push_back("lookup");
    ipRouteCmd.push_back("254");
    ipRouteCmd.push_back("prio");
    ipRouteCmd.push_back("17000");
    ExecCommand(ipRouteCmd);
    // Translation address Calculate network segment
    unsigned int nIp = IpTools::ConvertIpv4Address(ipAddr);
    unsigned int nMask = IpTools::ConvertIpv4Address(mask);
    std::string ipSegment = IpTools::ConvertIpv4Address(nIp & nMask) + "/";
    ipSegment += std::to_string(IpTools::GetMaskLength(mask));
    // Add routing network segment
    ipRouteCmd.clear();
    ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
    ipRouteCmd.push_back("route add");
    ipRouteCmd.push_back(ipSegment);
    ipRouteCmd.push_back("dev");
    ipRouteCmd.push_back(ifName);
    ipRouteCmd.push_back("table");
    ipRouteCmd.push_back("254");
    ExecCommand(ipRouteCmd);
    // Delete the default gateway
    ipRouteCmd.clear();
    ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
    ipRouteCmd.push_back("route del default");
    ipRouteCmd.push_back("dev");
    ipRouteCmd.push_back(ifName);
    ipRouteCmd.push_back("table");
    ipRouteCmd.push_back("254");
    ExecCommand(ipRouteCmd);
    // Add default gateway
    ipRouteCmd.clear();
    ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
    ipRouteCmd.push_back("route add default");
    ipRouteCmd.push_back("via");
    ipRouteCmd.push_back(gateWay);
    ipRouteCmd.push_back("dev");
    ipRouteCmd.push_back(ifName);
    ipRouteCmd.push_back("table");
    ipRouteCmd.push_back("254");
    ExecCommand(ipRouteCmd);
    // Flush routing cache
    ipRouteCmd.clear();
    ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
    ipRouteCmd.push_back("route flush cache");
    ExecCommand(ipRouteCmd);
}

/**
 * @Description : set Ipv6 Route
 * @Return None
 */
void IfConfig::AddIpv6Route(std::string ifName, std::string ipAddr, std::string mask, std::string gateWay) const
{
    std::vector<std::string> ipRouteCmd;
    ipRouteCmd.clear();
    ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
    ipRouteCmd.push_back("-6 rule add");
    ipRouteCmd.push_back("fwmark");
    ipRouteCmd.push_back("0x0/0xffff");
    ipRouteCmd.push_back("lookup");
    ipRouteCmd.push_back("254");
    ipRouteCmd.push_back("prio");
    ipRouteCmd.push_back("17000");
    ExecCommand(ipRouteCmd);
    // Add routing network segment
    ipRouteCmd.clear();
    ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
    ipRouteCmd.push_back("-6 route add");
    ipRouteCmd.push_back(mask + ipAddr.substr(ipAddr.length() - IPV6_SUFFIX_LEN, ipAddr.length()));
    ipRouteCmd.push_back("dev");
    ipRouteCmd.push_back(ifName);
    ipRouteCmd.push_back("table");
    ipRouteCmd.push_back("254");
    ExecCommand(ipRouteCmd);
    // Delete the default gateway
    ipRouteCmd.clear();
    ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
    ipRouteCmd.push_back("-6 route del default");
    ipRouteCmd.push_back("dev");
    ipRouteCmd.push_back(ifName);
    ipRouteCmd.push_back("table");
    ipRouteCmd.push_back("254");
    ExecCommand(ipRouteCmd);
    // Add the default gateway
    ipRouteCmd.clear();
    ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
    ipRouteCmd.push_back("-6 route add default");
    ipRouteCmd.push_back("via");
    ipRouteCmd.push_back(gateWay);
    ipRouteCmd.push_back("dev");
    ipRouteCmd.push_back(ifName);
    ipRouteCmd.push_back("table");
    ipRouteCmd.push_back("254");
    ExecCommand(ipRouteCmd);
    // Flush routing cache
    ipRouteCmd.clear();
    ipRouteCmd.push_back(SYSTEM_COMMAND_IP);
    ipRouteCmd.push_back("-6 route flush cache");
    ExecCommand(ipRouteCmd);
}

/**
 * @Description : set proxy
 * @param isAuto - whether to automatically proxy[in]
 * @param proxy - proxy host name[in]
 * @param port - port[in]
 * @param noProxys - objects to bypass proxy[in]
 * @Return None
 */
void IfConfig::SetProxy(bool isAuto, std::string proxy, std::string port, std::string noProxys, std::string pac) const
{
    LOGI("SetProxy pac=[%s]\n", pac.c_str());
    std::vector<std::string> ipRouteCmd;

    if (!isAuto) {
        // Add proxy
        if (!proxy.empty()) {
            ipRouteCmd.clear();
            ipRouteCmd.push_back("export");
            ipRouteCmd.push_back("http_proxy=" + proxy + ":" + port);
            ExecCommand(ipRouteCmd);
        }

        // Bypass proxy
        if (!noProxys.empty()) {
            ipRouteCmd.clear();
            ipRouteCmd.push_back("export");
            ipRouteCmd.push_back("no_proxy=" + noProxys);
            ExecCommand(ipRouteCmd);
        }
    }

    return;
}
}  // namespace Wifi
}  // namespace OHOS