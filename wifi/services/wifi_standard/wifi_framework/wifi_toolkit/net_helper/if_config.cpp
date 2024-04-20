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

#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <iostream>
#include <vector>
#include <thread>
#include "securec.h"
#include "if_config.h"
#include "ip_tools.h"
#include "ipv4_address.h"
#include "ipv6_address.h"
#include "wifi_settings.h"

namespace OHOS {
namespace Wifi {
const std::string SYSTEM_COMMAND_IP = "/system/bin/ip";
const int EXECVE_EXT_COMMAND = 127;
const int RECEIVE_BUFFER_LEN = 64;
const int MAX_COMMAND_ARG = 32;
#ifdef OHOS_ARCH_LITE
const std::string SYSTEM_COMMAND_NDC = "/system/bin/ndc";
const int IPV6_SUFFIX_LEN = 3;
const int MAX_IFNAME_LEN = 13;
#endif

IfConfig &IfConfig::GetInstance()
{
    static IfConfig ifConfig;
    return ifConfig;
}

IfConfig::IfConfig()
{}

IfConfig::~IfConfig()
{}

/**
 * @Description : Execute script commands
 * @Return success:true failed:false
 */
bool IfConfig::ExecCommand(const std::vector<std::string> &vecCommandArg)
{
    int argvSize = vecCommandArg.size();
    if (argvSize > MAX_COMMAND_ARG) {
        LOGE("IfConfig ExecCommand vecCommandArg size invalid.");
        return false;
    }
    std::thread t(
        [vecCommandArg, argvSize]() {
            int fd[2] = {0};
            if (pipe(fd) < 0) {
                LOGE("ifconfig create pipe failed.");
                return;
            }
            int pid = fork();
            if (pid == -1) {
                LOGE("ifconfig fork child process failed.");
                return;
            }
            if (pid == 0) {
                const char *execveStr[MAX_COMMAND_ARG];
                int i = 0;
                for (i = 0; i < argvSize && i < (MAX_COMMAND_ARG - 1); i++) {
                    execveStr[i] = vecCommandArg[i].c_str();
                }
                execveStr[i] = nullptr;
                char *env[] = {nullptr};
                close(fd[0]);
                dup2(fd[1], STDOUT_FILENO);
                close(fd[1]);
                /* last member of execveStr should be nullptr */
                if (execve(vecCommandArg[0].c_str(), (char *const*)execveStr, env) < 0) {
                    LOGE("execve %{public}s failed.", vecCommandArg[0].c_str());
                }
                _exit(EXECVE_EXT_COMMAND);
            }
            close(fd[1]);
            FILE *fp = fdopen(fd[0], "r");
            if (fp == nullptr) {
                LOGE("ifconfig fdopen failed.");
                return;
            }
            char buffer[RECEIVE_BUFFER_LEN];
            while (fgets(buffer, sizeof(buffer), fp) != nullptr) {
                LOGD("exec cmd receive: %{public}s", buffer);
            }
            fclose(fp);
        }
    );
    t.detach();
    return true;
}

/**
 * @Description : Flush the IpAddr
 * @Return None
 */
void IfConfig::FlushIpAddr(const std::string& ifName, const int& ipType)
{
    LOGI("Flush IP, ifName: %{public}s", ifName.c_str());

    if (ipType != static_cast<int>(IpType::IPTYPE_IPV4)) {
        return;
    }
    struct ifreq ifr;
    if (memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK ||
        strcpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), ifName.c_str()) != EOK) {
        LOGE("Init the ifreq struct failed!");
        return;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOGE("AddIpAddr:socket error");
        return;
    }
    struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
    sin->sin_family = AF_INET;
    /* ipAddr */
    if (inet_aton("0.0.0.0", &(sin->sin_addr)) < 0) {
        LOGE("AddIpAddr:inet_aton error");
        close(fd);
        return;
    }
    if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
        LOGE("AddIpAddr:ioctl SIOCSIFADDR error");
        close(fd);
        return;
    }
    close(fd);
    return;
}

/**
 * @Description : Add the IpAddr
 * @Return None
 */
void IfConfig::AddIpAddr(
    const std::string &ifName, const std::string &ipAddr, const std::string &mask, const int &ipType)
{
    LOGI("Add ip address, ifName = %{public}s", ifName.c_str());

    if (!CheckIfaceValid(ifName)) {
        return;
    }
    if (ipType == static_cast<int>(IpType::IPTYPE_IPV4)) {
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
 * @Description : set proxy
 * @param isAuto - whether to automatically proxy[in]
 * @param proxy - proxy host name[in]
 * @param port - port[in]
 * @param noProxys - objects to bypass proxy[in]
 * @Return None
 */
void IfConfig::SetProxy(
    bool isAuto, const std::string &proxy, const std::string &port, const std::string &noProxys, const std::string &pac)
{
    LOGI("SetProxy pac=[%s]\n", pac.c_str());
    std::vector<std::string> ipRouteCmd;

    if (!isAuto) {
        // Add proxy
        if (!proxy.empty()) {
            ipRouteCmd.clear();
            ipRouteCmd.push_back("export");
            ipRouteCmd.push_back("http_proxy=" + proxy + ":" + port);
        }

        // Bypass proxy
        if (!noProxys.empty()) {
            ipRouteCmd.clear();
            ipRouteCmd.push_back("export");
            ipRouteCmd.push_back("no_proxy=" + noProxys);
        }
    }
    return;
}

bool IfConfig::GetIpAddr(const std::string& ifName, std::string& ipAddr)
{
    struct ifreq ifr;
    if (memset_s(&ifr, sizeof(ifr), 0, sizeof(ifr)) != EOK ||
        strcpy_s(ifr.ifr_name, sizeof(ifr.ifr_name), ifName.c_str()) != EOK) {
        LOGE("set ifr info failed!");
        return false;
    }
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOGE("socket error\n");
        return false;
    }
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl error!\n");
        close(fd);
        return false;
    }
    struct sockaddr_in *sin = reinterpret_cast<struct sockaddr_in *>(&ifr.ifr_addr);
    ipAddr = inet_ntoa(sin->sin_addr);
    close(fd);
    return true;
}

bool IfConfig::CheckIfaceValid(const std::string& ifname)
{
    struct if_nameindex *ifidxs, *ifni;
    ifidxs = if_nameindex();
    if (ifidxs == nullptr) {
        LOGE("can not get interfaces");
        return false;
    }
    for (ifni = ifidxs; !(ifni->if_index == 0 && ifni->if_name == nullptr); ifni++) {
        if ((ifni->if_name != nullptr) &&
            strcmp(ifni->if_name, ifname.c_str()) == 0) {
            if_freenameindex(ifidxs);
            return true;
        }
    }
    if_freenameindex(ifidxs);
    LOGE("invalid interface: %{public}s", ifname.c_str());
    return false;
}

#ifdef OHOS_ARCH_LITE
/**
 * @Description : Set the network card routing, DNS
 * @Return success:0 failed:-1
 */
int IfConfig::SetIfDnsAndRoute(const DhcpResult *dhcpResult, int ipType, int instId)
{
    LOGD("ipType=%d, ip=%s, gateway=%s, subnet=%s, strDns1=%s, strDns2=%s",
        dhcpResult->iptype,
        dhcpResult->strOptClientId,
        dhcpResult->strOptSubnet,
        dhcpResult->strOptRouter1,
        dhcpResult->strOptDns1,
        dhcpResult->strOptDns2);
    SetNetDns(WifiSettings::GetInstance().GetStaIfaceName(), dhcpResult->strOptDns1, dhcpResult->strOptDns2);
    AddIfRoute(WifiSettings::GetInstance().GetStaIfaceName(), dhcpResult->strOptClientId, dhcpResult->strOptSubnet,
        dhcpResult->strOptRouter1, ipType);
    LOGI("set dns and route finished!");
    return 0;
}

/**
 * @Description : Set DNS
 * @Return None
 */
void IfConfig::SetNetDns(const std::string& ifName, const std::string& dns1, const std::string& dns2)
{
    std::vector<std::string> ipRouteCmd;
    ipRouteCmd.clear();
    ipRouteCmd.push_back(SYSTEM_COMMAND_NDC);
    ipRouteCmd.push_back("resolver");
    ipRouteCmd.push_back("setnetdns");
    ipRouteCmd.push_back(ifName);
    ipRouteCmd.push_back("");
    if (Ipv4Address::IsValidIPv4(dns1) || Ipv6Address::IsValidIPv6(dns1)) {
        ipRouteCmd.push_back(dns1);
    }
    if (Ipv4Address::IsValidIPv4(dns2) || Ipv6Address::IsValidIPv6(dns2)) {
        ipRouteCmd.push_back(dns2);
    }
    ExecCommand(ipRouteCmd);
    return;
}

/**
 * @Description : Add Route
 * @Return None
 */
void IfConfig::AddIfRoute(const std::string &ifName, const std::string &ipAddr, const std::string &mask,
    const std::string &gateWay, const int &ipType)
{
    if (ipType == static_cast<int>(IpType::IPTYPE_IPV4)) {
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
void IfConfig::AddIpv4Route(
    const std::string &ifName, const std::string &ipAddr, const std::string &mask, const std::string &gateWay)
{
    LOGI("Enter AddIpv4Route, ifName is %{public}s, ipAddr is %{private}s, mask is %s, gateWay is %{private}s",
        ifName.c_str(),
        ipAddr.c_str(),
        mask.c_str(),
        gateWay.c_str());

    struct rtentry route;
    if (memset_s(&route, sizeof(route), 0, sizeof(route)) != EOK) {
        LOGE("memset_s route info failed!");
        return;
    }

    struct sockaddr_in *addr = reinterpret_cast<struct sockaddr_in *>(&route.rt_gateway);
    addr->sin_family = AF_INET;
    if (inet_aton(gateWay.c_str(), &(addr->sin_addr)) < 0) {
        LOGE("inet_aton   error\n");
        return;
    }
    addr = reinterpret_cast<struct sockaddr_in *>(&route.rt_dst);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;
    addr = reinterpret_cast<struct sockaddr_in *>(&route.rt_genmask);
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;
    char strIfName[MAX_IFNAME_LEN + 1] = {0};
    if (strcpy_s(strIfName, sizeof(strIfName), ifName.c_str()) != EOK) {
        LOGE("strcpy_s error\n");
        return;
    }
    route.rt_dev = strIfName;
    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_metric = 0;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOGE("socket error\n");
        return;
    }
    if (ioctl(fd, SIOCADDRT, &route) < 0) {
        LOGE("ioctl SIOCADDRT error");
    }
    close(fd);
    return;
}

/**
 * @Description : set Ipv6 Route
 * @Return None
 */
void IfConfig::AddIpv6Route(
    const std::string &ifName, const std::string &ipAddr, const std::string &mask, const std::string &gateWay)
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
#endif
}  // namespace Wifi
}  // namespace OHOS
