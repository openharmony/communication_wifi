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
#include "wifi_ap_dhcp_interface.h"
#include <unistd.h>
#include <limits.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <random>
#include "securec.h"
#include "network_interface.h"
#include "ap_state_machine.h"
#include "log_helper.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_AP_WifiApDhcpInterface"
#define DHCP_USER "nobody"

/* Receives the SIGCHLD signal of the DHCP server process. */
static void SigChld(int signo)
{
    if (SIGCHLD == signo) {
        pid_t childPid = 0;
        int status = 0;
        int errnoBak = errno;
        pid_t dhcpPid = OHOS::Wifi::WifiApDhcpInterface::GetInstance().GetDhcpPid();

        /*
         * Only of the DHCP server, but the interrupted will break the systemcall.
         * Although it can be recovered, the exit status of other subprocesses is
         * processed. the waitpid processing process in the system interface cannot be
         * reclaimed, and a misleading message is displayed.
         */
        childPid = waitpid(dhcpPid, &status, WUNTRACED | WNOHANG);
        if (childPid == dhcpPid) {
            LOGE("DHCP server is dead. then stop hotspot.");
            OHOS::Wifi::ApStateMachine::GetInstance().SendMessage(
                static_cast<int>(OHOS::Wifi::ApStatemachineEvent::CMD_STOP_HOTSPOT));
        }

        errno = errnoBak;
    }
}

namespace OHOS {
namespace Wifi {
const std::string DHCP_SERVER_FILE("./dhcpd");
const std::string SOCKFD_PATH("/data/dhcp/ap_dhcp.sock");
const std::string IP_V4_MASK("255.255.255.0");
const int EUI64_ADDR_LEN = 64;
const int GENE_V6_ADDR_LEN = 64; /* Generally, the prefix length cannot exceed 64 characters. */
const int IPV6_ADDR_LEN = 128;
const int BUFFER_SIZE = 256;
WifiApDhcpInterface *WifiApDhcpInterface::g_instance = nullptr;
WifiApDhcpInterface &WifiApDhcpInterface::GetInstance()
{
    if (g_instance == nullptr) {
        g_instance = new WifiApDhcpInterface();
    }
    return *g_instance;
}

void WifiApDhcpInterface::DeleteInstance()
{
    if (g_instance != nullptr) {
        delete g_instance;
        g_instance = nullptr;
    }
}

WifiApDhcpInterface::WifiApDhcpInterface()
    : mFdSocketListen(-1), mPidDhcp(0), mPDealDhcpThread(nullptr), mDhcpCallback(nullptr)
{}

WifiApDhcpInterface::~WifiApDhcpInterface()
{
    StopDhcpServer();
}

static Ipv6Address ApGetValidIpv6Net(std::string &IfcName)
{
    std::vector<Ipv6Address> ip6Vec;
    if (!NetworkInterface::GetAllIpv6Address(IfcName, ip6Vec)) {
        printf("Failed to GetAllIpv6Address\n");
        return Ipv6Address::INVALID_INET6_ADDRESS;
    }
    for (auto ifr : ip6Vec) {
        if (Ipv6Address::IsAddrLocallink(ifr.GetIn6Addr()) || !ifr.IsValid()) {
            continue; /* skip bad or local link address */
        }
        return ifr;
    }
    printf("Failed to get valid address\n");
    return Ipv6Address::INVALID_INET6_ADDRESS;
}

bool WifiApDhcpInterface::ApplyIpAddress(
    const std::string hotspotInterface, const Ipv4Address &ipv4, const Ipv6Address &ipv6)
{
    bool ret;
    /* Avoid duplicate logs. */
    ret = NetworkInterface::AddIpAddress(hotspotInterface, ipv4);
    if (ipv6.IsValid()) {
        ret = ret || NetworkInterface::AddIpAddress(hotspotInterface, ipv6);
    }
    return ret;
}

bool WifiApDhcpInterface::AssignIpAddr(Ipv4Address &ipv4, Ipv6Address &ipv6,
    const std::vector<Ipv4Address> &vecIpv4Addr, const std::vector<Ipv6Address> &vecIpv6Addr, bool isIpV4)
{
    if (isIpV4) {
        ipv4 = AssignIpAddrV4(vecIpv4Addr, IP_V4_MASK);
        if (ipv4 == Ipv4Address::INVALID_INET_ADDRESS) {
            LOGE("Failed to allocate the IP address.");
            return false;
        }
    } else { /* ipv6 */
        std::string ifcShare = "wlan0";
        Ipv6Address apShareIp = ApGetValidIpv6Net(ifcShare);
        Ipv6Address prefixIp = Ipv6Address(Ipv6Address::INVALID_INET6_ADDRESS);
        if (apShareIp.GetAddressPrefixLength() > (IPV6_ADDR_LEN - EUI64_ADDR_LEN)) {
            /* ipv6-nat ip6tables must support IPv6-NAT. */
            prefixIp = AssignIpAddrV6(vecIpv6Addr);
            if (!prefixIp.IsValid()) {
                LOGE("Failed to allocate the IP address.");
                return false;
            }
        } else {
            /* Subnet processing,need the dhcp-pd. */
            prefixIp = apShareIp;
        }

        char hidePrefixIp[MAX_IP_LENGTH + 1] = {0};
        EncryptLogMsg(prefixIp.GetPrefix().c_str(), hidePrefixIp, sizeof(hidePrefixIp));
        LOGI("prefixIp:%{public}s/%zu.", hidePrefixIp, prefixIp.GetAddressPrefixLength());

        MacAddress macAddr = MacAddress::Create("");
        LOGW("generate EUI64 addr failed and use rand addr.");
        ipv6 = Ipv6Address::Create(
            prefixIp.GetAddressWithString(), prefixIp.GetAddressPrefixLength(), 0); /* use Rnd address */
        LOGI("ifcIp:%s.", ipv6.GetAddressWithString().c_str());
    }
    return true;
}

bool WifiApDhcpInterface::ForkExecProcess(const std::string hotspotInterface, const int32_t maxConn,
    const std::string ifcIp, const std::string ipMask, bool isIpV4)
{
    const int bufferSize = 20;
    char max[bufferSize] = {0};
    if (snprintf_s(max, sizeof(max), sizeof(max) - 1, "%d", maxConn) < 0) {
        return false;
    }
    const int argSize = 14;
    const char *args[argSize] = {
        DHCP_SERVER_FILE.c_str(),
        "--net-name",
        hotspotInterface.c_str(),
        "--host-ip",
        ifcIp.c_str(),
        "--host-mask",
        ipMask.c_str(),
        "--max-link",
        max,
        "--net-type",
        isIpV4 ? "1" : "2",
        "--user=" DHCP_USER,
        "--keep-in-foreground",
        nullptr
    };
    if (execv(args[0], const_cast<char *const *>(args))) {
        LOGE("execv failed: [ %{public}s ] \n", DHCP_SERVER_FILE.c_str());
    }
    _exit(-1);
    return true;
}

bool WifiApDhcpInterface::ForkParentProcess()
{
    LOGI("DHCP server pid is %{public}d.\n", mPidDhcp);
    RegisterSignal();
    if (!CreateListen()) {
        StopDhcpServer();
    }
    return true;
}

bool WifiApDhcpInterface::StartDhcpServer(const std::string hotspotInterface, const int32_t maxConn,
    const std::vector<Ipv4Address> &vecIpv4Addr, const std::vector<Ipv6Address> &vecIpv6Addr, bool isIpV4)
{
    pid_t pid;

    std::string ifcIp;
    std::string ipMask;

    if (mPidDhcp != 0) {
        LOGI("%{public}s already started.", DHCP_SERVER_FILE.c_str());
        return true;
    }

    Ipv4Address Ipv4(Ipv4Address::INVALID_INET_ADDRESS);
    Ipv6Address Ipv6(Ipv6Address::INVALID_INET6_ADDRESS);
    if (!AssignIpAddr(Ipv4, Ipv6, vecIpv4Addr, vecIpv6Addr, true)) {
        return false;
    }

    if (!ApplyIpAddress(hotspotInterface, Ipv4, Ipv6)) {
        return false;
    }
    ifcIp = Ipv4.GetNetworkAddressWithString();
    ipMask = Ipv4.GetMaskWithString();
    /* IPV6 should send like FC::2 to the DHCP server. do not have /64. */

    LOGI("Starting [ %{public}s ].", DHCP_SERVER_FILE.c_str());
    if ((pid = fork()) < 0) {
        LOGE("fork failed: %{public}s", strerror(errno));
        return false;
    }
    mUseIfc.push_back(hotspotInterface);

    /* DHCP_SERVER_FILE */
    if (pid) {
        /* Parent Process */
        mPidDhcp = pid;
        ForkParentProcess();
    } else {
        ForkExecProcess(hotspotInterface, maxConn, ifcIp, ipMask, isIpV4);
    }
    return true;
}

bool WifiApDhcpInterface::StopDhcpServer()
{
    UnregisterSignal();
    for (auto ifc : mUseIfc) {
        NetworkInterface::ClearAllIpAddress(ifc.c_str());
    }
    mUseIfc.clear();
    if (mPidDhcp == 0) {
        LOGI("[ %{public}s ] already stoppend.", DHCP_SERVER_FILE.c_str());
        return true;
    }

    if (!DestroyListen()) {
        LOGE("DestroyListen is failed.");
        /* Listening cannot be canceled, but the process still needs to be killed. */
    }

    if (kill(mPidDhcp, SIGTERM) == -1) {
        if (ESRCH == errno) {
            /* Normal. The subprocess is dead. The SIGCHLD signal triggers the stop hotspot. */
            LOGI("Normal:DHCP PID is not exist.");
            mPidDhcp = 0;
            return true;
        }
        LOGE("kill [ %{public}s ] failed: %{public}s\n", DHCP_SERVER_FILE.c_str(), strerror(errno));
        return false;
    }

    if (waitpid(mPidDhcp, nullptr, 0) == -1) {
        LOGE("waitpid [ %{public}s ] failed:%{public}s\n", DHCP_SERVER_FILE.c_str(), strerror(errno));
        return false;
    }

    mPidDhcp = 0;
    return true;
}

void WifiApDhcpInterface::RegisterSignal() const
{
    struct sigaction newAction {};

    if (sigfillset(&newAction.sa_mask) == -1) {
        LOGE("sigfillset failed. %{public}s", strerror(errno));
    }

    if (sigdelset(&newAction.sa_mask, SIGCHLD) == -1) {
        LOGE("sigdelset failed. %{public}s", strerror(errno));
    }

    newAction.sa_handler = SigChld;
    newAction.sa_flags = SA_RESTART;
    newAction.sa_restorer = nullptr;

    if (sigaction(SIGCHLD, &newAction, nullptr) == -1) {
        LOGE("sigaction failed. %{public}s", strerror(errno));
    }
}

void WifiApDhcpInterface::UnregisterSignal() const
{
    struct sigaction newAction {};

    if (sigemptyset(&newAction.sa_mask) == -1) {
        LOGE("sigfillset failed. %{public}s", strerror(errno));
    }

    newAction.sa_handler = SIG_DFL;
    newAction.sa_flags = SA_RESTART;
    newAction.sa_restorer = nullptr;

    if (sigaction(SIGCHLD, &newAction, nullptr) == -1) {
        LOGE("sigaction failed. %{public}s", strerror(errno));
    }
}

bool WifiApDhcpInterface::CreateListen()
{
    const int maxListenNum = 20;
    if (unlink(SOCKFD_PATH.c_str()) == -1) {
        LOGE("Normal:Delete  %{public}s  failed.  %{public}s", SOCKFD_PATH.c_str(), strerror(errno));
    }

    mFdSocketListen = socket(AF_UNIX, SOCK_STREAM, 0);
    if (mFdSocketListen == -1) {
        LOGE("create socket fd failed.   %{public}s", strerror(errno));
        return false;
    }

    struct sockaddr_un serverAddr {};
    serverAddr.sun_family = AF_UNIX;
    if (strncpy_s(serverAddr.sun_path, sizeof(serverAddr.sun_path), SOCKFD_PATH.c_str(), strlen(SOCKFD_PATH.c_str())) !=
        EOK) {
        close(mFdSocketListen);
        mFdSocketListen = -1;
        return false;
    }

    if (bind(mFdSocketListen, reinterpret_cast<struct sockaddr *>(&serverAddr), sizeof(serverAddr)) == -1) {
        LOGE("bind failed.   %{public}s", strerror(errno));
        close(mFdSocketListen);
        return false;
    }

    if (listen(mFdSocketListen, maxListenNum) < 0) {
        LOGE("listen failed. %{public}s", strerror(errno));
        close(mFdSocketListen);
        return false;
    }

    mPDealDhcpThread = new std::thread(&WifiApDhcpInterface::DealListen, this);
    return true;
}

bool WifiApDhcpInterface::DestroyListen()
{
    if (shutdown(mFdSocketListen, SHUT_RDWR) == -1) {
        LOGE("shutdown listen socket fd failed: %{public}s \n", strerror(errno));
        return false;
    }
    close(mFdSocketListen);
    mFdSocketListen = -1;

    if (mPDealDhcpThread) {
        mPDealDhcpThread->join();

        delete mPDealDhcpThread;
        mPDealDhcpThread = nullptr;
    }

    return true;
}

void WifiApDhcpInterface::DealClientReport(ClientInfo *pClient) const
{
    if (pClient == nullptr) {
        return;
    }

    LOGI("get client info from dhcp: \n len: %{public}d bytes \n check: %04x \n name: %{public}s \n",
        pClient->len,
        pClient->check,
        pClient->name);
    LOGI("mac: %s \n", pClient->macAddr);
    LOGI("ip: %s \n ipType: %{public}d \n\n", pClient->ipAddr, pClient->ipType);

    /* The correct client information is obtained, which is accessed through
     * the p_client pointer. */
    if (mDhcpCallback) {
        StationInfo staInfo;
        staInfo.bssid = pClient->macAddr;
        staInfo.deviceName = pClient->name;
        staInfo.ipAddr = pClient->ipAddr;

        mDhcpCallback(staInfo);
    } else {
        LOGE("Unregistered DHCP server callback.");
    }
}

void WifiApDhcpInterface::DealReadHandle(int clientSockfd) const
{
    while (true) {
        unsigned short tempLen = 0;
        ssize_t tempLen2 = 0;
        tempLen2 = read(clientSockfd, reinterpret_cast<unsigned char *>(&tempLen), sizeof(tempLen));
        if (tempLen2 == -1) {
            LOGE("read length error: %{public}s \n", strerror(errno));
            break;
        }
        if (tempLen2 == 0) {
            LOGI("read of EOF.");
            break;
        }

        if (tempLen == 0) {
            continue;
        }

        unsigned int msgLen = tempLen + sizeof(tempLen);
        ClientInfo *pClient = (ClientInfo *)calloc(msgLen, sizeof(char));
        if (pClient == nullptr) {
            LOGE("calloc error: %{public}s \n", strerror(errno));
            break;
        }
        pClient->len = tempLen;
        tempLen2 = read(clientSockfd, &pClient->check, tempLen);
        if (tempLen2 != tempLen) {
            LOGE("read error \n");
            if (pClient != nullptr) {
                free(pClient);
                pClient = nullptr;
            }
            continue;
        }
        DealClientReport(pClient);
        if (pClient != nullptr) {
            free(pClient);
            pClient = nullptr;
        }
    }
    return;
}

void WifiApDhcpInterface::DealListen() const
{
    while (true) {
        int clientSockfd = 0;
        struct sockaddr_un clientAddr {};
        socklen_t len = sizeof(clientAddr);

        clientSockfd = accept(mFdSocketListen, reinterpret_cast<struct sockaddr *>(&clientAddr), &len);
        if (clientSockfd == -1) {
            if ((errno == EINVAL) || (errno == EBADF)) { /* WifiApDhcpInterface::DestroyListen invoking shutdown. */
                LOGE("Normal: Stop listening and shutdown the socket fd.");
            } else {
                LOGE("accept failed: %{public}s.\n", strerror(errno));
            }
            break;
        }
        LOGI("accept ok\n");
        DealReadHandle(clientSockfd);

        close(clientSockfd);
    }
}

void WifiApDhcpInterface::RegisterApCallback(DhcpCallback callback)
{
    mDhcpCallback = callback;
}

pid_t WifiApDhcpInterface::GetDhcpPid() const
{
    return mPidDhcp;
}

bool WifiApDhcpInterface::CompareSubNet(const std::vector<Ipv4Address> &vecIpAddr,
    const struct in_addr &ifcSubNetInAddr, const struct in_addr &maskInAddr) const
{
    /* Check whether the network ID is the same as the IP address in vecIpAddr. */
    for (auto IpAddr : vecIpAddr) {
        struct in_addr IpAddr_in_addr;
        struct in_addr IpAddrSubNet_in_addr;

        if (inet_aton(IpAddr.GetAddressWithString().c_str(), &IpAddr_in_addr) < 0) {
            LOGE("fatal error,base address construct error. %{public}s\n", strerror(errno));
            return true;
        }

        IpAddrSubNet_in_addr.s_addr = CALC_SUBNET(IpAddr_in_addr.s_addr, maskInAddr.s_addr);
        if (IpAddrSubNet_in_addr.s_addr == ifcSubNetInAddr.s_addr) {
            return true;
        }
    }
    return false;
}

Ipv4Address WifiApDhcpInterface::AssignIpAddrV4(
    const std::vector<Ipv4Address> &vecIpAddr, const std::string &mask) const
{
    struct in_addr maskInAddr {}; /* IN_CLASSC_NET IP_V4_MASK */
    std::string ifcIp = "127.0.0.1";
    /* Mask */
    if (inet_aton(mask.c_str(), &maskInAddr) < 0) {
        LOGE("mask:inet_aton   error: %{public}s\n", strerror(errno));
        return Ipv4Address::INVALID_INET_ADDRESS;
    }
    struct in_addr ifcIpInAddr {};
    struct in_addr ifcSubNetInAddr {};
    /* IfcIp */
    if (inet_aton(ifcIp.c_str(), &ifcIpInAddr) < 0) {
        LOGE("ifcIp:inet_aton   error: %{public}s\n", strerror(errno));
        return Ipv4Address::INVALID_INET_ADDRESS;
    }

    while (true) {
        ifcSubNetInAddr.s_addr = CALC_SUBNET(ifcIpInAddr.s_addr, maskInAddr.s_addr);

        if (!CompareSubNet(vecIpAddr, ifcSubNetInAddr, maskInAddr)) {
            Ipv4Address ifIpv4Addr = Ipv4Address::Create(ifcIpInAddr, maskInAddr);
            return ifIpv4Addr;
        } else {
            /* For conflicting try to change the new network. */
            unsigned char cSubnet = ntohl(htonl(IN_CLASSC_NET & IN_CLASSB_HOST) & ifcSubNetInAddr.s_addr) >>
                                    IN_CLASSC_NSHIFT; /* 0.0.255.0 part of next IP */
            cSubnet++;
            if (cSubnet == 0xFF) {
                /* No valid value. */
                LOGE("No available IPv4 address is found.\n");
                return Ipv4Address::INVALID_INET_ADDRESS;
            } else {
                ifcSubNetInAddr.s_addr = (ifcSubNetInAddr.s_addr & htonl(IN_CLASSB_NET)) |
                                         htonl(static_cast<uint32_t>(cSubnet) << IN_CLASSC_NSHIFT);
                ifcIpInAddr.s_addr = ifcSubNetInAddr.s_addr | (ifcIpInAddr.s_addr & htonl(IN_CLASSC_HOST));
            }
        }
    }
    return Ipv4Address::INVALID_INET_ADDRESS;
}

Ipv6Address WifiApDhcpInterface::AssignIpAddrV6(const std::vector<Ipv6Address> &vecIpAddr)
{
    struct in6_addr ipPre {};
    std::random_device rd;
    int loopNum = 10;
    while (loopNum > 0) {
        bool isValidSubNet = true;
        ipPre.s6_addr[0] = 0xFD;
        int i;
        for (i = 1; i < (GENE_V6_ADDR_LEN / CHAR_BIT); i++) {
            ipPre.s6_addr[i] = std::abs((int)rd()) % CHAR_MAX;
        }
        for (auto IpAddr : vecIpAddr) {
            struct in6_addr IpAddr_in6_addr;
            if (inet_pton(AF_INET6, IpAddr.GetAddressWithString().c_str(), &IpAddr_in6_addr) < 0) {
                LOGI("IpAddr:bad ip:%s and inet_aton error: %{public}s",
                    IpAddr.GetAddressWithString().c_str(),
                    strerror(errno));
                continue;
            }
            if (memcmp(&IpAddr_in6_addr, &ipPre, sizeof(ipPre)) == 0) {
                isValidSubNet = false;
                LOGI("same IP: %x and %x", IpAddr_in6_addr.s6_addr32[0], IpAddr_in6_addr.s6_addr32[1]);
                break;
            }
        }
        if (isValidSubNet) {
            char retStr[BUFFER_SIZE] = {0};
            if (inet_ntop(AF_INET6, &ipPre, retStr, sizeof(retStr)) != nullptr) {
                char hideRetStr[BUFFER_SIZE] = {0};
                EncryptLogMsg(retStr, hideRetStr, sizeof(hideRetStr));
                return Ipv6Address::Create(std::string(retStr), GENE_V6_ADDR_LEN, 0);
            } else {
                LOGE("inet_ntop error:%{public}s ", strerror(errno));
                return Ipv6Address::INVALID_INET6_ADDRESS;
            }
        }
        loopNum--;
    }
    LOGE("Fatal error,can not generate valid ULA addr!");
    return Ipv6Address::INVALID_INET6_ADDRESS;
}
}  // namespace Wifi
}  // namespace OHOS
