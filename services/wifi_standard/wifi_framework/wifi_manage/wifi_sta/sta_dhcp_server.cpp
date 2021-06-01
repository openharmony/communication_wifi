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
#include "sta_dhcp_server.h"
#include "securec.h"
#include "if_config.h"

#undef LOG_TAG
#define LOG_TAG "OHWIFI_STA_DHCP_SERVER"

const std::string IPV4_DNS1 = "8.8.8.8";
const std::string IPV4_DNS2 = "8.8.4.4";
const std::string IPV6_DNS1 = "2400:3200::1";
const std::string IPV6_DNS2 = "2400:3200:baba::1";


namespace OHOS {
namespace Wifi {
const int IP_SIZE = 2;

StaDhcpServer::StaDhcpServer(DhcpResultHandler handler)
{
    pDealDhcpThread = nullptr;
    dhcpResultHandler = handler;
    isWakeDhcp = false;
    isExitDhcpThread = false;
    serverSockfd = -1;
    mIpType = IPTYPE_IPV4;
    ipNumber = IP_SIZE;

    memset_s(args, sizeof(args), 0, sizeof(args));
}

StaDhcpServer::~StaDhcpServer()
{
    LOGI("StaDhcpServer::~StaDhcpServer enter");
    ExitDhcpThread();
    LOGI("StaDhcpServer::~StaDhcpServer complete");
}

void StaDhcpServer::RunDhcpThreadFunc()
{
    LOGE("enter runDhcpThreadFunc\n");
    if (StartDhcpServer() != 0) {
        LOGE("startDhcpServer error\n");
        return;
    }

    while (1) {
        std::unique_lock<std::mutex> lck(mMutex);
        while (!isWakeDhcp) {
            LOGE("waiting for sigal\n");
            mCondition.wait(lck);
        }
        LOGE("unlock and start dhcp client\n");
        if (isExitDhcpThread) {
            break;
        }

        SetDhcpParam();
        ForkForDhcp();
        if (dhcpResultHandler) {
            dhcpResultHandler(result);
        }

        isWakeDhcp = false;
    }
    if (serverSockfd >= 0) {
        close(serverSockfd);
        serverSockfd = -1;
    }
    LOGI("dhcp thread over\n");
}

void StaDhcpServer::SetDhcpParam()
{
    int argsIndex = 0;
    memset_s(args, sizeof(args), 0, sizeof(args));
    if (mIpType == IPTYPE_IPV4) {
        ipNumber = 1;
        args[argsIndex] = const_cast<char *>(DHCP_CLIENT_FILE);
        args[++argsIndex] = const_cast<char *>("-4");
        args[++argsIndex] = nullptr;
    } else if (mIpType == IPTYPE_IPV6) {
        ipNumber = 1;
        args[argsIndex] = const_cast<char *>(DHCP_CLIENT_FILE);
        args[++argsIndex] = const_cast<char *>("-6");
        args[++argsIndex] = nullptr;
    } else {
        ipNumber = IP_SIZE;
        args[argsIndex] = const_cast<char *>(DHCP_CLIENT_FILE);
        args[++argsIndex] = nullptr;
    }
}
ErrCode StaDhcpServer::StartDhcpServer()
{
    unlink(SOCKFD_PATH);
    struct sockaddr_un serverAddr;
    serverAddr.sun_family = AF_UNIX;
    if (strcpy_s(serverAddr.sun_path, sizeof(serverAddr.sun_path), SOCKFD_PATH) != EOK) {
        return ErrCode::WIFI_OPT_FAILED;
    }
    serverSockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (serverSockfd < 0) {
        LOGE("startDhcpServer: failed to create server socket!");
        return ErrCode::WIFI_OPT_FAILED;
    }
    bool bFlag = false;
    do {
        struct timeval timeout;
        timeout.tv_sec = DHCP_ACCEPT_DELAY;
        timeout.tv_usec = 0;
        if (setsockopt(serverSockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) == -1) {
            LOGE("startDhcpServer: failed to set accept timeout!");
            break;
        }

        if (bind(serverSockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
            LOGE("startDhcpServer: failed to bind dhcp server socket!");
            break;
        }
        if (listen(serverSockfd, MAX_LISTEN) < 0) {
            LOGE("startDhcpServer: failed to listen!");
            break;
        }
        bFlag = true;
    } while (0);
    if (!bFlag) {
        close(serverSockfd);
        serverSockfd = -1;
        return ErrCode::WIFI_OPT_FAILED;
    }
    return ErrCode::WIFI_OPT_SUCCESS;
}

ErrCode StaDhcpServer::CheckDhcpInfo(int &dhcpResultIndex)
{
    if (mReceive.iptype > StaIpType::IPTYPE_IPV6) {
        LOGE("CheckDhcpInfo ip type error\n");
        dhcpResultIndex = StaIpType::IPTYPE_IPV4;
        return ErrCode::WIFI_OPT_FAILED;
    } else if (mReceive.iptype == StaIpType::IPTYPE_IPV4) {
        LOGE("CheckDhcpInfo ip type ipv4\n");
        dhcpResultIndex = StaIpType::IPTYPE_IPV4;
    } else {
        LOGE("CheckDhcpInfo ip type ipv6\n");
        dhcpResultIndex = StaIpType::IPTYPE_IPV6;
    }

    if (mReceive.datasize != (sizeof(mReceive.iptype) + strlen(mReceive.ip) + strlen(mReceive.gateway) +
        strlen(mReceive.subnet) + strlen(mReceive.dns) + sizeof(mReceive.leasetime))) {
        LOGE("CheckDhcpInfo datasize error\n");
        return ErrCode::WIFI_OPT_FAILED;
    }

    return ErrCode::WIFI_OPT_SUCCESS;
}

void StaDhcpServer::EnableIpv6() const
{
    std::vector<std::string> enableIpv6Cmd;
    enableIpv6Cmd.clear();
    enableIpv6Cmd.push_back(SYSTEM_COMMAND_ECHO);
    enableIpv6Cmd.push_back(SYSTEM_COMMAND_IPV6_ALL_PATH);
    IfConfig::GetInstance().ExecCommand(enableIpv6Cmd);

    enableIpv6Cmd.clear();
    enableIpv6Cmd.push_back(SYSTEM_COMMAND_ECHO);
    enableIpv6Cmd.push_back(SYSTEM_COMMAND_IPV6_WLAN0_PATH);
    IfConfig::GetInstance().ExecCommand(enableIpv6Cmd);

    enableIpv6Cmd.clear();
    enableIpv6Cmd.push_back(SYSTEM_COMMAND_ECHO);
    enableIpv6Cmd.push_back(SYSTEM_COMMAND_IPV6_DEFAULT_PATH);
    IfConfig::GetInstance().ExecCommand(enableIpv6Cmd);
}

void StaDhcpServer::StartDhcpClient()
{
    /* Enable IPv6. */
    EnableIpv6();

    /* The subprocess starts the DHCP_CLIENT_FILE process. */
    if (execv(args[0], const_cast<char *const *>(args))) {
        LOGE("execv %s failed!\n", args[0]);
    }
    _exit(-1);
}

void StaDhcpServer::CreateSocketServer()
{
    int clientSockfd, dhcpResultIndex;
    struct sockaddr_un clientAddr;
    socklen_t clientLen = sizeof(clientAddr);

    for (int index = 0; index < ipNumber; index++) {
        clientSockfd = accept(serverSockfd, (struct sockaddr *)&clientAddr, &clientLen);
        if (clientSockfd == -1) {
            LOGE("startDhcpClient accept failed\n");
            continue;
        }

        if (memset_s(&mReceive, sizeof(Packet), 0, sizeof(Packet)) != EOK) {
            close(clientSockfd);
            continue;
        }
        if (read(clientSockfd, &mReceive, sizeof(Packet)) < 0) {
            close(clientSockfd);
            continue;
        }

        if (CheckDhcpInfo(dhcpResultIndex) != 0) {
            close(clientSockfd);
            continue;
        }

        if (dhcpResultIndex <= 0) {
            close(clientSockfd);
            continue;
        }

        /* Notification state machine */
        result[dhcpResultIndex].isOptSuc = true;
        result[dhcpResultIndex].ip = mReceive.ip;
        result[dhcpResultIndex].iptype = mReceive.iptype;
        result[dhcpResultIndex].gateWay = mReceive.gateway;
        result[dhcpResultIndex].subnet = mReceive.subnet;
        if (dhcpResultIndex == static_cast<int>(StaIpType::IPTYPE_IPV4)) {
            result[dhcpResultIndex].dns = IPV4_DNS1;
            result[dhcpResultIndex].dns2 = IPV4_DNS2;
        } else {
            result[dhcpResultIndex].dns = IPV6_DNS1;
            result[dhcpResultIndex].dns2 = IPV6_DNS1;
        }
        close(clientSockfd);
    }

    KillDhcpClient();
}

ErrCode StaDhcpServer::ForkForDhcp()
{
    pid_t pid = fork();
    if (pid < 0) {
        LOGE("In StaDhcpServer fork failed.");
        return ErrCode::WIFI_OPT_FAILED;
    } else if (pid == 0) {
        StartDhcpClient();
    } else {
        CreateSocketServer();
    }
    return ErrCode::WIFI_OPT_SUCCESS;
}

void StaDhcpServer::KillDhcpClient() const
{
    FILE *pp = popen("./dhcpc -x", "r");
    if (pp == nullptr) {
        LOGE("In StaDhcpServer openDhcpClient popen failed!\n");
        return;
    }

    pclose(pp);
    pp = nullptr;
}

ErrCode StaDhcpServer::InitDhcpThread()
{
    pDealDhcpThread = new (std::nothrow)std::thread(&StaDhcpServer::RunDhcpThreadFunc, this);
    if (pDealDhcpThread == nullptr) {
        LOGE("In StaDhcpServer create message start Dhcp server thread failed!");
        return ErrCode::WIFI_OPT_FAILED;
    }
    return ErrCode::WIFI_OPT_SUCCESS;
}

void StaDhcpServer::SignalDhcpThread(int ipType)
{
    mIpType = ipType;
    std::unique_lock<std::mutex> lck(mMutex);
    isWakeDhcp = true;
    mCondition.notify_one();
}

void StaDhcpServer::ExitDhcpThread()
{
    {
        std::unique_lock<std::mutex> lck(mMutex);
        isWakeDhcp = true;
        isExitDhcpThread = true;
        mCondition.notify_one();
    }

    if (serverSockfd >= 0) {
        close(serverSockfd);
        serverSockfd = -1;
    }

    if (pDealDhcpThread != nullptr) {
        pDealDhcpThread->join();
        delete pDealDhcpThread;
        pDealDhcpThread = nullptr;
    }
}
}  // namespace Wifi
}  // namespace OHOS