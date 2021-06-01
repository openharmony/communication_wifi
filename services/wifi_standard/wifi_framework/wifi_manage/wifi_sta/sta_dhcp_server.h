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
#ifndef OHOS_WIFI_DHCP_SERVER_H
#define OHOS_WIFI_DHCP_SERVER_H

#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <cstdlib>
#include <iostream>
#include <vector>
#include <memory>
#include <condition_variable>
#include <mutex>
#include <thread>
#include "wifi_errcode.h"
#include "wifi_log.h"
#include "sta_define.h"

#define SOCKFD_PATH "/data/dhcp/sta_dhcp.sock"
#define DHCP_CLIENT_FILE "./dhcpc"

const std::string SYSTEM_COMMAND_ECHO = "echo 0 >";
const std::string SYSTEM_COMMAND_IPV6_ALL_PATH = "/proc/sys/net/ipv6/conf/all/disable_ipv6";
const std::string SYSTEM_COMMAND_IPV6_WLAN0_PATH = "/proc/sys/net/ipv6/conf/wlan0/disable_ipv6";
const std::string SYSTEM_COMMAND_IPV6_DEFAULT_PATH = "/proc/sys/net/ipv6/conf/default/disable_ipv6";

static const int MAX_LISTEN = 2;
static const int IPTYPE_SIZE = 20;
static const int GETIP_SIZE = 64;
static const int GATEWAY_SIZE = 64;
static const int SUBNET_SIZE = 64;
static const int DNS_SIZE = 64;
static const int INIT_CRC = 0x0000;
static const int DEFAULT_BIT = 8;
static const int DHCP_ACCEPT_DELAY = 3;

namespace OHOS {
namespace Wifi {
class Packet {
public:
    Packet()
    {
        iptype = 0;
        datasize = 0;
        check = 0;
        leasetime = 0;
    }

    ~Packet()
    {}

    unsigned char iptype;
    unsigned short datasize;
    unsigned short check;
    unsigned int leasetime;
    char ip[GETIP_SIZE] = {0};
    char gateway[GATEWAY_SIZE] = {0};
    char subnet[SUBNET_SIZE] = {0};
    char dns[DNS_SIZE] = {0};
};

class StaDhcpServer {
public:
    explicit StaDhcpServer(DhcpResultHandler handler);
    ~StaDhcpServer();
    /**
     * @Description  Start a thread.
     *
     * @Return success:0 failed:-1
     */
    ErrCode InitDhcpThread();
    /**
     * @Description : wake up the DHCP processing thread.
     *
     * @param ipType - Type of IP to be obtained [in]
     */
    void SignalDhcpThread(int ipType);

    DhcpResultHandler dhcpResultHandler;

private:
    Packet mReceive;
    std::thread *pDealDhcpThread;
    int mIpType;
    int serverSockfd;
    char *args[3];
    DhcpResult result;
    int ipNumber;
    /**
     * @Description  Thread execution function
     *
     */
    void RunDhcpThreadFunc();
    /**
     * @Description : Set the Dhcp Param.
     *
     */
    void SetDhcpParam();
    /**
     * @Description  Setting Socket Listening on the Socket Server
     *
     * @Return success : WIFI_OPT_SUCCESS, failed : WIFI_OPT_FAILED
     */
    ErrCode StartDhcpServer();
    /**
     * @Description  Verify DHCP transmission information.
     *
     * @param dhcpResultIndex - Structure array subscript 0:ipv4 1:ipv6 [in]
     * @Return success : WIFI_OPT_SUCCESS, failed : WIFI_OPT_FAILED
     */
    ErrCode CheckDhcpInfo(int &dhcpResultIndex);
    /**
     * @Description  Enable ipv6
     *
     */
    void EnableIpv6() const;
    /**
     * @Description  Create Socket Server and receives messages such as
     *               DHCP IP address, subnet mask, gateway, and DNS.
     */
    void CreateSocketServer();
    /**
     * @Description  fork a process
     *
     * @Return success: WIFI_OPT_SUCCESS, failed : WIFI_OPT_FAILED
     */

    ErrCode ForkForDhcp();
    /**
     * @Description  Starts the DHCP client program
     */
    void StartDhcpClient();
    /**
     * @Description  Kill the DHCP client program.
     *
     */
    void KillDhcpClient() const;
    /**
     * @Description  Exit the DHCP thread. Releasing Thread Resources on the DHCP Server.
     *
     */
    void ExitDhcpThread();

private:
    std::mutex mMutex;
    std::condition_variable mCondition;
    /* Wakeup flag */
    bool isWakeDhcp;
    /* exit the thread flag */
    bool isExitDhcpThread;
};
}  // namespace Wifi
}  // namespace OHOS
#endif