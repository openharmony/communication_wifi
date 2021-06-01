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
#ifndef OHOS_WIFI_DHCP_INTERFACE_H
#define OHOS_WIFI_DHCP_INTERFACE_H

#include <functional>
#include <string>
#include <sys/types.h>
#include <thread>
#include "ap_macro.h"
#include "ipv4_address.h"
#include "ipv6_address.h"
#include "mac_address.h"
#include "wifi_msg.h"

#define INIT_CRC 0x0000
#define CR_C16_POLYNOMIAL 0xA001

#define IP_V4 1
#define IP_V6 2
#define DEVICE_NAME_LEN 128
#define MAC_ADDR_MAX_LEN 64
#define IP_ADDR_MAX_LEN 64

/* Calculate the network number form the IP address and mask. */
#define CALC_SUBNET(IPADD, MASK) ((IPADD) & (MASK))

namespace OHOS {
namespace Wifi {
class WifiApDhcpInterface {
public:
    using DhcpCallback = std::function<void(StationInfo &staInfo)>;

    /**
     * @Description  Obtains the single instance
     * @param None
     * @return The reference of singleton objects
     */
    static WifiApDhcpInterface &GetInstance();
    /**
     * @Description  Delete the single instance.
     * @param None
     * @return None
     */
    static void DeleteInstance();
    /**
     * @Description  Start the DHCP server and pass the IP address.
     * @param hotspotInterface - Network Interfaces Used
     * @param maxConn - Maximum number of allowed connections
     * @param vecIpv4Addr - The ipv4 network that needs to be avoided by DHCP to avoid
                            duplicate when the network is used with STAs.
     * @param vecIpv6Addr - The ipv6 network that needs to be avoided by DHCP to avoid
                            duplicate when the network is used with STAs.
     * @param isIpV4 - Is an ipv4 network
     * @return true: success   false: failed
     */
    bool StartDhcpServer(const std::string hotspotInterface, const int32_t maxConn,
        const std::vector<Ipv4Address> &vecIpv4Addr, const std::vector<Ipv6Address> &vecIpv6Addr, bool isIpV4 = true);
    /**
     * @Description  Stop the DHCP server.
     * @param None
     * @return true: success      false: failed
     */
    bool StopDhcpServer();

    /**
     * @Description  Registers callback when the DHCP server
                     proactively sends data.
     * @param callback - Callback function pointer
     * @return None
     */
    void RegisterApCallback(DhcpCallback callback);

    /**
     * @Description  Get dhcp server process id.
     * @param None
     * @return dhcp server process id
     */
    pid_t GetDhcpPid() const;

private:
    WifiApDhcpInterface();
    ~WifiApDhcpInterface();
    DISALLOW_COPY_AND_ASSIGN(WifiApDhcpInterface)

    /**
     * @Description  Register the SIGCHID signal and receive the DHCP status.
     * @param None
     * @return None
     */
    void RegisterSignal() const;

    /**
     * @Description  Deregisters the SIGCHID signal
     * @param None
     * @return None
     */
    void UnregisterSignal() const;

    /**
     * @Description  connect with DHCP when it is start
     * @param None
     * @return true: success    false: failed
     */
    bool CreateListen();

    /**
     * @Description  Disconnect with DHCP
     * @param None
     * @return true: success    false: failed
     */
    bool DestroyListen();

    /**
     * @Description  Independent thread of processing DHCP msg
     * @param None
     * @return None
     */
    void DealListen() const;

    /**
     * @Description  Check whether the IP addresses are the same.
     * @param vecIpAddr - IPV4 Addresses vector.
     * @param ifcSubNetInAddr - IP address to be compared
     * @return true: Same    false: Without
     */
    bool CompareSubNet(const std::vector<Ipv4Address> &vecIpAddr, const struct in_addr &ifcSubNetInAddr,
        const struct in_addr &maskInAddr) const;

    /**
     * @Description  Returns the allocated IPV4 address with the parameters.
     * @param vecIpAddr - IPV4 Addresses to be avoided
     * @param mask - Network mask
     * @return success: Valid IP Address    failed: Ipv4Address::INVALID_INET_ADDRESS
     */
    Ipv4Address AssignIpAddrV4(const std::vector<Ipv4Address> &vecIpAddr, const std::string &mask) const;

    /**
     * @Description  Returns the allocated IPV6 address with the parameters.
     * @param vecIpAddr - IPV6 Addresses to be avoided
     * @return success: Valid IP Address    failed: Ipv6Address::INVALID_INET6_ADDRESS
     */
    Ipv6Address AssignIpAddrV6(const std::vector<Ipv6Address> &vecIpAddr);

    /**
     * @Description  Returns the allocated IP.
     * @param ipv4 - IPV4 Address
     * @param ipv6 - IPV6 Address
     * @param vecIpv4Addr - The ipv4 network that needs to be avoided by DHCP to avoid
                            duplicate when the network is used with STAs.
     * @param vecIpv6Addr - The ipv6 network that needs to be avoided by DHCP to avoid
                            duplicate when the network is used with STAs.
     * @param isIpV4 - Is an ipv4 network
     * @return success: Valid IP Address    failed: Ipv6Address::INVALID_INET6_ADDRESS
     */
    bool AssignIpAddr(Ipv4Address &ipv4, Ipv6Address &ipv6, const std::vector<Ipv4Address> &vecIpv4Addr,
        const std::vector<Ipv6Address> &vecIpv6Addr, bool isIpV4);

    /**
     * @Description  Apply the IP address with the interface.
     * @param hotspotInterface - Network Interfaces Used
     * @param ipv4 - IPV4 Address
     * @param ipv6 - IPV6 Address
     * @return true: Success    false: Failed
     */
    bool ApplyIpAddress(const std::string hotspotInterface, const Ipv4Address &ipv4, const Ipv6Address &ipv6);

    /**
     * @Description  Fork process function for register or process signals.
     * @param None
     * @return true: Success    false: Failed
     */
    bool ForkParentProcess();

    /**
     * @Description  Fork process function for start dhcp process.
     * @param hotspotInterface - Network Interfaces Used
     * @param maxConn - Maximum number of allowed connections
     * @param ifcIp - IP for interface
     * @param ifcIp - ipMask for IP
     * @param isIpV4 - IP Version
     * @return true: Success    false: Failed
     */
    bool ForkExecProcess(const std::string hotspotInterface, const int32_t maxConn, const std::string ifcIp,
        const std::string ipMask, bool isIpV4);

private:
    using ClientInfo = struct ClientInfo {
        unsigned short len;             /* check + macAddr + ipAddr + ipType Bytes */
        unsigned short check;           /* Check：macAddr + ipAddr + ipType */
        char name[DEVICE_NAME_LEN];     /* Client name */
        char macAddr[MAC_ADDR_MAX_LEN]; /* Client mac */
        char ipAddr[IP_ADDR_MAX_LEN];   /* Client ip */
        unsigned char ipType;           /* IPv4 IPv6 */
    };

    /**
     * @Description  Processing thread to report client information.
     * @param pClient - Client information struct point.
     * @return None
     */
    void DealClientReport(ClientInfo *pClient) const;

    /**
     * @Description  Processing thread to read DHCP msg.
     * @param clientSockfd - Client socket file descriptor.
     * @return None
     */
    void DealReadHandle(int clientSockfd) const;

private:
    std::vector<std::string> mUseIfc; /* Used Interface */
    int mFdSocketListen;              /* Socket fd */
    pid_t mPidDhcp;                   /* DHCP server PID */
    std::thread *mPDealDhcpThread;    /* DHCP message processing thread */
    DhcpCallback mDhcpCallback;       /* Event callback object */
    static WifiApDhcpInterface *g_instance;
};
}  // namespace Wifi
}  // namespace OHOS

#endif