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

#ifndef OHOS_DHCPD_INTERFACE_H
#define OHOS_DHCPD_INTERFACE_H
#include <string>
#include <memory>
#include <map>
#include <functional>

#include "ipv4_address.h"
#include "ipv6_address.h"
#include "mac_address.h"
#include "wifi_ap_msg.h"
#include "dhcp_c_api.h"

#define IP_V4 0
#define IP_V6 1
#define IP_ADDR_MAX_LEN 64

/* Calculate the network number form the IP address and mask. */
#define CALC_SUBNET(IPADD, MASK) ((IPADD) & (MASK))

namespace OHOS {
namespace Wifi {
class DhcpdInterface {
public:
    /**
     * @Description Constructs object.
     */
    DhcpdInterface();

    /**
     * @Description Destructor methods.
     */
    ~DhcpdInterface();

    bool RegisterDhcpCallBack(const std::string &ifaceName, ServerCallBack &event);

    /**
     * @Description Start the DHCP server and pass the IP address.
     * @param ifaceName - Network Interface
     * @param ipv4 - The ipv4 address of interface
     * @param ipv6 - The ipv6 address of interface
     * @param ipAddress - The dhcp server address
     * @param isIpV4 - Is an ipv4 network
     * @return true: success   false: fail
     */
    bool StartDhcpServerFromInterface(const std::string &ifaceName, Ipv4Address &ipv4, Ipv6Address &ipv6,
        const std::string &ipAddress = "", bool isIpV4 = true, const int32_t &leaseTime = DHCP_LEASE_TIME);

    /**
     * @Description Stop the DHCP server.
     * @param ifaceName - Network Interface
     * @return true: success      false: fail
     */
    bool StopDhcp(const std::string &ifaceName);

    /**
     * @Description Get currently connected station info: ip address, device name
     *
     * @param ifaceName - Network Interface
     * @param result - Connected station info
     * @return true - success
     * @return false - fail
     */
    bool GetConnectedStationInfo(const std::string &ifaceName, std::map<std::string, StationInfo> &result);

private:
    bool SetDhcpIpRange(const std::string &ifaceName);
    bool CompareSubNet(
        const std::vector<Ipv4Address> &vecIpAddr, const struct in_addr &input, const struct in_addr &mask) const;
    Ipv4Address AssignIpAddrV4(const std::vector<Ipv4Address> &vecIpAddr, const std::string &mask,
        const std::string &ipAddress) const;
    Ipv6Address AssignIpAddrV6(const std::vector<Ipv6Address> &vecIpAddr);
    bool AssignIpAddr(Ipv4Address &ipv4, Ipv6Address &ipv6, const std::vector<Ipv4Address> &vecIpv4Addr,
        const std::vector<Ipv6Address> &vecIpv6Addr, const std::string &ipAddress, bool isIpV4);
    bool ApplyIpAddress(const std::string &ifaceName, const Ipv4Address &ipv4, const Ipv6Address &ipv6);
    bool UpdateDefaultConfigFile(const int32_t &leaseTime);
    bool CallAdapterSetRange(std::string &ipAddr, const std::string &ifaceName);
    bool GetConnectedStaInfo(const std::string &ifaceName, int staNumber, DhcpStationInfo *staInfos, int *staSize);
private:
    Ipv4Address mBindIpv4;
    Ipv6Address mBindIpv6;
    bool mStartDhcpServerFlag = false;
};
} // namespace Wifi
} // namespace OHOS
#endif