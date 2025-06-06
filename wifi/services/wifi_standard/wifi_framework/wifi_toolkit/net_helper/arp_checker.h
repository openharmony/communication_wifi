/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_ARP_CHECKER_H
#define OHOS_WIFI_ARP_CHECKER_H
#include "utils/include/dhcp_arp_checker.h"

namespace OHOS {
namespace Wifi {
class ArpChecker {
public:
    ArpChecker();
    ~ArpChecker();
    void Start(std::string& ifname, std::string& hwAddr, std::string& ipAddr, std::string& gateway);
    void Stop();
    bool DoArpCheck(int timeoutMillis, bool isFillSenderIp);
    bool DoArpCheck(int timeoutMillis, bool isFillSenderIp, uint64_t &timeCost);
    void GetGwMacAddrList(int32_t timeoutMillis, bool isFillSenderIp, std::vector<std::string>& gwMacLists);
private:
    DHCP::DhcpArpChecker m_dhcpArpChecker;
};
}
}
#endif
