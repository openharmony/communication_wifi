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
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <string>

#include "raw_socket.h"

namespace OHOS {
namespace Wifi {
constexpr int IPV4_ALEN = 4;

/* defined in RFC 826 */
struct ArpPacket {
    uint16_t ar_hrd; // hardware type
    uint16_t ar_pro; // protocol type
    uint8_t ar_hln; // length of hardware address
    uint8_t ar_pln; // length of protocol address
    uint16_t ar_op; // opcode
    uint8_t ar_sha[ETH_ALEN]; // sender hardware address
    uint8_t ar_spa[IPV4_ALEN]; // sender protocol address
    uint8_t ar_tha[ETH_ALEN]; // target hardware address
    uint8_t ar_tpa[IPV4_ALEN]; // target protocol address
} __attribute__ ((__packed__));

class ArpChecker {
public:
    ArpChecker(std::string& ifname, std::string& hwAddr, std::string& ipAddr);
    ~ArpChecker();
    bool DoArp(int& timeoutMillis, std::string& targetIp, bool& isFillSenderIp);
private:
    RawSocket rawSocket_;
    struct in_addr localIpAddr_;
    uint8_t localHwAddr_[ETH_ALEN];
    uint8_t l2Broadcast_[ETH_ALEN];
};
}
}
#endif
