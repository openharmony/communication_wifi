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

#ifndef OHOS_MULTI_GATEWAY_H
#define OHOS_MULTI_GATEWAY_H

#include "arp_checker.h"
#include "singleton.h"

namespace OHOS {
namespace Wifi {
class MultiGateway {
public:
    MultiGateway();
    ~MultiGateway();
    static MultiGateway& GetInstance();
    void GetGatewayAddr(int32_t instId);
    bool IsMultiGateway();
    std::string GetGatewayIp();
    void GetNextGatewayMac(std::string& mac);
    int32_t SetStaticArp(const std::string& iface, const std::string& ipAddr, const std::string& macAddr);
    int32_t DelStaticArp(const std::string& iface, const std::string& ipAddr);
    int32_t GetGatewayNum(); // only called by selfcure thread
private:
    int32_t GetMacAddr(char *buff, const char *macAddr);
    int32_t DoArpItem(int32_t cmd, struct arpreq *req);
    std::vector<std::string> m_gwMacLists;
    uint32_t m_currentIdx;
    std::string m_gwIpAddr;
};
} // namespace Wifi
} // namespace OHOS
#endif