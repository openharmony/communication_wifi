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

#include "arp_checker.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "ohwifi_arp_checker"

namespace OHOS {
namespace Wifi {
ArpChecker::ArpChecker()
{
}

ArpChecker::~ArpChecker()
{
}

void ArpChecker::Start(std::string& ifname, std::string& hwAddr, std::string& ipAddr, std::string& gateway)
{
    m_dhcpArpChecker.Start(ifname, hwAddr, ipAddr, gateway);
}

void ArpChecker::Stop()
{
    m_dhcpArpChecker.Stop();
}

bool ArpChecker::DoArpCheck(int timeoutMillis, bool isFillSenderIp)
{
    uint64_t timeCost;
    return DoArpCheck(timeoutMillis, isFillSenderIp, timeCost);
}

bool ArpChecker::DoArpCheck(int timeoutMillis, bool isFillSenderIp, uint64_t &timeCost)
{
    return m_dhcpArpChecker.DoArpCheck(timeoutMillis, isFillSenderIp, timeCost);
}
}
}
