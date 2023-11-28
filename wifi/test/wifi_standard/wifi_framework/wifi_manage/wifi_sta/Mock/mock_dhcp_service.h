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
#ifndef OHOS_MOCK_DHCPSERVICE_H
#define OHOS_MOCK_DHCPSERVICE_H
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "dhcp_c_api.h"

namespace OHOS {
namespace Wifi {
class DhcpService {
public:
    DhcpService() = default;
    ~DhcpService() = default;
    
    int RegisterDhcpClientCallBack(const char *ifname, const ClientCallBack *event);
    int StartDhcpClient(const char *ifname, bool bIpv6);
    int StopDhcpClient(const char *ifname, bool bIpv6);
    int RenewDhcpClient(const char *ifname);

    int RegisterDhcpServerCallBack(const char *ifname, const ServerCallBack *event);
    int StartDhcpServer(const char *ifname);
    int StopDhcpServer(const char *ifname);
    int PutDhcpRange(const char *tagName, const DhcpRange *range);
    int RemoveDhcpRange(const char *tagName, const DhcpRange *range);
    int RemoveAllDhcpRange(const char *tagName);
    int SetDhcpRange(const char *ifname, const DhcpRange *range);
    int SetDhcpName(const char *ifname, const char *tagName);
    int GetDhcpClientInfos(const char *ifname, int staNumber, DhcpStationInfo *staInfo, int *staSize);
    int UpdateLeasesTime(const char *leaseTime);
};
}  // namespace Wifi
}  // namespace OHOS
#endif
