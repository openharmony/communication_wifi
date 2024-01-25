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
class MockDhcpService {
public:
    MOCK_METHOD2(RegisterDhcpClientCallBack, DhcpErrorCode(const char *ifname, const ClientCallBack *event));
    MOCK_METHOD2(StartDhcpClient, DhcpErrorCode(const char *ifname, bool bIpv6));
    MOCK_METHOD2(StopDhcpClient, DhcpErrorCode(const char *ifname, bool bIpv6));
    MOCK_METHOD1(RenewDhcpClient, DhcpErrorCode(const char *ifname));
    MOCK_METHOD2(RegisterDhcpServerCallBack, DhcpErrorCode(const char *ifname, const ServerCallBack *event));
    MOCK_METHOD1(StartDhcpServer, DhcpErrorCode(const char *ifname));
    MOCK_METHOD1(StopDhcpServer, DhcpErrorCode(const char *ifname));
    MOCK_METHOD2(PutDhcpRange, DhcpErrorCode(const char *tagName, const DhcpRange *range));
    MOCK_METHOD2(RemoveDhcpRange, DhcpErrorCode(const char *tagName, const void *range));
    MOCK_METHOD1(RemoveAllDhcpRange, DhcpErrorCode(const char *tagName));
    MOCK_METHOD2(SetDhcpRange, DhcpErrorCode(const char *ifname, const DhcpRange *range));
    MOCK_METHOD2(SetDhcpName, DhcpErrorCode(const char *ifname, const char *tagName));
    MOCK_METHOD4(GetDhcpClientInfos, DhcpErrorCode(const char *ifname, int staNumber, DhcpStationInfo *staInfo, int *staSize));
    MOCK_METHOD1(UpdateLeasesTime, DhcpErrorCode(const char *leaseTime));

    static MockDhcpService &GetInstance();
private:
    MockDhcpService();
    ~MockDhcpService();
};
}  // namespace Wifi
}  // namespace OHOS
#endif
