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
#include "mock_dhcp_service.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_DHCP_LABEL("DhcpService");

namespace OHOS {
namespace Wifi {

int DhcpService::RegisterDhcpClientCallBack(const char *ifname, const ClientCallBack *event)
{
    WIFI_LOGD("Enter DhcpService::[%{public}s].ifname:%{public}s", __FUNCTION__, ifname);
    return 0;
}

int DhcpService::StartDhcpClient(const char *ifname, bool bIpv6)
{
    WIFI_LOGD("Enter DhcpService::[%{public}s].ifname:%{public}s, isIpv6:%{public}d", __FUNCTION__, ifname,
        bIpv6);
    return 0;
}

int DhcpService::StopDhcpClient(const char *ifname, bool bIpv6)
{
    WIFI_LOGD("Enter DhcpService::[%{public}s].ifname:%{public}s, isIpv6:%{public}d", __FUNCTION__, ifname,
        bIpv6);
    return 0;
}

int DhcpService::RenewDhcpClient(const char *ifname)
{
    WIFI_LOGD("Enter DhcpService::[%{public}s].ifname:%{public}s", __FUNCTION__, ifname);
    return 0;
}

int DhcpService::RegisterDhcpServerCallBack(const char *ifname, const ServerCallBack *event)
{
    WIFI_LOGD("Enter DhcpService::[%{public}s].ifname:%{public}s", __FUNCTION__, ifname);
    return 0;
}

int DhcpService::StartDhcpServer(const char *ifname)
{
    WIFI_LOGD("Enter DhcpService::[%{public}s].ifname:%{public}s", __FUNCTION__, ifname);
    return 0;
}

int DhcpService::StopDhcpServer(const char *ifname)
{
    WIFI_LOGD("Enter DhcpService::[%{public}s].ifname:%{public}s", __FUNCTION__, ifname);
    return 0;
}

int DhcpService::PutDhcpRange(const char *tagName, const DhcpRange *range)
{
    WIFI_LOGD("Enter DhcpService::[%{public}s]", __FUNCTION__);
    return 0;
}

int DhcpService::RemoveDhcpRange(const char *tagName, const DhcpRange *range)
{
    WIFI_LOGD("Enter DhcpService::[%{public}s]", __FUNCTION__);
    return 0;
}

int DhcpService::RemoveAllDhcpRange(const char *tagName)
{
    WIFI_LOGD("Enter DhcpService::[%{public}s].tagName:%{public}s", __FUNCTION__, tagName);
    return 0;
}

int DhcpService::SetDhcpRange(const char *ifname, const DhcpRange *range)
{
    WIFI_LOGD("Enter DhcpService::[%{public}s]", __FUNCTION__);
    return 0;
}

int DhcpService::GetDhcpClientInfos(const char *ifname, int staNumber, DhcpStationInfo *staInfo, int *staSize)
{
    WIFI_LOGD("Enter DhcpService::[%{public}s].ifname:%{public}s", __FUNCTION__, ifname);
    return 0;
}

int DhcpService::UpdateLeasesTime(const char *leaseTime)
{
    WIFI_LOGD("Enter DhcpService::[%{public}s].", __FUNCTION__);
    return 0;
}
} // namespace Wifi
} // namespace OHOS
