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

DEFINE_WIFILOG_DHCP_LABEL("MockDhcpService");

using namespace OHOS::Wifi;


MockDhcpService &MockDhcpService::GetInstance()
{
    static MockDhcpService gMockDhcpService;
    return gMockDhcpService;
};

MockDhcpService::MockDhcpService() {}

MockDhcpService::~MockDhcpService() {}


extern "C" {
DhcpErrorCode __real_RegisterDhcpClientCallBack(const char *ifname, const ClientCallBack *event);
DhcpErrorCode __wrap_RegisterDhcpClientCallBack(const char *ifname, const ClientCallBack *event)
{
    WIFI_LOGI("SUN MockDhcpService::RegisterDhcpClientCallBackl");
    return MockDhcpService::GetInstance().RegisterDhcpClientCallBack(ifname, event);
}

DhcpErrorCode __real_StartDhcpClient(const char *ifname, bool bIpv6);
DhcpErrorCode __wrap_StartDhcpClient(const char *ifname, bool bIpv6)
{
    WIFI_LOGI("SUN MockDhcpService::StartDhcpClient");
    return MockDhcpService::GetInstance().StartDhcpClient(ifname, bIpv6);
}

DhcpErrorCode __real_StopDhcpClient(const char *ifname, bool bIpv6);
DhcpErrorCode __wrap_StopDhcpClient(const char *ifname, bool bIpv6)
{
    WIFI_LOGI("SUN MockDhcpService::StopDhcpClient");
    return MockDhcpService::GetInstance().StopDhcpClient(ifname, bIpv6);
}

DhcpErrorCode __real_RenewDhcpClient(const char *ifname);
DhcpErrorCode __wrap_RenewDhcpClient(const char *ifname)
{
    WIFI_LOGI("SUN MockDhcpService::RenewDhcpClient");
    return MockDhcpService::GetInstance().RenewDhcpClient(ifname);
}

DhcpErrorCode __real_RegisterDhcpServerCallBack(const char *ifname, const ServerCallBack *event);
DhcpErrorCode __wrap_RegisterDhcpServerCallBack(const char *ifname, const ServerCallBack *event)
{
    WIFI_LOGI("SUN MockDhcpService::RegisterDhcpServerCallBack");
    return MockDhcpService::GetInstance().RegisterDhcpServerCallBack(ifname, event);
}

DhcpErrorCode __real_StartDhcpServer(const char *ifname);
DhcpErrorCode __wrap_StartDhcpServer(const char *ifname)
{
    WIFI_LOGI("SUN MockDhcpService::StartDhcpServer");
    return MockDhcpService::GetInstance().StartDhcpServer(ifname);
}

DhcpErrorCode __real_StopDhcpServer(const char *ifname);
DhcpErrorCode __wrap_StopDhcpServer(const char *ifname)
{
    WIFI_LOGI("SUN MockDhcpService::StopDhcpServer");
    return MockDhcpService::GetInstance().StopDhcpServer(ifname);
}

DhcpErrorCode __real_SetDhcpRange(const char *ifname, const DhcpRange *range);
DhcpErrorCode __wrap_SetDhcpRange(const char *ifname, const DhcpRange *range)
{
    WIFI_LOGI("SUN MockDhcpService::SetDhcpRange");
    return MockDhcpService::GetInstance().SetDhcpRange(ifname, range);
}

DhcpErrorCode __real_SetDhcpName(const char *ifname, const char *tagName);
DhcpErrorCode __wrap_SetDhcpName(const char *ifname, const char *tagName)
{
    WIFI_LOGI("SUN MockDhcpService::SetDhcpName");
    return MockDhcpService::GetInstance().SetDhcpName(ifname, tagName);
}

DhcpErrorCode __real_PutDhcpRange(const char *tagName, const DhcpRange *range);
DhcpErrorCode __wrap_PutDhcpRange(const char *tagName, const DhcpRange *range)
{
    WIFI_LOGI("SUN MockDhcpService::PutDhcpRange");
    return MockDhcpService::GetInstance().PutDhcpRange(tagName, range);
}

DhcpErrorCode __real_RemoveAllDhcpRange(const char *tagName);
DhcpErrorCode __wrap_RemoveAllDhcpRange(const char *tagName)
{
    WIFI_LOGI("SUN MockDhcpService::RemoveAllDhcpRange");
    return MockDhcpService::GetInstance().RemoveAllDhcpRange(tagName);
}

DhcpErrorCode __real_RemoveDhcpRange(const char *tagName, const void *range);
DhcpErrorCode __wrap_RemoveDhcpRange(const char *tagName, const void *range)
{
    WIFI_LOGI("SUN MockDhcpService::RemoveDhcpRange");
    return MockDhcpService::GetInstance().RemoveDhcpRange(tagName, range);
}

DhcpErrorCode __real_GetDhcpClientInfos(const char *ifname, int staNumber, DhcpStationInfo *staInfo, int *staSize);
DhcpErrorCode __wrap_GetDhcpClientInfos(const char *ifname, int staNumber, DhcpStationInfo *staInfo, int *staSize)
{
    WIFI_LOGI("SUN MockDhcpService::GetDhcpClientInfos");
    return MockDhcpService::GetInstance().GetDhcpClientInfos(ifname, staNumber, staInfo,  staSize);
}

DhcpErrorCode __real_UpdateLeasesTime(const char *leaseTime);
DhcpErrorCode __wrap_UpdateLeasesTime(const char *leaseTime)
{
    WIFI_LOGI("SUN MockDhcpService::UpdateLeasesTime");
    return MockDhcpService::GetInstance().UpdateLeasesTime(leaseTime);
}
}