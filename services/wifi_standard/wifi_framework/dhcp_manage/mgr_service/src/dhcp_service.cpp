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

#include "dhcp_service.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_DHCP_LABEL("DhcpService");

namespace OHOS {
namespace Wifi {
DhcpService::DhcpService() : m_pClientService(nullptr), m_pServerService(nullptr)
{
    WIFI_LOGI("DhcpService::DhcpService()...");
    DhcpClientServiceImpl::m_mapDhcpResult.clear();
    DhcpClientServiceImpl::m_mapDhcpInfo.clear();
}

DhcpService::~DhcpService()
{
    WIFI_LOGI("DhcpService::~DhcpService()...");
    DhcpClientServiceImpl::m_mapDhcpResult.clear();
    DhcpClientServiceImpl::m_mapDhcpInfo.clear();
}

int DhcpService::StartDhcpClient(const std::string& ifname, bool bIpv6)
{
    if (m_pClientService == nullptr) {
        m_pClientService = std::make_unique<DhcpClientServiceImpl>();
        if (m_pClientService == nullptr) {
            WIFI_LOGE("DhcpService::StartDhcpClient() std::make_unique<DhcpClientServiceImpl>() failed!");
            return DHCP_OPT_FAILED;
        }
    }

    return m_pClientService->StartDhcpClient(ifname, bIpv6);
}

int DhcpService::StopDhcpClient(const std::string& ifname, bool bIpv6)
{
    if (m_pClientService == nullptr) {
        m_pClientService = std::make_unique<DhcpClientServiceImpl>();
        if (m_pClientService == nullptr) {
            WIFI_LOGE("DhcpService::StopDhcpClient() std::make_unique<DhcpClientServiceImpl>() failed!");
            return DHCP_OPT_FAILED;
        }
    }

    return m_pClientService->StopDhcpClient(ifname, bIpv6);
}

int DhcpService::GetDhcpResult(const std::string& ifname, IDhcpResultNotify *pResultNotify, int timeouts)
{
    if (m_pClientService == nullptr) {
        WIFI_LOGE("DhcpService::GetDhcpResult() error, m_pClientService = nullptr!");
        return DHCP_OPT_FAILED;
    }

    return m_pClientService->GetDhcpResult(ifname, pResultNotify, timeouts);
}

int DhcpService::GetDhcpInfo(const std::string& ifname, DhcpServiceInfo& dhcp)
{
    if (m_pClientService == nullptr) {
        WIFI_LOGE("DhcpService::GetDhcpInfo() error, m_pClientService = nullptr!");
        return DHCP_OPT_FAILED;
    }

    return m_pClientService->GetDhcpInfo(ifname, dhcp);
}

int DhcpService::RenewDhcpClient(const std::string& ifname)
{
    if (m_pClientService == nullptr) {
        WIFI_LOGE("DhcpService::RenewDhcpClient() error, m_pClientService = nullptr!");
        return DHCP_OPT_FAILED;
    }

    return m_pClientService->RenewDhcpClient(ifname);
}

int DhcpService::ReleaseDhcpClient(const std::string& ifname)
{
    if (m_pClientService == nullptr) {
        WIFI_LOGE("DhcpService::ReleaseDhcpClient() error, m_pClientService = nullptr!");
        return DHCP_OPT_FAILED;
    }

    return m_pClientService->ReleaseDhcpClient(ifname);
}

int DhcpService::StartDhcpServer(const std::string& ifname)
{
    if (m_pServerService == nullptr) {
        m_pServerService = std::make_unique<DhcpServerServiceImpl>();
        if (m_pServerService == nullptr) {
            WIFI_LOGE("DhcpService::StartDhcpServer() std::make_unique<DhcpServerServiceImpl>() failed!");
            return DHCP_OPT_FAILED;
        }
    }

    return m_pServerService->StartDhcpServer(ifname);
}

int DhcpService::StopDhcpServer(const std::string& ifname)
{
    if (m_pServerService == nullptr) {
        m_pServerService = std::make_unique<DhcpServerServiceImpl>();
        if (m_pServerService == nullptr) {
            WIFI_LOGE("DhcpService::StopDhcpServer() std::make_unique<DhcpServerServiceImpl>() failed!");
            return DHCP_OPT_FAILED;
        }
    }

    return m_pServerService->StopDhcpServer(ifname);
}

int DhcpService::GetServerStatus()
{
    if (m_pServerService == nullptr) {
        WIFI_LOGE("DhcpService::GetServerStatus() error, m_pServerService = nullptr!");
        return DHCP_OPT_FAILED;
    }

    return m_pServerService->GetServerStatus();
}

int DhcpService::PutDhcpRange(const std::string& tagName, const DhcpRange& range)
{
    if (m_pServerService == nullptr) {
        WIFI_LOGE("DhcpService::PutDhcpRange() error, m_pServerService = nullptr!");
        return DHCP_OPT_FAILED;
    }

    return m_pServerService->PutDhcpRange(tagName, range);
}

int DhcpService::RemoveDhcpRange(const std::string& tagName, const DhcpRange& range)
{
    if (m_pServerService == nullptr) {
        WIFI_LOGE("DhcpService::RemoveDhcpRange() error, m_pServerService = nullptr!");
        return DHCP_OPT_FAILED;
    }

    return m_pServerService->RemoveDhcpRange(tagName, range);
}

int DhcpService::RemoveAllDhcpRange(const std::string& tagName)
{
    if (m_pServerService == nullptr) {
        WIFI_LOGE("DhcpService::RemoveAllDhcpRange() error, m_pServerService = nullptr!");
        return DHCP_OPT_FAILED;
    }

    return m_pServerService->RemoveAllDhcpRange(tagName);
}

int DhcpService::SetDhcpRange(const std::string& ifname, const DhcpRange& range)
{
    if (m_pServerService == nullptr) {
        WIFI_LOGE("DhcpService::SetDhcpRange() error, m_pServerService = nullptr!");
        return DHCP_OPT_FAILED;
    }

    return m_pServerService->SetDhcpRange(ifname, range);
}

int DhcpService::SetDhcpRange(const std::string& ifname, const std::string& tagName)
{
    if (m_pServerService == nullptr) {
        WIFI_LOGE("DhcpService::SetDhcpRange() error, m_pServerService = nullptr!");
        return DHCP_OPT_FAILED;
    }

    return m_pServerService->SetDhcpRange(ifname, tagName);
}

int DhcpService::GetLeases(std::vector<std::string>& leases)
{
    if (m_pServerService == nullptr) {
        WIFI_LOGE("DhcpService::GetLeases() error, m_pServerService = nullptr!");
        return DHCP_OPT_FAILED;
    }

    return m_pServerService->GetLeases(leases);
}

int DhcpService::GetDhcpSerProExit(const std::string& ifname, IDhcpResultNotify *pResultNotify)
{
    if (m_pServerService == nullptr) {
        WIFI_LOGE("DhcpService::GetDhcpSerProExit() error, m_pServerService = nullptr!");
        return DHCP_OPT_FAILED;
    }

    return m_pServerService->GetDhcpSerProExit(ifname, pResultNotify);
}
}  // namespace Wifi
}  // namespace OHOS