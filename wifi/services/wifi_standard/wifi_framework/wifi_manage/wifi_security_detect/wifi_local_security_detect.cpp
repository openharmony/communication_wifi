/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "wifi_local_security_detect.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_settings.h"
#include "wifi_hisysevent.h"
#include "netsys_controller.h"

namespace OHOS {
namespace Wifi {
using namespace NetManagerStandard;
DEFINE_WIFILOG_LABEL("WifiLocalSecurityDetect");

WifiLocalSecurityDetect::WifiLocalSecurityDetect()
{
    staCallback_.callbackModuleName = "WifiLocalSecurityDetect";
    staCallback_.OnStaConnChanged = [this](OperateResState state, const WifiLinkedInfo &linkedInfo, int32_t instId) {
        this->DealStaConnChanged(state, linkedInfo, instId);
    };
    RegisterDnsResultCallback();
}

WifiLocalSecurityDetect::~WifiLocalSecurityDetect()
{
    UnRegisterDnsResultCallback();
}

void WifiLocalSecurityDetect::RegisterDnsResultCallback()
{
    dnsResultCallback_ = sptr<LocalSecurityDetectDnsResultCallback>::MakeSptr();
    int32_t ret = NetsysController::GetInstance().RegisterDnsResultCallback(dnsResultCallback_, 0);
    WIFI_LOGI("WifiLocalSecurityDetect::RegisterDnsResultCallback result = %{public}d", ret);
}

void WifiLocalSecurityDetect::UnRegisterDnsResultCallback()
{
    if (dnsResultCallback_ != nullptr) {
        NetsysController::GetInstance().UnregisterDnsResultCallback(dnsResultCallback_);
    }
}

WifiLocalSecurityDetect &WifiLocalSecurityDetect::GetInstance()
{
    static WifiLocalSecurityDetect securityWifi;
    return securityWifi;
}

void WifiLocalSecurityDetect::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &linkedInfo, int instId)
{
    std::unique_lock<std::mutex> lock(localDetectMutex_);
    // record canAccessInternetThroughWifi_ status
    if (state == OperateResState::CONNECT_NETWORK_ENABLED) {
        canAccessInternetThroughWifi_ = true;
    } else {
        canAccessInternetThroughWifi_ = false;
    }
    if (state == OperateResState::CONNECT_AP_CONNECTED) {
        HandleWifiConnected(linkedInfo);
    } else if (state == OperateResState::DISCONNECT_DISCONNECTED) {
        HandleWifiDisconnected(linkedInfo);
    } else {
        return;
    }
}

void WifiLocalSecurityDetect::SetApInfo(const WifiLinkedInfo &linkedInfo)
{
    apInfo_.ssid = linkedInfo.ssid;
    apInfo_.bssid = linkedInfo.bssid;
    apInfo_.frequency = linkedInfo.frequency;
    apInfo_.band = linkedInfo.band;
    apInfo_.rssi = linkedInfo.rssi;
}

void WifiLocalSecurityDetect::ResetApInfo()
{
    apInfo_.ssid = "";
    apInfo_.bssid = "";
    apInfo_.frequency = 0;
    apInfo_.band = -1;
    apInfo_.rssi = -1;
    apInfo_.cloudRiskType = static_cast<int>(WifiCloudRiskType::UNKNOWN);
}

void WifiLocalSecurityDetect::ReportWifiDnsHijackHiSysEvent(const std::string& domain)
{
    WifiRiskInfo wifiRiskInfo;
    wifiRiskInfo.riskType = static_cast<int>(WifiRiskInfoReason::WIFI_DNS_SPOOFING);
    wifiRiskInfo.hostName = domain;
    {
        std::lock_guard<std::mutex> lock(localDetectMutex_);
        wifiRiskInfo.ssid = apInfo_.ssid;
        wifiRiskInfo.bssid = apInfo_.bssid;
        wifiRiskInfo.frequency = apInfo_.frequency;
        wifiRiskInfo.band = apInfo_.band;
        wifiRiskInfo.rssi = apInfo_.rssi;
        wifiRiskInfo.cloudRiskType = apInfo_.cloudRiskType;
    }
    WriteWifiRiskInfoHiSysEvent(wifiRiskInfo);
}

void WifiLocalSecurityDetect::HandleWifiConnected(const WifiLinkedInfo & linkedInfo)
{
    currentUseNetworkId_ = linkedInfo.networkId;
    SetApInfo(linkedInfo);
    WifiDeviceConfig config;
    if (WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config) != 0) {
        WIFI_LOGE("%{public}s, not find networkId: %{public}d", __FUNCTION__, linkedInfo.networkId);
        return;
    }
    apInfo_.cloudRiskType = config.isSecureWifi ?
        static_cast<int>(WifiCloudRiskType::SAFE) : static_cast<int>(WifiCloudRiskType::UNSAFE);
    config.riskType = linkedInfo.riskType;
    WifiSettings::GetInstance().AddDeviceConfig(config);
    WifiSettings::GetInstance().SyncDeviceConfig();
    return;
}

void WifiLocalSecurityDetect::HandleWifiDisconnected(const WifiLinkedInfo & linkedInfo)
{
    currentUseNetworkId_ = -1;
    ResetApInfo();
    return;
}

StaServiceCallback WifiLocalSecurityDetect::GetStaCallback() const
{
    return staCallback_;
}

int32_t WifiLocalSecurityDetect::LocalSecurityDetectDnsResultCallback::OnDnsResultReport(uint32_t size,
    const std::list<NetDnsResultReport> netDnsResultReport)
{
    if (!WifiLocalSecurityDetect::GetInstance().canAccessInternetThroughWifi_) {
        WIFI_LOGI("DnsResultCallback failed because the visit is not through wifi...");
        return 1;
    }
    WifiLocalSecurityDetect::GetInstance().HandleDnsResultReport(netDnsResultReport);
    return 0;
}

void WifiLocalSecurityDetect::HandleDnsResultReport(const std::list<NetDnsResultReport>& dnsResultReport)
{
    if (dnsResultReport.empty()) {
        return;
    }
    for (auto& report : dnsResultReport) {
        const std::string& domain = report.host_;
        IpType currentIpType = HasPrivateIp(report.addrlist_) ? IpType::PRIVATE : IpType::PUBLIC;
        if (CheckPublicToPrivateTransition(domain, currentIpType)) {
            WIFI_LOGI("Potential dns hijack detected: Current Domain Ip type changed from public to private! \
                This may indicate a security issue.");
            ReportWifiDnsHijackHiSysEvent(domain);
        }
        AddRecordToDnsCache(domain, currentIpType);
    }
}

RecordDeque::iterator WifiLocalSecurityDetect::CheckDomainInDnsCache(const std::string& domain)
{
    for (auto it = domainHistoryCache_.begin(); it != domainHistoryCache_.end(); it++) {
        if (it->domain == domain) {
            return it;
        }
    }
    return domainHistoryCache_.end();
}

bool WifiLocalSecurityDetect::CheckPublicToPrivateTransition(const std::string& domain, IpType currentIpType)
{
    // 当前域名是公网，不可能存在劫持
    if (currentIpType == IpType::PUBLIC) {
        return false;
    }
    std::lock_guard<std::mutex> lock(localDetectMutex_);
    auto it = CheckDomainInDnsCache(domain);
    if (it == domainHistoryCache_.end()) {
        return false;
    }
    return it->ipType == IpType::PUBLIC && currentIpType == IpType::PRIVATE;
}

void WifiLocalSecurityDetect::AddRecordToDnsCache(const std::string& domain, IpType ipType)
{
    std::lock_guard<std::mutex> lock(localDetectMutex_);
    time_t now = time(nullptr);
    if (now - lastAddRecordTime_ > DOMAIN_STORE_CD) {
        UpdateDnsCache(domainHistoryCache_, domain, ipType);
        lastAddRecordTime_ = time(nullptr);
    }
}

void WifiLocalSecurityDetect::UpdateDnsCache(RecordDeque &records, const std::string& key, IpType ipType)
{
    bool found = false;
    for (auto it = records.begin(); it != records.end(); it++) {
        if (it->domain != key) {
            continue;
        }
        found = true;
        if (it->ipType != ipType) {
            it->ipType = ipType;
        }
        DomainRecord record = *it;
        records.erase(it);
        records.push_back(record);
        break;
    }
    if (!found) {
        records.emplace_back(DomainRecord{key, ipType});
    }
    if (records.size() > MAX_DNS_DOMAIN_RECORD_NUM) {
        records.pop_front();
    }
}

bool WifiLocalSecurityDetect::IsPrivateIp(const std::string& ip)
{
    // 尝试解析为Ipv4
    struct in_addr addr4;
    if (inet_pton(AF_INET, ip.c_str(), &addr4) == 1) {
        // ntohl
        uint32_t v = ntohl(addr4.s_addr);
        // 10.0.0.0/8
        if ((v & 0xFF000000u) == 0x0A000000u) {
            return true;
        }
        // 172.16.0.0/12 -> mask 0xFFF00000, network 0xAC100000
        if ((v & 0xFFF00000u) == 0xAC100000u) {
            return true;
        }
        // 192.168.0.0/16
        if ((v & 0xFFFF0000u) == 0xC0A80000u) {
            return true;
        }
        return false;
    }

    // 尝试解析为Ipv6
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, ip.c_str(), &addr6) == 1) {
        // 唯一本地地址 fc00::/7
        unsigned char first = addr6.s6_addr[0];
        if ((first & 0xFE) == 0xFC) {
            return true;
        }
        return false;
    }
    // 既不是合法Ipv4也不是合法Ipv6
    return false;
}

bool WifiLocalSecurityDetect::HasPrivateIp(const std::list<NetDnsResultAddrInfo> &addrList)
{
    for (const auto& addr : addrList) {
        if (IsPrivateIp(addr.addr_)) {
            return true;
        }
    }
    return false;
}

}  // namespace Wifi
}  // namespace OHOS