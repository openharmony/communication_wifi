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

#include "wifi_net_agent.h"
#include <cinttypes>
#include <algorithm>
#include "inet_addr.h"
#include "ip_tools.h"
#include "iservice_registry.h"
#include "netsys_native_service_proxy.h"
#include "net_conn_client.h"
#include "system_ability_definition.h"
#include "wifi_common_util.h"
#include "wifi_logger.h"
#include "wifi_config_center.h"
#include "ipv6_address.h"
#include "wifi_global_func.h"
#include "wifi_app_state_aware.h"

DEFINE_WIFILOG_LABEL("WifiNetAgent");

namespace OHOS {
namespace Wifi {
using namespace NetManagerStandard;

#define INVALID_SUPPLIER_ID 0

WifiNetAgent &WifiNetAgent::GetInstance()
{
    static WifiNetAgent gWifiNetAgent;
    return gWifiNetAgent;
}

WifiNetAgent::WifiNetAgent()
{
}
WifiNetAgent::~WifiNetAgent()
{
}

bool WifiNetAgent::RegisterNetSupplier()
{
    TimeStats timeStats(__func__);
    WIFI_LOGI("Enter RegisterNetSupplier.");

    std::string ident = "wifi";
    using NetManagerStandard::NetBearType;
    using NetManagerStandard::NetCap;
    std::set<NetCap> netCaps {NetCap::NET_CAPABILITY_INTERNET};
    if (supplierId != INVALID_SUPPLIER_ID) {
        WIFI_LOGI("RegisterNetSupplier supplierId alread exist.");
        return true;
    }
    int32_t result = NetConnClient::GetInstance().RegisterNetSupplier(NetBearType::BEARER_WIFI,
                                                                      ident, netCaps, supplierId);
    if (result == NETMANAGER_SUCCESS) {
        WIFI_LOGI("Register NetSupplier successful, supplierId is [%{public}d]", supplierId);
        return true;
    }
    WIFI_LOGI("Register NetSupplier failed");
    return false;
}

bool WifiNetAgent::RegisterNetSupplierCallback()
{
    TimeStats timeStats(__func__);
    WIFI_LOGI("Enter RegisterNetSupplierCallback.");
    sptr<NetConnCallback> pNetConnCallback = (std::make_unique<NetConnCallback>()).release();
    if (pNetConnCallback == nullptr) {
        WIFI_LOGE("pNetConnCallback is null\n");
        return false;
    }

    int32_t result = NetConnClient::GetInstance().RegisterNetSupplierCallback(supplierId, pNetConnCallback);
    if (result == NETMANAGER_SUCCESS) {
        WIFI_LOGI("Register NetSupplierCallback successful");
        return true;
    }
    WIFI_LOGE("Register NetSupplierCallback failed [%{public}d]", result);
    return false;
}

void WifiNetAgent::UnregisterNetSupplier()
{
    TimeStats timeStats(__func__);
    WIFI_LOGI("Enter UnregisterNetSupplier.");
    int32_t result = NetConnClient::GetInstance().UnregisterNetSupplier(supplierId);
    WIFI_LOGI("Unregister network result:%{public}d", result);
    supplierId = INVALID_SUPPLIER_ID;
}

void WifiNetAgent::UpdateNetSupplierInfo(const sptr<NetManagerStandard::NetSupplierInfo> &netSupplierInfo)
{
    TimeStats timeStats(__func__);
    WIFI_LOGI("Enter UpdateNetSupplierInfo.");
    int32_t result = NetConnClient::GetInstance().UpdateNetSupplierInfo(supplierId, netSupplierInfo);
    WIFI_LOGI("Update network result:%{public}d", result);
}

void WifiNetAgent::UpdateNetLinkInfo(IpInfo &wifiIpInfo, IpV6Info &wifiIpV6Info, WifiProxyConfig &wifiProxyConfig,
    int instId)
{
    TimeStats timeStats(__func__);
    WIFI_LOGI("Enter UpdateNetLinkInfo.");
    
    sptr<NetManagerStandard::NetLinkInfo> netLinkInfo = (std::make_unique<NetManagerStandard::NetLinkInfo>()).release();
    CreateNetLinkInfo(netLinkInfo, wifiIpInfo, wifiIpV6Info, wifiProxyConfig, instId);
    int32_t result = NetConnClient::GetInstance().UpdateNetLinkInfo(supplierId, netLinkInfo);
    WIFI_LOGI("UpdateNetLinkInfo result:%{public}d", result);
}

bool WifiNetAgent::AddRoute(const std::string interface, const std::string ipAddress, int prefixLength)
{
    TimeStats timeStats(__func__);
    LOGI("NetAgent add route");
    unsigned int ipInt = IpTools::ConvertIpv4Address(ipAddress);
    std::string mask = IpTools::ConvertIpv4Mask(prefixLength);
    unsigned int maskInt = IpTools::ConvertIpv4Address(mask);
    std::string strLocalRoute = IpTools::ConvertIpv4Address(ipInt & maskInt);
    std::string destAddress = strLocalRoute + "/" + std::to_string(prefixLength);

    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        LOGE("GetSystemAbilityManager failed!");
        return false;
    }
    auto remote = samgr->GetSystemAbility(COMM_NETSYS_NATIVE_SYS_ABILITY_ID);
    if (remote == nullptr) {
        LOGE("GetSystemAbility failed!");
        return false;
    }
    OHOS::sptr<OHOS::NetsysNative::INetsysService> netsysService = iface_cast<NetsysNative::INetsysService>(remote);
    if (netsysService == nullptr) {
        LOGE("NetdService is nullptr!");
        return false;
    }
    LOGI("Add route, interface: %{public}s, destAddress: %{public}s, ipAddress: %{public}s, prefixLength: %{public}d",
        interface.c_str(), IpAnonymize(destAddress).c_str(), IpAnonymize(ipAddress).c_str(), prefixLength);
    netsysService->NetworkAddRoute(OHOS::nmd::LOCAL_NETWORK_NETID, interface, destAddress, ipAddress);
    LOGI("NetAgent add route finish");
    return true;
}

bool WifiNetAgent::DelInterfaceAddress(const std::string interface, const std::string ipAddress, int prefixLength)
{
    int32_t result = NetConnClient::GetInstance().DelInterfaceAddress(interface, ipAddress, prefixLength);
    if (result == NETMANAGER_SUCCESS) {
        WIFI_LOGI("DelInterfaceAddress successful");
        return true;
    }
    WIFI_LOGI("DelInterfaceAddress failed");
    return false;
}

void WifiNetAgent::OnStaMachineUpdateNetLinkInfo(IpInfo &wifiIpInfo, IpV6Info &wifiIpV6Info,
    WifiProxyConfig &wifiProxyConfig, int instId)
{
    WifiEventHandler::PostSyncTimeOutTask([this, &wifiIpInfo, &wifiIpV6Info, &wifiProxyConfig, &instId]() {
        this->UpdateNetLinkInfo(wifiIpInfo, wifiIpV6Info, wifiProxyConfig, instId);
    });
}

void WifiNetAgent::OnStaMachineUpdateNetSupplierInfo(const sptr<NetManagerStandard::NetSupplierInfo> &netSupplierInfo)
{
    WifiEventHandler::PostSyncTimeOutTask([this, netInfo = netSupplierInfo]() {
        this->UpdateNetSupplierInfo(netInfo);
    });
}

void WifiNetAgent::OnStaMachineWifiStart()
{
    WifiEventHandler::PostSyncTimeOutTask([this]() {
        this->RegisterNetSupplier();
        this->RegisterNetSupplierCallback();
    });
}

void WifiNetAgent::OnStaMachineNetManagerRestart(const sptr<NetManagerStandard::NetSupplierInfo> &netSupplierInfo,
    int instId)
{
    WifiEventHandler::PostSyncTimeOutTask([this, supplierInfo = netSupplierInfo, m_instId = instId]() {
        this->RegisterNetSupplier();
        this->RegisterNetSupplierCallback();
        WifiLinkedInfo linkedInfo;
        WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, m_instId);
        if (linkedInfo.connState == ConnState::CONNECTED) {
#ifndef OHOS_ARCH_LITE
            if (supplierInfo != nullptr) {
                TimeStats timeStats("Call UpdateNetSupplierInfo");
                this->UpdateNetSupplierInfo(supplierInfo);
            }
#endif
            IpInfo wifiIpInfo;
            WifiConfigCenter::GetInstance().GetIpInfo(wifiIpInfo, m_instId);
            IpV6Info wifiIpV6Info;
            WifiConfigCenter::GetInstance().GetIpv6Info(wifiIpV6Info, m_instId);
            WifiDeviceConfig config;
            WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config);
            this->UpdateNetLinkInfo(wifiIpInfo, wifiIpV6Info, config.wifiProxyconfig, m_instId);
        }
    });
}

void WifiNetAgent::CreateNetLinkInfo(sptr<NetManagerStandard::NetLinkInfo> &netLinkInfo, IpInfo &wifiIpInfo,
    IpV6Info &wifiIpV6Info, WifiProxyConfig &wifiProxyConfig, int instId)
{
    netLinkInfo->ifaceName_ = WifiConfigCenter::GetInstance().GetStaIfaceName();

    SetNetLinkIPInfo(netLinkInfo, wifiIpInfo, wifiIpV6Info);
    SetNetLinkRouteInfo(netLinkInfo, wifiIpInfo, wifiIpV6Info);
    SetNetLinkDnsInfo(netLinkInfo, wifiIpInfo, wifiIpV6Info);
    SetNetLinkLocalRouteInfo(netLinkInfo, wifiIpInfo, wifiIpV6Info);
    if (wifiProxyConfig.configureMethod == ConfigureProxyMethod::AUTOCONFIGUE) {
        /* Automatic proxy is not supported */
    } else if (wifiProxyConfig.configureMethod == ConfigureProxyMethod::MANUALCONFIGUE) {
        std::vector<std::string> exclusionList;
        wifiProxyConfig.manualProxyConfig.GetExclusionObjectList(exclusionList);
        std::list<std::string> tmpExclusionList;
        std::copy_if(exclusionList.begin(), exclusionList.end(), std::back_inserter(tmpExclusionList),
            [](const std::string &str) { return !str.empty(); });
        netLinkInfo->httpProxy_.SetHost(std::move(wifiProxyConfig.manualProxyConfig.serverHostName));
        netLinkInfo->httpProxy_.SetPort(wifiProxyConfig.manualProxyConfig.serverPort);
        netLinkInfo->httpProxy_.SetExclusionList(tmpExclusionList);
    } else {
        netLinkInfo->httpProxy_.SetHost("");
        netLinkInfo->httpProxy_.SetPort(0);
    }

    return;
}

void WifiNetAgent::SetNetLinkIPInfo(sptr<NetManagerStandard::NetLinkInfo> &netLinkInfo, IpInfo &wifiIpInfo,
    IpV6Info &wifiIpV6Info)
{
    unsigned int prefixLength =
        static_cast<unsigned int>(IpTools::GetMaskLength(IpTools::ConvertIpv4Address(wifiIpInfo.netmask)));
    sptr<NetManagerStandard::INetAddr> netAddr = (std::make_unique<NetManagerStandard::INetAddr>()).release();
    netAddr->type_ = NetManagerStandard::INetAddr::IPV4;
    netAddr->family_ = NetManagerStandard::INetAddr::IPV4;
    netAddr->address_ = IpTools::ConvertIpv4Address(wifiIpInfo.ipAddress);
    netAddr->netMask_ = IpTools::ConvertIpv4Address(wifiIpInfo.netmask);
    netAddr->prefixlen_ = prefixLength;
    netLinkInfo->netAddrList_.push_back(*netAddr);

    LOGD("SetNetLinkIPInfo %{public}s", wifiIpV6Info.globalIpV6Address.c_str());
    sptr<NetManagerStandard::INetAddr> netIpv6Addr = nullptr;
    if (!wifiIpV6Info.globalIpV6Address.empty()) {
        netIpv6Addr = (std::make_unique<NetManagerStandard::INetAddr>()).release();
        netIpv6Addr->address_ = wifiIpV6Info.globalIpV6Address;
    }

    if (!wifiIpV6Info.randGlobalIpV6Address.empty()) {
        netIpv6Addr = (std::make_unique<NetManagerStandard::INetAddr>()).release();
        netIpv6Addr->address_ = wifiIpV6Info.randGlobalIpV6Address;
    }

    if (!wifiIpV6Info.uniqueLocalAddress1.empty()) {
        netIpv6Addr = (std::make_unique<NetManagerStandard::INetAddr>()).release();
        netIpv6Addr->address_ = wifiIpV6Info.uniqueLocalAddress1;
    }

    if (!wifiIpV6Info.uniqueLocalAddress2.empty()) {
        netIpv6Addr = (std::make_unique<NetManagerStandard::INetAddr>()).release();
        netIpv6Addr->address_ = wifiIpV6Info.uniqueLocalAddress2;
    }
    if (netIpv6Addr != nullptr) {
        netIpv6Addr->type_ = NetManagerStandard::INetAddr::IPV6;
        netIpv6Addr->family_ = NetManagerStandard::INetAddr::IPV6;
        netIpv6Addr->netMask_ = wifiIpV6Info.netmask;
        netIpv6Addr->prefixlen_ = 0;
        netLinkInfo->netAddrList_.push_back(*netIpv6Addr);
    }
}

void WifiNetAgent::SetNetLinkDnsInfo(sptr<NetManagerStandard::NetLinkInfo> &netLinkInfo, IpInfo &wifiIpInfo,
    IpV6Info &wifiIpV6Info)
{
    sptr<NetManagerStandard::INetAddr> dns = (std::make_unique<NetManagerStandard::INetAddr>()).release();
    dns->type_ = NetManagerStandard::INetAddr::IPV4;
    dns->family_ = NetManagerStandard::INetAddr::IPV4;
    if (wifiIpInfo.primaryDns != 0) {
        dns->address_ = IpTools::ConvertIpv4Address(wifiIpInfo.primaryDns);
        netLinkInfo->dnsList_.push_back(*dns);
        LOGI("SetNetLinkDnsInfo ipv4 address:%{public}s", IpAnonymize(dns->address_).c_str());
    }
    if (wifiIpInfo.secondDns != 0) {
        dns->address_ = IpTools::ConvertIpv4Address(wifiIpInfo.secondDns);
        netLinkInfo->dnsList_.push_back(*dns);
        LOGI("SetNetLinkDnsInfo ipv4 address:%{public}s", IpAnonymize(dns->address_).c_str());
    }
    sptr<NetManagerStandard::INetAddr> ipv6dns = (std::make_unique<NetManagerStandard::INetAddr>()).release();
    ipv6dns->type_ = NetManagerStandard::INetAddr::IPV6;
    ipv6dns->family_ = NetManagerStandard::INetAddr::IPV6;
    if (!wifiIpV6Info.primaryDns.empty()) {
        ipv6dns->address_ = wifiIpV6Info.primaryDns;
        netLinkInfo->dnsList_.push_back(*ipv6dns);
    }
    if (!wifiIpV6Info.secondDns.empty()) {
        ipv6dns->address_ = wifiIpV6Info.secondDns;
        netLinkInfo->dnsList_.push_back(*ipv6dns);
    }
}

void WifiNetAgent::SetNetLinkRouteInfo(sptr<NetManagerStandard::NetLinkInfo> &netLinkInfo, IpInfo &wifiIpInfo,
    IpV6Info &wifiIpV6Info)
{
    sptr<NetManagerStandard::Route> route = (std::make_unique<NetManagerStandard::Route>()).release();
    route->iface_ = netLinkInfo->ifaceName_;
    route->destination_.type_ = NetManagerStandard::INetAddr::IPV4;
    route->destination_.address_ = "0.0.0.0";
    route->destination_.family_ = NetManagerStandard::INetAddr::IPV4;
    route->gateway_.address_ = IpTools::ConvertIpv4Address(wifiIpInfo.gateway);
    route->gateway_.family_ = NetManagerStandard::INetAddr::IPV4;
    netLinkInfo->routeList_.push_back(*route);
    LOGD("SetNetLinkRouteInfo: gateway %{public}s, address %{public}s",
        wifiIpV6Info.gateway.c_str(), route->gateway_.address_.c_str());
    if (!wifiIpV6Info.gateway.empty()) {
        sptr<NetManagerStandard::Route> ipv6route = (std::make_unique<NetManagerStandard::Route>()).release();
        ipv6route->iface_ = netLinkInfo->ifaceName_;
        ipv6route->destination_.type_ = NetManagerStandard::INetAddr::IPV6;
        ipv6route->destination_.family_ = NetManagerStandard::INetAddr::IPV6;
        ipv6route->destination_.address_ = "::";
        ipv6route->destination_.prefixlen_ = 0;
        ipv6route->gateway_.address_ = wifiIpV6Info.gateway;
        ipv6route->gateway_.family_ = NetManagerStandard::INetAddr::IPV6;
        netLinkInfo->routeList_.push_back(*ipv6route);
    }
}

void WifiNetAgent::SetNetLinkLocalRouteInfo(sptr<NetManagerStandard::NetLinkInfo> &netLinkInfo, IpInfo &wifiIpInfo,
    IpV6Info &wifiIpV6Info)
{
    unsigned int prefixLength =
        static_cast<unsigned int>(IpTools::GetMaskLength(IpTools::ConvertIpv4Address(wifiIpInfo.netmask)));
    sptr<NetManagerStandard::Route> localRoute = (std::make_unique<NetManagerStandard::Route>()).release();
    std::string strLocalRoute = IpTools::ConvertIpv4Address(wifiIpInfo.ipAddress & wifiIpInfo.netmask);
    localRoute->iface_ = netLinkInfo->ifaceName_;
    localRoute->destination_.type_ = NetManagerStandard::INetAddr::IPV4;
    localRoute->destination_.address_ = strLocalRoute;
    localRoute->destination_.prefixlen_ = prefixLength;
    localRoute->gateway_.address_ = "0.0.0.0";
    netLinkInfo->routeList_.push_back(*localRoute);
    if (!wifiIpV6Info.netmask.empty()) {
        unsigned int ipv6PrefixLength = IpTools::GetIPV6MaskLength(wifiIpV6Info.netmask);
        sptr<NetManagerStandard::Route> ipv6route = (std::make_unique<NetManagerStandard::Route>()).release();
        ipv6route->iface_ = netLinkInfo->ifaceName_;
        ipv6route->destination_.type_ = NetManagerStandard::INetAddr::IPV6;
        ipv6route->destination_.address_ =
            Ipv6Address::GetPrefixByAddr(wifiIpV6Info.globalIpV6Address, ipv6PrefixLength);
        ipv6route->destination_.prefixlen_ = ipv6PrefixLength;
        ipv6route->gateway_.address_ = "";
        netLinkInfo->routeList_.push_back(*ipv6route);
    }
}

void WifiNetAgent::InitWifiNetAgent(const WifiNetAgentCallbacks &wifiNetAgentCallbacks)
{
    wifiNetAgentCallbacks_ = wifiNetAgentCallbacks;
}

bool WifiNetAgent::RequestNetwork(const int uid, const int networkId)
{
    if (!wifiNetAgentCallbacks_.OnRequestNetwork) {
        WIFI_LOGE("OnRequestNetwork is nullptr.");
        return false;
    }
    if (wifiNetAgentCallbacks_.OnRequestNetwork(uid, networkId)) {
        return true;
    }
    return false;
}

WifiNetAgent::NetConnCallback::NetConnCallback()
{
}

WifiNetAgent::NetConnCallback::~NetConnCallback()
{}

void WifiNetAgent::ResetSupplierId()
{
    supplierId = INVALID_SUPPLIER_ID;
}

uint32_t WifiNetAgent::GetSupplierId()
{
    return supplierId;
}

int32_t WifiNetAgent::NetConnCallback::RequestNetwork(
    const std::string &ident, const std::set<NetManagerStandard::NetCap> &netCaps,
    const NetManagerStandard::NetRequest &netrequest)
{
    WIFI_LOGD("Enter NetConnCallback::RequestNetwork");
    LogNetCaps(ident, netCaps);
#ifndef OHOS_ARCH_LITE
    if (requestIds_.find(netrequest.requestId) != requestIds_.end()) {
        return -1;
    }
    requestIds_.insert(netrequest.requestId);

    int networkId = ConvertStringToInt(netrequest.ident);
    if (networkId <= INVALID_NETWORK_ID || std::to_string(networkId) != netrequest.ident) {
        WIFI_LOGE("networkId is invaild.");
        return -1;
    }

    WIFI_LOGI("RequestNetwork uid[%{public}d], networkId[%{public}d].", netrequest.uid, networkId);
    if (!WifiAppStateAware::GetInstance().IsForegroundApp(netrequest.uid)) {
        WIFI_LOGE("App is not in foreground.");
        return -1;
    }

    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.connState == ConnState::CONNECTING || linkedInfo.connState == ConnState::CONNECTED) {
        if (linkedInfo.networkId == networkId) {
            WIFI_LOGI("RequestNetwork networkId is connecting or connected.");
            return 0;
        }
    }

    if (!WifiNetAgent::GetInstance().RequestNetwork(netrequest.uid, networkId)) {
        WIFI_LOGE("RequestNetwork fail.");
        return -1;
    }
#endif
    return 0;
}

int32_t WifiNetAgent::NetConnCallback::ReleaseNetwork(
    const std::string &ident, const std::set<NetManagerStandard::NetCap> &netCaps)
{
    WIFI_LOGD("Enter NetConnCallback::ReleaseNetwork");
    LogNetCaps(ident, netCaps);
    return 0;
}

void WifiNetAgent::NetConnCallback::LogNetCaps(
    const std::string &ident, const std::set<NetManagerStandard::NetCap> &netCaps) const
{
    WIFI_LOGD("ident=[%s]", ident.c_str());
    std::string logStr;
    const std::string logStrEnd("]");
    logStr = "netCaps[";
    for (auto netCap : netCaps) {
        logStr += std::to_string(static_cast<uint32_t>(netCap));
        logStr += " ";
    }
    logStr += logStrEnd;
    WIFI_LOGD("%{public}s", logStr.c_str());
}
}
}
