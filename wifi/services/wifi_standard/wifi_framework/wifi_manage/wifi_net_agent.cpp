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
#include "wifi_settings.h"

DEFINE_WIFILOG_LABEL("WifiNetAgent");

namespace OHOS {
namespace Wifi {
constexpr const char *WIFI_NET_CONN_MGR_WORK_THREAD = "WIFI_NET_CONN_MGR_WORK_THREAD";
using namespace NetManagerStandard;

WifiNetAgent::WifiNetAgent()
{
    netConnEventRunner_ = AppExecFwk::EventRunner::Create(WIFI_NET_CONN_MGR_WORK_THREAD);
    if (netConnEventRunner_) {
        netConnEventHandler_ = std::make_shared<WifiNetConnEventHandler>(netConnEventRunner_);
    } else {
        WIFI_LOGE("Create event runner failed.");
    }
}
WifiNetAgent::~WifiNetAgent()
{
    if (netConnEventRunner_) {
        netConnEventRunner_->Stop();
        netConnEventRunner_.reset();
    }

    if (netConnEventHandler_) {
        netConnEventHandler_.reset();
    }
}

bool WifiNetAgent::RegisterNetSupplier()
{
    TimeStats timeStats(__func__);
    WIFI_LOGI("Enter RegisterNetSupplier.");

    std::string ident = "wifi";
    using NetManagerStandard::NetBearType;
    using NetManagerStandard::NetCap;
    std::set<NetCap> netCaps {NetCap::NET_CAPABILITY_INTERNET};
    int32_t result = NetConnClient::GetInstance().RegisterNetSupplier(NetBearType::BEARER_WIFI,
                                                                      ident, netCaps, supplierId);
    if (result == NETMANAGER_SUCCESS) {
        WIFI_LOGI("Register NetSupplier successful");
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
}

void WifiNetAgent::UpdateNetSupplierInfo(const sptr<NetManagerStandard::NetSupplierInfo> &netSupplierInfo)
{
    TimeStats timeStats(__func__);
    WIFI_LOGI("Enter UpdateNetSupplierInfo.");
    int32_t result = NetConnClient::GetInstance().UpdateNetSupplierInfo(supplierId, netSupplierInfo);
    WIFI_LOGI("Update network result:%{public}d", result);
}

void WifiNetAgent::UpdateNetLinkInfo(IpInfo &wifiIpInfo, WifiProxyConfig &wifiProxyConfig)
{
    TimeStats timeStats(__func__);
    WIFI_LOGI("Enter UpdateNetLinkInfo.");

    sptr<NetManagerStandard::NetLinkInfo> netLinkInfo = (std::make_unique<NetManagerStandard::NetLinkInfo>()).release();
    CreateNetLinkInfo(netLinkInfo, wifiIpInfo, wifiProxyConfig);
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

void WifiNetAgent::OnStaMachineUpdateNetLinkInfo(IpInfo &wifiIpInfo, WifiProxyConfig &wifiProxyConfig)
{
    if (netConnEventHandler_) {
        netConnEventHandler_->PostSyncTask(
            [this, &wifiIpInfo, &wifiProxyConfig]() { this->UpdateNetLinkInfo(wifiIpInfo, wifiProxyConfig); });
    }
}

void WifiNetAgent::OnStaMachineUpdateNetSupplierInfo(const sptr<NetManagerStandard::NetSupplierInfo> &netSupplierInfo)
{
    if (netConnEventHandler_) {
        netConnEventHandler_->PostSyncTask([this, netInfo = netSupplierInfo]() {
           this->UpdateNetSupplierInfo(netInfo);
        });
    }
}

void WifiNetAgent::OnStaMachineWifiStart()
{
    if (netConnEventHandler_) {
        netConnEventHandler_->PostSyncTask([this]() {
            this->RegisterNetSupplier();
            this->RegisterNetSupplierCallback();
        });
    }
}

void WifiNetAgent::OnStaMachineNetManagerRestart(const sptr<NetManagerStandard::NetSupplierInfo> &netSupplierInfo)
{
    if (netConnEventHandler_) {
        netConnEventHandler_->PostSyncTask([this, supplierInfo = netSupplierInfo]() {
            this->RegisterNetSupplier();
            this->RegisterNetSupplierCallback();
            WifiLinkedInfo linkedInfo;
            WifiSettings::GetInstance().GetLinkedInfo(linkedInfo);
            if ((linkedInfo.detailedState == DetailedState::NOTWORKING)
                && (linkedInfo.connState == ConnState::CONNECTED)) {
#ifndef OHOS_ARCH_LITE
                if (supplierInfo != nullptr) {
                    TimeStats timeStats("Call UpdateNetSupplierInfo");
                    this->UpdateNetSupplierInfo(supplierInfo);
                }
#endif
                IpInfo wifiIpInfo;
                WifiSettings::GetInstance().GetIpInfo(wifiIpInfo);
                WifiDeviceConfig config;
                WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, config);
                this->UpdateNetLinkInfo(wifiIpInfo, config.wifiProxyconfig);
            }
        });
    }
}

void WifiNetAgent::CreateNetLinkInfo(sptr<NetManagerStandard::NetLinkInfo> &netLinkInfo, IpInfo &wifiIpInfo,
    WifiProxyConfig &wifiProxyConfig)
{
    netLinkInfo->ifaceName_ = "wlan0";

    unsigned int prefixLength = IpTools::GetMaskLength(IpTools::ConvertIpv4Address(wifiIpInfo.netmask));
    sptr<NetManagerStandard::INetAddr> netAddr = (std::make_unique<NetManagerStandard::INetAddr>()).release();
    netAddr->type_ = NetManagerStandard::INetAddr::IPV4;
    netAddr->family_ = NetManagerStandard::INetAddr::IPV4;
    netAddr->address_ = IpTools::ConvertIpv4Address(wifiIpInfo.ipAddress);
    netAddr->netMask_ = IpTools::ConvertIpv4Address(wifiIpInfo.netmask);
    netAddr->prefixlen_ = prefixLength;
    netLinkInfo->netAddrList_.push_back(*netAddr);

    sptr<NetManagerStandard::INetAddr> dns = (std::make_unique<NetManagerStandard::INetAddr>()).release();
    dns->type_ = NetManagerStandard::INetAddr::IPV4;
    dns->family_ = NetManagerStandard::INetAddr::IPV4;
    dns->address_ = IpTools::ConvertIpv4Address(wifiIpInfo.primaryDns);
    netLinkInfo->dnsList_.push_back(*dns);
    dns->address_ = IpTools::ConvertIpv4Address(wifiIpInfo.secondDns);
    netLinkInfo->dnsList_.push_back(*dns);

    sptr<NetManagerStandard::Route> route = (std::make_unique<NetManagerStandard::Route>()).release();
    route->iface_ = "wlan0";
    route->destination_.type_ = NetManagerStandard::INetAddr::IPV4;
    route->destination_.address_ = "0.0.0.0";
    route->gateway_.address_ = IpTools::ConvertIpv4Address(wifiIpInfo.gateway);
    netLinkInfo->routeList_.push_back(*route);

    sptr<NetManagerStandard::Route> localRoute = (std::make_unique<NetManagerStandard::Route>()).release();
    std::string strLocalRoute = IpTools::ConvertIpv4Address(wifiIpInfo.ipAddress & wifiIpInfo.netmask);
    localRoute->iface_ = route->iface_;
    localRoute->destination_.type_ = NetManagerStandard::INetAddr::IPV4;
    localRoute->destination_.address_ = strLocalRoute;
    localRoute->destination_.prefixlen_ = prefixLength;
    localRoute->gateway_.address_ = "0.0.0.0";
    netLinkInfo->routeList_.push_back(*localRoute);

    if (wifiProxyConfig.configureMethod == ConfigureProxyMethod::AUTOCONFIGUE) {
        /* Automatic proxy is not supported */
    } else if (wifiProxyConfig.configureMethod == ConfigureProxyMethod::MANUALCONFIGUE) {
        std::vector<std::string> exclusionList;
        wifiProxyConfig.manualProxyConfig.GetExclusionObjectList(exclusionList);
        std::list<std::string> tmpExclusionList;
        std::copy_if(exclusionList.begin(), exclusionList.end(), std::back_inserter(tmpExclusionList),
            [](const std::string &str) { return !str.empty(); } );
        netLinkInfo->httpProxy_.SetHost(std::move(wifiProxyConfig.manualProxyConfig.serverHostName));
        netLinkInfo->httpProxy_.SetPort(wifiProxyConfig.manualProxyConfig.serverPort);
        netLinkInfo->httpProxy_.SetExclusionList(tmpExclusionList);
    } else {
        netLinkInfo->httpProxy_.SetHost("");
        netLinkInfo->httpProxy_.SetPort(0);
    }

    return;
}

WifiNetAgent::NetConnCallback::NetConnCallback()
{
}

WifiNetAgent::NetConnCallback::~NetConnCallback()
{}

int32_t WifiNetAgent::NetConnCallback::RequestNetwork(
    const std::string &ident, const std::set<NetManagerStandard::NetCap> &netCaps)
{
    WIFI_LOGD("Enter NetConnCallback::RequestNetwork");
    LogNetCaps(ident, netCaps);
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
