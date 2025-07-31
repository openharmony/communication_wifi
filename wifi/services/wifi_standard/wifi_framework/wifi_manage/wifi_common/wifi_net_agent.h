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

#ifndef WIFI_NET_AGENT_H
#define WIFI_NET_AGENT_H

#include <memory>
#include <string>
#include <singleton.h>
#include <utility>
#include <vector>
#include <mutex>

#include "define.h"
#include "i_net_conn_service.h"
#include "net_all_capabilities.h"
#include "net_supplier_callback_base.h"
#include "wifi_event_handler.h"
#include "wifi_internal_msg.h"
#include "sta_service_callback.h"
#include "wifi_log.h"
#include "net_manager_constants.h"
#include "net_conn_callback_stub.h"
namespace OHOS {
namespace Wifi {
struct WifiNetAgentCallbacks {
    std::function<bool(const int uid, const int networkId)> OnRequestNetwork;
};

class WifiNetAgent {
public:
    ~WifiNetAgent();
    static WifiNetAgent &GetInstance();
    /**
     * Register the network information with the network management module
     *
     * @return true if register success else return false;
     */
    bool RegisterNetSupplier(int instId);
    /**
     * Register the network callback with the network management module
     *
     * @return true if register success else return false;
     */
    bool RegisterNetSupplierCallback(int instId);

    /**
     * Cancel the registration information to the network management
     */
    void UnregisterNetSupplier(int instId);

    /**
     * Update network information
     *
     * @param supplierId network unique identity id returned after network registration
     * @param netSupplierInfo network data information
     */
    void UpdateNetSupplierInfo(const sptr<NetManagerStandard::NetSupplierInfo> &netSupplierInfo, int instId);

    /**
     * Add route
     *
     * @param interface interface name
     * @param ipAddress IP address
     * @param prefixLength prefix length
     */
    bool AddRoute(const std::string interface, const std::string ipAddress, int prefixLength);

    /**
     * Delete interface address
     *
     * @param interface interface name
     * @param ipAddress IP address
     * @param prefixLength prefix length
     */
    bool DelInterfaceAddress(const std::string &interface, const std::string &ipAddress, int prefixLength);

    /**
     * Add OnStaMachineUpdateNetLinkInfo
     *
     * @param wifiIpInfo wifi network link data information
     * @param wifiIpV6Info wifi ipv6 network link data information
     * @param wifiProxyConfig wifi network link proxy information
     */
    void OnStaMachineUpdateNetLinkInfo(IpInfo wifiIpInfo, IpV6Info wifiIpV6Info, WifiProxyConfig wifiProxyConfig,
        int instId = 0);

    /**
     * Add OnStaMachineUpdateNetSupplierInfo
     *
     * @param netSupplierInfo net Supplier Info
     */
    void OnStaMachineUpdateNetSupplierInfo(const sptr<NetManagerStandard::NetSupplierInfo> netSupplierInfo, int instId);

    /**
     * Add OnStaMachineWifiStart
     *
     * @param
     */
    void OnStaMachineWifiStart(int instId);

    /**
     * Register network connect call back
     *
     * @return true if register success else return false;
     */
    bool RegisterNetConnObserver(int instId);

    /**
     * Add OnStaMachineNetManagerRestart
     *
     * @param netSupplierInfo net Supplier Info
     */
    void OnStaMachineNetManagerRestart(const sptr<NetManagerStandard::NetSupplierInfo> netSupplierInfo,
        int instId = 0);

    /**
     * Restart the Wi-Fi connection.
     *
     * @param
     */
    void RestoreWifiConnection();

    /**
     * Init WifiNetAgentCallbacks
     *
     * @param WifiNetAgentCallbacks WifiNetAgent callback
     */
    void InitWifiNetAgent(const WifiNetAgentCallbacks &wifiNetAgentCallbacks);

    /**
     * Add RequestNetwork
     *
     * @param uid uid
     * @param networkId deviceconfig networkId
     */
    bool RequestNetwork(const int uid, const int networkId);

    /**
     * return wifi supplierId
     */
    uint32_t GetSupplierId();
 
     /**
     * set wifi supplierId to 0
     */
    void ResetSupplierId();

public:
    class NetConnCallback : public NetManagerStandard::NetSupplierCallbackBase {
    public:
        /**
         * @Description : Construct a new NetConn object
         *
         */
        explicit NetConnCallback();

        /**
         * @Description : Destroy the NetConn object
         *
         */
        ~NetConnCallback() override;

        /**
         * @Description : Connection Management triggers the open automatic connection feature.
         *
         * @param ident - identity
         * @param netCaps - Net capability to request a network
         * @param registerType - Inner API or outer API
         *
         */
        int32_t RequestNetwork(
            const std::string &ident, const std::set<NetManagerStandard::NetCap> &netCaps,
            const NetManagerStandard::NetRequest &netrequest) override;
        /**
         * @Description : Connection Management triggers the close automatic connection feature.
         *
         * @param ident - identity
         * @param netCaps - Net capability to request a network
         */
        int32_t ReleaseNetwork(const NetManagerStandard::NetRequest &netrequest) override;
    private:
        void LogNetCaps(const std::string &ident, const std::set<NetManagerStandard::NetCap> &netCaps) const;

        std::unordered_set<int> requestIds_;
    };
private:
    WifiNetAgent();
    void CreateNetLinkInfo(sptr<NetManagerStandard::NetLinkInfo> &netLinkInfo, IpInfo &wifiIpInfo,
        IpV6Info &wifiIpV6Info, WifiProxyConfig &wifiProxyConfig, int instId = 0);

    void SetNetLinkIPInfo(sptr<NetManagerStandard::NetLinkInfo> &netLinkInfo, IpInfo &wifiIpInfo,
        IpV6Info &wifiIpV6Info);

    void SetNetLinkRouteInfo(sptr<NetManagerStandard::NetLinkInfo> &netLinkInfo, IpInfo &wifiIpInfo,
        IpV6Info &wifiIpV6Info);

    void SetNetLinkHostRouteInfo(sptr<NetManagerStandard::NetLinkInfo> &netLinkInfo, IpInfo &wifiIpInfo);

    void SetNetLinkLocalRouteInfo(sptr<NetManagerStandard::NetLinkInfo> &netLinkInfo, IpInfo &wifiIpInfo,
        IpV6Info &wifiIpV6Info);

    void SetNetLinkDnsInfo(sptr<NetManagerStandard::NetLinkInfo> &netLinkInfo, IpInfo &wifiIpInfo,
        IpV6Info &wifiIpV6Info);

    /**
     * Update link information
     *
     * @param wifiIpInfo wifi network link data information
     * @param wifiIpV6Info wifi network link IPV6 data information
     * @param wifiProxyConfig wifi network link proxy information
     */
    void UpdateNetLinkInfo(IpInfo &wifiIpInfo, IpV6Info &wifiIpV6Info, WifiProxyConfig &wifiProxyConfig,
        int instId = 0);
private:
    uint32_t supplierId{0};
    uint32_t supplierIdForWlan1{0};
    bool isWifiAvailable_[STA_INSTANCE_MAX_NUM] = {false};
    WifiNetAgentCallbacks wifiNetAgentCallbacks_;
    std::unique_ptr<WifiEventHandler> netAgentEventHandler_ = nullptr;
    std::mutex netAgentMutex_;
    class NetInfoObserver final : public NetManagerStandard::NetConnCallbackStub {
    public:
        int32_t NetAvailable(sptr<NetManagerStandard::NetHandle> &netHandle) override;
    };
    sptr<NetInfoObserver> netConnCallback_ { nullptr };
    static bool IsDefaultBtNet();
};
} // namespace Wifi
} // namespace OHOS
#endif // CELLULAR_DATA_NET_AGENT_H
