/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MOCK_AUTH_CENTER_H
#define OHOS_MOCK_AUTH_CENTER_H

#include "wifi_event_handler.h"
#include "wifi_errcode.h"
#include "network_selection.h"
#include "network_selector_factory.h"
#include "wifi_internal_msg.h"
#include "wifi_log.h"
#include "i_net_conn_service.h"
#include "net_all_capabilities.h"
#include "net_supplier_callback_base.h"
#include <any>

namespace OHOS {
namespace Wifi {
class WifiAuthCenter {
public:
    static WifiAuthCenter &GetInstance();

    int Init();

    static bool IsSystemAccess();

    static bool IsNativeProcess();

    int VerifySetWifiInfoPermission(const int &pid, const int &uid);

    int VerifyGetWifiInfoPermission(const int &pid, const int &uid);

    int VerifyGetScanInfosPermission(const int &pid, const int &uid);

    int VerifyGetWifiLocalMacPermission(const int &pid, const int &uid);

    int VerifyWifiConnectionPermission(const int &pid, const int &uid);

    int VerifySetWifiConfigPermission(const int &pid, const int &uid);

    int VerifyGetWifiDirectDevicePermission(const int &pid, const int &uid);

    int VerifyManageWifiHotspotPermission(const int &pid, const int &uid);

    int VerifyGetWifiPeersMacPermission(const int &pid, const int &uid);

    int VerifyGetWifiPeersMacPermissionEx(const int &pid, const int &uid, const int &tokenId);

    int VerifyGetWifiInfoInternalPermission(const int &pid, const int &uid);

    int VerifyManageWifiHotspotExtPermission(const int &pid, const int &uid);

    int VerifyGetWifiConfigPermission(const int &pid, const int &uid);
    
    int VerifyEnterpriseWifiConnectionPermission(const int &pid, const int &uid);

    int VerifySameProcessPermission(const int &pid, const int &uid);
};

class WifiNetAgent {
public:
    static WifiNetAgent &GetInstance();

    explicit WifiNetAgent();
    ~WifiNetAgent();
    void OnStaMachineUpdateNetLinkInfo(IpInfo &wifiIpInfo, IpV6Info &wifiIpV6Info, WifiProxyConfig &wifiProxyConfig,
        int instId = 0);
    void OnStaMachineUpdateNetSupplierInfo(const sptr<NetManagerStandard::NetSupplierInfo> netSupplierInfo,
        int instId = 0);
    void OnStaMachineNetManagerRestart(const sptr<NetManagerStandard::NetSupplierInfo> &netSupplierInfo,
        int instId = 0);
    void OnStaMachineWifiStart(int instId = 0);
    bool DelInterfaceAddress(const std::string &interface, const std::string &ipAddress, int prefixLength);
    void UnregisterNetSupplier(int instId = 0);
};

struct NetworkSelectionResult {
    InterScanInfo interScanInfo;
    WifiDeviceConfig wifiDeviceConfig;
};

class NetworkSelectionManager {
public:
    NetworkSelectionManager();

    bool SelectNetwork(NetworkSelectionResult &networkSelectionResult,
                       NetworkSelectType type,
                       const std::vector<InterScanInfo> &scanInfos);

    std::unique_ptr<NetworkSelectorFactory> pNetworkSelectorFactory = nullptr;

    static void TryNominate(std::vector<NetworkSelection::NetworkCandidate> &networkCandidates,
                            const std::unique_ptr<NetworkSelection::INetworkSelector> &networkSelector);
};

} // namespace Wifi
} // namespace OHOS
#endif