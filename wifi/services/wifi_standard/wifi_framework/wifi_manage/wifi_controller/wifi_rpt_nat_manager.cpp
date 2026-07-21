/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#ifdef FEATURE_WITH_GO_SIMULATION_AP
#include "wifi_rpt_nat_manager.h"
#include "network_interface.h"
#include "netsys_controller.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiRptNatManager");

namespace OHOS {
namespace Wifi {
namespace {
constexpr const char *RPT_NAT_REQUESTOR = "wifi_rpt";
constexpr int32_t NETMANAGER_OK = 0;

bool IsNetsysOk(int32_t ret, const char *apiName)
{
    if (ret != NETMANAGER_OK) {
        WIFI_LOGE("%{public}s failed, ret=%{public}d", apiName, ret);
        return false;
    }
    return true;
}
}  // namespace

bool WifiRptNatManager::EnableBridgeNat(bool enable, std::string inInterfaceName,
    std::string outInterfaceName) const
{
    WIFI_LOGI("EnableBridgeNat enable [%{public}s], inInterfaceName [%{private}s] outInterfaceName [%{private}s].",
        enable ? "true" : "false",
        inInterfaceName.c_str(),
        outInterfaceName.c_str());

    if (!NetworkInterface::IsValidInterfaceName(inInterfaceName) ||
        !NetworkInterface::IsValidInterfaceName(outInterfaceName)) {
        WIFI_LOGE("Invalid interface name.");
        return false;
    }

    if (inInterfaceName == outInterfaceName) {
        WIFI_LOGE("Duplicate interface, bridge NAT not needed.");
        return false;
    }

    if (enable) {
        return EnableBridgeNatInternal(inInterfaceName, outInterfaceName);
    }
    return DisableBridgeNatInternal(inInterfaceName, outInterfaceName);
}

bool WifiRptNatManager::EnableBridgeNatInternal(const std::string &downstreamIface,
    const std::string &upstreamIface) const
{
    auto &netsysController = NetManagerStandard::NetsysController::GetInstance();
    if (!IsNetsysOk(netsysController.IpEnableForwarding(RPT_NAT_REQUESTOR), "IpEnableForwarding")) {
        return false;
    }
    if (!IsNetsysOk(netsysController.IpfwdAddInterfaceForward(downstreamIface, upstreamIface),
        "IpfwdAddInterfaceForward")) {
        netsysController.IpDisableForwarding(RPT_NAT_REQUESTOR);
        return false;
    }
    if (!IsNetsysOk(netsysController.EnableNat(downstreamIface, upstreamIface), "EnableNat")) {
        netsysController.IpfwdRemoveInterfaceForward(downstreamIface, upstreamIface);
        netsysController.IpDisableForwarding(RPT_NAT_REQUESTOR);
        return false;
    }
    WIFI_LOGI("RPT bridge NAT enabled via NetsysController");
    return true;
}

bool WifiRptNatManager::DisableBridgeNatInternal(const std::string &downstreamIface,
    const std::string &upstreamIface) const
{
    auto &netsysController = NetManagerStandard::NetsysController::GetInstance();
    if (!IsNetsysOk(netsysController.DisableNat(downstreamIface, upstreamIface), "DisableNat")) {
        return false;
    }
    if (!IsNetsysOk(netsysController.IpfwdRemoveInterfaceForward(downstreamIface, upstreamIface),
        "IpfwdRemoveInterfaceForward")) {
        return false;
    }
    if (!IsNetsysOk(netsysController.IpDisableForwarding(RPT_NAT_REQUESTOR), "IpDisableForwarding")) {
        return false;
    }
    WIFI_LOGI("RPT bridge NAT disabled via NetsysController");
    return true;
}
}  // namespace Wifi
}  // namespace OHOS
#endif // FEATURE_WITH_GO_SIMULATION_AP
