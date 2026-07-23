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
#ifndef OHOS_RPT_NAT_MANAGER_H
#define OHOS_RPT_NAT_MANAGER_H

#ifdef FEATURE_WITH_GO_SIMULATION_AP
#include <string>

namespace OHOS {
namespace Wifi {
class WifiRptNatManager {
public:
    /**
     * @Description Bridge NAT from downstream (p2p) to upstream (STA) interface.
     * @param enable - enabled or disabled
     * @param inInterfaceName - downstream network interface
     * @param outInterfaceName - upstream network interface
     * @return true: success     false: failed
     */
    bool EnableBridgeNat(bool enable, std::string inInterfaceName, std::string outInterfaceName) const;

private:
    bool EnableBridgeNatInternal(const std::string &downstreamIface, const std::string &upstreamIface) const;
    bool DisableBridgeNatInternal(const std::string &downstreamIface, const std::string &upstreamIface) const;
};
}  // namespace Wifi
}  // namespace OHOS
#endif // FEATURE_WITH_GO_SIMULATION_AP
#endif
