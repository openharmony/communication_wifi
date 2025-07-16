/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include <memory>
#include "network_selector_factory.h"
#include "wifi_logger.h"

namespace OHOS::Wifi {
DEFINE_WIFILOG_LABEL("NetworkSelectorFactory")

NetworkSelectorFactory::NetworkSelectorFactory()
{
    handleFuncMap[static_cast<uint32_t>(NetworkSelectType::AUTO_CONNECT)] =
        &NetworkSelectorFactory::CreateAutoConnectNetworkSelector;
    handleFuncMap[static_cast<uint32_t>(NetworkSelectType::WIFI2WIFI)] =
        &NetworkSelectorFactory::CreateWifi2WifiNetworkSelector;
    handleFuncMap[static_cast<uint32_t>(NetworkSelectType::WIFI2WIFI_NONET)] =
        &NetworkSelectorFactory::CreateWifi2WifiNoNetNetworkSelector;
    handleFuncMap[static_cast<uint32_t>(NetworkSelectType::WIFI2WIFI_QOE_BAD)] =
        &NetworkSelectorFactory::CreateWifi2WifiQoeSlowNetworkSelector;
    handleFuncMap[static_cast<uint32_t>(NetworkSelectType::USER_CONNECT)] =
        &NetworkSelectorFactory::CreateAutoConnectNetworkSelector;
}

std::optional<std::unique_ptr<NetworkSelection::INetworkSelector>> NetworkSelectorFactory::GetNetworkSelector(
    NetworkSelectType networkSelectType)
{
    auto iter = handleFuncMap.find(static_cast<uint32_t>(networkSelectType));
    if (iter != handleFuncMap.end()) {
        return (this->*(iter->second))();
    }
    WIFI_LOGE("not find function to deal, code %{public}u", static_cast<uint32_t>(networkSelectType));
    return std::nullopt;
}

std::unique_ptr<NetworkSelection::INetworkSelector> NetworkSelectorFactory::CreateAutoConnectNetworkSelector()
{
    return std::make_unique<NetworkSelection::AutoConnectIntegrator>();
}

std::unique_ptr<NetworkSelection::INetworkSelector> NetworkSelectorFactory::CreateWifi2WifiNetworkSelector()
{
    return std::make_unique<NetworkSelection::Wifi2WifiIntegrator>();
}

std::unique_ptr<NetworkSelection::INetworkSelector> NetworkSelectorFactory::CreateWifi2WifiNoNetNetworkSelector()
{
    return std::make_unique<NetworkSelection::Wifi2WifiNoNetIntegrator>();
}
 
std::unique_ptr<NetworkSelection::INetworkSelector> NetworkSelectorFactory::CreateWifi2WifiQoeSlowNetworkSelector()
{
    return std::make_unique<NetworkSelection::Wifi2WifiQoeSlowIntegrator>();
}
} // namespace OHOS::Wifi
