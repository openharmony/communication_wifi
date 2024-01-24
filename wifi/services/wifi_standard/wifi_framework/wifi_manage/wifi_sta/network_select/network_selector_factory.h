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

#ifndef OHOS_WIFI_NETWORK_SELECTOR_FACTORY_H
#define OHOS_WIFI_NETWORK_SELECTOR_FACTORY_H

#include <memory>
#include <optional>
#include "network_selector_impl.h"
#include "wifi_errcode.h"

namespace OHOS::Wifi {
enum class NetworkSelectType { AUTO_CONNECT };
class NetworkSelectorFactory {
public:
    NetworkSelectorFactory();
    using HandleFunc = std::unique_ptr<NetworkSelection::INetworkSelector> (NetworkSelectorFactory::*)();
    using HandleFuncMap = std::map<int, HandleFunc>;

    /**
     * get network selector by type
     * @param networkSelectType
     * @return the network selector
     */
    std::optional<std::unique_ptr<NetworkSelection::INetworkSelector>> GetNetworkSelector(
        NetworkSelectType networkSelectType);

    /**
     * the function to create autoConnect networkSelector
     * @return the network selector
     */
    std::unique_ptr<NetworkSelection::INetworkSelector> CreateAutoConnectNetworkSelector();
private:
    HandleFuncMap handleFuncMap;
};
}

#endif
