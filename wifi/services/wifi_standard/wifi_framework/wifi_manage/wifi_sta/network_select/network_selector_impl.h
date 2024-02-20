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

#ifndef OHOS_WIFI_NETWORK_SELECTOR_IMPL_H_
#define OHOS_WIFI_NETWORK_SELECTOR_IMPL_H_

#include <memory>
#include "network_selection.h"

namespace OHOS::Wifi::NetworkSelection  {
class AutoConnectIntegrator : public CompositeNetworkSelector {
public:
    AutoConnectIntegrator();
protected:
    bool Nominate(NetworkCandidate &networkCandidate) override;
    void GetCandidatesFromSubNetworkSelector() override;
};

class SavedNetworkTracker final: public CompositeNetworkSelector {
public:
    SavedNetworkTracker();
protected:
    bool Nominate(NetworkCandidate &networkCandidate) override;
    void GetCandidatesFromSubNetworkSelector() override;
};

class SimpleFilterNetworkSelector : public SimpleNetworkSelector, public SimpleWifiFilter {
public:
    explicit SimpleFilterNetworkSelector(const std::string &networkSelectorName);
    ~SimpleFilterNetworkSelector() override;
};

class BlackListNetworkSelector final: public SimpleFilterNetworkSelector {
public:
    BlackListNetworkSelector();
protected:
    bool Nominate(NetworkCandidate &networkCandidate) override;
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class HasInternetNetworkSelector final: public SimpleFilterNetworkSelector {
public:
    HasInternetNetworkSelector();
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

#ifdef FEATURE_ITNETWORK_PREFERRED_SUPPORT
class CustNetPreferredNetworkSelector : public SimpleFilterNetworkSelector {
public:
    CustNetPreferredNetworkSelector();
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};
#endif

class RecoveryNetworkSelector final: public SimpleFilterNetworkSelector {
public:
    RecoveryNetworkSelector();
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class PortalNetworkSelector final : public SimpleNetworkSelector, public OrWifiFilter {
public:
    PortalNetworkSelector();
    ~PortalNetworkSelector() override;
    void InitFilter();
    std::string GetNetworkSelectorMsg() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
    std::vector<NetworkCandidate*> filteredNetworkCandidates;
};

class NoInternetNetworkSelector final: public SimpleFilterNetworkSelector {
public:
    NoInternetNetworkSelector();
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};
}
#endif
