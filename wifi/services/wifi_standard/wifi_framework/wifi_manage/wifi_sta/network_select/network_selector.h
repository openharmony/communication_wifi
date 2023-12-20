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

#ifndef OHOS_WIFI_NETWORK_SELECTOR_H_
#define OHOS_WIFI_NETWORK_SELECTOR_H_

#include <memory>
#include "network_selector_comparator.h"
#include "network_selector_filter.h"
#include "network_selection_msg.h"

namespace OHOS {
namespace Wifi {
class INetworkSelector {
public:
    virtual ~INetworkSelector() = default;

    /**
     *  the function to try nominator the candidate network.
     *
     * @param networkCandidate candidate network
     * @return return true if the candidate network is nominated.
     */
    virtual bool TryNominate(NetworkCandidate &networkCandidate) = 0;

    /**
     * the function to get best candidate networks.
     * @param selectedNetworkCandidates the best candidate networks.
     */
    virtual void GetBestCandidates(std::vector<NetworkCandidate *> &selectedNetworkCandidates) = 0;

    /**
     * transfer the info of network selector to json format string.
     * @return
     */
    virtual std::string GetNetworkSelectorMsg() = 0;
};

class NetworkSelector : public INetworkSelector {
public:

    explicit NetworkSelector(const std::string &networkSelectorName);

    /**
     * the function to set comparator。
     *
     * @param networkSelectorComparator comparator
     */
    virtual void SetWifiComparator(const std::shared_ptr<IWifiComparator> &networkSelectorComparator) final;

    /**
     * the function to set filter.
     *
     * @param networkSelectorFilter filter
     */
    virtual void SetWifiFilter(const std::shared_ptr<IWifiFilter> &networkSelectorFilter) final;
    bool TryNominate(NetworkCandidate &networkCandidate) final;
protected:

    /**
     * filter the candidate network
     *
     * @param networkCandidate candidate network
     * @return true if the candidate network pass.
     */
    virtual bool DoFilter(NetworkCandidate &networkCandidate) final;

    /**
     *  get best candidate network by comparator.
     *
     * @param selectedNetworkCandidates the best candidate networks;
     */
    virtual void GetBestCandidatesByComparator(std::vector<NetworkCandidate *> &selectedNetworkCandidates) final;

    /**
     * deal with the candidate network which pass the filter.
     *
     * @param networkCandidate candidate network
     * @return true if the candidate network is added to networkCandidates.
     */
    virtual bool Nominate(NetworkCandidate &networkCandidate) = 0;

    /**
     * deal with the candidate network after nominate.
     *
     * @param networkCandidate candidate network
     * @param nominateResult whether the candidate network is added to networkCandidates
     */
    virtual void AfterNominate(NetworkCandidate &networkCandidate, bool nominateResult);

    std::vector<NetworkCandidate *> networkCandidates;
    std::shared_ptr<IWifiComparator> comparator;
    std::shared_ptr<IWifiFilter> filter;
    const std::string m_networkSelectorName;
};

class SimpleNetworkSelector : public NetworkSelector {
public:
    explicit SimpleNetworkSelector(const std::string &networkSelectorName);
    std::string GetNetworkSelectorMsg() override;
    void GetBestCandidates(std::vector<NetworkCandidate *> &selectedNetworkCandidates) final;
protected:
    bool Nominate(NetworkCandidate &networkCandidate) override;
};

class CompositeNetworkSelector : public NetworkSelector {
public:
    explicit CompositeNetworkSelector(const std::string &networkSelectorName);

    /**
     * Add subnetworkSelector for compositeNetworkSelector
     *
     * @param subNetworkSelector  subNetworkSelector
     */
    void AddSubNetworkSelector(const std::shared_ptr<INetworkSelector> &subNetworkSelector);
    void GetBestCandidates(std::vector<NetworkCandidate *> &selectedNetworkCandidates) final;
    std::string GetNetworkSelectorMsg() override;
protected:
    /**
     * deal with the candidate network before compare.
     */
    virtual void GetCandidatesFromSubNetworkSelector() = 0;
    std::vector<std::shared_ptr<INetworkSelector>> subNetworkSelectors;
};

class AutoConnectNetworkSelector : public CompositeNetworkSelector {
public:
    AutoConnectNetworkSelector();
protected:
    bool Nominate(NetworkCandidate &networkCandidate) override;
    void GetCandidatesFromSubNetworkSelector() override;
};

class SavedNetworkSelector : public CompositeNetworkSelector {
public:
    SavedNetworkSelector();
protected:
    bool Nominate(NetworkCandidate &networkCandidate) override;
    void GetCandidatesFromSubNetworkSelector() override;
};

class BlackListNetworkSelector : public SimpleNetworkSelector, public SimpleWifiFilter {
public:
    BlackListNetworkSelector();
protected:
    bool Nominate(NetworkCandidate &networkCandidate) override;
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class HasInternetNetworkSelector : public SimpleNetworkSelector, public SimpleWifiFilter {
public:
    HasInternetNetworkSelector();
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class RecoveryNetworkSelector : public SimpleNetworkSelector, public SimpleWifiFilter {
public:
    RecoveryNetworkSelector();
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class PortalNetworkSelector final : public SimpleNetworkSelector, public OrWifiFilter {
public:
    PortalNetworkSelector();
    void InitFilter();
    std::string GetFilterMsg() override;
    std::string GetNetworkSelectorMsg() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class NoInternetNetworkSelector : public SimpleNetworkSelector, public SimpleWifiFilter {
public:
    NoInternetNetworkSelector();
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};
}
}
#endif
