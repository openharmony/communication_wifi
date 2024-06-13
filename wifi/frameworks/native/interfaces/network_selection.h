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

#ifndef OHOS_WIFI_NETWORK_SELECTION_H
#define OHOS_WIFI_NETWORK_SELECTION_H
#include <functional>
#include <memory>
#include "wifi_msg.h"
#include "inter_scan_info.h"

namespace OHOS::Wifi {
namespace NetworkSelection {
struct NetworkCandidate {
    const InterScanInfo &interScanInfo;
    WifiDeviceConfig wifiDeviceConfig;
    explicit NetworkCandidate(const InterScanInfo &interScanInfo) : interScanInfo(interScanInfo), wifiDeviceConfig() {}
    std::string ToString() const;
};

struct ScoreResult {
    double score;
    std::string scorerName;
    std::vector<ScoreResult> scoreDetails;
    ScoreResult() : score(0) {}
    std::string ToString() const;
};

class IWifiFilter {
public:
    virtual ~IWifiFilter() = default;

    /**
     * filter the candidate network
     * @param networkCandidate candidate network.
     * @return true if the candidate network satisfy the condition
     */
    virtual bool DoFilter(NetworkCandidate &networkCandidate) final;
    virtual std::string GetFilterMsg() = 0;
protected:

    /**
     * filter the candidate network
     * @param networkCandidate candidate network.
     * @return true if the candidate network satisfy the condition
     */
    virtual bool Filter(NetworkCandidate &networkCandidate) = 0;

    /**
     * deal with the candidate network after filter
     * @param networkCandidate candidate network.
     * @param filterResult  if the candidate network satisfy the condition
     */
    virtual void AfterFilter(NetworkCandidate &networkCandidate, bool filterResult);
};

class SimpleWifiFilter : public IWifiFilter {
public:
    explicit SimpleWifiFilter(const std::string &networkSelectorFilterName);
    ~SimpleWifiFilter() override;
    std::string GetFilterMsg() final;
protected:
    void AfterFilter(NetworkCandidate &networkCandidate, bool filterResult) final;
    std::vector<NetworkCandidate *> filteredNetworkCandidates;
    std::string filterName;
};

class WifiFunctionFilterAdapter : public IWifiFilter {
public:

    /**
     *
     * @param filter the point to filterFunction
     * @param filterName the filterName
     * @param reverse for default it should be filtered when the function return true, And it can be modified;
     */
    WifiFunctionFilterAdapter(const std::function<bool(NetworkCandidate &)> &filter,
                              const std::string &filterName,
                              bool reverse = false);
    ~WifiFunctionFilterAdapter() override;
    std::string GetFilterMsg() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
    std::function<bool(NetworkCandidate &)> targetFunction;
    std::string filterName;
    bool iSReverse;
};

class CompositeWifiFilter : public IWifiFilter {
public:
    /**
     *  Add Filter for composite network selector filter
     * @param filter filter
     */
    virtual void AddFilter(const std::shared_ptr<IWifiFilter> &filter);
    ~CompositeWifiFilter() override;
protected:
    std::vector<std::shared_ptr<IWifiFilter>> filters;
};

class AndWifiFilter : public CompositeWifiFilter {
public:
    ~AndWifiFilter() override;
    bool Filter(NetworkCandidate &networkCandidate) override;
    std::string GetFilterMsg() override;
};

class OrWifiFilter : public CompositeWifiFilter {
public:
    bool Filter(NetworkCandidate &networkCandidate) override;
    ~OrWifiFilter() override;
    std::string GetFilterMsg() override;
};

class IWifiScorer {
public:
    virtual ~IWifiScorer() = default;
    virtual void DoScore(NetworkCandidate &networkCandidate, ScoreResult &scoreResult) = 0;
};

class SimpleWifiScorer : public IWifiScorer {
public:
    explicit SimpleWifiScorer(const std::string &scorerName);
    ~SimpleWifiScorer() override;
    void DoScore(NetworkCandidate &networkCandidate, ScoreResult &scoreResult) final;
protected:
    virtual double Score(NetworkCandidate &networkCandidate) = 0;
    std::string m_scoreName;
};

class CompositeWifiScorer : public IWifiScorer {
public:
    explicit CompositeWifiScorer(const std::string &scorerName);
    ~CompositeWifiScorer() override;
    void DoScore(NetworkCandidate &networkCandidate, ScoreResult &scoreResult) final;
    void AddScorer(const std::shared_ptr<IWifiScorer> &scorer);
protected:
    std::vector<std::shared_ptr<IWifiScorer>> scorers;
    std::string m_scoreName;
};

class IWifiComparator {
public:
    virtual ~IWifiComparator() = default;

    /**
     * GetBestCandidates
     *
     * @param candidates the candidate network before compare.
     * @param selectedCandidates the best candidate network after compare.
     */
    virtual void GetBestCandidates(const std::vector<NetworkCandidate *> &candidates,
                                   std::vector<NetworkCandidate *> &selectedCandidates) = 0;
};

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
    ~NetworkSelector() override;
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

    std::vector<NetworkCandidate *> networkCandidates;
    std::shared_ptr<IWifiComparator> comparator;
    std::shared_ptr<IWifiFilter> filter;
    const std::string m_networkSelectorName;
};

class SimpleNetworkSelector : public NetworkSelector {
public:
    explicit SimpleNetworkSelector(const std::string &networkSelectorName);
    ~SimpleNetworkSelector() override;
    std::string GetNetworkSelectorMsg() override;
    void GetBestCandidates(std::vector<NetworkCandidate *> &selectedNetworkCandidates) final;
protected:
    bool Nominate(NetworkCandidate &networkCandidate) override;
};

class CompositeNetworkSelector : public NetworkSelector {
public:
    explicit CompositeNetworkSelector(const std::string &networkSelectorName);
    ~CompositeNetworkSelector() override;
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
}

enum class FilterTag {
    SAVED_NETWORK_TRACKER_FILTER_TAG,
    HAS_INTERNET_NETWORK_SELECTOR_FILTER_TAG,
    RECOVERY_NETWORK_SELECTOR_FILTER_TAG,
    PORTAL_NETWORK_SELECTOR_FILTER_TAG,
    IT_NETWORK_SELECTOR_FILTER_TAG
};

using FilterBuilder = std::function<void(NetworkSelection::CompositeWifiFilter &)>;
}
#endif
