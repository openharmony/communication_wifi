//
// Created by 69036 on 2023/12/22.
//

#ifndef OHOS_WIFI_NETWORK_SELECTION_H_
#define OHOS_WIFI_NETWORK_SELECTION_H_

#include <memory>
#include "network_selection_msg.h"

namespace OHOS {
namespace Wifi {

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
    std::string GetFilterMsg() final;
protected:
    void AfterFilter(NetworkCandidate &networkCandidate, bool filterResult) override;
    std::string filterName;
};

class WifiFunctionFilterAdapter : public SimpleWifiFilter {
public:

    /**
     *
     * @param filter the point to filterFunction
     * @param networkSelectorFilterName the filterName
     * @param reverse for default it should be filtered when the function return true, And it can be modified;
     */
    WifiFunctionFilterAdapter(const std::function<bool(NetworkCandidate &)> &filter,
                              const std::string &networkSelectorFilterName,
                              bool reverse = false);
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
    std::function<bool(NetworkCandidate &)> targetFunction;
    bool iSReverse;
};


class CompositeWifiFilter : public IWifiFilter {
public:
    CompositeWifiFilter() = default;
    /**
     *  Add Filter for composite network selector filter
     * @param filter filter
     */
    virtual void AddFilter(const std::shared_ptr<IWifiFilter> &filter);
protected:
    std::vector<std::shared_ptr<IWifiFilter>> filters;
};

class AndWifiFilter : public CompositeWifiFilter {
public:
    AndWifiFilter() = default;
    bool Filter(NetworkCandidate &networkCandidate) override;
    std::string GetFilterMsg() override;
};

class OrWifiFilter : public CompositeWifiFilter {
public:
    OrWifiFilter() = default;
    bool Filter(NetworkCandidate &networkCandidate) override;
    std::string GetFilterMsg() override;
};

struct ScoreResult {
    double score;
    std::string scorerName;
    std::vector<ScoreResult> scoreDetails;
    ScoreResult()
    {
        score = 0;
    }
};

class IWifiScorer {
public:
    virtual ~IWifiScorer() = default;
    virtual void DoScore(NetworkCandidate &networkCandidate, ScoreResult &scoreResult) = 0;
};

class SimpleWifiScorer : public IWifiScorer {
public:
    explicit SimpleWifiScorer(const std::string &scorerName);
    void DoScore(NetworkCandidate &networkCandidate, ScoreResult &scoreResult) final;
protected:
    virtual double Score(NetworkCandidate &networkCandidate) = 0;
    std::string m_scoreName;
};

class CompositeWifiScorer : public IWifiScorer {
public:
    explicit CompositeWifiScorer(const std::string &scorerName);
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
}
}
#endif
