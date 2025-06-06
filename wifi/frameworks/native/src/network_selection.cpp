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

#include "network_selection.h"

namespace OHOS::Wifi::NetworkSelection {

std::map<FiltedReason, std::string> filtReasonToString = {
    {FiltedReason::UNKNOW, "UNKNOW"},
    {FiltedReason::HIDDEN_NETWORK, "HIDDEN_NETWORK"},
    {FiltedReason::OPEN_NETWORK, "OPEN_NETWORK"},
    {FiltedReason::NOT_OPEN_NETWORK, "NOT_OPEN_NETWORK"},
    {FiltedReason::WEAK_ALGORITHM_WEP_SECURITY, "WEAK_ALGORITHM_WEP_SECURITY"},
    {FiltedReason::WEAK_ALGORITHM_WPA_SECURITY, "WEAK_ALGORITHM_WPA_SECURITY"},
    {FiltedReason::HAS_NETWORK_HISTORY, "HAS_NETWORK_HISTORY"},
    {FiltedReason::PORTAL_NETWORK, "PORTAL_NETWORK"},
    {FiltedReason::NOT_PORTAL_NETWORK, "NOT_PORTAL_NETWORK"},
    {FiltedReason::OWE_NETWORK, "OWE_NETWORK"},
    {FiltedReason::UNRECOVERABLE_NETWORK, "UNRECOVERABLE_NETWORK"},
    {FiltedReason::NETWORK_STATUS_DISABLE, "NETWORK_STATUS_DISABLE"},
    {FiltedReason::UNEXPECTED_NETWORK_BY_USER, "UNEXPECTED_NETWORK_BY_USER"},
    {FiltedReason::NO_INTERNET, "NO_INTERNET"},
    {FiltedReason::HAS_INTERNET, "HAS_INTERNET"},
    {FiltedReason::NETWORK_ID_INVALID, "NETWORK_ID_INVALID"},
    {FiltedReason::NOT_SYSTEM_NETWORK, "NOT_SYSTEM_NETWORK"},
    {FiltedReason::TIME_INVALID, "TIME_INVALID"},
    {FiltedReason::EPHEMERAL_NETWORK, "EPHEMERAL_NETWORK"},
    {FiltedReason::PASSPOINT_NETWORK, "PASSPOINT_NETWORK"},
    {FiltedReason::POOR_SIGNAL, "POOR_SIGNAL"},
    {FiltedReason::TIMEOUT_AND_NEED_RECHECK, "TIMEOUT_AND_NEED_RECHECK"},
    {FiltedReason::NOT_ALLOW_AUTO_CONNECT, "NOT_ALLOW_AUTO_CONNECT"},
};

std::string NetworkCandidate::ToString(const std::string &filterName) const
{
    std::stringstream networkCandidateInfo;
    networkCandidateInfo << wifiDeviceConfig.networkId << "-";
    constexpr int BSSID_MIN_SIZE = 2;
    if (interScanInfo.bssid.size() <= BSSID_MIN_SIZE) {
        networkCandidateInfo << interScanInfo.bssid;
    } else {
        networkCandidateInfo << interScanInfo.bssid.substr(interScanInfo.bssid.size() - BSSID_MIN_SIZE);
    }
    if (filterName.empty()) {
        return networkCandidateInfo.str();
    }
    std::set<FiltedReason, FiltedReasonComparator, std::allocator<FiltedReason>> reasons = filtedReason.at(filterName);
    if (reasons.empty()) {
        return networkCandidateInfo.str();
    }
    networkCandidateInfo << "-";
    for (const auto &reason: reasons) {
        networkCandidateInfo << filtReasonToString[reason] << "&";
    }
    std::string candidateInfoStr = networkCandidateInfo.str();
    candidateInfoStr.erase(candidateInfoStr.size() - 1);
    return candidateInfoStr;
}

std::string ScoreResult::ToString() const
{
    constexpr int precision = 2;
    std::stringstream scoreMsg;
    scoreMsg << "{ ";
    scoreMsg << scorerName << " : " << std::fixed << std::setprecision(precision) << score;
    if (scoreDetails.empty()) {
        scoreMsg << " }";
        return scoreMsg.str();
    }
    scoreMsg << ", \"details\" : { ";
    for (std::size_t i = 0; i < scoreDetails.size(); i++) {
        scoreMsg << scoreDetails.at(i).ToString();
        if (i < (scoreDetails.size() - 1)) {
            scoreMsg << ", ";
        }
    }
    scoreMsg << " }";
    return scoreMsg.str();
}

bool IWifiFilter::DoFilter(NetworkCandidate &networkCandidate)
{
    bool filterResult = Filter(networkCandidate);
    AfterFilter(networkCandidate, filterResult);
    return filterResult;
}

void IWifiFilter::AfterFilter(NetworkCandidate &networkCandidate,
                              bool filterResult) {}

SimpleWifiFilter::SimpleWifiFilter(const std::string &networkSelectorFilterName)
    : IWifiFilter(), filterName(networkSelectorFilterName) {}

SimpleWifiFilter::~SimpleWifiFilter() = default;

void SimpleWifiFilter::AfterFilter(NetworkCandidate &networkCandidate, bool filterResult)
{
    if (!filterResult) {
        filteredNetworkCandidates.emplace_back(&networkCandidate);
    }
}

std::string SimpleWifiFilter::GetFilterMsg()
{
    return filterName;
}

WifiFunctionFilterAdapter::WifiFunctionFilterAdapter(const std::function<bool(NetworkCandidate &)> &filter,
                                                     const std::string &filterName,
                                                     bool reverse)
    : IWifiFilter(), targetFunction(filter), filterName(filterName), iSReverse(reverse) {}

WifiFunctionFilterAdapter::~WifiFunctionFilterAdapter() = default;

std::string WifiFunctionFilterAdapter::GetFilterMsg()
{
    return filterName;
}

bool WifiFunctionFilterAdapter::Filter(NetworkCandidate &networkCandidate)
{
    return iSReverse != targetFunction.operator()(networkCandidate);
}

CompositeWifiFilter::~CompositeWifiFilter() = default;

void CompositeWifiFilter::AddFilter(const std::shared_ptr<IWifiFilter> &filter)
{
    if (filter) {
        filters.emplace_back(filter);
    }
}

AndWifiFilter::~AndWifiFilter() = default;

bool AndWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    return std::all_of(filters.begin(), filters.end(), [&networkCandidate](auto filter) {
        return filter->DoFilter(networkCandidate);
    });
}

std::string AndWifiFilter::GetFilterMsg()
{
    std::stringstream filterMsg;
    filterMsg << "(";
    for (std::size_t i = 0; i < filters.size(); i++) {
        filterMsg << filters.at(i)->GetFilterMsg();
        if (i < filters.size() - 1) {
            filterMsg << "&&";
        }
    }
    filterMsg << ")";
    return filterMsg.str();
}

OrWifiFilter::~OrWifiFilter() = default;

bool OrWifiFilter::Filter(NetworkCandidate &networkCandidate)
{
    return std::any_of(filters.begin(), filters.end(), [&networkCandidate](auto filter) {
        return filter->DoFilter(networkCandidate);
    });
}

std::string OrWifiFilter::GetFilterMsg()
{
    std::stringstream filterMsg;
    filterMsg << "(";
    for (std::size_t i = 0; i < filters.size(); i++) {
        filterMsg << filters.at(i)->GetFilterMsg();
        if (i < filters.size() - 1) {
            filterMsg << "||";
        }
    }
    filterMsg << ")";
    return filterMsg.str();
}

SimpleWifiScorer::SimpleWifiScorer(const std::string &scorerName) : IWifiScorer(), m_scoreName(scorerName) {}

SimpleWifiScorer::~SimpleWifiScorer() = default;

void SimpleWifiScorer::DoScore(NetworkCandidate &networkCandidate, ScoreResult &scoreResult)
{
    scoreResult.scorerName = m_scoreName;
    scoreResult.score = Score(networkCandidate);
}

CompositeWifiScorer::CompositeWifiScorer(const std::string &scorerName) : IWifiScorer(), m_scoreName(scorerName) {}

CompositeWifiScorer::~CompositeWifiScorer() = default;

void CompositeWifiScorer::AddScorer(const std::shared_ptr<IWifiScorer> &scorer)
{
    if (scorer) {
        scorers.emplace_back(scorer);
    }
}

void CompositeWifiScorer::DoScore(NetworkCandidate &networkCandidate,
                                  ScoreResult &scoreResult)
{
    scoreResult.scorerName = m_scoreName;
    for (auto &score : scorers) {
        if (score) {
            ScoreResult subScoreResult;
            score->DoScore(networkCandidate, subScoreResult);
            scoreResult.scoreDetails.emplace_back(subScoreResult);
            scoreResult.score += subScoreResult.score;
        }
    }
}

WifiFunctionScorerAdapter::WifiFunctionScorerAdapter(const std::function<double(NetworkCandidate &)> &scorer,
                                                     const std::string &scorerName)
    :SimpleWifiScorer(scorerName), targetFunction(scorer) {}
 
WifiFunctionScorerAdapter::~WifiFunctionScorerAdapter() = default;
 
double WifiFunctionScorerAdapter::Score(NetworkCandidate &networkCandidate)
{
    return targetFunction.operator()(networkCandidate);
}

NetworkSelector::NetworkSelector(const std::string &networkSelectorName) : m_networkSelectorName(networkSelectorName) {}

NetworkSelector::~NetworkSelector() = default;

void NetworkSelector::SetWifiComparator(const std::shared_ptr<IWifiComparator> &networkSelectorComparator)
{
    comparator = networkSelectorComparator;
}

void NetworkSelector::SetWifiFilter(const std::shared_ptr<IWifiFilter> &networkSelectorFilter)
{
    filter = networkSelectorFilter;
}

bool NetworkSelector::TryNominate(NetworkCandidate &networkCandidate)
{
    bool ret = false;
    if (DoFilter(networkCandidate)) {
        ret = Nominate(networkCandidate);
    }
    return ret;
}

bool NetworkSelector::DoFilter(NetworkCandidate &networkCandidate)
{
    return !filter || filter->DoFilter(networkCandidate);
}

void NetworkSelector::GetBestCandidatesByComparator(std::vector<NetworkCandidate *> &selectedNetworkCandidates)
{
    if (comparator) {
        comparator->GetBestCandidates(networkCandidates, selectedNetworkCandidates);
    } else {
        selectedNetworkCandidates.insert(selectedNetworkCandidates.end(),
                                         networkCandidates.begin(),
                                         networkCandidates.end());
    }
}

SimpleNetworkSelector::SimpleNetworkSelector(const std::string &networkSelectorName)
    : NetworkSelector(networkSelectorName) {}

SimpleNetworkSelector::~SimpleNetworkSelector() = default;

bool SimpleNetworkSelector::Nominate(NetworkCandidate &networkCandidate)
{
    networkCandidates.emplace_back(&networkCandidate);
    return true;
}

std::string SimpleNetworkSelector::GetNetworkSelectorMsg()
{
    std::stringstream networkSelectorMsg;
    networkSelectorMsg << R"({ "name": ")" << m_networkSelectorName << "\" ";
    if (filter) {
        networkSelectorMsg << R"(,"filter": ")" << filter->GetFilterMsg() << "\"";
    }
    networkSelectorMsg << "}";
    return networkSelectorMsg.str();
}

void SimpleNetworkSelector::GetBestCandidates(std::vector<NetworkCandidate *> &selectedNetworkCandidates)
{
    GetBestCandidatesByComparator(selectedNetworkCandidates);
}

CompositeNetworkSelector::CompositeNetworkSelector(const std::string &networkSelectorName) : NetworkSelector(
    networkSelectorName) {}

CompositeNetworkSelector::~CompositeNetworkSelector() = default;

void CompositeNetworkSelector::AddSubNetworkSelector(const std::shared_ptr<INetworkSelector> &subNetworkSelector)
{
    if (subNetworkSelector) {
        subNetworkSelectors.emplace_back(subNetworkSelector);
    }
}

void CompositeNetworkSelector::GetBestCandidates(std::vector<NetworkCandidate *> &selectedNetworkCandidates)
{
    GetCandidatesFromSubNetworkSelector();
    GetBestCandidatesByComparator(selectedNetworkCandidates);
}

std::string CompositeNetworkSelector::GetNetworkSelectorMsg()
{
    std::stringstream networkSelectorMsg;
    networkSelectorMsg << R"({ "name": ")" << m_networkSelectorName << "\" ";
    if (filter) {
        networkSelectorMsg << R"(,"filter": ")" << filter->GetFilterMsg() << "\"";
    }
    if (!subNetworkSelectors.empty()) {
        networkSelectorMsg << R"(,"subNetworkSelectors": [)";
        for (std::size_t i = 0; i < subNetworkSelectors.size(); i++) {
            networkSelectorMsg << subNetworkSelectors.at(i)->GetNetworkSelectorMsg();
            if (i < subNetworkSelectors.size() - 1) {
                networkSelectorMsg << ",";
            }
        }
        networkSelectorMsg << "]";
    }
    networkSelectorMsg << "}";
    return networkSelectorMsg.str();
}
}