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
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("NetworkSelection")

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

void SimpleWifiFilter::AfterFilter(NetworkCandidate &networkCandidate, bool filterResult)
{
    if (!filterResult) {
        networkCandidate.filteredMsg.emplace_back(filterName);
    }
}

std::string SimpleWifiFilter::GetFilterMsg()
{
    return filterName;
}

WifiFunctionFilterAdapter::WifiFunctionFilterAdapter(const std::function<bool(NetworkCandidate &)> &filter,
                                                     const std::string &networkSelectorFilterName,
                                                     bool reverse)
    : SimpleWifiFilter(networkSelectorFilterName), targetFunction(filter), iSReverse(reverse) {}

bool WifiFunctionFilterAdapter::Filter(NetworkCandidate &networkCandidate)
{
    return iSReverse != targetFunction.operator()(networkCandidate);
}

void CompositeWifiFilter::AddFilter(const std::shared_ptr<IWifiFilter> &filter)
{
    if (filter) {
        filters.emplace_back(filter);
    }
}

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
    for (auto i = 0; i < filters.size(); i++) {
        filterMsg << filters.at(i)->GetFilterMsg();
        if (i < filters.size() - 1) {
            filterMsg << "&&";
        }
    }
    filterMsg << ")";
    return filterMsg.str();
}

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
    for (auto i = 0; i < filters.size(); i++) {
        filterMsg << filters.at(i)->GetFilterMsg();
        if (i < filters.size() - 1) {
            filterMsg << "||";
        }
    }
    filterMsg << ")";
    return filterMsg.str();
}

SimpleWifiScorer::SimpleWifiScorer(const std::string &scorerName) : IWifiScorer(), m_scoreName(scorerName) {}

void SimpleWifiScorer::DoScore(NetworkCandidate &networkCandidate, ScoreResult &scoreResult)
{
    scoreResult.scorerName = m_scoreName;
    scoreResult.score = Score(networkCandidate);
}

CompositeWifiScorer::CompositeWifiScorer(const std::string &scorerName) : IWifiScorer(), m_scoreName(scorerName) {}

void CompositeWifiScorer::AddScorer(const std::shared_ptr<IWifiScorer> &scorer)
{
    scorers.emplace_back(scorer);
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

NetworkSelector::NetworkSelector(const std::string &networkSelectorName) : m_networkSelectorName(networkSelectorName) {}

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
        AfterNominate(networkCandidate, ret);
    }
    return ret;
}

bool NetworkSelector::DoFilter(NetworkCandidate &networkCandidate)
{
    return !filter || filter->DoFilter(networkCandidate);
}

void NetworkSelector::AfterNominate(NetworkCandidate &networkCandidate, bool nominateResult)
{
    if (nominateResult) {
        networkCandidate.nominateMsg.emplace_back(m_networkSelectorName);
    }
}

void NetworkSelector::GetBestCandidatesByComparator(std::vector<NetworkCandidate *> &selectedNetworkCandidates)
{
    if (comparator) {
        comparator->GetBestCandidates(networkCandidates, selectedNetworkCandidates);
    } else {
        WIFI_LOGI("comparator in %{public}s is null, select all networkCandidates as result",
                  m_networkSelectorName.c_str());
        selectedNetworkCandidates.insert(selectedNetworkCandidates.end(),
                                         networkCandidates.begin(),
                                         networkCandidates.end());
    }
}

void SimpleNetworkSelector::GetBestCandidates(std::vector<NetworkCandidate *> &selectedNetworkCandidates)
{
    GetBestCandidatesByComparator(selectedNetworkCandidates);
}

SimpleNetworkSelector::SimpleNetworkSelector(const std::string &networkSelectorName)
    : NetworkSelector(networkSelectorName) {}

CompositeNetworkSelector::CompositeNetworkSelector(const std::string &networkSelectorName) : NetworkSelector(
    networkSelectorName) {}

void CompositeNetworkSelector::AddSubNetworkSelector(const std::shared_ptr<INetworkSelector> &subNetworkSelector)
{
    subNetworkSelectors.emplace_back(subNetworkSelector);
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
        for (auto i = 0; i < subNetworkSelectors.size(); i++) {
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
}
}