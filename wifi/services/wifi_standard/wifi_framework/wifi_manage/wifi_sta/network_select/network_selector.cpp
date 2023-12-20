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

#include <sstream>
#include "network_selector.h"
#include "network_selection_utils.h"
#include "network_filter_builder_manager.h"
#include "wifi_logger.h"

using namespace std;

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("NETWORK_SELECTOR")

NetworkSelector::NetworkSelector(const string &networkSelectorName):m_networkSelectorName(networkSelectorName) {}

void NetworkSelector::SetWifiComparator(const shared_ptr<IWifiComparator> &networkSelectorComparator)
{
    comparator = networkSelectorComparator;
}

void NetworkSelector::SetWifiFilter(const shared_ptr<IWifiFilter> &networkSelectorFilter)
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

void NetworkSelector::GetBestCandidatesByComparator(vector<NetworkCandidate *> &selectedNetworkCandidates)
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

void SimpleNetworkSelector::GetBestCandidates(vector<NetworkCandidate *> &selectedNetworkCandidates)
{
    GetBestCandidatesByComparator(selectedNetworkCandidates);
}

SimpleNetworkSelector::SimpleNetworkSelector(const string &networkSelectorName)
    : NetworkSelector(networkSelectorName) {}

CompositeNetworkSelector::CompositeNetworkSelector(const string &networkSelectorName) : NetworkSelector(
    networkSelectorName) {}

void CompositeNetworkSelector::AddSubNetworkSelector(const shared_ptr<INetworkSelector> &subNetworkSelector)
{
    subNetworkSelectors.emplace_back(subNetworkSelector);
}

void CompositeNetworkSelector::GetBestCandidates(vector<NetworkCandidate *> &selectedNetworkCandidates)
{
    GetCandidatesFromSubNetworkSelector();
    GetBestCandidatesByComparator(selectedNetworkCandidates);
}

void AutoConnectNetworkSelector::GetCandidatesFromSubNetworkSelector()
{
    for (const auto &subNetworkSelector : subNetworkSelectors) {
        subNetworkSelector->GetBestCandidates(networkCandidates);
    }
}

string CompositeNetworkSelector::GetNetworkSelectorMsg()
{
    stringstream networkSelectorMsg;
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

AutoConnectNetworkSelector::AutoConnectNetworkSelector() : CompositeNetworkSelector(
    "autoConnectedNetworkSelectorManager")
{
    auto filters = make_shared<AndWifiFilter>();
    filters->AddFilter(make_shared<WifiFunctionFilter>(NetworkSelectionUtils::IsHiddenNetwork,
                                                       "notHiddenNetwork",
                                                       true));
    filters->AddFilter(make_shared<WifiFunctionFilter>(NetworkSelectionUtils::IsSignalTooWeak,
                                                       "notSignalTooWeak",
                                                       true));
    SetWifiFilter(filters);
    auto savedNetworkSelector = make_shared<SavedNetworkSelector>();
    AddSubNetworkSelector(savedNetworkSelector);
    auto comparator = make_shared<WifiScorerComparator>(m_networkSelectorName);
    comparator->AddScorer(make_shared<ThroughputScorer>());
    SetWifiComparator(comparator);
}

bool AutoConnectNetworkSelector::Nominate(NetworkCandidate &networkCandidate)
{
    for (auto &networkSelector : subNetworkSelectors) {
        networkSelector->TryNominate(networkCandidate);
    }
    return false;
}

SavedNetworkSelector::SavedNetworkSelector() : CompositeNetworkSelector("savedNetworkSelector")
{
    auto andFilter = make_shared<AndWifiFilter>();
    andFilter->AddFilter(make_shared<WifiFunctionFilter>(NetworkSelectionUtils::IsSavedNetwork, "savedNetwork"));
    andFilter->AddFilter(make_shared<WifiFunctionFilter>(NetworkSelectionUtils::IsPassPointNetwork,
                                                         "notPassPoint",
                                                         true));
    andFilter->AddFilter(make_shared<WifiFunctionFilter>(NetworkSelectionUtils::IsEphemeralNetwork,
                                                         "notEphemeral",
                                                         true));
    andFilter->AddFilter(make_shared<WifiFunctionFilter>(NetworkSelectionUtils::IsNetworkEnabled, "enableNetwork"));
    andFilter->AddFilter(make_shared<WifiFunctionFilter>(NetworkSelectionUtils::IsMatchUserSelected,
                                                         "matchUserSelected"));
    ExternalWifiFilterBuildManager::GetInstance().BuildFilter(FilterTag::SAVED_NETWORK_SELECTOR_FILTER_TAG, *andFilter);
    auto blackListNetworkSelector = make_shared<BlackListNetworkSelector>();
    auto hasInternetNetworkSelector = make_shared<HasInternetNetworkSelector>();
    auto recoveryNetworkSelector = make_shared<RecoveryNetworkSelector>();
    auto portalNetworkSelector = make_shared<PortalNetworkSelector>();
    portalNetworkSelector->InitFilter();
    auto noInternetNetworkSelector = make_shared<NoInternetNetworkSelector>();
    andFilter->AddFilter(blackListNetworkSelector);
    andFilter->AddFilter(hasInternetNetworkSelector);
    andFilter->AddFilter(recoveryNetworkSelector);
    andFilter->AddFilter(portalNetworkSelector);
    andFilter->AddFilter(noInternetNetworkSelector);
    SetWifiFilter(andFilter);
    AddSubNetworkSelector(hasInternetNetworkSelector);
    AddSubNetworkSelector(recoveryNetworkSelector);
    AddSubNetworkSelector(portalNetworkSelector);
    AddSubNetworkSelector(noInternetNetworkSelector);
    AddSubNetworkSelector(blackListNetworkSelector);
}

bool SavedNetworkSelector::Nominate(NetworkCandidate &networkCandidate)
{
    return false;
}

void SavedNetworkSelector::GetCandidatesFromSubNetworkSelector()
{
    for (const auto &subNetworkSelector : subNetworkSelectors) {
        subNetworkSelector->GetBestCandidates(networkCandidates);
        if (!networkCandidates.empty()) {
            /* abandon networkCandidates from other low-priority networkSelectors */
            return;
        }
    }
}

bool SimpleNetworkSelector::Nominate(NetworkCandidate &networkCandidate)
{
    networkCandidates.emplace_back(&networkCandidate);
    return true;
}

string SimpleNetworkSelector::GetNetworkSelectorMsg()
{
    stringstream networkSelectorMsg;
    networkSelectorMsg << R"({ "name": ")" << m_networkSelectorName << "\" ";
    if (filter) {
        networkSelectorMsg << R"(,"filter": ")" << filter->GetFilterMsg() << "\"";
    }
    networkSelectorMsg << "}";
    return networkSelectorMsg.str();
}

BlackListNetworkSelector::BlackListNetworkSelector() : SimpleNetworkSelector("blackListNetworkSelector"),
                                                       SimpleWifiFilter("blackListNetworkSelector")
{
    SetWifiFilter(make_shared<WifiFunctionFilter>(NetworkSelectionUtils::IsBlackListNetwork, "inBlackList"));
}

bool BlackListNetworkSelector::Nominate(NetworkCandidate &networkCandidate)
{
    if (!networkCandidates.empty()) {
        networkCandidates.at(0) = &networkCandidate;
    } else {
        networkCandidates.emplace_back(&networkCandidate);
    }
    return true;
}

bool BlackListNetworkSelector::Filter(NetworkCandidate &networkCandidate)
{
    return !TryNominate(networkCandidate);
}

HasInternetNetworkSelector::HasInternetNetworkSelector() : SimpleNetworkSelector("hasInternetNetworkSelector"),
                                                           SimpleWifiFilter("hasInternetNetworkSelector")
{
    auto filters = make_shared<AndWifiFilter>();
    ExternalWifiFilterBuildManager::GetInstance().BuildFilter(FilterTag::HAS_INTERNET_NETWORK_SELECTOR_FILTER_TAG,
                                                              *filters);
    filters->AddFilter(make_shared<WifiFunctionFilter>(NetworkSelectionUtils::IsHasInternetNetwork, "hasInternet"));
    SetWifiFilter(filters);
    auto networkScoreComparator = make_shared<WifiScorerComparator>(m_networkSelectorName);
    networkScoreComparator->AddScorer(make_shared<NetworkStatusHistoryScorer>());
    networkScoreComparator->AddScorer(make_shared<SavedNetworkScorer>("hasInternetNetworkScorer"));
    networkScoreComparator->AddScorer(make_shared<RssiScorer>());
    SetWifiComparator(networkScoreComparator);
}

bool HasInternetNetworkSelector::Filter(NetworkCandidate &networkCandidate)
{
    TryNominate(networkCandidate);
    return networkCandidates.empty();
}

RecoveryNetworkSelector::RecoveryNetworkSelector() : SimpleNetworkSelector("recoveryNetworkSelector"),
                                                     SimpleWifiFilter("recoveryNetworkSelector")
{
    auto filters = make_shared<AndWifiFilter>();
    ExternalWifiFilterBuildManager::GetInstance().BuildFilter(FilterTag::RECOVERY_NETWORK_SELECTOR_FILTER_TAG,
                                                              *filters);
    filters->AddFilter(make_shared<WifiFunctionFilter>(NetworkSelectionUtils::IsRecoveryNetwork, "recovery"));
    SetWifiFilter(filters);
    auto networkScorerComparator = make_shared<WifiScorerComparator>(m_networkSelectorName);
    networkScorerComparator->AddScorer(make_shared<SavedNetworkScorer>("recoveryNetworkScorer"));
    networkScorerComparator->AddScorer(make_shared<RssiScorer>());
    SetWifiComparator(networkScorerComparator);
}

bool RecoveryNetworkSelector::Filter(NetworkCandidate &networkCandidate)
{
    TryNominate(networkCandidate);
    return networkCandidates.empty();
}

PortalNetworkSelector::PortalNetworkSelector() : SimpleNetworkSelector("portalNetworkSelector"), OrWifiFilter()
{
    SetWifiFilter(make_shared<WifiFunctionFilter>(NetworkSelectionUtils::IsPoorPortalNetwork, "notPoorPortal", true));
    auto networkScorerComparator = make_shared<WifiScorerComparator>(m_networkSelectorName);
    networkScorerComparator->AddScorer(make_shared<LastHaveInternetTimeScorer>());
    networkScorerComparator->AddScorer(make_shared<SavedNetworkScorer>("portalNetworkScorer"));
    networkScorerComparator->AddScorer(make_shared<RssiScorer>());
    SetWifiComparator(networkScorerComparator);
}

void PortalNetworkSelector::InitFilter()
{
    AddFilter(make_shared<WifiFunctionFilter>(NetworkSelectionUtils::IsPortalNetwork, "portal"));
    AddFilter(make_shared<WifiFunctionFilter>(NetworkSelectionUtils::MayBePortalNetwork, "maybePortal"));
    ExternalWifiFilterBuildManager::GetInstance().BuildFilter(FilterTag::PORTAL_NETWORK_SELECTOR_FILTER_TAG, *this);
}

bool PortalNetworkSelector::Filter(NetworkCandidate &networkCandidate)
{
    if (OrWifiFilter::Filter(networkCandidate)) {
        TryNominate(networkCandidate);
        return false;
    }
    if (networkCandidates.empty()) {
        return true;
    }
    networkCandidate.filteredMsg.emplace_back(m_networkSelectorName);
    return false;
}

string PortalNetworkSelector::GetNetworkSelectorMsg()
{
    stringstream networkSelectorMsg;
    networkSelectorMsg << R"({ "name": ")" << m_networkSelectorName << "\" ";
    string filterMsg;
    if (!filters.empty()) {
        filterMsg += OrWifiFilter::GetFilterMsg();
    }
    if (filter) {
        if (!filterMsg.empty()) {
            filterMsg += "&&";
        }
        filterMsg += filter->GetFilterMsg();
    }
    if (!filterMsg.empty()) {
        networkSelectorMsg << R"(,"filter": ")" << filterMsg << "\"";
    }
    networkSelectorMsg << "}";
    return networkSelectorMsg.str();
}

string PortalNetworkSelector::GetFilterMsg()
{
    return m_networkSelectorName;
}

NoInternetNetworkSelector::NoInternetNetworkSelector() : SimpleNetworkSelector("noInternetNetworkSelector"),
                                                         SimpleWifiFilter("noInternetNetworkSelector")
{
    SetWifiFilter(make_shared<WifiFunctionFilter>(NetworkSelectionUtils::IsNoInternetNetwork, "noInternet"));
    auto networkScorerComparator = make_shared<WifiScorerComparator>(m_networkSelectorName);
    networkScorerComparator->AddScorer(make_shared<SavedNetworkScorer>("noInternetNetworkScorer"));
    networkScorerComparator->AddScorer(make_shared<RssiScorer>());
    SetWifiComparator(networkScorerComparator);
}

bool NoInternetNetworkSelector::Filter(NetworkCandidate &networkCandidate)
{
    TryNominate(networkCandidate);
    return false;
}
}
}