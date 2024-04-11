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
#include "network_selector_impl.h"
#include "wifi_comparator_impl.h"
#include "wifi_scorer_impl.h"
#include "network_selection_utils.h"
#include "external_wifi_filter_builder_manager.h"
#include "wifi_filter_impl.h"
#include "wifi_logger.h"
#include "parameters.h"

using namespace std;

namespace OHOS::Wifi::NetworkSelection {

DEFINE_WIFILOG_LABEL("NetworkSelector")

void AutoConnectIntegrator::GetCandidatesFromSubNetworkSelector()
{
    for (const auto &subNetworkSelector : subNetworkSelectors) {
        subNetworkSelector->GetBestCandidates(networkCandidates);
    }
}

AutoConnectIntegrator::AutoConnectIntegrator() : CompositeNetworkSelector(
    "autoConnectIntegrator")
{
    auto filters = make_shared<AndWifiFilter>();
    filters->AddFilter(make_shared<HiddenWifiFilter>());
    filters->AddFilter(make_shared<SignalStrengthWifiFilter>());
    if (OHOS::system::GetParameter("ohos.boot.advsecmode.state", "0") != "0") {
        filters->AddFilter(make_shared<WeakAlgorithmWifiFilter>());
    }
    SetWifiFilter(filters);
    AddSubNetworkSelector(make_shared<SavedNetworkTracker>());
    auto comparator = make_shared<WifiScorerComparator>(m_networkSelectorName);
    comparator->AddScorer(make_shared<ThroughputScorer>());
    SetWifiComparator(comparator);
}

bool AutoConnectIntegrator::Nominate(NetworkCandidate &networkCandidate)
{
    for (auto &networkSelector : subNetworkSelectors) {
        networkSelector->TryNominate(networkCandidate);
    }
    return false;
}

SavedNetworkTracker::SavedNetworkTracker() : CompositeNetworkSelector("savedNetworkTracker")
{
    auto andFilter = make_shared<AndWifiFilter>();
    andFilter->AddFilter(make_shared<SavedWifiFilter>());
    andFilter->AddFilter(make_shared<PassPointWifiFilter>());
    andFilter->AddFilter(make_shared<EphemeralWifiFilter>());
    andFilter->AddFilter(make_shared<DisableWifiFilter>());
    andFilter->AddFilter(make_shared<MatchedUserSelectBssidWifiFilter>());
    ExternalWifiFilterBuildManager::GetInstance().BuildFilter(FilterTag::SAVED_NETWORK_TRACKER_FILTER_TAG, *andFilter);
#ifdef FEATURE_ITNETWORK_PREFERRED_SUPPORT
    shared_ptr<CustNetPreferredNetworkSelector> custNetPreferredNetworkSelector = nullptr;
    if (NetworkSelectionUtils::CheckDeviceTypeByVendorCountry()) {
        custNetPreferredNetworkSelector = make_shared<CustNetPreferredNetworkSelector>();
    }
#endif
    auto blackListNetworkSelector = make_shared<BlackListNetworkSelector>();
    auto hasInternetNetworkSelector = make_shared<HasInternetNetworkSelector>();
    auto recoveryNetworkSelector = make_shared<RecoveryNetworkSelector>();
    auto portalNetworkSelector = make_shared<PortalNetworkSelector>();
    portalNetworkSelector->InitFilter();
    auto noInternetNetworkSelector = make_shared<NoInternetNetworkSelector>();

#ifdef FEATURE_ITNETWORK_PREFERRED_SUPPORT
    andFilter->AddFilter(custNetPreferredNetworkSelector);
#endif
    andFilter->AddFilter(blackListNetworkSelector);
    andFilter->AddFilter(hasInternetNetworkSelector);
    andFilter->AddFilter(recoveryNetworkSelector);
    andFilter->AddFilter(portalNetworkSelector);
    andFilter->AddFilter(noInternetNetworkSelector);
    SetWifiFilter(andFilter);
    /*
     * current networkSelector only obtains one non-empty network selection result of subNetworkSelector, which is
     * depends on the sequence of the subNetworkSelectors, When the network selection result of one of the
     * subNetworkSelectors is not empty, the network selection result of other subNetworkSelectors inserted later will
     * be abandoned.
     */
#ifdef FEATURE_ITNETWORK_PREFERRED_SUPPORT
    AddSubNetworkSelector(custNetPreferredNetworkSelector);
#endif
    AddSubNetworkSelector(hasInternetNetworkSelector);
    AddSubNetworkSelector(recoveryNetworkSelector);
    AddSubNetworkSelector(portalNetworkSelector);
    AddSubNetworkSelector(noInternetNetworkSelector);
    AddSubNetworkSelector(blackListNetworkSelector);
}

bool SavedNetworkTracker::Nominate(NetworkCandidate &networkCandidate)
{
    return false;
}

void SavedNetworkTracker::GetCandidatesFromSubNetworkSelector()
{
    for (const auto &subNetworkSelector : subNetworkSelectors) {
        subNetworkSelector->GetBestCandidates(networkCandidates);
        if (!networkCandidates.empty()) {
            /* abandon networkCandidates from other low-priority networkSelectors */
            return;
        }
    }
}

SimpleFilterNetworkSelector::SimpleFilterNetworkSelector(const std::string &networkSelectorName)
    : SimpleNetworkSelector(networkSelectorName), SimpleWifiFilter(networkSelectorName) {}

SimpleFilterNetworkSelector::~SimpleFilterNetworkSelector()
{
    if (!networkCandidates.empty()) {
        WIFI_LOGI("networkCandidates in %{public}s: %{public}s",
                  m_networkSelectorName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(networkCandidates).c_str());
    }
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  m_networkSelectorName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

BlackListNetworkSelector::BlackListNetworkSelector() : SimpleFilterNetworkSelector("blackListNetworkSelector")
{
    SetWifiFilter(make_shared<WifiFunctionFilterAdapter>(NetworkSelectionUtils::IsBlackListNetwork, "isBlackList"));
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

HasInternetNetworkSelector::HasInternetNetworkSelector() : SimpleFilterNetworkSelector("hasInternetNetworkSelector")
{
    auto filters = make_shared<AndWifiFilter>();
    ExternalWifiFilterBuildManager::GetInstance().BuildFilter(FilterTag::HAS_INTERNET_NETWORK_SELECTOR_FILTER_TAG,
                                                              *filters);
    filters->AddFilter(make_shared<HasInternetWifiFilter>());
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

#ifdef FEATURE_ITNETWORK_PREFERRED_SUPPORT
CustNetPreferredNetworkSelector::CustNetPreferredNetworkSelector()
    : SimpleFilterNetworkSelector("custNetPreferredNetworkSelector")
{
    auto filters = make_shared<OrWifiFilter>();
    ExternalWifiFilterBuildManager::GetInstance().BuildFilter(FilterTag::IT_NETWORK_SELECTOR_FILTER_TAG,
                                                              *filters);
    SetWifiFilter(filters);
    auto networkScoreComparator = make_shared<WifiScorerComparator>(m_networkSelectorName);
    networkScoreComparator->AddScorer(make_shared<SavedNetworkScorer>("custNetPreferredNetworkScorer"));
    networkScoreComparator->AddScorer(make_shared<RssiScorer>());
    SetWifiComparator(networkScoreComparator);
}

bool CustNetPreferredNetworkSelector::Filter(NetworkCandidate &networkCandidate)
{
    return !NetworkSelector::TryNominate(networkCandidate);
}
#endif

RecoveryNetworkSelector::RecoveryNetworkSelector() : SimpleFilterNetworkSelector("recoveryNetworkSelector")
{
    auto filters = make_shared<AndWifiFilter>();
    ExternalWifiFilterBuildManager::GetInstance().BuildFilter(FilterTag::RECOVERY_NETWORK_SELECTOR_FILTER_TAG,
                                                              *filters);
    filters->AddFilter(make_shared<RecoveryWifiFilter>());
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
    SetWifiFilter(make_shared<PoorPortalWifiFilter>());
    auto networkScorerComparator = make_shared<WifiScorerComparator>(m_networkSelectorName);
    networkScorerComparator->AddScorer(make_shared<LastHaveInternetTimeScorer>());
    networkScorerComparator->AddScorer(make_shared<SavedNetworkScorer>("portalNetworkScorer"));
    networkScorerComparator->AddScorer(make_shared<RssiScorer>());
    SetWifiComparator(networkScorerComparator);
}

PortalNetworkSelector::~PortalNetworkSelector()
{
    if (!filteredNetworkCandidates.empty()) {
        WIFI_LOGI("filteredNetworkCandidates in %{public}s: %{public}s",
                  m_networkSelectorName.c_str(),
                  NetworkSelectionUtils::GetNetworkCandidatesInfo(filteredNetworkCandidates).c_str());
    }
}

void PortalNetworkSelector::InitFilter()
{
    AddFilter(make_shared<PortalWifiFilter>());
    AddFilter(make_shared<MaybePortalWifiFilter>());
    ExternalWifiFilterBuildManager::GetInstance().BuildFilter(FilterTag::PORTAL_NETWORK_SELECTOR_FILTER_TAG, *this);
}

bool PortalNetworkSelector::Filter(NetworkCandidate &networkCandidate)
{
    if (OrWifiFilter::Filter(networkCandidate)) {
        TryNominate(networkCandidate);
        filteredNetworkCandidates.emplace_back(&networkCandidate);
        return false;
    }
    if (networkCandidates.empty()) {
        return true;
    }
    filteredNetworkCandidates.emplace_back(&networkCandidate);
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

NoInternetNetworkSelector::NoInternetNetworkSelector() : SimpleFilterNetworkSelector("noInternetNetworkSelector")
{
    SetWifiFilter(make_shared<NoInternetWifiFilter>());
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
