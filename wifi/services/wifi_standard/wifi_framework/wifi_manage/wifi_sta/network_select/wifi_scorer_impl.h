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

#ifndef OHOS_WIFI_WIFI_SCORER_IMPL_H_
#define OHOS_WIFI_WIFI_SCORER_IMPL_H_

#include <memory>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include "network_selection.h"


namespace OHOS::Wifi::NetworkSelection {

class RssiScorer : public SimpleWifiScorer {
public:
    RssiScorer();
    double Score(NetworkCandidate &networkCandidate) override;
};

class LastHaveInternetTimeScorer : public SimpleWifiScorer {
public:
    LastHaveInternetTimeScorer();
    double Score(NetworkCandidate &networkCandidate) override;
};

class NetworkStatusHistoryScorer : public SimpleWifiScorer {
public:
    NetworkStatusHistoryScorer();
    double Score(NetworkCandidate &networkCandidate) override;
};

class ThroughputScorer : public IWifiScorer {
public:
    void DoScore(NetworkCandidate &networkCandidate, ScoreResult &scoreResult) override;

private:
    static double GetRssiBaseScore(NetworkCandidate &networkCandidate);

    static double GetSavedNetworkAward(NetworkCandidate &networkCandidate);

    bool IsRecentUserSelected(NetworkCandidate &networkCandidate) const;

    bool IsSecurityNetwork(NetworkCandidate &networkCandidate) const;
    static constexpr int SECURITY_AWARD_SCORE = 40;
    static constexpr int SAVED_NETWORK_AWARD_SCORE = 40;
};

class SecurityBonusScorer : public SimpleWifiScorer {
public:
    SecurityBonusScorer();
    double Score(NetworkCandidate &networkCandidate) override;
private:
    /**
     *  Function to determine whether the security type of the scanInfo is more secure.
     *
     * @param interScanInfo scanInfo
     * @return true if the security of the scanInfo is more secure.
     */
    bool IsHigherSecurityTypeFromScanResult(const InterScanInfo &interScanInfo);

    /**
     * Function to determine whether the security type of the scanInfo is Sae.
     *
     * @param interScanInfo scanInfo
     * @return true if the security of the scanInfo is Sae.
     */
    bool IsEncryptionSae(const InterScanInfo &interScanInfo);

    /**
     * Function to determine whether the security type of the scanInfo is PskSae.
     *
     * @param interScanInfo scanInfo
     * @return true if the security of the scanInfo is PskSae.
     */
    bool IsEncryptionPskSaeTransition(const InterScanInfo &interScanInfo);

    /**
     * Function to determine whether the security type of the scanInfo is Owe.
     *
     * @param interScanInfo scanInfo
     * @return true if the security of the scanInfo is Owe.
     */
    bool IsEncryptionOwe(const InterScanInfo &interScanInfo);

    /**
     * Function to determine whether the security type of the scanInfo is OweTransition.
     *
     * @param interScanInfo scanInfo
     * @return true if the security of the scanInfo is OweTransition.
     */
    bool IsEncryptionOweTransition(const InterScanInfo &interScanInfo);

    /**
     * Function to determine whether the security type of the scanInfo is Wpa3EnterpriseOnly.
     *
     * @param interScanInfo scanInfo
     * @return true if the security of the scanInfo is Wpa3EnterpriseOnly.
     */
    bool IsWpa3EnterpriseOnlyNetwork(const InterScanInfo &interScanInfo);

    /**
     * Function to determine whether the security type of the scanInfo is Wpa3EnterpriseTransition.
     *
     * @param interScanInfo scanInfo
     * @return true if the security of the scanInfo is Wpa3EnterpriseTransition.
     */
    bool IsWpa3EnterpriseTransitionNetwork(const InterScanInfo &interScanInfo);

    /**
     * Function to determine whether the security type is existed in the scanInfo.
     *
     * @param interScanInfo scanInfo
     * @param securityType target security type
     * @return true if the security type existed
     */
    bool ExistSecurityType(const InterScanInfo &interScanInfo, const std::string &securityType);
};

class RssiLevelBonusScorer : public SimpleWifiScorer {
public:
    RssiLevelBonusScorer();
    double Score(NetworkCandidate &networkCandidate) override;
};

class Network5gBonusScorer : public SimpleWifiScorer {
public:
    Network5gBonusScorer();
    double Score(NetworkCandidate &networkCandidate) override;
};

class SavedNetworkScorer : public CompositeWifiScorer {
public:
    explicit SavedNetworkScorer(const std::string &scorerName);
};
}

#endif
