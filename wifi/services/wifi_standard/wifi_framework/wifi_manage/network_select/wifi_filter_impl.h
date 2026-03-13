/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_WIFI_FILTER_H
#define OHOS_WIFI_WIFI_FILTER_H
#include "network_selection.h"

namespace OHOS::Wifi::NetworkSelection {
constexpr int32_t DEFAULT_MIN_RSSI_INTERVAL = 8;

class HiddenWifiFilter final : public SimpleWifiFilter {
public:
    HiddenWifiFilter();
    ~HiddenWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class NotCurrentNetworkFilter final : public SimpleWifiFilter {
public:
    NotCurrentNetworkFilter();
    ~NotCurrentNetworkFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class SameBssidNetworkFilter final : public SimpleWifiFilter {
public:
    SameBssidNetworkFilter();
    ~SameBssidNetworkFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class ValidNetworkIdFilter final : public SimpleWifiFilter {
public:
    ValidNetworkIdFilter();
    ~ValidNetworkIdFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class SignalLevelFilter final : public SimpleWifiFilter {
public:
    SignalLevelFilter();
    ~SignalLevelFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};
 
class NotNetworkBlackListFilter final : public SimpleWifiFilter {
public:
    NotNetworkBlackListFilter();
    ~NotNetworkBlackListFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};
 
class NotP2pFreqAt5gFilter final : public SimpleWifiFilter {
public:
    NotP2pFreqAt5gFilter();
    ~NotP2pFreqAt5gFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};
 
class ValidConfigNetworkFilter final : public SimpleWifiFilter {
public:
    ValidConfigNetworkFilter();
    ~ValidConfigNetworkFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};
 
class WifiSwitchThresholdFilter final : public SimpleWifiFilter {
public:
    explicit WifiSwitchThresholdFilter(int32_t minRssiInterval = DEFAULT_MIN_RSSI_INTERVAL);
    ~WifiSwitchThresholdFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
private:
    int32_t minRssiInterval_;
};

class WifiSwitchThresholdQoeFilter final : public SimpleWifiFilter {
public:
    WifiSwitchThresholdQoeFilter();
    ~WifiSwitchThresholdQoeFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class WifiSwitch5GNot2GFilter final : public SimpleWifiFilter {
public:
    WifiSwitch5GNot2GFilter();
    ~WifiSwitch5GNot2GFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class SignalStrengthWifiFilter final : public SimpleWifiFilter {
public:
    SignalStrengthWifiFilter();
    ~SignalStrengthWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
class LongUnusedOpenWifiFilter final : public SimpleWifiFilter {
public:
    LongUnusedOpenWifiFilter();
    ~LongUnusedOpenWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};
#endif

class SavedWifiFilter final : public SimpleWifiFilter {
public:
    SavedWifiFilter();
    ~SavedWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};


class EphemeralWifiFilter final : public SimpleWifiFilter {
public:
    EphemeralWifiFilter();
    ~EphemeralWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class PassPointWifiFilter final : public SimpleWifiFilter {
public:
    PassPointWifiFilter();
    ~PassPointWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class DisableWifiFilter final : public SimpleWifiFilter {
public:
    DisableWifiFilter();
    ~DisableWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class MatchedUserSelectBssidWifiFilter final : public SimpleWifiFilter {
public:
    MatchedUserSelectBssidWifiFilter();
    ~MatchedUserSelectBssidWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class HasInternetWifiFilter final : public SimpleWifiFilter {
public:
    HasInternetWifiFilter();
    ~HasInternetWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class RecoveryWifiFilter final : public SimpleWifiFilter {
public:
    RecoveryWifiFilter();
    ~RecoveryWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class PoorPortalWifiFilter final : public SimpleWifiFilter {
public:
    PoorPortalWifiFilter();
    ~PoorPortalWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class PortalWifiFilter final : public SimpleWifiFilter {
public:
    PortalWifiFilter();
    ~PortalWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class MaybePortalWifiFilter final : public SimpleWifiFilter {
public:
    MaybePortalWifiFilter();
    ~MaybePortalWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class NoInternetWifiFilter final : public SimpleWifiFilter {
public:
    NoInternetWifiFilter();
    ~NoInternetWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};


class WeakAlgorithmWifiFilter final : public SimpleWifiFilter {
public:
    WeakAlgorithmWifiFilter();
    ~WeakAlgorithmWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class SuggestionNetworkWifiFilter final : public SimpleWifiFilter {
public:
    SuggestionNetworkWifiFilter();
    ~SuggestionNetworkWifiFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class SecureNetworkFilter final : public SimpleWifiFilter {
public:
    SecureNetworkFilter();
    ~SecureNetworkFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class HigherCategoryFilter final : public SimpleWifiFilter {
public:
    HigherCategoryFilter();
    ~HigherCategoryFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};

class Perf5gBlackListFilter final : public SimpleWifiFilter {
public:
    Perf5gBlackListFilter();
    ~Perf5gBlackListFilter() override;
protected:
    bool Filter(NetworkCandidate &networkCandidate) override;
};
}
#endif //OHOS_WIFI_WIFI_FILTER_H
