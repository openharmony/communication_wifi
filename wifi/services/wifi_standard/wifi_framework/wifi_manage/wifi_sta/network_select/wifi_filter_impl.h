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
class HiddenWifiFilter final : public SimpleWifiFilter {
public:
    HiddenWifiFilter();
    ~HiddenWifiFilter() override;
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
}
#endif //OHOS_WIFI_WIFI_FILTER_H
