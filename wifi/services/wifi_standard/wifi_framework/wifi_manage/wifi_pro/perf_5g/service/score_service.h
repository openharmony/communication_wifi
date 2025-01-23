/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_PRO_PERF_5G_SCORE_SERVICE_H
#define OHOS_WIFI_PRO_PERF_5G_SCORE_SERVICE_H
#include <vector>
#include "connected_ap.h"
#include "candidate_relation_ap_info.h"
namespace OHOS {
namespace Wifi {

class IScoreCalculator {
public:
    virtual ~IScoreCalculator() = default;
    virtual bool IsSatisfied(ApInfo &apInfo) = 0;
    virtual void Calculate(ApInfo &apInfo, ScoreResult &scoreResult) = 0;
};
class ScoreService {
public:
    explicit ScoreService(std::vector<IScoreCalculator *> scoreCalculators);
    ~ScoreService();
    void CalculateScore(ApInfo &apInfo, ScoreResult &scoreResult);
private:
    std::vector<IScoreCalculator *> scoreCalculators_;
};

class RssiScoreCalculator : public IScoreCalculator {
public:
    RssiScoreCalculator();
    ~RssiScoreCalculator() override;
    bool IsSatisfied(ApInfo &apInfo) override;
    void Calculate(ApInfo &apInfo, ScoreResult &scoreResult) override;
private:
    std::vector<int> rssi_;
    std::vector<int> score_;
};

class ConnectTimeScoreCalculator : public IScoreCalculator {
public:
    ConnectTimeScoreCalculator();
    ~ConnectTimeScoreCalculator() override;
    bool IsSatisfied(ApInfo &apInfo) override;
    void Calculate(ApInfo &apInfo, ScoreResult &scoreResult) override;
private:
    std::vector<int> connectHourTime_;
    std::vector<int> score_;
};

class AvgRttScoreCalculator : public IScoreCalculator {
public:
    AvgRttScoreCalculator();
    ~AvgRttScoreCalculator() override;
    bool IsSatisfied(ApInfo &apInfo) override;
    void Calculate(ApInfo &apInfo, ScoreResult &scoreResult) override;
private:
    std::vector<int> avgRtt_;
    std::vector<int> score_;
};

class PacketLostScoreCalculator : public IScoreCalculator {
public:
    PacketLostScoreCalculator();
    ~PacketLostScoreCalculator() override;
    bool IsSatisfied(ApInfo &apInfo) override;
    void Calculate(ApInfo &apInfo, ScoreResult &scoreResult) override;
private:
    std::vector<double> packetLossRate_;
    std::vector<int> score_;
};

class Ap5gScoreCalculator : public IScoreCalculator {
public:
    explicit Ap5gScoreCalculator(std::string connectedApBssid);
    ~Ap5gScoreCalculator() override;
    bool IsSatisfied(ApInfo &apInfo) override;
    void Calculate(ApInfo &apInfo, ScoreResult &scoreResult) override;
private:
    bool IsBtConnected();
    std::string connectedApBssid_;
};
class WifiCategoryScoreCalculator : public IScoreCalculator {
public:
    WifiCategoryScoreCalculator();
    ~WifiCategoryScoreCalculator() override;
    bool IsSatisfied(ApInfo &apInfo) override;
    void Calculate(ApInfo &apInfo, ScoreResult &scoreResult) override;
};
}  // namespace Wifi
}  // namespace OHOS
#endif