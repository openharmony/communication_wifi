/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"){}
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

#include "dual_band_learning_alg_service.h"
#include "dual_band_utils.h"
#include <cmath>
#include <algorithm>
#include <vector>
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("DualBandLearningAlgService");
constexpr int MEAN_P_MIN_RSSI = -72;
constexpr int MEAN_P_MAX_RSSI = -42;
const int DETAIL_STEPS[] = {0, 1, 3, 5};
const unsigned int FLOW_THRESHOLDS[] = {0, 20, 100, 500};
constexpr unsigned int FLOW_RATE_TIME_RANGE_SECOND = 15;
constexpr double MEAN_P_MIN = 0.05;
constexpr double MEAN_P_MAX = 0.95;
constexpr int LOOP_MAX = 20;
constexpr double BASE_VALUE = 500.0;
constexpr double VALID_SIZE_RATE_LIST = 5;
const double PI = acos(-1.0);
const double E = exp(1);
constexpr uint32_t  USE_1000 = 1000;

DualBandLearningAlgService::DualBandLearningAlgService()
{}
DualBandLearningAlgService::~DualBandLearningAlgService()
{}
bool DualBandLearningAlgService::Selected(std::string meanPstring, int rssi)
{
    if (meanPstring.empty()) {
        WIFI_LOGW("%{public}s, meanPstring is empty, selection fialed", __FUNCTION__);
        return false;
    }
    if (!IsValidRssi(rssi)) {
        WIFI_LOGW("%{public}s, rssi is invaild, selection fialed", __FUNCTION__);
        return false;
    }
    std::vector<double> meanPvalues;
    DualBandUtils::StringToVectorDouble(meanPstring, DualBandUtils::comma, meanPvalues);
    int meanPIndex = rssi - MEAN_P_MIN_RSSI;
    if (meanPIndex >= static_cast<int>(meanPvalues.size()) || meanPIndex < 0) {
        WIFI_LOGW("%{public}s, meanPIndex by rssi is invaild, selection fialed", __FUNCTION__);
        return false;
    }
    double aValue = meanPvalues[meanPIndex] * BASE_VALUE;
    double bValue = (1.0 - meanPvalues[meanPIndex]) * BASE_VALUE;
    double pValue = Random(aValue, bValue);
    double selectedThreshold = 0.5;
    return DualBandUtils::Compare(pValue, selectedThreshold) >= 0;
}
void DualBandLearningAlgService::UpdateMeanPValue(std::list<LinkQuality> &rate2gList,
    std::list<LinkQuality> &rate5gList, int rssi5g, std::string &meanPString)
{
    if (meanPString.empty()) {
        WIFI_LOGW("%{public}s, meanPString is invalid", __FUNCTION__);
        return;
    }
    if (rate2gList.empty() || rate2gList.size() != VALID_SIZE_RATE_LIST) {
        WIFI_LOGW("%{public}s, 2g ap rate list is invalid", __FUNCTION__);
        return;
    }
    if (rate5gList.empty() || rate5gList.size() != VALID_SIZE_RATE_LIST) {
        WIFI_LOGW("%{public}s, 5g ap rate list is invalid", __FUNCTION__);
        return;
    }
    if (!IsValidRssi(rssi5g)) {
        WIFI_LOGW("%{public}s, 5g rssi(%{public}d) is over range(%{public}d-%{public}d)",
            __FUNCTION__, rssi5g, MEAN_P_MIN_RSSI, MEAN_P_MAX_RSSI);
        return;
    }
    if (!IsReachTrafficThreshold(rate2gList)) {
        WIFI_LOGW("%{public}s, flow rate of 2g ap less than 20, ignore", __FUNCTION__);
        return;
    }
    if (!IsReachTrafficThreshold(rate5gList)) {
        WIFI_LOGW("%{public}s, flow rate of 5g ap less than 20, ignore", __FUNCTION__);
        return;
    }
    std::vector<double> meanPvalues;
    DualBandUtils::StringToVectorDouble(meanPString, DualBandUtils::comma, meanPvalues);
    if (meanPvalues.empty()) {
        WIFI_LOGW("%{public}s, meanP double vector is empty, ignore", __FUNCTION__);
        return;
    }
    long averageRate24g = Get2gAverageRate(rate2gList);
    long averageRate5g = Get5gAverageRate(rate5gList);
    bool isMoveToRight = IsMoveRight(averageRate24g, averageRate5g);
    unsigned long flowRate5g = GetFlowRate(rate5gList);
    long detailStep = GetDetailStep(flowRate5g);
    MoveMeanPs(meanPvalues, detailStep, rssi5g, isMoveToRight);
    meanPString = DualBandUtils::DoubleArrToString(meanPvalues, DualBandUtils::comma);
}
double DualBandLearningAlgService::Random(double aValue, double bValue)
{
    double xValue = Gamma(aValue, 1.0);
    double yValue = Gamma(bValue, 1.0);
    double sum = xValue + yValue;
    if (DualBandUtils::EqualZero(sum)) {
        return 0.0;
    }
    return xValue / sum;
}
double DualBandLearningAlgService::Gamma(double shape, double scale)
{
    if (DualBandUtils::Compare(shape, 0.0) <= 0 || DualBandUtils::Compare(scale, 0.0) <= 0) {
        return 0.0;
    }
    if (DualBandUtils::Compare(shape, 1.0) < 0) {
        return UseJohnkGenerator(shape, scale);
    } else {
        return UseBestGenerator(shape, scale);
    }
}
double DualBandLearningAlgService::UseJohnkGenerator(double shape, double scale)
{
    int loopCount = 0;
    while (loopCount++ < LOOP_MAX) {
        double uValue = DualBandUtils::Random();
        double bValue = (E + shape) / E;
        double pValue = bValue * uValue;
        if (DualBandUtils::Compare(pValue, 1.0) <= 0) {
            if (shape == 0.0) {
                return 0.0;
            }
            double xValue = pow(pValue, 1.0 / shape);
            if (DualBandUtils::Compare(uValue, exp(-xValue)) <= 0) {
                return scale * xValue;
            }
        } else {
            if (shape == 0.0) {
                return 0.0;
            }
            double xValue = -log((bValue - pValue) / shape);
            if (uValue <= pow(xValue, shape - 1.0)) {
                return scale * xValue;
            }
        }
    }
    return 0.0;
}
double DualBandLearningAlgService::UseBestGenerator(double shape, double scale)
{
    double bValue = shape - 1.0 / 3.0;
    if (DualBandUtils::EqualZero(bValue)) {
        return 0.0;
    }
    double cValue = 1.0 / std::sqrt(9.0 * bValue);
    double vValue;
    int loopCount = 0;
    while (loopCount++ < LOOP_MAX) {
        double xValue;
        int doLoopCount = 0;
        do {
            xValue = StandardNormal();
            vValue = 1.0 + cValue * xValue;
        } while (vValue <= 0.0 && ++doLoopCount < LOOP_MAX);
        if (doLoopCount >= LOOP_MAX) {
            return 0.0;
        }
        vValue = vValue * vValue * vValue;
        double uValue = DualBandUtils::Random();
        double xSquared = xValue * xValue;
        bool isSatisfied = uValue < 1.0 - 0.0331 * xSquared * xSquared ||
            log(uValue) < 0.5 * xSquared + bValue * (1.0 - vValue + log(vValue));
        if (isSatisfied) {
            return scale * bValue * vValue;
        }
    }
    return 0.0;
}
double DualBandLearningAlgService::StandardNormal()
{
    double u1 = DualBandUtils::Random();
    double u2 = DualBandUtils::Random();
    double rValue = sqrt(-2.0 * log(u1));
    double theta = 2.0 * PI * u2;
    return rValue * cos(theta);
}
long DualBandLearningAlgService::Get2gAverageRate(std::list<LinkQuality> &rate2gList)
{
    long rateSum = 0L;
    long rateNum = 3;
    for (auto it = std::next(rate2gList.end(), -(rateNum)); it != rate2gList.end(); it++) {
        rateSum += std::max(it->txrate, it->rxrate);
    }
    return rateSum / rateNum;
}
long DualBandLearningAlgService::Get5gAverageRate(std::list<LinkQuality> &rate5gList)
{
    long rateSum = 0L;
    long rateNum = 3;
    std::list<LinkQuality>::iterator end = std::next(rate5gList.begin(), rateNum);
    for (auto it = std::next(rate5gList.begin()); it != end; it++) {
        rateSum += std::max(it->txrate, it->rxrate);
    }
    return rateSum / rateNum;
}
long DualBandLearningAlgService::GetDetailStep(unsigned long flowRate)
{
    int detailStepIndex = 0;
    int flowThresholdSize = std::size(FLOW_THRESHOLDS);
    for (int index = 1; index < flowThresholdSize; index++) {
        if (flowRate > FLOW_THRESHOLDS[index]) {
            detailStepIndex = index;
        } else {
            break;
        }
    }
    return DETAIL_STEPS[detailStepIndex];
}
unsigned long DualBandLearningAlgService::GetFlowRate(std::list<LinkQuality> &rateList)
{
    if (rateList.empty()) {
        return 0;
    }
    uint32_t flowTx = (rateList.back().txBytes - rateList.front().txBytes) / USE_1000 / FLOW_RATE_TIME_RANGE_SECOND;
    uint32_t flowRx = (rateList.back().txBytes - rateList.front().txBytes) / USE_1000 / FLOW_RATE_TIME_RANGE_SECOND;
    // avoid add flow
    if ((flowTx > 0) && (flowRx > (UINT32_MAX - flowTx))) {
        WIFI_LOGW("%{public}s, add overflow", __FUNCTION__);
        flowTx = UINT32_MAX;
    } else {
        flowTx += flowRx;
    }
    return static_cast<unsigned long>(flowTx);
}
bool DualBandLearningAlgService::IsMoveRight(long averageRate24g, long averageRate5g)
{
    long half = 2;
    return averageRate5g > (averageRate24g / half);
}
bool DualBandLearningAlgService::IsValidRssi(int rssi)
{
    return rssi >= MEAN_P_MIN_RSSI && rssi <= MEAN_P_MAX_RSSI;
}
bool DualBandLearningAlgService::IsReachTrafficThreshold(std::list<LinkQuality> &rateList)
{
    unsigned long flowRate = GetFlowRate(rateList);
    return GetDetailStep(flowRate) != 0;
}
void DualBandLearningAlgService::MoveMeanPs(std::vector<double> &meanPVs, int detailStep,
    int rssi5g, bool moveToRight)
{
    int rssiMeanPIndex = rssi5g - MEAN_P_MIN_RSSI;
    std::vector<double>::iterator start;
    std::vector<double>::iterator end;
    if (moveToRight) {
        start = std::next(meanPVs.begin(), rssiMeanPIndex);
        end = meanPVs.end();
    } else {
        start = meanPVs.begin();
        end = std::next(meanPVs.begin(), rssiMeanPIndex + 1);
    }
    while (start != end) {
        double meanPvalue = *start;
        if (moveToRight) {
            double aValue = meanPvalue * BASE_VALUE + static_cast<double>(detailStep);
            *start = GetNewMeanP(aValue / BASE_VALUE);
        } else {
            double bValue = (1.0 - meanPvalue) * BASE_VALUE + static_cast<double>(detailStep);
            *start = GetNewMeanP(bValue / BASE_VALUE - 1.0);
        }
        start++;
    }
}
double DualBandLearningAlgService::GetNewMeanP(double meanPvalue)
{
    if (meanPvalue < MEAN_P_MIN) {
        return MEAN_P_MIN;
    }
    return std::min(meanPvalue, MEAN_P_MAX);
}

}  // namespace Wifi
}  // namespace OHOS