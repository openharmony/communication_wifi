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
#ifndef OHOS_WIFI_PRO_PERF_5G_DUAL_BAND_LEARNING_ALG_SERVICE_H
#define OHOS_WIFI_PRO_PERF_5G_DUAL_BAND_LEARNING_ALG_SERVICE_H
#include <string>
#include <list>
#include "wifi_pro_common.h"
namespace OHOS {
namespace Wifi {

class DualBandLearningAlgService {
public:
    DualBandLearningAlgService();
    ~DualBandLearningAlgService();
    static bool Selected(std::string meanPstring, int rssi);
    static void UpdateMeanPValue(std::list<LinkQuality> &rate2gList,
        std::list<LinkQuality> &rate5gList, int rssi5g, std::string &meanPString);
private:
    static double Random(double aValue, double bValue);
    static double Gamma(double shape, double scale);
    static double UseJohnkGenerator(double shape, double scale);
    static double UseBestGenerator(double shape, double scale);
    static double StandardNormal();
    static long Get2gAverageRate(std::list<LinkQuality> &rate2gList);
    static long Get5gAverageRate(std::list<LinkQuality> &rate5gList);
    static long GetDetailStep(long flowRate);
    static long GetFlowRate(std::list<LinkQuality> &rateList);
    static bool IsMoveRight(long averageRate24g, long averageRate5g);
    static bool IsValidRssi(int rssi);
    static bool IsReachTrafficThreshold(std::list<LinkQuality> &rateList);
    static void MoveMeanPs(std::vector<double> &meanPVs, int detailStep, int rssi5g, bool moveToRight);
    static double GetNewMeanP(double meanPvalue);
};

}  // namespace Wifi
}  // namespace OHOS
#endif