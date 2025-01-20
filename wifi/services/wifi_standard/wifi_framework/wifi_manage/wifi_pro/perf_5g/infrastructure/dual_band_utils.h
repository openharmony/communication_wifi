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

#ifndef OHOS_WIFI_PRO_PERF_5G_DUAL_BAND_UTILS_H
#define OHOS_WIFI_PRO_PERF_5G_DUAL_BAND_UTILS_H
#include <string>
#include "wifi_msg.h"
#include <vector>
#include "connected_ap.h"

namespace OHOS {
namespace Wifi {

class DualBandUtils {
public:
    static constexpr char comma = ',';
    static std::string GetMeanPforLearnAlg();
    static int GetMeanPVersion();
    static void StringToVectorLong(std::string &str, const char splitCh, std::vector<unsigned long> &vectorValue);
    static void StringToVectorDouble(std::string &str, const char splitCh, std::vector<double> &vectorValue);
    static std::string LongArrToString(std::vector<unsigned long> &arr, const char &splitCh);
    static std::string IntArrToString(std::vector<int> &arr, const char &splitCh);
    static std::string DoubleArrToString(std::vector<double> &arr, const char &splitCh);
    static int Compare(double value1, double value2);
    static bool EqualZero(double value);
    static double Random();
    static bool IsEnterprise(const WifiDeviceConfig &wifiDeviceConfig);
    static bool IsSameRouterAp(std::string &apBssid, std::string &anotherApBssid);
    static void SpecialBssidToCommonBssid(std::string &specialBssid);
    static bool IsSameSsidAp(ApInfo &apInfo, std::string &ssid, std::string &bssid, std::string &keyMgmt);
};

}  // namespace Wifi
}  // namespace OHOS
#endif