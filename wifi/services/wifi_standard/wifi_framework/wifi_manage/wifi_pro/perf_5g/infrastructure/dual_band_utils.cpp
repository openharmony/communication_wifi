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

#include "dual_band_utils.h"
#include "wifi_common_util.h"
#include <cctype>
#include <cstddef>
#include <random>
#include <ctime>
#include <sstream>
#include <vector>

namespace OHOS {
namespace Wifi {
constexpr int MEAN_P_VERSION = 1;
constexpr double EPS = 1e-6;
constexpr int BSSID_COMMON_LENGTH = 17;
constexpr int BSSID_SPECIAL_LENGTH = 12;

std::string DualBandUtils::GetMeanPforLearnAlg()
{
    return "0.27,0.44,0.52,0.57,0.59,0.60,0.61,0.62,0.62,0.63,0.64,0.65,"
        "0.67,0.69,0.70,0.72,0.74,0.75,0.77,0.79,0.80,0.81,0.82,0.82,0.82,0.82,0.83,0.84,0.87,0.89,0.89";
}
int DualBandUtils::GetMeanPVersion()
{
    return MEAN_P_VERSION;
}

void DualBandUtils::StringToVectorLong(std::string &str, const char splitCh, std::vector<unsigned long> &vectorValue)
{
    if (str.empty()) {
        return;
    }
    std::istringstream strStream(str);
    std::string subString;
    while (std::getline(strStream, subString, splitCh)) {
        vectorValue.push_back(StringToUlong(subString));
    }
}
void DualBandUtils::StringToVectorDouble(std::string &str, const char splitCh, std::vector<double> &vectorValue)
{
    if (str.empty()) {
        return;
    }
    std::istringstream strStream(str);
    std::string subString;
    while (std::getline(strStream, subString, splitCh)) {
        vectorValue.push_back(StringToDouble(subString));
    }
}
std::string DualBandUtils::LongArrToString(std::vector<unsigned long> &arr, const char &splitCh)
{
    std::stringstream ss;
    for (size_t i = 0; i < arr.size(); i++) {
        ss << arr[i];
        if (i != arr.size() - 1) {
            ss << splitCh;
        }
    }
    return ss.str();
}
std::string DualBandUtils::IntArrToString(std::vector<int> &arr, const char &splitCh)
{
    std::stringstream sStream;
    for (size_t i = 0; i < arr.size(); i++) {
        sStream << arr[i];
        if (i != arr.size() - 1) {
            sStream << splitCh;
        }
    }
    return sStream.str();
}
std::string DualBandUtils::DoubleArrToString(std::vector<double> &arr, const char &splitCh)
{
    std::stringstream stream;
    for (size_t i = 0; i < arr.size(); i++) {
        stream << arr[i];
        if (i != arr.size() - 1) {
            stream << splitCh;
        }
    }
    return stream.str();
}
int DualBandUtils::Compare(double value1, double value2)
{
    if (std::fabs(value1 - value2) < EPS) {
        return 0;
    }
    if (value1 > value2 + EPS) {
        return 1;
    }
    return -1;
}
bool DualBandUtils::EqualZero(double value)
{
    return Compare(value, 0.0) == 0;
}
double DualBandUtils::Random()
{
    std::uniform_real_distribution<double> randomDouble(0, 1);
    unsigned int seed = static_cast<unsigned int>(time(nullptr));
    if (seed == 0) {
        seed = 1;
    }
    std::default_random_engine randomEngine(seed);
    return randomDouble(randomEngine);
}
bool DualBandUtils::IsEnterprise(const WifiDeviceConfig &wifiDeviceConfig)
{
    auto &keyMgmt = wifiDeviceConfig.keyMgmt;
    bool isEnterpriseSecurityType = (keyMgmt == KEY_MGMT_EAP) || (keyMgmt == KEY_MGMT_SUITE_B_192) ||
        (keyMgmt == KEY_MGMT_WAPI_CERT);
    auto &eap = wifiDeviceConfig.wifiEapConfig.eap;
    return isEnterpriseSecurityType && (eap != EAP_METHOD_NONE);
}
bool DualBandUtils::IsSameRouterAp(std::string &apBssid, std::string &anotherApBssid)
{
    if (apBssid.empty() || anotherApBssid.empty()) {
        return false;
    }
    if (apBssid.length() == BSSID_SPECIAL_LENGTH) {
        SpecialBssidToCommonBssid(apBssid);
    }
    if (anotherApBssid.length() == BSSID_SPECIAL_LENGTH) {
        SpecialBssidToCommonBssid(anotherApBssid);
    }
    if (apBssid.length() != BSSID_COMMON_LENGTH || anotherApBssid.length() != BSSID_COMMON_LENGTH) {
        return false;
    }
    int deffrentSize = 3;
    std::string apBssidCompareString = apBssid.substr(0, apBssid.length() - deffrentSize);
    std::string anotherApBssidCompareString = anotherApBssid.substr(0, anotherApBssid.length() - deffrentSize);
    bool isSameRouter = !strcasecmp(apBssidCompareString.data(), anotherApBssidCompareString.data());
    if (!isSameRouter) {
        apBssidCompareString = apBssid.substr(deffrentSize, apBssid.length());
        anotherApBssidCompareString = anotherApBssid.substr(deffrentSize, anotherApBssid.length());
        isSameRouter = !strcasecmp(apBssidCompareString.data(), anotherApBssidCompareString.data());
    }
    return isSameRouter;
}
void DualBandUtils::SpecialBssidToCommonBssid(std::string &specialBssid)
{
    int startInertIndex = 3;
    int insertStep = 3;
    int insertTotalNum = 5;
    for (int insertNum = 0; insertNum < insertTotalNum; insertNum++) {
        specialBssid.insert(startInertIndex, ":");
        startInertIndex += insertStep;
    }
}
bool DualBandUtils::IsSameSsidAp(ApInfo &apInfo, std::string &ssid, std::string &bssid, std::string &keyMgmt)
{
    return apInfo.bssid != bssid && apInfo.ssid == ssid && apInfo.keyMgmt == keyMgmt;
}

}  // namespace Wifi
}  // namespace OHOS