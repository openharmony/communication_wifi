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
#include "ap_connection_info.h"
#include "dual_band_utils.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("ApConnectionInfo");

constexpr int AP_RSSI_RANGE_LOW = -90;
constexpr int AP_RSSI_RANGE_HIGH = -45;
constexpr int RECORD_COUNT = AP_RSSI_RANGE_HIGH - AP_RSSI_RANGE_LOW + 1;
constexpr int AVG_RSSI_WINDOW_AROUND_RANGE = 4;
constexpr int WIFI_SIGNAL_LIST_SIZE = 5;

ApConnectionInfo::ApConnectionInfo(std::string &bssid)
    : bssid_(bssid), rttProducts_(RECORD_COUNT, 0), rttPacketVolumes_(RECORD_COUNT, 0), totalUseTime_(0L)
{}
ApConnectionInfo::ApConnectionInfo()
{}
ApConnectionInfo::~ApConnectionInfo()
{}
int ApConnectionInfo::GetRssiSatisfyRttThreshold(long rttThreshold, int defaultRssi)
{
    if (rttProducts_.empty() || rttPacketVolumes_.empty()) {
        WIFI_LOGI("%{public}s, rttProducts or rttPacketVolumes is empty, return default rssi threshold (%{public}d)",
            __FUNCTION__, defaultRssi);
        return defaultRssi;
    }
    int startRssi = -80;
    int startIndex = startRssi - AP_RSSI_RANGE_LOW;
    int rangeSize = 4;
    int endIndex = startIndex + rangeSize;
    long windowRttProductTotal = 0;
    long windowRttPacketVolumeTotal = 0;
    for (int i = startIndex; i <= endIndex; i++) {
        windowRttProductTotal += rttProducts_[i];
        windowRttPacketVolumeTotal += rttPacketVolumes_[i];
    }
    int rssiIndex = startIndex;
    if (IsSatisfyRttThreshold(windowRttProductTotal,
        windowRttPacketVolumeTotal, rttThreshold, rssiIndex)) {
        return AP_RSSI_RANGE_LOW + rssiIndex;
    }
    int windowSize = 9;
    for (endIndex += 1; endIndex < RECORD_COUNT; endIndex++) {
        windowRttProductTotal += rttProducts_[endIndex];
        windowRttPacketVolumeTotal += rttPacketVolumes_[endIndex];
        if (endIndex - startIndex + 1 > windowSize) {
            windowRttProductTotal -= rttProducts_[startIndex];
            windowRttPacketVolumeTotal -= rttPacketVolumes_[startIndex];
            startIndex++;
        }
        rssiIndex = endIndex - rangeSize;
        if (IsSatisfyRttThreshold(windowRttProductTotal,
            windowRttPacketVolumeTotal, rttThreshold, rssiIndex)) {
            return AP_RSSI_RANGE_LOW + rssiIndex;
        }
    }
    WIFI_LOGI("%{public}s, not fundo rssi in rtt window value, return default rssi threshold (%{public}d)",
        __FUNCTION__, defaultRssi);
    return defaultRssi;
}
long ApConnectionInfo::GetTotalUseTime()
{
    long totalUseTime = totalUseTime_;
    if (connectedTime_ != steady_clock::time_point::min()) {
        totalUseTime += duration_cast<seconds>(steady_clock::now() - connectedTime_).count();
    }
    return totalUseTime;
}
unsigned long ApConnectionInfo::GetAvgRttOnRssi(int rssi)
{
    if (rttProducts_.empty() || rttPacketVolumes_.empty()) {
        return 0;
    }
    int windowStartIndex = rssi - AP_RSSI_RANGE_LOW - AVG_RSSI_WINDOW_AROUND_RANGE;
    int windowEndIndex = rssi - AP_RSSI_RANGE_LOW + AVG_RSSI_WINDOW_AROUND_RANGE;
    if (windowStartIndex < 0) {
        windowStartIndex = 0;
        windowEndIndex = windowStartIndex + AVG_RSSI_WINDOW_AROUND_RANGE;
    } else if (windowEndIndex >= RECORD_COUNT) {
        windowEndIndex = RECORD_COUNT - 1;
        windowStartIndex = windowEndIndex - AVG_RSSI_WINDOW_AROUND_RANGE;
    }
    unsigned long windowRttProductTotal = 0;
    unsigned long windowRttPacketVolumeTotal = 0;
    for (int index = windowStartIndex; index <= windowEndIndex; index++) {
        windowRttProductTotal += rttProducts_[index];
        windowRttPacketVolumeTotal += rttPacketVolumes_[index];
    }
    if (windowRttProductTotal == 0 || windowRttPacketVolumeTotal == 0) {
        return 0;
    }
    return windowRttProductTotal / windowRttPacketVolumeTotal;
}
double ApConnectionInfo::GetLostRate()
{
    return 0.0;
}
int ApConnectionInfo::GetTotalUseHour()
{
    int secondToHourGap = 3600;
    return GetTotalUseTime() / secondToHourGap;
}
void ApConnectionInfo::AddUseTime(long useTime)
{
    totalUseTime_ += useTime;
}
std::string ApConnectionInfo::GetRttProductString()
{
    return DualBandUtils::LongArrToString(rttProducts_, DualBandUtils::comma);
}
std::string ApConnectionInfo::GetRttPacketVolumeString()
{
    return DualBandUtils::LongArrToString(rttPacketVolumes_, DualBandUtils::comma);
}
std::string ApConnectionInfo::GetOtaLostRatesString()
{
    return DualBandUtils::DoubleArrToString(otaLostRates_, DualBandUtils::comma);
}
std::string ApConnectionInfo::GetOtaPktVolumesString()
{
    return DualBandUtils::DoubleArrToString(otaPktVolumes_, DualBandUtils::comma);
}
std::string ApConnectionInfo::GetOtaBadPktProductsString()
{
    return DualBandUtils::DoubleArrToString(otaBadPktProducts_, DualBandUtils::comma);
}
void ApConnectionInfo::SetRttProducts(std::string rttProductsString)
{
    if (rttProductsString.empty()) {
        return;
    }
    rttProducts_.clear();
    DualBandUtils::StringToVectorLong(rttProductsString, DualBandUtils::comma, rttProducts_);
}
void ApConnectionInfo::SetRttPacketVolumes(std::string rttPacketVolumesString)
{
    if (rttPacketVolumesString.empty()) {
        return;
    }
    rttPacketVolumes_.clear();
    DualBandUtils::StringToVectorLong(rttPacketVolumesString, DualBandUtils::comma, rttPacketVolumes_);
}
void ApConnectionInfo::SetOtaLostRates(std::string otaLostRatesString)
{
    if (otaLostRatesString.empty()) {
        return;
    }
    otaLostRates_.clear();
    DualBandUtils::StringToVectorDouble(otaLostRatesString, DualBandUtils::comma, otaLostRates_);
}
void ApConnectionInfo::SetOtaPktVolumes(std::string otaPktVolumesString)
{
    if (otaPktVolumesString.empty()) {
        return;
    }
    otaPktVolumes_.clear();
    DualBandUtils::StringToVectorDouble(otaPktVolumesString, DualBandUtils::comma, otaPktVolumes_);
}
void ApConnectionInfo::SetOtaBadPktProducts(std::string otaBadPktProductsString)
{
    if (otaBadPktProductsString.empty()) {
        return;
    }
    otaBadPktProducts_.clear();
    DualBandUtils::StringToVectorDouble(otaBadPktProductsString, DualBandUtils::comma, otaBadPktProducts_);
}
void ApConnectionInfo::SetConnectedTime(steady_clock::time_point connectedTime)
{
    connectedTime_ = connectedTime;
}
void ApConnectionInfo::Disconnected()
{
    totalUseTime_ += duration_cast<seconds>(steady_clock::now() - connectedTime_).count();
    connectedTime_ = steady_clock::time_point::min();
}
void ApConnectionInfo::HandleLinkQuality(LinkQuality &linkQuality, bool is5gAfterPerf, bool is5gAp)
{
    if (!is5gAfterPerf && is5gAp) {
        return;
    }
    if (is5gAfterPerf && IsFullLinkQuality()) {
        return;
    }
    if (IsFullLinkQuality()) {
        linkQualitys_.pop_back();
    }
    linkQualitys_.push_back(linkQuality);
}
bool ApConnectionInfo::IsFullLinkQuality()
{
    return linkQualitys_.size() == WIFI_SIGNAL_LIST_SIZE;
}
std::list<LinkQuality>& ApConnectionInfo::GetLinkQualitys()
{
    return linkQualitys_;
}
void ApConnectionInfo::HandleRtt(int rssi, unsigned int rtt, unsigned int rttPkt)
{
    if (rttPkt <= 0) {
        WIFI_LOGI("%{public}s, rttPkt is invalid", __FUNCTION__);
        return;
    }
    int currentRssi = rssi;
    if (currentRssi > AP_RSSI_RANGE_HIGH) {
        currentRssi = AP_RSSI_RANGE_HIGH;
    } else if (currentRssi < AP_RSSI_RANGE_LOW) {
        currentRssi = AP_RSSI_RANGE_LOW;
    }
    int index = currentRssi - AP_RSSI_RANGE_LOW;
    unsigned long newRttProducts = rttProducts_[index] + rtt * rttPkt;
    unsigned long newRttPktVolumes = rttPacketVolumes_[index] + rttPkt;
    if (newRttProducts < rttProducts_[index] || newRttPktVolumes < rttPacketVolumes_[index]) {
        rttProducts_[index] = rtt * rttPkt;
        rttPacketVolumes_[index] = rttPkt;
        return;
    }
    rttProducts_[index] = newRttProducts;
    rttPacketVolumes_[index] = newRttPktVolumes;
}

bool ApConnectionInfo::IsSatisfyRttThreshold(long windowRttProductTotal,
    long windowRttPacketVolumeTotal, long rttThreshold, int rssiIndex)
{
    if (windowRttPacketVolumeTotal == 0) {
        return false;
    }
    long windowRttAvg = windowRttProductTotal / windowRttPacketVolumeTotal;
    if (windowRttAvg >= rttThreshold) {
        return false;
    }
    if (rttPacketVolumes_[rssiIndex] == 0) {
        return false;
    }
    long rssiRttAvg = rttProducts_[rssiIndex] / rttPacketVolumes_[rssiIndex];
    if (rssiRttAvg < rttThreshold) {
        return true;
    }
    return false;
}

}  // namespace Wifi
}  // namespace OHOS