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
#ifndef OHOS_WIFI_PRO_PERF_5G_AP_CONNECTION_INFO_H
#define OHOS_WIFI_PRO_PERF_5G_AP_CONNECTION_INFO_H
#include <string>
#include <vector>
#include <chrono>
#include <list>
#include "wifi_msg.h"
#include "wifi_pro_common.h"

namespace OHOS {
namespace Wifi {
using namespace std::chrono;

class ApConnectionInfo {
public:
    explicit ApConnectionInfo(std::string &bssid);
    ApConnectionInfo();
    ~ApConnectionInfo();
    int GetRssiSatisfyRttThreshold(long rttThreshold, int defaultRssi);
    long GetTotalUseTime();
    unsigned long GetAvgRttOnRssi(int rssi);
    double GetLostRate();
    int GetTotalUseHour();
    void AddUseTime(long useTime);
    std::string GetRttProductString();
    std::string GetRttPacketVolumeString();
    std::string GetOtaLostRatesString();
    std::string GetOtaPktVolumesString();
    std::string GetOtaBadPktProductsString();
    void SetRttProducts(std::string rttProductsString);
    void SetRttPacketVolumes(std::string rttPacketVolumesString);
    void SetOtaLostRates(std::string otaLostRatesString);
    void SetOtaPktVolumes(std::string otaPktVolumesString);
    void SetOtaBadPktProducts(std::string otaBadPktProductsString);
    void SetConnectedTime(steady_clock::time_point connectedTime);
    void Disconnected();
    void HandleLinkQuality(LinkQuality &linkQuality, bool is5gAfterPerf, bool is5gAp);
    bool IsFullLinkQuality();
    std::list<LinkQuality>& GetLinkQualitys();
    void HandleRtt(int rssi, unsigned int rtt, unsigned int rttPkt);

private:
    std::string bssid_;
    std::vector<unsigned long> rttProducts_;
    std::vector<unsigned long> rttPacketVolumes_;
    std::vector<double> otaLostRates_;
    std::vector<double> otaPktVolumes_;
    std::vector<double> otaBadPktProducts_;
    std::list<LinkQuality> linkQualitys_;
    steady_clock::time_point connectedTime_ = steady_clock::time_point::min();
    long totalUseTime_ = 0L;

    bool IsSatisfyRttThreshold(long windowRttProductTotal,
        long windowRttPacketVolumeTotal, long rttThreshold, int rssiIndex);
};
}  // namespace Wifi
}  // namespace OHOS
#endif