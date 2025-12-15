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
 
#ifndef OHOS_SELF_CURE_UTILS_H
#define OHOS_SELF_CURE_UTILS_H

#include "singleton.h"
#include "netsys_dns_report_callback.h"
#include "self_cure_state_machine.h"

namespace OHOS {
namespace Wifi {
constexpr int VEC_POS_3 = 3;
constexpr int GET_NEXT_IP_MAC_CNT = 10;
constexpr int64_t IPV6_CHR_EVENT_MIN_INTERVAL = 30 * 60 * 1000 * 1000; // 30 minutes
inline constexpr const char* CONST_WIFI_DNSCURE_IPCFG = "const.wifi.dnscure_ipcfg";
class SelfCureUtils {
public:
    SelfCureUtils();
    ~SelfCureUtils();
    static SelfCureUtils& GetInstance();
    void RegisterDnsResultCallback();
    void UnRegisterDnsResultCallback();
    int32_t GetCurrentDnsFailedCounter();
    void ClearDnsFailedCounter();
    int32_t GetSelfCureType(int32_t currentCureLevel);

    std::string GetNextIpAddr(const std::string& gateway, const std::string& currentAddr,
                              const std::vector<std::string>& testedAddr);
    static void UpdateSelfCureHistoryInfo(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel, bool success);
    static void UpdateSelfCureConnectHistoryInfo(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel,
                                                 bool success);
    bool AllowSelfCure(const WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel);
    bool SelfCureAcceptable(WifiSelfCureHistoryInfo &historyInfo, int requestCureLevel);
    std::vector<std::string> TransStrToVec(std::string str, char c);
    std::string TransVecToIpAddress(const std::vector<uint32_t>& vec);
    std::vector<uint32_t> TransIpAddressToVec(std::string addr);
    int String2InternetSelfCureHistoryInfo(const std::string selfCureHistory, WifiSelfCureHistoryInfo &info);
    int SetSelfCureFailInfo(OHOS::Wifi::WifiSelfCureHistoryInfo &info, std::vector<std::string>& histories, int cnt);
    int SetSelfCureConnectFailInfo(WifiSelfCureHistoryInfo &info, std::vector<std::string>& histories, int cnt);
    bool IsIpConflictDetect();
    std::string GetSelfCureHistory();
    void ReportNoInternetChrEvent();
    bool IsIpv6SelfCureSupported() const;
    bool DisableIpv6(int instId = 0);
    bool HasIpv6Disabled(int instId = 0) const;
    void SetIpv6Disabled(bool disabled, int instId = 0);
    void ReportIpv6ChrEvent();
private:
    class SelfCureDnsResultCallback : public NetManagerStandard::NetsysDnsReportCallback {
    public:
        SelfCureDnsResultCallback() {};
        ~SelfCureDnsResultCallback() {};
        int32_t OnDnsResultReport(uint32_t size, const std::list<NetsysNative::NetDnsResultReport> reports);
    private:
        int32_t GetWifiNetId();
        int32_t GetDefaultNetId();
    public:
        int32_t dnsFailedCounter_ = 0;
    };

private:
    std::atomic<int64_t> lastReportIpv6Time_ = 0;
    std::atomic<bool> ipv6Disabled_[2] = {false, false};
    sptr<SelfCureDnsResultCallback> dnsResultCallback_{nullptr};
};
} // namespace Wifi
} // namespace OHOS
#endif // OHOS_SELF_CURE_UTILS_H