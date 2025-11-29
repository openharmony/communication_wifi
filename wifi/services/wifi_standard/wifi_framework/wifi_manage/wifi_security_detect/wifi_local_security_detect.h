/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_WIFI_LOCAL_SECURITY_DETECT_H
#define OHOS_WIFI_WIFI_LOCAL_SECURITY_DETECT_H

#include "define.h"
#include "wifi_log.h"
#include "wifi_errcode.h"
#include "wifi_internal_msg.h"
#include <ctime>
#include "wifi_msg.h"
#include "sta_service_callback.h"
#include "netsys_dns_report_callback.h"
#include "netsys_net_dns_result_data.h"
#include <list>
#include <deque>
#include <unordered_map>
#include <arpa/inet.h>
#include <netinet/in.h>

#define DOMAIN_STORE_CD 15
#define MAX_DNS_DOMAIN_RECORD_NUM 50
namespace OHOS {
namespace Wifi {
using namespace NetsysNative;

enum class IpType {
    PUBLIC = 0,   // 公网
    PRIVATE       // 内网
};

struct DomainRecord {
    std::string domain;
    IpType ipType;
};
using RecordDeque = std::deque<DomainRecord>;

class WifiLocalSecurityDetect {
public:
    WifiLocalSecurityDetect();
    ~WifiLocalSecurityDetect();
    void RegisterDnsResultCallback();
    void UnRegisterDnsResultCallback();
    static WifiLocalSecurityDetect &GetInstance();

    /**
     * @Description Get register sta callback
     * @return StaServiceCallback - sta callback
     */
    StaServiceCallback GetStaCallback() const;

    /**
     * @Description handle sta connection state change
     * @param state - OperateResState
     * @param linkedInfo - const WifiLinkedInfo
     */
    void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &linkedInfo, int instId);

private:
    class LocalSecurityDetectDnsResultCallback : public NetManagerStandard::NetsysDnsReportCallback {
    public:
        LocalSecurityDetectDnsResultCallback() {};
        ~LocalSecurityDetectDnsResultCallback() {};
        int32_t OnDnsResultReport(uint32_t size, const std::list<NetDnsResultReport> reports);
    };

private:
    std::mutex localDetectMutex_;
    StaServiceCallback staCallback_;
    int32_t currentUseNetworkId_ = -1;
    bool canAccessInternetThroughWifi_ = false;
    sptr<LocalSecurityDetectDnsResultCallback> dnsResultCallback_{nullptr};
    time_t lastAddRecordTime_ = -1;
    RecordDeque domainHistoryCache_;
    void HandleWifiConnected(const WifiLinkedInfo &linkedInfo);
    void HandleWifiDisconnected(const WifiLinkedInfo &linkedInfo);
    void HandleDnsResultReport(const std::list<NetDnsResultReport>& dnsResultReport);
    /**
     * 检查当前域名是否在缓存中
     * @param domain 域名
     * @param currentIpType 当前Ip类型
     * @return 是否发生公网到内网的跳变
     */
    RecordDeque::iterator CheckDomainInDnsCache(const std::string& domain);
    /**
     * 检查指定域名的Ip类型是否从公网跳变到内网
     * @param domain 域名
     * @return 目标域名的迭代器或end
     */
    bool CheckPublicToPrivateTransition(const std::string& domain, IpType currentIpType);
    /**
     * 添加新的dns解析记录
     * @param domain 域名
     * @param ipType Ip类型
     */
    void AddRecordToDnsCache(const std::string& domain, IpType ipType);
    void UpdateDnsCache(RecordDeque &records, const std::string& key, IpType ipType);
    bool IsPrivateIp(const std::string& ip);
    bool HasPrivateIp(const std::list<NetDnsResultAddrInfo> &addrList);
};

}  // namespace Wifi
}  // namespace OHOS

#endif
