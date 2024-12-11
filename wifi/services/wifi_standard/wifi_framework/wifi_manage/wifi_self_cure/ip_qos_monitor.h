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

#ifndef OHOS_IP_QOS_MONITOR_H
#define OHOS_IP_QOS_MONITOR_H

#include "self_cure_service.h"
#include "wifi_netlink.h"
#include "wifi_net_observer.h"

namespace OHOS {
namespace Wifi {
class IpQosMonitor {
public:
    static IpQosMonitor &GetInstance();
    void StartMonitor(int32_t arg = 0);
    void QueryPackets(int32_t arg = 0);
    void HandleTcpReportMsgComplete(const std::vector<int64_t> &elems, int32_t cmd);
    void ParseTcpReportMsg(const std::vector<int64_t> &elems, int32_t cmd);
    void HandleTcpPktsResp(const std::vector<int64_t> &elems);
    bool ParseNetworkInternetGood(const std::vector<int64_t> &elems);
    int64_t GetCurrentTcpTxCounter();
    int64_t GetCurrentTcpRxCounter();
private:
    bool AllowSelfCureNetwork(int32_t currentRssi);
    int32_t mInstId = 0;
    bool mInternetSelfCureAllowed = true;
    bool mHttpDetectedAllowed = true;
    int64_t mLastTcpTxCounter = 0;
    int64_t mLastTcpRxCounter = 0;
    int32_t mInternetFailedCounter = 0;
    sptr<NetStateObserver> mNetWorkDetect;
};

} // namespace Wifi
} // namespace OHOS
#endif // OHOS_IP_QOS_MONITOR_H