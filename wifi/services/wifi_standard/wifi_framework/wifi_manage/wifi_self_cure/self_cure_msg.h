/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_SELF_CURE_MSG_H
#define OHOS_SELF_CURE_MSG_H

#include "string"

namespace OHOS {
namespace Wifi {
/* self cure history info */
struct WifiSelfCureHistoryInfo {
    /* record dns failed count */
    int dnsSelfCureFailedCnt;

    /* record last dns failed milliseconds */
    int64_t lastDnsSelfCureFailedTs;

    /* record renew dhcp failed count */
    int renewDhcpSelfCureFailedCnt;

    /* record last renew dhcp failed milliseconds */
    int64_t lastRenewDhcpSelfCureFailedTs;

    /* record static ip failed count */
    int staticIpSelfCureFailedCnt;

    /* record last static ip failed milliseconds */
    int64_t lastStaticIpSelfCureFailedTs;

    /* record reassoc failed count */
    int reassocSelfCureFailedCnt;

    /* record last reassoc failed milliseconds */
    int64_t lastReassocSelfCureFailedTs;

    /* record rand mac selfcure fail cnt */
    int randMacSelfCureFailedCnt;

    /* record rand mac selfcure fail time */
    int64_t lastRandMacSelfCureFailedCntTs;

    /* record reset failed count */
    int resetSelfCureFailedCnt;

    /* record last reset failed milliseconds */
    int64_t lastResetSelfCureFailedTs;

    /* record reassoc connect failed count */
    int reassocSelfCureConnectFailedCnt;

    /* record last reassoc connect failed milliseconds */
    int64_t lastReassocSelfCureConnectFailedTs;

    /* record rand mac selfcure connect fail cnt */
    int randMacSelfCureConnectFailedCnt;

    /* record rand mac selfcure connect fail time */
    int64_t lastRandMacSelfCureConnectFailedCntTs;

    /* record reset connect failed count */
    int resetSelfCureConnectFailedCnt;

    /* record last reset connect failed milliseconds */
    int64_t lastResetSelfCureConnectFailedTs;
    WifiSelfCureHistoryInfo()
    {
        dnsSelfCureFailedCnt = 0;
        lastDnsSelfCureFailedTs = 0;
        renewDhcpSelfCureFailedCnt = 0;
        lastRenewDhcpSelfCureFailedTs = 0;
        staticIpSelfCureFailedCnt = 0;
        lastStaticIpSelfCureFailedTs = 0;
        reassocSelfCureFailedCnt = 0;
        lastReassocSelfCureFailedTs = 0;
        randMacSelfCureFailedCnt = 0;
        lastRandMacSelfCureFailedCntTs = 0;
        resetSelfCureFailedCnt = 0;
        lastResetSelfCureFailedTs = 0;
        reassocSelfCureConnectFailedCnt = 0;
        lastReassocSelfCureConnectFailedTs = 0;
        randMacSelfCureConnectFailedCnt = 0;
        lastRandMacSelfCureConnectFailedCntTs = 0;
        resetSelfCureConnectFailedCnt = 0;
        lastResetSelfCureConnectFailedTs = 0;
    }
    std::string GetSelfCureHistory()
    {
        std::string internetSelfCureHistory;
        internetSelfCureHistory.append(std::to_string(dnsSelfCureFailedCnt) + "|");
        internetSelfCureHistory.append(std::to_string(lastDnsSelfCureFailedTs) + "|");
        internetSelfCureHistory.append(std::to_string(renewDhcpSelfCureFailedCnt) + "|");
        internetSelfCureHistory.append(std::to_string(lastRenewDhcpSelfCureFailedTs) + "|");
        internetSelfCureHistory.append(std::to_string(staticIpSelfCureFailedCnt) + "|");
        internetSelfCureHistory.append(std::to_string(lastStaticIpSelfCureFailedTs) + "|");
        internetSelfCureHistory.append(std::to_string(reassocSelfCureFailedCnt) + "|");
        internetSelfCureHistory.append(std::to_string(lastReassocSelfCureFailedTs) + "|");
        internetSelfCureHistory.append(std::to_string(randMacSelfCureFailedCnt) + "|");
        internetSelfCureHistory.append(std::to_string(lastRandMacSelfCureFailedCntTs) + "|");
        internetSelfCureHistory.append(std::to_string(resetSelfCureFailedCnt) + "|");
        internetSelfCureHistory.append(std::to_string(lastResetSelfCureFailedTs) + "|");
        internetSelfCureHistory.append(std::to_string(reassocSelfCureConnectFailedCnt) + "|");
        internetSelfCureHistory.append(std::to_string(lastReassocSelfCureConnectFailedTs) + "|");
        internetSelfCureHistory.append(std::to_string(randMacSelfCureConnectFailedCnt) + "|");
        internetSelfCureHistory.append(std::to_string(lastRandMacSelfCureConnectFailedCntTs) + "|");
        internetSelfCureHistory.append(std::to_string(resetSelfCureConnectFailedCnt) + "|");
        internetSelfCureHistory.append(std::to_string(lastResetSelfCureConnectFailedTs));
        return internetSelfCureHistory;
    }
};

enum class SelfCureType {
    SCE_TYPE_INVALID = 0,
    SCE_TYPE_DNS = 1,
    SCE_TYPE_REASSOC = 2,
    SCE_TYPE_WIFI6 = 3,
    SCE_TYPE_STATIC_IP = 4,
    SCE_TYPE_MULTI_GW = 5,
    SCE_TYPE_RANDMAC = 6,
    SCE_TYPE_RESET = 7,
};

enum SelfCureState {
    SCE_WIFI_INVALID_STATE,
    SCE_WIFI_OFF_STATE,
    SCE_WIFI_ON_STATE,
    SCE_WIFI_CONNECT_STATE,
    SCE_WIFI_REASSOC_STATE,
};

constexpr int32_t SCE_EVENT_WIFI_STATE_CHANGED = 101;
constexpr int32_t SCE_EVENT_NET_INFO_CHANGED = 102;
constexpr int32_t SCE_EVENT_CONN_CHANGED = 103;

constexpr int32_t SCE_WIFI_STATUS_ABORT = -3;
constexpr int32_t SCE_WIFI_STATUS_LOST = -2;
constexpr int32_t SCE_WIFI_STATUS_FAIL = -1;
constexpr int32_t SCE_WIFI_STATUS_SUCC = 0;
}
}
#endif