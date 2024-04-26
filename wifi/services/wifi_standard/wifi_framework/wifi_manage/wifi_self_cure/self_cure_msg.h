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
    uint64_t lastDnsSelfCureFailedTs;

    /* record renew dhcp failed count */
    int renewDhcpSelfCureFailedCnt;

    /* record last renew dhcp failed milliseconds */
    uint64_t lastRenewDhcpSelfCureFailedTs;

    /* record static ip failed count */
    int staticIpSelfCureFailedCnt;

    /* record last static ip failed milliseconds */
    uint64_t lastStaticIpSelfCureFailedTs;

    /* record reassoc failed count */
    int reassocSelfCureFailedCnt;

    /* record last reassoc failed milliseconds */
    uint64_t lastReassocSelfCureFailedTs;

    /* record rand mac selfcure fail cnt */
    int randMacSelfCureFailedCnt;

    /* record rand mac selfcure fail time */
    uint64_t lastRandMacSelfCureFailedCntTs;

    /* record reset failed count */
    int resetSelfCureFailedCnt;

    /* record last reset failed milliseconds */
    uint64_t lastResetSelfCureFailedTs;

    /* record reassoc connect failed count */
    int reassocSelfCureConnectFailedCnt;

    /* record last reassoc connect failed milliseconds */
    uint64_t lastReassocSelfCureConnectFailedTs;

    /* record rand mac selfcure connect fail cnt */
    int randMacSelfCureConnectFailedCnt;

    /* record rand mac selfcure connect fail time */
    uint64_t lastRandMacSelfCureConnectFailedCntTs;

    /* record reset connect failed count */
    int resetSelfCureConnectFailedCnt;

    /* record last reset connect failed milliseconds */
    uint64_t lastResetSelfCureConnectFailedTs;
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
}
}
#endif