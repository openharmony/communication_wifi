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

#ifndef INCLUDE_WIFI_NETLINK_H
#define INCLUDE_WIFI_NETLINK_H

#include <functional>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <memory>
#include <netinet/in.h>
#include <sys/epoll.h>
#include "wifi_errcode.h"

enum WifiKnlMsgType {
    NETLINK_WIFIPRO_START_MONITOR = 0,
    NETLINK_WIFIPRO_GET_MSG,
};

enum CmdWord {
    CMD_START_MONITOR = 10,
    CMD_QUERY_PKTS = 15,
    MSG_REPORT_IPQOS = 100,
};

struct WifiNlPacketMsg {
    uint32_t msgFrom;
    uint32_t rtt;
    uint32_t rttPkts;
    uint32_t rttWhen;
    uint32_t congestion;
    uint32_t congWhen;
    uint32_t tcpQuality;
    uint32_t tcpTxPkts;
    uint32_t tcpRxPkts;
    uint32_t tcpRetransPkts;
};

struct TagMsg2Knl {
    struct nlmsghdr hdr;
};

struct PacketInfo {
    struct nlmsghdr hdr;
    struct WifiNlPacketMsg qos;
};

struct WifiNetLinkCallbacks {
    std::function<void(const std::vector<int64_t> &elems, const int32_t cmd, const int32_t mInstId)> OnTcpReportMsgComplete;
};

namespace OHOS {
namespace Wifi {

class WifiNetLink {
public:
    static WifiNetLink &GetInstance();
    void InitWifiNetLink(const WifiNetLinkCallbacks &wifiNetLinkCallbacks);
    int32_t SendCmdKernel(int32_t sockFd, int32_t cmd, int32_t flag);
    int32_t StartMonitor(int32_t sockFd);
    int32_t ProcessQueryTcp(int32_t sockFd);
    int32_t SendQoeCmd(int32_t cmd, int32_t arg = 0);
    int32_t ProcessReportMsg(int32_t sockFd, int32_t cmd);
private:
    WifiNetLinkCallbacks mWifiNetLinkCallbacks;
    int32_t mInstId = 0;
};
    
}  // namespace Wifi
}  // namespace OHOS
#endif


