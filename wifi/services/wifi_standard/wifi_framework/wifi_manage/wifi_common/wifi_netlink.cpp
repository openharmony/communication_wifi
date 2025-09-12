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

#include "wifi_netlink.h"
#include <asm/types.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include "securec.h"
#include <linux/netlink.h>
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiNetLink");
static const int32_t NETLINK_WIFIPRO_EVENT_NL = 24;
static const int32_t NEW_INT_ARR_LENGTH = 10;
static const int32_t QOS_RTT = 0;
static const int32_t QOS_RTT_PKTS = 1;
static const int32_t QOS_RTT_WHEN = 2;
static const int32_t QOS_CONGESTION = 3;
static const int32_t QOS_CONG_WHEN = 4;
static const int32_t QOS_TCP_QUALITY = 5;
static const int32_t QOS_TCP_TX_PKTS = 6;
static const int32_t QOS_TCP_RX_PKTS = 7;
static const int32_t QOS_TCP_RETRANS_PKTS = 8;
static const int32_t QOS_MSG_FROM = 9;

enum WifiKnlMsgType {
    NETLINK_WIFIPRO_START_MONITOR = 0,
    NETLINK_WIFIPRO_GET_MSG,
    NETLINK_WIFIPRO_GET_IPV6_MSG = 9,
};

enum CmdWord {
    CMD_START_MONITOR = 10,
    CMD_QUERY_PKTS = 15,
    CMD_QUERY_IPV6_PKTS = 24,
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

WifiNetLink &WifiNetLink::GetInstance()
{
    static WifiNetLink gWifiNetLink;
    return gWifiNetLink;
}

void WifiNetLink::InitWifiNetLink(const WifiNetLinkCallbacks &wifiNetLinkCallbacks)
{
    mWifiNetLinkCallbacks = wifiNetLinkCallbacks;
}

int32_t WifiNetLink::SendCmdKernel(int32_t sockFd, int32_t cmd, int32_t flag)
{
    int32_t ret = -1;
    struct timeval tv;
    struct sockaddr_nl stKpeer;
    struct TagMsg2Knl stMessage;
    if (memset_s(&stKpeer, sizeof(stKpeer), 0, sizeof(stKpeer)) != EOK) {
        WIFI_LOGE("SendCmdKernel memset_s failed stKpeer");
        return ret;
    }
    stKpeer.nl_family = AF_NETLINK;
    stKpeer.nl_pid = 0;
    stKpeer.nl_groups = 0;

    if (memset_s(&stMessage, sizeof(struct TagMsg2Knl), 0, sizeof(struct TagMsg2Knl)) != EOK) {
        WIFI_LOGE("SendCmdKernel memset_s failed stMessage.");
        return ret;
    }
    stMessage.hdr.nlmsg_len = static_cast<unsigned int>(NLMSG_LENGTH(0));
    stMessage.hdr.nlmsg_flags = flag;
    stMessage.hdr.nlmsg_type = cmd;
    stMessage.hdr.nlmsg_pid = static_cast<unsigned int>(getpid());
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(sockFd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        WIFI_LOGE("socket option SO_RCVTIMEO not support.");
        return ret;
    }
    ret = sendto(sockFd, &stMessage, stMessage.hdr.nlmsg_len, 0,
        reinterpret_cast<struct sockaddr *>(&stKpeer), sizeof(stKpeer));
    if (ret == -1) {
        WIFI_LOGE("send %{public}d to kernel failed!!!", cmd);
    }
    return ret;
}

int32_t WifiNetLink::StartMonitor(int32_t sockFd)
{
    return SendCmdKernel(sockFd, NETLINK_WIFIPRO_START_MONITOR, 0);
}

int32_t WifiNetLink::ProcessQueryTcp(int32_t sockFd)
{
    return SendCmdKernel(sockFd, NETLINK_WIFIPRO_GET_MSG, 0);
}

int32_t WifiNetLink::ProcessQueryIpv6Tcp(int32_t sockFd)
{
    return SendCmdKernel(sockFd, NETLINK_WIFIPRO_GET_IPV6_MSG, 0);
}

int32_t WifiNetLink::SendQoeCmd(int32_t cmd, int32_t arg)
{
    int32_t sockFd = -1;
    int32_t sendResult = -1;
    bool isNeedReport = false;
    int32_t ret = -1;
    sockFd = socket(PF_NETLINK, SOCK_RAW, NETLINK_WIFIPRO_EVENT_NL);
    if (sockFd < 0) {
        WIFI_LOGE("%{public}s: open monitor_fd error, sockFd: %{public}d, errno: %{public}d",
            __FUNCTION__, sockFd, errno);
        return ret;
    }
    switch (cmd) {
        case CMD_START_MONITOR:
            sendResult = StartMonitor(sockFd);
            break;
        case CMD_QUERY_PKTS:
            sendResult = ProcessQueryTcp(sockFd);
            isNeedReport = true;
            break;
        case CMD_QUERY_IPV6_PKTS:
            sendResult = ProcessQueryIpv6Tcp(sockFd);
            isNeedReport = true;
            break;
        default:
            break;
    }
    if (sendResult != -1 && isNeedReport) {
        ret = ProcessReportMsg(sockFd, cmd);
        close(sockFd);
        return ret;
    }
    close(sockFd);
    return sendResult;
}

int32_t WifiNetLink::ProcessReportMsg(int32_t sockFd, int32_t cmd)
{
    WIFI_LOGD("ProcessReportMsg cmd = %{public}d", cmd);
    struct sockaddr_nl stKpeer;
    struct PacketInfo info;
    struct timeval tv;
    int32_t uiKpeerLen = 0;
    int32_t uiRcvLen = 0;

    stKpeer.nl_family = AF_NETLINK;
    stKpeer.nl_pid = 0;
    stKpeer.nl_groups = 0;
    uiKpeerLen = sizeof(struct sockaddr_nl);

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        WIFI_LOGE("socket option SO_RCVTIMEO not support.");
        return -1;
    }

    uiRcvLen = recvfrom(sockFd, &info, sizeof(struct PacketInfo), 0,
        reinterpret_cast<struct sockaddr *>(&stKpeer), reinterpret_cast<socklen_t *>(&uiKpeerLen));
    if (uiRcvLen > 0) {
        std::vector<int64_t> elems(NEW_INT_ARR_LENGTH, 0);
        elems[QOS_RTT] = info.qos.rtt;
        elems[QOS_RTT_PKTS] = info.qos.rttPkts;
        elems[QOS_RTT_WHEN] = info.qos.rttWhen;
        elems[QOS_CONGESTION] = info.qos.congestion;
        elems[QOS_CONG_WHEN] = info.qos.congWhen;
        elems[QOS_TCP_QUALITY] = info.qos.tcpQuality;
        elems[QOS_TCP_TX_PKTS] = info.qos.tcpTxPkts;
        elems[QOS_TCP_RX_PKTS] = info.qos.tcpRxPkts;
        elems[QOS_TCP_RETRANS_PKTS] = info.qos.tcpRetransPkts;
        elems[QOS_MSG_FROM] = info.qos.msgFrom;
        mWifiNetLinkCallbacks.OnTcpReportMsgComplete(elems, cmd, mInstId);
        return 0;
    } else {
        const char* type = (cmd == CMD_QUERY_IPV6_PKTS) ? "IPv6" : "IPv4";
        WIFI_LOGI("Received invalid %{public}s message", type);
        return -1;
    }
}

} // namespace Wifi
} // namespace OHOS
