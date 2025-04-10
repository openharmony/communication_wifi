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

#include "ip_qos_monitor.h"
#include "wifi_logger.h"
#include "wifi_config_center.h"
#include "wifi_global_func.h"

static const int32_t MIN_DELTA_TCP_TX = 3;
static const int32_t QOS_TCP_TX_PKTS = 6;
static const int32_t QOS_TCP_RX_PKTS = 7;
static const int32_t QOS_MSG_FROM = 9;
static const int32_t MIN_PACKET_LEN = 7;
static const int32_t CMD_START_MONITOR = 10;
static const int32_t CMD_QUERY_PKTS = 15;

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("IpQosMonitor");

IpQosMonitor &IpQosMonitor::GetInstance()
{
    static IpQosMonitor gIpQosMonitor;
    return gIpQosMonitor;
}

void IpQosMonitor::StartMonitor(int32_t arg)
{
    WIFI_LOGD("enter %{public}s", __FUNCTION__);
    WifiNetLink::GetInstance().SendQoeCmd(CMD_START_MONITOR, arg);
}

void IpQosMonitor::QueryPackets(int32_t arg)
{
    WIFI_LOGD("enter %{public}s", __FUNCTION__);
    WifiNetLink::GetInstance().SendQoeCmd(CMD_QUERY_PKTS, arg);
}

void IpQosMonitor::HandleTcpReportMsgComplete(const std::vector<int64_t> &elems, int32_t cmd)
{
    WIFI_LOGD("enter %{public}s", __FUNCTION__);
    ParseTcpReportMsg(elems, cmd);
}

void IpQosMonitor::ParseTcpReportMsg(const std::vector<int64_t> &elems, int32_t cmd)
{
    if (elems.size() == 0) {
        WIFI_LOGE("TcpReportMsg elems size is 0");
        return;
    }
    if (cmd == CMD_QUERY_PKTS) {
        HandleTcpPktsResp(elems);
    }
}

void IpQosMonitor::HandleTcpPktsResp(const std::vector<int64_t> &elems)
{
    WIFI_LOGD("enter %{public}s", __FUNCTION__);
    bool internetGood = ParseNetworkInternetGood(elems);
    if (internetGood) {
        if (!lastTxRxGood_) {
            WIFI_LOGI("%{public}s: set tx_rx_good true", __FUNCTION__);
            lastTxRxGood_ = true;
        }
        mInternetFailedCounter = 0;
        mInternetSelfCureAllowed = true;
        mHttpDetectedAllowed = true;
        return;
    }

    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    int32_t signalLevel = WifiSettings::GetInstance().GetSignalLevel(linkedInfo.rssi, linkedInfo.band, mInstId);
    if (lastTxRxGood_) {
        WIFI_LOGI("%{public}s: set tx_rx_good false", __FUNCTION__);
        lastTxRxGood_ = false;
    }
    mInternetFailedCounter++;
    WIFI_LOGI("%{public}s: mInternetFailedCounter = %{public}d", __FUNCTION__, mInternetFailedCounter);
    if ((mInternetFailedCounter >= 1) && (linkedInfo.connState == ConnState::CONNECTED)) {
        ISelfCureService *pSelfCureService = WifiServiceManager::GetInstance().GetSelfCureServiceInst(mInstId);
        if (pSelfCureService == nullptr) {
            WIFI_LOGE("%{public}s: pSelfCureService is null", __FUNCTION__);
            return;
        }
        if (mHttpDetectedAllowed && signalLevel >= SIGNAL_LEVEL_2) {
            WIFI_LOGI("%{public}s: start http detect", __FUNCTION__);
            if (mNetWorkDetect == nullptr) {
                mNetWorkDetect = sptr<NetStateObserver>(new NetStateObserver());
            }
            mNetWorkDetect->StartWifiDetection();
            mHttpDetectedAllowed = false;
            return;
        }
    }
}

bool IpQosMonitor::AllowSelfCureNetwork(int32_t currentRssi)
{
    ISelfCureService *pSelfCureService = WifiServiceManager::GetInstance().GetSelfCureServiceInst(mInstId);
    if (pSelfCureService == nullptr) {
        WIFI_LOGE("%{public}s: pSelfCureService is null.", __FUNCTION__);
        return false;
    }
    if (mInternetSelfCureAllowed && currentRssi >= MIN_VAL_LEVEL_3_5 &&
       (!pSelfCureService->IsSelfCureOnGoing())) {
        return true;
    }
    return false;
}

bool IpQosMonitor::ParseNetworkInternetGood(const std::vector<int64_t> &elems)
{
    WIFI_LOGD("enter %{public}s", __FUNCTION__);
    bool queryResp = (elems[QOS_MSG_FROM] == 0);
    int32_t packetsLength = static_cast<int32_t>(elems.size());
    if ((queryResp) && (packetsLength > MIN_PACKET_LEN)) {
        int64_t tcpTxPkts = elems[QOS_TCP_TX_PKTS];
        int64_t tcpRxPkts = elems[QOS_TCP_RX_PKTS];
        WIFI_LOGD("tcpTxPkts = %{public}" PRId64 ", tcpRxPkts = %{public}" PRId64, tcpTxPkts, tcpRxPkts);
        if ((mLastTcpTxCounter == 0) && (mLastTcpRxCounter == 0)) {
            mLastTcpTxCounter = tcpTxPkts;
            mLastTcpRxCounter = tcpRxPkts;
            WIFI_LOGI("mLastTcpTxCounter = %{public}" PRId64 ", mLastTcpRxCounter = %{public}" PRId64,
                mLastTcpTxCounter, mLastTcpRxCounter);
            return lastTxRxGood_;
        }
        int64_t deltaTcpTxPkts = tcpTxPkts - mLastTcpTxCounter;
        int64_t deltaTcpRxPkts = tcpRxPkts - mLastTcpRxCounter;
        WIFI_LOGI("deltaTcpTxPkts = %{public}" PRId64 ", deltaTcpRxPkts = %{public}" PRId64,
            deltaTcpTxPkts, deltaTcpRxPkts);
        mLastTcpTxCounter = tcpTxPkts;
        mLastTcpRxCounter = tcpRxPkts;
        if (deltaTcpRxPkts == 0) {
            if (deltaTcpTxPkts < MIN_DELTA_TCP_TX) {
                WIFI_LOGI("%{public}s deltaTcpRxPkts 0, deltaTcpTxPkts less 3, return last tx rx status %{public}d",
                    __FUNCTION__, lastTxRxGood_);
                return lastTxRxGood_;
            }
            if (deltaTcpTxPkts >= MIN_DELTA_TCP_TX) {
                WIFI_LOGI("%{public}s internetGood: false", __FUNCTION__);
                return false;
            }
        }
    }
    return true;
}

int64_t IpQosMonitor::GetCurrentTcpTxCounter()
{
    return mLastTcpTxCounter;
}

int64_t IpQosMonitor::GetCurrentTcpRxCounter()
{
    return mLastTcpRxCounter;
}

void IpQosMonitor::ResetTxRxProperty()
{
    WIFI_LOGI("%{public}s: reset tx rx status", __FUNCTION__);
    lastTxRxGood_ = false;
    mLastTcpTxCounter = 0;
    mLastTcpRxCounter = 0;
}

bool IpQosMonitor::GetTxRxStatus()
{
    return lastTxRxGood_;
}

} // namespace Wifi
} // namespace OHOS
