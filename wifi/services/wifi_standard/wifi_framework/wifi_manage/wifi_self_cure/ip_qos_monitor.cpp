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
static const int32_t QOS_IPV6_MSG_FROM = 5;
static const int32_t MIN_PACKET_LEN = 9;
static const int32_t CMD_START_MONITOR = 10;
static const int32_t CMD_QUERY_PKTS = 15;
static const int32_t CMD_QUERY_IPV6_PKTS = 24;
static const int32_t IPV6_FAILURE_THRESHOLD = 3;
static const int32_t INTERNET_FAILURE_THRESHOLD = 2;

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
    
    // Reset IPv6 failed counter when starting monitor, indicating a new connection
    if (mIpv6FailedCounter > 0) {
        WIFI_LOGI("StartMonitor: reset IPv6 failed counter from %{public}d to 0", mIpv6FailedCounter);
        mIpv6FailedCounter = 0;
    }
    
    WifiNetLink::GetInstance().SendQoeCmd(CMD_START_MONITOR, arg);
}

void IpQosMonitor::QueryPackets(int32_t arg)
{
    WIFI_LOGD("enter %{public}s", __FUNCTION__);
    WifiNetLink::GetInstance().SendQoeCmd(CMD_QUERY_PKTS, arg);
}

void IpQosMonitor::QueryIpv6Packets(int32_t arg)
{
    WIFI_LOGD("enter %{public}s", __FUNCTION__);
    WifiNetLink::GetInstance().SendQoeCmd(CMD_QUERY_IPV6_PKTS, arg);
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
    } else if (cmd == CMD_QUERY_IPV6_PKTS) {
        HandleIpv6TcpPktsResp(elems);
    }
}

void IpQosMonitor::HandleTcpPktsResp(const std::vector<int64_t> &elems)
{
    WIFI_LOGD("enter %{public}s", __FUNCTION__);
    std::unique_lock<std::mutex> locker(txRxStatusMtx_);
    bool ignored = false;
    bool internetGood = ParseNetworkInternetGood(elems, ignored);
    if (ignored) {
        WIFI_LOGD("QoS sample ignored (no traffic), no state change.");
        return;
    }
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
    if ((mInternetFailedCounter >= INTERNET_FAILURE_THRESHOLD) && (linkedInfo.connState == ConnState::CONNECTED)) {
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
            if (mNetWorkDetect == nullptr) {
                WIFI_LOGE("%{public}s mNetWorkDetect is null", __func__);
                return;
            }
            mNetWorkDetect->StartWifiDetection();
            mHttpDetectedAllowed = false;
            return;
        }
    }
}

void IpQosMonitor::HandleIpv6TcpPktsResp(const std::vector<int64_t> &elems)
{
    WIFI_LOGD("enter %{public}s", __FUNCTION__);
    Ipv6ControlData controlData;
    controlData.enableIpv6SelfCure = true;
    controlData.txPacketThreshold = MIN_DELTA_TCP_TX;
    controlData.failCountThreshold = IPV6_FAILURE_THRESHOLD;
#ifndef OHOS_ARCH_LITE
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("%{public}s: pEnhanceService is null", __FUNCTION__);
    } else {
        controlData = pEnhanceService->GetIpv6ControlData();
    }
#endif
    if (!controlData.enableIpv6SelfCure) {
        WIFI_LOGD("IPv6 self cure is disabled by EnhanceService");
        return;
    }

    bool ipv6InternetGood = ParseIpv6NetworkInternetGood(elems, controlData.txPacketThreshold);
    if (ipv6InternetGood) {
        mIpv6FailedCounter = 0;
        WIFI_LOGD("IPv6 connection is good, reset failed counter");
        return;
    }
    
    mIpv6FailedCounter++;
    WIFI_LOGI("%{public}s: IPv6 mIpv6FailedCounter = %{public}d", __FUNCTION__, mIpv6FailedCounter);
    
    // Check WiFi connection state, only handle IPv6 failure when connected
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    if (linkedInfo.connState != ConnState::CONNECTED) {
        WIFI_LOGD("WiFi not connected, ignore IPv6 failure");
        return;
    }
    
    // Notify SelfCure service when IPv6 fails 3 times consecutively
    if (mIpv6FailedCounter >= controlData.failCountThreshold) {
        ISelfCureService *pSelfCureService = WifiServiceManager::GetInstance().GetSelfCureServiceInst(mInstId);
        if (pSelfCureService == nullptr) {
            WIFI_LOGE("%{public}s: pSelfCureService is null", __FUNCTION__);
            return;
        }
        
        // Notify SelfCure service about IPv6 connection failure to trigger IPv6 disable mechanism
        ErrCode result = pSelfCureService->NotifyIpv6FailureDetected(GetTxRxStatus());
        if (result == WIFI_OPT_SUCCESS) {
            WIFI_LOGI("%{public}s: IPv6 failure notified to SelfCure successfully after %{public}d failures",
                __FUNCTION__, mIpv6FailedCounter);
        } else {
            WIFI_LOGE("%{public}s: Failed to notify IPv6 failure to SelfCure", __FUNCTION__);
            mIpv6FailedCounter = 0; // Reset counter to avoid repeated notifications
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

bool IpQosMonitor::ParseNetworkInternetGood(const std::vector<int64_t> &elems, bool &ignored)
{
    WIFI_LOGD("enter %{public}s", __FUNCTION__);
    int32_t packetsLength = static_cast<int32_t>(elems.size());
    // Check if array length is sufficient to access required indices
    if (packetsLength <= QOS_MSG_FROM) {
        WIFI_LOGE("elems length %{public}d is too short, expected > %{public}d", packetsLength, QOS_MSG_FROM);
        return true;
    }
    
    bool queryResp = (elems[QOS_MSG_FROM] == 0);
    if (queryResp) {
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
        
        // Handle integer overflow wraparound
        if (deltaTcpTxPkts < 0 || deltaTcpRxPkts < 0) {
            WIFI_LOGW("TCP counter overflow detected, reset counters");
            mLastTcpTxCounter = tcpTxPkts;
            mLastTcpRxCounter = tcpRxPkts;
            return true; // Return true on overflow to avoid false negative
        }
        
        WIFI_LOGI("deltaTcpTxPkts = %{public}" PRId64 ", deltaTcpRxPkts = %{public}" PRId64,
            deltaTcpTxPkts, deltaTcpRxPkts);
        mLastTcpTxCounter = tcpTxPkts;
        mLastTcpRxCounter = tcpRxPkts;
        if (deltaTcpRxPkts == 0) {
            if (deltaTcpTxPkts == 0) {
                WIFI_LOGD("No traffic sample (deltaTx=0, deltaRx=0), marking as ignored.");
                ignored = true;
                return lastTxRxGood_;
            }
            if (deltaTcpTxPkts < MIN_DELTA_TCP_TX) {
                WIFI_LOGD("%{public}s deltaTcpRxPkts 0, deltaTcpTxPkts less 3, return last tx rx status %{public}d",
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

bool IpQosMonitor::ParseIpv6NetworkInternetGood(const std::vector<int64_t> &elems, int32_t txPacketThreshold)
{
    WIFI_LOGD("enter %{public}s", __FUNCTION__);
    
    // First check elems length
    int32_t packetsLength = static_cast<int32_t>(elems.size());
    if (packetsLength <= MIN_PACKET_LEN) {
        WIFI_LOGE("IPv6 elems length %{public}d is too short, expected > %{public}d", packetsLength, MIN_PACKET_LEN);
        return true; // Return true when length is insufficient to avoid false negative
    }
    
    // Check if this is an IPv6 query response, elems[QOS_MSG_FROM] should equal QOS_IPV6_MSG_FROM(5)
    bool queryResp = (elems[QOS_MSG_FROM] == QOS_IPV6_MSG_FROM);
    if (!queryResp) {
        WIFI_LOGD("IPv6 not a query response, msgFrom = %{public}" PRId64 ", expected = %{public}d",
            elems[QOS_MSG_FROM], QOS_IPV6_MSG_FROM);
        return true; // Return true when not IPv6 query response
    }
    
    int64_t tcpTxPkts = elems[QOS_TCP_TX_PKTS];
    int64_t tcpRxPkts = elems[QOS_TCP_RX_PKTS];
    WIFI_LOGD("IPv6 tcpTxPkts = %{public}" PRId64 ", tcpRxPkts = %{public}" PRId64, tcpTxPkts, tcpRxPkts);
    
    if ((mLastIpv6TcpTxCounter == 0) && (mLastIpv6TcpRxCounter == 0)) {
        mLastIpv6TcpTxCounter = tcpTxPkts;
        mLastIpv6TcpRxCounter = tcpRxPkts;
        WIFI_LOGI("IPv6 mLastTcpTxCounter = %{public}" PRId64 ", mLastTcpRxCounter = %{public}" PRId64,
            mLastIpv6TcpTxCounter, mLastIpv6TcpRxCounter);
        return true;
    }
    
    int64_t deltaTcpTxPkts = tcpTxPkts - mLastIpv6TcpTxCounter;
    int64_t deltaTcpRxPkts = tcpRxPkts - mLastIpv6TcpRxCounter;
    
    // Handle integer overflow wraparound
    if (deltaTcpTxPkts < 0 || deltaTcpRxPkts < 0) {
        WIFI_LOGW("IPv6 TCP counter overflow detected, reset counters");
        mLastIpv6TcpTxCounter = tcpTxPkts;
        mLastIpv6TcpRxCounter = tcpRxPkts;
        return true; // Return true on overflow to avoid false negative
    }
    
    WIFI_LOGI("IPv6 deltaTcpTxPkts = %{public}" PRId64 ", deltaTcpRxPkts = %{public}" PRId64,
        deltaTcpTxPkts, deltaTcpRxPkts);
    
    mLastIpv6TcpTxCounter = tcpTxPkts;
    mLastIpv6TcpRxCounter = tcpRxPkts;
    
    if (deltaTcpRxPkts == 0) {
        if (deltaTcpTxPkts >= txPacketThreshold) {
            WIFI_LOGI("%{public}s IPv6 internetGood: false", __FUNCTION__);
            return false;
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
    std::unique_lock<std::mutex> locker(txRxStatusMtx_);
    lastTxRxGood_ = false;
    mLastTcpTxCounter = 0;
    mLastTcpRxCounter = 0;
}

bool IpQosMonitor::GetTxRxStatus()
{
    std::unique_lock<std::mutex> locker(txRxStatusMtx_);
    return lastTxRxGood_;
}

int64_t IpQosMonitor::GetCurrentIpv6TcpTxCounter() const
{
    return mLastIpv6TcpTxCounter;
}
 
int64_t IpQosMonitor::GetCurrentIpv6TcpRxCounter() const
{
    return mLastIpv6TcpRxCounter;
}

int32_t IpQosMonitor::GetIpv6FailedCounter() const
{
    return mIpv6FailedCounter;
}
} // namespace Wifi
} // namespace OHOS
