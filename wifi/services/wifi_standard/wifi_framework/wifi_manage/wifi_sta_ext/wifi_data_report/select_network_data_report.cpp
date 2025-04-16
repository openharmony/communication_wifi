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

#include "select_network_data_report.h"
#include "sta_state_machine.h"
#include "wifi_common_util.h"
#include "wifi_logger.h"
#include "wifi_config_center.h"
#include "wifi_settings.h"
#include <climits>

namespace OHOS {
namespace Wifi {

DEFINE_WIFILOG_LABEL("SelectNetworkDataReport");

namespace WifiDataConstants {

constexpr int BEACON_RSSI_LEN = 10;
constexpr int CDF_LAST_LEN = 8; // txtime, uldelay 最后长度
constexpr int CDF_RAW_LEN = 64; // txtime, uldelay 芯片组件上报到signalpoll的最初长度
constexpr int CDF_PROCESS_LEN = 32; // txtime, uldelay int8 转 int16 后的长度
constexpr int AI_OFFSET_8 = 8;
constexpr int AI_OFFSET_16 = 16;
constexpr int AI_OFFSET_24 = 24;
constexpr int AI_INDEX_1 = 1;
constexpr int AI_INDEX_2 = 2;
constexpr int AI_INDEX_3 = 3;
constexpr int AI_CW_LEN = 2; // cwmin, cwmax
constexpr int CHANNEL_WIDTH_2_4G = 5; // 2.4G频段信道带宽
constexpr int CHANNEL_WIDTH_5G = 20; // 5G频段信道带宽
constexpr int QOE_INFO_LEN = 149; // signalpoll上报最长长度
constexpr int DELAY_TIME = 4 * 60 * 60; // 设置推送时间间隔为DELAY_TIME
constexpr int CONN_FAILED_COUNT_THRESHOLD = 3; // 失败上报阈值,防止关联失败重连导致上报
constexpr int MAX_PUSH_COUNT = 10; // 10条数据融合为一条上报

} // namespace WifiDataConstants

WifiDataReportService::WifiDataReportService(StaStateMachine* staStateMachinePtr, int instId)
    : StaSMExt(staStateMachinePtr, instId) {}

WifiDataReportService::~WifiDataReportService() {}


void WifiDataReportService::InitReportApAllInfo()
{
    std::lock_guard<std::mutex> lock(historyMutex_);
    disConnFlag_ = false;
    connEventTimepInfo_ = ConnectEventTimeInfo();
    lastPushTime_.clear();
    historyData_.clear();
}

uint32_t WifiDataReportService::GetUint32FromExt(const std::vector<uint8_t>& ext, size_t index)
{
    if (index + sizeof(uint32_t) - 1 >= ext.size()) {
        WIFI_LOGE("GetUint32FromExt fail");
        return 0;
    }
    return (static_cast<uint32_t>(ext[index]) |
            static_cast<uint32_t>(ext[index + WifiDataConstants::AI_INDEX_1]) << WifiDataConstants::AI_OFFSET_8 |
            static_cast<uint32_t>(ext[index + WifiDataConstants::AI_INDEX_2]) << WifiDataConstants::AI_OFFSET_16 |
            static_cast<uint32_t>(ext[index + WifiDataConstants::AI_INDEX_3]) << WifiDataConstants::AI_OFFSET_24);
}

std::vector<uint16_t> WifiDataReportService::ConvertUint8ToUint16(const std::vector<uint8_t>& uint8Vec)
{
    std::vector<uint16_t> uint16Vec;
    /* 确保输入向量的长度是偶数 */
    if (uint8Vec.size() % sizeof(uint16_t) != 0) {
        return uint16Vec;
    }
    uint8_t lowByte;
    uint8_t highByte;
    uint16_t combined;
    for (size_t i = 0; i < uint8Vec.size() - 1; i += sizeof(uint16_t)) {
        /* 获取高位和低位字节 */
        lowByte = uint8Vec[i];
        highByte = uint8Vec[i + 1];
        /* 合并成一个 uint16_t, 高位字节左移8位后与低位字节按位或 */
        combined = (highByte << WifiDataConstants::AI_OFFSET_8) | lowByte;
        /* 添加到 uint16_t 向量中 */
        uint16Vec.push_back(combined);
    }
    return uint16Vec;
}

std::vector<uint16_t> WifiDataReportService::SequenceMerge(const std::vector<uint16_t>& sequence)
{
    std::vector<uint16_t> mergeSequence(WifiDataConstants::CDF_LAST_LEN, 0);
    if (sequence.size() != WifiDataConstants::CDF_PROCESS_LEN) {
        WIFI_LOGE("sequence should have exactly 32 elements.");
        return mergeSequence;
    }
    int index = 0;
    /* BE */
    std::vector<uint16_t> cdfBe;
    cdfBe.insert(cdfBe.end(), sequence.begin() + index, sequence.begin() + index + WifiDataConstants::CDF_LAST_LEN);
    index = index + WifiDataConstants::CDF_LAST_LEN;
    /* BK */
    std::vector<uint16_t> cdfBk;
    cdfBk.insert(cdfBk.end(), sequence.begin() + index, sequence.begin() + index + WifiDataConstants::CDF_LAST_LEN);
    index = index + WifiDataConstants::CDF_LAST_LEN;
    /* VI */
    std::vector<uint16_t> cdfVi;
    cdfVi.insert(cdfVi.end(), sequence.begin() + index, sequence.begin() + index + WifiDataConstants::CDF_LAST_LEN);
    index = index + WifiDataConstants::CDF_LAST_LEN;
    /* VO */
    std::vector<uint16_t> cdfVo;
    cdfVo.insert(cdfVo.end(), sequence.begin() + index, sequence.begin() + index + WifiDataConstants::CDF_LAST_LEN);

    for (size_t i = 0; i < cdfBe.size(); i++) {
        mergeSequence[i] = cdfBe[i] + cdfBk[i] + cdfVi[i] + cdfVo[i];
    }
    return mergeSequence;
}

void WifiDataReportService::GetApDeviceInfo(const int& networkId, int instId, WifiDeviceConfig& apDeviceInfo)
{
    if (WifiSettings::GetInstance().GetDeviceConfig(networkId, apDeviceInfo, instId) != 0) {
        WIFI_LOGE("ReportApConnEventInfo GetDeviceConfig failed!");
        return;
    }
}

void WifiDataReportService::UpdateApConnEventTimepInfo(ConnTimeType timeType)
{
    switch (timeType) {
        case ConnTimeType::STA_CONN_START:
            connEventTimepInfo_.timepConnStart = std::time(nullptr);
            break;
        case ConnTimeType::STA_DHCP_SUC:
            connEventTimepInfo_.timepDhcpSuc = std::time(nullptr);
            connEventTimepInfo_.timeToSucConn =
                connEventTimepInfo_.timepDhcpSuc - connEventTimepInfo_.timepConnStart;
            break;
        case ConnTimeType::STA_DISCONN_SUC:
            connEventTimepInfo_.timepDisconnSuc = std::time(nullptr);
            connEventTimepInfo_.timeToDuraConn =
                connEventTimepInfo_.timepDisconnSuc - connEventTimepInfo_.timepDhcpSuc;
            break;
        default:
            break;
    }
}

bool WifiDataReportService::IsAdjacentChannel(int apFrequency, int targetApFrequency, char wifiBand)
{
    int channelWidth = wifiBand == 1 ? WifiDataConstants::CHANNEL_WIDTH_2_4G : WifiDataConstants::CHANNEL_WIDTH_5G;

    return std::abs(targetApFrequency - apFrequency) <= channelWidth;
}

void WifiDataReportService::UpdateSameAdjaFreqCount(WifiCrowdsourcedDetailInfo& apDetailInfo,
    const std::string targetBssid, const int freq, const int band)
{
    int apSamefreqCount = 0;
    int apAdjafreqCount = 0;

    /* 获取扫描结果并判空 */
    std::vector<WifiScanInfo> scanResults;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanResults);
    if (scanResults.empty()) {
        WIFI_LOGE("scanResults is empty");
        return;
    }

    /* 计算同频邻频ap数 */
    for (WifiScanInfo& result : scanResults) {
        if (result.bssid.empty()) {
            continue;
        }
        if (result.bssid == targetBssid) {
            continue;
        }
        if (result.frequency == freq) {
            apSamefreqCount++;
            continue;
        }
        if (IsAdjacentChannel(freq, result.frequency, band)) {
            apAdjafreqCount++;
        }
    }

    apDetailInfo.apSamefreq = apSamefreqCount;
    apDetailInfo.apAdjafreq = apAdjafreqCount;
}

void WifiDataReportService::UpdateForegroundBundleName(WifiCrowdsourcedDetailInfo& apDetailInfo)
{
    StaStateMachine* staStateMachinePtr = GetStaStateMachine();
    if (staStateMachinePtr == nullptr) {
        WIFI_LOGE("Failed to get staStateMachinePtr.");
        return;
    }
    apDetailInfo.appName = staStateMachinePtr->curForegroundAppBundleName_;
}

void WifiDataReportService::UpdateCrowdsourcedDetailInfo(WifiCrowdsourcedDetailInfo& apDetailInfo,
    const WifiLinkedInfo& linkedInfo, const WifiDeviceConfig& apDeviceInfo)
{
    /* 更新上报时间 */
    apDetailInfo.reporTimeStamp = std::time(nullptr);

    /* 更新 link 和 device 信息 */
    apDetailInfo.lastHasInternetTime = apDeviceInfo.lastHasInternetTime;
    apDetailInfo.connFailedCount = apDeviceInfo.connFailedCount;
    apDetailInfo.isPortal = apDeviceInfo.isPortal;
    apDetailInfo.apKeyMgmt = apDeviceInfo.keyMgmt;
    apDetailInfo.channelWidth = apDeviceInfo.channel;
    apDetailInfo.band = apDeviceInfo.band;
    apDetailInfo.frequency = apDeviceInfo.frequency;
    apDetailInfo.rssi = linkedInfo.rssi;
    apDetailInfo.ssid = linkedInfo.ssid;
    apDetailInfo.bssid = linkedInfo.bssid;
    apDetailInfo.isHiddenSSID = linkedInfo.ifHiddenSSID;
    apDetailInfo.wifiStandard = linkedInfo.wifiStandard;
    apDetailInfo.maxSupportedRxLinkSpeed = linkedInfo.maxSupportedRxLinkSpeed;
    apDetailInfo.maxSupportedTxLinkSpeed = linkedInfo.maxSupportedTxLinkSpeed;
    apDetailInfo.supportedWifiCategory = linkedInfo.supportedWifiCategory;
    apDetailInfo.isMloConnected = linkedInfo.isMloConnected;
    apDetailInfo.apMobile = linkedInfo.isDataRestricted; // 通过数据流量限制判断热点是否为手机连接
    apDetailInfo.timeToDuraConn = connEventTimepInfo_.timeToDuraConn;
    apDetailInfo.timeToSucConn = connEventTimepInfo_.timeToSucConn;

    /* 更新前台应用包名 */
    UpdateForegroundBundleName(apDetailInfo);

    /* 更新同频 ap 和邻频 ap 数 */
    UpdateSameAdjaFreqCount(apDetailInfo, linkedInfo.bssid, linkedInfo.frequency, linkedInfo.band);
}


void WifiDataReportService::ParseSignalPollInfo(WifiCrowdsourcedQoeInfo& parseInfo,
    const WifiSignalPollInfo& signalPollInfo)
{
    /* 填充 QoeInfo 字段 */
    parseInfo.txRate = signalPollInfo.txrate;
    parseInfo.rxRate = signalPollInfo.rxrate;
    parseInfo.noise = signalPollInfo.noise;
    parseInfo.txPackets = signalPollInfo.txPackets;
    parseInfo.rxPackets = signalPollInfo.rxPackets;
    parseInfo.snr = signalPollInfo.snr;
    parseInfo.chload = signalPollInfo.chload;
    parseInfo.txBytes = signalPollInfo.txBytes;
    parseInfo.rxBytes = signalPollInfo.rxBytes;
    parseInfo.txFailed = signalPollInfo.txFailed;
    parseInfo.chloadSelf = signalPollInfo.chloadSelf;
    ParseSignalPollInfoEx(parseInfo, signalPollInfo); // 解析SignalPoll.Ext中的信息
}

void WifiDataReportService::ParseSignalPollInfoEx(WifiCrowdsourcedQoeInfo& parseInfo,
    const WifiSignalPollInfo& signalPollInfo)
{
    std::vector<uint8_t> signalPollInfoVec = signalPollInfo.ext;
    if (signalPollInfoVec.size() < WifiDataConstants::QOE_INFO_LEN) {
        return;
    }
    size_t index = 0;
    index = index + WifiDataConstants::BEACON_RSSI_LEN; // 跳过 beacon rssi
    parseInfo.txPpduCnt = GetUint32FromExt(signalPollInfoVec, index); // BadApTxPpduCnt

    index = index + sizeof(uint32_t);
    parseInfo.txPpduRetryCnt = GetUint32FromExt(signalPollInfoVec, index); // BadApTxPpduRetryCnt

    index = index + sizeof(uint32_t);
    parseInfo.txMcs = signalPollInfoVec[index]; // BadApTxMcs

    index = index + 1 + WifiDataConstants::AI_CW_LEN; // jump cw
    std::vector<uint8_t> uldelayCdfUint8; // uldelay 序列
    std::vector<uint16_t> uldelayCdfUint16;
    uldelayCdfUint8.insert(uldelayCdfUint8.end(),
        signalPollInfoVec.begin() + index, signalPollInfoVec.begin() + index + WifiDataConstants::CDF_RAW_LEN);
    uldelayCdfUint16 = ConvertUint8ToUint16(uldelayCdfUint8);

    index = index + WifiDataConstants::CDF_RAW_LEN;
    std::vector<uint8_t> txTimeCdfUint8; // txtime 序列
    std::vector<uint16_t> txTimeCdfUint16;
    txTimeCdfUint8.insert(txTimeCdfUint8.end(),
        signalPollInfoVec.begin() + index, signalPollInfoVec.begin() + index + WifiDataConstants::CDF_RAW_LEN);
    txTimeCdfUint16 = ConvertUint8ToUint16(txTimeCdfUint8);
    /* 合并序列 */
    std::vector<uint16_t> ulDelayCdf = SequenceMerge(uldelayCdfUint16);
    std::vector<uint16_t> txTimeCdf = SequenceMerge(txTimeCdfUint16);

    parseInfo.ulDelayCdf = ulDelayCdf;
    parseInfo.txTimeCdf = txTimeCdf;
}

void WifiDataReportService::UpdateCrowdsourcedQoeInfo(WifiCrowdsourcedQoeInfo& apQoeInfo,
    const std::vector<WifiCrowdsourcedQoeInfo>& historyData)
{
    /* 累加 */
    for (const auto& info : historyData) {
        apQoeInfo.txRate += info.txRate;
        apQoeInfo.rxRate += info.rxRate;
        apQoeInfo.noise += info.noise;
        apQoeInfo.txPackets += info.txPackets;
        apQoeInfo.rxPackets += info.rxPackets;
        apQoeInfo.snr += info.snr;
        apQoeInfo.chload += info.chload;
        apQoeInfo.txBytes = (apQoeInfo.txBytes > INT_MAX - info.txBytes) ? INT_MAX : apQoeInfo.txBytes + info.txBytes;
        apQoeInfo.rxBytes = (apQoeInfo.rxBytes > INT_MAX - info.rxBytes) ? INT_MAX : apQoeInfo.rxBytes + info.rxBytes;
        apQoeInfo.txFailed += info.txFailed;
        apQoeInfo.chloadSelf += info.chloadSelf;
        apQoeInfo.txPpduCnt += info.txPpduCnt;
        apQoeInfo.txPpduRetryCnt += info.txPpduRetryCnt;
        apQoeInfo.txMcs = info.txMcs;
    }

    /* 计算均值 */
    apQoeInfo.txRate /= WifiDataConstants::MAX_PUSH_COUNT;
    apQoeInfo.rxRate /= WifiDataConstants::MAX_PUSH_COUNT;
    apQoeInfo.noise /= WifiDataConstants::MAX_PUSH_COUNT;
    apQoeInfo.txPackets /= WifiDataConstants::MAX_PUSH_COUNT;
    apQoeInfo.rxPackets /= WifiDataConstants::MAX_PUSH_COUNT;
    apQoeInfo.snr /= WifiDataConstants::MAX_PUSH_COUNT;
    apQoeInfo.chload /= WifiDataConstants::MAX_PUSH_COUNT;
    apQoeInfo.txBytes /= WifiDataConstants::MAX_PUSH_COUNT;
    apQoeInfo.rxBytes /= WifiDataConstants::MAX_PUSH_COUNT;
    apQoeInfo.txFailed /= WifiDataConstants::MAX_PUSH_COUNT;
    apQoeInfo.chloadSelf /= WifiDataConstants::MAX_PUSH_COUNT;
    apQoeInfo.txPpduCnt /= WifiDataConstants::MAX_PUSH_COUNT;
    apQoeInfo.txPpduRetryCnt /= WifiDataConstants::MAX_PUSH_COUNT;
    apQoeInfo.txMcs /= WifiDataConstants::MAX_PUSH_COUNT;

    /* 处理 vector 型数据，将每个 vector 中的元素相加 */
    apQoeInfo.ulDelayCdf.resize(WifiDataConstants::CDF_LAST_LEN, 0); // 调整 mergedInfo.ulDelayCdf 的大小并初始化其元素为 0
    apQoeInfo.txTimeCdf.resize(WifiDataConstants::CDF_LAST_LEN, 0); // 调整 mergedInfo.txTimeCdf 的大小并初始化其元素为 0

    /* 合并 ulDelayCdf, txTimeCdf */
    for (const auto& info : historyData) {
        if (info.ulDelayCdf.size() < WifiDataConstants::CDF_LAST_LEN ||
            info.txTimeCdf.size() < WifiDataConstants::CDF_LAST_LEN) {
            return;
        }

        for (size_t i = 0; i < WifiDataConstants::CDF_LAST_LEN; ++i) {
            apQoeInfo.ulDelayCdf[i] += info.ulDelayCdf[i];
            apQoeInfo.txTimeCdf[i] += info.txTimeCdf[i];
        }
    }
}

/* 事件上报 */
void WifiDataReportService::ReportApConnEventInfo(ConnReportReason reportReason, int targetNetworkId)
{
    std::lock_guard<std::mutex> lock(historyMutex_);
    /* 检查断连标志位 */
    if (disConnFlag_) {
        return;
    }

    StaStateMachine* staStateMachinePtr = GetStaStateMachine();
    if (staStateMachinePtr == nullptr) {
        WIFI_LOGE("Failed to get staStateMachinePtr.");
        return;
    }

    /* 获取 Ap deviece 信息 */
    WifiDeviceConfig apDeviceInfo;
    GetApDeviceInfo(targetNetworkId, staStateMachinePtr->m_instId, apDeviceInfo);

    /* 根据连接原因更改对应设置 */
    switch (reportReason) {
        case ConnReportReason::CONN_SUC_START: // 更新连接成功时间, 不改变标志位 disConnFlag_
            UpdateApConnEventTimepInfo(ConnTimeType::STA_DHCP_SUC);
            break;
        case ConnReportReason::CONN_DISCONNECTED: // 更新正常断开连接时间, 改变标志位 disConnFlag_
            UpdateApConnEventTimepInfo(ConnTimeType::STA_DISCONN_SUC);
            disConnFlag_ = true;
            break;
        case ConnReportReason::CONN_ASSOCIATION_REJECTION: // 关联拒绝, 改变标志位 disConnFlag_
        case ConnReportReason::CONN_ASSOCIATION_FULL: // 接入点满, 改变标志位 disConnFlag_
            if (apDeviceInfo.connFailedCount < WifiDataConstants::CONN_FAILED_COUNT_THRESHOLD) {
                disConnFlag_ = true;
                return;
            }
            [[fallthrough]];
        case ConnReportReason::CONN_WRONG_PASSWORD: // 密码错误, 改变标志位 disConnFlag_
        case ConnReportReason::CONN_AUTHENTICATION_FAILURE: // 认证失败, 改变标志位 disConnFlag_
        case ConnReportReason::CONN_DHCP_FAILURE: // Dhcp 失败, 改变标志位 disConnFlag_
            disConnFlag_ = true;
            break;
        default:
            break;
    }
    /* 调用众包接口 */
    WifiCrowdsourcedInfo wifiCrowdsourcedInfo;
    wifiCrowdsourcedInfo.apDetailInfo.reason = reportReason;
    UpdateCrowdsourcedDetailInfo(wifiCrowdsourcedInfo.apDetailInfo, staStateMachinePtr->linkedInfo, apDeviceInfo);
    if (staStateMachinePtr->enhanceService_ == nullptr) {
        return;
    }
    staStateMachinePtr->enhanceService_->CrowdsourcedDataReportInterface(wifiCrowdsourcedInfo);
}

/* 周期上报 */
void WifiDataReportService::ReportQoeInfo(const WifiSignalPollInfo& signalPollInfo, ConnReportReason reportReason,
    int targetNetworkId)
{
    std::lock_guard<std::mutex> lock(historyMutex_);
    StaStateMachine* staStateMachinePtr = GetStaStateMachine();
    if (staStateMachinePtr == nullptr) {
        WIFI_LOGE("Failed to get staStateMachinePtr.");
        return;
    }

    time_t now = std::time(nullptr);
    auto it = lastPushTime_.find(staStateMachinePtr->linkedInfo.bssid);
    time_t lastPush;
    if (it != lastPushTime_.end()) {
        /* 非第一次上报 qoe */
        lastPush = it->second;  // 已存在，直接引用
    } else {
        /* 第一次上报 qoe */
        lastPushTime_[staStateMachinePtr->linkedInfo.bssid] = 0;
        lastPush = lastPushTime_[staStateMachinePtr->linkedInfo.bssid];
    }

    /* 是否第一次上报或者距离上次上报间隔是否超过 DELAY_TIME */
    if (lastPush != 0 && now - lastPush < WifiDataConstants::DELAY_TIME) {
        return;
    }

    WifiCrowdsourcedQoeInfo parseInfo;
    ParseSignalPollInfo(parseInfo, signalPollInfo);
    historyData_.push_back(parseInfo);

    if (historyData_.size() >= WifiDataConstants::MAX_PUSH_COUNT) {
        WifiCrowdsourcedInfo wifiCrowdsourcedInfo;
        wifiCrowdsourcedInfo.apDetailInfo.reason = reportReason;

        /* 获取 Ap deviece 信息 */
        WifiDeviceConfig apDeviceInfo;
        GetApDeviceInfo(targetNetworkId, staStateMachinePtr->m_instId, apDeviceInfo);

        UpdateCrowdsourcedDetailInfo(wifiCrowdsourcedInfo.apDetailInfo, // 更新 link 和 device 信息
            staStateMachinePtr->linkedInfo, apDeviceInfo);

        UpdateCrowdsourcedQoeInfo(wifiCrowdsourcedInfo.apQoeInfo, historyData_); // 融合历史数据，更新 qoe 信息
        historyData_.clear();

        if (staStateMachinePtr->enhanceService_ == nullptr) {
            return;
        }
        staStateMachinePtr->enhanceService_->CrowdsourcedDataReportInterface(wifiCrowdsourcedInfo);
        lastPushTime_[staStateMachinePtr->linkedInfo.bssid] = std::time(nullptr);
    }
}

} // namespace Wifi
} // namespace OHOS