/*
 * Copyright (C) 2024-2025 Huawei Device Co., Ltd.
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
#include "wifi_common_util.h"
#include "wifi_logger.h"
#include "wifi_config_center.h"
#include "wifi_settings.h"

namespace OHOS {
namespace Wifi {

DEFINE_WIFILOG_LABEL("SelectNetworkDataReport");

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
constexpr int GPS_FLAG = 8; // 携带GPS信息
constexpr int REPORT_VERSION = 2; // 上报方式1：立即、2：闲时上报

WifiDataReportService& WifiDataReportService::GetInstance()
{
    static WifiDataReportService instance;
    return instance;
}

void WifiDataReportService::InitReportApAllInfo()
{
    std::lock_guard<std::mutex> lock(historyMutex);
    connEventTimepInfo = ConnectEventTimeInfo();
    apAllInfo = ApAllInfo(); // 开始wifi连接时, 对结构体初始化
    lastPushTime.clear();
}

uint32_t WifiDataReportService::GetUint32FromExt(const std::vector<uint8_t>& ext, size_t index)
{
    if (index + sizeof(uint32_t) - 1 >= ext.size()) {
        WIFI_LOGE("GetUint32FromExt fail");
        return 0;
    }
    return (static_cast<uint32_t>(ext[index]) | static_cast<uint32_t>(ext[index + AI_INDEX_1]) << AI_OFFSET_8 |
            static_cast<uint32_t>(ext[index + AI_INDEX_2]) << AI_OFFSET_16 |
            static_cast<uint32_t>(ext[index + AI_INDEX_3]) << AI_OFFSET_24);
}

std::vector<uint16_t> WifiDataReportService::ConvertUint8ToUint16(const std::vector<uint8_t>& uint8Vec)
{
    std::vector<uint16_t> uint16Vec;
    // 确保输入向量的长度是偶数
    if (uint8Vec.size() % sizeof(uint16_t) != 0) {
        return uint16Vec;
    }
    uint8_t lowByte;
    uint8_t highByte;
    uint16_t combined;
    for (size_t i = 0; i < uint8Vec.size() - 1; i += sizeof(uint16_t)) {
        // 获取高位和低位字节
        lowByte = uint8Vec[i];
        highByte = uint8Vec[i + 1];
        // 合并成一个 uint16_t, 高位字节左移8位后与低位字节按位或
        combined = (highByte << AI_OFFSET_8) | lowByte;
        // 添加到 uint16_t 向量中
        uint16Vec.push_back(combined);
    }
    return uint16Vec;
}

std::vector<uint16_t> WifiDataReportService::SequenceMerge(const std::vector<uint16_t>& sequence)
{
    std::vector<uint16_t> mergeSequence(CDF_LAST_LEN, 0);
    if (sequence.size() != CDF_PROCESS_LEN) {
        WIFI_LOGE("sequence should have exactly 32 elements.");
        return mergeSequence;
    }
    int index = 0;
    /* BE */
    std::vector<uint16_t> cdfBe;
    cdfBe.insert(cdfBe.end(), sequence.begin() + index, sequence.begin() + index + CDF_LAST_LEN);
    index = index + CDF_LAST_LEN;
    /* BK */
    std::vector<uint16_t> cdfBk;
    cdfBk.insert(cdfBk.end(), sequence.begin() + index, sequence.begin() + index + CDF_LAST_LEN);
    index = index + CDF_LAST_LEN;
    /* VI */
    std::vector<uint16_t> cdfVi;
    cdfVi.insert(cdfVi.end(), sequence.begin() + index, sequence.begin() + index + CDF_LAST_LEN);
    index = index + CDF_LAST_LEN;
    /* VO */
    std::vector<uint16_t> cdfVo;
    cdfVo.insert(cdfVo.end(), sequence.begin() + index, sequence.begin() + index + CDF_LAST_LEN);

    for (size_t i = 0; i < cdfBe.size(); i++) {
        mergeSequence[i] = cdfBe[i] + cdfBk[i] + cdfVi[i] + cdfVo[i];
    }
    return mergeSequence;
}

void WifiDataReportService::UpdateApDeviceInfo(const int& targetId, int instId)
{
    WifiDeviceConfig apDeviceInfo;
    if (WifiSettings::GetInstance().GetDeviceConfig(targetId, apDeviceInfo, instId) != 0) {
        WIFI_LOGE("GetDeviceConfig failed!");
        return;
    }
    apAllInfo.apDetailInfo.lastHasInternetTime = apDeviceInfo.lastHasInternetTime;
    apAllInfo.apDetailInfo.connFailedCount = apDeviceInfo.connFailedCount;
    apAllInfo.apDetailInfo.isPortal = apDeviceInfo.isPortal;
    apAllInfo.apDetailInfo.apKeyMgmt = apDeviceInfo.keyMgmt;
}

void WifiDataReportService::UpdateApLinkedInfo(const WifiLinkedInfo& linkedInfo)
{
    apAllInfo.apDetailInfo.band = linkedInfo.band;
    apAllInfo.apDetailInfo.frequency = linkedInfo.frequency;
    apAllInfo.apDetailInfo.rssi = linkedInfo.rssi;
    apAllInfo.apDetailInfo.ssid = linkedInfo.ssid;
    apAllInfo.apDetailInfo.bssid = linkedInfo.bssid;
    apAllInfo.apDetailInfo.isHiddenSSID = linkedInfo.ifHiddenSSID;
    apAllInfo.apDetailInfo.wifiStandard = linkedInfo.wifiStandard;
    apAllInfo.apDetailInfo.maxSupportedRxLinkSpeed = linkedInfo.maxSupportedRxLinkSpeed;
    apAllInfo.apDetailInfo.maxSupportedTxLinkSpeed = linkedInfo.maxSupportedTxLinkSpeed;
    apAllInfo.apDetailInfo.channelWidth = linkedInfo.channelWidth;
    apAllInfo.apDetailInfo.supportedWifiCategory = linkedInfo.supportedWifiCategory;
    apAllInfo.apDetailInfo.isMloConnected = linkedInfo.isMloConnected;
    apAllInfo.apDetailInfo.apMobile = linkedInfo.isDataRestricted; // 通过数据流量限制判断热点是否为手机
}

void WifiDataReportService::UpdateAppBundleNameInfo(const std::string& bundleName)
{
    apAllInfo.apDetailInfo.appName = bundleName;
}

void WifiDataReportService::UpdateApSignalPollInfo(const WifiSignalPollInfo& info)
{
    std::vector<uint8_t> qoeInfo = info.ext;
    if (qoeInfo.size() < QOE_INFO_LEN) {
        return;
    }
    size_t index = 0;
    index = index + BEACON_RSSI_LEN; // 跳过 beacon rssi
    apAllInfo.apQoeInfo.txPpduCnt = GetUint32FromExt(qoeInfo, index);

    index = index + sizeof(uint32_t);
    apAllInfo.apQoeInfo.txPpduRetryCnt = GetUint32FromExt(qoeInfo, index);

    index = index + sizeof(uint32_t);
    apAllInfo.apQoeInfo.txMcs = qoeInfo[index];

    index = index + 1 + AI_CW_LEN; // jump cw
    std::vector<uint8_t> uldelayCdfUint8; // uldelay 序列
    std::vector<uint16_t> uldelayCdfUint16;
    uldelayCdfUint8.insert(uldelayCdfUint8.end(),
        qoeInfo.begin() + index, qoeInfo.begin() + index + CDF_RAW_LEN);
    uldelayCdfUint16 = ConvertUint8ToUint16(uldelayCdfUint8);

    index = index + CDF_RAW_LEN;
    std::vector<uint8_t> txTimeCdfUint8; // txtime 序列
    std::vector<uint16_t> txTimeCdfUint16;
    txTimeCdfUint8.insert(txTimeCdfUint8.end(),
        qoeInfo.begin() + index, qoeInfo.begin() + index + CDF_RAW_LEN);
    txTimeCdfUint16 = ConvertUint8ToUint16(txTimeCdfUint8);
    /* 合并序列 */
    apAllInfo.apQoeInfo.ulDelayCdf = SequenceMerge(uldelayCdfUint16);
    apAllInfo.apQoeInfo.txTimeCdf = SequenceMerge(txTimeCdfUint16);
    UpdateApSignalPollInfoEx(info);
}

void WifiDataReportService::UpdateApSignalPollInfoEx(const WifiSignalPollInfo& info)
{
    apAllInfo.apDetailInfo.reason = ConnReportReason::CONN_SUC_KEEP;
    apAllInfo.apQoeInfo.chloadSelf = info.chloadSelf;
    apAllInfo.apQoeInfo.txFailed = info.txFailed;
    apAllInfo.apQoeInfo.rxBytes = info.rxBytes;
    apAllInfo.apQoeInfo.txBytes = info.txBytes;
    apAllInfo.apQoeInfo.chload = info.chload;
    apAllInfo.apQoeInfo.snr = info.snr;
    apAllInfo.apQoeInfo.rxPackets = info.rxPackets;
    apAllInfo.apQoeInfo.txPackets = info.txPackets;
    apAllInfo.apQoeInfo.noise = info.noise;
    apAllInfo.apQoeInfo.rxRate = info.rxrate;
    apAllInfo.apQoeInfo.txRate = info.txrate;
    apAllInfo.apDetailInfo.rssi = info.signal;
}

void WifiDataReportService::UpdateApConnEventTimepInfo(ConnTimeType timeType)
{
    switch (timeType) {
        case ConnTimeType::STA_CONN_START:
            connEventTimepInfo.timepConnStart = std::time(nullptr);
            break;
        case ConnTimeType::STA_DHCP_SUC:
            connEventTimepInfo.timepDhcpSuc = std::time(nullptr);
            apAllInfo.apDetailInfo.timeToSucConn =
                connEventTimepInfo.timepDhcpSuc - connEventTimepInfo.timepConnStart;
            break;
        case ConnTimeType::STA_DISCONN_SUC:
            connEventTimepInfo.timepDisconnSuc = std::time(nullptr);
            apAllInfo.apDetailInfo.timeToDuraConn =
                connEventTimepInfo.timepDisconnSuc - connEventTimepInfo.timepDhcpSuc;
            break;
        default:
            break;
    }
}

bool WifiDataReportService::IsAdjacentChannel(int apFrequency, int targetApFrequency, char wifiBand)
{
    int channelWidth = wifiBand == 1 ? CHANNEL_WIDTH_2_4G : CHANNEL_WIDTH_5G;

    return std::abs(targetApFrequency - apFrequency) <= channelWidth;
}

void WifiDataReportService::UpdateSameAdjaFreq()
{
    apAllInfo.apDetailInfo.apSamefreq = 0;
    apAllInfo.apDetailInfo.apAdjafreq = 0;
    std::vector<WifiScanInfo> scanResults;
    WifiConfigCenter::GetInstance().GetWifiScanConfig()->GetScanInfoList(scanResults);
    if (scanResults.empty()) {
        WIFI_LOGE("scanResults is empty");
        return;
    }
    for (WifiScanInfo result : scanResults) {
        if (result.bssid.empty()) {
            continue;
        }
        if (result.bssid == apAllInfo.apDetailInfo.bssid) {
            continue;
        }
        if (result.frequency == apAllInfo.apDetailInfo.frequency) {
            apAllInfo.apDetailInfo.apSamefreq++;
            continue;
        }
        if (IsAdjacentChannel(apAllInfo.apDetailInfo.frequency, result.frequency, apAllInfo.apDetailInfo.band)) {
            apAllInfo.apDetailInfo.apAdjafreq++;
        }
    }
}

std::string WifiDataReportService::ApInfoToJsonInfo(const ApAllInfo& info)
{
    /* 填充 DetailInfo 字段 */
    Json::Value root(Json::objectValue);
    root["BadApType"] = static_cast<int>(info.apDetailInfo.reason);
    root["BadApReportTimeStamp"] = info.apDetailInfo.reporTimeStamp;
    root["BadApSsid"] = info.apDetailInfo.ssid.c_str();
    root["BadApBssid"] = info.apDetailInfo.bssid.c_str();
    root["BadApAppName"] = info.apDetailInfo.appName.c_str();
    root["BadApRssi"] = info.apDetailInfo.rssi;
    root["BadApLastHasInternetTime"] = info.apDetailInfo.lastHasInternetTime;
    root["BadApWifiStandard"] = info.apDetailInfo.wifiStandard;
    root["BadApSupportedWifiCategory"] = static_cast<int>(info.apDetailInfo.supportedWifiCategory);
    root["BadApKeyMgmt"] = info.apDetailInfo.apKeyMgmt.c_str();
    root["BadApConnFailedCount"] = info.apDetailInfo.connFailedCount;
    root["BadApMaxSupportedRxLinkSpeed"] = info.apDetailInfo.maxSupportedRxLinkSpeed;
    root["BadApMaxSupportedTxLinkSpeed"] = info.apDetailInfo.maxSupportedTxLinkSpeed;
    root["BadApMobile"] = info.apDetailInfo.apMobile;
    root["BadApFreq"] = info.apDetailInfo.frequency;
    root["BadApBW"] = static_cast<int>(info.apDetailInfo.channelWidth);
    root["BadApPortal"] = info.apDetailInfo.isPortal;
    root["BadApIsMloConnected"] = info.apDetailInfo.isMloConnected;
    root["BadApHome"] = info.apDetailInfo.isApHome;
    root["BadApScenne"] = info.apDetailInfo.apScenne;
    root["BadApHidden"] = info.apDetailInfo.isHiddenSSID;
    root["BadApSameFreq"] = info.apDetailInfo.apSamefreq;
    root["BadApAdjaFreq"] = info.apDetailInfo.apAdjafreq;
    root["BadApDuraConn"] = info.apDetailInfo.timeToDuraConn;
    root["BadApSucConn"] = info.apDetailInfo.timeToSucConn;
    ApInfoToJsonInfoEx(root, info);

    /* Json转字符串 */
    Json::StreamWriterBuilder writer;
    return Json::writeString(writer, root);
}

void WifiDataReportService::ApInfoToJsonInfoEx(Json::Value& root, const ApAllInfo& info)
{
    /* 填充 QoeInfo 字段 */
    root["BadApTxRate"] = info.apQoeInfo.txRate;
    root["BadApRxRate"] = info.apQoeInfo.rxRate;
    root["BadApNoise"] = info.apQoeInfo.noise;
    root["BadApTxPackets"] = info.apQoeInfo.txPackets;
    root["BadApRxPackets"] = info.apQoeInfo.rxPackets;
    root["BadApSnr"] = info.apQoeInfo.snr;
    root["BadApChload"] = info.apQoeInfo.chload;
    root["BadApTxBytes"] = info.apQoeInfo.txBytes;
    root["BadApRxBytes"] = info.apQoeInfo.rxBytes;
    root["BadApTxFailed"] = info.apQoeInfo.txFailed;
    root["BadApChloadSelf"] = info.apQoeInfo.chloadSelf;
    root["BadApTxPpduCnt"] = info.apQoeInfo.txPpduCnt;
    root["BadApTxPpduRetryCnt"] = info.apQoeInfo.txPpduRetryCnt;
    root["BadApTxMcs"] = info.apQoeInfo.txMcs;

    /* 处理向量类型的字段 */

    Json::Value ulDelayCdfArray(Json::arrayValue);
    for (uint16_t ulDelay : info.apQoeInfo.ulDelayCdf) {
        ulDelayCdfArray.append(ulDelay);
    }
    root["BadApUlDelayCdf"] = ulDelayCdfArray;

    Json::Value txTimeCdfArray(Json::arrayValue);
    for (uint16_t txTime : info.apQoeInfo.txTimeCdf) {
        txTimeCdfArray.append(txTime);
    }
    root["BadApTxTimeCdf"] = txTimeCdfArray;
}

void WifiDataReportService::ReportApConnEventInfo(ConnReportReason connReportReason, const WifiLinkedInfo& linkedInfo,
    int instId, const int& targetId, IEnhanceService* enhanceService_)
{
    std::lock_guard<std::mutex> lock(historyMutex);
    /* 检查 enhanceService_ 是否为空或断连标志位 */
    if (apAllInfo.apDetailInfo.disConnFlag) {
        return;
    }

    /* 更新上报时间, 断连原因 */
    apAllInfo.apDetailInfo.reporTimeStamp = std::time(nullptr);
    apAllInfo.apDetailInfo.reason = connReportReason;

    /* 更新 ap 信息 */
    UpdateApLinkedInfo(linkedInfo); // 更新 AP linked 信息
    UpdateApDeviceInfo(targetId, instId); // 更新 AP device 信息
    /* 根据连接原因更改对应设置 */
    switch (connReportReason) {
        case ConnReportReason::CONN_SUC_START: // 更新连接成功时间, 不改变标志位 disConnFlag
            UpdateApConnEventTimepInfo(ConnTimeType::STA_DHCP_SUC);
            break;
        case ConnReportReason::CONN_DISCONNECTED: // 更新正常断开连接时间, 改变标志位 disConnFlag
            UpdateApConnEventTimepInfo(ConnTimeType::STA_DISCONN_SUC);
            apAllInfo.apDetailInfo.disConnFlag = true;
            break;
        case ConnReportReason::CONN_ASSOCIATION_REJECTION: // 关联拒绝, 改变标志位 disConnFlag
        case ConnReportReason::CONN_ASSOCIATION_FULL: // 接入点满, 改变标志位 disConnFlag
            if (apAllInfo.apDetailInfo.connFailedCount < CONN_FAILED_COUNT_THRESHOLD) {
                apAllInfo.apDetailInfo.disConnFlag = true;
                return;
            }
            [[fallthrough]];
        case ConnReportReason::CONN_WRONG_PASSWORD: // 密码错误, 改变标志位 disConnFlag
        case ConnReportReason::CONN_AUTHENTICATION_FAILURE: // 认证失败, 改变标志位 disConnFlag
        case ConnReportReason::CONN_DHCP_FAILURE: // Dhcp 失败, 改变标志位 disConnFlag
            apAllInfo.apDetailInfo.disConnFlag = true;
            break;
        default:
            break;
    }

    /* 调用众包接口 */
    std::string apJsonData = ApInfoToJsonInfo(apAllInfo);
    if (enhanceService_ == nullptr) {
        return;
    }
    enhanceService_->CrowdsourcedDataReportInterface(apJsonData, GPS_FLAG, REPORT_VERSION);
}

void WifiDataReportService::ReportQoeInfo(const WifiSignalPollInfo& qoeInfo, IEnhanceService* enhanceService_)
{
    std::lock_guard<std::mutex> lock(historyMutex);
    auto now = std::chrono::steady_clock::now();
    auto& lastPush = lastPushTime[apAllInfo.apDetailInfo.bssid]; // 最后一次上报时间

    // 检查 lastPush 是否初始化过
    if (lastPush == std::chrono::steady_clock::time_point()) {
        // 如果是第一次调用, 直接返回
        lastPush = now; // 设置为当前时间
        return;
    }

    if (now - lastPush >= pushInterval && enhanceService_ != nullptr) {
        UpdateApSignalPollInfo(qoeInfo); // 更新qoe信息
        UpdateSameAdjaFreq(); // 更新同频邻频ap数
        apAllInfo.apDetailInfo.reporTimeStamp = std::time(nullptr); // 更新上报时间
        std::string apJsonData = ApInfoToJsonInfo(apAllInfo);
        enhanceService_->CrowdsourcedDataReportInterface(apJsonData, GPS_FLAG, REPORT_VERSION);
        lastPush = std::chrono::steady_clock::now();
    }
}

} // namespace Wifi
} // namespace OHOS