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

#ifndef OHOS_SELECT_NETWORK_DATA_REPORT_H
#define OHOS_SELECT_NETWORK_DATA_REPORT_H
#include <vector>
#include <mutex>
#include <map>
#include "wifi_log.h"
#include "ienhance_service.h"
#include "json/json.h"

namespace OHOS {
namespace Wifi {

constexpr int DELAY_TIME = 240; // 上报间隔时间
constexpr int CONN_FAILED_COUNT_THRESHOLD = 3; // 失败上报阈值,防止关联失败重连导致上报

enum class ConnTimeType {
    STA_CONN_START = 0,
    STA_DHCP_SUC = 1,
    STA_DISCONN_SUC = 2
};

enum class ConnReportReason {
    CONN_INIT = -1,
    CONN_SUC_KEEP = 0,
    CONN_SUC_START = 1,
    CONN_WRONG_PASSWORD = 2,
    CONN_AUTHENTICATION_FAILURE = 3,
    CONN_ASSOCIATION_REJECTION = 4,
    CONN_DHCP_FAILURE = 5,
    CONN_DISCONNECTED = 6,
    CONN_ASSOCIATION_FULL = 7
};

struct ApDetailInfo {
    ConnReportReason reason;
    bool disConnFlag; // 断连上报标志位,不参与众包上报,防止异常断连导致二次事件上报
    time_t reporTimeStamp;
    std::string ssid;
    std::string bssid;
    std::string appName;
    int8_t rssi;
    time_t lastHasInternetTime;
    int8_t wifiStandard;
    WifiCategory supportedWifiCategory;
    std::string apKeyMgmt;
    uint8_t connFailedCount;
    uint16_t maxSupportedRxLinkSpeed;
    uint16_t maxSupportedTxLinkSpeed;
    int8_t apMobile;
    uint16_t frequency;
    uint8_t band; // 2.4G / 5G
    WifiChannelWidth channelWidth; // curr ap channel width
    int8_t isPortal;
    int8_t isMloConnected;
    int8_t isApHome;
    int8_t apScenne;
    int8_t isHiddenSSID;
    int8_t apSamefreq;
    int8_t apAdjafreq;
    int32_t timeToDuraConn;
    int32_t timeToSucConn;
    ApDetailInfo()
    {
        reason = ConnReportReason::CONN_INIT;
        disConnFlag = false;
        reporTimeStamp = std::time(nullptr);
        ssid = "";
        bssid = "";
        appName = "";
        rssi = 0;
        lastHasInternetTime = 0;
        wifiStandard = -1;
        supportedWifiCategory = WifiCategory::DEFAULT;
        apKeyMgmt = "";
        connFailedCount = 0;
        maxSupportedRxLinkSpeed = 0;
        maxSupportedTxLinkSpeed = 0;
        apMobile = -1;
        frequency = 0;
        band = 0;
        channelWidth = WifiChannelWidth::WIDTH_INVALID;
        isPortal = -1;
        isMloConnected = -1;
        isApHome = -1;
        apScenne = -1;
        isHiddenSSID = -1;
        apSamefreq = -1;
        apAdjafreq = -1;
        timeToDuraConn = -1;
        timeToSucConn = -1;
    }
};

struct ConnectEventTimeInfo {
    time_t timepConnStart;
    time_t timepDhcpSuc;
    time_t timepDisconnSuc;
    ConnectEventTimeInfo()
    {
        timepConnStart = std::time(nullptr);
        timepDhcpSuc = 0;
        timepDisconnSuc = 0;
    }
};

struct ApQoeInfo {
    uint32_t txRate;
    uint32_t rxRate;
    int8_t noise;
    uint32_t txPackets;
    uint32_t rxPackets;
    uint8_t snr;
    uint16_t chload;
    uint32_t txBytes;
    uint32_t rxBytes;
    uint32_t txFailed;
    uint16_t chloadSelf;
    uint32_t txPpduCnt;
    uint32_t txPpduRetryCnt;
    uint8_t txMcs;
    std::vector<uint16_t> ulDelayCdf;
    std::vector<uint16_t> txTimeCdf;
    ApQoeInfo()
    {
        txRate = 0;
        rxRate = 0;
        noise = 0;
        txPackets = 0;
        rxPackets = 0;
        snr = 0;
        chload = 0;
        txBytes = 0;
        rxBytes = 0;
        txFailed = 0;
        chloadSelf = 0;
        txPpduCnt = 0;
        txPpduRetryCnt = 0;
        txMcs = 0;
    }
};

struct ApAllInfo {
    ApDetailInfo apDetailInfo;
    ApQoeInfo apQoeInfo;
    ApAllInfo()
    {
        apDetailInfo = ApDetailInfo();
        apQoeInfo = ApQoeInfo();
    }
};

/* 单例类声明 */
class WifiDataReportService {
private:
    ConnectEventTimeInfo connEventTimepInfo;
    ApAllInfo apAllInfo;

    std::map<std::string, std::chrono::steady_clock::time_point> lastPushTime; // 存储每个bssid的最后推送时间
    const std::chrono::minutes pushInterval = std::chrono::minutes(DELAY_TIME); // 设置推送时间间隔为DELAY_TIME
    std::mutex historyMutex; // 用于保护历史记录

    /* 私有化构造函数 */
    WifiDataReportService() {}

    /* 析构函数 */
    ~ WifiDataReportService() {}

public:
    /* 获取单例实例 */
    static WifiDataReportService& GetInstance();

    /* 禁用复制和赋值操作 */
    WifiDataReportService(const WifiDataReportService&) = delete;
    void operator=(const WifiDataReportService&) = delete;

    /* 初始化函数并赋值 AP device 信息 */
    void InitReportApAllInfo();

    uint32_t GetUint32FromExt(const std::vector<uint8_t>& ext, size_t index);
    std::vector<uint16_t> ConvertUint8ToUint16(const std::vector<uint8_t>& uint8Vec);
    std::vector<uint16_t> SequenceMerge(const std::vector<uint16_t>& sequence);
    /* 更新函数 */
    void UpdateApConnEventTimepInfo(ConnTimeType timeType); // 更新 AP 连接事件时间戳
    void UpdateAppBundleNameInfo(const std::string& bundleName); // 更新前台应用包名
    void UpdateApDeviceInfo(const int& targetId, int instId); // 获取并更新 AP Device 信息
    void UpdateApLinkedInfo(const WifiLinkedInfo& info);
    void UpdateApSignalPollInfo(const WifiSignalPollInfo& info);
    void UpdateApSignalPollInfoEx(const WifiSignalPollInfo& info);

    /* 计算同频邻频ap数 */
    bool IsAdjacentChannel(int apFrequency, int targetApFrequency, char wifiBand);
    void UpdateSameAdjaFreq();

    /* ApInfo --> JsonInfo --> string */
    std::string ApInfoToJsonInfo(const ApAllInfo& info);
    void ApInfoToJsonInfoEx(Json::Value& root, const ApAllInfo& info);

    /* 事件上报 */
    void ReportApConnEventInfo(ConnReportReason connReportReason, const WifiLinkedInfo& linkedInfo,
        int instId, const int& targetId, IEnhanceService* enhanceService_);

    /* 周期上报 */
    void ReportQoeInfo(const WifiSignalPollInfo& qoeInfo, IEnhanceService* enhanceService_);
};
} // namespace Wifi
} // namespace OHOS
#endif