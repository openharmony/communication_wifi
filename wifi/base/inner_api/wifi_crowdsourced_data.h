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

#ifndef WIFI_CROWDSOURCED_DATA_H
#define WIFI_CROWDSOURCED_DATA_H

#include "wifi_scan_msg.h"

namespace OHOS {
namespace Wifi {

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

struct ConnectEventTimeInfo {
    time_t timepConnStart;
    time_t timepDhcpSuc;
    time_t timepDisconnSuc;
    int32_t timeToDuraConn;
    int32_t timeToSucConn;
    ConnectEventTimeInfo()
    {
        timepConnStart = std::time(nullptr);
        timepDhcpSuc = 0;
        timepDisconnSuc = 0;
        timeToDuraConn = -1;
        timeToSucConn = -1;
    }
};

struct WifiCrowdsourcedDetailInfo {
    ConnReportReason reason;
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
    int channelWidth; // curr ap channel width
    int8_t isPortal;
    int8_t isMloConnected;
    int8_t isApHome;
    int8_t apScenne;
    int8_t isHiddenSSID;
    int8_t apSamefreq;
    int8_t apAdjafreq;
    int32_t timeToDuraConn;
    int32_t timeToSucConn;
    WifiCrowdsourcedDetailInfo()
    {
        reason = ConnReportReason::CONN_INIT;
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
        channelWidth = -1;
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

struct WifiCrowdsourcedQoeInfo {
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
    WifiCrowdsourcedQoeInfo()
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

struct WifiCrowdsourcedInfo {
    WifiCrowdsourcedDetailInfo apDetailInfo;
    WifiCrowdsourcedQoeInfo apQoeInfo;
    WifiCrowdsourcedInfo()
    {
        WifiCrowdsourcedDetailInfo();
        WifiCrowdsourcedQoeInfo();
    }
};

}  // namespace Wifi
}  // namespace OHOS
#endif