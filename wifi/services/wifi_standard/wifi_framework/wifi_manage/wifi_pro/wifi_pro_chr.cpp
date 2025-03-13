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

#include "wifi_pro_chr.h"
#include "wifi_common_util.h"
#include "wifi_config_center.h"
#include "wifi_settings.h"
#include "wifi_hisysevent.h"
#include "hisysevent.h"
#include "json/json.h"
namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiProChr");
const int64_t ONE_DAY_TIME = 20;
const int32_t TIME_LEVEL1_CNT = 3000;
const int32_t TIME_LEVEL2_CNT = 5000;
const int32_t TIME_START_TO_CONNECT_LEVEL1_CNT = 1000;
const int32_t TIME_START_TO_CONNECT_LEVEL2_CNT = 1500;
const int32_t TIME_CONNECT_TO_SUCC_LEVEL1_CNT = 2000;
const int32_t TIME_CONNECT_TO_SUCC_LEVEL2_CNT = 3500;

int32_t g_fastScanCnt = 0;
int32_t g_fullScanCnt = 0;
int32_t g_poorLinkCnt = 0;
int32_t g_noNetCnt = 0;
int32_t g_qoeSlowCnt = 0;
std::map<ReasonNotSwitch, int32_t> g_ReasonNotSwitchCnt = {};
std::map<WifiProEventResult, int32_t> g_SelectNetResultCnt = {};
std::map<WifiProEventResult, int32_t> g_WifiProResultCnt = {};
std::map<WifiProSwitchTimeCnt, int32_t> g_WifiProSwitchTimeCnt = {};

template<typename... Types>
static void WriteEvent(const std::string& eventType, Types... args)
{
    int ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::COMMUNICATION, eventType,
        HiviewDFX::HiSysEvent::EventType::STATISTIC, args...);
    if (ret != 0) {
        WIFI_LOGE("Write event fail: %{public}s", eventType.c_str());
    }
}

WifiProChr &WifiProChr::GetInstance()
{
    static WifiProChr gWifiProChr;
    return gWifiProChr;
}

WifiProChr::WifiProChr()
{
    WIFI_LOGI("Enter WifiProChr");
    ResetChrRecord();
}

WifiProChr::~WifiProChr()
{
    WIFI_LOGI("Enter ~WifiProChr");
    ResetChrRecord();
}

void WifiProChr::ResetChrRecord()
{
    WIFI_LOGI("Enter ResetChrRecord");
    g_fastScanCnt = 0;
    g_fullScanCnt = 0;
    g_poorLinkCnt = 0;
    g_noNetCnt = 0;
    g_qoeSlowCnt = 0;
    std::map<ReasonNotSwitch, int32_t> reasonNotSwitchEmptyMap = {};
    g_ReasonNotSwitchCnt.swap(reasonNotSwitchEmptyMap);

    std::map<WifiProEventResult, int32_t> selectNetResultEmptyMap = {};
    g_SelectNetResultCnt.swap(selectNetResultEmptyMap);

    std::map<WifiProEventResult, int32_t> wifiProResultEmptyMap = {};
    g_WifiProResultCnt.swap(wifiProResultEmptyMap);

    std::map<WifiProSwitchTimeCnt, int32_t> wifiProSwitchTimeEmptyMap = {};
    g_WifiProSwitchTimeCnt.swap(wifiProSwitchTimeEmptyMap);
}

void WifiProChr::RecordScanChrCnt(std::string eventName)
{
    if (eventName == CHR_EVENT_WIFIPRO_FAST_SCAN_CNT) {
        g_fastScanCnt++;
    } else if (eventName == CHR_EVENT_WIFIPRO_FULL_SCAN_CNT) {
        g_fullScanCnt++;
    }
}

void WifiProChr::RecordSelectNetChrCnt(bool isSuccess)
{
    WIFI_LOGI("RecordSelectNetChrCnt, isSuccess : %{public}d, switchReason_ : %{public}d, ",
        isSuccess, static_cast<int>(switchReason_));
    if (isSuccess) {
        if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_NO_INTERNET) {
            g_SelectNetResultCnt[WifiProEventResult::NONET_SUCC]++;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_APP_QOE_SLOW) {
            g_SelectNetResultCnt[WifiProEventResult::QOE_SUCCC]++;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_POOR_RSSI) {
            g_SelectNetResultCnt[WifiProEventResult::POORLINK_SUCC]++;
        }
    } else {
        if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_NO_INTERNET) {
            g_SelectNetResultCnt[WifiProEventResult::NONET_FAILED]++;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_APP_QOE_SLOW) {
            g_SelectNetResultCnt[WifiProEventResult::QOESLOW_FAILED]++;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_POOR_RSSI) {
            g_SelectNetResultCnt[WifiProEventResult::POORLINK_FAILED]++;
        }
    }
}

void WifiProChr::RecordSwitchChrCnt(bool isSuccess)
{
    WIFI_LOGI("RecordSwitchChrCnt, isSuccess : %{public}d, switchReason_ : %{public}d, ",
        isSuccess, static_cast<int>(switchReason_));
    if (isSuccess) {
        if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_NO_INTERNET) {
            g_WifiProResultCnt[WifiProEventResult::NONET_SUCC]++;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_APP_QOE_SLOW) {
            g_WifiProResultCnt[WifiProEventResult::QOE_SUCCC]++;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_POOR_RSSI) {
            g_WifiProResultCnt[WifiProEventResult::POORLINK_SUCC]++;
        } else {
            return;
        }
        UpdateWifiProLinkedInfo();
    } else {
        if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_NO_INTERNET) {
            g_WifiProResultCnt[WifiProEventResult::NONET_FAILED]++;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_APP_QOE_SLOW) {
            g_WifiProResultCnt[WifiProEventResult::QOESLOW_FAILED]++;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_POOR_RSSI) {
            g_WifiProResultCnt[WifiProEventResult::POORLINK_FAILED]++;
        }
    }
    switchReason_ = WifiSwitchReason::WIFI_SWITCH_REASON_DEFAULT;
}

void WifiProChr::RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt time)
{
    WIFI_LOGI("RecordSwitchTimeChrCnt");
    if (g_WifiProSwitchTimeCnt.count(time) == 0) {
        g_WifiProSwitchTimeCnt.insert(std::make_pair(time, 0));
    } else {
        g_WifiProSwitchTimeCnt[time]++;
    }
}

void WifiProChr::RecordReasonNotSwitchChrCnt(ReasonNotSwitch reason)
{
    WIFI_LOGI("RecordReasonNotSwitchChrCnt");
    if (g_ReasonNotSwitchCnt.count(reason) == 0) {
        g_ReasonNotSwitchCnt.insert(std::make_pair(reason, 0));
    } else {
        g_ReasonNotSwitchCnt[reason]++;
    }
}

void WifiProChr::RecordWifiProStartTime(WifiSwitchReason reason)
{
    WIFI_LOGI("RecordWifiProStartTime");
    wifiProStartTime_ = GetElapsedMicrosecondsSinceBoot();
    switchReason_ = reason;
}

void WifiProChr::RecordWifiProConnectTime()
{
    WIFI_LOGI("RecordWifiProConnectTime");
    wifiProSumTime_ = GetElapsedMicrosecondsSinceBoot() - wifiProStartTime_;
    if (wifiProSumTime_ < TIME_START_TO_CONNECT_LEVEL1_CNT) {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::START_TO_CONNECT_LEVEL1);
    } else if (wifiProSumTime_ < TIME_START_TO_CONNECT_LEVEL2_CNT) {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::START_TO_CONNECT_LEVEL2);
    } else {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::START_TO_CONNECT_LEVEL3);
    }
}

void WifiProChr::RecordWifiProSwitchSuccTime()
{
    WIFI_LOGI("RecordWifiProSwitchSuccTime");
    int64_t wifiProConnectToSucc = GetElapsedMicrosecondsSinceBoot() - wifiProStartTime_ - wifiProSumTime_;
    if (wifiProConnectToSucc < TIME_CONNECT_TO_SUCC_LEVEL1_CNT) {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::CONNECT_TO_SUCC_LEVEL1);
    } else if (wifiProConnectToSucc < TIME_CONNECT_TO_SUCC_LEVEL2_CNT) {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::CONNECT_TO_SUCC_LEVEL2);
    } else {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::CONNECT_TO_SUCC_LEVEL3);
    }

    wifiProSumTime_ = GetElapsedMicrosecondsSinceBoot() - wifiProStartTime_;
    if (wifiProSumTime_ < TIME_LEVEL1_CNT) {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::SWITCH_TIME_LEVEL1);
    } else if (wifiProSumTime_ < TIME_LEVEL2_CNT) {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::SWITCH_TIME_LEVEL2);
    } else {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::SWITCH_TIME_LEVEL3);
    }
}

void WifiProChr::UpdateWifiProLinkedInfo()
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    WifiDeviceConfig configs;
    WifiSettings::GetInstance().GetDeviceConfig(linkedInfo.networkId, configs);
    wifiProConnectSsid_ = configs.ssid;
    wifiProConnectKeyMgmt_ = configs.keyMgmt;
    WIFI_LOGI("UpdateWifiProLinkedInfo, wifiProSuccFlag_ : %{public}s, wifiProConnectSsid_ : %{public}s, ",
        wifiProConnectSsid_.c_str(), wifiProConnectKeyMgmt_.c_str());
}

void WifiProChr::RecordCountWiFiPro(bool isValid)
{
    WIFI_LOGI("RecordCountWiFiPro, isValid : %{public}d, switchReason_ : %{public}d",
        isValid, static_cast<int>(switchReason_));
    if (isValid) {
        if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_NO_INTERNET) {
            g_noNetCnt++;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_APP_QOE_SLOW) {
            g_qoeSlowCnt++;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_POOR_RSSI) {
            g_poorLinkCnt++;
        }
    } else {
        if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_NO_INTERNET) {
            g_noNetCnt--;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_APP_QOE_SLOW) {
            g_qoeSlowCnt--;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_POOR_RSSI) {
            g_poorLinkCnt--;
        }
    }
    if (lastLoadTime_ == 0 || GetElapsedMicrosecondsSinceBoot() - lastLoadTime_ > ONE_DAY_TIME) {
        lastLoadTime_ = GetElapsedMicrosecondsSinceBoot();
        WriteWifiProSysEvent();
        ResetChrRecord();
        WIFI_LOGI("WifiProChr::WriteWifiProSysEvent success");
    }
}

void WifiProChr::WriteWifiProSysEvent()
{
    WIFI_LOGI("WriteWifiProSysEvent enter");
    Json::Value root;
    Json::FastWriter writer;
    root["FAST_SCAN_CNT"] = g_fastScanCnt;
    root["FULL_SCAN_CNT"] = g_fullScanCnt;
    root["WIFIPRO_POOR_LINK_CNT"] = g_poorLinkCnt;
    root["WIFIPRO_NONET_CNT"] = g_noNetCnt;
    root["WIFIPRO_QOE_SLOW_CNT"] = g_qoeSlowCnt;
    root["POOR_LINK_SELECT_NET_SUCC_CNT"] = g_SelectNetResultCnt[WifiProEventResult::POORLINK_SUCC];
    root["NONET_SELECT_NET_SUCC_CNT"] = g_SelectNetResultCnt[WifiProEventResult::NONET_SUCC];
    root["QOE_SLOW_SELECT_NET_SUCC_CNT"] = g_SelectNetResultCnt[WifiProEventResult::QOE_SUCCC];
    root["POOR_LINK_SELECT_NET_FAILED_CNT"] = g_SelectNetResultCnt[WifiProEventResult::POORLINK_FAILED];
    root["NONET_SELECT_NET_FAILED_CNT"] = g_SelectNetResultCnt[WifiProEventResult::NONET_FAILED];
    root["QOE_SLOW_SELECT_NET_FAILED_CNT"] = g_SelectNetResultCnt[WifiProEventResult::QOESLOW_FAILED];
    root["POOR_LINK_SWITCH_SUCC_CNT"] = g_WifiProResultCnt[WifiProEventResult::POORLINK_SUCC];
    root["NONET_SWITCH_SUCC_CNT"] = g_WifiProResultCnt[WifiProEventResult::NONET_SUCC];
    root["QOE_SLOW_SWITCH_SUCC_CNT"] = g_WifiProResultCnt[WifiProEventResult::QOE_SUCCC];
    root["POOR_LINK_SWITCH_FAILED_CNT"] = g_WifiProResultCnt[WifiProEventResult::POORLINK_FAILED];
    root["NONET_SWITCH_FAILED_CNT"] = g_WifiProResultCnt[WifiProEventResult::NONET_FAILED];
    root["QOE_SLOW_SWITCH_FAILED_CNT"] = g_WifiProResultCnt[WifiProEventResult::QOESLOW_FAILED];
    root["TIME_LEVEL1_CNT"] = g_WifiProSwitchTimeCnt[SWITCH_TIME_LEVEL1];
    root["TIME_LEVEL2_CNT"] = g_WifiProSwitchTimeCnt[SWITCH_TIME_LEVEL2];
    root["TIME_LEVEL3_CNT"] = g_WifiProSwitchTimeCnt[SWITCH_TIME_LEVEL3];
    root["TIME_START_TO_CONNECT_LEVEL1_CNT"] = g_WifiProSwitchTimeCnt[START_TO_CONNECT_LEVEL1];
    root["TIME_START_TO_CONNECT_LEVEL2_CNT"] = g_WifiProSwitchTimeCnt[START_TO_CONNECT_LEVEL2];
    root["TIME_START_TO_CONNECT_LEVEL3_CNT"] = g_WifiProSwitchTimeCnt[START_TO_CONNECT_LEVEL3];
    root["TIME_CONNECT_TO_SUCC_LEVEL1_CNT"] = g_WifiProSwitchTimeCnt[CONNECT_TO_SUCC_LEVEL1];
    root["TIME_CONNECT_TO_SUCC_LEVEL2_CNT"] = g_WifiProSwitchTimeCnt[CONNECT_TO_SUCC_LEVEL2];
    root["TIME_CONNECT_TO_SUCC_LEVEL3_CNT"] = g_WifiProSwitchTimeCnt[CONNECT_TO_SUCC_LEVEL3];
    root["REASON_NOT_SWTICH_SWITCHING"] = g_ReasonNotSwitchCnt[ReasonNotSwitch::WIFIPRO_SWITCHING];
    root["REASON_NOT_SWTICH_SELFCURING"] = g_ReasonNotSwitchCnt[ReasonNotSwitch::WIFIPRO_SELFCURING];
    root["REASON_NOT_SWTICH_NONET_BEFORE"] = g_ReasonNotSwitchCnt[ReasonNotSwitch::WIFIPRO_NONET_BEFORE_CONNECT];
    root["REASON_NOT_SWTICH_SIGNAL_BRIDGE"] = g_ReasonNotSwitchCnt[ReasonNotSwitch::WIFIPRO_SIGNAL_BRIDGE_ON];
    root["REASON_NOT_SWTICH_AP_STA_ON"] = g_ReasonNotSwitchCnt[ReasonNotSwitch::WIFIPRO_AP_STA_ON];
    root["REASON_NOT_SWTICH_APP_WLISTS"] = g_ReasonNotSwitchCnt[ReasonNotSwitch::WIFIPRO_APP_WHITE_LISTS];
    root["REASON_NOT_SWTICH_ISCALLING"] = g_ReasonNotSwitchCnt[ReasonNotSwitch::WIFIPRO_ISCALLING];
    root["REASON_NOT_SWTICH_NOT_AUTOSWITCH"] = g_ReasonNotSwitchCnt[ReasonNotSwitch::WIFIPRO_NOT_ALLOW_AUTOSWITCH];
    root["REASON_NOT_SWTICH_DISABLED"] = g_ReasonNotSwitchCnt[ReasonNotSwitch::WIFIPRO_DISABLED];
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_PRO_STATISTICS", "EVENT_VALUE", writer.write(root));
}
}  // namespace Wifi
}  // namespace OHOS