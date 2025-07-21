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
const int64_t ONE_DAY_TIME = 24 * 60 * 60 * 1000;
const int64_t TIME_LEVEL1_CNT = 3000;
const int64_t TIME_LEVEL2_CNT = 5000;
const int64_t TIME_START_TO_CONNECT_LEVEL1_CNT = 1000;
const int64_t TIME_START_TO_CONNECT_LEVEL2_CNT = 1500;
const int64_t TIME_CONNECT_TO_SUCC_LEVEL1_CNT = 2000;
const int64_t TIME_CONNECT_TO_SUCC_LEVEL2_CNT = 3500;
const int64_t USE_1000 = 1000;

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
    fastScanCnt_ = 0;
    fullScanCnt_ = 0;
    poorLinkCnt_ = 0;
    noNetCnt_ = 0;
    qoeSlowCnt_ = 0;
    reasonNotSwitchCnt_.clear();
    selectNetResultCnt_.clear();
    wifiProResultCnt_.clear();
    wifiProSwitchTimeCnt_.clear();
}

void WifiProChr::RecordScanChrCnt(std::string eventName)
{
    if (eventName == CHR_EVENT_WIFIPRO_FAST_SCAN_CNT) {
        fastScanCnt_++;
    } else if (eventName == CHR_EVENT_WIFIPRO_FULL_SCAN_CNT) {
        fullScanCnt_++;
    }
}

void WifiProChr::RecordSelectNetChrCnt(bool isSuccess)
{
    WIFI_LOGI("RecordSelectNetChrCnt, isSuccess : %{public}d, switchReason_ : %{public}d, ",
        isSuccess, static_cast<int>(switchReason_));
    if (isSuccess) {
        if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_NO_INTERNET) {
            selectNetResultCnt_[WifiProEventResult::NONET_SUCC]++;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_APP_QOE_SLOW) {
            selectNetResultCnt_[WifiProEventResult::QOE_SUCCC]++;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_POOR_RSSI) {
            selectNetResultCnt_[WifiProEventResult::POORLINK_SUCC]++;
        }
    } else {
        if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_NO_INTERNET) {
            selectNetResultCnt_[WifiProEventResult::NONET_FAILED]++;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_APP_QOE_SLOW) {
            selectNetResultCnt_[WifiProEventResult::QOESLOW_FAILED]++;
        } else if (switchReason_ == WifiSwitchReason::WIFI_SWITCH_REASON_POOR_RSSI) {
            selectNetResultCnt_[WifiProEventResult::POORLINK_FAILED]++;
        }
    }
}

void WifiProChr::RecordSwitchChrCnt(bool isSuccess)
{
    WIFI_LOGI("RecordSwitchChrCnt, isSuccess : %{public}d, switchReason_ : %{public}d, ",
        isSuccess, static_cast<int>(switchReason_));
    if (isSuccess) {
        switch (switchReason_) {
            case WifiSwitchReason::WIFI_SWITCH_REASON_NO_INTERNET:
                wifiProResultCnt_[WifiProEventResult::NONET_SUCC]++;
                break;
            case WifiSwitchReason::WIFI_SWITCH_REASON_APP_QOE_SLOW:
                wifiProResultCnt_[WifiProEventResult::QOE_SUCCC]++;
                break;
            case WifiSwitchReason::WIFI_SWITCH_REASON_POOR_RSSI:
                wifiProResultCnt_[WifiProEventResult::POORLINK_SUCC]++;
                break;
            default:
                break;
        }
    } else {
        switch (switchReason_) {
            case WifiSwitchReason::WIFI_SWITCH_REASON_NO_INTERNET:
                wifiProResultCnt_[WifiProEventResult::NONET_FAILED]++;
                break;
            case WifiSwitchReason::WIFI_SWITCH_REASON_APP_QOE_SLOW:
                wifiProResultCnt_[WifiProEventResult::QOESLOW_FAILED]++;
                break;
            case WifiSwitchReason::WIFI_SWITCH_REASON_POOR_RSSI:
                wifiProResultCnt_[WifiProEventResult::POORLINK_FAILED]++;
                break;
            default:
                break;
        }
    }
    switchReason_ = WifiSwitchReason::WIFI_SWITCH_REASON_DEFAULT;
}

void WifiProChr::RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt time)
{
    WIFI_LOGI("RecordSwitchTimeChrCnt");
    if (wifiProSwitchTimeCnt_.count(time) == 0) {
        wifiProSwitchTimeCnt_.insert(std::make_pair(time, 0));
    } else {
        wifiProSwitchTimeCnt_[time]++;
    }
}

void WifiProChr::RecordReasonNotSwitchChrCnt(ReasonNotSwitch reason)
{
    WIFI_LOGD("RecordReasonNotSwitchChrCnt");
    if (reasonNotSwitchCnt_.count(reason) == 0) {
        reasonNotSwitchCnt_.insert(std::make_pair(reason, 0));
    } else {
        reasonNotSwitchCnt_[reason]++;
    }
}

void WifiProChr::RecordWifiProStartTime(WifiSwitchReason reason)
{
    WIFI_LOGD("RecordWifiProStartTime");
    wifiProStartTime_ = GetElapsedMicrosecondsSinceBoot() / USE_1000;
    switchReason_ = reason;
}

void WifiProChr::RecordWifiProConnectTime()
{
    WIFI_LOGD("RecordWifiProConnectTime");
    wifiProSumTime_ = GetElapsedMicrosecondsSinceBoot() / USE_1000 - wifiProStartTime_;
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
    WIFI_LOGD("RecordWifiProSwitchSuccTime");
    int64_t wifiProConnectToSucc = GetElapsedMicrosecondsSinceBoot() / USE_1000 - wifiProStartTime_ - wifiProSumTime_;
    if (wifiProConnectToSucc < TIME_CONNECT_TO_SUCC_LEVEL1_CNT) {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::CONNECT_TO_SUCC_LEVEL1);
    } else if (wifiProConnectToSucc < TIME_CONNECT_TO_SUCC_LEVEL2_CNT) {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::CONNECT_TO_SUCC_LEVEL2);
    } else {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::CONNECT_TO_SUCC_LEVEL3);
    }

    wifiProSumTime_ = GetElapsedMicrosecondsSinceBoot() / USE_1000 - wifiProStartTime_;
    if (wifiProSumTime_ < TIME_LEVEL1_CNT) {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::SWITCH_TIME_LEVEL1);
    } else if (wifiProSumTime_ < TIME_LEVEL2_CNT) {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::SWITCH_TIME_LEVEL2);
    } else {
        RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt::SWITCH_TIME_LEVEL3);
    }
}

void WifiProChr::RecordCountWiFiPro(bool isValid)
{
    WIFI_LOGD("RecordCountWiFiPro, isValid : %{public}d, switchReason_ : %{public}d",
        isValid, static_cast<int>(switchReason_));
    if (isValid) {
        switch (switchReason_) {
            case WifiSwitchReason::WIFI_SWITCH_REASON_NO_INTERNET:
                noNetCnt_++;
                break;
            case WifiSwitchReason::WIFI_SWITCH_REASON_APP_QOE_SLOW:
                qoeSlowCnt_++;
                break;
            case WifiSwitchReason::WIFI_SWITCH_REASON_POOR_RSSI:
                poorLinkCnt_++;
                break;
            default:
                break;
        }
    } else {
        switch (switchReason_) {
            case WifiSwitchReason::WIFI_SWITCH_REASON_NO_INTERNET:
                noNetCnt_--;
                break;
            case WifiSwitchReason::WIFI_SWITCH_REASON_APP_QOE_SLOW:
                qoeSlowCnt_--;
                break;
            case WifiSwitchReason::WIFI_SWITCH_REASON_POOR_RSSI:
                poorLinkCnt_--;
                break;
            default:
                break;
        }
    }
    if (lastLoadTime_ == 0 || GetElapsedMicrosecondsSinceBoot() / USE_1000 - lastLoadTime_ > ONE_DAY_TIME) {
        lastLoadTime_ = GetElapsedMicrosecondsSinceBoot() / USE_1000;
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
    root["FAST_SCAN_CNT"] = fastScanCnt_;
    root["FULL_SCAN_CNT"] = fullScanCnt_;
    root["WIFIPRO_POOR_LINK_CNT"] = poorLinkCnt_;
    root["WIFIPRO_NONET_CNT"] = noNetCnt_;
    root["WIFIPRO_QOE_SLOW_CNT"] = qoeSlowCnt_;
    root["POOR_LINK_SELECT_NET_SUCC_CNT"] = selectNetResultCnt_[WifiProEventResult::POORLINK_SUCC];
    root["NONET_SELECT_NET_SUCC_CNT"] = selectNetResultCnt_[WifiProEventResult::NONET_SUCC];
    root["QOE_SLOW_SELECT_NET_SUCC_CNT"] = selectNetResultCnt_[WifiProEventResult::QOE_SUCCC];
    root["POOR_LINK_SELECT_NET_FAILED_CNT"] = selectNetResultCnt_[WifiProEventResult::POORLINK_FAILED];
    root["NONET_SELECT_NET_FAILED_CNT"] = selectNetResultCnt_[WifiProEventResult::NONET_FAILED];
    root["QOE_SLOW_SELECT_NET_FAILED_CNT"] = selectNetResultCnt_[WifiProEventResult::QOESLOW_FAILED];
    root["POOR_LINK_SWITCH_SUCC_CNT"] = wifiProResultCnt_[WifiProEventResult::POORLINK_SUCC];
    root["NONET_SWITCH_SUCC_CNT"] = wifiProResultCnt_[WifiProEventResult::NONET_SUCC];
    root["QOE_SLOW_SWITCH_SUCC_CNT"] = wifiProResultCnt_[WifiProEventResult::QOE_SUCCC];
    root["POOR_LINK_SWITCH_FAILED_CNT"] = wifiProResultCnt_[WifiProEventResult::POORLINK_FAILED];
    root["NONET_SWITCH_FAILED_CNT"] = wifiProResultCnt_[WifiProEventResult::NONET_FAILED];
    root["QOE_SLOW_SWITCH_FAILED_CNT"] = wifiProResultCnt_[WifiProEventResult::QOESLOW_FAILED];
    root["TIME_LEVEL1_CNT"] = wifiProSwitchTimeCnt_[SWITCH_TIME_LEVEL1];
    root["TIME_LEVEL2_CNT"] = wifiProSwitchTimeCnt_[SWITCH_TIME_LEVEL2];
    root["TIME_LEVEL3_CNT"] = wifiProSwitchTimeCnt_[SWITCH_TIME_LEVEL3];
    root["TIME_START_TO_CONNECT_LEVEL1_CNT"] = wifiProSwitchTimeCnt_[START_TO_CONNECT_LEVEL1];
    root["TIME_START_TO_CONNECT_LEVEL2_CNT"] = wifiProSwitchTimeCnt_[START_TO_CONNECT_LEVEL2];
    root["TIME_START_TO_CONNECT_LEVEL3_CNT"] = wifiProSwitchTimeCnt_[START_TO_CONNECT_LEVEL3];
    root["TIME_CONNECT_TO_SUCC_LEVEL1_CNT"] = wifiProSwitchTimeCnt_[CONNECT_TO_SUCC_LEVEL1];
    root["TIME_CONNECT_TO_SUCC_LEVEL2_CNT"] = wifiProSwitchTimeCnt_[CONNECT_TO_SUCC_LEVEL2];
    root["TIME_CONNECT_TO_SUCC_LEVEL3_CNT"] = wifiProSwitchTimeCnt_[CONNECT_TO_SUCC_LEVEL3];
    root["REASON_NOT_SWTICH_SWITCHING"] = reasonNotSwitchCnt_[ReasonNotSwitch::WIFIPRO_SWITCHING];
    root["REASON_NOT_SWTICH_SELFCURING"] = reasonNotSwitchCnt_[ReasonNotSwitch::WIFIPRO_SELFCURING];
    root["REASON_NOT_SWTICH_NONET_BEFORE"] = reasonNotSwitchCnt_[ReasonNotSwitch::WIFIPRO_NONET_BEFORE_CONNECT];
    root["REASON_NOT_SWTICH_SIGNAL_BRIDGE"] = reasonNotSwitchCnt_[ReasonNotSwitch::WIFIPRO_SIGNAL_BRIDGE_ON];
    root["REASON_NOT_SWTICH_AP_STA_ON"] = reasonNotSwitchCnt_[ReasonNotSwitch::WIFIPRO_AP_STA_ON];
    root["REASON_NOT_SWTICH_APP_WLISTS"] = reasonNotSwitchCnt_[ReasonNotSwitch::WIFIPRO_APP_WHITE_LISTS];
    root["REASON_NOT_SWTICH_ISCALLING"] = reasonNotSwitchCnt_[ReasonNotSwitch::WIFIPRO_ISCALLING];
    root["REASON_NOT_SWTICH_NOT_AUTOSWITCH"] = reasonNotSwitchCnt_[ReasonNotSwitch::WIFIPRO_NOT_ALLOW_AUTOSWITCH];
    root["REASON_NOT_SWTICH_DISABLED"] = reasonNotSwitchCnt_[ReasonNotSwitch::WIFIPRO_DISABLED];
    WriteEvent("WIFI_CHR_EVENT", "EVENT_NAME", "WIFI_PRO_STATISTICS", "EVENT_VALUE", writer.write(root));
}
}  // namespace Wifi
}  // namespace OHOS