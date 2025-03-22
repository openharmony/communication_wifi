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

#ifndef OHOS_WIFI_PRO_CHR_H
#define OHOS_WIFI_PRO_CHR_H
#include <string>
#include <iostream>
#include <map>
#include "wifi_logger.h"
#include "wifi_pro_common.h"
#include "wifi_msg.h"
#include "wifi_event_handler.h"
namespace OHOS {
namespace Wifi {

inline const std::string CHR_EVENT_WIFIPRO_FAST_SCAN_CNT = "FAST_SCAN_CNT";
inline const std::string CHR_EVENT_WIFIPRO_FULL_SCAN_CNT = "FULL_SCAN_CNT";

enum WifiProSwitchTimeCnt {
    SWITCH_TIME_LEVEL1 = 0,                         // less 3000ms
    SWITCH_TIME_LEVEL2,                         // 3000ms - 5000ms
    SWITCH_TIME_LEVEL3,                         // over 5000ms
    START_TO_CONNECT_LEVEL1,                    // less 1000ms
    START_TO_CONNECT_LEVEL2,                    // 1000ms - 1500ms
    START_TO_CONNECT_LEVEL3,                    // over 1500ms
    CONNECT_TO_SUCC_LEVEL1,                     // less 2000ms
    CONNECT_TO_SUCC_LEVEL2,                     // 2000ms - 3500ms
    CONNECT_TO_SUCC_LEVEL3,                     // over 3500ms
};

enum WifiProEventResult {
    POORLINK_SUCC = 0,
    NONET_SUCC,
    QOE_SUCCC,
    POORLINK_FAILED,
    NONET_FAILED,
    QOESLOW_FAILED,
};

enum ReasonNotSwitch {
    WIFIPRO_SWITCHING = 0,
    WIFIPRO_SELFCURING,
    WIFIPRO_NONET_BEFORE_CONNECT,
    WIFIPRO_SIGNAL_BRIDGE_ON,
    WIFIPRO_AP_STA_ON,
    WIFIPRO_APP_WHITE_LISTS,
    WIFIPRO_ISCALLING,
    WIFIPRO_NOT_ALLOW_AUTOSWITCH,
    WIFIPRO_DISABLED,
};

class WifiProChr {
    WifiProChr();
    ~WifiProChr();

public:
    static WifiProChr &GetInstance();
    void RecordScanChrCnt(std::string eventName);
    void RecordSelectNetChrCnt(bool isSuccess);
    void RecordSwitchChrCnt(bool isSuccess);
    void RecordSwitchTimeChrCnt(WifiProSwitchTimeCnt time);
    void RecordReasonNotSwitchChrCnt(ReasonNotSwitch reason);
    void ResetChrRecord();
    void RecordWifiProStartTime(WifiSwitchReason reason);
    void RecordWifiProConnectTime();
    void RecordWifiProSwitchSuccTime();
    void RecordCountWiFiPro(bool isValid);
    void WriteWifiProSysEvent();

private:
    int64_t wifiProStartTime_ = 0;
    int64_t wifiProSumTime_ = 0;
    int64_t lastLoadTime_ = 0;
    WifiSwitchReason switchReason_ = WifiSwitchReason::WIFI_SWITCH_REASON_DEFAULT;
    int32_t fastScanCnt_ = 0;
    int32_t fullScanCnt_ = 0;
    int32_t poorLinkCnt_ = 0;
    int32_t noNetCnt_ = 0;
    int32_t qoeSlowCnt_ = 0;
    std::map<ReasonNotSwitch, int32_t> reasonNotSwitchCnt_ = {};
    std::map<WifiProEventResult, int32_t> selectNetResultCnt_ = {};
    std::map<WifiProEventResult, int32_t> wifiProResultCnt_ = {};
    std::map<WifiProSwitchTimeCnt, int32_t> wifiProSwitchTimeCnt_ = {};
};
}  // namespace Wifi
}  // namespace OHOS
#endif