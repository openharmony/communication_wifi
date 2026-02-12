/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
#include <mutex>
#include "wifi_hisysevent.h"
#include "wifi_scan_control_msg.h"
#include "wifi_config_center.h"
#include "wifi_event_handler.h"
#include "wifi_native_struct.h"
#include "scan_common.h"

namespace OHOS {
namespace Wifi {
const int64_t SCAN_CHR_DELAY_TIME = 10 * 1000; // ms

enum class ScanChrParam {
    FC_LP_SCAN_CNT, /* Count of full-channel LP scan */
    FC_LP_SCAN_AP_CNT, /* Count of APs detected by full-channel LP scan */
    NFC_LP_SCAN_CNT, /* Count of non-full-channel LP scan */
    NFC_LP_SCAN_CHANNEL_CNT, /* Count of channels for non-full-channel LP scan */
    NFC_LP_SCAN_AP_CNT, /* Count of APs detected by non-full-channel LP scan */
    FC_SCAN_CNT, /* Count of full-channel scan */
    FC_SCAN_AP_CNT, /* Count of APs detected by full-channel scan */
    NFC_SCAN_CNT, /* Count of non-full-channel scan */
    NFC_SCAN_CHANNEL_CNT, /* Count of channels for non-full-channel scan */
    NFC_SCAN_AP_CNT, /* Count of APs detected by non-full-channel scan */
    LP_SCAN_UNCTRL_CNT, /* Count of LP scan control bypasses in screen projection and gaming scenarios */
    LP_SCAN_AP_SWT_CNT, /* Count of WiFi handovers triggered by LP scan results */
    SCAN_AP_SWT_CNT, /* Count of WiFi handovers triggered by scan results */
    LP_SCAN_ABORT_CNT, /* Count of LP scan rejected by the driver */
};

const std::map<ScanChrParam, uint32_t ScanStatisticInfo::*> g_scanParamMap = {
    { ScanChrParam::FC_LP_SCAN_CNT, &ScanStatisticInfo::fcLpScanCnt },
    { ScanChrParam::FC_LP_SCAN_AP_CNT, &ScanStatisticInfo::fcLpScanApCnt },
    { ScanChrParam::NFC_LP_SCAN_CNT, &ScanStatisticInfo::nfcLpScanCnt },
    { ScanChrParam::NFC_LP_SCAN_CHANNEL_CNT, &ScanStatisticInfo::nfcLpScanChannelCnt },
    { ScanChrParam::NFC_LP_SCAN_AP_CNT, &ScanStatisticInfo::nfcLpScanApCnt },
    { ScanChrParam::FC_SCAN_CNT, &ScanStatisticInfo::fcScanCnt },
    { ScanChrParam::FC_SCAN_AP_CNT, &ScanStatisticInfo::fcScanApCnt },
    { ScanChrParam::NFC_SCAN_CNT, &ScanStatisticInfo::nfcScanCnt },
    { ScanChrParam::NFC_SCAN_CHANNEL_CNT, &ScanStatisticInfo::nfcScanChannelCnt },
    { ScanChrParam::NFC_SCAN_AP_CNT, &ScanStatisticInfo::nfcScanApCnt },
    { ScanChrParam::LP_SCAN_UNCTRL_CNT, &ScanStatisticInfo::lpScanUnctrlCnt },
    { ScanChrParam::LP_SCAN_AP_SWT_CNT, &ScanStatisticInfo::lpScanApSwtCnt },
    { ScanChrParam::SCAN_AP_SWT_CNT, &ScanStatisticInfo::scanApSwtCnt },
    { ScanChrParam::LP_SCAN_ABORT_CNT, &ScanStatisticInfo::lpScanAbortCnt },
};

class WifiScanChr {
public:
    WifiScanChr();
    ~WifiScanChr();
    void Init();
    void Exit();
    static WifiScanChr &GetInstance();
    void RecordScanChrCountInfo(const WifiHalScanParam &scanParam);
    void RecordScanChrApCountInfo(const WifiHalScanParam &runningScanSettings,
        const ScanStatusReport &scanStatusReport);
    void RecordScanChrCommonInfo(ScanChrParam scanChrParam, uint32_t statisticValue = 1);
    void RecordScanChrLimitInfo(const WifiScanDeviceInfo &wifiScanDeviceInfo,
        const ScanLimitType &scanLimitType);

private:
    void WriteScanChrStatisticData();
    void ClearScanChrHistoryData();

private:
    ScanStatisticInfo scanInfo_;
    std::unique_ptr<WifiEventHandler> scanChrThread_ = nullptr;
    std::function<void()> func_ = nullptr;
    std::mutex scanChrCommonInfoMutex_;
    std::mutex scanChrLimitInfoMutex_;
};

}
}

#endif