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

#include "scan_chr.h"
#include "wifi_logger.h"
#include "wifi_common_util.h"
#include "wifi_channel_helper.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiScanChr");

WifiScanChr::WifiScanChr()
{
    WIFI_LOGI("%{public}s enter", __FUNCTION__);
    Init();
}

WifiScanChr::~WifiScanChr()
{
    WIFI_LOGI("%{public}s exit", __FUNCTION__);
    Exit();
}

WifiScanChr &WifiScanChr::GetInstance()
{
    static WifiScanChr instance;
    return instance;
}

void WifiScanChr::Init()
{
    WIFI_LOGI("%{public}s enter", __FUNCTION__);
    if (scanChrThread_) {
        WIFI_LOGW("scanChrThread_ already initialized");
        return;
    }
    scanChrThread_ =  std::make_unique<WifiEventHandler>("scanChrThread");
    if (!scanChrThread_) {
        WIFI_LOGE("Failed to create scanChrThread_");
        return;
    }
    func_ = std::bind([this]() { this->WriteScanChrStatisticData(); });
    scanChrThread_->PostAsyncTask(func_, SCAN_CHR_DELAY_TIME);
}

void WifiScanChr::Exit()
{
    WIFI_LOGI("%{public}s exit", __FUNCTION__);
    if (scanChrThread_) {
        scanChrThread_.reset();
    }
    ClearScanChrHistoryData();
}

void WifiScanChr::RecordScanChrCountInfo(const WifiHalScanParam &runningScanSettings,
    const ScanStatusReport &scanStatusReport)
{
    ChannelsTable channelsTable;
    WifiChannelHelper::GetInstance().GetValidChannels(channelsTable);
    if (runningScanSettings.scanFreqs.empty() || runningScanSettings.scanFreqs.size() ==
        (channelsTable[BandType::BAND_2GHZ].size() + channelsTable[BandType::BAND_5GHZ].size())) {
        if (runningScanSettings.scanStyle == SCAN_TYPE_LOW_PRIORITY) {
            WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::FC_LP_SCAN_CNT);
            WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::FC_LP_SCAN_AP_CNT,
                scanStatusReport.scanInfoList.size());
        } else if (runningScanSettings.scanStyle == SCAN_DEFAULT_TYPE) {
            WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::FC_SCAN_CNT);
            WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::FC_SCAN_AP_CNT,
                scanStatusReport.scanInfoList.size());
        } else {
            WIFI_LOGE("RecordScanChrCountInfo: unsupported scanStyle=%{public}d", runningScanSettings.scanStyle);
        }
    } else {
        if (runningScanSettings.scanStyle == SCAN_TYPE_LOW_PRIORITY) {
            WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::NFC_LP_SCAN_CNT);
            WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::NFC_LP_SCAN_CHANNEL_CNT,
                runningScanSettings.scanFreqs.size());
            WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::NFC_LP_SCAN_AP_CNT,
                scanStatusReport.scanInfoList.size());
        } else if (runningScanSettings.scanStyle == SCAN_DEFAULT_TYPE) {
            WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::NFC_SCAN_CNT);
            WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::NFC_SCAN_CHANNEL_CNT,
                runningScanSettings.scanFreqs.size());
            WifiScanChr::GetInstance().RecordScanChrCommonInfo(ScanChrParam::NFC_SCAN_AP_CNT,
                scanStatusReport.scanInfoList.size());
        } else {
            WIFI_LOGE("RecordScanChrCountInfo: unsupported scanStyle=%{public}d", runningScanSettings.scanStyle);
        }
    }
}

void WifiScanChr::RecordScanChrCommonInfo(ScanChrParam scanChrParam, uint32_t statisticValue)
{
    std::unique_lock<std::mutex> lock(scanChrLimitInfoMutex_);
    if (g_scanParamMap.count(scanChrParam) > 0) {
        scanInfo_.*g_scanParamMap.at(scanChrParam) += statisticValue;
    } else {
        WIFI_LOGE("%{public}s: Invalid scanChrParam.", __FUNCTION__);
    }
}

void WifiScanChr::RecordScanChrLimitInfo(const WifiScanDeviceInfo &wifiScanDeviceInfo,
    const ScanLimitType &scanLimitType)
{
    std::unique_lock<std::mutex> lock(scanChrLimitInfoMutex_);
    std::string scanInitiator = "";
    bool isForeground = false;
    switch (wifiScanDeviceInfo.scanType) {
        case ScanType::SCAN_DEFAULT:
            break;
        case ScanType::SCAN_TYPE_EXTERN:
        case ScanType::SCAN_TYPE_NATIVE_EXTERN:
            scanInitiator = wifiScanDeviceInfo.packageName.empty() ?
                std::to_string(wifiScanDeviceInfo.initiatorUid) : wifiScanDeviceInfo.packageName;
            isForeground = ((wifiScanDeviceInfo.scanMode == ScanMode::APP_FOREGROUND_SCAN) ||
                (wifiScanDeviceInfo.scanMode == ScanMode::SYS_FOREGROUND_SCAN));
            break;
        case ScanType::SCAN_TYPE_SYSTEMTIMER:
            scanInitiator = "SYSTEM_SCAN";
            break;
        case ScanType::SCAN_TYPE_PNO:
            scanInitiator = "PNO_SCAN";
            break;
        case ScanType::SCAN_TYPE_WIFIPRO:
            scanInitiator = "WIFIPRO_SCAN";
            break;
        case ScanType::SCAN_TYPE_5G_AP:
            scanInitiator = "5G_AP_SCAN";
            break;
        default:
            break;
    }
    WriteScanLimitHiSysEvent(scanInitiator, static_cast<int>(scanLimitType), isForeground);
}

void WifiScanChr::WriteScanChrStatisticData()
{
    WIFI_LOGI("%{public}s enter", __FUNCTION__);
    WriteWifiScanInfoHiSysEvent(scanInfo_);
    ClearScanChrHistoryData();
    scanChrThread_->PostAsyncTask(func_, SCAN_CHR_DELAY_TIME);
}

void WifiScanChr::ClearScanChrHistoryData()
{
    if (memset_s(&scanInfo_, sizeof(ScanStatisticInfo), 0, sizeof(ScanStatisticInfo)) != EOK) {
        WIFI_LOGE("ClearHistoryScanChrData fail.");
    }
}

}
}
