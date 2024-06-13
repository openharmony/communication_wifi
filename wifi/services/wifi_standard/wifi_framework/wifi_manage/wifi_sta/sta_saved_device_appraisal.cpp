/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "sta_saved_device_appraisal.h"
#include "wifi_logger.h"
#include "wifi_settings.h"
#include "wifi_common_util.h"

DEFINE_WIFILOG_LABEL("StaSavedDeviceAppraisal");

#define BINARY_CODE 0001
#define LAST_SELECTION_SCORE_DECAY_S 300
#define MAX(A, B) (((A) >= (B)) ? (A) : (B))
namespace OHOS {
namespace Wifi {
StaSavedDeviceAppraisal::StaSavedDeviceAppraisal(bool supportFmRoamingFlag, int instId)
    : signalScorePerLevel(WifiSettings::GetInstance().GetScoretacticsScoreSlope(instId)),
      signalBaseScore(WifiSettings::GetInstance().GetScoretacticsInitScore(instId)),
      sameBssidScore(WifiSettings::GetInstance().GetScoretacticsSameBssidScore(instId)),
      sameDeviceScore(WifiSettings::GetInstance().GetScoretacticsSameNetworkScore(instId)),
      frequency5GHzScore(WifiSettings::GetInstance().GetScoretacticsFrequency5GHzScore(instId)),
      userSelectedDeviceScore(WifiSettings::GetInstance().GetScoretacticsLastSelectionScore(instId)),
      safetyDeviceScore(WifiSettings::GetInstance().GetScoretacticsSecurityScore(instId)),
      normalDeviceScore(WifiSettings::GetInstance().GetScoretacticsNormalScore(instId)),
      firmwareRoamFlag(supportFmRoamingFlag),
      m_instId(instId)
{}
StaSavedDeviceAppraisal::~StaSavedDeviceAppraisal()
{
    WIFI_LOGI("Enter ~StaSavedDeviceAppraisal.\n");
}

ErrCode StaSavedDeviceAppraisal::DeviceAppraisals(
    WifiDeviceConfig &electedDevice, std::vector<InterScanInfo> &scanInfos, WifiLinkedInfo &info)
{
    WIFI_LOGD("Enter DeviceAppraisals.\n");
    int highestScore = 0;
    int sign = 0;
    InterScanInfo scanInfoElected;
    scanInfoElected.rssi = VALUE_LIMIT_MIN_RSSI;

    for (auto scanInfo : scanInfos) {
        WifiDeviceConfig device;
        std::string deviceKeyMgmt;
        scanInfo.GetDeviceMgmt(deviceKeyMgmt);
        if (WifiSettings::GetInstance().GetDeviceConfig(scanInfo.ssid, deviceKeyMgmt, device) != 0) {
            WIFI_LOGD("Skip unsaved ssid Network %{public}s.", SsidAnonymize(scanInfo.ssid).c_str());
            continue;
        }

        if (WhetherSkipDevice(device)) {
            continue;
        }

        int score = 0;
        AppraiseDeviceQuality(score, scanInfo, device, info, device.connFailedCount >= MAX_RETRY_COUNT);
        WIFI_LOGD("The device networkId:%{public}d ssid:%{public}s score:%{public}d rssi:%{public}d.",
            device.networkId, SsidAnonymize(scanInfo.ssid).c_str(), score, scanInfo.rssi);
        if (CheckHigherPriority(score, highestScore, scanInfo.rssi, scanInfoElected.rssi)) {
            highestScore = score;
            scanInfoElected.rssi = scanInfo.rssi;
            electedDevice = device;
            electedDevice.bssid = scanInfo.bssid;
            sign = 1;
            WIFI_LOGD("set highestScore: %{public}d, ssid: %{public}s", highestScore, SsidAnonymize(device.ssid).c_str());
        } else {
            WIFI_LOGD("The config %{public}s is ignored!\n", MacAnonymize(scanInfo.ssid).c_str());
        }
    }
    if (sign == 1) {
        WIFI_LOGI("DeviceAppraisals, networkId:%{public}d, ssid:%{public}s, bssid:%{public}s.",
            electedDevice.networkId, SsidAnonymize(electedDevice.ssid).c_str(),
            MacAnonymize(electedDevice.bssid).c_str());
        if (info.connState == ConnState::CONNECTED && electedDevice.networkId == info.networkId) {
            WifiDeviceConfig networkInfo;
            electedDevice = networkInfo;
            WIFI_LOGI("The electedDevice is the current connected device. Skip the device selection.");
            return WIFI_OPT_FAILED;
        } else {
            WIFI_LOGI("The device is selected successfully.\n");
            return WIFI_OPT_SUCCESS;
        }
    } else {
        WIFI_LOGI("Skip all scan results.\n");
        return WIFI_OPT_FAILED;
    }
}

bool StaSavedDeviceAppraisal::WhetherSkipDevice(WifiDeviceConfig &device)
{
    /* Skip this type of device and evaluate it by other appraisals */
    if (device.isPasspoint || device.isEphemeral) {
        WIFI_LOGI("Skip isPasspoint or isEphemeral Network %{public}s.", SsidAnonymize(device.ssid).c_str());
        return true;
    }

    if (device.status == static_cast<int>(WifiDeviceConfigStatus::DISABLED)) {
        WIFI_LOGI("Skip disabled Network %{public}s.", SsidAnonymize(device.ssid).c_str());
        return true;
    }
    std::string bssid = WifiSettings::GetInstance().GetConnectTimeoutBssid(m_instId);
    if (!bssid.empty() && bssid == device.bssid) {
        WIFI_LOGI("Skip the connect timeout Network %{public}s.", SsidAnonymize(device.ssid).c_str());
        return true;
    }
    return false;
}

void StaSavedDeviceAppraisal::AppraiseDeviceQuality(int &score, InterScanInfo &scanInfo,
    WifiDeviceConfig &device, WifiLinkedInfo &info, bool flip)
{
    WIFI_LOGD("Enter AppraiseDeviceQuality.\n");
    int rssi = scanInfo.rssi;
    /* Converts a signal to a grid number */
    int signalStrength = CalculateSignalBars(rssi, MAX_SIGNAL_BAR_NUM);
    /* Signal strength score */
    score += signalBaseScore + signalStrength * signalScorePerLevel;
    WIFI_LOGD("signalstrength score is %{public}d.\n", score);

    /* 5 GHz frequency band: bonus point */
    if (Whether5GDevice(scanInfo.frequency)) {
        score += frequency5GHzScore;
        WIFI_LOGD("5G score is %{public}d.\n", frequency5GHzScore);
    }

    /* normal device config: bonus point */
    if (device.uid == WIFI_INVALID_UID) {
        score += normalDeviceScore;
        WIFI_LOGD("normal score is %{public}d.\n", normalDeviceScore);
    }

    /* Bonus points for last user selection */
    int userLastSelectedNetworkId = WifiSettings::GetInstance().GetUserLastSelectedNetworkId(m_instId);
    if (userLastSelectedNetworkId != INVALID_NETWORK_ID && userLastSelectedNetworkId == device.networkId) {
        time_t userLastSelectedNetworkTimeVal = WifiSettings::GetInstance().GetUserLastSelectedNetworkTimeVal(m_instId);
        time_t now = time(0);
        time_t timeDifference = now - userLastSelectedNetworkTimeVal;
        /*
         * Basic score of the device selected by the user: 120.
         * One point is deducted from every 5 points since the time when the user
         * selects the device.
         */
        if (timeDifference > 0) {
            int decay = static_cast<int>(timeDifference / LAST_SELECTION_SCORE_DECAY_S);
            int bonus = MAX((userSelectedDeviceScore - decay), (0));
            score += bonus;
            WIFI_LOGI("lastselected score is %{public}d.\n", bonus);
        }
    }
    /*
     * If the current device is the same as the elected device, bonus points
     * are added.
     */
    if (info.detailedState == DetailedState::WORKING && scanInfo.ssid == info.ssid) {
        score += sameDeviceScore;
        WIFI_LOGI("samenetwork score is %{public}d.\n", sameDeviceScore);
        /*
         * When firmware roaming is supported, the same BSSID is added to different
         * BSSIDs.
         */
        if (firmwareRoamFlag && scanInfo.bssid != info.bssid) {
            score += sameBssidScore;
            WIFI_LOGI("roamingsupport score is %{public}d.\n", sameBssidScore);
        }
    }

    if (info.detailedState == DetailedState::WORKING && info.bssid == scanInfo.bssid) {
        score += sameBssidScore;
        WIFI_LOGI("SameBssid score is %{public}d.\n", sameBssidScore);
    }

    if (device.keyMgmt != "NONE" && device.keyMgmt.size() != 0) {
        score += safetyDeviceScore;
        WIFI_LOGI("security score is %{public}d.\n", safetyDeviceScore);
    }

    if (flip) { // lowest priority ssid, filp the score
        score = 0 - score;
    }
}

bool StaSavedDeviceAppraisal::Whether5GDevice(int frequency)
{
    if (frequency > MIN_5_FREQUENCY && frequency < MAX_5_FREQUENCY) {
        return true;
    } else {
        return false;
    }
}

int StaSavedDeviceAppraisal::CalculateSignalBars(int rssi, int signalBars)
{
    WIFI_LOGD("Enter CalculateSignalBars");
    if (rssi <= VALUE_LIMIT_MIN_RSSI) {
        return 0;
    } else if (rssi >= VALUE_LIMIT_MAX_RSSI) {
        return signalBars - 1;
    } else {
        float inputRange = (VALUE_LIMIT_MAX_RSSI - VALUE_LIMIT_MIN_RSSI);
        float outputRange = (signalBars - 1);
        return static_cast<int>(static_cast<float>(rssi - VALUE_LIMIT_MIN_RSSI) * outputRange / inputRange);
    }
}

bool StaSavedDeviceAppraisal::CheckHigherPriority(int score, int lastScore, int rssi, int selectedRssi)
{
    bool higerPriority = false;
    if (lastScore == 0) {
        higerPriority = true; // first higerPriority
    } else if (lastScore > 0) {
        higerPriority = score > lastScore || // compare score, if equal then compare rssi
            (score == lastScore && rssi > selectedRssi);
    } else {
        if (score >= 0) {
            higerPriority = true; // > 0 higher priority
        } else {
            higerPriority = score < lastScore || // both low priority then compare score
                (score == lastScore && rssi > selectedRssi);
        }
    }
    return higerPriority;
}
}  // namespace Wifi
}  // namespace OHOS