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

#include "wifi_sensor_scene.h"

#include <functional>
#include "net_all_capabilities.h"
#include "net_supplier_info.h"
#include "wifi_logger.h"
#include "wifi_service_manager.h"
#include "wifi_hisysevent.h"
#include "wifi_settings.h"
#include "wifi_config_center.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiSensorScene");

constexpr int SCENARIO_UNKNOWN = -1;
constexpr int SCENARIO_OUTDOOR = 1;

constexpr int MIN_5GHZ_BAND_FREQUENCY = 5000;

constexpr int MIN_RSSI_VALUE_24G = -80;
constexpr int MIN_RSSI_VALUE_5G = -77;
constexpr int MIN_RSSI_VALUE_OUTDOOR_24G = -75;
constexpr int MIN_RSSI_VALUE_OUTDOOR_5G = -72;
constexpr int CONN_RSSI_CNT = 10;

WifiSensorScene::WifiSensorScene() : scenario_(SCENARIO_UNKNOWN),
    minRssi24G_(MIN_RSSI_VALUE_24G), minRssi5G_(MIN_RSSI_VALUE_5G), isCallbackReg_(false)
{
    InitCallback();
}

WifiSensorScene &WifiSensorScene::GetInstance()
{
    static WifiSensorScene gWifiSensorScene;
    return gWifiSensorScene;
}

void WifiSensorScene::InitCallback()
{
    using namespace std::placeholders;
    WIFI_LOGI("Enter InitCallback");
    staCallback_.callbackModuleName = "WifiSensorScene";
    staCallback_.OnStaConnChanged = [this](OperateResState state, const WifiLinkedInfo &linkedInfo, int32_t instId) {
        this->DealStaConnChanged(state, linkedInfo, instId);
    };
    staCallback_.OnWifiHalSignalInfoChange = [this](const WifiSignalPollInfo &wifiSignalPollInfo) {
        this->HandleSignalInfoChange(wifiSignalPollInfo);
    };
}

void WifiSensorScene::DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId)
{
    std::lock_guard<std::mutex> lock(staCbMutex_);
    if (instId != INSTID_WLAN0 || info.networkId == INVALID_NETWORK_ID || info.bssid.empty() ||
        (state != OperateResState::DISCONNECT_DISCONNECTED && state != OperateResState::CONNECT_AP_CONNECTED)) {
        return;
    }
    if (state == OperateResState::DISCONNECT_DISCONNECTED) {
        if (rssiCnt_ < CONN_RSSI_CNT) {
            ReportLinkedQuality(0);
        }
        connScene_ = UNKNOW_SCENE;
        rssiCnt_ = 0;
        reportRssi_ = 0;
        connRssi_ = 0;
    }
    if (lastState_ == OperateResState::DISCONNECT_DISCONNECTED && state == OperateResState::CONNECT_AP_CONNECTED) {
        connRssi_ = info.rssi;
        IsOutdoorScene() ? connScene_ = OUTDOOR_SCENE : connScene_ = INDOOR_SCENE;
    }
    lastState_ = state;
}

void WifiSensorScene::HandleSignalInfoChange(const WifiSignalPollInfo &wifiSignalPollInfo)
{
    WIFI_LOGD("Enter HandleSignalInfoChange");
    std::lock_guard<std::mutex> lock(staCbMutex_);
    if (rssiCnt_ == CONN_RSSI_CNT) {
        WifiLinkedInfo linkedInfo;
        WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
        int32_t maxSignalLevel = WifiSettings::GetInstance().GetSignalLevel(maxRssi_, linkedInfo.band, INSTID_WLAN0);
        if (maxSignalLevel == SIG_LEVEL_4) {
            ReportLinkedQuality(connRssi_);
        } else {
            ReportLinkedQuality(reportRssi_);
        }
    }
    if (rssiCnt_ > CONN_RSSI_CNT) {
        WIFI_LOGD("Current link has collected rssi data");
        return;
    }
    rssiCnt_++;
    reportRssi_ = wifiSignalPollInfo.signal < reportRssi_ ? wifiSignalPollInfo.signal : reportRssi_;
    maxRssi_ = wifiSignalPollInfo.signal < maxRssi_ ? maxRssi_ : wifiSignalPollInfo.signal;
}

StaServiceCallback WifiSensorScene::GetStaCallback() const
{
    return staCallback_;
}

void WifiSensorScene::ReportLinkedQuality(int32_t rssi, int32_t instId)
{
    IodStatisticInfo iodStatisticInfo;
    if (rssi == 0) {
        WIFI_LOGI("Connection duration is short, connScene_: %{public}d", connScene_);
        connScene_ == OUTDOOR_SCENE ? iodStatisticInfo.outdoorConnShortTime++ : iodStatisticInfo.indoorConnShortTime++;
        return;
    }
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    int32_t signalLevel = WifiSettings::GetInstance().GetSignalLevel(rssi, linkedInfo.band, instId);
    WIFI_LOGI("ReportLinkedQuality, connScene_: %{public}d, signalLevel: %{public}d", connScene_, signalLevel);
    switch (signalLevel) {
        case SIG_LEVEL_0:
            connScene_ == OUTDOOR_SCENE ? iodStatisticInfo.outdoorConnLevel0++ : iodStatisticInfo.indoorConnLevel0++;
            break;
        case SIG_LEVEL_1:
            connScene_ == OUTDOOR_SCENE ? iodStatisticInfo.outdoorConnLevel1++ : iodStatisticInfo.indoorConnLevel1++;
            break;
        case SIG_LEVEL_2:
            connScene_ == OUTDOOR_SCENE ? iodStatisticInfo.outdoorConnLevel2++ : iodStatisticInfo.indoorConnLevel2++;
            break;
        case SIG_LEVEL_3:
            connScene_ == OUTDOOR_SCENE ? iodStatisticInfo.outdoorConnLevel3++ : iodStatisticInfo.indoorConnLevel3++;
            break;
        case SIG_LEVEL_4:
            connScene_ == OUTDOOR_SCENE ? iodStatisticInfo.outdoorConnLevel4++ : iodStatisticInfo.indoorConnLevel4++;
            break;
        default:
            WIFI_LOGE("Invalid signal level");
            break;
    }
    WriteIodHiSysEvent(iodStatisticInfo);
}

int WifiSensorScene::GetMinRssiThres(int frequency)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (scenario_ == SCENARIO_OUTDOOR) {
        minRssi24G_ = MIN_RSSI_VALUE_OUTDOOR_24G;
        minRssi5G_ = MIN_RSSI_VALUE_OUTDOOR_5G;
    } else {
        minRssi24G_ = MIN_RSSI_VALUE_24G;
        minRssi5G_ = MIN_RSSI_VALUE_5G;
    }
    int minRssi = frequency < MIN_5GHZ_BAND_FREQUENCY ? minRssi24G_ : minRssi5G_;
    return minRssi;
}

void WifiSensorScene::SensorEnhCallback(int scenario)
{
    WIFI_LOGI("%{public}s scene %{public}d", __FUNCTION__, scenario);
    std::lock_guard<std::mutex> lock(mutex_);
    if (scenario_ != scenario) {
        IodStatisticInfo iodStatisticInfo;
        if (scenario == SCENARIO_OUTDOOR) {
            iodStatisticInfo.in2OutCnt++;
        } else {
            iodStatisticInfo.out2InCnt++;
        }
        WriteIodHiSysEvent(iodStatisticInfo);
        scenario_ = scenario;
    }
}

void WifiSensorScene::RegisterSensorEnhCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (isCallbackReg_) {
        return;
    }

    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("%{public}s get pEnhance service failed!", __FUNCTION__);
        return;
    }
    std::function<void(int)> callback = [this](int scenario) {
        SensorEnhCallback(scenario);
    };
    ErrCode ret = pEnhanceService->RegisterSensorEnhanceCallback(callback);
    if (ret == WIFI_OPT_SUCCESS) {
        isCallbackReg_ = true;
    }
    WIFI_LOGI("%{public}s ret %{public}d", __FUNCTION__, ret);
}

bool WifiSensorScene::IsOutdoorScene()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return scenario_ == SCENARIO_OUTDOOR;
}

void WifiSensorScene::OnConnectivityChanged(int32_t bearType, int32_t code)
{
    if ((bearType == NetManagerStandard::NetBearType::BEARER_WIFI ||
        bearType == NetManagerStandard::NetBearType::BEARER_CELLULAR) &&
        code == NetManagerStandard::NetConnState::NET_CONN_STATE_CONNECTED) {
        RegisterSensorEnhCallback();
    }
}

}  // namespace Wifi
}  // namespace OHOS