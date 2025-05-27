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
#include "wifi_logger.h"
#include "wifi_service_manager.h"
#include <mutex>

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

WifiSensorScene::WifiSensorScene() : scenario_(SCENARIO_UNKNOWN),
    minRssi24G(MIN_RSSI_VALUE_24G), minRssi5G(MIN_RSSI_VALUE_5G) {}

WifiSensorScene &WifiSensorScene::GetInstance()
{
    static WifiSensorScene gWifiSensorScene;
    return gWifiSensorScene;
}

void WifiSensorScene::Init()
{
    RegisterSensorEnhCallback();
}

int WifiSensorScene::GetMinRssiThres(int frequency)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (scenario_ == SCENARIO_OUTDOOR) {
        minRssi24G = MIN_RSSI_VALUE_OUTDOOR_24G;
        minRssi5G = MIN_RSSI_VALUE_OUTDOOR_5G;
    } else {
        minRssi24G = MIN_RSSI_VALUE_24G;
        minRssi5G = MIN_RSSI_VALUE_5G;
    }
    int minRssi = frequency < MIN_5GHZ_BAND_FREQUENCY ? minRssi24G : minRssi5G;
    WIFI_LOGI("%{public}s scene %{public}d thres %{public}d", __FUNCTION__, scenario_, minRssi);
    return minRssi;
}

void WifiSensorScene::SensorEnhCallback(int scenario)
{
    WIFI_LOGI("%{public}s scene %{public}d", __FUNCTION__, scenario);
    std::lock_guard<std::mutex> lock(mutex_);
    if (scenario_ != scenario) {
        scenario_ = scenario;
    }
}

void WifiSensorScene::RegisterSensorEnhCallback()
{
    IEnhanceService *pEnhanceService = WifiServiceManager::GetInstance().GetEnhanceServiceInst();
    if (pEnhanceService == nullptr) {
        WIFI_LOGE("%{public}s get pEnhance service failed!", __FUNCTION__);
        return;
    }
    std::function<void(int)> callback = [this](int scenario) {
        SensorEnhCallback(scenario);
    };
    ErrCode ret = pEnhanceService->RegisterSensorEnhanceCallback(callback);
    WIFI_LOGI("%{public}s ret %{public}d", __FUNCTION__, ret);
}

}  // namespace Wifi
}  // namespace OHOS