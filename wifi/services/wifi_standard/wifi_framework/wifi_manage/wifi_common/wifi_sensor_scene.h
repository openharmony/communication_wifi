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

#ifndef OHOS_WIFI_SENSOR_SCENE_H
#define OHOS_WIFI_SENSOR_SCENE_H

#include <mutex>
#include "sta_service_callback.h"

namespace OHOS {
namespace Wifi {

enum ConnScene {
    UNKNOW_SCENE = 0,
    OUTDOOR_SCENE = 1,
    INDOOR_SCENE = 2,
};

class WifiSensorScene {
public:
    WifiSensorScene();
    ~WifiSensorScene() = default;

    static WifiSensorScene &GetInstance();

    void OnConnectivityChanged(int32_t bearType, int32_t code);
    int GetMinRssiThres(int frequency);
    bool IsOutdoorScene();
    StaServiceCallback GetStaCallback() const;

private:
    void RegisterSensorEnhCallback();
    void SensorEnhCallback(int scenario);
    void InitCallback();
    void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId);
    void HandleSignalInfoChange(const WifiSignalPollInfo &wifiSignalPollInfo);
    void ReportLinkedQuality(int32_t rssi, int32_t instId = 0);

private:
    std::mutex mutex_;
    std::mutex staCbMutex_;
    int scenario_;

    int minRssi24G_;
    int minRssi5G_;

    int rssiCnt_ = 0;
    int connScene_ = UNKNOW_SCENE;
    int reportRssi_ = 0;
    int connRssi_ = 0;
    int maxRssi_ = -140;
    OperateResState lastState_ = OperateResState::DISCONNECT_DISCONNECTED;
    StaServiceCallback staCallback_;
    bool isCallbackReg_;
};

}  // namespace Wifi
}  // namespace OHOS
#endif