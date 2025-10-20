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

#include "wifi_hiappevent.h"

#include <random>
#include "app_event.h"
#include "app_event_processor_mgr.h"
#include "parameters.h"

#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiHiAppEvent");
constexpr int32_t HA_CONFIG_TIMEOUT = 90;  // report every 90 second
constexpr int32_t HA_CONFIG_ROW = 30;  // report every 30 data points
constexpr int32_t HA_NOT_SUPPORT = -200;  // processId not hap
constexpr const char *KIT_NAME = "ConnectivityKit";
WifiHiAppEvent::WifiHiAppEvent()
{
}

WifiHiAppEvent::~WifiHiAppEvent()
{
}

WifiHiAppEvent* WifiHiAppEvent::GetInstance()
{
    static WifiHiAppEvent data;
    return &data;
}

void WifiHiAppEvent::AddProcessor()
{
    if (processorId_ != -1) {
        return;
    }
    OHOS::HiviewDFX::HiAppEvent::ReportConfig config;
    std::string appId = system::GetParameter("persist.wifi.ha_appid", "");
    if (appId.empty()) {
        WIFI_LOGE("AddProcessor appId is empty");
        return;
    }
    config.name = "ha_app_event";
    config.appId = appId;
    config.routeInfo = "AUTO";
    config.triggerCond.timeout = HA_CONFIG_TIMEOUT;
    config.triggerCond.row = HA_CONFIG_ROW;
    config.eventConfigs.clear();
    {
        OHOS::HiviewDFX::HiAppEvent::EventConfig event1;
        event1.domain = "api_diagnostic";
        event1.name = "api_exec_end";
        event1.isRealTime = false;
        config.eventConfigs.push_back(event1);
    }
    {
        OHOS::HiviewDFX::HiAppEvent::EventConfig event2;
        event2.domain = "api_diagnostic";
        event2.name = "api_called_stat";
        event2.isRealTime = true;
        config.eventConfigs.push_back(event2);
    }
    {
        OHOS::HiviewDFX::HiAppEvent::EventConfig event3;
        event3.domain = "api_diagnostic";
        event3.name = "api_called_stat_cnt";
        event3.isRealTime = true;
        config.eventConfigs.push_back(event3);
    }
    processorId_ = HiviewDFX::HiAppEvent::AppEventProcessorMgr::AddProcessor(config);
}

void WifiHiAppEvent::WriteEndEvent(const int64_t beginTime, const int result, const int errCode,
    const std::string& apiName)
{
    AddProcessor();
    if (processorId_ == HA_NOT_SUPPORT) {
        return;
    }
    HiviewDFX::HiAppEvent::Event event("api_diagnostic", "api_exec_end", HiviewDFX::HiAppEvent::BEHAVIOR);
    auto transId = std::string("transId_") + std::to_string(std::rand());
    event.AddParam("trans_id", transId);
    event.AddParam("api_name", apiName);
    event.AddParam("sdk_name", std::string(KIT_NAME));
    event.AddParam("begin_time", beginTime);
    event.AddParam("end_time", GetCurrentMillis());
    event.AddParam("result", result);
    event.AddParam("error_code", errCode);
    HiviewDFX::HiAppEvent::Write(event);
}

int64_t WifiHiAppEvent::GetCurrentMillis()
{
    return std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now()).
        time_since_epoch().count();
}
}  // namespace Wifi
}  // namespace OHOS