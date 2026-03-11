/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "wifi_logger.h"
#include "wifi_common_util.h"
#include "app_network_speed_limit_chr.h"
 
namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("AppNetworkSpeedLimitChr");
 
AppNetworkSpeedLimitChr::AppNetworkSpeedLimitChr()
{
    WIFI_LOGI("%{public}s enter", __FUNCTION__);
}
 
AppNetworkSpeedLimitChr::~AppNetworkSpeedLimitChr()
{
    WIFI_LOGI("%{public}s exit", __FUNCTION__);
    ClearAppNetworkSpeedLimitChrHistoryData();
}
 
AppNetworkSpeedLimitChr &AppNetworkSpeedLimitChr::GetInstance()
{
    static AppNetworkSpeedLimitChr instance;
    return instance;
}
 
void AppNetworkSpeedLimitChr::RecordAppNetworkSpeedLimitCommonInfo(
    const AppNetworkSpeedLimitStatisticInfo &appSpeedLimitInfo)
{
    std::unique_lock<std::mutex> lock(appSpeedLimitInfoMutex_);
    appSpeedLimitInfo_ = appSpeedLimitInfo;
    WriteAppNetworkSpeedLimitChrStatisticData();
}
 
void AppNetworkSpeedLimitChr::WriteAppNetworkSpeedLimitChrStatisticData()
{
    WriteWifiAppNetWorkSpeedLimitCommonInfoHiSysEvent(appSpeedLimitInfo_);
    ClearAppNetworkSpeedLimitChrHistoryData();
}
 
void AppNetworkSpeedLimitChr::ClearAppNetworkSpeedLimitChrHistoryData()
{
    appSpeedLimitInfo_.speedLimitScenarioAndLevel = "";
    appSpeedLimitInfo_.speedLimitForegroundAppInfo = "";
    appSpeedLimitInfo_.speedLimitBackgroundAppInfo = "";
    appSpeedLimitInfo_.speedLimitGameState = -1;
}
 
}
}