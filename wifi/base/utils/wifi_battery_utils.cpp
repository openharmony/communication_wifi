/*
 * Copyright (C) 2025-2025 Huawei Device Co., Ltd.
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
#include "wifi_battery_utils.h"
#include "wifi_logger.h"
#ifdef HAS_BATTERY_MANAGER_PART
#include "battery_srv_client.h"
#endif

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiBatteryUtils");

BatteryUtils::BatteryUtils()
{
    WIFI_LOGI("%{public}s enter", __FUNCTION__);
}

BatteryUtils::~BatteryUtils()
{
    WIFI_LOGI("%{public}s enter", __FUNCTION__);
}

BatteryUtils &BatteryUtils::GetInstance()
{
    static BatteryUtils instance;
    return instance;
}

bool BatteryUtils::IsChargedPlugIn()
{
#ifdef HAS_BATTERY_MANAGER_PART
    auto &batterySrvClient = PowerMgr::BatterySrvClient::GetInstance();
    auto batteryPluggedType = batterySrvClient.GetPluggedType();
    if (batteryPluggedType == PowerMgr::BatteryPluggedType::PLUGGED_TYPE_USB ||
        batteryPluggedType == PowerMgr::BatteryPluggedType::PLUGGED_TYPE_AC) {
        return true;
    }
#endif
    return false;
}

int BatteryUtils::GetBatteryCapacity()
{
#ifdef HAS_BATTERY_MANAGER_PART
    return PowerMgr::BatterySrvClient::GetInstance().GetCapacity();
#else
    return 0;
#endif
}
}   // namespace Wifi
}   // namespace OHOS