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
 
#include "hid2d_service_registry.h"
#include "wifi_logger.h"
 
namespace OHOS {
namespace Wifi {
namespace {
 
const std::vector<Hid2dServiceEntry> g_hid2dServiceRegistry = {
    {SOFT_BUS_SERVICE_UID, "SoftBus", ScanLimitType::HID2D_SOFTBUS, SOFT_BUS_SERVER_SA_ID, true},
    {CAST_ENGINE_SERVICE_UID, "Cast", ScanLimitType::HID2D_CAST, CAST_ENGINE_SA_ID, true},
    {MIRACAST_SERVICE_UID, "Miracast", ScanLimitType::HID2D_MIRACAST, MIRACAST_SERVICE_SA_ID, true},
    {SHARE_SERVICE_UID, "Share", ScanLimitType::HID2D_SHARE, SHARE_SERVICE_ID, false},
    {MOUSE_CROSS_SERVICE_UID, "MouseCross", ScanLimitType::HID2D_CROSS, MOUSE_CROSS_SERVICE_ID, false},
    {GAMESERVICE_SA_UID, "Game", ScanLimitType::HID2D_GAME, GAMESERVICE_SA_ID, false},
    {WATCH_SERVICE_UID, "Watch", ScanLimitType::HID2D_WATCH, SUBSYS_WEARABLE_SYS_ABILITY_ID_BEGIN, false},
    {HICAR_SERVICE_UID, "HiCar", ScanLimitType::HID2D_SOFTBUS, HICAR_SERVICE_SA_ID, true},
};
 
const std::vector<int> g_hid2dServiceUids = {
    SOFT_BUS_SERVICE_UID,
    CAST_ENGINE_SERVICE_UID,
    MIRACAST_SERVICE_UID,
    SHARE_SERVICE_UID,
    MOUSE_CROSS_SERVICE_UID,
    GAMESERVICE_SA_UID,
    WATCH_SERVICE_UID,
    HICAR_SERVICE_UID,
};
 
} // namespace
 
const std::vector<Hid2dServiceEntry>& GetHid2dServiceRegistry()
{
    return g_hid2dServiceRegistry;
}
 
bool IsHid2dServiceUid(int uid)
{
    for (const auto& entry : g_hid2dServiceRegistry) {
        if (entry.uid == uid) {
            return true;
        }
    }
    return false;
}
 
bool IsHid2dServiceSaId(int saId)
{
    for (const auto& entry : g_hid2dServiceRegistry) {
        if (entry.systemAbilityId == saId) {
            return true;
        }
    }
    return false;
}
 
const Hid2dServiceEntry* FindServiceByUid(int uid)
{
    for (const auto& entry : g_hid2dServiceRegistry) {
        if (entry.uid == uid) {
            return &entry;
        }
    }
    return nullptr;
}
 
const Hid2dServiceEntry* FindServiceBySaId(int saId)
{
    for (const auto& entry : g_hid2dServiceRegistry) {
        if (entry.systemAbilityId == saId) {
            return &entry;
        }
    }
    return nullptr;
}
 
const std::vector<int>& GetAllHid2dServiceUids()
{
    return g_hid2dServiceUids;
}
 
} // namespace Wifi
} // namespace OHOS