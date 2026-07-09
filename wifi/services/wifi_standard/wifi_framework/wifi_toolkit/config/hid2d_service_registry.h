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
 
#ifndef OHOS_WIFI_HID2D_SERVICE_REGISTRY_H
#define OHOS_WIFI_HID2D_SERVICE_REGISTRY_H
 
#include <string>
#include <vector>
#include "wifi_scan_control_msg.h"

#define SOFT_BUS_SERVICE_UID 1024
#define SOFT_BUS_SERVER_SA_ID 4700
#define CAST_ENGINE_SERVICE_UID 5526
#define MIRACAST_SERVICE_UID 5529
#define MIRACAST_SERVICE_SA_ID 5527
#define SHARE_SERVICE_UID 5520
#define MOUSE_CROSS_SERVICE_UID 6699
#define HICAR_SERVICE_UID 65872
#define HICAR_SERVICE_SA_ID 65872
#define GAMESERVICE_SA_UID 7011
#define GAMESERVICE_SA_ID 66006
#define WATCH_SERVICE_UID 7500
#define WATCH_SERVICE_SA_ID 65570
#define CAST_ENGINE_SA_ID 65546
#define SHARE_SERVICE_ID 2902
#define MOUSE_CROSS_SERVICE_ID 65569
#define WEARABLE_SERVICE_SA_ID 4300

namespace OHOS {
namespace Wifi {

struct Hid2dServiceEntry {
    int uid;
    std::string serviceName;
    ScanLimitType limitType;
    int systemAbilityId;
    bool allowLpScan;
};

const std::vector<Hid2dServiceEntry>& GetHid2dServiceRegistry();
bool IsHid2dServiceUid(int uid);
bool IsHid2dServiceSaId(int saId);
const Hid2dServiceEntry* FindServiceByUid(int uid);
const Hid2dServiceEntry* FindServiceBySaId(int saId);
const std::vector<int>& GetAllHid2dServiceUids();

} // namespace Wifi
} // namespace OHOS
#endif