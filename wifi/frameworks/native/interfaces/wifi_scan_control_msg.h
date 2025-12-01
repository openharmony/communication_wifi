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

#ifndef OHOS_WIFI_SCAN_CONTROL_MSG_H
#define OHOS_WIFI_SCAN_CONTROL_MSG_H

#include "wifi_hid2d_msg.h"
#include "wifi_scan_msg.h"
#include "wifi_p2p_msg.h"
#include "define.h"

namespace OHOS {
namespace Wifi {
struct Hid2dInfo {
    Hid2dUpperScene softBusScene;
    Hid2dUpperScene castScene;
    Hid2dUpperScene shareScene;
    Hid2dUpperScene mouseCrossScene;
    Hid2dUpperScene miraCastScene;
    P2pConnectedState p2pConnectState;
    int p2pEnhanceState;
    int64_t hid2dSceneLastSetTime;

    Hid2dInfo()
    {
        p2pConnectState = P2pConnectedState::P2P_DISCONNECTED;
        p2pEnhanceState = 0;
        hid2dSceneLastSetTime = 0;
    }
};

struct WifiScanDeviceInfo {
    int appId;
    int idelState;
    int thermalLevel;
    int screenState;
    int staScene;
    int staSceneForbidCount;
    int freezeState;
    int noChargerState;
    int gnssFixState;
    std::string packageName;
    int initiatorUid;
    time_t staCurrentTime;
    bool isAbsFreezeScaned;
    bool externScan;
    bool isSystemApp;
    ScanMode scanMode;
    ScanType scanType;
    int scanStyle;
    Hid2dInfo hid2dInfo;
    ScanControlInfo scanControlInfo;
    std::vector<PackageInfo> scan_thermal_trust_list;
    std::vector<PackageInfo> scan_frequency_trust_list;
    std::vector<PackageInfo> scan_screen_off_trust_list;
    std::vector<PackageInfo> scan_gps_block_list;
    std::vector<PackageInfo> scan_hid2d_list;
    std::vector<std::string> abnormalAppList;

    WifiScanDeviceInfo()
    {
        appId = 0;
        idelState = MODE_STATE_CLOSE;
        thermalLevel = 1;
        screenState = MODE_STATE_DEFAULT;
        staScene = SCAN_SCENE_MAX;
        freezeState = MODE_STATE_CLOSE;
        noChargerState = MODE_STATE_CLOSE;
        scanMode = ScanMode::SCAN_MODE_MAX;
        scanType = ScanType::SCAN_DEFAULT;
        scanStyle = SCAN_DEFAULT_TYPE;
        isAbsFreezeScaned = false;
        staSceneForbidCount = 0;
        externScan = false;
        isSystemApp = false;
        staCurrentTime = 0;
        gnssFixState = 0;
        packageName = "";
        initiatorUid = -1;
    }

    std::string GetScanInitiatorName()
    {
        std::string scanInitiatorName = "";
        if (packageName.empty()) {
            scanInitiatorName = std::to_string(initiatorUid);
        } else {
            scanInitiatorName = packageName;
        }
        return scanInitiatorName;
    }
};

enum class ScanLimitType {
    INVALID = -1,
    INTERVAL,
    SCAN_DISABLE,
    WIFI_DISABLE,
    HID2D_SOFTBUS,
    HID2D_CAST,
    HID2D_MIRACAST,
    HID2D_SHARE,
    HID2D_CROSS,
    THERMAL,
    SCREEN_OFF,
    SCHED_STRATEGY,
    DURING_STA,
    CUSTOM_SCENE,
    GNSS_FIX,
    MOVING_FREEZE,
    ABNORMAL_APP,
    CANNOT_SWITCH_AP,
    STA_STATE,
    ACTION_LISTEN,
    HID2D_CLONE,
    GAME_SCENE,
    GLASSES_SCENE,
    LP_SCANSTYLE,
};
}  // namespace Wifi
}  // namespace OHOS
#endif