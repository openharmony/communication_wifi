/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_WIFI_PERMISSION_UTILS_H
#define OHOS_WIFI_PERMISSION_UTILS_H

#include "wifi_permission_helper.h"

namespace OHOS {
namespace Wifi {
const int API_VERSION_9 = 9;
const int API_VERSION_10 = 10;
const int API_VERSION_11 = 11;
const int API_VERSION_12 = 12;
const int API_VERSION_INVALID = -1;

class WifiPermissionUtils {
public:
    static int VerifyManageEdmPolicyPermission();
    static int VerifySetWifiInfoPermission();
    static int VerifyGetWifiInfoPermission();
    static int VerifySameProcessPermission();
    static int VerifyWifiConnectionPermission();
    static int VerifyGetScanInfosPermission();
    static int VerifyGetWifiLocalMacPermission();
    static int VerifySetWifiConfigPermission();
    static int VerifyGetWifiConfigPermission();
    static int VerifyGetWifiDirectDevicePermission();
    static int VerifyManageWifiHotspotPermission();
    static int VerifyGetWifiPeersMacPermission();
    static int VerifyGetWifiInfoInternalPermission();
    static int VerifyGetWifiPeersMacPermissionEx(const int &pid, const int &uid, const int &tokenId);
    static int VerifyManageWifiHotspotExtPermission();
    static int VerifyEnterpriseWifiConnectionPermission();
    static int GetApiVersion();
};
}  // namespace Wifi
}  // namespace OHOS
#endif