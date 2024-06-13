/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MOCK_AUTH_CENTER_H
#define OHOS_MOCK_AUTH_CENTER_H

#define PERMISSION_GRANTED (1)
#define PERMISSION_DENIED (0)

namespace OHOS {
namespace Wifi {
class WifiAuthCenter {
public:
    static WifiAuthCenter &GetInstance();

    int Init();

    static bool IsSystemAppByToken();

    static bool IsNativeProcess();

    int VerifySetWifiInfoPermission(const int &pid, const int &uid);

    int VerifyGetWifiInfoPermission(const int &pid, const int &uid);

    int VerifyGetScanInfosPermission(const int &pid, const int &uid);

    int VerifyGetWifiLocalMacPermission(const int &pid, const int &uid);

    int VerifyWifiConnectionPermission(const int &pid, const int &uid);

    int VerifySetWifiConfigPermission(const int &pid, const int &uid);

    int VerifyGetWifiDirectDevicePermission(const int &pid, const int &uid);

    int VerifyManageWifiHotspotPermission(const int &pid, const int &uid);

    int VerifyGetWifiPeersMacPermission(const int &pid, const int &uid);

    int VerifyGetWifiPeersMacPermissionEx(const int &pid, const int &uid, const int &tokenId);

    int VerifyGetWifiInfoInternalPermission(const int &pid, const int &uid);

    int VerifyManageWifiHotspotExtPermission(const int &pid, const int &uid);

    int VerifyGetWifiConfigPermission(const int &pid, const int &uid);
};
} // namespace Wifi
} // namespace OHOS
#endif