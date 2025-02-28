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

#include "mock_auth_center.h"

namespace OHOS {
namespace Wifi {
constexpr int PERMISSION_DENIED = 0;
WifiAuthCenter &WifiAuthCenter::GetInstance()
{
    static WifiAuthCenter gWifiAuthCenter;
    return gWifiAuthCenter;
}

int WifiAuthCenter::Init()
{
    return PERMISSION_DENIED;
}

bool WifiAuthCenter::IsSystemAccess()
{
    return false;
}

bool WifiAuthCenter::IsNativeProcess()
{
    return false;
}

int WifiAuthCenter::VerifySetWifiInfoPermission(const int &pid, const int &uid)
{
    return PERMISSION_DENIED;
}

int WifiAuthCenter::VerifyGetWifiInfoPermission(const int &pid, const int &uid)
{
    return PERMISSION_DENIED;
}

int WifiAuthCenter::VerifyGetScanInfosPermission(const int &pid, const int &uid)
{
    return PERMISSION_DENIED;
}

int WifiAuthCenter::VerifyGetWifiLocalMacPermission(const int &pid, const int &uid)
{
    return PERMISSION_DENIED;
}

int WifiAuthCenter::VerifyWifiConnectionPermission(const int &pid, const int &uid)
{
    return PERMISSION_DENIED;
}

int WifiAuthCenter::VerifySetWifiConfigPermission(const int &pid, const int &uid)
{
    return PERMISSION_DENIED;
}

int WifiAuthCenter::VerifyGetWifiDirectDevicePermission(const int &pid, const int &uid)
{
    return PERMISSION_DENIED;
}

int WifiAuthCenter::VerifyManageWifiHotspotPermission(const int &pid, const int &uid)
{
    return PERMISSION_DENIED;
}

int WifiAuthCenter::VerifyGetWifiPeersMacPermission(const int &pid, const int &uid)
{
    return PERMISSION_DENIED;
}

int WifiAuthCenter::VerifyGetWifiPeersMacPermissionEx(const int &pid, const int &uid, const int &tokenId)
{
    return PERMISSION_DENIED;
}
int WifiAuthCenter::VerifyGetWifiInfoInternalPermission(const int &pid, const int &uid)
{
    return PERMISSION_DENIED;
}

int WifiAuthCenter::VerifyManageWifiHotspotExtPermission(const int &pid, const int &uid)
{
    return PERMISSION_DENIED;
}

int WifiAuthCenter::VerifyGetWifiConfigPermission(const int &pid, const int &uid)
{
    return PERMISSION_DENIED;
}

int WifiAuthCenter::VerifyEnterpriseWifiConnectionPermission(const int &pid, const int &uid)
{
    return PERMISSION_DENIED;
}

int WifiAuthCenter::VerifySameProcessPermission(const int &pid, const int &uid)
{
    return PERMISSION_DENIED;
}
} // namespace Wifi
} // namespace OHOS
