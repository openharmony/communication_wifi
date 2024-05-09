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

#include "wifi_auth_center.h"
#include "wifi_permission_helper.h"
#include "wifi_logger.h"
#ifndef OHOS_ARCH_LITE
#include <cinttypes>
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "accesstoken_kit.h"
#endif

DEFINE_WIFILOG_LABEL("WifiAuthCenter");

namespace OHOS {
namespace Wifi {
#ifdef PERMISSION_ALWAYS_GRANT
bool g_permissinAlwaysGrant = true;
#else
bool g_permissinAlwaysGrant = false;
#endif // PERMISSION_ALWAYS_GRANT

WifiAuthCenter &WifiAuthCenter::GetInstance()
{
    static WifiAuthCenter gWifiAuthCenter;
    return gWifiAuthCenter;
}

int WifiAuthCenter::Init()
{
    /* init system auth service client here */
    return 0;
}

#ifndef OHOS_ARCH_LITE
bool WifiAuthCenter::IsSystemAppByToken() {
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    bool isSystemApp = Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::ATokenTypeEnum callingType =
        Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    WIFI_LOGI("fullTokenId:%" PRIu64 ", isSystemApp:%{public}d, tokenId:%{public}d, callingType:%{public}d.",
        fullTokenId, isSystemApp, tokenId, callingType);
    if (callingType == Security::AccessToken::TOKEN_HAP && !isSystemApp) {
        WIFI_LOGE("The caller is not a system app.");
        return false;
    }
    return true;
}
bool WifiAuthCenter::IsNativeProcess()
{
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    Security::AccessToken::ATokenTypeEnum callingType =
        Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (callingType == Security::AccessToken::TOKEN_NATIVE) {
        return true;
    }
    WIFI_LOGE("The caller tokenId:%{public}d, callingType:%{public}d is not a native process.", tokenId, callingType);
    return false;
}
#endif

int WifiAuthCenter::VerifySetWifiInfoPermission(const int &pid, const int &uid)
{
    if (g_permissinAlwaysGrant) {
        return PERMISSION_GRANTED;
    }
    return WifiPermissionHelper::VerifySetWifiInfoPermission(pid, uid);
}

int WifiAuthCenter::VerifyGetWifiInfoPermission(const int &pid, const int &uid)
{
    if (g_permissinAlwaysGrant) {
        return PERMISSION_GRANTED;
    }
    return WifiPermissionHelper::VerifyGetWifiInfoPermission(pid, uid);
}

int WifiAuthCenter::VerifyGetScanInfosPermission(const int &pid, const int &uid)
{
    if (g_permissinAlwaysGrant) {
        return PERMISSION_GRANTED;
    }
    return WifiPermissionHelper::VerifyGetScanInfosPermission(pid, uid);
}

int WifiAuthCenter::VerifyGetWifiLocalMacPermission(const int &pid, const int &uid)
{
    if (g_permissinAlwaysGrant) {
        return PERMISSION_GRANTED;
    }
    return WifiPermissionHelper::VerifyGetWifiLocalMacPermission(pid, uid);
}

int WifiAuthCenter::VerifyWifiConnectionPermission(const int &pid, const int &uid)
{
    if (g_permissinAlwaysGrant) {
        return PERMISSION_GRANTED;
    }
    return WifiPermissionHelper::VerifyWifiConnectionPermission(pid, uid);
}

int WifiAuthCenter::VerifySetWifiConfigPermission(const int &pid, const int &uid)
{
    if (g_permissinAlwaysGrant) {
        return PERMISSION_GRANTED;
    }
    return WifiPermissionHelper::VerifySetWifiConfigPermission(pid, uid);
}

int WifiAuthCenter::VerifyGetWifiConfigPermission(const int &pid, const int &uid)
{
    if (g_permissinAlwaysGrant) {
        return PERMISSION_GRANTED;
    }
    return WifiPermissionHelper::VerifyGetWifiConfigPermission(pid, uid);
}

int WifiAuthCenter::VerifyGetWifiDirectDevicePermission(const int &pid, const int &uid)
{
    if (g_permissinAlwaysGrant) {
        return PERMISSION_GRANTED;
    }
    return WifiPermissionHelper::VerifyGetWifiDirectDevicePermission(pid, uid);
}

int WifiAuthCenter::VerifyManageWifiHotspotPermission(const int &pid, const int &uid)
{
    if (g_permissinAlwaysGrant) {
        return PERMISSION_GRANTED;
    }
    return WifiPermissionHelper::VerifyManageWifiHotspotPermission(pid, uid);
}

int WifiAuthCenter::VerifyGetWifiPeersMacPermission(const int &pid, const int &uid)
{
    if (g_permissinAlwaysGrant) {
        return PERMISSION_GRANTED;
    }
    return WifiPermissionHelper::VerifyGetWifiPeersMacPermission(pid, uid);
}

int WifiAuthCenter::VerifyGetWifiPeersMacPermissionEx(const int &pid, const int &uid, const int &tokenId)
{
    if (g_permissinAlwaysGrant) {
        return PERMISSION_GRANTED;
    }
    return WifiPermissionHelper::VerifyGetWifiPeersMacPermissionEx(pid, uid, tokenId);
}

int WifiAuthCenter::VerifyGetWifiInfoInternalPermission(const int &pid, const int &uid)
{
    if (g_permissinAlwaysGrant) {
        return PERMISSION_GRANTED;
    }
    return WifiPermissionHelper::VerifyGetWifiInfoInternalPermission(pid, uid);
}

int WifiAuthCenter::VerifyManageWifiHotspotExtPermission(const int &pid, const int &uid)
{
    if (g_permissinAlwaysGrant) {
        return PERMISSION_GRANTED;
    }
    return WifiPermissionHelper::VerifyManageWifiHotspotExtPermission(pid, uid);
}
} // namespace Wifi
} // namespace OHOS