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
#include "wifi_permission_helper.h"
#include <mutex>
#include "wifi_log.h"
#ifndef OHOS_ARCH_LITE
#include "ipc_skeleton.h"
#include "accesstoken_kit.h"
#endif
#undef LOG_TAG
#define LOG_TAG "OHWIFI_MANAGER_PERMISSION_HELPER"

namespace OHOS {
namespace Wifi {

int WifiPermissionHelper::VerifyPermission(const std::string &permissionName, const int &pid,
    const int &uid, const int &tokenId)
{
#ifdef OHOS_ARCH_LITE
    return PERMISSION_GRANTED;
#else
    /* Waive all permission checks for wifi_enhance */
    const int uidWifiEnhance = 1010;
    if (uid == uidWifiEnhance) {
        return PERMISSION_GRANTED;
    }

    Security::AccessToken::AccessTokenID callerToken = 0;
    if (tokenId == 0) {
        callerToken = IPCSkeleton::GetCallingTokenID();
    } else {
        callerToken = (Security::AccessToken::AccessTokenID)tokenId;
    }

    int result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    if (result == Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
        return PERMISSION_GRANTED;
    }
 
    LOGE("callerToken=0x%{public}x has no permission_name=%{public}s, pid=%{public}d, uid=%{public}d",
        callerToken, permissionName.c_str(), pid, uid);
    return PERMISSION_DENIED;
#endif
}

int WifiPermissionHelper::VerifySetWifiInfoPermission(const int &pid, const int &uid)
{
    if (VerifyPermission("ohos.permission.SET_WIFI_INFO", pid, uid, 0) == PERMISSION_DENIED) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

int WifiPermissionHelper::VerifyGetWifiInfoPermission(const int &pid, const int &uid)
{
    if (VerifyPermission("ohos.permission.GET_WIFI_INFO", pid, uid, 0) == PERMISSION_DENIED) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

int WifiPermissionHelper::VerifySetWifiConfigPermission(const int &pid, const int &uid)
{
    if (VerifyPermission("ohos.permission.SET_WIFI_CONFIG", pid, uid, 0) == PERMISSION_DENIED) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

int WifiPermissionHelper::VerifyGetWifiConfigPermission(const int &pid, const int &uid)
{
    if (VerifyPermission("ohos.permission.GET_WIFI_CONFIG", pid, uid, 0) == PERMISSION_DENIED) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

int WifiPermissionHelper::VerifyGetScanInfosPermission(const int &pid, const int &uid)
{
    if (VerifyPermission("ohos.permission.LOCATION", pid, uid, 0) == PERMISSION_DENIED) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

int WifiPermissionHelper::VerifyGetWifiLocalMacPermission(const int &pid, const int &uid)
{
    if (VerifyPermission("ohos.permission.GET_WIFI_LOCAL_MAC", pid, uid, 0) == PERMISSION_DENIED) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

int WifiPermissionHelper::VerifyWifiConnectionPermission(const int &pid, const int &uid)
{
    if (VerifyPermission("ohos.permission.MANAGE_WIFI_CONNECTION", pid, uid, 0) == PERMISSION_DENIED) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

int WifiPermissionHelper::VerifyGetWifiDirectDevicePermission(const int &pid, const int &uid)
{
    if (VerifyPermission("ohos.permission.LOCATION", pid, uid, 0) == PERMISSION_DENIED) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

int WifiPermissionHelper::VerifyManageWifiHotspotPermission(const int &pid, const int &uid)
{
    if (VerifyPermission("ohos.permission.MANAGE_WIFI_HOTSPOT", pid, uid, 0) == PERMISSION_DENIED) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

int WifiPermissionHelper::VerifyGetWifiPeersMacPermission(const int &pid, const int &uid)
{
    if (VerifyPermission("ohos.permission.GET_WIFI_PEERS_MAC", pid, uid, 0) == PERMISSION_DENIED) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

int WifiPermissionHelper::VerifyGetWifiPeersMacPermissionEx(const int &pid, const int &uid, const int &tokenId)
{
    if (VerifyPermission("ohos.permission.GET_WIFI_PEERS_MAC", pid, uid, tokenId) == PERMISSION_DENIED) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

int WifiPermissionHelper::VerifyGetWifiInfoInternalPermission(const int &pid, const int &uid)
{
    if (VerifyPermission("ohos.permission.GET_WIFI_INFO_INTERNAL", pid, uid, 0) == PERMISSION_DENIED) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}

int WifiPermissionHelper::VerifyManageWifiHotspotExtPermission(const int &pid, const int &uid)
{
    if (VerifyPermission("ohos.permission.MANAGE_WIFI_HOTSPOT_EXT", pid, uid, 0) == PERMISSION_DENIED) {
        return PERMISSION_DENIED;
    }
    return PERMISSION_GRANTED;
}
}  // namespace Wifi
}  // namespace OHOS
