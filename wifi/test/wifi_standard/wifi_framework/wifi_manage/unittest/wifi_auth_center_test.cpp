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
#include <gtest/gtest.h>
#include "wifi_auth_center_test.h"
#include "permission_def.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
HWTEST_F(WifiAuthCenterTest, InitPermission_SUCCESS, TestSize.Level1)
{
    EXPECT_EQ(0, WifiAuthCenter::GetInstance().InitPermission(pid, uid));
}

static OHOS::Wifi::PermissionDef g_wifiPermissions[ARRAY_PERMISSION] = {
    {"ohos.permission.GET_WIFI_INFO", USER_GRANT, NOT_RESTRICTED},
    {"ohos.permission.SET_WIFI_INFO", USER_GRANT, NOT_RESTRICTED},
    {"ohos.permission.GET_WIFI_CONFIG", USER_GRANT, NOT_RESTRICTED},
    {"ohos.permission.MANAGE_WIFI_CONNECTION", USER_GRANT, NOT_RESTRICTED},
    {"ohos.permission.MANAGE_WIFI_HOTSPOT", USER_GRANT, NOT_RESTRICTED},
    {"ohos.permission.MANAGE_ENHANCER_WIFI", USER_GRANT, NOT_RESTRICTED},
    {"ohos.permission.GET_WIFI_LOCAL_MAC", USER_GRANT, NOT_RESTRICTED},
    {"ohos.permission.LOCATION", USER_GRANT, NOT_RESTRICTED},
    {"ohos.permission.GET_P2P_DEVICE_LOCATION", USER_GRANT, NOT_RESTRICTED},
};

HWTEST_F(WifiAuthCenterTest, ChangePermission_SUCCESS, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid));
}

HWTEST_F(WifiAuthCenterTest, CheckChangePermission_GRANTED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifySetWifiInfoPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, CheckChangePermission_DENIED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {0};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifySetWifiInfoPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, CheckAccessPermission_GRANTED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiInfoPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, CheckAccessPermission_DENIED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {0};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiInfoPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, CheckAccessScanInfosPermission_GRANTED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetScanInfosPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, CheckAccessScanInfosPermission_DENIED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {0};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetScanInfosPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, CheckGetLocalMacAddressPermission_GRANTED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiLocalMacPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, CheckGetLocalMacAddressPermission_DENIED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {0};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiLocalMacPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, CheckNetworkStackPermission_GRANTED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyWifiConnectionPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, CheckNetworkStackPermission_DENIED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {0};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyWifiConnectionPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, CheckNetworkStackOrSettingsPermission_GRANTED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyWifiConnectionPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, CheckNetworkStackOrSettingsPermission_DENIED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {0};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyWifiConnectionPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, CheckNetworkSettingsPermission_GRANTED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyWifiConnectionPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, CheckNetworkSettingsPermission_DENIED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {0};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyWifiConnectionPermission(pid, uid));
}
HWTEST_F(WifiAuthCenterTest, SetWifiConfigPermission_GRANTED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifySetWifiConfigPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, SetWifiConfigPermission_DENIED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {0};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifySetWifiConfigPermission(pid, uid));
}
HWTEST_F(WifiAuthCenterTest, GetWifiConfigPermission_GRANTED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiConfigPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, GetWifiConfigPermission_DENIED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {0};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiConfigPermission(pid, uid));
}
HWTEST_F(WifiAuthCenterTest, GetWifiDirectPermission_GRANTED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiDirectDevicePermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, GetWifiDirectPermission_DENIED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {0};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiDirectDevicePermission(pid, uid));
}
HWTEST_F(WifiAuthCenterTest, WifiHotspotPermission_GRANTED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyManageWifiHotspotPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, WifiHotspotPermission_DENIED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {0};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyManageWifiHotspotPermission(pid, uid));
}
HWTEST_F(WifiAuthCenterTest, GetWifiPeersMacPermission_GRANTED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiPeersMacPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, GetWifiPeersMacPermission_DENIED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {0};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiPeersMacPermission(pid, uid));
}
HWTEST_F(WifiAuthCenterTest, GetWifiInfoPermission_GRANTED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiInfoInternalPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, GetWifiInfoPermission_DENIED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {0};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiInfoInternalPermission(pid, uid));
}
HWTEST_F(WifiAuthCenterTest, HotspotExtPermission_GRANTED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {1, 1, 1, 1, 1, 1, 1, 1, 1};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyManageWifiHotspotExtPermission(pid, uid));
}

HWTEST_F(WifiAuthCenterTest, HotspotExtPermission_DENIED, TestSize.Level1)
{
    std::map<std::string, int> permissions;
    int num[ARRAY_PERMISSION] = {0};
    for (int i = 0; i < ARRAY_PERMISSION; i++) {
        permissions[g_wifiPermissions[i].name] = num[i];
    }
    WifiAuthCenter::GetInstance().ChangePermission(permissions, pid, uid);
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyManageWifiHotspotExtPermission(pid, uid));
}
}  // namespace Wifi
}  // namespace OHOS