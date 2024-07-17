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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "wifi_auth_center.h"
#include "wifi_permission_helper.h"

using namespace OHOS::Wifi;
using namespace testing;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;
class WifiAuthCenterTest : public Test {
public:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

HWTEST_F(WifiAuthCenterTest, VerifySetWifiInfoPermission, TestSize.Level1)
{
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifySetWifiInfoPermission(123, 456));
}

HWTEST_F(WifiAuthCenterTest, VerifyGetWifiInfoPermission, TestSize.Level1)
{
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiInfoPermission(123, 456));
}

HWTEST_F(WifiAuthCenterTest, VerifyGetScanInfosPermission, TestSize.Level1)
{
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetScanInfosPermission(123, 456));
}

HWTEST_F(WifiAuthCenterTest, VerifyGetWifiLocalMacPermission, TestSize.Level1)
{
    EXPECT_EQ(
        PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiLocalMacPermission(123, 456));
}

HWTEST_F(WifiAuthCenterTest, VerifyWifiConnectionPermission, TestSize.Level1)
{
    EXPECT_EQ(
        PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyWifiConnectionPermission(123, 456));
}

HWTEST_F(WifiAuthCenterTest, VerifySetWifiConfigPermission, TestSize.Level1)
{
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifySetWifiConfigPermission(123, 456));
}

HWTEST_F(WifiAuthCenterTest, VerifyGetWifiConfigPermission, TestSize.Level1)
{
    EXPECT_EQ(PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiConfigPermission(123, 456));
}

HWTEST_F(WifiAuthCenterTest, VerifyGetWifiDirectDevicePermission, TestSize.Level1)
{
    EXPECT_EQ(
        PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiDirectDevicePermission(123, 456));
}

HWTEST_F(WifiAuthCenterTest, VerifyManageWifiHotspotPermission, TestSize.Level1)
{
    EXPECT_EQ(
        PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyManageWifiHotspotPermission(123, 456));
}

HWTEST_F(WifiAuthCenterTest, VerifyGetWifiPeersMacPermission, TestSize.Level1)
{
    EXPECT_EQ(
        PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiPeersMacPermission(123, 456));
}

HWTEST_F(WifiAuthCenterTest, VerifyGetWifiPeersMacPermissionEx, TestSize.Level1)
{
    EXPECT_EQ(
        PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiPeersMacPermissionEx(123, 456, 789));
}

HWTEST_F(WifiAuthCenterTest, VerifyGetWifiInfoInternalPermission, TestSize.Level1)
{
    EXPECT_EQ(
        PERMISSION_GRANTED, WifiAuthCenter::GetInstance().VerifyGetWifiInfoInternalPermission(123, 456));
}

HWTEST_F(WifiAuthCenterTest, VerifyManageWifiHotspotExtPermission, TestSize.Level1)
{
    EXPECT_EQ(PERMISSION_GRANTED,
              WifiAuthCenter::GetInstance().VerifyManageWifiHotspotExtPermission(123, 456));
}

HWTEST_F(WifiAuthCenterTest, IsSystemAppByTokenTest001, TestSize.Level1)
{
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.IsSystemAppByToken(), true);
}

HWTEST_F(WifiAuthCenterTest, IsNativeProcessTest001, TestSize.Level1)
{
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.IsNativeProcess(), false);
}

HWTEST_F(WifiAuthCenterTest, VerifySetWifiInfoPermissionTest001, TestSize.Level1)
{
    #undef PERMISSION_ALWAYS_GRANT
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.VerifySetWifiInfoPermission(123, 456), PERMISSION_GRANTED);
}

HWTEST_F(WifiAuthCenterTest, VerifyGetWifiInfoPermissionTest001, TestSize.Level1)
{
    #undef PERMISSION_ALWAYS_GRANT
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.VerifyGetWifiInfoPermission(123, 456), PERMISSION_GRANTED);
}

HWTEST_F(WifiAuthCenterTest, VerifyGetScanInfosPermissionTest001, TestSize.Level1)
{
    #undef PERMISSION_ALWAYS_GRANT
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.VerifyGetScanInfosPermission(123, 456), PERMISSION_GRANTED);
}

HWTEST_F(WifiAuthCenterTest, VerifyGetWifiLocalMacPermissionTest001, TestSize.Level1)
{
    #undef PERMISSION_ALWAYS_GRANT
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.VerifyGetWifiLocalMacPermission(123, 456), PERMISSION_GRANTED);
}

HWTEST_F(WifiAuthCenterTest, VerifyWifiConnectionPermissionTest001, TestSize.Level1)
{
    #undef PERMISSION_ALWAYS_GRANT
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.VerifyWifiConnectionPermission(123, 456), PERMISSION_GRANTED);
}

HWTEST_F(WifiAuthCenterTest, VerifySetWifiConfigPermissionTest001, TestSize.Level1)
{
    #undef PERMISSION_ALWAYS_GRANT
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.VerifySetWifiConfigPermission(123, 456), PERMISSION_GRANTED);
}

HWTEST_F(WifiAuthCenterTest, VerifyGetWifiConfigPermissionTest001, TestSize.Level1)
{
    #undef PERMISSION_ALWAYS_GRANT
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.VerifyGetWifiConfigPermission(123, 456), PERMISSION_GRANTED);
}

HWTEST_F(WifiAuthCenterTest, VerifyGetWifiDirectDevicePermissionTest001, TestSize.Level1)
{
    #undef PERMISSION_ALWAYS_GRANT
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.VerifyGetWifiDirectDevicePermission(123, 456), PERMISSION_GRANTED);
}

HWTEST_F(WifiAuthCenterTest, VerifyManageWifiHotspotPermissionTest001, TestSize.Level1)
{
    #undef PERMISSION_ALWAYS_GRANT
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.VerifyManageWifiHotspotPermission(123, 456), PERMISSION_GRANTED);
}

HWTEST_F(WifiAuthCenterTest, VerifyGetWifiPeersMacPermissionTest001, TestSize.Level1)
{
    #undef PERMISSION_ALWAYS_GRANT
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.VerifyGetWifiPeersMacPermission(123, 456), PERMISSION_GRANTED);
}

HWTEST_F(WifiAuthCenterTest, VerifyGetWifiPeersMacPermissionExTest001, TestSize.Level1)
{
    #undef PERMISSION_ALWAYS_GRANT
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.VerifyGetWifiPeersMacPermissionEx(123, 456, 0), PERMISSION_GRANTED);
}

HWTEST_F(WifiAuthCenterTest, VerifyGetWifiInfoInternalPermissionExTest001, TestSize.Level1)
{
    #undef PERMISSION_ALWAYS_GRANT
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.VerifyGetWifiInfoInternalPermission(123, 456), PERMISSION_GRANTED);
}

HWTEST_F(WifiAuthCenterTest, VerifyManageWifiHotspotExtPermissionTest001, TestSize.Level1)
{
    #undef PERMISSION_ALWAYS_GRANT
    WifiAuthCenter wifiAuthCenter;
    EXPECT_EQ(wifiAuthCenter.VerifyManageWifiHotspotExtPermission(123, 456), PERMISSION_GRANTED);
}