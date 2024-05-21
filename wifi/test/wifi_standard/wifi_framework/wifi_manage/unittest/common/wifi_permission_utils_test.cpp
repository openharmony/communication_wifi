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
#include "wifi_permission_utils.h"
#include "wifi_auth_center.h"
#include "wifi_log.h"
#include "wifi_logger.h"
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
class WifiPermissionUtilsTest : public Test {
public:
    void SetUp() override
    {
        // Set up any necessary dependencies
    }

    void TearDown() override
    {
        // Clean up any dependencies
    }
};

HWTEST_F(WifiPermissionUtilsTest, VerifySetWifiInfoPermission_ReturnsPermissionGranted, TestSize.Level1)
{
    EXPECT_EQ(WifiPermissionUtils::VerifySetWifiInfoPermission(), PERMISSION_GRANTED);
}

HWTEST_F(WifiPermissionUtilsTest, VerifyGetWifiInfoPermission_ReturnsPermissionGranted, TestSize.Level1)
{
    EXPECT_EQ(WifiPermissionUtils::VerifyGetWifiInfoPermission(), PERMISSION_GRANTED);
}

HWTEST_F(WifiPermissionUtilsTest, VerifyWifiConnectionPermission_ReturnsPermissionGranted, TestSize.Level1)
{
    EXPECT_EQ(WifiPermissionUtils::VerifyWifiConnectionPermission(), PERMISSION_GRANTED);
}

HWTEST_F(WifiPermissionUtilsTest, VerifyGetScanInfosPermission_ReturnsPermissionGranted, TestSize.Level1)
{
    EXPECT_EQ(WifiPermissionUtils::VerifyGetScanInfosPermission(), PERMISSION_GRANTED);
}

HWTEST_F(WifiPermissionUtilsTest, VerifyGetWifiLocalMacPermission_ReturnsPermissionGranted, TestSize.Level1)
{
    EXPECT_EQ(WifiPermissionUtils::VerifyGetWifiLocalMacPermission(), PERMISSION_GRANTED);
}

HWTEST_F(WifiPermissionUtilsTest, VerifySetWifiConfigPermission_ReturnsPermissionGranted, TestSize.Level1)
{
    EXPECT_EQ(WifiPermissionUtils::VerifySetWifiConfigPermission(), PERMISSION_GRANTED);
}

HWTEST_F(WifiPermissionUtilsTest, VerifyGetWifiConfigPermission_ReturnsPermissionGranted, TestSize.Level1)
{
    EXPECT_EQ(WifiPermissionUtils::VerifyGetWifiConfigPermission(), PERMISSION_GRANTED);
}

HWTEST_F(WifiPermissionUtilsTest, VerifyGetWifiDirectDevicePermission_ReturnsPermissionGranted, TestSize.Level1)
{
    EXPECT_EQ(WifiPermissionUtils::VerifyGetWifiDirectDevicePermission(), PERMISSION_GRANTED);
}

HWTEST_F(WifiPermissionUtilsTest, VerifyManageWifiHotspotPermission_ReturnsPermissionGranted, TestSize.Level1)
{
    EXPECT_EQ(WifiPermissionUtils::VerifyManageWifiHotspotPermission(), PERMISSION_GRANTED);
}

HWTEST_F(WifiPermissionUtilsTest, VerifyGetWifiPeersMacPermission_ReturnsPermissionGranted, TestSize.Level1)
{
    EXPECT_EQ(WifiPermissionUtils::VerifyGetWifiPeersMacPermission(), PERMISSION_GRANTED);
}

HWTEST_F(WifiPermissionUtilsTest, VerifyGetWifiPeersMacPermissionEx_ReturnsPermissionGranted, TestSize.Level1)
{
    int pid = 123;
    int uid = 456;
    int tokenId = 789;
    EXPECT_EQ(WifiPermissionUtils::VerifyGetWifiPeersMacPermissionEx(pid, uid, tokenId), PERMISSION_GRANTED);
}

HWTEST_F(WifiPermissionUtilsTest, VerifyGetWifiInfoInternalPermission_ReturnsPermissionGranted, TestSize.Level1)
{
    EXPECT_EQ(WifiPermissionUtils::VerifyGetWifiInfoInternalPermission(), PERMISSION_GRANTED);
}

HWTEST_F(WifiPermissionUtilsTest, VerifyManageWifiHotspotExtPermission_ReturnsPermissionGranted, TestSize.Level1)
{
    EXPECT_EQ(WifiPermissionUtils::VerifyManageWifiHotspotExtPermission(), PERMISSION_GRANTED);
}