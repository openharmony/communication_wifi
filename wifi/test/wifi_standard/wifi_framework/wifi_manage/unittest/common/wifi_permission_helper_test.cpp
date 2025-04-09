/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#include "wifi_permission_helper.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("WifiPermissionHelperTest");
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class WifiPermissionHelperTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pid = static_cast<int>(getpid());
        uid = static_cast<int>(getuid());
    }

    virtual void TearDown()
    {
    }
public:
    int pid;
    int uid;
};

/**
 * @tc.name: VerifyPermission001
 * @tc.desc: VerifyPermission
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiPermissionHelperTest, VerifyPermission001, TestSize.Level1)
{
    WIFI_LOGI("VerifyPermission001 enter");
    std::string permissionName = "ohos.permission.GET_WIFI_INFO";
    EXPECT_TRUE(WifiPermissionHelper::VerifyPermission(permissionName, pid, uid, 0) == PERMISSION_GRANTED);
}
/**
 * @tc.name: VerifyAllPermission001
 * @tc.desc: VerifyPermission
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiPermissionHelperTest, VerifyAllPermission001, TestSize.Level1)
{
    WIFI_LOGI("VerifyAllPermission001 enter");
    EXPECT_TRUE(WifiPermissionHelper::VerifySetWifiInfoPermission(pid, uid) == PERMISSION_GRANTED);
    EXPECT_TRUE(WifiPermissionHelper::VerifyGetWifiInfoPermission(pid, uid) == PERMISSION_GRANTED);
    EXPECT_TRUE(WifiPermissionHelper::VerifySetWifiConfigPermission(pid, uid) == PERMISSION_GRANTED);
    EXPECT_TRUE(WifiPermissionHelper::VerifyGetWifiConfigPermission(pid, uid) == PERMISSION_GRANTED);
    EXPECT_TRUE(WifiPermissionHelper::VerifyGetScanInfosPermission(pid, uid) == PERMISSION_GRANTED);
    EXPECT_TRUE(WifiPermissionHelper::VerifyGetWifiLocalMacPermission(pid, uid) == PERMISSION_GRANTED);
    EXPECT_TRUE(WifiPermissionHelper::VerifyWifiConnectionPermission(pid, uid) == PERMISSION_GRANTED);
    EXPECT_TRUE(WifiPermissionHelper::VerifyGetWifiDirectDevicePermission(pid, uid) == PERMISSION_GRANTED);
    EXPECT_TRUE(WifiPermissionHelper::VerifyManageWifiHotspotPermission(pid, uid) == PERMISSION_GRANTED);
    EXPECT_TRUE(WifiPermissionHelper::VerifyGetWifiPeersMacPermission(pid, uid) == PERMISSION_GRANTED);
    EXPECT_TRUE(WifiPermissionHelper::VerifyGetWifiInfoInternalPermission(pid, uid) == PERMISSION_GRANTED);
    EXPECT_TRUE(WifiPermissionHelper::VerifyManageWifiHotspotExtPermission(pid, uid) == PERMISSION_GRANTED);
}
}  // namespace Wifi
}  // namespace OHOS