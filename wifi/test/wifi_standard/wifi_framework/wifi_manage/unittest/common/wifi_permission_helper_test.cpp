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
constexpr int PID_NUM_1001 = 1001;
constexpr int UID_NUM_1001 = 1001;
static std::map<std::string, int> permissions = {
    {"ohos.permission.GET_WIFI_INFO", PERMISSION_DENIED},
    {"ohos.permission.SET_WIFI_INFO", PERMISSION_DENIED},
    {"ohos.permission.GET_WIFI_CONFIG", PERMISSION_DENIED},
    {"ohos.permission.MANAGE_WIFI_CONNECTION", PERMISSION_DENIED},
    {"ohos.permission.MANAGE_WIFI_HOTSPOT", PERMISSION_GRANTED},
    {"ohos.permission.GET_WIFI_LOCAL_MAC", PERMISSION_DENIED},
    {"ohos.permission.LOCATION", PERMISSION_DENIED},
    {"ohos.permission.MANAGE_WIFI_HOTSPOT_EXT", PERMISSION_DENIED},
};

class WifiPermissionHelperTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pid = PID_NUM_1001;
        uid = UID_NUM_1001;
        pWifiPermissionHelper = std::make_unique<WifiPermissionHelper>();
        pWifiPermissionHelper->InitPermission(pid, uid);
    }

    virtual void TearDown()
    {
        pWifiPermissionHelper.reset();
    }
public:
    int pid;
    int uid;
    std::unique_ptr<WifiPermissionHelper> pWifiPermissionHelper;
};
/**
 * @tc.name: ChangePermission001
 * @tc.desc: ChangePermission
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiPermissionHelperTest, ChangePermission001, TestSize.Level1)
{
    WIFI_LOGI("ChangePermission001 enter");
    EXPECT_TRUE(pWifiPermissionHelper->ChangePermission(permissions, pid, uid) == 0);
}
/**
 * @tc.name: ClearPermission001
 * @tc.desc: ClearPermission
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiPermissionHelperTest, ClearPermission001, TestSize.Level1)
{
    WIFI_LOGI("ClearPermission001 enter");
    EXPECT_TRUE(pWifiPermissionHelper->ClearPermission(pid, uid) == 0);
}
/**
 * @tc.name: MockVerifyPermission001
 * @tc.desc: MockVerifyPermission with error pid
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiPermissionHelperTest, MockVerifyPermission001, TestSize.Level1)
{
    WIFI_LOGI("MockVerifyPermission001 enter");
    std::string permissionName = "ohos.permission.MANAGE_WIFI_CONNECTION";
    EXPECT_TRUE(pWifiPermissionHelper->MockVerifyPermission(permissionName, 1, uid) == PERMISSION_DENIED);
}
/**
 * @tc.name: MockVerifyPermission002
 * @tc.desc: MockVerifyPermission with error permission
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiPermissionHelperTest, MockVerifyPermission002, TestSize.Level1)
{
    WIFI_LOGI("MockVerifyPermission002 enter");
    std::string permissionName = "test";
    EXPECT_TRUE(pWifiPermissionHelper->MockVerifyPermission(permissionName, pid, uid) == PERMISSION_DENIED);
}
/**
 * @tc.name: MockVerifyPermission003
 * @tc.desc: MockVerifyPermission with permission DENIED
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiPermissionHelperTest, MockVerifyPermission003, TestSize.Level1)
{
    WIFI_LOGI("MockVerifyPermission003 enter");
    std::string permissionName = "ohos.permission.MANAGE_WIFI_CONNECTION";
    EXPECT_TRUE(pWifiPermissionHelper->ChangePermission(permissions, pid, uid) == 0);
    EXPECT_TRUE(pWifiPermissionHelper->MockVerifyPermission(permissionName, pid, uid) == PERMISSION_DENIED);
}
/**
 * @tc.name: MockVerifyPermission004
 * @tc.desc: MockVerifyPermission with error uid
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiPermissionHelperTest, MockVerifyPermission004, TestSize.Level1)
{
    WIFI_LOGI("MockVerifyPermission004 enter");
    std::string permissionName = "ohos.permission.MANAGE_WIFI_HOTSPOT";
    EXPECT_TRUE(pWifiPermissionHelper->ChangePermission(permissions, pid, uid) == 0);
    EXPECT_TRUE(pWifiPermissionHelper->MockVerifyPermission(permissionName, pid, 1) == PERMISSION_DENIED);
}
/**
 * @tc.name: MockVerifyPermission005
 * @tc.desc: MockVerifyPermission with error permission
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiPermissionHelperTest, MockVerifyPermission005, TestSize.Level1)
{
    WIFI_LOGI("MockVerifyPermission005 enter");
    std::string permissionName = "test";
    EXPECT_TRUE(pWifiPermissionHelper->ChangePermission(permissions, pid, uid) == 0);
    EXPECT_TRUE(pWifiPermissionHelper->MockVerifyPermission(permissionName, pid, uid) == PERMISSION_DENIED);
}
/**
 * @tc.name: MockVerifyPermission006
 * @tc.desc: MockVerifyPermission with  permission DENIED
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiPermissionHelperTest, MockVerifyPermission006, TestSize.Level1)
{
    WIFI_LOGI("MockVerifyPermission006 enter");
    std::string permissionName = "ohos.permission.MANAGE_WIFI_CONNECTION";
    EXPECT_TRUE(pWifiPermissionHelper->ChangePermission(permissions, pid, uid) == 0);
    EXPECT_TRUE(pWifiPermissionHelper->MockVerifyPermission(permissionName, pid, uid) == PERMISSION_DENIED);
}
/**
 * @tc.name: MockVerifyPermission007
 * @tc.desc: MockVerifyPermission
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiPermissionHelperTest, MockVerifyPermission007, TestSize.Level1)
{
    WIFI_LOGI("MockVerifyPermission007 enter");
    std::string permissionName = "ohos.permission.MANAGE_WIFI_HOTSPOT";
    EXPECT_TRUE(pWifiPermissionHelper->MockVerifyPermission(permissionName, pid, uid) == PERMISSION_GRANTED);
}
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
    EXPECT_TRUE(pWifiPermissionHelper->VerifyPermission(permissionName, pid, uid) == PERMISSION_DENIED);
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
    EXPECT_TRUE(pWifiPermissionHelper->VerifySetWifiInfoPermission(pid, uid) == PERMISSION_DENIED);
    EXPECT_TRUE(pWifiPermissionHelper->VerifyGetWifiInfoPermission(pid, uid) == PERMISSION_DENIED);
    EXPECT_TRUE(pWifiPermissionHelper->VerifySetWifiConfigPermission(pid, uid) == PERMISSION_DENIED);
    EXPECT_TRUE(pWifiPermissionHelper->VerifyGetWifiConfigPermission(pid, uid) == PERMISSION_DENIED);
    EXPECT_TRUE(pWifiPermissionHelper->VerifyGetScanInfosPermission(pid, uid) == PERMISSION_DENIED);
    EXPECT_TRUE(pWifiPermissionHelper->VerifyGetWifiLocalMacPermission(pid, uid) == PERMISSION_DENIED);
    EXPECT_TRUE(pWifiPermissionHelper->VerifyWifiConnectionPermission(pid, uid) == PERMISSION_DENIED);
    EXPECT_TRUE(pWifiPermissionHelper->VerifyGetWifiDirectDevicePermission(pid, uid) == PERMISSION_DENIED);
    EXPECT_TRUE(pWifiPermissionHelper->VerifyManageWifiHotspotPermission(pid, uid) == PERMISSION_DENIED);
    EXPECT_TRUE(pWifiPermissionHelper->VerifyGetWifiPeersMacPermission(pid, uid) == PERMISSION_DENIED);
    EXPECT_TRUE(pWifiPermissionHelper->VerifyGetWifiInfoInternalPermission(pid, uid) == PERMISSION_DENIED);
    EXPECT_TRUE(pWifiPermissionHelper->VerifyManageWifiHotspotExtPermission(pid, uid) == PERMISSION_DENIED);
}
}  // namespace Wifi
}  // namespace OHOS