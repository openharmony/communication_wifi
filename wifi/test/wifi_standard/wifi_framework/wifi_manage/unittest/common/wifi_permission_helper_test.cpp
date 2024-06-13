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
 * @tc.name: VerifyPermission001
 * @tc.desc: VerifyPermission
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(WifiPermissionHelperTest, VerifyPermission001, TestSize.Level1)
{
    WIFI_LOGI("VerifyPermission001 enter");
    std::string permissionName = "ohos.permission.GET_WIFI_INFO";
    EXPECT_TRUE(pWifiPermissionHelper->VerifyPermission(permissionName, pid, uid, 0) == PERMISSION_DENIED);
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