/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
 
#include "hid2d_service_registry_test.h"
 
using ::testing::ext::TestSize;
 
namespace OHOS {
namespace Wifi {
 
HWTEST_F(Hid2dServiceRegistryTest, IsHid2dServiceUid_True, TestSize.Level1)
{
    EXPECT_TRUE(IsHid2dServiceUid(SOFT_BUS_SERVICE_UID));
    EXPECT_TRUE(IsHid2dServiceUid(CAST_ENGINE_SERVICE_UID));
    EXPECT_TRUE(IsHid2dServiceUid(MIRACAST_SERVICE_UID));
    EXPECT_TRUE(IsHid2dServiceUid(SHARE_SERVICE_UID));
    EXPECT_TRUE(IsHid2dServiceUid(MOUSE_CROSS_SERVICE_UID));
    EXPECT_TRUE(IsHid2dServiceUid(GAMESERVICE_SA_UID));
    EXPECT_TRUE(IsHid2dServiceUid(WATCH_SERVICE_UID));
    EXPECT_TRUE(IsHid2dServiceUid(HICAR_SERVICE_UID));
}
 
HWTEST_F(Hid2dServiceRegistryTest, IsHid2dServiceUid_False, TestSize.Level1)
{
    EXPECT_FALSE(IsHid2dServiceUid(0));
    EXPECT_FALSE(IsHid2dServiceUid(9999));
    EXPECT_FALSE(IsHid2dServiceUid(-1));
}
 
HWTEST_F(Hid2dServiceRegistryTest, IsHid2dServiceSaId_True, TestSize.Level1)
{
    EXPECT_TRUE(IsHid2dServiceSaId(4700));
    EXPECT_TRUE(IsHid2dServiceSaId(65546));
    EXPECT_TRUE(IsHid2dServiceSaId(5527));
    EXPECT_TRUE(IsHid2dServiceSaId(2902));
    EXPECT_TRUE(IsHid2dServiceSaId(65569));
    EXPECT_TRUE(IsHid2dServiceSaId(66006));
    EXPECT_TRUE(IsHid2dServiceSaId(65872));
}
 
HWTEST_F(Hid2dServiceRegistryTest, IsHid2dServiceSaId_False, TestSize.Level1)
{
    EXPECT_FALSE(IsHid2dServiceSaId(0));
    EXPECT_FALSE(IsHid2dServiceSaId(9999));
    EXPECT_FALSE(IsHid2dServiceSaId(-1));
}
 
HWTEST_F(Hid2dServiceRegistryTest, FindServiceByUid_Valid, TestSize.Level1)
{
    const auto* entry = FindServiceByUid(SOFT_BUS_SERVICE_UID);
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(SOFT_BUS_SERVICE_UID, entry->uid);
    EXPECT_EQ("SoftBus", entry->serviceName);
    EXPECT_EQ(ScanLimitType::HID2D_SOFTBUS, entry->limitType);
    EXPECT_EQ(4700, entry->systemAbilityId);
    EXPECT_TRUE(entry->allowLpScan);
}
 
HWTEST_F(Hid2dServiceRegistryTest, FindServiceByUid_Invalid, TestSize.Level1)
{
    EXPECT_EQ(nullptr, FindServiceByUid(0));
    EXPECT_EQ(nullptr, FindServiceByUid(9999));
}
 
HWTEST_F(Hid2dServiceRegistryTest, FindServiceBySaId_Valid, TestSize.Level1)
{
    const auto* entry = FindServiceBySaId(65546);
    ASSERT_NE(nullptr, entry);
    EXPECT_EQ(CAST_ENGINE_SERVICE_UID, entry->uid);
    EXPECT_EQ("Cast", entry->serviceName);
    EXPECT_EQ(ScanLimitType::HID2D_CAST, entry->limitType);
    EXPECT_EQ(65546, entry->systemAbilityId);
    EXPECT_TRUE(entry->allowLpScan);
}
 
HWTEST_F(Hid2dServiceRegistryTest, FindServiceBySaId_Invalid, TestSize.Level1)
{
    EXPECT_EQ(nullptr, FindServiceBySaId(0));
    EXPECT_EQ(nullptr, FindServiceBySaId(9999));
}
 
HWTEST_F(Hid2dServiceRegistryTest, GetAllHid2dServiceUids_Size, TestSize.Level1)
{
    const auto& uids = GetAllHid2dServiceUids();
    EXPECT_EQ(8, uids.size());
}
 
HWTEST_F(Hid2dServiceRegistryTest, GetAllHid2dServiceUids_Content, TestSize.Level1)
{
    const auto& uids = GetAllHid2dServiceUids();
    EXPECT_NE(uids.end(), std::find(uids.begin(), uids.end(), SOFT_BUS_SERVICE_UID));
    EXPECT_NE(uids.end(), std::find(uids.begin(), uids.end(), CAST_ENGINE_SERVICE_UID));
    EXPECT_NE(uids.end(), std::find(uids.begin(), uids.end(), MIRACAST_SERVICE_UID));
    EXPECT_NE(uids.end(), std::find(uids.begin(), uids.end(), SHARE_SERVICE_UID));
    EXPECT_NE(uids.end(), std::find(uids.begin(), uids.end(), MOUSE_CROSS_SERVICE_UID));
    EXPECT_NE(uids.end(), std::find(uids.begin(), uids.end(), GAMESERVICE_SA_UID));
    EXPECT_NE(uids.end(), std::find(uids.begin(), uids.end(), WATCH_SERVICE_UID));
    EXPECT_NE(uids.end(), std::find(uids.begin(), uids.end(), HICAR_SERVICE_UID));
}
 
HWTEST_F(Hid2dServiceRegistryTest, GetHid2dServiceRegistry_Size, TestSize.Level1)
{
    const auto& registry = GetHid2dServiceRegistry();
    EXPECT_EQ(8, registry.size());
}
 
HWTEST_F(Hid2dServiceRegistryTest, GetHid2dServiceRegistry_NoLpScan, TestSize.Level1)
{
    const auto& registry = GetHid2dServiceRegistry();
    for (const auto& entry : registry) {
        if (entry.serviceName == "Share" ||
            entry.serviceName == "MouseCross" ||
            entry.serviceName == "Game" ||
            entry.serviceName == "Watch") {
            EXPECT_FALSE(entry.allowLpScan) << entry.serviceName << " should not allow LP scan";
        }
    }
}
 
}  // namespace Wifi
}  // namespace OHOS