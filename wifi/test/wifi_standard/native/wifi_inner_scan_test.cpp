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
#include <gmock/gmock.h>
#include <cstddef>
#include <cstdint>
#include "securec.h"
#include "inner_api/wifi_msg.h"
#include "inner_api/wifi_scan.h"
#include "wifi_logger.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;
DEFINE_WIFILOG_LABEL("WifiInnerScanTest");

namespace OHOS {
namespace Wifi {
static std::shared_ptr<WifiScan> devicePtr = WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);

class WifiInnerScanTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiInnerScanTest, SetScanControlInfoTest, TestSize.Level1)
{
    WIFI_LOGE("SetScanControlInfoTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ScanControlInfo info;
    ErrCode result = devicePtr->SetScanControlInfo(info);
    WIFI_LOGE("SetScanControlInfoTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerScanTest, GetSupportedFeaturesTest, TestSize.Level1)
{
    WIFI_LOGE("GetSupportedFeaturesTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    long features;
    ErrCode result = devicePtr->GetSupportedFeatures(features);
    WIFI_LOGE("GetSupportedFeaturesTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerScanTest, SetScanOnlyAvailableTest, TestSize.Level1)
{
    WIFI_LOGE("SetScanOnlyAvailableTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ErrCode result = devicePtr->SetScanOnlyAvailable(true);
    WIFI_LOGE("SetScanOnlyAvailableTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerScanTest, GetScanOnlyAvailableTest, TestSize.Level1)
{
    WIFI_LOGE("GetScanOnlyAvailableTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    bool bScanOnlyAvailable = false;
    ErrCode result = devicePtr->GetScanOnlyAvailable(bScanOnlyAvailable);
    WIFI_LOGE("GetScanOnlyAvailableTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}
} // namespace Wifi
} // namespace OHOS