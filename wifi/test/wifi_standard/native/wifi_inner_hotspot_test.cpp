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
#include "inner_api/wifi_hotspot.h"
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
DEFINE_WIFILOG_LABEL("WifiInnerHotspotTest");

namespace OHOS {
namespace Wifi {
constexpr int TIME = 300;
static std::shared_ptr<WifiHotspot> devicePtr = WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);

class WifiInnerHotspotTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiInnerHotspotTest, IsHotspotDualBandSupportedTest, TestSize.Level1)
{
    WIFI_LOGE("IsHotspotDualBandSupportedTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    bool isSupported;
    ErrCode result = devicePtr->IsHotspotDualBandSupported(isSupported);
    WIFI_LOGE("IsHotspotDualBandSupportedTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, GetHotspotStateTest, TestSize.Level1)
{
    WIFI_LOGE("GetHotspotStateTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    int state;
    ErrCode result = devicePtr->GetHotspotState(state);
    WIFI_LOGE("GetHotspotStateTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, GetHotspotConfigTest, TestSize.Level1)
{
    WIFI_LOGE("GetHotspotConfigTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    HotspotConfig config;
    ErrCode result = devicePtr->GetHotspotConfig(config);
    WIFI_LOGE("GetHotspotConfigTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, SetHotspotConfigTest, TestSize.Level1)
{
    WIFI_LOGE("SetHotspotConfigTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    HotspotConfig config;
    ErrCode result = devicePtr->SetHotspotConfig(config);
    WIFI_LOGE("SetHotspotConfigTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, SetHotspotIdleTimeoutTest, TestSize.Level1)
{
    WIFI_LOGE("SetHotspotIdleTimeoutTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ErrCode result = devicePtr->SetHotspotIdleTimeout(TIME);
    WIFI_LOGE("SetHotspotIdleTimeoutTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, GetStationListTest, TestSize.Level1)
{
    WIFI_LOGE("GetStationListTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    std::vector<StationInfo> info;
    ErrCode result = devicePtr->GetStationList(info);
    WIFI_LOGE("GetStationListTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, DisassociateStaTest, TestSize.Level1)
{
    WIFI_LOGE("DisassociateStaTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    StationInfo info;
    ErrCode result = devicePtr->DisassociateSta(info);
    WIFI_LOGE("DisassociateStaTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, GetBlockListsTest, TestSize.Level1)
{
    WIFI_LOGE("GetBlockListsTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    std::vector<StationInfo> infos;
    ErrCode result = devicePtr->GetBlockLists(infos);
    WIFI_LOGE("GetBlockListsTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, AddBlockListTest, TestSize.Level1)
{
    WIFI_LOGE("AddBlockListTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    StationInfo info;
    ErrCode result = devicePtr->AddBlockList(info);
    WIFI_LOGE("AddBlockListTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, DelBlockListTest, TestSize.Level1)
{
    WIFI_LOGE("DelBlockListTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    StationInfo info;
    ErrCode result = devicePtr->DelBlockList(info);
    WIFI_LOGE("DelBlockListTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, GetValidBandsTest, TestSize.Level1)
{
    WIFI_LOGE("GetValidBandsTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    std::vector<BandType> bands;
    ErrCode result = devicePtr->GetValidBands(bands);
    WIFI_LOGE("GetValidBandsTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, GetValidChannelsTest, TestSize.Level1)
{
    WIFI_LOGE("GetValidChannelsTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    std::vector<int32_t> validchannels;
    ErrCode result = devicePtr->GetValidChannels(BandType::BAND_2GHZ, validchannels);
    WIFI_LOGE("GetValidChannelsTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, GetSupportedFeaturesTest, TestSize.Level1)
{
    WIFI_LOGE("GetSupportedFeaturesTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    long features;
    ErrCode result = devicePtr->GetSupportedFeatures(features);
    WIFI_LOGE("GetSupportedFeaturesTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, GetSupportedPowerModelTest, TestSize.Level1)
{
    WIFI_LOGE("GetSupportedPowerModelTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    std::set<PowerModel> setPowerModelList;
    ErrCode result = devicePtr->GetSupportedPowerModel(setPowerModelList);
    WIFI_LOGE("GetSupportedPowerModelTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, GetPowerModelTest, TestSize.Level1)
{
    WIFI_LOGE("GetPowerModelTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    PowerModel model;
    ErrCode result = devicePtr->GetPowerModel(model);
    WIFI_LOGE("GetPowerModelTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiInnerHotspotTest, SetPowerModelTest, TestSize.Level1)
{
    WIFI_LOGE("SetPowerModelTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ErrCode result = devicePtr->SetPowerModel(PowerModel::GENERAL);
    WIFI_LOGE("SetPowerModelTest result(0x%{public}x)", result);
    EXPECT_TRUE(result);
}
} // namespace Wifi
} // namespace OHOS