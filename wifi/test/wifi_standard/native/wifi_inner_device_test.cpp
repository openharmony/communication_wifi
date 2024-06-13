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
#include "inner_api/wifi_device.h"
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
DEFINE_WIFILOG_LABEL("WifiInnerDeviceTest");

namespace OHOS {
namespace Wifi {
constexpr int NETWORKID = 0;
static std::string PROTECTNAME = "test1";
static std::string COUNTRYCODE = "86";
static std::shared_ptr<WifiDevice> devicePtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);

class WifiInnerDeviceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(WifiInnerDeviceTest, InitWifiProtectTest, TestSize.Level1)
{
    WIFI_LOGE("InitWifiProtectTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ErrCode result = devicePtr->InitWifiProtect(WifiProtectType::WIFI_PROTECT_MULTICAST, PROTECTNAME);
    WIFI_LOGE("InitWifiProtectTest result(0x%{public}x)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, GetWifiProtectRefTest, TestSize.Level1)
{
    WIFI_LOGE("GetWifiProtectRefTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ErrCode result = devicePtr->GetWifiProtectRef(WifiProtectMode::WIFI_PROTECT_FULL, PROTECTNAME);
    WIFI_LOGE("GetWifiProtectRefTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, PutWifiProtectRefTest, TestSize.Level1)
{
    WIFI_LOGE("PutWifiProtectRefTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ErrCode result = devicePtr->PutWifiProtectRef(PROTECTNAME);
    WIFI_LOGE("PutWifiProtectRefTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, RemoveCandidateConfigTest, TestSize.Level1)
{
    WIFI_LOGE("RemoveCandidateConfigTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ErrCode result = devicePtr->RemoveCandidateConfig(NETWORKID);
    WIFI_LOGE("RemoveCandidateConfigTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}
 
HWTEST_F(WifiInnerDeviceTest, RemoveCandidateConfig2Test, TestSize.Level1)
{
    WIFI_LOGE("RemoveCandidateConfig2Test enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    WifiDeviceConfig config;
    ErrCode result = devicePtr->RemoveCandidateConfig(config);
    WIFI_LOGE("RemoveCandidateConfig2Test result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, UpdateDeviceConfigTest, TestSize.Level1)
{
    WIFI_LOGE("UpdateDeviceConfigTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    WifiDeviceConfig config;
    int ret;
    ErrCode result = devicePtr->UpdateDeviceConfig(config, ret);
    WIFI_LOGE("UpdateDeviceConfigTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, RemoveAllDeviceTest, TestSize.Level1)
{
    WIFI_LOGE("RemoveAllDeviceTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ErrCode result = devicePtr->RemoveAllDevice();
    WIFI_LOGE("RemoveAllDeviceTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, EnableDeviceConfigTest, TestSize.Level1)
{
    WIFI_LOGE("EnableDeviceConfigTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ErrCode result = devicePtr->EnableDeviceConfig(NETWORKID, true);
    WIFI_LOGE("EnableDeviceConfigTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, DisableDeviceConfigTest, TestSize.Level1)
{
    WIFI_LOGE("DisableDeviceConfigTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ErrCode result = devicePtr->DisableDeviceConfig(NETWORKID);
    WIFI_LOGE("DisableDeviceConfigTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, IsConnectedTest, TestSize.Level1)
{
    WIFI_LOGE("IsConnectedTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    bool isConnected = false;
    ErrCode result = devicePtr->IsConnected(isConnected);
    WIFI_LOGE("IsConnectedTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, ReConnectTest, TestSize.Level1)
{
    WIFI_LOGE("ReConnectTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ErrCode result = devicePtr->ReConnect();
    WIFI_LOGE("ReConnectTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, ReAssociateTest, TestSize.Level1)
{
    WIFI_LOGE("ReAssociateTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ErrCode result = devicePtr->ReAssociate();
    WIFI_LOGE("ReAssociateTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, GetWifiStateTest, TestSize.Level1)
{
    WIFI_LOGE("GetWifiStateTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    int state;
    ErrCode result = devicePtr->GetWifiState(state);
    WIFI_LOGE("GetWifiStateTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, GetDisconnectedReasonTest, TestSize.Level1)
{
    WIFI_LOGE("GetDisconnectedReasonTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    DisconnectedReason reason;
    ErrCode result = devicePtr->GetDisconnectedReason(reason);
    WIFI_LOGE("GetDisconnectedReasonTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, GetIpv6InfoTest, TestSize.Level1)
{
    WIFI_LOGE("GetIpv6InfoTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    IpV6Info info;
    ErrCode result = devicePtr->GetIpv6Info(info);
    WIFI_LOGE("GetIpv6InfoTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, SetCountryCodeTest, TestSize.Level1)
{
    WIFI_LOGE("SetCountryCodeTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ErrCode result = devicePtr->SetCountryCode(COUNTRYCODE);
    WIFI_LOGE("SetCountryCodeTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, GetCountryCodeTest, TestSize.Level1)
{
    WIFI_LOGE("GetCountryCodeTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    std::string countryCode;
    ErrCode result = devicePtr->GetCountryCode(countryCode);
    WIFI_LOGE("GetCountryCodeTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, GetSupportedFeaturesTest, TestSize.Level1)
{
    WIFI_LOGE("GetSupportedFeaturesTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    long features;
    ErrCode result = devicePtr->GetSupportedFeatures(features);
    WIFI_LOGE("GetSupportedFeaturesTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, SetAppFrozenTest, TestSize.Level1)
{
    WIFI_LOGE("SetAppFrozenTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    std::set<int> pidList;
    pidList.insert(1011);
    pidList.insert(1012);
    ErrCode result = devicePtr->SetAppFrozen(pidList, true);
    WIFI_LOGE("SetAppFrozenTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiInnerDeviceTest, ResetAllFrozenAppTest, TestSize.Level1)
{
    WIFI_LOGE("ResetAllFrozenAppTest enter!");
    EXPECT_TRUE(devicePtr != nullptr);
    ErrCode result = devicePtr->ResetAllFrozenApp();
    WIFI_LOGE("ResetAllFrozenAppTest result(0x%{public}x)", result);
    EXPECT_GE(result, WIFI_OPT_SUCCESS);
}
} // namespace Wifi
} // namespace OHOS