/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "cJSON.h"
#include "wifi_security_detect_test.h"

using namespace testing::ext;
namespace OHOS {
namespace Wifi {

HWTEST_F(WifiSecurityDetectTest, DealStaConnChangedTest01, TestSize.Level1)
{
    OperateResState state = OperateResState::CONNECT_NETWORK_ENABLED;
    WifiLinkedInfo info;
    info.networkId = 1;
    int instId = 1;
    wifiSecurityDetect_->DealStaConnChanged(state, info, instId);
    EXPECT_EQ(wifiSecurityDetect_->networkDetecting_, true);
}

HWTEST_F(WifiSecurityDetectTest, DealStaConnChangedTest02, TestSize.Level1)
{
    OperateResState state = OperateResState::DISCONNECT_DISCONNECTED;
    WifiLinkedInfo info;
    info.networkId = 1;
    int instId = 1;
    wifiSecurityDetect_->DealStaConnChanged(state, info, instId);
    EXPECT_EQ(wifiSecurityDetect_->currentConnectedNetworkId_, -1);
}

HWTEST_F(WifiSecurityDetectTest, DealStaConnChangedTest03, TestSize.Level1)
{
    OperateResState state = OperateResState::CLOSE_WIFI_SUCCEED;
    WifiLinkedInfo info;
    info.networkId = 1;
    int instId = 1;
    wifiSecurityDetect_->DealStaConnChanged(state, info, instId);
    EXPECT_EQ(wifiSecurityDetect_->currentConnectedNetworkId_, -1);
}

HWTEST_F(WifiSecurityDetectTest, AuthenticationConvertTest01, TestSize.Level1)
{
    int32_t result = wifiSecurityDetect_->AuthenticationConvert(KEY_MGMT_NONE);
    EXPECT_EQ(result, SecurityType::SECURITY_TYPE_OPEN);
}

HWTEST_F(WifiSecurityDetectTest, AuthenticationConvertTest02, TestSize.Level1)
{
    int32_t result = wifiSecurityDetect_->AuthenticationConvert(KEY_MGMT_WEP);
    EXPECT_EQ(result, SecurityType::SECURITY_TYPE_WEP);
}

HWTEST_F(WifiSecurityDetectTest, AuthenticationConvertTest03, TestSize.Level1)
{
    int32_t result = wifiSecurityDetect_->AuthenticationConvert(KEY_MGMT_WPA_PSK);
    EXPECT_EQ(result, SecurityType::SECURITY_TYPE_PSK);
}

HWTEST_F(WifiSecurityDetectTest, AuthenticationConvertTest04, TestSize.Level1)
{
    int32_t result = wifiSecurityDetect_->AuthenticationConvert(KEY_MGMT_SAE);
    EXPECT_EQ(result, SecurityType::SECURITY_TYPE_SAE);
}

HWTEST_F(WifiSecurityDetectTest, AuthenticationConvertTest05, TestSize.Level1)
{
    int32_t result = wifiSecurityDetect_->AuthenticationConvert(KEY_MGMT_EAP);
    EXPECT_EQ(result, SecurityType::SECURITY_TYPE_EAP);
}

HWTEST_F(WifiSecurityDetectTest, AuthenticationConvertTest06, TestSize.Level1)
{
    int32_t result = wifiSecurityDetect_->AuthenticationConvert(KEY_MGMT_SUITE_B_192);
    EXPECT_EQ(result, SecurityType::SECURITY_TYPE_EAP_WPA3_ENTERPRISE_192_BIT);
}

HWTEST_F(WifiSecurityDetectTest, AuthenticationConvertTest07, TestSize.Level1)
{
    int32_t result = wifiSecurityDetect_->AuthenticationConvert(KEY_MGMT_WAPI_CERT);
    EXPECT_EQ(result, SecurityType::SECURITY_TYPE_WAPI_CERT);
}

HWTEST_F(WifiSecurityDetectTest, AuthenticationConvertTest08, TestSize.Level1)
{
    int32_t result = wifiSecurityDetect_->AuthenticationConvert(KEY_MGMT_WAPI_PSK);
    EXPECT_EQ(result, SecurityType::SECURITY_TYPE_WAPI_PSK);
}

HWTEST_F(WifiSecurityDetectTest, AuthenticationConvertTest09, TestSize.Level1)
{
    int32_t result = wifiSecurityDetect_->AuthenticationConvert("");
    EXPECT_EQ(result, -1);
}

HWTEST_F(WifiSecurityDetectTest, IsSettingSecurityDetectOnTest01, TestSize.Level1)
{
    bool result = wifiSecurityDetect_->IsSettingSecurityDetectOn();
    EXPECT_EQ(result, false);
}

HWTEST_F(WifiSecurityDetectTest, PopupNotificationTest01, TestSize.Level1)
{
    wifiSecurityDetect_->PopupNotification(WifiNotification::OPEN, 1);
    EXPECT_TRUE(wifiSecurityDetect_ != nullptr);
}

HWTEST_F(WifiSecurityDetectTest, PopupNotificationTest02, TestSize.Level1)
{
    wifiSecurityDetect_->PopupNotification(WifiNotification::CLOSE, 1);
    EXPECT_TRUE(wifiSecurityDetect_ != nullptr);
}

HWTEST_F(WifiSecurityDetectTest, AssembleUriTest, TestSize.Level1)
{
    Uri uri = wifiSecurityDetect_->AssembleUri("wifi_cloud_security_check");
    EXPECT_EQ(uri.ToString(),
        "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true&key=wifi_cloud_security_check");
}

}  // namespace Wifi
}  // namespace OHOS