/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <cstdio>
#include <gtest/gtest.h>
#include "wifi_hdi_wpa_callback.h"
#include "wifi_log.h"

using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
constexpr int PD_STATUS_CODE_SHOW_PIN = 0;
constexpr int PD_STATUS_CODE_ENTER_PIN = 1;
constexpr int PD_STATUS_CODE_PBC_REQ = 2;
constexpr int PD_STATUS_CODE_PBC_RSP = 3;
constexpr int PD_STATUS_CODE_FAIL = 4;

class WifiHdiWpaCallbackTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(WifiHdiWpaCallbackTest, OnEventBssidChangedTest, TestSize.Level1)
{
    struct HdiWpaBssidChangedParam bssidChangedParam;
    bssidChangedParam.bssidLen = 17;

    int32_t result = OnEventBssidChanged(nullptr, &bssidChangedParam, "wlan0");
    EXPECT_EQ(result, 1);
    result = OnEventBssidChanged(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);

    bssidChangedParam.bssid = nullptr;
    bssidChangedParam.bssidLen = 0;
    result = OnEventBssidChanged(nullptr, &bssidChangedParam, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventTempDisabledTest, TestSize.Level1)
{
    struct HdiWpaTempDisabledParam tempDisabledParam;
    int32_t result = OnEventTempDisabled(nullptr, &tempDisabledParam, "wlan0");
    EXPECT_EQ(result, 0);
    result = OnEventTempDisabled(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventAssociateRejectTEST, TestSize.Level1)
{
    struct HdiWpaAssociateRejectParam associateRejectParam;
    associateRejectParam.statusCode = 1;
    int32_t result = OnEventAssociateReject(nullptr, &associateRejectParam, "wlan0");
    EXPECT_EQ(result, 0);
    result = OnEventAssociateReject(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventDeviceFoundTest, TestSize.Level1)
{
    struct HdiP2pDeviceInfoParam deviceInfoParam;
    deviceInfoParam.srcAddressLen = 17;
    deviceInfoParam.p2pDeviceAddressLen = 17;
    deviceInfoParam.configMethods = 1;
    deviceInfoParam.deviceCapabilities = 2;
    deviceInfoParam.groupCapabilities = 3;
    deviceInfoParam.wfdDeviceInfo = nullptr;
    deviceInfoParam.wfdLength = 0;

    int32_t result = OnEventDeviceFound(nullptr, &deviceInfoParam, "wlan0");
    EXPECT_EQ(result, 0);
    result = OnEventDeviceFound(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventGroupStartedTest, TestSize.Level1)
{
    struct HdiP2pGroupStartedParam groupStartedParam;
    groupStartedParam.isGo = 1;
    groupStartedParam.isPersistent = 1;
    groupStartedParam.frequency = 2412;
    groupStartedParam.goDeviceAddressLen = 17;

    int32_t result = OnEventGroupStarted(nullptr, &groupStartedParam, "wlan0");
    EXPECT_EQ(result, 0);
    result = OnEventGroupStarted(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventProvisionDiscoveryCompletedTest_01, TestSize.Level1)
{
    struct HdiP2pProvisionDiscoveryCompletedParam provisionDiscoveryCompletedParam;
    provisionDiscoveryCompletedParam.provDiscStatusCode = PD_STATUS_CODE_SHOW_PIN;
    provisionDiscoveryCompletedParam.p2pDeviceAddressLen = 17;

    int32_t result = OnEventProvisionDiscoveryCompleted(nullptr, &provisionDiscoveryCompletedParam, "wlan0");
    EXPECT_EQ(result, 0);
    result = OnEventProvisionDiscoveryCompleted(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventProvisionDiscoveryCompletedTest_02, TestSize.Level1)
{
    struct HdiP2pProvisionDiscoveryCompletedParam provisionDiscoveryCompletedParam;
    provisionDiscoveryCompletedParam.provDiscStatusCode = PD_STATUS_CODE_ENTER_PIN;
    provisionDiscoveryCompletedParam.p2pDeviceAddressLen = 17;

    int32_t result = OnEventProvisionDiscoveryCompleted(nullptr, &provisionDiscoveryCompletedParam, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventProvisionDiscoveryCompletedTest_03, TestSize.Level1)
{
    struct HdiP2pProvisionDiscoveryCompletedParam provisionDiscoveryCompletedParam;
    provisionDiscoveryCompletedParam.provDiscStatusCode = PD_STATUS_CODE_PBC_REQ;
    provisionDiscoveryCompletedParam.p2pDeviceAddressLen = 17;

    int32_t result = OnEventProvisionDiscoveryCompleted(nullptr, &provisionDiscoveryCompletedParam, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventProvisionDiscoveryCompletedTest_04, TestSize.Level1)
{
    struct HdiP2pProvisionDiscoveryCompletedParam provisionDiscoveryCompletedParam;
    provisionDiscoveryCompletedParam.provDiscStatusCode = PD_STATUS_CODE_PBC_RSP;
    provisionDiscoveryCompletedParam.p2pDeviceAddressLen = 17;

    int32_t result = OnEventProvisionDiscoveryCompleted(nullptr, &provisionDiscoveryCompletedParam, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventProvisionDiscoveryCompletedTest_05, TestSize.Level1)
{
    struct HdiP2pProvisionDiscoveryCompletedParam provisionDiscoveryCompletedParam;
    provisionDiscoveryCompletedParam.provDiscStatusCode = PD_STATUS_CODE_FAIL;

    int32_t result = OnEventProvisionDiscoveryCompleted(nullptr, &provisionDiscoveryCompletedParam, "wlan0");
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventServDiscReq_01, TestSize.Level1)
{
    struct HdiP2pServDiscReqInfoParam servDiscReqInfoParam;
    servDiscReqInfoParam.freq = 2412;
    servDiscReqInfoParam.dialogToken = 1;
    servDiscReqInfoParam.updateIndic = 2;
    servDiscReqInfoParam.macLen = 6;
    servDiscReqInfoParam.mac = new uint8_t[servDiscReqInfoParam.macLen];
    memcpy_s(servDiscReqInfoParam.mac, servDiscReqInfoParam.macLen, "\x00\x11\x22\x33\x44\x55", 6);
    servDiscReqInfoParam.tlvsLen = 4;
    servDiscReqInfoParam.tlvs = new uint8_t[servDiscReqInfoParam.tlvsLen];
    memcpy_s(servDiscReqInfoParam.tlvs, servDiscReqInfoParam.tlvsLen, "x01x02x03x04", 4);

    int32_t result = OnEventServDiscReq(nullptr, &servDiscReqInfoParam, "wlan0");
    EXPECT_EQ(result, 0);
    result = OnEventServDiscReq(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);

    delete[] servDiscReqInfoParam.mac;
    delete[] servDiscReqInfoParam.tlvs;
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventStaConnectState_01, TestSize.Level1)
{
    struct HdiP2pStaConnectStateParam staConnectStateParam;
    staConnectStateParam.p2pDeviceAddressLen = 17;
    staConnectStateParam.state = 1;

    int32_t result = OnEventStaConnectState(nullptr, &staConnectStateParam, "wlan0");
    EXPECT_EQ(result, 0);
    result = OnEventStaConnectState(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaCallbackTest, OnEventStaConnectState_02, TestSize.Level1)
{
    struct HdiP2pStaConnectStateParam staConnectStateParam;
    staConnectStateParam.p2pDeviceAddressLen = 17;
    staConnectStateParam.state = 0;

    int32_t result = OnEventStaConnectState(nullptr, &staConnectStateParam, "wlan0");
    EXPECT_EQ(result, 0);

    staConnectStateParam.state = 1;
    result = OnEventStaConnectState(nullptr, &staConnectStateParam, "wlan0");
    EXPECT_EQ(result, 0);

    result = OnEventStaConnectState(nullptr, nullptr, "wlan0");
    EXPECT_EQ(result, 1);
}
} // namespace Wifi
} // namespace OHOS