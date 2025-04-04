/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#include "kits/c/wifi_device.h"
#include "wifi_logger.h"
#include "mock_wifi_c_device.h"

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
DEFINE_WIFILOG_LABEL("WifiCDeviceStubTest");

namespace OHOS {
namespace Wifi {

constexpr int NETWORK_ID = 15;
constexpr int FREQUENCY = 2437;
constexpr int TIMESTAMP = -750366468;
constexpr int RSSI = 2;
constexpr int TYPE_OPEN = 0;
constexpr unsigned char BSSID[WIFI_MAC_LEN] = "test1";
constexpr int BAND = 2;
constexpr int ZERO = 0;

class WifiCDeviceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}

    void EnableWifiSuccess()
    {
        EXPECT_FALSE(EnableWifi() == WIFI_SUCCESS);
    }

    void DisableWifiSuccess()
    {
        EXPECT_FALSE(DisableWifi() == WIFI_SUCCESS);
    }

    void EnableSemiWifiSuccess()
    {
        EXPECT_FALSE(EnableSemiWifi() == WIFI_SUCCESS);
    }

    void IsWifiActiveEnable()
    {
        IsWifiActive();
        WifiDetailState state;
        EXPECT_TRUE(GetWifiDetailState(&state) != WIFI_SUCCESS);
    }

    void ScanSuccess()
    {
        EXPECT_FALSE(Scan() == WIFI_SUCCESS);
    }
   
    void GetScanInfoListSucess()
    {
        WifiScanInfo result;
        if (strcpy_s(result.ssid, sizeof(result.ssid), "networkId") != EOK) {
            return;
        }

        if (memcpy_s(result.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1) != EOK) {
            return;
        }
        result.securityType = TYPE_OPEN;
        result.rssi = RSSI;
        result.frequency = FREQUENCY;
        result.timestamp = TIMESTAMP;
        unsigned int mSize = 0;
        EXPECT_TRUE(GetScanInfoList(&result, &mSize) != WIFI_SUCCESS);
    }

    void GetWifiDetailStateSucess()
    {
        WifiDetailState state;
        EXPECT_TRUE(GetWifiDetailState(&state) != WIFI_SUCCESS);
    }

    void GetScanInfoListFail()
    {
        WifiScanInfo* result = nullptr;
        unsigned int mSize = 0;
        EXPECT_TRUE(GetScanInfoList(result, &mSize) != WIFI_SUCCESS);
    }

    void AddDeviceConfigSuccess()
    {
        int result = 0;
        WifiDeviceConfig config;
        if (strcpy_s(config.ssid, sizeof(config.ssid), "networkId") != EOK) {
            return;
        }

        if (memcpy_s(config.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1) != EOK) {
            return;
        }

        if (strcpy_s(config.preSharedKey, sizeof(config.preSharedKey), "12345678") != EOK) {
            return;
        }
        config.securityType = TYPE_OPEN;
        config.netId = NETWORK_ID;
        config.freq = FREQUENCY;
        EXPECT_TRUE(AddDeviceConfig(&config, &result) != WIFI_SUCCESS);
    }

    void AddDeviceConfigFail2()
    {
        WIFI_LOGI("AddDeviceConfigFail2 enter");
        int result = 0;
        WifiDeviceConfig config;
        if (strcpy_s(config.ssid, sizeof(config.ssid), "1networkId1networkId1networkId12") != EOK) {
            WIFI_LOGE("AddDeviceConfigFail2 strcpy_s ssid Fail!");
            return;
        }

        if (memcpy_s(config.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1) != EOK) {
            WIFI_LOGE("AddDeviceConfigFail2 memcpy_s bssid Fail!");
            return;
        }

        if (strcpy_s(config.preSharedKey, sizeof(config.preSharedKey), "12345678") != EOK) {
            WIFI_LOGE("AddDeviceConfigFail2 strcpy_s preSharedKey Fail!");
            return;
        }
        config.securityType = TYPE_OPEN;
        config.netId = NETWORK_ID;
        config.freq = FREQUENCY;
        EXPECT_TRUE(AddDeviceConfig(&config, &result) != WIFI_SUCCESS);
    }

    void AddDeviceConfigFail3()
    {
        WIFI_LOGI("AddDeviceConfigFail3 enter");
        int result = 0;
        WifiDeviceConfig config;
        if (strcpy_s(config.ssid, sizeof(config.ssid), "networkId") != EOK) {
            WIFI_LOGE("AddDeviceConfigFail3 strcpy_s ssid Fail!");
            return;
        }

        if (memcpy_s(config.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1) != EOK) {
            WIFI_LOGE("AddDeviceConfigFail3 memcpy_s bssid Fail!");
            return;
        }

        if (strcpy_s(config.preSharedKey, sizeof(config.preSharedKey),
            "1234567892123456789212345678921234567892123456789212345678921234") != EOK) {
            WIFI_LOGE("AddDeviceConfigFail3 strcpy_s preSharedKey Fail!");
            return;
        }
        config.securityType = TYPE_OPEN;
        config.netId = NETWORK_ID;
        config.freq = FREQUENCY;
        EXPECT_TRUE(AddDeviceConfig(&config, &result) != WIFI_SUCCESS);
    }

    void GetDeviceConfigsSuccess()
    {
        unsigned int mSize = 0;
        WifiDeviceConfig result;
        if (strcpy_s(result.ssid, sizeof(result.ssid), "networkId") != EOK) {
            return;
        }

        if (memcpy_s(result.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1) != EOK) {
            return;
        }

        if (strcpy_s(result.preSharedKey, sizeof(result.preSharedKey), "12345678") != EOK) {
            return;
        }
        result.securityType = TYPE_OPEN;
        result.netId = NETWORK_ID;
        result.freq = FREQUENCY;
        EXPECT_TRUE(GetDeviceConfigs(&result, &mSize) != WIFI_SUCCESS);
    }

    void GetDeviceConfigsFail()
    {
        WIFI_LOGI("GetDeviceConfigsFail enter");
        unsigned int mSize = 0;
        WifiDeviceConfig result;
        if (strcpy_s(result.ssid, sizeof(result.ssid), "networkId") != EOK) {
            WIFI_LOGE("GetDeviceConfigsFail strcpy_s ssid Fail!");
            return;
        }

        if (memcpy_s(result.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1) != EOK) {
            WIFI_LOGE("GetDeviceConfigsFail memcpy_s bssid Fail!");
            return;
        }

        if (strcpy_s(result.preSharedKey, sizeof(result.preSharedKey), "12345678") != EOK) {
            WIFI_LOGE("GetDeviceConfigsFail strcpy_s preSharedKey Fail!");
            return;
        }
        result.securityType = TYPE_OPEN;
        result.netId = NETWORK_ID;
        result.freq = FREQUENCY;
        EXPECT_CALL(WifiCDevice::GetInstance(), GetDeviceConfigs(_, _)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        EXPECT_TRUE(GetDeviceConfigs(&result, &mSize) != WIFI_SUCCESS);
    }

    void RemoveDeviceSuccess()
    {
        int networkId = NETWORK_ID;
        EXPECT_TRUE(RemoveDevice(networkId) != WIFI_SUCCESS);
    }

    void DisableDeviceConfigSuccess()
    {
        int networkId = NETWORK_ID;
        EXPECT_TRUE(DisableDeviceConfig(networkId) != WIFI_SUCCESS);
    }

    void EnableDeviceConfigSuccess()
    {
        int networkId = NETWORK_ID;
        EXPECT_TRUE(EnableDeviceConfig(networkId) != WIFI_SUCCESS);
    }

    void ConnectToSuccess()
    {
        int networkId = NETWORK_ID;
        EXPECT_TRUE(ConnectTo(networkId) != WIFI_SUCCESS);
    }
   
    void ConnectToDeviceSuccess()
    {
        WifiDeviceConfig config;
        if (strcpy_s(config.ssid, sizeof(config.ssid), "networkId") != EOK) {
            return;
        }

        if (memcpy_s(config.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1) != EOK) {
            return;
        }

        if (strcpy_s(config.preSharedKey, sizeof(config.preSharedKey), "12345678") != EOK) {
            return;
        }
        config.netId = NETWORK_ID;
        config.freq = FREQUENCY;
        EXPECT_TRUE(ConnectToDevice(&config) != WIFI_SUCCESS);
    }

    void ConnectToDeviceFail()
    {
        WIFI_LOGI("ConnectToDeviceFail enter");
        WifiDeviceConfig config;
        if (strcpy_s(config.ssid, sizeof(config.ssid), "1networkId1networkId1networkId12") != EOK) {
            WIFI_LOGE("ConnectToDeviceFail strcpy_s ssid Fail!");
            return;
        }

        if (memcpy_s(config.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1) != EOK) {
            WIFI_LOGE("ConnectToDeviceFail memcpy_s bssid Fail!");
            return;
        }

        if (strcpy_s(config.preSharedKey, sizeof(config.preSharedKey), "12345678") != EOK) {
            WIFI_LOGE("ConnectToDeviceFail strcpy_s preSharedKey Fail!");
            return;
        }
        config.netId = NETWORK_ID;
        config.freq = FREQUENCY;
        EXPECT_TRUE(ConnectToDevice(&config) != WIFI_SUCCESS);
    }

    void DisconnectSuccess()
    {
        EXPECT_TRUE(Disconnect() != WIFI_SUCCESS);
    }
 
    void GetLinkedInfoSuccess()
    {
        WifiLinkedInfo result;
        if (strcpy_s(result.ssid, sizeof(result.ssid), "networkId") != EOK) {
            return;
        }

        if (memcpy_s(result.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1) != EOK) {
            return;
        }
        result.frequency = FREQUENCY;
        result.connState = WIFI_CONNECTED;
        EXPECT_TRUE(GetLinkedInfo(&result) != WIFI_SUCCESS);
    }

    void GetDeviceMacAddressSuccess()
    {
        unsigned char result[WIFI_MAC_LEN] = {0};
        EXPECT_TRUE(GetDeviceMacAddress(result) != WIFI_SUCCESS);
    }

    void AdvanceScanSuccess()
    {
        WifiScanParams params;
        if (strcpy_s(params.ssid, sizeof(params.ssid), "networkId") != EOK) {
            return;
        }

        if (memcpy_s(params.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1) != EOK) {
            return;
        }
        params.scanType = WIFI_FREQ_SCAN;
        params.freqs = FREQUENCY;
        params.band = BAND;
        params.ssidLen = strlen(params.ssid);
        EXPECT_TRUE(AdvanceScan(&params) != WIFI_SUCCESS);
    }

    void GetIpInfoSuccess()
    {
        IpInfo info;
        EXPECT_TRUE(GetIpInfo(&info) != WIFI_SUCCESS);
    }

    void GetSignalLevelSuccess()
    {
        int rssi = RSSI;
        int band = BAND;
        EXPECT_EQ(GetSignalLevel(rssi, band), -1);
    }

    void SetLowLatencyModeTest()
    {
        EXPECT_TRUE(SetLowLatencyMode(true) == WIFI_SUCCESS);
        EXPECT_TRUE(SetLowLatencyMode(false) == WIFI_SUCCESS);
    }

    void IsBandTypeSupportedTest()
    {
        bool supported = false;
        EXPECT_TRUE(IsBandTypeSupported(BAND, &supported) != WIFI_SUCCESS);
    }

    void Get5GHzChannelListTest()
    {
        int result = ZERO;
        int size = ZERO;
        EXPECT_TRUE(Get5GHzChannelList(&result, &size) != WIFI_SUCCESS);
    }

    void StartPortalCertificationTest()
    {
        EXPECT_TRUE(StartPortalCertification() != WIFI_SUCCESS);
    }
};

HWTEST_F(WifiCDeviceTest, EnableWifiSuccess, TestSize.Level1)
{
    EnableWifiSuccess();
}

HWTEST_F(WifiCDeviceTest, DisableWifiSuccess, TestSize.Level1)
{
    DisableWifiSuccess();
}

HWTEST_F(WifiCDeviceTest, EnableSemiWifiSuccess, TestSize.Level1)
{
    EnableSemiWifiSuccess();
}

HWTEST_F(WifiCDeviceTest, IsWifiActiveEnable, TestSize.Level1)
{
    IsWifiActiveEnable();
}

HWTEST_F(WifiCDeviceTest, ScanSuccess, TestSize.Level1)
{
    ScanSuccess();
}

HWTEST_F(WifiCDeviceTest, GetScanInfoListSucess, TestSize.Level1)
{
    GetScanInfoListSucess();
}

HWTEST_F(WifiCDeviceTest, GetWifiDetailStateSucess, TestSize.Level1)
{
    GetWifiDetailStateSucess();
}

HWTEST_F(WifiCDeviceTest, GetScanInfoListFail, TestSize.Level1)
{
    GetScanInfoListFail();
}

HWTEST_F(WifiCDeviceTest, AddDeviceConfigSuccess, TestSize.Level1)
{
    AddDeviceConfigSuccess();
}

HWTEST_F(WifiCDeviceTest, AddDeviceConfigFail2, TestSize.Level1)
{
    AddDeviceConfigFail2();
}

HWTEST_F(WifiCDeviceTest, AddDeviceConfigFail3, TestSize.Level1)
{
    AddDeviceConfigFail3();
}

HWTEST_F(WifiCDeviceTest, GetDeviceConfigsSuccess, TestSize.Level1)
{
    GetDeviceConfigsSuccess();
}

HWTEST_F(WifiCDeviceTest, GetDeviceConfigsFail, TestSize.Level1)
{
    GetDeviceConfigsFail();
}

HWTEST_F(WifiCDeviceTest, RemoveDeviceSuccess, TestSize.Level1)
{
    RemoveDeviceSuccess();
}

HWTEST_F(WifiCDeviceTest, DisableDeviceConfigSuccess, TestSize.Level1)
{
    DisableDeviceConfigSuccess();
}

HWTEST_F(WifiCDeviceTest, EnableDeviceConfigSuccess, TestSize.Level1)
{
    EnableDeviceConfigSuccess();
}

HWTEST_F(WifiCDeviceTest, ConnectToSuccess, TestSize.Level1)
{
    ConnectToSuccess();
}

HWTEST_F(WifiCDeviceTest, ConnectToDeviceSuccess, TestSize.Level1)
{
    ConnectToDeviceSuccess();
}

HWTEST_F(WifiCDeviceTest, ConnectToDeviceFail, TestSize.Level1)
{
    ConnectToDeviceFail();
}

HWTEST_F(WifiCDeviceTest, DisconnectSuccess, TestSize.Level1)
{
    DisconnectSuccess();
}

HWTEST_F(WifiCDeviceTest, GetLinkedInfoSuccess, TestSize.Level1)
{
    GetLinkedInfoSuccess();
}

HWTEST_F(WifiCDeviceTest, GetDeviceMacAddressSuccess, TestSize.Level1)
{
    GetDeviceMacAddressSuccess();
}

HWTEST_F(WifiCDeviceTest, AdvanceScanSuccess, TestSize.Level1)
{
    AdvanceScanSuccess();
}

HWTEST_F(WifiCDeviceTest, GetIpInfoSuccess, TestSize.Level1)
{
    GetIpInfoSuccess();
}

HWTEST_F(WifiCDeviceTest, GetSignalLevelSuccess, TestSize.Level1)
{
    GetSignalLevelSuccess();
}

HWTEST_F(WifiCDeviceTest, SetLowLatencyModeTest, TestSize.Level1)
{
    SetLowLatencyModeTest();
}

HWTEST_F(WifiCDeviceTest, IsBandTypeSupportedTest, TestSize.Level1)
{
    IsBandTypeSupportedTest();
}

HWTEST_F(WifiCDeviceTest, Get5GHzChannelListTest, TestSize.Level1)
{
    Get5GHzChannelListTest();
}
} // namespace Wifi
} // namespace OHOS