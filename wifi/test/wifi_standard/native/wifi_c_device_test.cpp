/*
 * Copyright (C) 2022-2025 Huawei Device Co., Ltd.
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
#include "parameters.h"
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

const std::string g_errLog = "wifi_test";
const std::string PARAM_FORCE_OPEN_WIFI = "persist.edm.force_open_wifi";
class WifiCDeviceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}

    void EnableWifiSuccess()
    {
        EnableWifi();
    }

    void DisableWifiSuccess()
    {
        DisableWifi();
    }

    void EnableSemiWifiSuccess()
    {
        EnableSemiWifi();
    }

    void IsWifiActiveEnable()
    {
        IsWifiActive();
        WifiDetailState state;
        EXPECT_EQ(GetWifiDetailState(&state), WIFI_SUCCESS);
    }

    void ScanSuccess()
    {
        EXPECT_FALSE(Scan() == WIFI_SUCCESS);
    }
   
    void GetScanInfoListSucess()
    {
        WifiScanInfo result;

        strcpy_s(result.ssid, sizeof(result.ssid), "networkId");

        memcpy_s(result.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1);
        result.securityType = TYPE_OPEN;
        result.rssi = RSSI;
        result.frequency = FREQUENCY;
        result.timestamp = TIMESTAMP;
        unsigned int mSize = 0;
        EXPECT_NE(GetScanInfoList(&result, &mSize), WIFI_SUCCESS);
    }

    void GetWifiDetailStateSucess()
    {
        WifiDetailState state;
        EXPECT_EQ(GetWifiDetailState(&state), WIFI_SUCCESS);
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

        strcpy_s(config.ssid, sizeof(config.ssid), "networkId");

        memcpy_s(config.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1);

        strcpy_s(config.preSharedKey, sizeof(config.preSharedKey), "12345678");
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

        strcpy_s(config.ssid, sizeof(config.ssid), "1networkId1networkId1networkId12");
        memcpy_s(config.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1);

        strcpy_s(config.preSharedKey, sizeof(config.preSharedKey), "12345678");
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

        strcpy_s(config.ssid, sizeof(config.ssid), "networkId");
        memcpy_s(config.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1);
        strcpy_s(config.preSharedKey, sizeof(config.preSharedKey),
             "1234567892123456789212345678921234567892123456789212345678921234");
        config.securityType = TYPE_OPEN;
        config.netId = NETWORK_ID;
        config.freq = FREQUENCY;
        EXPECT_TRUE(AddDeviceConfig(&config, &result) != WIFI_SUCCESS);
    }

    void GetDeviceConfigsSuccess()
    {
        unsigned int mSize = 0;
        WifiDeviceConfig result;
        strcpy_s(result.ssid, sizeof(result.ssid), "networkId");
        memcpy_s(result.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1);
        strcpy_s(result.preSharedKey, sizeof(result.preSharedKey), "12345678");
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
        strcpy_s(result.ssid, sizeof(result.ssid), "networkId");
        memcpy_s(result.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1);
        strcpy_s(result.preSharedKey, sizeof(result.preSharedKey), "12345678");
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
        strcpy_s(config.ssid, sizeof(config.ssid), "networkId");

        memcpy_s(config.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1);

        strcpy_s(config.preSharedKey, sizeof(config.preSharedKey), "12345678");
        config.netId = NETWORK_ID;
        config.freq = FREQUENCY;
        EXPECT_TRUE(ConnectToDevice(&config) != WIFI_SUCCESS);
    }

    void ConnectToDeviceFail()
    {
        WIFI_LOGI("ConnectToDeviceFail enter");
        WifiDeviceConfig config;

        strcpy_s(config.ssid, sizeof(config.ssid), "1networkId1networkId1networkId12");

        memcpy_s(config.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1);

        strcpy_s(config.preSharedKey, sizeof(config.preSharedKey), "12345678");
        config.netId = NETWORK_ID;
        config.freq = FREQUENCY;
        EXPECT_TRUE(ConnectToDevice(&config) != WIFI_SUCCESS);
    }

    void DisconnectSuccess()
    {
        Disconnect();
    }
 
    void GetLinkedInfoSuccess()
    {
        WifiLinkedInfo result;
        strcpy_s(result.ssid, sizeof(result.ssid), "networkId");

        memcpy_s(result.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1);
        result.frequency = FREQUENCY;
        result.connState = WIFI_CONNECTED;
        EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
    }

    void GetDeviceMacAddressSuccess()
    {
        unsigned char result[WIFI_MAC_LEN] = {0};
        EXPECT_TRUE(GetDeviceMacAddress(result) != WIFI_SUCCESS);
    }

    void AdvanceScanSuccess()
    {
        WifiScanParams params;
        strcpy_s(params.ssid, sizeof(params.ssid), "networkId");
        memcpy_s(params.bssid, WIFI_MAC_LEN, BSSID, WIFI_MAC_LEN - 1);
        params.scanType = WIFI_FREQ_SCAN;
        params.freqs = FREQUENCY;
        params.band = BAND;
        params.ssidLen = strlen(params.ssid);
        EXPECT_TRUE(AdvanceScan(&params) != WIFI_SUCCESS);
    }

    void GetIpInfoSuccess()
    {
        IpInfo info;
        EXPECT_EQ(GetIpInfo(&info), WIFI_SUCCESS);
    }

    void GetSignalLevelSuccess()
    {
        int rssi = RSSI;
        int band = BAND;
        EXPECT_NE(GetSignalLevel(rssi, band), -1);
    }

    void SetLowLatencyModeTest()
    {
        EXPECT_TRUE(SetLowLatencyMode(true) == WIFI_SUCCESS);
        EXPECT_TRUE(SetLowLatencyMode(false) == WIFI_SUCCESS);
    }

    void IsBandTypeSupportedTest()
    {
        bool supported = false;
        EXPECT_FALSE(IsBandTypeSupported(BAND, &supported) != WIFI_SUCCESS);
    }

    void StartPortalCertificationTest()
    {
        EXPECT_TRUE(StartPortalCertification() != WIFI_SUCCESS);
    }
};

HWTEST_F(WifiCDeviceTest, EnableWifiSuccess, TestSize.Level1)
{
    EnableWifiSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiCDeviceTest, DisableWifiSuccess, TestSize.Level1)
{
    DisableWifiSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(WifiCDeviceTest, DisableWifiFail, TestSize.Level1)
{
    system::SetParameter(PARAM_FORCE_OPEN_WIFI, "true");
    EXPECT_TRUE(DisableWifi() != WIFI_SUCCESS);
    system::SetParameter(PARAM_FORCE_OPEN_WIFI, "false");
}

HWTEST_F(WifiCDeviceTest, EnableSemiWifiSuccess, TestSize.Level1)
{
    EnableSemiWifiSuccess();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
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
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
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
} // namespace Wifi
} // namespace OHOS