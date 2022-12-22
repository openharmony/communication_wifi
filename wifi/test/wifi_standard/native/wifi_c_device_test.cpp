/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#include "../../../interfaces/kits/c/wifi_device.h"



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

namespace OHOS {
namespace Wifi {

constexpr int NETWORK_ID = 15;
constexpr int BAND = 2;
constexpr int FREQUENCY = 2437;
constexpr int TIMESTAMP = -750366468;
constexpr int RSSI = 2;

class WifiCDeviceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}

    void EnableWifiSuccess()
    {
        EXPECT_TRUE(EnableWifi() == WIFI_OPT_SUCCESS);
    }

    void DisableWifiSuccess()
    {
        EXPECT_TRUE(DisableWifi() == WIFI_OPT_SUCCESS);
    }

    void IsWifiActiveEnable()
    {
        EXPECT_TRUE(IsWifiActive() == true);
    }

    void ScanSuccess()
    {
        EXPECT_TRUE(Scan() == WIFI_OPT_SUCCESS);
    }
    
    void GetScanInfoListSucess()
    {
        WifiScanInfo result;
        result.ssid = "networkId";
        result.bssid = "01:23:45:67:89:AB";
        result.rssi = RSSI;
        result.frequency = FREQUENCY;
        result.timestamp = TIMESTAMP;
        unsigned int mSize = 0;
        EXPECT_TRUE(GetScanInfoList(&result, &mSize)) == WIFI_OPT_SUCCESS);
    }

    void GetScanInfoListFail()
    {
        WifiScanInfo* result = nullptr;
        unsigned int mSize = 0;
        EXPECT_TRUE(GetScanInfoList(result, &mSize)) == WIFI_OPT_FAILED);
    }

    void AddDeviceConfigSuccess()
    {
        int result = 0;
        WifiDeviceConfig config;
        config.ssid = "networkId";
        config.bssid = "01:23:45:67:89:AB";
        config.preSharedKey = "12345678";
        EXPECT_TRUE(AddDeviceConfig(&config, &result)) == WIFI_OPT_SUCCESS);
    }

    void GetDeviceConfigsSuccess()
    {
        unsigned int mSize = 0;
        WifiDeviceConfig result;
        result.ssid = "networkId";
        result.bssid = "01:23:45:67:89:AB";
        result.preSharedKey = "12345678";
        EXPECT_TRUE(GetDeviceConfigs(&result, &mSize)) == WIFI_OPT_SUCCESS);
    }

    void RemoveDeviceSuccess()
    {
        int networkId = NETWORK_ID;
        EXPECT_TRUE(RemoveDevice(networkId) == WIFI_OPT_SUCCESS);
    }

    void DisableDeviceConfigSuccess()
    {
        int networkId = NETWORK_ID;
        EXPECT_TRUE(DisableDeviceConfig(networkId) == WIFI_OPT_SUCCESS);
    }

    void EnableDeviceConfigSuccess()
    {
        int networkId = NETWORK_ID;
        EXPECT_TRUE(EnableDeviceConfig(networkId) == WIFI_OPT_SUCCESS);
    }

    void ConnectToSuccess()
    {
        int networkId = NETWORK_ID;
        EXPECT_TRUE(ConnectTo(networkId) == WIFI_OPT_SUCCESS);
    }
    
    void ConnectToDeviceSuccess()
    {
        WifiDeviceConfig config;
        config.ssid = "networkId";
        config.bssid = "01:23:45:67:89:AB";
        config.preSharedKey = "12345678";
        config.netId = NETWORK_ID;
        config.freq = FREQUENCY;
        EXPECT_TRUE(ConnectToDevice(&config) == WIFI_OPT_SUCCESS);
    }

    void DisconnectSuccess()
    {
        EXPECT_TRUE(Disconnect() == WIFI_OPT_SUCCESS);
    }
    
    void GetLinkedInfoSuccess()
    {
        WifiLinkedInfo result;
        result.ssid = "networkId";
        result.bssid = "01:23:45:67:89:AB";
        result.frequency = FREQUENCY;
        result.connState = WIFI_CONNECTED;
        EXPECT_TRUE(GetLinkedInfo(&result) == WIFI_OPT_SUCCESS);
    }

    void GetDeviceMacAddressSuccess()
    {
        unsigned char result[WIFI_MAC_LEN] = {0};
        EXPECT_TRUE(GetDeviceMacAddress(result) == WIFI_OPT_SUCCESS);
    }

    void AdvanceScanSuccess()
    {
        WifiScanParams params;
        params.ssid = "networkId";
        params.bssid = "01:23:45:67:89:AB";
        params.scanType = WIFI_FREQ_SCAN;
        params.freqs = FREQUENCY;
        params.band = BAND;
        params.ssidLen = strlen(params.ssid);
        EXPECT_TRUE(AdvanceScan(&params) == WIFI_OPT_SUCCESS);
    }

    void GetIpInfoSuccess()
    {
        IpInfo info;
        EXPECT_TRUE(GetIpInfo(&info) == WIFI_OPT_SUCCESS);
    }

    void GetSignalLevelSuccess()
    {
        int rssi = RSSI;
        int band = BAND;
        EXPECT_EQ(GetSignalLevel(rssi, band), -1);
    }

    void SetLowLatencyModeSuccess()
    {
        int enabled = 0;
        SetLowLatencyMode(enabled);
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

HWTEST_F(WifiCDeviceTest, GetScanInfoListFail, TestSize.Level1)
{
    GetScanInfoListFail();
}

HWTEST_F(WifiCDeviceTest, AddDeviceConfigSuccess, TestSize.Level1)
{
    AddDeviceConfigSuccess();
}

HWTEST_F(WifiCDeviceTest, GetDeviceConfigsSuccess, TestSize.Level1)
{
    GetDeviceConfigsSuccess();
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

HWTEST_F(WifiCDeviceTest, SetLowLatencyModeSuccess, TestSize.Level1)
{
    SetLowLatencyModeSuccess();
}
} // namespace Wifi
} // namespace OHOS