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
#include <gtest/gtest.h>
#include "wifi_hdi_wpa_client.h"
#include "wifi_hdi_wpa_callback.h"
#include "wifi_error_no.h"
#include "mock_wifi_hdi_wpa_ap_impl.h"
#include "mock_wifi_hdi_wpa_p2p_impl.h"

using ::testing::_;
using ::testing::Return;
using ::testing::ext::TestSize;

#define DEFAULT_HOSTAPD_CONF_PATH CONFIG_ROOR_DIR"/wpa_supplicant/hostapd.conf"

namespace OHOS {
namespace Wifi {
class WifiHdiWpaClientTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}

public:
    std::unique_ptr<WifiHdiWpaClient> wifiHdiWpaClient;
};

HWTEST_F(WifiHdiWpaClientTest, StartWifi, TestSize.Level1)
{
    std::string ifaceName = "wlan0";
    int instId = 0;
    WifiErrorNo result = wifiHdiWpaClient->StartWifi(ifaceName.c_str(), instId);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqConnect, TestSize.Level1)
{
    int networkId = 111;
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->ReqConnect(networkId, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, StopWifi, TestSize.Level1)
{
    int instId = 0;
    WifiErrorNo result = wifiHdiWpaClient->StopWifi(instId);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqReconnect, TestSize.Level1)
{
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->ReqReconnect(ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqReassociate, TestSize.Level1)
{
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->ReqReassociate(ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqDisconnect, TestSize.Level1)
{
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->ReqDisconnect(ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, GetStaCapabilities, TestSize.Level1)
{
    unsigned int capabilities = 0;
    WifiErrorNo result = wifiHdiWpaClient->GetStaCapabilities(capabilities);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, GetStaDeviceMacAddress, TestSize.Level1)
{
    std::string macAddress = "00:11:22:33:44:55";
    std::string result;
    std::string ifaceName = "wlan0";
    WifiErrorNo error = wifiHdiWpaClient->GetStaDeviceMacAddress(result, ifaceName.c_str());
    EXPECT_EQ(error, WIFI_HAL_OPT_FAILED);

    error = wifiHdiWpaClient->GetStaDeviceMacAddress(macAddress, ifaceName.c_str());
    EXPECT_EQ(error, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, QueryScanInfos, TestSize.Level1)
{
    int size = HAL_GET_MAX_SCAN_INFO;
    ScanInfo *results = (ScanInfo *)malloc(sizeof(ScanInfo) * size);
    for (int i = 0; i < size; ++i) {
        results[i].freq = 2412;
        results[i].siglv = -50;
        results[i].timestamp = 1234567890;
        results[i].channelWidth = 20;
        results[i].centerFrequency0 = 2412;
        results[i].centerFrequency1 = 0;
        results[i].isVhtInfoExist = false;
        results[i].isHtInfoExist = false;
        results[i].isHeInfoExist = false;
        results[i].isErpExist = false;
        results[i].maxRates = 54;
        results[i].extMaxRates = 0;
        results[i].ieSize = 0;
        results[i].infoElems = NULL;
        results[i].isHiLinkNetwork = 0;
    }
    std::vector<InterScanInfo> scanInfos;
    WifiErrorNo result = wifiHdiWpaClient->QueryScanInfos(scanInfos);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    free(results);
}

HWTEST_F(WifiHdiWpaClientTest, ReqStartPnoScan, TestSize.Level1)
{
    WifiHalPnoScanParam scanParam;
    WifiErrorNo result = wifiHdiWpaClient->ReqStartPnoScan(scanParam);
    EXPECT_EQ(result, WIFI_HAL_OPT_NOT_SUPPORT);
}

HWTEST_F(WifiHdiWpaClientTest, ReqStopPnoScan, TestSize.Level1)
{
    WifiErrorNo result = wifiHdiWpaClient->ReqStopPnoScan();
    EXPECT_EQ(result, WIFI_HAL_OPT_NOT_SUPPORT);
}

HWTEST_F(WifiHdiWpaClientTest, RemoveDevice, TestSize.Level1)
{
    int networkId = 222;
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->RemoveDevice(networkId, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    result = wifiHdiWpaClient->RemoveDevice(-1, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
}

HWTEST_F(WifiHdiWpaClientTest, GetNextNetworkId, TestSize.Level1)
{
    int networkId;
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->GetNextNetworkId(networkId, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    EXPECT_EQ(networkId, 0);
}

HWTEST_F(WifiHdiWpaClientTest, ClearDeviceConfig, TestSize.Level1)
{
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->ClearDeviceConfig(ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqEnableNetwork, TestSize.Level1)
{
    int networkId = 333;
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->ReqEnableNetwork(networkId, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqDisableNetwork, TestSize.Level1)
{
    int networkId = 444;
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->ReqDisableNetwork(networkId, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, SetDeviceConfigTest, TestSize.Level1)
{
    int networkId = 555;
    WifiHalDeviceConfig config;
    config.psk = "";
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    config.psk = "12345";
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    config.psk = "1234567891011121314151617181920abcdefdhigklmnopqrst123456789101112131415";
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    config.psk = "12345678910";
    config.authAlgorithms = 10;
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);

    config.ssid = "TestSSID";
    config.psk = "TestPassword";
    config.keyMgmt = "WPA-PSK";
    config.priority = 1;
    SetNetworkConfig expectedConfig[DEVICE_CONFIG_END_POS];
    memcpy_s(expectedConfig, sizeof(expectedConfig), 0, sizeof(expectedConfig));
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);

    config.keyMgmt = "SAE";
    config.eapConfig.eap = "NONE";
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);

    config.keyMgmt = "NONE";
    config.eapConfig.eap = "TLS";
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);

    config.keyMgmt = "WEP";
    config.eapConfig.eap = "TTLS";
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);

    config.keyMgmt = "WAPI";
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, SetDeviceConfigTest1, TestSize.Level1)
{
    int networkId = 555;
    WifiHalDeviceConfig config;
    config.priority = -1;
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    config.priority = 1;
    config.scanSsid = 1;
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    config.scanSsid = 2;
    config.wepKeyIdx = 1;
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    config.wepKeyIdx = -1;
    config.authAlgorithms = 1;
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    config.authAlgorithms = 0;
    config.isRequirePmf = true;
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    config.allowedProtocols = 1;
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    config.allowedProtocols = -1;
    config.allowedPairwiseCiphers = 1;
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    config.allowedPairwiseCiphers = 0;
    config.allowedGroupCiphers = 1;
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    config.allowedGroupCiphers = 0;
    config.allowedGroupMgmtCiphers = 1;
    result = wifiHdiWpaClient->SetDeviceConfig(networkId, config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, SetBssid, TestSize.Level1)
{
    int networkId = 666;
    std::string bssid = "00:11:22:33:44:55";
    std::string ifaceName = "wlan0";
    SetNetworkConfig expectedConfig;
    memset_s(&expectedConfig, sizeof(expectedConfig), 0, sizeof(expectedConfig));

    WifiErrorNo result = wifiHdiWpaClient->SetBssid(networkId, bssid, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    bssid = "";
    result = wifiHdiWpaClient->SetBssid(networkId, bssid, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, SaveDeviceConfig, TestSize.Level1)
{
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->SaveDeviceConfig(ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqRegisterStaEventCallbackTEST, TestSize.Level1)
{
    int instId = 0;
    std::string ifaceName = "wlan0";
    WifiEventCallback *wifiEventCallbackMock = new WifiEventCallback();
    WifiErrorNo result =
        wifiHdiWpaClient->ReqRegisterStaEventCallback(*wifiEventCallbackMock, ifaceName.c_str(), instId);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    delete wifiEventCallbackMock;
}

HWTEST_F(WifiHdiWpaClientTest, ReqStartWpsPbcModeTEST, TestSize.Level1)
{
    WifiHalWpsConfig config;
    config.anyFlag = true;
    config.multiAp = false;
    config.bssid = "00:11:22:33:44:55";
    std::string ifaceName = "wlan0";
    WifiWpsParam expectedParam;
    memset_s(&expectedParam, sizeof(expectedParam), 0, sizeof(expectedParam));
    expectedParam.anyFlag = true;
    expectedParam.multiAp = false;
    strncpy_s(expectedParam.bssid, sizeof(expectedParam.bssid), config.bssid.c_str(), sizeof(expectedParam.bssid) - 1);
    WifiErrorNo result = wifiHdiWpaClient->ReqStartWpsPbcMode(config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqStartWpsPbcModeTest, TestSize.Level1)
{
    WifiHalWpsConfig config;
    config.anyFlag = true;
    config.multiAp = false;
    config.bssid = "";
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->ReqStartWpsPbcMode(config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqStartWpsPinModeTEST, TestSize.Level1)
{
    WifiHalWpsConfig config;
    config.anyFlag = true;
    config.multiAp = false;
    config.bssid = "00:11:22:33:44:55";
    config.pinCode = "12345678";
    std::string ifaceName = "wlan0";
    WifiWpsParam expectedParam;
    memset_s(&expectedParam, sizeof(expectedParam), 0, sizeof(expectedParam));
    expectedParam.anyFlag = config.anyFlag;
    expectedParam.multiAp = config.multiAp;
    strncpy_s(expectedParam.bssid, sizeof(expectedParam.bssid), config.bssid.c_str(), sizeof(expectedParam.bssid) - 1);
    strncpy_s(expectedParam.pinCode, sizeof(expectedParam.pinCode), config.pinCode.c_str(),
        sizeof(expectedParam.pinCode) - 1);
    int pinCode;
    WifiErrorNo result = wifiHdiWpaClient->ReqStartWpsPinMode(config, pinCode, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqStartWpsPinModeTest, TestSize.Level1)
{
    WifiHalWpsConfig config;
    config.anyFlag = true;
    config.multiAp = false;
    config.bssid = "";
    std::string ifaceName = "wlan0";
    int pinCode;
    WifiErrorNo result = wifiHdiWpaClient->ReqStartWpsPinMode(config, pinCode, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqStopWpsTEST, TestSize.Level1)
{
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->ReqStopWps(ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqGetRoamingCapabilitiesTEST, TestSize.Level1)
{
    OHOS::Wifi::WifiHalRoamCapability capability;
    WifiErrorNo result = wifiHdiWpaClient->ReqGetRoamingCapabilities(capability);
    EXPECT_EQ(result, WIFI_HAL_OPT_NOT_SUPPORT);
}

HWTEST_F(WifiHdiWpaClientTest, ReqSetRoamConfigTEST, TestSize.Level1)
{
    WifiHalRoamConfig config;
    WifiErrorNo result = wifiHdiWpaClient->ReqSetRoamConfig(config);
    EXPECT_EQ(result, WIFI_HAL_OPT_NOT_SUPPORT);
}

HWTEST_F(WifiHdiWpaClientTest, ReqGetConnectSignalInfoTEST, TestSize.Level1)
{
    std::string endBssid = "00:11:22:33:44:55";
    WifiSignalPollInfo info;
    WifiErrorNo result = wifiHdiWpaClient->ReqGetConnectSignalInfo(endBssid, info);
    EXPECT_EQ(result, WIFI_HAL_OPT_NOT_SUPPORT);
}

HWTEST_F(WifiHdiWpaClientTest, ReqWpaAutoConnectTEST, TestSize.Level1)
{
    int enable = 1;
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->ReqWpaAutoConnect(enable, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqWpaBlocklistClearTEST, TestSize.Level1)
{
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->ReqWpaBlocklistClear(ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqSetPowerSave, TestSize.Level1)
{
    bool enable = true;
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->ReqSetPowerSave(enable, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqWpaSetCountryCodeTEST, TestSize.Level1)
{
    std::string countryCode = "US";
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->ReqWpaSetCountryCode(countryCode, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqWpaGetCountryCodeTEST, TestSize.Level1)
{
    std::string expectedCountryCode = "US";
    std::string ifaceName = "wlan0";
    std::string countryCode;
    WifiErrorNo result = wifiHdiWpaClient->ReqWpaGetCountryCode(countryCode, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqWpaSetSuspendModeTEST, TestSize.Level1)
{
    bool mode = true;
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->ReqWpaSetSuspendMode(mode, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqWpaShellCmdTest, TestSize.Level1)
{
    std::string ifName = "wlan0";
    std::string cmd = "iw wlan0 scan";
    WifiErrorNo result = wifiHdiWpaClient->ReqWpaShellCmd(ifName, cmd);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqWpaShellCmdTest1, TestSize.Level1)
{
    std::string ifName = "Test-wlan0";
    std::string cmd = "iw wlan0 scan";
    WifiErrorNo result = wifiHdiWpaClient->ReqWpaShellCmd(ifName, cmd);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqWpaShellCmdTest2, TestSize.Level1)
{
    std::string ifName = "wlan0";
    std::string cmd(1025, 'a');
    WifiErrorNo result = wifiHdiWpaClient->ReqWpaShellCmd(ifName, cmd);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, GetNetworkListTEST, TestSize.Level1)
{
    std::string ifaceName = "wlan0";
    std::vector<WifiHalWpaNetworkInfo> networkList;
    WifiErrorNo result = wifiHdiWpaClient->GetNetworkList(networkList, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, GetDeviceConfigTEST, TestSize.Level1)
{
    WifiHalGetDeviceConfig config;
    config.networkId = 777;
    config.param = "param";
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->GetDeviceConfig(config, ifaceName.c_str());
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, StartAp, TestSize.Level1)
{
    int id = 123;
    std::string ifaceName = "wlan0";
    WifiErrorNo result = wifiHdiWpaClient->StartAp(id, ifaceName);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, StopAp, TestSize.Level1)
{
    int id = 123;
    WifiErrorNo result = wifiHdiWpaClient->StopAp(id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, SetSoftApConfigTEST, TestSize.Level1)
{
    HotspotConfig config;
    int id = 123;
    WifiErrorNo result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, SetSoftApConfigTest1, TestSize.Level1)
{
    HotspotConfig config;
    int id = 123;
    MockWifiHdiWpaApImpl::SetMockFlag(true);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApPasswd(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    WifiErrorNo result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApName(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApWpaValue(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApBand(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApChannel(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApMaxConn(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetAp80211n(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApWmm(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiReloadApConfigInfo(_))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiDisableAp(_))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    MockWifiHdiWpaApImpl::SetMockFlag(false);
}

HWTEST_F(WifiHdiWpaClientTest, SetSoftApConfigTest2, TestSize.Level1)
{
    HotspotConfig config;
    int id = 123;
    MockWifiHdiWpaApImpl::SetMockFlag(true);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApPasswd(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApName(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_FAILED));
    WifiErrorNo result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    MockWifiHdiWpaApImpl::SetMockFlag(false);
}

HWTEST_F(WifiHdiWpaClientTest, SetSoftApConfigTest3, TestSize.Level1)
{
    HotspotConfig config;
    int id = 123;
    MockWifiHdiWpaApImpl::SetMockFlag(true);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApPasswd(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApName(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApWpaValue(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_FAILED));
    WifiErrorNo result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    MockWifiHdiWpaApImpl::SetMockFlag(false);
}

HWTEST_F(WifiHdiWpaClientTest, SetSoftApConfigTest4, TestSize.Level1)
{
    HotspotConfig config;
    int id = 123;
    MockWifiHdiWpaApImpl::SetMockFlag(true);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApPasswd(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApName(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApWpaValue(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApBand(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_FAILED));
    WifiErrorNo result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    MockWifiHdiWpaApImpl::SetMockFlag(false);
}

HWTEST_F(WifiHdiWpaClientTest, SetSoftApConfigTest5, TestSize.Level1)
{
    HotspotConfig config;
    int id = 123;
    MockWifiHdiWpaApImpl::SetMockFlag(true);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApPasswd(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApName(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApWpaValue(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApBand(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApChannel(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_FAILED));
    WifiErrorNo result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    MockWifiHdiWpaApImpl::SetMockFlag(false);
}

HWTEST_F(WifiHdiWpaClientTest, SetSoftApConfigTest6, TestSize.Level1)
{
    HotspotConfig config;
    int id = 123;
    MockWifiHdiWpaApImpl::SetMockFlag(true);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApPasswd(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApName(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApWpaValue(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApBand(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApChannel(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApMaxConn(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_FAILED));
    WifiErrorNo result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    MockWifiHdiWpaApImpl::SetMockFlag(false);
}

HWTEST_F(WifiHdiWpaClientTest, SetSoftApConfigTest7, TestSize.Level1)
{
    HotspotConfig config;
    int id = 123;
    MockWifiHdiWpaApImpl::SetMockFlag(true);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApPasswd(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApName(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApWpaValue(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApBand(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApChannel(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApMaxConn(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetAp80211n(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_FAILED));
    WifiErrorNo result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    MockWifiHdiWpaApImpl::SetMockFlag(false);
}

HWTEST_F(WifiHdiWpaClientTest, SetSoftApConfigTest8, TestSize.Level1)
{
    HotspotConfig config;
    int id = 123;
    MockWifiHdiWpaApImpl::SetMockFlag(true);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApPasswd(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApName(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApWpaValue(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApBand(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApChannel(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApMaxConn(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetAp80211n(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApWmm(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_FAILED));
    WifiErrorNo result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    MockWifiHdiWpaApImpl::SetMockFlag(false);
}

HWTEST_F(WifiHdiWpaClientTest, SetSoftApConfigTest9, TestSize.Level1)
{
    HotspotConfig config;
    int id = 123;
    MockWifiHdiWpaApImpl::SetMockFlag(true);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApPasswd(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApName(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApWpaValue(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApBand(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApChannel(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApMaxConn(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetAp80211n(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApWmm(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiReloadApConfigInfo(_))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_FAILED));
    WifiErrorNo result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    MockWifiHdiWpaApImpl::SetMockFlag(false);
}

HWTEST_F(WifiHdiWpaClientTest, SetSoftApConfigTest10, TestSize.Level1)
{
    HotspotConfig config;
    int id = 123;
    MockWifiHdiWpaApImpl::SetMockFlag(true);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApPasswd(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApName(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApWpaValue(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApBand(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApChannel(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApMaxConn(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetAp80211n(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiSetApWmm(_, _))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiReloadApConfigInfo(_))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiDisableAp(_))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_FAILED));
    WifiErrorNo result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    MockWifiHdiWpaApImpl::SetMockFlag(false);
}

HWTEST_F(WifiHdiWpaClientTest, SetSoftApConfigTest11, TestSize.Level1)
{
    HotspotConfig config;
    int id = 1;
    config.SetSsid("aptest");
    config.SetPreSharedKey("12345678");
    WifiErrorNo result = wifiHdiWpaClient->SetSoftApConfig("wlan0", config, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    sleep(1);
    std::remove(DEFAULT_HOSTAPD_CONF_PATH);
}

HWTEST_F(WifiHdiWpaClientTest, RegisterApEventTEST, TestSize.Level1)
{
    IWifiApMonitorEventCallback callback;
    int id = 123;
    WifiErrorNo result = wifiHdiWpaClient->RegisterApEvent(callback, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    callback.onStaJoinOrLeave = nullptr;
    result = wifiHdiWpaClient->RegisterApEvent(callback, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
}

HWTEST_F(WifiHdiWpaClientTest, GetStationListTEST, TestSize.Level1)
{
    std::vector<std::string> result;
    WifiErrorNo res = wifiHdiWpaClient->GetStationList(result);
    EXPECT_EQ(res, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, AddBlockByMacTEST, TestSize.Level1)
{
    std::string mac = "00:11:22:33:44:55";
    int id = 123;
    WifiErrorNo result = wifiHdiWpaClient->AddBlockByMac(mac, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    mac = "";
    wifiHdiWpaClient->AddBlockByMac(mac, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, DelBlockByMacTEST, TestSize.Level1)
{
    std::string mac = "00:11:22:33:44:55";
    int id = 123;
    WifiErrorNo result = wifiHdiWpaClient->DelBlockByMac(mac, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    mac = "";
    wifiHdiWpaClient->DelBlockByMac(mac, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, RemoveStationTEST, TestSize.Level1)
{
    std::string mac = "00:11:22:33:44:55";
    int id = 123;
    WifiErrorNo result = wifiHdiWpaClient->RemoveStation(mac, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    mac = "";
    wifiHdiWpaClient->RemoveStation(mac, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqDisconnectStaByMacTEST, TestSize.Level1)
{
    std::string mac = "00:11:22:33:44:55";
    int id = 123;
    WifiErrorNo result = wifiHdiWpaClient->ReqDisconnectStaByMac(mac, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    mac = "";
    wifiHdiWpaClient->ReqDisconnectStaByMac(mac, id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pStartTest, TestSize.Level1)
{
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pStart("wlan", true);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pStopTest, TestSize.Level1)
{
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pStop();
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetSsidPostfixNameTest, TestSize.Level1)
{
    std::string postfixName = "postfix";
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetSsidPostfixName(postfixName);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetDeviceNameTest, TestSize.Level1)
{
    std::string name = "DeviceName";
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetDeviceName(name);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetWpsDeviceTypeTest, TestSize.Level1)
{
    std::string type = "type";
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetWpsDeviceType(type);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetWpsSecondaryDeviceTypeTest, TestSize.Level1)
{
    std::string type = "WPS_TYPE";
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetWpsSecondaryDeviceType(type);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetWpsConfigMethodsTest, TestSize.Level1)
{
    std::string config = "12345678";
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetWpsConfigMethods(config);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pGetDeviceAddressTest, TestSize.Level1)
{
    std::string result;
    WifiErrorNo ret = wifiHdiWpaClient->ReqP2pGetDeviceAddress(result);
    EXPECT_EQ(ret, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pFlushTest, TestSize.Level1)
{
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pFlush();
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pFlushServiceTest, TestSize.Level1)
{
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pFlushService();
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSaveConfigTest, TestSize.Level1)
{
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSaveConfig();
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pRegisterCallbackTest, TestSize.Level1)
{
    P2pHalCallback callbacks;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pRegisterCallback(callbacks);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetupWpsPbcTest, TestSize.Level1)
{
    std::string groupInterface = "p2p0";
    std::string bssid = "00:11:22:33:44:55";
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetupWpsPbc(groupInterface, bssid);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetupWpsPinTest, TestSize.Level1)
{
    std::string groupInterface = "wlan0";
    std::string address = "00:11:22:33:44:55";
    std::string pin = "12345678";
    std::string result;
    WifiErrorNo ret = wifiHdiWpaClient->ReqP2pSetupWpsPin(groupInterface, address, pin, result);
    EXPECT_EQ(ret, WIFI_HAL_OPT_OK);
    pin = "1234";
    ret = wifiHdiWpaClient->ReqP2pSetupWpsPin(groupInterface, address, pin, result);
    EXPECT_EQ(ret, WIFI_HAL_OPT_INVALID_PARAM);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pRemoveNetworkTest, TestSize.Level1)
{
    int networkId = 888;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pRemoveNetwork(networkId);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pListNetworksTest, TestSize.Level1)
{
    std::map<int, WifiP2pGroupInfo> mapGroups;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pListNetworks(mapGroups);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pListNetworksTest1, TestSize.Level1)
{
    std::map<int, WifiP2pGroupInfo> mapGroups;
    MockWifiHdiWpaP2pImpl::SetMockFlag(true);
    EXPECT_CALL(MockWifiHdiWpaP2pImpl::GetInstance(), HdiP2pListNetworks(_))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pListNetworks(mapGroups);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    EXPECT_TRUE(mapGroups.empty());
    MockWifiHdiWpaP2pImpl::SetMockFlag(false);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pListNetworksTest2, TestSize.Level1)
{
    std::map<int, WifiP2pGroupInfo> mapGroups;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pListNetworks(mapGroups);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    EXPECT_TRUE(mapGroups.empty());
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetGroupMaxIdleTest, TestSize.Level1)
{
    std::string groupInterface = "p2p0";
    size_t time = 300;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetGroupMaxIdle(groupInterface, time);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetPowerSave_EnableTest, TestSize.Level1)
{
    std::string groupInterface = "p2p0";
    bool enable = true;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetPowerSave(groupInterface, enable);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetPowerSave_DisableTest, TestSize.Level1)
{
    std::string groupInterface = "p2p0";
    bool enable = false;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetPowerSave(groupInterface, enable);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetWfdEnable_EnableTest, TestSize.Level1)
{
    bool enable = true;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetWfdEnable(enable);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetWfdEnable_DisableTest, TestSize.Level1)
{
    bool enable = false;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetWfdEnable(enable);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetWfdDeviceConfigTest, TestSize.Level1)
{
    std::string config = "config";
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetWfdDeviceConfig(config);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pStartFindTest, TestSize.Level1)
{
    size_t timeout = 5000;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pStartFind(timeout);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pStopFindTest, TestSize.Level1)
{
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pStopFind();
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetExtListenTest, TestSize.Level1)
{
    bool enable = true;
    size_t period = 100;
    size_t interval = 200;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetExtListen(enable, period, interval);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    period = 0;
    result = wifiHdiWpaClient->ReqP2pSetExtListen(enable, period, interval);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    interval = 0;
    result = wifiHdiWpaClient->ReqP2pSetExtListen(enable, period, interval);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    interval = 65536;
    result = wifiHdiWpaClient->ReqP2pSetExtListen(enable, period, interval);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);

    period = 65536;
    result = wifiHdiWpaClient->ReqP2pSetExtListen(enable, period, interval);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    interval = 0;
    result = wifiHdiWpaClient->ReqP2pSetExtListen(enable, period, interval);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    interval = 65536;
    result = wifiHdiWpaClient->ReqP2pSetExtListen(enable, period, interval);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    interval = 200;
    result = wifiHdiWpaClient->ReqP2pSetExtListen(enable, period, interval);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);

    period = 1;
    interval = 0;
    result = wifiHdiWpaClient->ReqP2pSetExtListen(enable, period, interval);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);

    enable = false;
    result = wifiHdiWpaClient->ReqP2pSetExtListen(enable, period, interval);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetListenChannel, TestSize.Level1)
{
    size_t channel = 6;
    unsigned char regClass = 81;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetListenChannel(channel, regClass);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pConnectTest, TestSize.Level1)
{
    std::string temp = "";
    WifiP2pConfigInternal config;
    config.SetDeviceAddress("00:11:22:33:44:55");
    config.SetGroupOwnerIntent(7);
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pConnect(config, false, temp);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    result = wifiHdiWpaClient->ReqP2pConnect(config, true, temp);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pCancelConnect, TestSize.Level1)
{
    WifiHdiWpaClient wifiClient;
    WifiErrorNo result = wifiClient.ReqP2pCancelConnect();
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pProvisionDiscovery, TestSize.Level1)
{
    WifiP2pConfigInternal config;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pProvisionDiscovery(config);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pAddGroupTest, TestSize.Level1)
{
    int id = 1;
    int fre = 15;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pAddGroup(true, id, fre);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pRemoveGroupTest, TestSize.Level1)
{
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pRemoveGroup("p2p0");
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pRemoveGroupNonExistentTest, TestSize.Level1)
{
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pRemoveGroup("p2p1");
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pInviteTest, TestSize.Level1)
{
    WifiP2pGroupInfo groupInfo;
    std::string deviceAddress = "00:11:22:33:44:55";
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pInvite(groupInfo, deviceAddress);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pReinvokeTest01, TestSize.Level1)
{
    int networkId = 1;
    std::string deviceAddr = "00:11:22:33:44:55";
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pReinvoke(networkId, deviceAddr);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pReinvokeTest02, TestSize.Level1)
{
    int networkId = -1;
    std::string deviceAddr = "00:11:22:33:44:55";
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pReinvoke(networkId, deviceAddr);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pReinvokeTest03, TestSize.Level1)
{
    int networkId = 1;
    std::string deviceAddr = "00:11:22:33:44";
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pReinvoke(networkId, deviceAddr);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pGetGroupCapabilityTest01, TestSize.Level1)
{
    std::string deviceAddress = "00:11:22:33:44:55";
    uint32_t capability;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pGetGroupCapability(deviceAddress, capability);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pGetGroupCapabilityTest02, TestSize.Level1)
{
    std::string deviceAddress = "00:11:22:33:44";
    uint32_t capability;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pGetGroupCapability(deviceAddress, capability);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pAddServiceTest, TestSize.Level1)
{
    WifiP2pServiceInfo serviceInfo;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pAddService(serviceInfo);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pRemoveServiceTest, TestSize.Level1)
{
    WifiP2pServiceInfo info;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pRemoveService(info);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    std::vector<std::string> vec = { "" };
    result = wifiHdiWpaClient->ReqP2pRemoveService(info);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    vec = { "upnp 1", "service" };
    result = wifiHdiWpaClient->ReqP2pRemoveService(info);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    vec = { "bonjour query" };
    result = wifiHdiWpaClient->ReqP2pRemoveService(info);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pReqServiceDiscoveryTest01, TestSize.Level1)
{
    std::string deviceAddress = "00:11:22:33:44:55";
    std::vector<unsigned char> tlvs = { 0x01, 0x02, 0x03 };
    std::string reqID;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pReqServiceDiscovery(deviceAddress, tlvs, reqID);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    EXPECT_TRUE(reqID.empty());
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pReqServiceDiscoveryTest02, TestSize.Level1)
{
    std::string deviceAddress = "00:11:22:33:44";
    std::vector<unsigned char> tlvs = { 0x01, 0x02, 0x03 };
    std::string reqID;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pReqServiceDiscovery(deviceAddress, tlvs, reqID);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    EXPECT_TRUE(reqID.empty());
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pReqServiceDiscoveryTest03, TestSize.Level1)
{
    std::string deviceAddress = "00:11:22:33:44:55";
    std::vector<unsigned char> tlvs;
    std::string reqID;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pReqServiceDiscovery(deviceAddress, tlvs, reqID);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);
    EXPECT_TRUE(reqID.empty());
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pCancelServiceDiscoveryTest, TestSize.Level1)
{
    std::string id = "12345";
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pCancelServiceDiscovery(id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    result = wifiHdiWpaClient->ReqP2pCancelServiceDiscovery("");
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetRandomMacTest, TestSize.Level1)
{
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetRandomMac(true);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    result = wifiHdiWpaClient->ReqP2pSetRandomMac(false);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    result = wifiHdiWpaClient->ReqP2pSetRandomMac(2);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetMiracastTypeTest, TestSize.Level1)
{
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetMiracastType(1);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ReqSetPersistentReconnectTest, TestSize.Level1)
{
    WifiHdiWpaClient wifiClient;
    WifiErrorNo result = wifiClient.ReqSetPersistentReconnect(1);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    result = wifiClient.ReqSetPersistentReconnect(0);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    result = wifiClient.ReqSetPersistentReconnect(2);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqRespServiceDiscoveryTest, TestSize.Level1)
{
    WifiP2pDevice device;
    int frequency = 2412;
    int dialogToken = 1;
    std::vector<unsigned char> tlvs;
    WifiErrorNo result = wifiHdiWpaClient->ReqRespServiceDiscovery(device, frequency, dialogToken, tlvs);
    EXPECT_EQ(result, WIFI_HAL_OPT_INVALID_PARAM);

    tlvs = { 0x01, 0x02, 0x03 };
    result = wifiHdiWpaClient->ReqRespServiceDiscovery(device, frequency, dialogToken, tlvs);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    tlvs.empty();
    result = wifiHdiWpaClient->ReqRespServiceDiscovery(device, frequency, dialogToken, tlvs);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqSetServiceDiscoveryExternalTest, TestSize.Level1)
{
    WifiHdiWpaClient client;
    WifiErrorNo result = client.ReqSetServiceDiscoveryExternal(true);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqGetP2pPeerTest01, TestSize.Level1)
{
    std::string deviceAddress = "00:11:22:33:44:55";
    WifiP2pDevice device;
    WifiErrorNo result = wifiHdiWpaClient->ReqGetP2pPeer(deviceAddress, device);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqGetP2pPeerTest02, TestSize.Level1)
{
    std::string deviceAddress = "00:11:22:33:44";
    WifiP2pDevice device;
    WifiErrorNo result = wifiHdiWpaClient->ReqGetP2pPeer(deviceAddress, device);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pGetSupportFrequenciesTest, TestSize.Level1)
{
    std::vector<int> frequencies;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pGetSupportFrequencies(1, frequencies);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
    EXPECT_TRUE(frequencies.empty());
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pSetGroupConfigTest, TestSize.Level1)
{
    int networkId = 1;
    HalP2pGroupConfig config;
    config.ssid = "TestSSID";
    config.bssid = "00:11:22:33:44:55";
    config.psk = "TestPassword";
    config.proto = "WPA2";
    config.keyMgmt = "WPA-PSK";
    config.pairwise = "CCMP";
    config.authAlg = "OPEN";
    config.mode = 1;
    config.disabled = 0;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pSetGroupConfig(networkId, config);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, PushP2pGroupConfigStringTest, TestSize.Level1)
{
    P2pGroupConfig config;
    std::string str = "test";
    int result = wifiHdiWpaClient->PushP2pGroupConfigString(&config, GROUP_CONFIG_SSID, str);
    EXPECT_EQ(result, 1);
    str = "";
    result = wifiHdiWpaClient->PushP2pGroupConfigString(&config, GROUP_CONFIG_SSID, str);
    EXPECT_EQ(result, 0);
    std::string str1(258, 'a');
    result = wifiHdiWpaClient->PushP2pGroupConfigString(&config, GROUP_CONFIG_SSID, str1);
    EXPECT_EQ(result, 0);
}

HWTEST_F(WifiHdiWpaClientTest, PushP2pGroupConfigIntTest, TestSize.Level1)
{
    P2pGroupConfig pConfig;
    int expectedValue = 123;
    int result = wifiHdiWpaClient->PushP2pGroupConfigInt(&pConfig, GROUP_CONFIG_MODE, expectedValue);
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pGetGroupConfigTest, TestSize.Level1)
{
    int networkId = 1;
    HalP2pGroupConfig config;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pGetGroupConfig(networkId, config);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pAddNetworkTest, TestSize.Level1)
{
    int networkId = -1;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pAddNetwork(networkId);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqP2pHid2dConnectTest, TestSize.Level1)
{
    Hid2dConnectConfig config;
    WifiErrorNo result = wifiHdiWpaClient->ReqP2pHid2dConnect(config);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    std::string ssid(135, 'a');
    config.SetSsid(ssid);
    result = wifiHdiWpaClient->ReqP2pHid2dConnect(config);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);

    config.SetSsid("Test");
    config.SetBssid("1234567890abcdefg123456");
    result = wifiHdiWpaClient->ReqP2pHid2dConnect(config);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);

    config.SetBssid("1234567890");
    std::string passphrase(130, 'a');
    config.SetPreSharedKey(passphrase);
    result = wifiHdiWpaClient->ReqP2pHid2dConnect(config);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, SetWapiConfigTest, TestSize.Level1)
{
    WifiHalDeviceConfig config;
    SetNetworkConfig conf;
    int num = 0;
    wifiHdiWpaClient->SetWapiConfig(config, &conf, num);
    config.keyMgmt = KEY_MGMT_WAPI_PSK;
    wifiHdiWpaClient->SetWapiConfig(config, &conf, num);
    config.keyMgmt = KEY_MGMT_WAPI_CERT;
    wifiHdiWpaClient->SetWapiConfig(config, &conf, num);
    EXPECT_NE(num, 0);
}

HWTEST_F(WifiHdiWpaClientTest, ReqWpaGetPskPassphraseTest, TestSize.Level1)
{
    std::string ifname = "test";
    std::string psk = "123456";
    WifiErrorNo result = wifiHdiWpaClient->ReqWpaGetPskPassphrase(ifname, psk);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, ReqWpaGetPskPassphraseTest1, TestSize.Level1)
{
    std::string ifname = "Test-wlan0";
    std::string psk = "123456";
    WifiErrorNo result = wifiHdiWpaClient->ReqWpaGetPskPassphrase(ifname, psk);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, ScanTest, TestSize.Level1)
{
    WifiHalScanParam scanParam;
    WifiErrorNo result = wifiHdiWpaClient->Scan(scanParam);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, DeliverP2pDataTest, TestSize.Level1)
{
    int32_t cmdType = 2;
    int32_t dataType = 1;
    std::string carryData = "1";
    WifiErrorNo result = wifiHdiWpaClient->DeliverP2pData(cmdType, dataType, carryData);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, EnableApTest, TestSize.Level1)
{
    int32_t id = 0;
    WifiErrorNo result = wifiHdiWpaClient->EnableAp(id);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, EnableApTest1, TestSize.Level1)
{
    int32_t id = 0;
    MockWifiHdiWpaApImpl::SetMockFlag(true);
    EXPECT_CALL(MockWifiHdiWpaApImpl::GetInstance(), HdiEnableAp(_))
        .WillRepeatedly(Return(WifiErrorNo::WIFI_HAL_OPT_OK));
    WifiErrorNo result = wifiHdiWpaClient->EnableAp(id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
    MockWifiHdiWpaApImpl::SetMockFlag(false);
}

HWTEST_F(WifiHdiWpaClientTest, PushDeviceConfigAuthAlgorithmTest, TestSize.Level1)
{
    SetNetworkConfig pConfig;
    DeviceConfigType type = DEVICE_CONFIG_SSID;
    unsigned int alg = 1;
    int result = wifiHdiWpaClient->PushDeviceConfigAuthAlgorithm(&pConfig, type, alg);
    EXPECT_EQ(result, 1);

    alg = 3;
    result = wifiHdiWpaClient->PushDeviceConfigAuthAlgorithm(&pConfig, type, alg);
    EXPECT_EQ(result, 1);

    alg = 5;
    result = wifiHdiWpaClient->PushDeviceConfigAuthAlgorithm(&pConfig, type, alg);
    EXPECT_EQ(result, 1);

    alg = 7;
    result = wifiHdiWpaClient->PushDeviceConfigAuthAlgorithm(&pConfig, type, alg);
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaClientTest, PushDeviceConfigParseMaskTest, TestSize.Level1)
{
    SetNetworkConfig pConfig;
    DeviceConfigType type = DEVICE_CONFIG_SSID;
    unsigned int mask = 0x1;
    std::string parseStr[] = {"test"};
    int size = 1;
    int result = wifiHdiWpaClient->PushDeviceConfigParseMask(&pConfig, type, mask, parseStr, size);
    EXPECT_EQ(result, 1);

    mask = 0x0;
    result = wifiHdiWpaClient->PushDeviceConfigParseMask(&pConfig, type, mask, parseStr, size);
    EXPECT_EQ(result, 1);
}

HWTEST_F(WifiHdiWpaClientTest, GetMloLinkedInfoTest, TestSize.Level1)
{
    std::string ifaceName = "wlan0";
    std::vector<WifiLinkedInfo> mloLinkInfo;
    WifiErrorNo result = wifiHdiWpaClient->GetMloLinkedInfo(ifaceName, mloLinkInfo);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaClientTest, P2pRejectTest, TestSize.Level1)
{
    std::string bssid = "00:11:22:33:44:55";
    WifiErrorNo result = wifiHdiWpaClient->P2pReject(bssid);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaClientTest, SetMiracastSinkConfigTest, TestSize.Level1)
{
    std::string config = "112233";
    WifiErrorNo result = wifiHdiWpaClient->SetMiracastSinkConfig(config);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}
} // namespace Wifi
} // namespace OHOS
