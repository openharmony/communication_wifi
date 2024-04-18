/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include <iostream>
#include "wifi_idl_client_test.h"
#include "securec.h"
#include "wifi_scan_param.h"
#include "wifi_log.h"

#undef LOG_TAG
#define LOG_TAG "WifiIdlClientTest"

namespace OHOS {
namespace Wifi {
constexpr int FREQUENCY1 = 2412;
constexpr int FREQUENCY2 = 2417;
constexpr int SCANFRENQUE = 32;
constexpr int INVALIDNET = -1;
constexpr int BIT0 = 1;
constexpr int BIT1 = 2;
constexpr int BIT2 = 4;
constexpr int TEN = 4;
constexpr int MAX_TIME = 65546;

HWTEST_F(WifiIdlClientTest, StartWifiTest, TestSize.Level1)
{
    WifiErrorNo err = mClient.StartWifi();
    EXPECT_TRUE(err == WIFI_IDL_OPT_CONN_SUPPLICANT_FAILED || err == WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.StartWifi() == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, GetStaDeviceMacAddressTest, TestSize.Level1)
{
    std::string mac;
    WifiErrorNo err = mClient.GetStaDeviceMacAddress(mac);
    EXPECT_TRUE(err == WIFI_IDL_OPT_FAILED || err == WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.GetStaDeviceMacAddress(mac) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, GetStaCapabilitiesTest, TestSize.Level1)
{
    unsigned int capabilities = 0;
    WifiErrorNo err = mClient.GetStaCapabilities(capabilities);
    EXPECT_TRUE(err == WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.GetStaCapabilities(capabilities) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, GetSupportFrequenciesTest, TestSize.Level1)
{
    std::vector<int> freqs;
    WifiErrorNo err = mClient.GetSupportFrequencies(1, freqs);
    EXPECT_FALSE(err == WIFI_IDL_OPT_OK);
    for (auto iter = freqs.begin(); iter != freqs.end(); ++iter) {
        LOGD("Get frequency: %{public}d", *iter);
    }
    freqs.clear();
    err = mClient.GetSupportFrequencies(2, freqs);
    EXPECT_FALSE(err == WIFI_IDL_OPT_OK);
    for (auto iter = freqs.begin(); iter != freqs.end(); ++iter) {
        LOGD("Get frequency: %{public}d", *iter);
    }
    freqs.clear();
    err = mClient.GetSupportFrequencies(4, freqs);
    EXPECT_FALSE(err == WIFI_IDL_OPT_OK);
    for (auto iter = freqs.begin(); iter != freqs.end(); ++iter) {
        LOGD("Get frequency: %{public}d", *iter);
    }
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.GetSupportFrequencies(1, freqs) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, SetConnectMacAddrTest, TestSize.Level1)
{
    std::string mac = "abcdefghijklmn";
    WifiErrorNo err = mClient.SetConnectMacAddr(mac, 0);
    EXPECT_TRUE(err == WIFI_IDL_OPT_INPUT_MAC_INVALID);
    mac = "00:00:00:00:00:00";
    err = mClient.SetConnectMacAddr(mac, 0);
    EXPECT_GE(err, WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.SetConnectMacAddr(mac, 1) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, SetScanMacAddressTest, TestSize.Level1)
{
    std::string mac = "abcdefghijklmn";
    WifiErrorNo err = mClient.SetScanMacAddress(mac);
    EXPECT_TRUE(err == WIFI_IDL_OPT_INPUT_MAC_INVALID);
    mac = "00:00:00:00:00:00";
    err = mClient.SetScanMacAddress(mac);
    EXPECT_FALSE(err == WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.SetScanMacAddress(mac) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, DisconnectLastRoamingBssidTest, TestSize.Level1)
{
    std::string mac = "abcdefghijklmn";
    WifiErrorNo err = mClient.DisconnectLastRoamingBssid(mac);
    EXPECT_TRUE(err == WIFI_IDL_OPT_INPUT_MAC_INVALID);
    mac = "00:00:00:00:00:00";
    err = mClient.DisconnectLastRoamingBssid(mac);
    EXPECT_FALSE(err == WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.DisconnectLastRoamingBssid(mac) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqGetSupportFeatureTest, TestSize.Level1)
{
    long feature = 0;
    WifiErrorNo err = mClient.ReqGetSupportFeature(feature);
    EXPECT_FALSE(err == WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqGetSupportFeature(feature) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, SetTxPowerTest, TestSize.Level1)
{
    int power = 1;
    WifiErrorNo err = mClient.SetTxPower(power);
    EXPECT_FALSE(err == WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.SetTxPower(power) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

static char **MockConVectorToCArrayString(const std::vector<std::string> &vec)
{
    int size = vec.size();
    if (size == 0) {
        return nullptr;
    }
    char **list = (char **)calloc(size, sizeof(char *));
    if (list == nullptr) {
        return nullptr;
    }
    int i = 0;
    for (; i < size; ++i) {
        int len = vec[i].length();
        list[i] = (char *)calloc(len + 1, sizeof(char));
        if (list[i] == nullptr) {
            break;
        }
        if (strncpy_s(list[i], len + 1, vec[i].c_str(), len) != EOK) {
            break;
        }
    }
    if (i < size) {
        for (int j = 0; j <= i; ++j) {
            free(list[j]);
        }
        free(list);
        return nullptr;
    } else {
        return list;
    }
}

HWTEST_F(WifiIdlClientTest, MockConVectorToCArrayStringTest, TestSize.Level1)
{
    std::vector<std::string> vec;
    char **list = MockConVectorToCArrayString(vec);
    ASSERT_TRUE(list == nullptr);
    vec.push_back("hello");
    vec.push_back("world");
    list = MockConVectorToCArrayString(vec);
    ASSERT_TRUE(list != nullptr);
    for (std::size_t i = 0; i < vec.size(); ++i) {
        ASSERT_TRUE(list[i] != nullptr);
        ASSERT_TRUE(strcmp(list[i], vec[i].c_str()) == 0);
    }
    for (std::size_t i = 0; i < vec.size(); ++i) {
        free(list[i]);
    }
    free(list);
}

static bool MockScanTest(const WifiScanParam &scanParam)
{
    ScanSettings settings;
    if (memset_s(&settings, sizeof(settings), 0, sizeof(settings)) != EOK) {
        return false;
    }
    bool bfail = false;
    do {
        if (scanParam.hiddenNetworkSsid.size() > 0) {
            settings.hiddenSsidSize = scanParam.hiddenNetworkSsid.size();
            settings.hiddenSsid = MockConVectorToCArrayString(scanParam.hiddenNetworkSsid);
            if (settings.hiddenSsid == nullptr) {
                bfail = true;
                break;
            }
        }
        if (scanParam.scanFreqs.size() > 0) {
            settings.freqSize = scanParam.scanFreqs.size();
            settings.freqs = (int *)calloc(settings.freqSize, sizeof(int));
            if (settings.freqs == nullptr) {
                bfail = true;
                break;
            }
            for (int i = 0; i < settings.freqSize; ++i) {
                settings.freqs[i] = scanParam.scanFreqs[i];
            }
        }
        if (scanParam.scanStyle > 0) {
            settings.scanStyle = scanParam.scanStyle;
        }
    } while (0);
    if (settings.freqs != nullptr) {
        free(settings.freqs);
    }
    if (settings.hiddenSsid != nullptr) {
        for (int i = 0; i < settings.hiddenSsidSize; ++i) {
            free(settings.hiddenSsid[i]);
        }
        free(settings.hiddenSsid);
    }
    return !bfail;
}

HWTEST_F(WifiIdlClientTest, ScanTest, TestSize.Level1)
{
    WifiScanParam param;
    param.hiddenNetworkSsid.push_back("abcd");
    param.hiddenNetworkSsid.push_back("efgh");
    ASSERT_TRUE(MockScanTest(param));
    param.scanFreqs.push_back(2412);
    param.scanFreqs.push_back(2417);
    param.scanStyle = 1;
    ASSERT_TRUE(MockScanTest(param));
}

HWTEST_F(WifiIdlClientTest, ReqGetNetworkListTest, TestSize.Level1)
{
    std::vector<WifiWpaNetworkInfo> infos;
    WifiErrorNo err = mClient.ReqGetNetworkList(infos);
    EXPECT_TRUE(err == WIFI_IDL_OPT_FAILED || err == WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqGetNetworkList(infos) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

static void FreePnoScanPstr(PnoScanSettings &settings)
{
    if (settings.freqs != nullptr) {
        free(settings.freqs);
    }
    if (settings.hiddenSsid != nullptr) {
        for (int i = 0; i < settings.hiddenSsidSize; ++i) {
            free(settings.hiddenSsid[i]);
        }
        free(settings.hiddenSsid);
    }
    if (settings.savedSsid != nullptr) {
        for (int i = 0; i < settings.savedSsidSize; ++i) {
            free(settings.savedSsid[i]);
        }
        free(settings.savedSsid);
    }
}

static bool MockPnoScanTest(const WifiPnoScanParam &scanParam)
{
    PnoScanSettings settings;
    if (memset_s(&settings, sizeof(settings), 0, sizeof(settings)) != EOK) {
        return false;
    }
    bool bfail = false;
    do {
        if (scanParam.scanInterval > 0) {
            settings.scanInterval = scanParam.scanInterval;
        }
        settings.minRssi2Dot4Ghz = scanParam.minRssi2Dot4Ghz;
        settings.minRssi5Ghz = scanParam.minRssi5Ghz;
        if (scanParam.hiddenSsid.size() > 0) {
            settings.hiddenSsidSize = scanParam.hiddenSsid.size();
            settings.hiddenSsid = MockConVectorToCArrayString(scanParam.hiddenSsid);
            if (settings.hiddenSsid == nullptr) {
                bfail = true;
                break;
            }
        }
        if (scanParam.savedSsid.size() > 0) {
            settings.savedSsidSize = scanParam.savedSsid.size();
            settings.savedSsid = MockConVectorToCArrayString(scanParam.savedSsid);
            if (settings.savedSsid == nullptr) {
                bfail = true;
                break;
            }
        }
        if (scanParam.scanFreqs.size() > 0) {
            settings.freqSize = scanParam.scanFreqs.size();
            settings.freqs = (int *)calloc(settings.freqSize, sizeof(int));
            if (settings.freqs == nullptr) {
                return WIFI_IDL_OPT_FAILED;
            }
            for (int i = 0; i < settings.freqSize; ++i) {
                settings.freqs[i] = scanParam.scanFreqs[i];
            }
        }
    } while (0);
    FreePnoScanPstr(settings);
    return !bfail;
}

HWTEST_F(WifiIdlClientTest, ReqStartPnoScanTest, TestSize.Level1)
{
    WifiPnoScanParam param;
    param.hiddenSsid.push_back("abcd");
    param.hiddenSsid.push_back("efgh");
    ASSERT_TRUE(MockPnoScanTest(param));
    param.scanFreqs.push_back(2412);
    param.scanFreqs.push_back(2417);
    ASSERT_TRUE(MockPnoScanTest(param));
    param.savedSsid.push_back("abcd");
    ASSERT_TRUE(MockPnoScanTest(param));
}

HWTEST_F(WifiIdlClientTest, StopWifiTest, TestSize.Level1)
{
    WifiErrorNo err = mClient.StopWifi();
    EXPECT_TRUE(err == WIFI_IDL_OPT_FAILED || err == WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.StopWifi() == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, AddBlockByMacTest, TestSize.Level1)
{
    std::string mac = "abcdefghijklmn";
    WifiErrorNo err = mClient.AddBlockByMac(mac);
    EXPECT_TRUE(err == WIFI_IDL_OPT_INPUT_MAC_INVALID);
    mac = "00:00:00:00:00:00";
    err = mClient.AddBlockByMac(mac);
    EXPECT_GE(err, WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.AddBlockByMac(mac) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, DelBlockByMacTest, TestSize.Level1)
{
    std::string mac = "abcdefghijklmn";
    WifiErrorNo err = mClient.DelBlockByMac(mac);
    EXPECT_TRUE(err == WIFI_IDL_OPT_INPUT_MAC_INVALID);
    mac = "00:00:00:00:00:00";
    err = mClient.DelBlockByMac(mac);
    EXPECT_GE(err, WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.DelBlockByMac(mac) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, RemoveStationTest, TestSize.Level1)
{
    std::string mac = "abcdefghijklmn";
    WifiErrorNo err = mClient.RemoveStation(mac);
    EXPECT_TRUE(err == WIFI_IDL_OPT_INPUT_MAC_INVALID);
    mac = "00:00:00:00:00:00";
    err = mClient.RemoveStation(mac);
    EXPECT_GE(err, WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.RemoveStation(mac) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ExitAllClientTest, TestSize.Level1)
{
    mClient.ExitAllClient();
    MockWifiPublic::SetMockFlag(true);
    mClient.ExitAllClient();
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqConnectTest, TestSize.Level1)
{
    int networkId = 1;
    EXPECT_FALSE(mClient.ReqConnect(networkId) == WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqConnect(networkId) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqReconnectTest, TestSize.Level1)
{
    EXPECT_FALSE(mClient.ReqReconnect() == WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqReconnect() == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqReassociateTest, TestSize.Level1)
{
    EXPECT_FALSE(mClient.ReqReassociate() == WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqReassociate() == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqDisconnectTest, TestSize.Level1)
{
    EXPECT_FALSE(mClient.ReqDisconnect() == WIFI_IDL_OPT_OK);
    EXPECT_FALSE(mClient.ReqReassociate() == WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqReassociate() == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqDisconnect() == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, SendRequestTest1, TestSize.Level1)
{
    WifiStaRequest request;
    EXPECT_TRUE(mClient.SendRequest(request) == WIFI_IDL_OPT_OK);
}

HWTEST_F(WifiIdlClientTest, ScanTest1, TestSize.Level1)
{
    WifiScanParam scanParam;
    scanParam.hiddenNetworkSsid.push_back("abcd");
    scanParam.hiddenNetworkSsid.push_back("efgh");
    scanParam.scanFreqs.push_back(FREQUENCY1);
    scanParam.scanFreqs.push_back(FREQUENCY2);
    scanParam.scanStyle = 1;
    EXPECT_TRUE(mClient.Scan(scanParam) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.Scan(scanParam) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ScanTest2, TestSize.Level1)
{
    WifiScanParam scanParam;
    scanParam.scanFreqs.push_back(FREQUENCY1);
    scanParam.scanFreqs.push_back(FREQUENCY2);
    scanParam.scanStyle = 1;
    EXPECT_TRUE(mClient.Scan(scanParam) == WIFI_IDL_OPT_FAILED);
}

HWTEST_F(WifiIdlClientTest, ScanTest3, TestSize.Level1)
{
    WifiScanParam scanParam;
    scanParam.hiddenNetworkSsid.push_back("abcd");
    scanParam.hiddenNetworkSsid.push_back("efgh");
    scanParam.scanStyle = 1;
    EXPECT_TRUE(mClient.Scan(scanParam) == WIFI_IDL_OPT_FAILED);
}

HWTEST_F(WifiIdlClientTest, ScanTest4, TestSize.Level1)
{
    WifiScanParam scanParam;
    scanParam.scanStyle = 1;
    EXPECT_TRUE(mClient.Scan(scanParam) == WIFI_IDL_OPT_FAILED);
}

HWTEST_F(WifiIdlClientTest, ReqStartPnoScanTest1, TestSize.Level1)
{
    WifiPnoScanParam scanParam;
    scanParam.scanInterval = 1;
    scanParam.scanFreqs.push_back(SCANFRENQUE);
    scanParam.hiddenSsid.push_back("abcd");
    scanParam.savedSsid.push_back("honor");
    EXPECT_FALSE(mClient.ReqStartPnoScan(scanParam) == WIFI_IDL_OPT_OK);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqStartPnoScan(scanParam) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqStartPnoScanTest2, TestSize.Level1)
{
    WifiPnoScanParam scanParam;
    scanParam.scanFreqs.push_back(SCANFRENQUE);
    scanParam.hiddenSsid.push_back("abcd");
    scanParam.savedSsid.push_back("honor");
    EXPECT_FALSE(mClient.ReqStartPnoScan(scanParam) == WIFI_IDL_OPT_OK);
}

HWTEST_F(WifiIdlClientTest, ReqStartPnoScanTest3, TestSize.Level1)
{
    WifiPnoScanParam scanParam;
    scanParam.scanInterval = 1;
    scanParam.scanFreqs.push_back(SCANFRENQUE);
    scanParam.savedSsid.push_back("honor");
    EXPECT_FALSE(mClient.ReqStartPnoScan(scanParam) == WIFI_IDL_OPT_OK);
}

HWTEST_F(WifiIdlClientTest, ReqStartPnoScanTest4, TestSize.Level1)
{
    WifiPnoScanParam scanParam;
    scanParam.scanInterval = 1;
    scanParam.scanFreqs.push_back(SCANFRENQUE);
    scanParam.hiddenSsid.push_back("abcd");
    EXPECT_FALSE(mClient.ReqStartPnoScan(scanParam) == WIFI_IDL_OPT_OK);
}

HWTEST_F(WifiIdlClientTest, ReqStartPnoScanTest5, TestSize.Level1)
{
    WifiPnoScanParam scanParam;
    scanParam.scanInterval = 1;
    scanParam.hiddenSsid.push_back("abcd");
    scanParam.savedSsid.push_back("honor");
    EXPECT_FALSE(mClient.ReqStartPnoScan(scanParam) == WIFI_IDL_OPT_OK);
}

HWTEST_F(WifiIdlClientTest, RemoveDeviceTest1, TestSize.Level1)
{
    int networkId = INVALIDNET;
    EXPECT_EQ(WIFI_IDL_OPT_INVALID_PARAM, mClient.RemoveDevice(networkId));
}

HWTEST_F(WifiIdlClientTest, RemoveDeviceTest2, TestSize.Level1)
{
    int networkId = 1;
    mClient.RemoveDevice(networkId);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.RemoveDevice(networkId) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, GetNextNetworkIdTest1, TestSize.Level1)
{
    int networkId = 1;
    mClient.GetNextNetworkId(networkId);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.GetNextNetworkId(networkId) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqEnableNetwork(networkId) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqDisableNetwork(networkId) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqEnableNetworkTest1, TestSize.Level1)
{
    int networkId = 1;
    mClient.ReqEnableNetwork(networkId);
}

HWTEST_F(WifiIdlClientTest, ReqDisableNetworkTest1, TestSize.Level1)
{
    int networkId = 1;
    mClient.ReqDisableNetwork(networkId);
}

HWTEST_F(WifiIdlClientTest, GetDeviceConfigTest1, TestSize.Level1)
{
    WifiIdlGetDeviceConfig config;
    config.networkId = 1;
    config.param = "abcd";
    config.value = "1234";
    mClient.GetDeviceConfig(config);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.GetDeviceConfig(config) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, SetDeviceConfigTest1, TestSize.Level1)
{
    WifiIdlDeviceConfig config;
    int networkId = 1;
    config.psk = "123456";
    EXPECT_TRUE(mClient.SetDeviceConfig(networkId, config) == WIFI_IDL_OPT_FAILED);
}

HWTEST_F(WifiIdlClientTest, SetDeviceConfigTest2, TestSize.Level1)
{
    WifiIdlDeviceConfig config;
    int networkId = 1;
    config.psk = "ADFJKLAJFKLFAJDKLJAFKLDSJGJRIOJIESAJRFNESAGIASEJDGJASDKDGJKALSDJASASDF";
    EXPECT_TRUE(mClient.SetDeviceConfig(networkId, config) == WIFI_IDL_OPT_FAILED);
}

HWTEST_F(WifiIdlClientTest, SetDeviceConfigTest3, TestSize.Level1)
{
    WifiIdlDeviceConfig config;
    int networkId = 1;
    config.psk = "123456";
    config.authAlgorithms = TEN;
    EXPECT_TRUE(mClient.SetDeviceConfig(networkId, config) == WIFI_IDL_OPT_FAILED);
}

HWTEST_F(WifiIdlClientTest, SetDeviceConfigTest4, TestSize.Level1)
{
    WifiIdlDeviceConfig config;
    int networkId = 1;
    config.ssid = "abcd";
    config.psk = "123456789";
    config.authAlgorithms = BIT0;
    config.keyMgmt = "NONE";
    config.priority = 1;
    config.scanSsid = 1;
    config.wepKeyIdx = 1;
    config.eapConfig.phase2Method = 0;
    mClient.SetDeviceConfig(networkId, config);
    config.keyMgmt = "WEP";
    mClient.SetDeviceConfig(networkId, config);
    config.keyMgmt = "WPA-PSK";
    mClient.SetDeviceConfig(networkId, config);
    config.priority = INVALIDNET;
    mClient.SetDeviceConfig(networkId, config);
    config.scanSsid = 0;
    mClient.SetDeviceConfig(networkId, config);
    config.wepKeyIdx = INVALIDNET;
    mClient.SetDeviceConfig(networkId, config);
    config.authAlgorithms = 0;
    mClient.SetDeviceConfig(networkId, config);
    config.eapConfig.phase2Method = 1;
    mClient.SetDeviceConfig(networkId, config);
    config.ssid = "";
    mClient.SetDeviceConfig(networkId, config);
    config.authAlgorithms = BIT1;
    mClient.SetDeviceConfig(networkId, config);
    config.authAlgorithms = BIT2;
    mClient.SetDeviceConfig(networkId, config);
    config.authAlgorithms = 0;
    mClient.SetDeviceConfig(networkId, config);
    config.isRequirePmf = true;
    mClient.SetDeviceConfig(networkId, config);
    config.allowedProtocols = 1;
    mClient.SetDeviceConfig(networkId, config);
    config.allowedPairwiseCiphers = 1;
    mClient.SetDeviceConfig(networkId, config);
    config.allowedGroupCiphers = 1;
    mClient.SetDeviceConfig(networkId, config);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.SetDeviceConfig(networkId, config) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, SetWpsBssidTest1, TestSize.Level1)
{
    int networkId = 1;
    std::string bssid = "";
    EXPECT_TRUE(mClient.SetBssid(networkId, bssid) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.SetBssid(networkId, bssid) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, SetWpsBssidTest2, TestSize.Level1)
{
    int networkId = 1;
    std::string bssid = "abcde";
    mClient.SetBssid(networkId, bssid);
}

HWTEST_F(WifiIdlClientTest, SaveDeviceConfigTest, TestSize.Level1)
{
    mClient.SaveDeviceConfig();
}

HWTEST_F(WifiIdlClientTest, ReqStartWpsPbcModeTest, TestSize.Level1)
{
    WifiIdlWpsConfig config;
    config.anyFlag = 1;
    config.multiAp = 1;
    mClient.ReqStartWpsPbcMode(config);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqStartWpsPbcMode(config) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.SaveDeviceConfig() == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqStartWpsPinModeTest, TestSize.Level1)
{
    WifiIdlWpsConfig config;
    int pinCode = 1;
    config.anyFlag = 1;
    config.multiAp = 1;
    mClient.ReqStartWpsPinMode(config, pinCode);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqStartWpsPinMode(config, pinCode) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqStopWpsTest, TestSize.Level1)
{
    mClient.ReqStopWps();
}

HWTEST_F(WifiIdlClientTest, ReqGetRoamingCapabilitiesTest, TestSize.Level1)
{
    WifiIdlRoamCapability capability;
    mClient.ReqGetRoamingCapabilities(capability);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqGetRoamingCapabilities(capability) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqStopWps() == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqSetRoamConfigTest1, TestSize.Level1)
{
    WifiIdlRoamConfig config;
    EXPECT_TRUE(mClient.ReqSetRoamConfig(config) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqSetRoamConfig(config) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqSetRoamConfigTest2, TestSize.Level1)
{
    WifiIdlRoamConfig config;
    config.blocklistBssids.push_back("abcd");
    config.blocklistBssids.push_back("1234");
    config.trustlistBssids.push_back("abcd");
    config.trustlistBssids.push_back("56789");
    mClient.ReqSetRoamConfig(config);
}

HWTEST_F(WifiIdlClientTest, ReqSetRoamConfigTest3, TestSize.Level1)
{
    WifiIdlRoamConfig config;
    config.blocklistBssids.push_back("abcd");
    config.blocklistBssids.push_back("1234");
    mClient.ReqSetRoamConfig(config);
}

HWTEST_F(WifiIdlClientTest, ReqSetRoamConfigTest4, TestSize.Level1)
{
    WifiIdlRoamConfig config;
    config.trustlistBssids.push_back("abcd");
    config.trustlistBssids.push_back("56789");
    EXPECT_TRUE(mClient.ReqSetRoamConfig(config) == WIFI_IDL_OPT_FAILED);
}

HWTEST_F(WifiIdlClientTest, ReqGetConnectSignalInfoTest2, TestSize.Level1)
{
    std::string endBssid = "aa::bb::cc:dd::ee:ff";
    WifiWpaSignalInfo info;
    mClient.ReqGetConnectSignalInfo(endBssid, info);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqGetConnectSignalInfo(endBssid, info) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, StartApTest, TestSize.Level1)
{
    int id = 1;
    mClient.StartAp(id, "wlan0");
}

HWTEST_F(WifiIdlClientTest, StopApTest, TestSize.Level1)
{
    int id = 1;
    mClient.StopAp(id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.StartAp(id, "wlan0") == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.StopAp(id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, SetSoftApConfigTest, TestSize.Level1)
{
    int id = 1;
    HotspotConfig config;
    config.SetSsid("abcde");
    config.SetPreSharedKey("123456789");
    mClient.SetSoftApConfig(config, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.SetSoftApConfig(config, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, GetStationListTest, TestSize.Level1)
{
    int id = 1;
    std::vector<std::string> result;
    mClient.GetStationList(result, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.GetStationList(result, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, AddBlockByMacTest1, TestSize.Level1)
{
    int id = 1;
    std::string mac = "123456";
    EXPECT_TRUE(mClient.AddBlockByMac(mac, id) == WIFI_IDL_OPT_INPUT_MAC_INVALID);
}

HWTEST_F(WifiIdlClientTest, AddBlockByMacTest2, TestSize.Level1)
{
    int id = 1;
    std::string mac = "00:00:11:22:33:44";
    mClient.AddBlockByMac(mac, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.AddBlockByMac(mac, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, DelBlockByMacTest1, TestSize.Level1)
{
    int id = 1;
    std::string mac = "00:00:11";
    EXPECT_TRUE(mClient.DelBlockByMac(mac, id) == WIFI_IDL_OPT_INPUT_MAC_INVALID);
}

HWTEST_F(WifiIdlClientTest, DelBlockByMacTest2, TestSize.Level1)
{
    int id = 1;
    std::string mac = "00:00:11:22:33:44";
    mClient.DelBlockByMac(mac, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.DelBlockByMac(mac, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, RemoveStationTest1, TestSize.Level1)
{
    int id = 1;
    std::string mac = "00:00:11";
    EXPECT_TRUE(mClient.RemoveStation(mac, id) == WIFI_IDL_OPT_INPUT_MAC_INVALID);
}

HWTEST_F(WifiIdlClientTest, RemoveStationTest2, TestSize.Level1)
{
    int id = 1;
    std::string mac = "00:00:11:22:33:44";
    mClient.RemoveStation(mac, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.RemoveStation(mac, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, GetFrequenciesByBandTest1, TestSize.Level1)
{
    int id = 1;
    int32_t band = 1;
    std::vector<int> frequencies;
    mClient.GetFrequenciesByBand(band, frequencies, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.GetFrequenciesByBand(band, frequencies, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, SetWifiCountryCodeTest1, TestSize.Level1)
{
    std::string code = "abcde";
    int id = 1;
    EXPECT_TRUE(mClient.SetWifiCountryCode(code, id) == WIFI_IDL_OPT_INVALID_PARAM);
}

HWTEST_F(WifiIdlClientTest, SetWifiCountryCodeTest2, TestSize.Level1)
{
    std::string code = "ab";
    int id = 1;
    mClient.SetWifiCountryCode(code, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.SetWifiCountryCode(code, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqDisconnectStaByMacTest1, TestSize.Level1)
{
    int id = 1;
    std::string mac = "00:00:11";
    EXPECT_TRUE(mClient.ReqDisconnectStaByMac(mac, id) == WIFI_IDL_OPT_INPUT_MAC_INVALID);
}

HWTEST_F(WifiIdlClientTest, ReqDisconnectStaByMacTest2, TestSize.Level1)
{
    int id = 1;
    std::string mac = "00:00:11:22:33:44";
    mClient.ReqDisconnectStaByMac(mac, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqDisconnectStaByMac(mac, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqGetPowerModelTest, TestSize.Level1)
{
    int id = 1;
    int model = 1;
    mClient.ReqGetPowerModel(model, id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqGetPowerModel(model, id) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqSetPowerModelTest, TestSize.Level1)
{
    int id = 1;
    int model = 1;
    mClient.ReqSetPowerModel(model, id);
}

HWTEST_F(WifiIdlClientTest, GetWifiChipObjectTest, TestSize.Level1)
{
    int id = 1;
    IWifiChip chip;
    EXPECT_TRUE(mClient.GetWifiChipObject(id, chip) == WIFI_IDL_OPT_OK);
}

HWTEST_F(WifiIdlClientTest, GetChipIdsTest, TestSize.Level1)
{
    std::vector<int> ids;
    EXPECT_TRUE(mClient.GetChipIds(ids) == WIFI_IDL_OPT_OK);
}

HWTEST_F(WifiIdlClientTest, GetUsedChipIdTest, TestSize.Level1)
{
    int id = 1;
    EXPECT_TRUE(mClient.GetUsedChipId(id) == WIFI_IDL_OPT_OK);
}

HWTEST_F(WifiIdlClientTest, GetChipCapabilitiesTest, TestSize.Level1)
{
    int capabilities = 1;
    EXPECT_TRUE(mClient.GetChipCapabilities(capabilities) == WIFI_IDL_OPT_OK);
}

HWTEST_F(WifiIdlClientTest, GetSupportedModesTest, TestSize.Level1)
{
    std::vector<int> modes;
    mClient.GetSupportedModes(modes);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.GetSupportedModes(modes) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ConfigRunModesTest, TestSize.Level1)
{
    int mode = 1;
    EXPECT_TRUE(mClient.ConfigRunModes(mode) == WIFI_IDL_OPT_OK);
}

HWTEST_F(WifiIdlClientTest, GetCurrentModeTest, TestSize.Level1)
{
    int mode = 1;
    EXPECT_TRUE(mClient.GetCurrentMode(mode) == WIFI_IDL_OPT_OK);
}

HWTEST_F(WifiIdlClientTest, RegisterChipEventCallbackTest, TestSize.Level1)
{
    WifiChipEventCallback callback;
    mClient.RegisterChipEventCallback(callback);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.RegisterChipEventCallback(callback) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, RequestFirmwareDebugInfoTest, TestSize.Level1)
{
    std::string debugInfo = "debug";
    EXPECT_TRUE(mClient.RequestFirmwareDebugInfo(debugInfo) == WIFI_IDL_OPT_OK);
}

HWTEST_F(WifiIdlClientTest, ReqStartSupplicantTest, TestSize.Level1)
{
    mClient.ReqStartSupplicant();
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqStartSupplicant() == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqStopSupplicant() == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqConnectSupplicant() == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqDisconnectSupplicant() == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqStopSupplicantTest, TestSize.Level1)
{
    mClient.ReqStopSupplicant();
}

HWTEST_F(WifiIdlClientTest, ReqConnectSupplicantTest, TestSize.Level1)
{
    mClient.ReqConnectSupplicant();
}

HWTEST_F(WifiIdlClientTest, ReqDisconnectSupplicantTest, TestSize.Level1)
{
    mClient.ReqDisconnectSupplicant();
}

HWTEST_F(WifiIdlClientTest, ReqRequestToSupplicantTest, TestSize.Level1)
{
    std::string request = "request";
    mClient.ReqRequestToSupplicant(request);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqRequestToSupplicant(request) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqSetPowerSave(true) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqSetPowerSaveTest1, TestSize.Level1)
{
    bool enable = true;
    mClient.ReqSetPowerSave(enable);
}

HWTEST_F(WifiIdlClientTest, ReqSetPowerSaveTest2, TestSize.Level1)
{
    bool enable = false;
    mClient.ReqSetPowerSave(enable);
}

HWTEST_F(WifiIdlClientTest, ReqWpaSetCountryCodeTest1, TestSize.Level1)
{
    std::string countryCode = "adaf";
    EXPECT_TRUE(mClient.ReqWpaSetCountryCode(countryCode) == WIFI_IDL_OPT_INVALID_PARAM);
    countryCode = "af";
    mClient.ReqWpaSetCountryCode(countryCode);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqWpaSetCountryCode(countryCode) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqWpaGetCountryCode(countryCode) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqWpaGetCountryCodeTest2, TestSize.Level1)
{
    std::string countryCode = "ad";
    mClient.ReqWpaGetCountryCode(countryCode);
}

HWTEST_F(WifiIdlClientTest, ReqWpaGetCountryCodeTest, TestSize.Level1)
{
    std::string countryCode = "ad";
    mClient.ReqWpaGetCountryCode(countryCode);
}

HWTEST_F(WifiIdlClientTest, ReqWpaBlocklistClearTest, TestSize.Level1)
{
    mClient.ReqWpaBlocklistClear();
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqWpaBlocklistClear() == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqP2pStop() == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqP2pSaveConfig() == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pStopTest, TestSize.Level1)
{
    mClient.ReqP2pStop();
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetWpsDeviceTypeTest, TestSize.Level1)
{
    std::string type = "tv";
    mClient.ReqP2pSetWpsDeviceType(type);
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetWpsSecondaryDeviceTypeTest, TestSize.Level1)
{
    std::string type = "tv";
    mClient.ReqP2pSetWpsSecondaryDeviceType(type);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pSetWpsSecondaryDeviceType(type) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqP2pSetWpsDeviceType(type) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pSaveConfigTest, TestSize.Level1)
{
    mClient.ReqP2pSaveConfig();
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetupWpsPbcTest, TestSize.Level1)
{
    std::string groupInterface = "Interface";
    std::string bssid = "honor";
    mClient.ReqP2pSetupWpsPbc(groupInterface, bssid);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pSetupWpsPbc(groupInterface, bssid) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetupWpsPinTest1, TestSize.Level1)
{
    std::string groupInterface = "Interface";
    std::string address = "aa:bb:cc:dd:ee:ff";
    std::string pin = "123";
    std::string result = "none";
    EXPECT_TRUE(mClient.ReqP2pSetupWpsPin(groupInterface, address, pin, result) == WIFI_IDL_OPT_INVALID_PARAM);
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetupWpsPinTest2, TestSize.Level1)
{
    std::string groupInterface = "Interface";
    std::string address = "aa:bb:cc:dd:ee:ff";
    std::string pin = "12345678";
    std::string result = "none";
    mClient.ReqP2pSetupWpsPin(groupInterface, address, pin, result);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pSetupWpsPin(groupInterface, address, pin, result) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pRemoveNetworkTest, TestSize.Level1)
{
    int networkId = 1;
    mClient.ReqP2pRemoveNetwork(networkId);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pRemoveNetwork(networkId) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetGroupMaxIdleTest, TestSize.Level1)
{
    std::string groupInterface = "groupInterface";
    size_t time = 1;
    mClient.ReqP2pSetGroupMaxIdle(groupInterface, time);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pSetGroupMaxIdle(groupInterface, time) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetPowerSaveTest, TestSize.Level1)
{
    std::string groupInterface = "groupInterface";
    bool enable = true;
    mClient.ReqP2pSetPowerSave(groupInterface, enable);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pSetPowerSave(groupInterface, enable) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqP2pSetWfdDeviceConfig(groupInterface) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqP2pSetWfdEnable(enable) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetWfdEnableTest, TestSize.Level1)
{
    bool enable = true;
    mClient.ReqP2pSetWfdEnable(enable);
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetWfdDeviceConfigTest, TestSize.Level1)
{
    std::string config = "abcde";
    mClient.ReqP2pSetWfdDeviceConfig(config);
}

HWTEST_F(WifiIdlClientTest, ReqP2pStartFindTest, TestSize.Level1)
{
    size_t timeout = 1;
    mClient.ReqP2pStartFind(timeout);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pStartFind(timeout) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqP2pStopFind() == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pStopFindTest, TestSize.Level1)
{
    mClient.ReqP2pStopFind();
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetExtListenTest, TestSize.Level1)
{
    bool enable = true;
    size_t period = 0;
    size_t interval = 0;
    EXPECT_TRUE(mClient.ReqP2pSetExtListen(enable, period, interval) == WIFI_IDL_OPT_INVALID_PARAM);
    period = MAX_TIME;
    EXPECT_TRUE(mClient.ReqP2pSetExtListen(enable, period, interval) == WIFI_IDL_OPT_INVALID_PARAM);
    period = 1;
    EXPECT_TRUE(mClient.ReqP2pSetExtListen(enable, period, interval) == WIFI_IDL_OPT_INVALID_PARAM);
    interval = MAX_TIME;
    EXPECT_TRUE(mClient.ReqP2pSetExtListen(enable, period, interval) == WIFI_IDL_OPT_INVALID_PARAM);
    interval = 1;
    period = BIT2;
    EXPECT_TRUE(mClient.ReqP2pSetExtListen(enable, period, interval) == WIFI_IDL_OPT_INVALID_PARAM);
    interval = BIT2;
    period = 1;
    enable = false;
    mClient.ReqP2pSetExtListen(enable, period, interval);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pSetExtListen(enable, period, interval) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetListenChannelTest, TestSize.Level1)
{
    size_t channel = 1;
    unsigned char regClass = BIT1;
    mClient.ReqP2pSetListenChannel(channel, regClass);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pSetListenChannel(channel, regClass) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pConnectTest, TestSize.Level1)
{
    WifiP2pConfigInternal config;
    bool isJoinExistingGroup = true;
    std::string pin = "adc";
    WpsInfo info;
    info.SetPin("25");
    info.SetWpsMethod(WpsMethod::WPS_METHOD_PBC);
    config.SetNetId(1);
    config.SetGroupOwnerIntent(1);
    config.SetDeviceAddress("aa:bb::cc:dd");
    config.SetWpsInfo(info);
    EXPECT_TRUE(mClient.ReqP2pConnect(config, isJoinExistingGroup, pin) == WIFI_IDL_OPT_INVALID_PARAM);
    isJoinExistingGroup = false;
    config.SetGroupOwnerIntent(INVALIDNET);
    EXPECT_TRUE(mClient.ReqP2pConnect(config, isJoinExistingGroup, pin) == WIFI_IDL_OPT_INVALID_PARAM);
    config.SetGroupOwnerIntent(SCANFRENQUE);
    EXPECT_TRUE(mClient.ReqP2pConnect(config, isJoinExistingGroup, pin) == WIFI_IDL_OPT_INVALID_PARAM);
    config.SetDeviceAddress("aa:bb::cc:dd:ee:ff");
    EXPECT_TRUE(mClient.ReqP2pConnect(config, isJoinExistingGroup, pin) == WIFI_IDL_OPT_INVALID_PARAM);
    info.SetWpsMethod(WpsMethod::WPS_METHOD_LABEL);
    config.SetWpsInfo(info);
    mClient.ReqP2pConnect(config, isJoinExistingGroup, pin);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pConnect(config, isJoinExistingGroup, pin) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqP2pCancelConnect() == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pCancelConnectTest, TestSize.Level1)
{
    mClient.ReqP2pCancelConnect();
}

HWTEST_F(WifiIdlClientTest, ReqP2pProvisionDiscoveryTest, TestSize.Level1)
{
    WifiP2pConfigInternal config;
    WpsInfo info;
    info.SetWpsMethod(WpsMethod::WPS_METHOD_LABEL);
    config.SetWpsInfo(info);
    mClient.ReqP2pProvisionDiscovery(config);
    info.SetWpsMethod(WpsMethod::WPS_METHOD_DISPLAY);
    config.SetWpsInfo(info);
    mClient.ReqP2pProvisionDiscovery(config);
    info.SetWpsMethod(WpsMethod::WPS_METHOD_KEYPAD);
    config.SetWpsInfo(info);
    mClient.ReqP2pProvisionDiscovery(config);
    info.SetWpsMethod(WpsMethod::WPS_METHOD_INVALID);
    config.SetWpsInfo(info);
    EXPECT_TRUE(mClient.ReqP2pProvisionDiscovery(config) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pProvisionDiscovery(config) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pAddGroupTest, TestSize.Level1)
{
    bool isPersistent = false;
    int networkId = 1;
    int freq = 1;
    mClient.ReqP2pAddGroup(isPersistent, networkId, freq);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pAddGroup(isPersistent, networkId, freq) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pRemoveGroupTest, TestSize.Level1)
{
    std::string groupInterface = "Interface";
    mClient.ReqP2pRemoveGroup(groupInterface);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pRemoveGroup(groupInterface) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pInviteTest, TestSize.Level1)
{
    uint32_t cap = 1;
    WifiP2pGroupInfo group;
    std::string deviceAddr = "aa:bb:cc:dd:ee:ff";
    mClient.ReqP2pInvite(group, deviceAddr);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pInvite(group, deviceAddr) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqP2pReinvoke(1, deviceAddr) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqP2pGetGroupCapability(deviceAddr, cap) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pReinvokeTest, TestSize.Level1)
{
    int networkId = 1;
    std::string deviceAddr = "aa:bb:cc:dd:ee:ff";
    mClient.ReqP2pReinvoke(networkId, deviceAddr);
}

HWTEST_F(WifiIdlClientTest, ReqP2pGetGroupCapabilityTest, TestSize.Level1)
{
    uint32_t cap = 1;
    std::string deviceAddress = "aa:bb:cc:dd:ee:ff";
    mClient.ReqP2pGetGroupCapability(deviceAddress, cap);
}

HWTEST_F(WifiIdlClientTest, ReqP2pAddServiceTest, TestSize.Level1)
{
    WifiP2pServiceInfo info;
    std::vector<std::string> queryList;
    EXPECT_TRUE(mClient.ReqP2pAddService(info) == WIFI_IDL_OPT_OK);
    queryList.push_back("a b");
    info.SetQueryList(queryList);
    EXPECT_TRUE(mClient.ReqP2pAddService(info) == WIFI_IDL_OPT_FAILED);
    queryList.clear();
    queryList.push_back("aa bb cc");
    info.SetQueryList(queryList);
    EXPECT_TRUE(mClient.ReqP2pAddService(info) == WIFI_IDL_OPT_FAILED);
    queryList.clear();
    queryList.push_back("upnp bb cc");
    info.SetQueryList(queryList);
    mClient.ReqP2pAddService(info);
    queryList.clear();
    queryList.push_back("bonjour bb cc");
    info.SetQueryList(queryList);
    mClient.ReqP2pAddService(info);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pAddService(info) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pRemoveServiceTest, TestSize.Level1)
{
    WifiP2pServiceInfo info;
    std::vector<std::string> queryList;
    EXPECT_TRUE(mClient.ReqP2pRemoveService(info) == WIFI_IDL_OPT_OK);
    queryList.push_back("a b");
    info.SetQueryList(queryList);
    EXPECT_TRUE(mClient.ReqP2pRemoveService(info) == WIFI_IDL_OPT_FAILED);
    queryList.clear();
    queryList.push_back("aa bb cc");
    info.SetQueryList(queryList);
    EXPECT_TRUE(mClient.ReqP2pRemoveService(info) == WIFI_IDL_OPT_FAILED);
    queryList.clear();
    queryList.push_back("upnp bb cc");
    info.SetQueryList(queryList);
    mClient.ReqP2pRemoveService(info);
    queryList.clear();
    queryList.push_back("bonjour bb cc");
    info.SetQueryList(queryList);
    mClient.ReqP2pRemoveService(info);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pRemoveService(info) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pReqServiceDiscoveryTest, TestSize.Level1)
{
    std::string reqID;
    std::vector<unsigned char> tlvs;
    std::string deviceAddress = "aa:bb:cc:dd";
    EXPECT_TRUE(mClient.ReqP2pReqServiceDiscovery(deviceAddress, tlvs, reqID) == WIFI_IDL_OPT_INVALID_PARAM);
    deviceAddress = "aa:bb:cc:dd:ee:ff";
    EXPECT_TRUE(mClient.ReqP2pReqServiceDiscovery(deviceAddress, tlvs, reqID) == WIFI_IDL_OPT_INVALID_PARAM);
    tlvs.push_back(1);
    mClient.ReqP2pReqServiceDiscovery(deviceAddress, tlvs, reqID);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pReqServiceDiscovery(deviceAddress, tlvs, reqID) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pCancelServiceDiscoveryTest, TestSize.Level1)
{
    std::string id = "tv";
    mClient.ReqP2pCancelServiceDiscovery(id);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pCancelServiceDiscovery(id) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqP2pSetMiracastType(1) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetMiracastTypeTest, TestSize.Level1)
{
    int type = 1;
    mClient.ReqP2pSetMiracastType(type);
}

HWTEST_F(WifiIdlClientTest, ReqRespServiceDiscoveryTest, TestSize.Level1)
{
    WifiP2pDevice device;
    int frequency = 1;
    int dialogToken = 1;
    std::vector<unsigned char> tlvs;
    EXPECT_TRUE(mClient.ReqRespServiceDiscovery(device, frequency, dialogToken, tlvs) == WIFI_IDL_OPT_INVALID_PARAM);
    tlvs.push_back(1);
    mClient.ReqRespServiceDiscovery(device, frequency, dialogToken, tlvs);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqRespServiceDiscovery(device, frequency, dialogToken, tlvs) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqGetP2pPeerTest, TestSize.Level1)
{
    WifiP2pDevice device;
    std::string deviceAddress = "aa:bb:cc:00:00:00";
    mClient.ReqGetP2pPeer(deviceAddress, device);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqGetP2pPeer(deviceAddress, device) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pGetSupportFrequenciesTest, TestSize.Level1)
{
    int band = 1;
    std::vector<int> frequencies;
    mClient.ReqP2pGetSupportFrequencies(band, frequencies);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pGetSupportFrequencies(band, frequencies) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetGroupConfigTest, TestSize.Level1)
{
    int networkId = 1;
    IdlP2pGroupConfig config;
    config.ssid = "abcd";
    config.bssid = "00:00:00:00:00:00";
    config.psk = "132456789";
    mClient.ReqP2pSetGroupConfig(networkId, config);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pSetGroupConfig(networkId, config) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pGetGroupConfigTest, TestSize.Level1)
{
    int networkId = 1;
    IdlP2pGroupConfig config;
    mClient.ReqP2pGetGroupConfig(networkId, config);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pGetGroupConfig(networkId, config) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pAddNetworkTest, TestSize.Level1)
{
    int networkId = 1;
    mClient.ReqP2pAddNetwork(networkId);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pAddNetwork(networkId) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pHid2dConnectTest, TestSize.Level1)
{
    Hid2dConnectConfig config;
    config.SetSsid("abcd");
    config.SetBssid("00:00:00:00:00:00");
    config.SetPreSharedKey("123456789");
    mClient.ReqP2pHid2dConnect(config);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pHid2dConnect(config) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqWpaSetSuspendMode(true) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqWpaSetSuspendModeTest, TestSize.Level1)
{
    bool mode = true;
    mClient.ReqWpaSetSuspendMode(mode);
}

HWTEST_F(WifiIdlClientTest, QueryScanInfosTest, TestSize.Level1)
{
    std::vector<InterScanInfo> scanInfos;
    mClient.QueryScanInfos(scanInfos);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.QueryScanInfos(scanInfos) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqRegisterSupplicantEventCallbackTest, TestSize.Level1)
{
    SupplicantEventCallback callback;
    mClient.ReqRegisterSupplicantEventCallback(callback);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqRegisterSupplicantEventCallback(callback) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqUnRegisterSupplicantEventCallback() == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqUnRegisterSupplicantEventCallbackTest, TestSize.Level1)
{
    mClient.ReqUnRegisterSupplicantEventCallback();
}

HWTEST_F(WifiIdlClientTest, ReqP2pGetDeviceAddressTest, TestSize.Level1)
{
    std::string deviceAddress = "10.26.120.74";
    mClient.ReqP2pGetDeviceAddress(deviceAddress);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pGetDeviceAddress(deviceAddress) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqWpaAutoConnect(0) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pListNetworksTest, TestSize.Level1)
{
    std::map<int, WifiP2pGroupInfo> mapGroups;
    mClient.ReqP2pListNetworks(mapGroups);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pListNetworks(mapGroups) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqP2pStart() == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqWpaAutoConnectTest, TestSize.Level1)
{
    mClient.ReqWpaAutoConnect(0);
}

HWTEST_F(WifiIdlClientTest, ReqP2pStartTest, TestSize.Level1)
{
    mClient.ReqP2pStart();
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetDeviceNameTest, TestSize.Level1)
{
    std::string name = "10.26.120.74";
    mClient.ReqP2pSetDeviceName(name);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pSetSsidPostfixName(name) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqP2pSetDeviceName(name) == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqP2pSetWpsConfigMethods(name) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetSsidPostfixNameTest, TestSize.Level1)
{
    std::string postfixName = "10.26.120.74";
    mClient.ReqP2pSetSsidPostfixName(postfixName);
}

HWTEST_F(WifiIdlClientTest, ReqP2pSetWpsConfigMethodsTest, TestSize.Level1)
{
    std::string config = "10.26.120.74";
    mClient.ReqP2pSetWpsConfigMethods(config);
}

HWTEST_F(WifiIdlClientTest, ReqP2pFlushTest, TestSize.Level1)
{
    mClient.ReqP2pFlush();
}

HWTEST_F(WifiIdlClientTest, ReqP2pFlushServiceTest, TestSize.Level1)
{
    mClient.ReqP2pFlushService();
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pFlush() == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqP2pFlushService() == WIFI_IDL_OPT_FAILED);
    EXPECT_TRUE(mClient.ReqWpaSetPowerMode(true) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqWpaSetPowerModeTest, TestSize.Level1)
{
    mClient.ReqWpaSetPowerMode(true);
}

HWTEST_F(WifiIdlClientTest, ReqStopPnoScanTest, TestSize.Level1)
{
    mClient.ReqStopPnoScan();
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqStopPnoScan() == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqRegisterStaEventCallbackt, TestSize.Level1)
{
    WifiEventCallback callback;
    mClient.ReqRegisterStaEventCallback(callback);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqRegisterStaEventCallback(callback) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqP2pGetChba0FreqTest, TestSize.Level1)
{
    int chba0Freq = 0;
    mClient.ReqP2pGetChba0Freq(chba0Freq);
    MockWifiPublic::SetMockFlag(true);
    EXPECT_TRUE(mClient.ReqP2pGetChba0Freq(chba0Freq) == WIFI_IDL_OPT_FAILED);
    MockWifiPublic::SetMockFlag(false);
}

HWTEST_F(WifiIdlClientTest, ReqIsSupportDbdcTest, TestSize.Level1)
{
    bool isSupport = true;
    mClient.ReqIsSupportDbdc(isSupport);
    MockWifiPublic::SetMockFlag(true);
    mClient.ReqIsSupportDbdc(isSupport);
    MockWifiPublic::SetMockFlag(false);
}
}  // namespace Wifi
}  // namespace OHOS