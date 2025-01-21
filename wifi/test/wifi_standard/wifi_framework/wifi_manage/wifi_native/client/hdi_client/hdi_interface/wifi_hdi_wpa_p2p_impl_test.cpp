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
#include "wifi_hdi_wpa_p2p_impl.h"
#include "wifi_error_no.h"
#include "mock_wifi_hdi_wpa_ap_impl.h"

using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
const int SIZE = 128;
class WifiHdiWpaP2pImplTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() override {}
    void TearDown() override {}
};

HWTEST_F(WifiHdiWpaP2pImplTest, HdiWpaP2pStartTest, TestSize.Level1)
{
    WifiErrorNo result = HdiWpaP2pStart("wlan0", true);
    EXPECT_EQ(result, WIFI_HAL_OPT_FAILED);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiWpaP2pStopTest, TestSize.Level1)
{
    WifiErrorNo result = HdiWpaP2pStop();
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetSsidPostfixNameTest, TestSize.Level1)
{
    const char *name = nullptr;
    WifiErrorNo result = HdiP2pSetSsidPostfixName(name);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetWpsDeviceTypeTest, TestSize.Level1)
{
    const char *type = nullptr;
    WifiErrorNo result = HdiP2pSetWpsDeviceType(type);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetWpsConfigMethodsTest, TestSize.Level1)
{
    const char *methods = nullptr;
    WifiErrorNo result = HdiP2pSetWpsConfigMethods(methods);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetGroupMaxIdleTest, TestSize.Level1)
{
    const char *groupIfc = nullptr;
    int time = 1;
    WifiErrorNo result = HdiP2pSetGroupMaxIdle(groupIfc, time);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetWfdEnableTest, TestSize.Level1)
{
    int enable = 1;
    HdiP2pSetWfdEnable(enable);
    EXPECT_EQ(HdiP2pSetWfdEnable(enable),WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetPersistentReconnectTest, TestSize.Level1)
{
    int status = 1;
    HdiP2pSetPersistentReconnect(status);
    EXPECT_EQ(HdiP2pSetPersistentReconnect(status),WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetWpsSecondaryDeviceTypeTest, TestSize.Level1)
{
    const char *type = nullptr;
    WifiErrorNo result = HdiP2pSetWpsSecondaryDeviceType(type);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetupWpsPbcTest, TestSize.Level1)
{
    const char *groupIfc = nullptr;
    const char *address = nullptr;
    WifiErrorNo result = HdiP2pSetupWpsPbc(groupIfc, address);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetupWpsPinTest, TestSize.Level1)
{
    const char *groupIfc = nullptr;
    const char *address = nullptr;
    const char *pin = nullptr;
    char *res = nullptr;
    WifiErrorNo result = HdiP2pSetupWpsPin(groupIfc, address, pin, res);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetPowerSaveTest, TestSize.Level1)
{
    const char *groupIfc = nullptr;
    int enable = 1;
    WifiErrorNo result = HdiP2pSetPowerSave(groupIfc, enable);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetDeviceNameTest, TestSize.Level1)
{
    const char *name = nullptr;
    WifiErrorNo result = HdiP2pSetDeviceName(name);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetWfdDeviceConfigTest, TestSize.Level1)
{
    const char *config = nullptr;
    WifiErrorNo result = HdiP2pSetWfdDeviceConfig(config);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetRandomMacTest, TestSize.Level1)
{
    int enable = 1;
    HdiP2pSetRandomMac(enable);
    EXPECT_EQ(HdiP2pSetRandomMac(enable),WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pStartFindTest, TestSize.Level1)
{
    int timeout = 120;
    HdiP2pStartFind(timeout);
    EXPECT_EQ(HdiP2pStartFind(timeout),WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetExtListenTest, TestSize.Level1)
{
    int enable = 1;
    int period = 1;
    int interval = 1;
    HdiP2pSetExtListen(enable, period, interval);
    EXPECT_EQ(HdiP2pSetExtListen(enable, period, interval), WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetListenChannelTest, TestSize.Level1)
{
    int channel = 1;
    int regClass = 1;
    WifiErrorNo result = HdiP2pSetListenChannel(channel, regClass);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pProvisionDiscoveryTest, TestSize.Level1)
{
    const char *peerBssid = nullptr;
    int mode = 1;
    WifiErrorNo result = HdiP2pProvisionDiscovery(peerBssid, mode);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pAddGroupTest, TestSize.Level1)
{
    int isPersistent = 1;
    int networkId = 5;
    int freq = 5180;
    WifiErrorNo result = HdiP2pAddGroup(isPersistent, networkId, freq);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pAddServiceTest, TestSize.Level1)
{
    struct HdiP2pServiceInfo *info = nullptr;
    WifiErrorNo result = HdiP2pAddService(info);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pStopFindTest, TestSize.Level1)
{
    HdiP2pStopFind();
    EXPECT_EQ(HdiP2pStopFind(),WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pFlushTest, TestSize.Level1)
{
    HdiP2pFlush();
    EXPECT_EQ(HdiP2pFlush(), WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pFlushServiceTest, TestSize.Level1)
{
    HdiP2pFlushService();
    EXPECT_EQ(HdiP2pFlushService(),WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pRemoveNetworkTest, TestSize.Level1)
{
    int networkId = 4;
    WifiErrorNo result = HdiP2pRemoveNetwork(networkId);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetGroupConfigTest, TestSize.Level1)
{
    int networkId = 3;
    P2pGroupConfig pConfig;
    int size = 1;
    WifiErrorNo result = HdiP2pSetGroupConfig(networkId, &pConfig, size);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pInviteTest, TestSize.Level1)
{
    const char *peerBssid = nullptr;
    const char *goBssid = nullptr;
    const char *ifname = nullptr;
    WifiErrorNo result = HdiP2pInvite(peerBssid, goBssid, ifname);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);

    result = HdiP2pInvite("peerBssid", "goBssid", "ifname");
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pReinvokeTest, TestSize.Level1)
{
    int networkId = 2;
    const char *bssid = nullptr;
    WifiErrorNo result = HdiP2pReinvoke(networkId, bssid);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pGetDeviceAddressTest, TestSize.Level1)
{
    char deviceAddress[SIZE] = {0};
    HdiP2pGetDeviceAddress(deviceAddress, SIZE);
    EXPECT_EQ(HdiP2pGetDeviceAddress(deviceAddress, SIZE), WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pReqServiceDiscoveryTest, TestSize.Level1)
{
    struct HdiP2pReqService reqService;
    char replyDisc[SIZE] = {0};
    WifiErrorNo result = HdiP2pReqServiceDiscovery(&reqService, replyDisc, SIZE);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pCancelServiceDiscoveryTest, TestSize.Level1)
{
    const char *id;
    WifiErrorNo result = HdiP2pCancelServiceDiscovery(id);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pRespServerDiscoveryTest, TestSize.Level1)
{
    struct HdiP2pServDiscReqInfo info;
    WifiErrorNo result = HdiP2pRespServerDiscovery(&info);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pConnectTest, TestSize.Level1)
{
    P2pConnectInfo info;
    char replyPin[SIZE] = {0};
    WifiErrorNo result = HdiP2pConnect(&info, replyPin, SIZE);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pHid2dConnectTest, TestSize.Level1)
{
    struct Hid2dConnectInfo info;
    WifiErrorNo result = HdiP2pHid2dConnect(&info);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSetServDiscExternalTest, TestSize.Level1)
{
    int mode = 1;
    HdiP2pSetServDiscExternal(mode);
    EXPECT_EQ(HdiP2pSetServDiscExternal(mode),WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pRemoveGroupTest, TestSize.Level1)
{
    const char *groupName;
    WifiErrorNo result = HdiP2pRemoveGroup(groupName);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pCancelConnectTest, TestSize.Level1)
{
    WifiErrorNo result = HdiP2pCancelConnect();
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pGetGroupConfigTest, TestSize.Level1)
{
    int networkId = 1;
    char *param = nullptr;
    char *value = nullptr;
    WifiErrorNo result = HdiP2pGetGroupConfig(networkId, param, value);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pAddNetworkTest, TestSize.Level1)
{
    int *networkId = nullptr;
    WifiErrorNo result = HdiP2pAddNetwork(networkId);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pGetPeerTest, TestSize.Level1)
{
    const char *bssid = "123";
    struct HdiP2pDeviceInfo info;
    WifiErrorNo result = HdiP2pGetPeer(bssid, &info);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pGetGroupCapabilityTest, TestSize.Level1)
{
    const char *bssid = "123";
    int cap = 1;
    WifiErrorNo result = HdiP2pGetGroupCapability(bssid, cap);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pListNetworksTest, TestSize.Level1)
{
    struct HdiP2pNetworkList infoList;
    HdiP2pListNetworks(&infoList);
    EXPECT_EQ(HdiP2pListNetworks(&infoList), WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pSaveConfigTest, TestSize.Level1)
{
    HdiP2pSaveConfig();
    EXPECT_EQ(HdiP2pSaveConfig(), WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiDeliverP2pDataTest, TestSize.Level1)
{
    int32_t cmdType = 2;
    int32_t dataType = 1;
    const char *carryData = "1";
    HdiDeliverP2pData(cmdType, dataType, carryData);
    EXPECT_EQ(HdiDeliverP2pData(cmdType, dataType, carryData), WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, HdiP2pRemoveServiceTest, TestSize.Level1)
{
    struct HdiP2pServiceInfo info;
    WifiErrorNo result = HdiP2pRemoveService(&info);
    EXPECT_EQ(result, WIFI_HAL_OPT_OK);
}

HWTEST_F(WifiHdiWpaP2pImplTest, RegisterHdiWpaP2pEventCallbackTest, TestSize.Level1)
{
    struct IWpaCallback callback;
    callback.OnEventDeviceFound = nullptr;
    EXPECT_EQ(RegisterHdiWpaP2pEventCallback(nullptr), WIFI_HAL_OPT_INVALID_PARAM);
    EXPECT_EQ(RegisterHdiWpaP2pEventCallback(&callback), WIFI_HAL_OPT_INVALID_PARAM);
}
}
}