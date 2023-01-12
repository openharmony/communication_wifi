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
#include "i_wifi_p2p_iface.h"

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
constexpr int PROVDISC = 2;
constexpr int PERSISTENT = 1;
constexpr int TIME = 2;
constexpr int FREQUENCY = 0;
constexpr char PIN[WIFI_PIN_CODE_LENGTH+1] = "A123456";
constexpr int MODE = 2;
constexpr int BAND = 3;

class IWifiP2pIface : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(IWifiP2pIface, P2pStopSuccess, TestSize.Level1)
{
    EXPECT_TRUE(P2pStop() == WIFI_IDL_OPT_FAILED);
}

HWTEST_F(IWifiP2pIface, P2pSetWpsDeviceTypeSuccess, TestSize.Level1)
{
    char *type = nullptr;
    if (strcpy_s(type, sizeof(type), "networkId") != EOK) {
        return;
    }
    EXPECT_TRUE(P2pSetWpsDeviceType(type) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pSetWpsSecondaryDeviceTypeSuccess, TestSize.Level1)
{
    char *type = nullptr;
    if (strcpy_s(type, sizeof(type), "networkId") != EOK) {
        return;
    }
    EXPECT_TRUE(P2pSetWpsSecondaryDeviceType(type) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pGetDeviceAddressSucess, TestSize.Level1)
{
    EXPECT_TRUE(P2pSaveConfig() == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pSetupWpsPbcSuccess, TestSize.Level1)
{
    char *groupIfc = nullptr;
    const char *address = nullptr;
    if (strcpy_s(groupIfc, sizeof(groupIfc), "networkId") != EOK) {
        return;
    }
    if (strcpy_s(address, sizeof(address), "00:00:00:00:00") != EOK) {
        return;
    }
    EXPECT_TRUE(P2pSetupWpsPbc(groupIfc, address) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pSetupWpsPinSuccess, TestSize.Level1)
{
    char *groupIfc = nullptr;
    char *address = nullptr;
    char *pin = nullptr;
    const char *result = nullptr;
    int resultLen = NETWORK_ID;
    if (strcpy_s(groupIfc, sizeof(groupIfc), "networkId") != EOK) {
        return;
    }
    if (strcpy_s(address, sizeof(address), "00:00:00:00:00") != EOK) {
        return;
    }
    if (strcpy_s(groupIfc, sizeof(groupIfc), "networkId") != EOK) {
        return;
    }
    if (strcpy_s(address, sizeof(address), "test") != EOK) {
        return;
    }
    EXPECT_TRUE(P2pSetupWpsPin(groupIfc, address, pin, result, resultLen) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pRemoveNetworkSuccess, TestSize.Level1)
{
    int networkId = NETWORK_ID;
    EXPECT_TRUE(P2pRemoveNetwork(networkId) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pSetGroupMaxIdleSuccess, TestSize.Level1)
{
    char *groupIfc = nullptr;
    int time = TIME;
    if (strcpy_s(groupIfc, sizeof(groupIfc), "networkId") != EOK) {
        return;
    }
    EXPECT_TRUE(P2pSetGroupMaxIdle(groupIfc, time) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pSetPowerSaveSuccess, TestSize.Level1)
{
    char *groupIfc = nullptr;
    int enable = MODE;
    if (strcpy_s(groupIfc, sizeof(groupIfc), "networkId") != EOK) {
        return;
    }
    EXPECT_TRUE(P2pSetPowerSave(groupIfc, time) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pSetWfdEnableSuccess, TestSize.Level1)
{
    int enable = MODE;
    EXPECT_TRUE(P2pSetWfdEnable(enable) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pSetWfdDeviceConfigSuccess, TestSize.Level1)
{
    char *config = nullptr;
    if (strcpy_s(config, sizeof(config), "networkId") != EOK) {
        return;
    }
    EXPECT_TRUE(P2pSetWfdDeviceConfig(config) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pStartFindSuccess, TestSize.Level1)
{
    int timeout = TIME;
    EXPECT_TRUE(P2pStartFind(timeout) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pStopFindSuccess, TestSize.Level1)
{
    EXPECT_TRUE(P2pStopFind() == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pSetExtListenSuccess, TestSize.Level1)
{
    int timeout = TIME;
    int period = PROVDISC;
    int interval = MODE;
    EXPECT_TRUE(P2pSetExtListen(timeout, period, interval) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pSetListenChannelSuccess, TestSize.Level1)
{
    int channel = 0;
    int regClass = 0;
    EXPECT_TRUE(P2pSetListenChannel(timeout, period) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pConnectSuccess, TestSize.Level1)
{
    P2pConnectInfo info;
    info.mode = NETWORK_ID;
    info.provdisc = PROVDISC;
    info.goIntent = NETWORK_ID;
    info.persistent = PERSISTENT;
    info.pin = PIN;
    if (strcpy_s(info.peerDevAddr, sizeof(info.peerDevAddr), "00:00:00:00:00") != EOK) {
        return;
    }
    EXPECT_TRUE(P2pConnect(&info) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pCancelConnectSuccess, TestSize.Level1)
{
    EXPECT_TRUE(P2pCancelConnect() == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pProvisionDiscoverySuccess, TestSize.Level1)
{
    char *peerBssid = nullptr;
    int mode = MODE;
    if (strcpy_s(peerBssid, sizeof(peerBssid), "123456") != EOK) {
        return;
    }
    EXPECT_TRUE(P2pProvisionDiscovery(peerBssid, mode) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pAddGroupSuccess, TestSize.Level1)
{
    int isPersistent = PERSISTENT;
    int networkId = NETWORK_ID;
    int freq = FREQUENCY;
    EXPECT_TRUE(P2pAddGroup(isPersistent, networkId, freq) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pRemoveGroupSuccess, TestSize.Level1)
{
    char *interface = nullptr;
    int mode = MODE;
    if (strcpy_s(peerBssid, sizeof(interface), "A123456") != EOK) {
    return;
    }
    EXPECT_TRUE(P2pRemoveGroup(interface) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pInviteSuccess, TestSize.Level1)
{
    char *peerBssid = nullptr;
    char *goBssid = nullptr;
    char *ifname = nullptr;
    int persisitent = PERSISTENT;
    if (strcpy_s(peerBssid, sizeof(peerBssid), "networkId") != EOK) {
        return;
    }
    if (strcpy_s(goBssid, sizeof(goBssid), "00:00:00:00:00") != EOK) {
        return;
    }
    if (strcpy_s(ifname, sizeof(ifname), "networkId") != EOK) {
        return;
    }
    EXPECT_TRUE(P2pInvite(persisitent, peerBssid, goBssid, ifname) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pReinvokeSuccess, TestSize.Level1)
{
    char *bssid = nullptr;
    int networkId = NETWORK_ID;
    if (strcpy_s(bssid, sizeof(bssid), "A123456") != EOK) {
        return;
    }
    EXPECT_TRUE(P2pReinvoke(networkId, bssid) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pGetGroupCapabilitySuccess, TestSize.Level1)
{
    char *bssid = nullptr;
    int *cap = &NETWORK_ID;
    if (strcpy_s(bssid, sizeof(bssid), "A123456") != EOK) {
    return;
    }
    EXPECT_TRUE(P2pGetGroupCapability(bssid, cap) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pAddServiceSuccess, TestSize.Level1)
{
    P2pServiceInfo info;
    info.mode = NETWORK_ID;
    info.version = PROVDISC;
    if (memcpy_s(info.name, WIFI_P2P_SERVER_NAME_LENGTH, "Hwmate", WIFI_P2P_SERVER_NAME_LENGTH - 1) != EOK) {
        return;
    }
    if (memcpy_s(info.bssid, WIFI_P2P_SERVE_INFO_LENGTH, "Hwmate", WIFI_P2P_SERVER_NAME_LENGTH - 1) != EOK) {
        return;
    }
    EXPECT_TRUE(P2pAddService(&info) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pRemoveServiceSuccess, TestSize.Level1)
{
    P2pServiceInfo info;
    info.mode = NETWORK_ID;
    info.version = PROVDISC;
    if (memcpy_s(info.name, WIFI_P2P_SERVER_NAME_LENGTH, "Hwmate", WIFI_P2P_SERVER_NAME_LENGTH - 1) != EOK) {
        return;
    }
    if (memcpy_s(info.bssid, WIFI_P2P_SERVE_INFO_LENGTH, "Hwmate", WIFI_P2P_SERVER_NAME_LENGTH - 1) != EOK) {
        return;
    }
    EXPECT_TRUE(P2pRemoveService(&info) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pReqServiceDiscoverySuccess, TestSize.Level1)
{
    char *bssid = nullptr;
    char *msg = nullptr;
    char *retMsg = nullptr;
    int size = PERSISTENT;
    if (strcpy_s(bssid, sizeof(bssid), "networkId") != EOK) {
    return;
    }
    if (strcpy_s(msg, sizeof(msg), "00:00:00:00:00") != EOK) {
    return;
    }
    if (strcpy_s(retMsg, sizeof(retMsg), "networkId") != EOK) {
    return;
    }
    EXPECT_TRUE(P2pReqServiceDiscovery(bssid, msg, retMsg, size) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pCancelServiceDiscoverySuccess, TestSize.Level1)
{
    char *id = nullptr;
    if (strcpy_s(id, sizeof(id), "networkId") != EOK) {
        return;
    }
    EXPECT_TRUE(P2pCancelServiceDiscovery(id) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pSetMiracastTypeSuccess, TestSize.Level1)
{
    int type = PERSISTENT;
    EXPECT_TRUE(P2pSetMiracastType(type) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pSetPersistentReconnectSuccess, TestSize.Level1)
{
    int mode = MODE;
    EXPECT_TRUE(P2pSetPersistentReconnect(mode) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pRespServerDiscoverySuccess, TestSize.Level1)
{
    char *deviceAddress = nullptr;
    char *frequency = nullptr;
    int frequency = FREQUENCY;
    int dialogToken = PERSISTENT;
    if (strcpy_s(tlvs, sizeof(tlvs), "networkId") != EOK) {
    return;
    }
    if (strcpy_s(deviceAddress, sizeof(deviceAddress), "00:00:00:00:00") != EOK) {
    return;
    }
    EXPECT_TRUE(P2pRespServerDiscovery(deviceAddress, frequency, dialogToken, frequency) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pSetServDiscExternalSuccess, TestSize.Level1)
{
    int mode = MODE;
    EXPECT_TRUE(P2pSetServDiscExternal(mode) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pGetPeerSuccess, TestSize.Level1)
{
    char *deviceAddress = nullptr;
    P2pDeviceInfo peerInfo;
    if (strcpy_s(deviceAddress, sizeof(deviceAddress), "00:00:00:00:00") != EOK) {
        return;
    }
    EXPECT_TRUE(P2pGetPeer(deviceAddress, &peerInfo) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pGetFrequenciesSuccess, TestSize.Level1)
{
    int32_t band = BAND;
    int *frequency = &FREQUENCY;
    int32_t *size = &FREQUENCY;
    EXPECT_TRUE(P2pGetFrequencies(BAND, frequency, size) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pSetGroupConfigSuccess, TestSize.Level1)
{
    P2pGroupConfig pConfig;
    int size = PERSISTENT;
    int networkId = NETWORK_ID;
    int freq = FREQUENCY;
    EXPECT_TRUE(P2pSetGroupConfig(networkId, &pConfig, size) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pGetGroupConfigSuccess, TestSize.Level1)
{
    P2pGroupConfig pConfig;
    int size = PERSISTENT;
    int networkId = NETWORK_ID;
    int freq = FREQUENCY;
    EXPECT_TRUE(P2pGetGroupConfig(networkId, &pConfig, size) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, P2pAddNetworkSuccess, TestSize.Level1)
{
    int *networkId = &NETWORK_ID;
    EXPECT_TRUE(P2pAddNetwork(networkId) == WIFI_IDL_OPT_OK);
}

HWTEST_F(IWifiP2pIface, Hid2dConnectSuccess, TestSize.Level1)
{
    Hid2dConnectInfo info;
    info.frequency = FREQUENCY;
    if (memcpy_s(info.ssid, WIFI_SSID_LENGTH, "Hwmate", WIFI_SSID_LENGTH - 1) != EOK) {
        return;
    }
    if (memcpy_s(info.bssid, WIFI_BSSID_LENGTH, "00:00:00:00:00", WIFI_BSSID_LENGTH - 1) != EOK) {
        return;
    }
    if (memcpy_s(info.bssid, WIFI_P2P_PASSWORD_SIZE, "A123456", WIFI_P2P_PASSWORD_SIZE - 1) != EOK) {
        return;
    }
    EXPECT_TRUE(Hid2dConnect(&info) == WIFI_IDL_OPT_OK);
}
} // namespace Wifi
} // namespace OHOS
